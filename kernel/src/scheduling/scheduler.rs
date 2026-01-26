use crate::cpu;
use crate::drivers::interrupt_index::{
    current_cpu_id, get_current_logical_id, send_eoi, IpiDest, IpiKind, LocalApic, APIC,
};
use crate::drivers::timer_driver::{PER_CORE_SWITCHES, TIMER};
use crate::executable::program::PROGRAM_MANAGER;
use crate::idt::SCHED_IPI_VECTOR;
use crate::memory::paging::stack::StackSize;
use crate::scheduling::runtime::runtime::{yield_now, RUNTIME_POOL};
use crate::scheduling::scheduler;
use crate::scheduling::state::{BlockReason, SchedState, State};
use crate::scheduling::task::{idle_task, Task, TaskRef, IDLE_MAGIC_LOWER, IDLE_UUID_UPPER};
use crate::util::KERNEL_INITIALIZED;

pub use crate::scheduling::task::TaskHandle;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::naked_asm;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use crossbeam_queue::ArrayQueue;
use kernel_types::irq::IrqSafeMutex;
use lazy_static::lazy_static;
use spin::Mutex;
use spin::RwLock;
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::instructions::{hlt, interrupts};
use x86_64::registers::control::Cr3;

const BALANCE_INTERVAL_TICKS: usize = 150;
const RUNQ_CAP: usize = 4096;
const IPIQ_CAP: usize = 64;

const MAX_TASKS: usize = 65_536;

#[derive(Debug)]
#[repr(u32)]
pub enum TaskError {
    NotFound(u64),
}

struct TaskTable {
    slots: Box<[AtomicPtr<TaskRef>]>,
}

impl TaskTable {
    fn new(max_tasks: usize) -> Self {
        let mut v: Vec<AtomicPtr<TaskRef>> = Vec::with_capacity(max_tasks + 1);
        for _ in 0..=max_tasks {
            v.push(AtomicPtr::new(ptr::null_mut()));
        }
        Self {
            slots: v.into_boxed_slice(),
        }
    }

    #[inline(always)]
    fn insert(&self, id: u64, task: &TaskHandle) {
        let idx = id as usize;
        if idx == 0 || idx >= self.slots.len() {
            panic!(
                "task id {} out of bounds (cap={})",
                id,
                self.slots.len() - 1
            );
        }

        let raw = Arc::into_raw(task.clone()) as *mut TaskRef;

        let prev = self.slots[idx].compare_exchange(
            ptr::null_mut(),
            raw,
            Ordering::Release,
            Ordering::Relaxed,
        );

        if prev.is_err() {
            unsafe { drop(Arc::from_raw(raw)) };
            panic!("task id {} reused / slot not empty", id);
        }
    }

    #[inline(always)]
    fn get(&self, id: u64) -> Option<TaskHandle> {
        let idx = id as usize;
        if idx == 0 || idx >= self.slots.len() {
            return None;
        }

        let p = self.slots[idx].load(Ordering::Acquire);
        if p.is_null() {
            return None;
        }

        unsafe {
            Arc::increment_strong_count(p);
            Some(Arc::from_raw(p))
        }
    }
}

pub struct CoreScheduler {
    sched_lock: IrqSafeMutex<SchedulerState>,
    run_queue: ArrayQueue<TaskHandle>,
    ipi_queue: ArrayQueue<TaskHandle>,
    idle_task: TaskHandle,
    current_ptr: AtomicPtr<TaskRef>,
    lapic_id: u8,
    load: AtomicUsize,
}

struct SchedulerState {
    current: Option<TaskHandle>,
}

pub struct Scheduler {
    all_tasks: TaskTable,
    cores: RwLock<Vec<Arc<CoreScheduler>>>,
    next_task_id: AtomicU64,
    num_cores: AtomicUsize,
    last_balance_tick: AtomicUsize,
    balance_lock: Mutex<()>,
}

lazy_static! {
    pub static ref SCHEDULER: Scheduler = Scheduler::new();
}

impl Scheduler {
    fn new() -> Self {
        Self {
            all_tasks: TaskTable::new(MAX_TASKS),
            cores: RwLock::new(Vec::new()),
            next_task_id: AtomicU64::new(1),
            num_cores: AtomicUsize::new(0),
            last_balance_tick: AtomicUsize::new(0),
            balance_lock: Mutex::new(()),
        }
    }

    #[inline(always)]
    fn core(&self, cpu_id: usize) -> Option<Arc<CoreScheduler>> {
        let cores = self.cores.read();
        cores.get(cpu_id).cloned()
    }

    #[inline(always)]
    fn build_core(&self, cpu_id: usize, lapic_id: u8) -> Arc<CoreScheduler> {
        let idle = Task::new_kernel_mode(idle_task, 0, StackSize::Tiny, "".into(), 0);

        idle.inner.write().context.r10 = 0x1c82f35548bcbe24;
        idle.inner.write().context.r11 = 0x890189d70ecaca7f;

        let idle_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
        idle.set_task_id(idle_id);
        idle.set_target_cpu(cpu_id);

        self.all_tasks.insert(idle_id, &idle);

        let idle_ptr = Arc::as_ptr(&idle) as *mut TaskRef;

        Arc::new(CoreScheduler {
            sched_lock: IrqSafeMutex::new(SchedulerState { current: None }),
            run_queue: ArrayQueue::new(RUNQ_CAP),
            ipi_queue: ArrayQueue::new(IPIQ_CAP),
            idle_task: idle,
            current_ptr: AtomicPtr::new(idle_ptr),
            lapic_id,
            load: AtomicUsize::new(0),
        })
    }

    pub fn init_core(&self, cpu_id: usize) {
        let mut cores = self.cores.write();

        if cpu_id < cores.len() {
            return;
        }

        assert!(
            cpu_id == cores.len(),
            "cpu ids must be contiguous (got {}, expected next {})",
            cpu_id,
            cores.len()
        );

        let lapic_id = get_current_logical_id();
        cores.push(self.build_core(cpu_id, lapic_id));
        self.num_cores.store(cores.len(), Ordering::Release);
    }

    fn register_task(&self, task: TaskHandle) -> u64 {
        let id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
        if (id as usize) > MAX_TASKS {
            panic!("task table exhausted: id {} > MAX_TASKS {}", id, MAX_TASKS);
        }
        task.set_task_id(id);
        self.all_tasks.insert(id, &task);
        id
    }

    pub fn spawn_task(&self, task: TaskHandle) -> u64 {
        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            return 0;
        }

        let id = self.register_task(task.clone());
        let best_cpu = self.choose_core_for_new_task(n);
        task.set_target_cpu(best_cpu);
        self.enqueue_to_core(best_cpu, task);
        id
    }

    pub fn add_task(&self, task: TaskHandle) -> u64 {
        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            return 0;
        }

        let id = self.register_task(task.clone());
        let best_cpu = self.choose_core_for_new_task(n);
        task.set_target_cpu(best_cpu);
        self.enqueue_to_core(best_cpu, task);
        id
    }

    fn enqueue_to_core(&self, cpu: usize, task: TaskHandle) {
        let Some(core) = self.core(cpu) else {
            panic!("enqueue_to_core: cpu {} not initialized", cpu);
        };
        Self::push_runqueue_or_panic(cpu, &core.run_queue, &core.load, task);
    }

    fn enqueue_to_core_ipi(&self, cpu: usize, task: TaskHandle) {
        let Some(core) = self.core(cpu) else {
            panic!("enqueue_to_core_ipi: cpu {} not initialized", cpu);
        };
        if let Some(_) = core.ipi_queue.push(task).err() {
            panic!("ipi queue overflow on cpu {cpu}");
        }
        core.load.fetch_add(1, Ordering::Release);
    }

    #[inline(always)]
    fn push_runqueue_or_panic(
        cpu: usize,
        queue: &ArrayQueue<TaskHandle>,
        load: &AtomicUsize,
        task: TaskHandle,
    ) {
        if let Some(_) = queue.push(task).err() {
            panic!("run queue overflow on cpu {cpu}");
        }
        load.fetch_add(1, Ordering::Release);
    }

    fn choose_core_for_new_task(&self, n: usize) -> usize {
        let start = (self.next_task_id.load(Ordering::Relaxed) as usize) % n;
        let mut best = start;
        let mut best_load: Option<usize> = None;

        for k in 0..n {
            let i = (start + k) % n;
            let Some(load) = self.core_effective_load(i) else {
                continue;
            };

            if best_load.map_or(true, |b| load < b) {
                best_load = Some(load);
                best = i;
                if load == 0 {
                    break;
                }
            }
        }

        best
    }

    fn core_load_unlocked(&self, i: usize) -> Option<usize> {
        let core = self.core(i)?;
        let guard = match core.sched_lock.try_lock() {
            Some(g) => g,
            None => return None,
        };

        let rq_len = core.run_queue.len();
        let ipi_len = core.ipi_queue.len();
        let running = match guard.current.as_ref() {
            Some(t) if !Arc::ptr_eq(t, &core.idle_task) => 1,
            _ => 0,
        };

        Some(rq_len + ipi_len + running)
    }

    fn core_effective_load(&self, i: usize) -> Option<usize> {
        let core = self.core(i)?;
        Some(core.load.load(Ordering::Acquire))
    }

    #[inline(always)]
    pub fn get_task_by_id(&self, id: u64) -> Option<TaskHandle> {
        self.all_tasks.get(id)
    }

    #[inline(always)]
    pub fn get_current_task(&self, cpu_id: usize) -> Option<TaskHandle> {
        let core = self.core(cpu_id)?;
        let p = core.current_ptr.load(Ordering::Acquire);
        if p.is_null() {
            return None;
        }
        unsafe {
            Arc::increment_strong_count(p);
            Some(Arc::from_raw(p))
        }
    }

    pub fn delete_task(&self, id: u64) -> Result<(), TaskError> {
        if let Some(h) = self.get_task_by_id(id) {
            h.terminate();
            Ok(())
        } else {
            Err(TaskError::NotFound(id))
        }
    }

    pub fn unpark(&self, task: &TaskHandle) {
        task.grant_permit();

        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            return;
        }

        let mut spins: u32 = 0;

        loop {
            match task.sched_state() {
                SchedState::Blocked => {
                    if task
                        .cas_sched_state(SchedState::Blocked, SchedState::Runnable)
                        .is_err()
                    {
                        continue;
                    }

                    //task.set_block_reason(BlockReason::None);

                    let target = task.target_cpu();
                    let best_cpu = if target < n {
                        let target_load = self.core_effective_load(target).unwrap_or(usize::MAX);
                        if target_load == 0 {
                            target
                        } else {
                            self.find_least_loaded_cpu(n, target)
                        }
                    } else {
                        self.find_least_loaded_cpu(n, 0)
                    };

                    task.set_target_cpu(best_cpu);

                    if best_cpu != current_cpu_id() {
                        self.enqueue_to_core_ipi(best_cpu, task.clone());

                        if let Some(best_core) = self.core(best_cpu) {
                            unsafe {
                                APIC.lock().as_ref().map(|a| {
                                    a.lapic.send_ipi(
                                        IpiDest::ApicId(best_core.lapic_id),
                                        IpiKind::Fixed {
                                            vector: SCHED_IPI_VECTOR,
                                        },
                                    )
                                });
                            }
                        }
                    } else {
                        self.enqueue_to_core(best_cpu, task.clone());
                    }

                    return;
                }

                SchedState::Parking => {
                    spins += 1;
                    if spins <= 64 {
                        core::hint::spin_loop();
                        continue;
                    }
                    return;
                }

                SchedState::Runnable | SchedState::Running | SchedState::Terminated => {
                    return;
                }
            }
        }
    }

    fn find_least_loaded_cpu(&self, n: usize, hint: usize) -> usize {
        let best = hint % n;

        // Fast path: check hint CPU first
        if let Some(load) = self.core_effective_load(best) {
            if load == 0 {
                return best;
            }
        }

        let mut best = best;
        let mut best_load = self.core_effective_load(best);

        for k in 1..n {
            let i = (hint + k) % n;
            let Some(load) = self.core_effective_load(i) else {
                continue;
            };

            let take = match best_load {
                Some(cur) => load < cur,
                None => true,
            };

            if take {
                best_load = Some(load);
                best = i;
                if load == 0 {
                    break;
                }
            }
        }

        best
    }

    pub fn park_current(&self, reason: BlockReason) {
        let cpu_id = current_cpu_id() as usize;
        let Some(core) = self.core(cpu_id) else {
            return;
        };

        let current = {
            let state = core.sched_lock.lock();
            match state.current.as_ref() {
                Some(t) => t.clone(),
                None => return,
            }
        };

        if Arc::ptr_eq(&current, &core.idle_task) {
            return;
        }

        if current.consume_permit() {
            return;
        }

        {
            let mut _state = core.sched_lock.lock();

            if current.consume_permit() {
                return;
            }

            //current.set_block_reason(reason);
            current.set_sched_state(SchedState::Parking);
        }

        yield_now();
    }

    pub fn park_current_if(&self, reason: BlockReason, should_park: bool) {
        let cpu_id = current_cpu_id() as usize;
        let Some(core) = self.core(cpu_id) else {
            return;
        };

        if !should_park {
            return;
        }

        let current = {
            let state = core.sched_lock.lock();
            match state.current.as_ref() {
                Some(t) => t.clone(),
                None => return,
            }
        };

        if Arc::ptr_eq(&current, &core.idle_task) {
            return;
        }

        if current.consume_permit() {
            return;
        }

        {
            let mut _state = core.sched_lock.lock();

            if current.consume_permit() {
                return;
            }

            //current.set_block_reason(reason);
            current.set_sched_state(SchedState::Parking);
        }

        yield_now();
    }

    #[inline(always)]
    pub fn on_timer_tick(&self, state: *mut State, cpu_id: usize) {
        if !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return;
        }
        let Some(core) = self.core(cpu_id) else {
            return;
        };

        let now_cycles = cpu::get_cycles();
        self.maybe_balance();

        {
            let sched_state = core.sched_lock.lock();
            if let Some(ref cur) = sched_state.current {
                let Some(mut guard) = cur.inner.try_write() else {
                    return;
                };
                guard.update_from_context(state);
            }
        }

        let runtime = RUNTIME_POOL.clone();
        let _ = runtime.is_shutdown();

        let next = match self.schedule_next(cpu_id, &core, now_cycles) {
            Some(task) => task,
            None => return,
        };

        self.restore_page_table(&next);

        let ctx_guard = next.inner.read();
        unsafe { ctx_guard.context.restore(state) };
    }

    fn schedule_next(
        &self,
        cpu_id: usize,
        core: &Arc<CoreScheduler>,
        now_cycles: u64,
    ) -> Option<TaskHandle> {
        let mut sched_state = core.sched_lock.lock();

        let previous = sched_state.current.take();

        if let Some(ref prev) = previous {
            if !Arc::ptr_eq(prev, &core.idle_task) {
                if let Some(t) = prev.inner.try_read() {
                    t.account_switched_out(now_cycles);
                }

                match prev.sched_state() {
                    SchedState::Running | SchedState::Runnable => {
                        prev.set_sched_state(SchedState::Runnable);
                        Self::push_runqueue_or_panic(
                            cpu_id,
                            &core.run_queue,
                            &core.load,
                            prev.clone(),
                        );
                    }
                    SchedState::Parking => {
                        if prev.consume_permit() {
                            prev.set_sched_state(SchedState::Runnable);
                            //prev.set_block_reason(BlockReason::None);
                            Self::push_runqueue_or_panic(
                                cpu_id,
                                &core.run_queue,
                                &core.load,
                                prev.clone(),
                            );
                        } else if prev
                            .cas_sched_state(SchedState::Parking, SchedState::Blocked)
                            .is_ok()
                        {
                            if prev.consume_permit() {
                                if prev
                                    .cas_sched_state(SchedState::Blocked, SchedState::Runnable)
                                    .is_ok()
                                {
                                    //prev.set_block_reason(BlockReason::None);
                                    Self::push_runqueue_or_panic(
                                        cpu_id,
                                        &core.run_queue,
                                        &core.load,
                                        prev.clone(),
                                    );
                                }
                            }
                        }
                    }
                    SchedState::Blocked => {}
                    SchedState::Terminated => {}
                }
            }
        }

        loop {
            let Some(cand) = core.run_queue.pop() else {
                break;
            };
            core.load.fetch_sub(1, Ordering::Release);

            match cand.sched_state() {
                SchedState::Terminated => continue,
                SchedState::Parking => continue,
                SchedState::Blocked => continue,
                SchedState::Runnable | SchedState::Running => {
                    cand.set_sched_state(SchedState::Running);

                    if let Some(t) = cand.inner.try_read() {
                        t.mark_scheduled_in(cpu_id, now_cycles);
                    }

                    sched_state.current = Some(cand.clone());
                    core.current_ptr
                        .store(Arc::as_ptr(&cand) as *mut TaskRef, Ordering::Release);
                    return Some(cand);
                }
            }
        }

        core.idle_task.set_sched_state(SchedState::Running);
        if let Some(t) = core.idle_task.inner.try_read() {
            t.mark_scheduled_in(cpu_id, now_cycles);
        }

        sched_state.current = Some(core.idle_task.clone());
        core.current_ptr.store(
            Arc::as_ptr(&core.idle_task) as *mut TaskRef,
            Ordering::Release,
        );
        Some(core.idle_task.clone())
    }

    #[inline(always)]
    pub fn restore_page_table(&self, task_handle: &TaskHandle) {
        if task_handle.is_kernel_mode.load(Ordering::Relaxed) {
            return;
        }
        let pid = task_handle.inner.read().parent_pid;

        if let Some(program) = PROGRAM_MANAGER.get(pid) {
            unsafe { Cr3::write(program.read().cr3, Cr3::read().1) };
        } else {
            let id = task_handle.task_id();
            let _ = self.delete_task(id);
        }
    }

    pub fn maybe_balance(&self) {
        let current_tick = TIMER.load(Ordering::Relaxed);
        let last = self.last_balance_tick.load(Ordering::Relaxed);

        if current_tick.wrapping_sub(last) < BALANCE_INTERVAL_TICKS {
            return;
        }

        let Some(_guard) = self.balance_lock.try_lock() else {
            return;
        };

        self.last_balance_tick
            .store(current_tick, Ordering::Relaxed);
        self.balance();
    }

    fn balance(&self) {
        let n = self.num_cores.load(Ordering::Acquire);
        if n < 2 {
            return;
        }

        loop {
            let mut min_idx = 0;
            let mut max_idx = 0;
            let mut min_load = usize::MAX;
            let mut max_load = 0;

            for i in 0..n {
                let Some(load) = self.core_effective_load(i) else {
                    continue;
                };

                if load < min_load {
                    min_idx = i;
                    min_load = load;
                }
                if load > max_load {
                    max_idx = i;
                    max_load = load;
                }
            }

            if min_load == usize::MAX || max_load <= min_load + 1 {
                break;
            }

            let Some(max_core) = self.core(max_idx) else {
                break;
            };

            let task = match max_core.run_queue.pop() {
                Some(t) => {
                    max_core.load.fetch_sub(1, Ordering::Release);
                    Some(t)
                }
                None => match max_core.ipi_queue.pop() {
                    Some(t) => {
                        max_core.load.fetch_sub(1, Ordering::Release);
                        Some(t)
                    }
                    None => None,
                },
            };

            let Some(task) = task else {
                continue;
            };

            task.set_target_cpu(min_idx);
            let Some(min_core) = self.core(min_idx) else {
                break;
            };
            Self::push_runqueue_or_panic(min_idx, &min_core.run_queue, &min_core.load, task);
        }
    }

    pub fn num_cores(&self) -> usize {
        self.num_cores.load(Ordering::Relaxed)
    }

    pub fn rescue_stranded_tasks(&self, caller_cpu: usize) {
        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            return;
        }

        let max_id = self.next_task_id.load(Ordering::Relaxed);

        for id in 1..max_id {
            let Some(task) = self.all_tasks.get(id) else {
                continue;
            };

            if task.target_cpu() != caller_cpu {
                continue;
            }

            if task.sched_state() == SchedState::Blocked && task.consume_permit() {
                if task
                    .cas_sched_state(SchedState::Blocked, SchedState::Runnable)
                    .is_ok()
                {
                    self.enqueue_to_core(caller_cpu, task);
                }
            }
        }
    }

    #[inline(always)]
    pub fn on_ipi(&self, state: *mut State, cpu_id: usize) {
        if !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return;
        }

        let Some(core) = self.core(cpu_id) else {
            return;
        };

        let is_idle = {
            let sched_state = core.sched_lock.lock();
            match sched_state.current.as_ref() {
                Some(t) => Arc::ptr_eq(t, &core.idle_task),
                None => false,
            }
        };

        if !is_idle {
            send_eoi(SCHED_IPI_VECTOR);
            return;
        }

        let now_cycles = cpu::get_cycles();

        let mut ipi_cand: Option<TaskHandle> = None;
        loop {
            let Some(cand) = core.ipi_queue.pop() else {
                break;
            };
            core.load.fetch_sub(1, Ordering::Release);

            match cand.sched_state() {
                SchedState::Terminated => continue,
                SchedState::Parking => continue,
                SchedState::Blocked => continue,
                SchedState::Runnable | SchedState::Running => {
                    ipi_cand = Some(cand);
                    break;
                }
            }
        }

        let next = if let Some(cand) = ipi_cand {
            cand.set_sched_state(SchedState::Running);

            if let Some(t) = cand.inner.try_read() {
                t.mark_scheduled_in(cpu_id, now_cycles);
            }

            {
                let mut sched_state = core.sched_lock.lock();
                sched_state.current = Some(cand.clone());
                core.current_ptr
                    .store(Arc::as_ptr(&cand) as *mut TaskRef, Ordering::Release);
            }

            cand
        } else {
            match self.schedule_next(cpu_id, &core, now_cycles) {
                Some(t) => t,
                None => {
                    send_eoi(SCHED_IPI_VECTOR);
                    return;
                }
            }
        };

        self.restore_page_table(&next);

        send_eoi(SCHED_IPI_VECTOR);

        let ctx_guard = next.inner.read();
        unsafe { ctx_guard.context.restore(state) };
    }
}

#[no_mangle]
pub extern "C" fn ipi_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    let cpu_id = current_cpu_id() as usize;
    SCHEDULER.on_ipi(state, cpu_id);
}

#[no_mangle]
pub extern "C" fn yield_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    let cpu_id = current_cpu_id() as usize;
    SCHEDULER.on_timer_tick(state, cpu_id);
}

#[no_mangle]
pub extern "C" fn ipi_eoi_only() {
    crate::drivers::interrupt_index::send_eoi(SCHED_IPI_VECTOR);
}

#[unsafe(naked)]
#[no_mangle]
pub extern "win64" fn ipi_entry() {
    naked_asm!(
        "/* {upper} {lower} {eoi_only} */",
        "cli",
        "push rax",
        "mov  rax, {upper}",
        "cmp  r10, rax",
        "jne  9f",
        "mov  rax, {lower}",
        "cmp  r11, rax",
        "jne  9f",
        "pop  rax",

        "push r15","push r14","push r13","push r12",
        "push r11","push r10","push r9","push r8",
        "push rdi","push rsi","push rbp","push rbx",
        "push rdx","push rcx","push rax",

        "mov  rdi, rsp",
        "cld",
        "sub  rsp, 8",
        "call {handler}",
        "add  rsp, 8",

        "pop  rax","pop  rcx","pop  rdx","pop  rbx",
        "pop  rbp","pop  rsi","pop  rdi","pop  r8",
        "pop  r9","pop  r10","pop  r11","pop  r12",
        "pop  r13","pop  r14","pop  r15",
        "iretq",
        // TODO: Read the ABI for the caller saved registers
        "9:",
        "pop  rax",
        "push r15","push r14","push r13","push r12",
        "push r11","push r10","push r9","push r8",
        "push rdi","push rsi","push rbp","push rbx",
        "push rdx","push rcx","push rax",
        "sub  rsp, 8",
        "call {eoi_only}",
        "add  rsp, 8",
        "pop  rax","pop  rcx","pop  rdx","pop  rbx",
        "pop  rbp","pop  rsi","pop  rdi","pop  r8",
        "pop  r9","pop  r10","pop  r11","pop  r12",
        "pop  r13","pop  r14","pop  r15",
        "iretq",

        upper = const IDLE_UUID_UPPER,
        lower = const IDLE_MAGIC_LOWER,
        handler = sym ipi_handler_c,
        eoi_only = sym ipi_eoi_only,
    );
}

#[unsafe(naked)]
pub extern "win64" fn yield_interrupt_entry() {
    naked_asm!(
        "cli",
        "push r15","push r14","push r13","push r12",
        "push r11","push r10","push r9","push r8",
        "push rdi","push rsi","push rbp","push rbx",
        "push rdx","push rcx","push rax",

        "mov  rdi, rsp",
        "cld",
        "sub  rsp, 8",
        "call {handler}",
        "add  rsp, 8",

        "pop  rax","pop  rcx","pop  rdx","pop  rbx",
        "pop  rbp","pop  rsi","pop  rdi","pop  r8",
        "pop  r9","pop  r10","pop  r11","pop  r12",
        "pop  r13","pop  r14","pop  r15",
        "iretq",
        handler = sym yield_handler_c,
    );
}

pub fn kernel_task_end() -> ! {
    interrupts::without_interrupts(|| {
        let task = SCHEDULER
            .get_current_task(current_cpu_id() as usize)
            .unwrap();
        task.terminate();
    });
    loop {
        yield_now();
    }
}
