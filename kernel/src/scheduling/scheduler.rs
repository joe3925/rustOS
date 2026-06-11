use crate::arch::scheduling::idle_task;
use crate::arch::MAX_CPUS;
use crate::arch::{control::Cr3, interrupts};
use crate::cpu;
use crate::drivers::interrupt_index::current_is_in_interrupt_atomic;
use crate::drivers::interrupt_index::LocalApic;
use crate::drivers::interrupt_index::{
    current_cpu_id, get_current_logical_id, send_eoi, IpiDest, IpiKind, APIC,
};
use crate::drivers::timer_driver::NUM_CORES;
use crate::drivers::timer_driver::TIMER;
use crate::executable::program::PROGRAM_MANAGER;
use crate::idt::SCHED_IPI_VECTOR;
use crate::idt::{InterruptGuard, NestedInterruptEnableGuard};
use crate::memory::paging::stack::StackSize;
use crate::scheduling::domain::{DomainMaster, EnqueueReason, SwitchOutOutcome, TaskSchedBinding};
use crate::scheduling::fifo_scheduler::{build_fifo_domain, new_fifo_task_binding};
use crate::scheduling::runtime::runtime::yield_now;
use crate::scheduling::state::{BlockReason, SchedState, State};
use crate::scheduling::task::CurrentTask;
use crate::scheduling::task::Task;
use crate::scheduling::task::TaskError;
pub use crate::scheduling::task::TaskHandle;
use crate::scheduling::task::TaskTable;
use crate::scheduling::tls;
use crate::util::KERNEL_INITIALIZED;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kernel_types::irq::IrqSafeRwLock;
use lazy_static::lazy_static;
const TASK_TABLE_INITIAL_SLOTS: usize = 4096;

pub fn default_task_sched_binding() -> TaskSchedBinding {
    new_fifo_task_binding()
}

#[derive(Debug)]
pub enum TaskMigrationError {
    TaskNotFound(u64),
    PendingMigration(u64),
}

pub struct KernelFpuGuard {
    saved_task: Option<TaskHandle>,
}

impl KernelFpuGuard {
    #[inline(always)]
    pub fn new() -> Self {
        let cpu_id = current_cpu_id();
        let saved_task = if let Some(task) = SCHEDULER.get_current_task(cpu_id) {
            {
                let mut guard = task.inner.try_write().expect(
                    "Failed to acquire task lock for saving FPU state in interrupt handler",
                );
                guard.save_fpu_state();
            }

            Some(task)
        } else {
            None
        };

        Self { saved_task }
    }
}

impl Drop for KernelFpuGuard {
    fn drop(&mut self) {
        self.saved_task.take();

        let cpu_id = current_cpu_id();
        if let Some(current) = SCHEDULER.get_current_task(cpu_id) {
            let mut guard = current
                .inner
                .try_write()
                .expect("Failed to acquire task lock for restoring FPU state in interrupt handler");
            guard.restore_fpu_state();
        }
    }
}

pub struct CoreScheduler {
    sched_lock: IrqSafeRwLock<SchedulerState>,
    idle_task: TaskHandle,
    current: CurrentTask,
    lapic_id: u8,
}

struct SchedulerState {
    current: Option<TaskHandle>,
}

pub struct Scheduler {
    all_tasks: TaskTable,
    cores: IrqSafeRwLock<Vec<Arc<CoreScheduler>>>,
    domains: DomainMaster,
    next_task_id: AtomicU64,
    num_cores: AtomicUsize,
}

lazy_static! {
    pub static ref SCHEDULER: Scheduler = Scheduler::new();
}

impl Scheduler {
    fn new() -> Self {
        Self {
            all_tasks: TaskTable::new(TASK_TABLE_INITIAL_SLOTS),
            cores: IrqSafeRwLock::new(Vec::new()),
            domains: DomainMaster::new(
                alloc::vec![build_fifo_domain(NUM_CORES.load(Ordering::Relaxed))]
                    .into_boxed_slice(),
                NUM_CORES.load(Ordering::Relaxed),
            ),
            next_task_id: AtomicU64::new(1),
            num_cores: AtomicUsize::new(0),
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

        let _idle_id = self.register_task_no_reap(idle.clone());
        idle.set_target_cpu(cpu_id);

        Arc::new(CoreScheduler {
            sched_lock: IrqSafeRwLock::new(SchedulerState { current: None }),
            idle_task: idle.clone(),
            current: CurrentTask::new(&idle),
            lapic_id,
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
        assert!(
            cpu_id < MAX_CPUS,
            "cpu id {} exceeds scheduler domain cpu capacity {}",
            cpu_id,
            MAX_CPUS
        );

        let lapic_id = get_current_logical_id();
        cores.push(self.build_core(cpu_id, lapic_id));
        self.num_cores.store(cores.len(), Ordering::Release);
    }

    fn register_task(&self, task: TaskHandle) -> u64 {
        if current_is_in_interrupt_atomic().load(Ordering::Relaxed) {
            panic!("attempted to register task from interrupt context");
        }

        self.reap_retired_tasks();

        if let Some(id) = self.all_tasks.insert(&task) {
            self.next_task_id.fetch_add(1, Ordering::Relaxed);
            return id;
        }

        self.reap_retired_tasks();

        let id = self
            .all_tasks
            .insert(&task)
            .unwrap_or_else(|| panic!("fixed task table exhausted"));

        self.next_task_id.fetch_add(1, Ordering::Relaxed);
        id
    }

    fn register_task_no_reap(&self, task: TaskHandle) -> u64 {
        if current_is_in_interrupt_atomic().load(Ordering::Relaxed) {
            panic!("attempted to register task from interrupt context");
        }

        let id = self
            .all_tasks
            .insert(&task)
            .unwrap_or_else(|| panic!("task table exhausted while registering non-reap task"));

        self.next_task_id.fetch_add(1, Ordering::Relaxed);
        id
    }

    #[inline(always)]
    pub fn reap_retired_tasks(&self) {
        if current_is_in_interrupt_atomic().load(Ordering::Relaxed) {
            return;
        }

        self.all_tasks.reap_retired();
    }

    #[inline(always)]
    fn unregister_task(&self, task: &TaskHandle) {
        let id = task.task_id();
        if id != 0 {
            self.all_tasks.retire(id, task);
        }
    }

    pub fn add_task(&self, task: TaskHandle) -> u64 {
        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            return 0;
        }

        let id = self.register_task(task.clone());
        let domain = self.domains.get(task.domain_id());
        let target_cpu = domain.enqueue(task, EnqueueReason::New, self.new_task_placement_start());
        self.kick_remote_core(target_cpu);
        id
    }

    pub(crate) fn kick_remote_core(&self, cpu: usize) {
        if cpu == current_cpu_id() || !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return;
        }

        if let Some(core) = self.core(cpu) {
            let in_interrupt = current_is_in_interrupt_atomic().load(Ordering::Acquire);

            if in_interrupt {
                let Some(apic) = APIC.try_lock() else {
                    return;
                };

                if let Some(a) = apic.as_ref() {
                    unsafe {
                        a.lapic.send_ipi(
                            IpiDest::ApicId(core.lapic_id),
                            IpiKind::Fixed {
                                vector: SCHED_IPI_VECTOR,
                            },
                        )
                    }
                }

                return;
            }

            unsafe {
                if let Some(a) = APIC.lock().as_ref() {
                    a.lapic.send_ipi(
                        IpiDest::ApicId(core.lapic_id),
                        IpiKind::Fixed {
                            vector: SCHED_IPI_VECTOR,
                        },
                    )
                }
            }
        }
    }

    #[inline(always)]
    pub fn get_task_by_id(&self, id: u64) -> Option<TaskHandle> {
        self.all_tasks.get(id)
    }

    #[inline(always)]
    pub fn get_current_task(&self, cpu_id: usize) -> Option<TaskHandle> {
        self.core(cpu_id)?.current.load()
    }

    pub fn delete_task(&self, id: u64) -> Result<(), TaskError> {
        if let Some(h) = self.get_task_by_id(id) {
            h.terminate();
            Ok(())
        } else {
            Err(TaskError::NotFound(id))
        }
    }

    pub fn migrate_task_domain(
        &self,
        id: u64,
        sched_binding: TaskSchedBinding,
    ) -> Result<(), TaskMigrationError> {
        let _ = self.domains.get(sched_binding.domain_id());

        let Some(task) = self.get_task_by_id(id) else {
            return Err(TaskMigrationError::TaskNotFound(id));
        };

        if task.set_pending_sched_binding(sched_binding).is_err() {
            return Err(TaskMigrationError::PendingMigration(id));
        }

        if task.sched_state() == SchedState::Blocked {
            self.commit_pending_migration(&task, current_cpu_id(), cpu::get_cycles());
        }

        Ok(())
    }

    pub fn unpark(&self, task: &TaskHandle) {
        task.grant_permit();

        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            return;
        }

        let in_interrupt = current_is_in_interrupt_atomic().load(Ordering::Acquire);
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

                    let hint_cpu = task.target_cpu();
                    if task.has_pending_sched_binding() && !in_interrupt {
                        self.commit_pending_migration(task, current_cpu_id(), cpu::get_cycles());
                    }

                    let domain = self.domains.get(task.domain_id());
                    let target_cpu = domain.enqueue(task.clone(), EnqueueReason::Wakeup, hint_cpu);
                    self.kick_remote_core(target_cpu);

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

    pub fn park_current(&self, _reason: BlockReason) {
        if !interrupts::are_enabled() {
            panic!("Attempt to park with interrupts disabled, this will always cause a deadlock");
        }

        let cpu_id = current_cpu_id();
        let Some(core) = self.core(cpu_id) else {
            return;
        };

        let current = {
            let state = core.sched_lock.read();
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
            let _state = core.sched_lock.write();

            if current.consume_permit() {
                return;
            }

            current.set_sched_state(SchedState::Parking);
        }

        yield_now();
    }

    #[inline(always)]
    pub fn on_timer_tick(&self, state: *mut State, cpu_id: usize) -> Option<TaskHandle> {
        if !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return None;
        }

        let Some(core) = self.core(cpu_id) else {
            return None;
        };

        let now_cycles = cpu::get_cycles();

        let mut prev_task = None;

        {
            let sched_state = core.sched_lock.read();

            if let Some(ref cur) = sched_state.current {
                let Some(mut guard) = cur.inner.try_write() else {
                    return None;
                };

                guard.update_from_context(state);

                if !Arc::ptr_eq(cur, &core.idle_task) {
                    prev_task = Some(cur.clone());
                }
            }
        }

        let next = match self.schedule_next(cpu_id, &core, now_cycles, true) {
            Some(task) => task,
            None => return prev_task,
        };

        self.maybe_balance();

        self.restore_page_table(&next);
        self.restore_thread_local_storage(&next);

        let ctx_guard = next.inner.read();
        unsafe { ctx_guard.context.restore(state) };

        prev_task
    }

    fn schedule_next(
        &self,
        cpu_id: usize,
        core: &Arc<CoreScheduler>,
        now_cycles: u64,
        prev_fpu_already_saved: bool,
    ) -> Option<TaskHandle> {
        let mut sched_state = core.sched_lock.write();
        let previous = sched_state.current.take();
        let mut switch_out_previous = None;

        if let Some(prev) = previous {
            let prev_is_idle = Arc::ptr_eq(&prev, &core.idle_task);

            let mut lock_failed = false;

            if let Some(mut guard) = prev.inner.try_write() {
                if !prev_fpu_already_saved {
                    guard.save_fpu_state();
                }

                if !prev_is_idle {
                    guard.account_switched_out(now_cycles);
                }
            } else {
                lock_failed = true;
            }

            if lock_failed {
                sched_state.current = Some(prev.clone());
                core.current.store(&prev);
                return Some(prev);
            }

            if !prev_is_idle {
                match prev.sched_state() {
                    SchedState::Running | SchedState::Runnable => {
                        prev.set_sched_state(SchedState::Runnable);
                        switch_out_previous = Some((prev.clone(), SwitchOutOutcome::StillRunnable));
                    }
                    SchedState::Parking => {
                        if prev.consume_permit() {
                            prev.set_sched_state(SchedState::Runnable);
                            switch_out_previous =
                                Some((prev.clone(), SwitchOutOutcome::StillRunnable));
                        } else if prev
                            .cas_sched_state(SchedState::Parking, SchedState::Blocked)
                            .is_ok()
                        {
                            if prev.consume_permit()
                                && prev
                                    .cas_sched_state(SchedState::Blocked, SchedState::Runnable)
                                    .is_ok()
                            {
                                switch_out_previous =
                                    Some((prev.clone(), SwitchOutOutcome::StillRunnable));
                            } else {
                                switch_out_previous =
                                    Some((prev.clone(), SwitchOutOutcome::Blocking));
                            }
                        } else {
                            switch_out_previous = match prev.sched_state() {
                                SchedState::Running | SchedState::Runnable => {
                                    Some((prev.clone(), SwitchOutOutcome::StillRunnable))
                                }
                                SchedState::Parking | SchedState::Blocked => {
                                    Some((prev.clone(), SwitchOutOutcome::Blocking))
                                }
                                SchedState::Terminated => {
                                    Some((prev.clone(), SwitchOutOutcome::Terminated))
                                }
                            };
                        }
                    }
                    SchedState::Blocked => {
                        switch_out_previous = Some((prev.clone(), SwitchOutOutcome::Blocking));
                    }
                    SchedState::Terminated => {
                        switch_out_previous = Some((prev.clone(), SwitchOutOutcome::Terminated));
                    }
                }
            }
        }

        if let Some((prev, outcome)) = switch_out_previous {
            self.handle_switch_out(&prev, cpu_id, now_cycles, outcome);
        }

        loop {
            let cand = match self.domains.pick_next(cpu_id, now_cycles) {
                Some(task) => task,
                None => break,
            };

            match cand.sched_state() {
                SchedState::Terminated => {
                    self.handle_switch_out(&cand, cpu_id, now_cycles, SwitchOutOutcome::Terminated);
                    continue;
                }
                SchedState::Parking => continue,
                SchedState::Blocked => continue,
                SchedState::Runnable | SchedState::Running => {
                    if self.commit_pending_migration(&cand, cpu_id, now_cycles) {
                        let domain = self.domains.get(cand.domain_id());
                        let target_cpu = domain.enqueue(
                            cand.clone(),
                            EnqueueReason::Migrated,
                            cand.target_cpu(),
                        );
                        self.kick_remote_core(target_cpu);
                        continue;
                    }

                    cand.set_sched_state(SchedState::Running);

                    {
                        let mut guard = cand.inner.write();
                        guard.restore_fpu_state();
                        guard.mark_scheduled_in(cpu_id, now_cycles);
                    }

                    sched_state.current = Some(cand.clone());
                    core.current.store(&cand);
                    return Some(cand);
                }
            }
        }

        core.idle_task.set_sched_state(SchedState::Running);

        {
            let mut guard = core.idle_task.inner.write();
            guard.restore_fpu_state();
            guard.mark_scheduled_in(cpu_id, now_cycles);
        }

        sched_state.current = Some(core.idle_task.clone());
        core.current.store(&core.idle_task);
        Some(core.idle_task.clone())
    }

    fn handle_switch_out(
        &self,
        task: &TaskHandle,
        cpu_id: usize,
        now_cycles: u64,
        outcome: SwitchOutOutcome,
    ) {
        if outcome == SwitchOutOutcome::StillRunnable && task.has_pending_sched_binding() {
            if self.commit_pending_migration(task, cpu_id, now_cycles) {
                let domain = self.domains.get(task.domain_id());
                let target_cpu =
                    domain.enqueue(task.clone(), EnqueueReason::Migrated, task.target_cpu());
                self.kick_remote_core(target_cpu);
                return;
            }
        }

        let domain = self.domains.get(task.domain_id());
        domain.on_switch_out(task, cpu_id, now_cycles, outcome);

        if outcome == SwitchOutOutcome::Terminated {
            self.unregister_task(task);
        }
    }

    fn commit_pending_migration(&self, task: &TaskHandle, cpu_id: usize, now_cycles: u64) -> bool {
        let Some(new_binding) = task.take_pending_sched_binding() else {
            return false;
        };

        let old_domain = self.domains.get(task.domain_id());
        old_domain.on_switch_out(task, cpu_id, now_cycles, SwitchOutOutcome::Migrated);
        drop(task.replace_sched_binding(new_binding));
        true
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

    #[inline(always)]
    pub fn restore_thread_local_storage(&self, task_handle: &TaskHandle) {
        let thread_pointer = if task_handle.is_kernel_mode.load(Ordering::Relaxed) {
            task_handle.tls_thread_pointer.load(Ordering::Relaxed)
        } else {
            0
        };

        tls::activate(thread_pointer);
    }

    pub fn maybe_balance(&self) {
        let current_tick = TIMER.load(Ordering::Relaxed);
        self.domains.maybe_balance(current_tick);
    }

    pub fn num_cores(&self) -> usize {
        self.num_cores.load(Ordering::Relaxed)
    }

    pub(crate) fn new_task_placement_start(&self) -> usize {
        let n = self.num_cores.load(Ordering::Acquire);
        if n == 0 {
            0
        } else {
            self.next_task_id.load(Ordering::Relaxed) as usize % n
        }
    }

    pub(crate) fn cpu_is_idle(&self, cpu_id: usize) -> bool {
        self.core(cpu_id)
            .is_some_and(|core| core.current.is_task(&core.idle_task))
    }

    pub(crate) fn with_core_sched_lock<R>(
        &self,
        cpu_id: usize,
        f: impl FnOnce() -> R,
    ) -> Option<R> {
        let core = self.core(cpu_id)?;
        let _state = core.sched_lock.write();
        Some(f())
    }

    pub(crate) fn unregister_task_from_domain(&self, task: &TaskHandle) {
        self.unregister_task(task);
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
            let sched_state = core.sched_lock.read();
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

        let next = match self.schedule_next(cpu_id, &core, now_cycles, true) {
            Some(t) => t,
            None => {
                send_eoi(SCHED_IPI_VECTOR);
                return;
            }
        };

        self.restore_page_table(&next);
        self.restore_thread_local_storage(&next);

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

    if current_is_in_interrupt_atomic().load(Ordering::Acquire) {
        send_eoi(SCHED_IPI_VECTOR);
        return;
    }

    let _guard = InterruptGuard::new();
    let _fpu_guard = KernelFpuGuard::new();
    //let _nested_interrupts = NestedInterruptEnableGuard::new();
    let cpu_id = current_cpu_id();

    SCHEDULER.on_ipi(state, cpu_id);
}

#[no_mangle]
pub extern "C" fn yield_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    if current_is_in_interrupt_atomic().load(Ordering::Acquire) {
        return;
    }

    let _guard = InterruptGuard::new();
    let _fpu_guard = KernelFpuGuard::new();
    //let _nested_interrupts = NestedInterruptEnableGuard::new();
    let cpu_id = current_cpu_id();

    SCHEDULER.on_timer_tick(state, cpu_id);
}

#[no_mangle]
pub extern "C" fn ipi_eoi_only() {
    crate::drivers::interrupt_index::send_eoi(SCHED_IPI_VECTOR);
}

pub extern "C" fn kernel_task_end() -> ! {
    crate::memory::heap::mimalloc_thread_done();

    interrupts::without_interrupts(|| {
        let task = SCHEDULER.get_current_task(current_cpu_id()).unwrap();
        task.terminate();
    });

    loop {
        yield_now();
    }
}
