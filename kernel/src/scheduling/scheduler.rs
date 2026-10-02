use crate::executable::program::PROGRAM_MANAGER;
use crate::idt::interrupt_impl::InterruptGuard;
use crate::memory::heap::heap::mimalloc_thread_done;
use crate::memory::paging::address_space::{kernel_address_space_root, switch_address_space_root};
use crate::memory::paging::stack::StackSize;
use crate::platform;
use crate::scheduling::domain::{
    CpuSet, DomainEntry, DomainMaster, EnqueueReason, KERNEL_DOMAIN_ID, RoundRobinDomainAlgorithm,
    SwitchOutOutcome, TaskSchedBinding, USER_DOMAIN_ID,
};
use crate::scheduling::fifo_scheduler::{FifoPriority, build_fifo_domain, fifo_task_sched_binding};
use crate::scheduling::runtime::runtime::yield_now;
use crate::scheduling::state::{FpuState, SchedState, State};
use crate::scheduling::task::Task;
use crate::scheduling::task::TaskError;
use crate::scheduling::task::TaskHandle;
use crate::scheduling::task::{TaskTable, TaskUpdate};
use crate::scheduling::tls;
use crate::util::KERNEL_INITIALIZED;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::{Mutex, MutexGuard};
const TASK_TABLE_INITIAL_SLOTS: usize = 4096;

pub(crate) fn kernel_task_sched_binding() -> TaskSchedBinding {
    fifo_task_sched_binding(FifoPriority::Normal)
}

pub(crate) fn user_task_sched_binding() -> TaskSchedBinding {
    TaskSchedBinding::new(
        USER_DOMAIN_ID,
        crate::scheduling::fifo_scheduler::FifoTaskState::new(FifoPriority::Normal),
    )
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
    pub fn try_new() -> Option<Self> {
        let cpu_id = platform::current_cpu_id();
        let saved_task = if let Some(task) = SCHEDULER.get_current_task(cpu_id) {
            {
                let mut guard = task.inner.try_write()?;
                guard.save_fpu_state();
            }

            Some(task)
        } else {
            None
        };

        Some(Self { saved_task })
    }

    #[inline(always)]
    pub fn new() -> Self {
        Self::try_new()
            .expect("Failed to acquire task lock for saving FPU state in interrupt handler")
    }
}

impl Drop for KernelFpuGuard {
    fn drop(&mut self) {
        self.saved_task.take();

        let cpu_id = platform::current_cpu_id();
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
    scheduling: Mutex<SchedulerState>,
    current_task_id: AtomicU64,
    idle_task: TaskHandle,
    current_is_idle: AtomicBool,
    platform_cpu_id: kernel_types::irq::PlatformCpuId,
}

struct SchedulerState {
    current: Option<TaskHandle>,
}

pub struct RunQueueAccess<'a> {
    cpu_id: usize,
    state: MutexGuard<'a, SchedulerState>,
}

impl RunQueueAccess<'_> {
    pub(crate) fn cpu_id(&self) -> usize {
        self.cpu_id
    }
}

pub struct LocalScheduler<'a> {
    current: Option<TaskUpdate>,
    return_fpu: Option<FpuState>,
    access: Option<RunQueueAccess<'a>>,
}

impl LocalScheduler<'_> {
    pub(crate) unsafe fn on_timer_tick(&mut self, state: *mut State) -> Option<TaskHandle> {
        unsafe { SCHEDULER.schedule_next(self, state) }
    }
}

impl Drop for LocalScheduler<'_> {
    fn drop(&mut self) {
        drop(self.current.take());
        drop(self.access.take());
        SCHEDULER.maybe_balance();
        if let Some(fpu) = self.return_fpu.as_ref() {
            platform::restore_fpu_state(fpu);
        }
    }
}

pub struct Scheduler {
    all_tasks: TaskTable,
    cores: [AtomicPtr<CoreScheduler>; platform::MAX_CPUS],
    domains: DomainMaster<RoundRobinDomainAlgorithm>,
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
            cores: [const { AtomicPtr::new(ptr::null_mut()) }; platform::MAX_CPUS],
            domains: DomainMaster::new(
                alloc::vec![
                    DomainEntry::new(
                        KERNEL_DOMAIN_ID,
                        build_fifo_domain("kernel", CpuSet::all(), platform::processor_count()),
                    ),
                    DomainEntry::new(
                        USER_DOMAIN_ID,
                        build_fifo_domain("user", CpuSet::all(), platform::processor_count()),
                    ),
                ]
                .into_boxed_slice(),
                platform::processor_count(),
            ),
            next_task_id: AtomicU64::new(1),
            num_cores: AtomicUsize::new(0),
        }
    }

    #[inline(always)]
    fn core(&self, cpu_id: usize) -> Option<&CoreScheduler> {
        let slot = self.cores.get(cpu_id)?;
        let ptr = slot.load(Ordering::Acquire);
        unsafe { ptr.as_ref() }
    }

    #[inline(always)]
    fn build_core(
        &self,
        cpu_id: usize,
        platform_cpu_id: kernel_types::irq::PlatformCpuId,
    ) -> Box<CoreScheduler> {
        let idle = Task::new_kernel_mode(
            platform::idle_task_entry(),
            0,
            StackSize::Tiny,
            "".into(),
            0,
        );

        platform::mark_idle_task_context(&mut idle.inner.write().context);

        let _idle_id = self.register_task_no_reap(idle.clone());
        idle.try_update().unwrap().set_target_cpu(cpu_id);

        Box::new(CoreScheduler {
            scheduling: Mutex::new(SchedulerState { current: None }),
            current_task_id: AtomicU64::new(0),
            idle_task: idle.clone(),
            current_is_idle: AtomicBool::new(false),
            platform_cpu_id,
        })
    }

    pub fn init_core(&self, cpu_id: usize) {
        assert!(
            cpu_id < platform::MAX_CPUS,
            "cpu id {} exceeds scheduler domain cpu capacity {}",
            cpu_id,
            platform::MAX_CPUS
        );

        if self.core(cpu_id).is_some() {
            return;
        }

        let expected = self.num_cores();
        assert!(
            cpu_id == expected,
            "cpu ids must be contiguous (got {}, expected next {})",
            cpu_id,
            expected
        );

        let platform_cpu_id = platform::current_platform_cpu_id();
        let core = self.build_core(cpu_id, platform_cpu_id);
        self.cores[cpu_id].store(Box::into_raw(core), Ordering::Release);
        self.num_cores();
    }

    fn register_task(&self, task: TaskHandle) -> u64 {
        if platform::current_is_in_interrupt() {
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
        if platform::current_is_in_interrupt() {
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
        if platform::current_is_in_interrupt() {
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
        let n = self.num_cores();
        if n == 0 {
            return 0;
        }

        let mut update = loop {
            if let Some(update) = task.try_update() {
                break update;
            }
            yield_now();
        };
        let id = self.register_task(task.clone());
        self.domains.enqueue(
            update.domain_id(),
            &mut update,
            EnqueueReason::New,
            self.new_task_placement_start(),
        );
        id
    }

    pub(crate) fn kick_remote_core(&self, cpu: usize) {
        if cpu == platform::current_cpu_id() || !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return;
        }

        if let Some(core) = self.core(cpu) {
            let _ = platform::send_ipi(core.platform_cpu_id, platform::scheduler_ipi_vector());
        }
    }

    #[inline(always)]
    pub fn get_task_by_id(&self, id: u64) -> Option<TaskHandle> {
        self.all_tasks.get(id)
    }

    pub fn get_current_task(&self, cpu_id: usize) -> Option<TaskHandle> {
        let core = self.core(cpu_id)?;
        loop {
            let id = core.current_task_id.load(Ordering::Acquire);
            let task = self.all_tasks.get(id);
            if core.current_task_id.load(Ordering::Acquire) == id {
                return task;
            }
        }
    }

    pub fn get_local_current_task(&self) -> Option<TaskHandle> {
        loop {
            let cpu_id = platform::current_cpu_id();
            let task = self.get_current_task(cpu_id);
            if platform::current_cpu_id() == cpu_id {
                return task;
            }
        }
    }

    pub fn try_get_current_task(&self, cpu_id: usize) -> Option<TaskHandle> {
        let core = self.core(cpu_id)?;
        let id = core.current_task_id.load(Ordering::Acquire);
        let task = self.all_tasks.get(id);
        if core.current_task_id.load(Ordering::Acquire) == id {
            task
        } else {
            None
        }
    }

    pub(crate) fn try_core_scheduler(&self, cpu_id: usize) -> Option<RunQueueAccess<'_>> {
        let core = self.core(cpu_id)?;
        Some(RunQueueAccess {
            cpu_id,
            state: core.scheduling.try_lock()?,
        })
    }

    pub(crate) fn try_local_scheduler(&self) -> Option<LocalScheduler<'_>> {
        if !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return None;
        }
        let cpu_id = platform::current_cpu_id();
        let access = self.try_core_scheduler(cpu_id)?;
        let (current, return_fpu) = match access.state.current.as_ref() {
            Some(task) => {
                let update = task.try_update()?;
                let fpu = {
                    let mut inner = task.inner.try_write()?;
                    inner.save_fpu_state();
                    inner.fpu_state.clone()
                };
                (Some(update), Some(fpu))
            }
            None => (None, None),
        };
        Some(LocalScheduler {
            current,
            return_fpu,
            access: Some(access),
        })
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
        let Some(task) = self.get_task_by_id(id) else {
            return Err(TaskMigrationError::TaskNotFound(id));
        };

        let mut update = loop {
            if let Some(update) = task.try_update() {
                break update;
            }
            yield_now();
        };
        if update.set_pending_sched_binding(sched_binding).is_err() {
            return Err(TaskMigrationError::PendingMigration(id));
        }
        if update.sched_state() == SchedState::Blocked {
            self.commit_pending_migration(
                &mut update,
                platform::current_cpu_id(),
                platform::cycle_counter(),
            );
        }
        update.notify_after_update(task.target_cpu());
        Ok(())
    }

    pub(crate) fn enqueue_woken_task(&self, task: &mut TaskUpdate) {
        let hint = task.target_cpu();
        self.domains
            .enqueue(task.domain_id(), task, EnqueueReason::Wakeup, hint);
    }

    pub fn unpark(&self, task: &TaskHandle) {
        task.grant_permit();
        drop(task.try_update());
    }

    pub fn park_current(&self) {
        if !platform::interrupts_enabled() || platform::current_is_in_interrupt() {
            panic!("cannot park in interrupt context");
        }
        let Some(current) = self.get_local_current_task() else {
            return;
        };
        let mut update = loop {
            if let Some(update) = current.try_update() {
                break update;
            }
            yield_now();
        };
        let cpu_id = platform::current_cpu_id();
        if self
            .core(cpu_id)
            .is_some_and(|core| Arc::ptr_eq(&current, &core.idle_task))
        {
            return;
        }
        if update.consume_permit() {
            return;
        }
        if !update.set_sched_state(SchedState::Parking) {
            return;
        }
        drop(update);
        while current.sched_state() == SchedState::Parking {
            yield_now();
        }
    }

    unsafe fn schedule_next(
        &self,
        local: &mut LocalScheduler<'_>,
        state: *mut State,
    ) -> Option<TaskHandle> {
        let access = local.access.as_mut()?;
        let cpu_id = access.cpu_id();
        let core = self.core(cpu_id)?;
        let now_cycles = platform::cycle_counter();
        let previous_handle = local.current.as_ref().map(|task| (**task).clone());
        if let Some(previous) = local.current.as_ref() {
            let mut inner = previous.inner.try_write()?;
            unsafe { inner.update_from_context(state) };
            if previous.sched_state() == SchedState::Running
                && !Arc::ptr_eq(previous, &core.idle_task)
                && !self.domains.should_preempt(previous.domain_id(), previous)
            {
                return previous_handle;
            }
        }

        let mut selected = None;
        let mut selected_context = None;
        let mut selected_fpu = None;
        let mut selected_root = None;
        for _ in 0..TASK_TABLE_INITIAL_SLOTS {
            let Some(mut candidate) = self.domains.pick_next(access, now_cycles) else {
                break;
            };
            match candidate.sched_state() {
                SchedState::Terminated => {
                    self.handle_switch_out(
                        &mut candidate,
                        cpu_id,
                        now_cycles,
                        SwitchOutOutcome::Terminated,
                    );
                    continue;
                }
                SchedState::Runnable => {}
                _ => panic!("non-runnable task selected"),
            }
            if self.commit_pending_migration(&mut candidate, cpu_id, now_cycles) {
                let hint = candidate.target_cpu();
                self.domains.enqueue(
                    candidate.domain_id(),
                    &mut candidate,
                    EnqueueReason::Migrated,
                    hint,
                );
                continue;
            }
            let prepared = if let Some(inner) = candidate.inner.try_read() {
                let root = if candidate.is_kernel_mode() {
                    Some(kernel_address_space_root())
                } else {
                    match PROGRAM_MANAGER.try_get(inner.parent_pid) {
                        Ok(Some(program)) => {
                            program.try_read().map(|program| program.address_space_root)
                        }
                        Ok(None) => {
                            candidate.terminate();
                            None
                        }
                        Err(()) => None,
                    }
                };
                root.map(|root| (inner.context, inner.fpu_state.clone(), root))
            } else {
                None
            };
            let Some((context, fpu, root)) = prepared else {
                let hint = candidate.target_cpu();
                self.domains.enqueue(
                    candidate.domain_id(),
                    &mut candidate,
                    EnqueueReason::Preempted,
                    hint,
                );
                continue;
            };
            selected_context = Some(context);
            selected_fpu = Some(fpu);
            selected_root = Some(root);
            selected = Some(candidate);
            break;
        }

        if selected.is_none() {
            if let Some(previous) = local.current.as_mut() {
                let resume = match previous.sched_state() {
                    SchedState::Running | SchedState::Runnable => {
                        !previous.has_pending_sched_binding()
                    }
                    SchedState::Parking => previous.consume_permit(),
                    _ => false,
                };
                if resume && previous.set_sched_state(SchedState::Running) {
                    return previous_handle;
                }
                if Arc::ptr_eq(previous, &core.idle_task) {
                    return previous_handle;
                }
            }
            let idle = core.idle_task.try_update()?;
            {
                let inner = idle.inner.try_read()?;
                selected_context = Some(inner.context);
                selected_fpu = Some(inner.fpu_state.clone());
                selected_root = Some(kernel_address_space_root());
            }
            selected = Some(idle);
        }

        let mut next = selected.unwrap();
        if !next.set_sched_state(SchedState::Running) {
            self.handle_switch_out(&mut next, cpu_id, now_cycles, SwitchOutOutcome::Terminated);
            return previous_handle;
        }
        if let Some(inner) = next.inner.try_read() {
            inner.mark_scheduled_in(cpu_id, now_cycles);
        }

        let mut previous = local.current.take();
        if let Some(prev) = previous.as_mut() {
            if !Arc::ptr_eq(prev, &core.idle_task) {
                if let Some(inner) = prev.inner.try_read() {
                    inner.account_switched_out(now_cycles);
                }
                let outcome = match prev.sched_state() {
                    SchedState::Running | SchedState::Runnable => {
                        if prev.set_sched_state(SchedState::Runnable) {
                            SwitchOutOutcome::StillRunnable
                        } else {
                            SwitchOutOutcome::Terminated
                        }
                    }
                    SchedState::Parking => {
                        if prev.consume_permit() {
                            if prev.set_sched_state(SchedState::Runnable) {
                                SwitchOutOutcome::StillRunnable
                            } else {
                                SwitchOutOutcome::Terminated
                            }
                        } else if prev.set_sched_state(SchedState::Blocked) {
                            SwitchOutOutcome::Blocking
                        } else {
                            SwitchOutOutcome::Terminated
                        }
                    }
                    SchedState::Blocked => SwitchOutOutcome::Blocking,
                    SchedState::Terminated => SwitchOutOutcome::Terminated,
                };
                self.handle_switch_out(prev, cpu_id, now_cycles, outcome);
            }
        }

        unsafe { switch_address_space_root(selected_root.unwrap()) };
        self.restore_thread_local_storage(&next);
        unsafe { platform::restore_task_context(&selected_context.unwrap(), state) };
        local.return_fpu = selected_fpu;
        access.state.current = Some((*next).clone());
        core.current_is_idle
            .store(Arc::ptr_eq(&next, &core.idle_task), Ordering::Release);
        core.current_task_id
            .store(next.task_id(), Ordering::Release);
        local.current = Some(next);
        if let Some(prev) = previous.as_ref() {
            if prev.sched_state() == SchedState::Terminated {
                self.unregister_task(prev);
            }
        }
        drop(previous);
        previous_handle.filter(|task| !Arc::ptr_eq(task, &core.idle_task))
    }

    fn handle_switch_out(
        &self,
        task: &mut TaskUpdate,
        cpu_id: usize,
        now_cycles: u64,
        outcome: SwitchOutOutcome,
    ) {
        if outcome == SwitchOutOutcome::StillRunnable && task.has_pending_sched_binding() {
            if self.commit_pending_migration(task, cpu_id, now_cycles) {
                let hint = task.target_cpu();
                self.domains
                    .enqueue(task.domain_id(), task, EnqueueReason::Migrated, hint);
                return;
            }
        }
        self.domains
            .on_switch_out(task.domain_id(), task, cpu_id, now_cycles, outcome);
        if outcome == SwitchOutOutcome::Terminated
            && self
                .core(cpu_id)
                .is_none_or(|core| core.current_task_id.load(Ordering::Acquire) != task.task_id())
        {
            self.unregister_task(task);
        }
    }

    fn commit_pending_migration(
        &self,
        task: &mut TaskUpdate,
        cpu_id: usize,
        now_cycles: u64,
    ) -> bool {
        let Some(new_binding) = task.take_pending_sched_binding() else {
            return false;
        };

        self.domains.on_switch_out(
            task.domain_id(),
            task,
            cpu_id,
            now_cycles,
            SwitchOutOutcome::Migrated,
        );
        drop(task.replace_sched_binding(new_binding));
        true
    }

    #[inline(always)]
    pub fn restore_page_table(&self, task_handle: &TaskHandle) {
        if task_handle.is_kernel_mode() {
            unsafe { switch_address_space_root(kernel_address_space_root()) };
            return;
        }

        let Some(inner) = task_handle.inner.try_read() else {
            return;
        };
        let pid = inner.parent_pid;
        drop(inner);

        match PROGRAM_MANAGER.try_get(pid) {
            Ok(Some(program)) => {
                if let Some(program) = program.try_read() {
                    unsafe { switch_address_space_root(program.address_space_root) };
                }
            }
            Ok(None) => task_handle.terminate(),
            Err(()) => {}
        }
    }

    #[inline(always)]
    pub fn restore_thread_local_storage(&self, task_handle: &TaskHandle) {
        let thread_pointer = if task_handle.is_kernel_mode() {
            task_handle.tls_thread_pointer.load(Ordering::Relaxed)
        } else {
            0
        };

        // SAFETY: kernel tasks retain their KernelTls allocation in TaskInner
        // for as long as this thread pointer can be scheduled.
        unsafe { tls::activate(thread_pointer) };
    }

    pub fn maybe_balance(&self) {
        let current_tick = platform::timer_tick_count();
        self.domains.maybe_balance(current_tick);
    }

    pub fn num_cores(&self) -> usize {
        let mut count = self.num_cores.load(Ordering::Acquire);

        loop {
            if count == self.cores.len() || self.cores[count].load(Ordering::Acquire).is_null() {
                return count;
            }

            match self.num_cores.compare_exchange(
                count,
                count + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => count += 1,
                Err(actual) => count = actual,
            }
        }
    }

    pub(crate) fn new_task_placement_start(&self) -> usize {
        let n = self.num_cores();
        if n == 0 {
            0
        } else {
            self.next_task_id.load(Ordering::Relaxed) as usize % n
        }
    }

    pub(crate) fn cpu_is_idle(&self, cpu_id: usize) -> bool {
        self.core(cpu_id)
            .is_some_and(|core| core.current_is_idle.load(Ordering::Acquire))
    }

    pub(crate) fn unregister_task_from_domain(&self, task: &TaskUpdate) {
        self.unregister_task(task);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ipi_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    if platform::current_is_in_interrupt() {
        platform::end_interrupt(platform::scheduler_ipi_vector());
        return;
    }

    let _guard = InterruptGuard::new();
    if let Some(mut local) = SCHEDULER.try_local_scheduler() {
        let core = SCHEDULER
            .core(local.access.as_ref().unwrap().cpu_id())
            .unwrap();
        if local
            .current
            .as_ref()
            .is_none_or(|task| Arc::ptr_eq(task, &core.idle_task))
        {
            unsafe { local.on_timer_tick(state) };
        }
    }
    platform::end_interrupt(platform::scheduler_ipi_vector());
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yield_handler_c(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    if platform::current_is_in_interrupt() {
        return;
    }

    let _guard = InterruptGuard::new();
    if let Some(mut local) = SCHEDULER.try_local_scheduler() {
        unsafe { local.on_timer_tick(state) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ipi_eoi_only() {
    platform::end_interrupt(platform::scheduler_ipi_vector());
}

pub extern "C" fn kernel_task_end() -> ! {
    mimalloc_thread_done();

    let task = SCHEDULER.get_local_current_task().unwrap();
    task.terminate();

    loop {
        yield_now();
    }
}
