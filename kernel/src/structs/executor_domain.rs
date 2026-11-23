use crate::scheduling::runtime::runtime::KernelExecutorPlatform;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use kernel_executor::global_async::{
    DestroyExecutorDomainError, ExecutorDomain, ExecutorDomainId, ExecutorDomainInfo,
    GlobalAsyncExecutor,
};
use spin::Mutex;

pub(crate) const DEFAULT_PROCESS_IO_WEIGHT: usize = 24;

pub struct UserExecutorDomain {
    owner_pid: u64,
    pub(crate) domain: Arc<ExecutorDomain<KernelExecutorPlatform>>,
    user_handles: AtomicUsize,
    draining: AtomicBool,
    config_lock: Mutex<()>,
}

impl UserExecutorDomain {
    pub fn new(
        owner_pid: u64,
        domain: Arc<ExecutorDomain<KernelExecutorPlatform>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            owner_pid,
            domain,
            user_handles: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
            config_lock: Mutex::new(()),
        })
    }

    pub fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    pub fn id(&self) -> ExecutorDomainId {
        self.domain.id()
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    pub fn info(&self) -> ExecutorDomainInfo {
        let _guard = self.config_lock.lock();
        self.domain.info()
    }

    pub fn update_config(&self, weight: usize) {
        let _guard = self.config_lock.lock();
        self.domain.set_weight(weight);
    }

    pub fn user_handle_opened(&self) {
        self.user_handles.fetch_add(1, Ordering::AcqRel);
    }

    pub fn user_handle_closed(&self) {
        let previous = self.user_handles.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous != 0, "executor-domain user handle underflow");
        if previous == 1 {
            self.begin_draining();
        }
    }

    pub fn begin_draining(&self) {
        if self.draining.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = GlobalAsyncExecutor::<KernelExecutorPlatform>::global()
            .destroy_executor_domain(self.domain.id());
    }
}

impl core::fmt::Debug for UserExecutorDomain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserExecutorDomain")
            .field("owner_pid", &self.owner_pid)
            .field("id", &self.domain.id())
            .field("draining", &self.is_draining())
            .finish_non_exhaustive()
    }
}

impl Drop for UserExecutorDomain {
    fn drop(&mut self) {
        if !self.draining.load(Ordering::Acquire) {
            match GlobalAsyncExecutor::<KernelExecutorPlatform>::global().destroy_executor_domain(self.domain.id()) {
                Ok(_) | Err(DestroyExecutorDomainError::StaleDomain) => {}
                Err(_) => {}
            }
        }
    }
}
