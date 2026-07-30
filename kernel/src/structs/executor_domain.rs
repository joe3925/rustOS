use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use kernel_executor::global_async::{
    DestroyExecutorDomainError, ExecutorDomain, ExecutorDomainId, ExecutorDomainStats,
    GlobalAsyncExecutor, ReplaceResizePolicyResult,
};
use kernel_types::capacity::ResizePolicyKind;
use spin::Mutex;

pub struct UserExecutorDomain {
    owner_pid: u64,
    id: ExecutorDomainId,
    domain: Arc<ExecutorDomain>,
    user_handles: AtomicUsize,
    draining: AtomicBool,
    config_lock: Mutex<()>,
}

impl UserExecutorDomain {
    pub fn new(owner_pid: u64, id: ExecutorDomainId, domain: Arc<ExecutorDomain>) -> Arc<Self> {
        Arc::new(Self {
            owner_pid,
            id,
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
        self.id
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    pub fn stats(&self) -> ExecutorDomainStats {
        let _guard = self.config_lock.lock();
        self.domain.stats()
    }

    pub fn update_config(
        &self,
        policy: Option<ResizePolicyKind>,
        max_active: Option<usize>,
    ) -> ReplaceResizePolicyResult {
        let _guard = self.config_lock.lock();
        if let Some(policy) = policy {
            let result = self.domain.replace_resize_policy(policy);
            if result != ReplaceResizePolicyResult::Changed {
                return result;
            }
        }
        if let Some(max_active) = max_active {
            self.domain.set_max_active(max_active);
        }
        ReplaceResizePolicyResult::Changed
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
        let _ = GlobalAsyncExecutor::global().destroy_executor_domain(self.id);
    }
}

impl core::fmt::Debug for UserExecutorDomain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserExecutorDomain")
            .field("owner_pid", &self.owner_pid)
            .field("id", &self.id)
            .field("draining", &self.is_draining())
            .finish_non_exhaustive()
    }
}

impl Drop for UserExecutorDomain {
    fn drop(&mut self) {
        if !self.draining.load(Ordering::Acquire) {
            match GlobalAsyncExecutor::global().destroy_executor_domain(self.id) {
                Ok(_) | Err(DestroyExecutorDomainError::StaleDomain) => {}
                Err(_) => {}
            }
        }
    }
}
