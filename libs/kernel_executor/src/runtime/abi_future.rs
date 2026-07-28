use kernel_types::async_ffi::AbiFutureAllocation;

use crate::future_arena::FutureArena;
use crate::global_async::{ExecutorDomainId, GlobalAsyncExecutor};
use crate::platform::current_executor_context;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_abi_future_allocate(size: usize, align: usize) -> AbiFutureAllocation {
    let Some(context) = current_executor_context() else {
        return AbiFutureAllocation::null();
    };
    let domain_id = ExecutorDomainId::from_raw(context.domain_id);
    let Some(domain) = GlobalAsyncExecutor::global().get_executor_domain(domain_id) else {
        return AbiFutureAllocation::null();
    };
    domain
        .future_arena()
        .allocate(size, align)
        .map(FutureArena::into_abi)
        .unwrap_or_else(AbiFutureAllocation::null)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_abi_future_free(allocation: AbiFutureAllocation) {
    let domain_id = ExecutorDomainId::from_raw(allocation.owner_domain);
    let domain = GlobalAsyncExecutor::global()
        .get_executor_domain(domain_id)
        .expect("ABI future owner domain is invalid");
    assert!(
        domain.future_arena().release_abi(allocation),
        "invalid or stale ABI future allocation token"
    );
    domain.maybe_finish_draining();
}
