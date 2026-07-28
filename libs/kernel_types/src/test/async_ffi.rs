use crate::async_ffi::{AbiFutureAllocation, AbiPoll};

#[test]
fn abi_poll_has_stable_discriminants() {
    assert_eq!(AbiPoll::Pending as u8, 0);
    assert_eq!(AbiPoll::Ready as u8, 1);
}

#[test]
fn null_allocation_is_unambiguously_invalid() {
    let allocation = AbiFutureAllocation::null();
    assert!(allocation.ptr.is_null());
    assert_eq!(allocation.owner_domain, 0);
    assert_eq!(allocation.token, 0);
}
