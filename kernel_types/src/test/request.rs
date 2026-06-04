use alloc::{string::String, vec, vec::Vec};
use core::mem::size_of;

use crate::request::{
    BorrowedHandle, DeviceControl, RequestData, RequestDataError, RequestHandle, RequestPayload,
    TraversalPolicy, type_name_stripped, type_tag,
};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, kernel_macros::RequestPayload)]
struct SmallPayload {
    id: u32,
    flags: u16,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, kernel_macros::RequestPayload)]
struct LargePayload {
    words: [u64; 80],
}

#[test]
fn request_data_stores_small_payloads_inline_and_moves_them_out_once() {
    let payload = SmallPayload {
        id: 0xAABB_CCDD,
        flags: 0x55AA,
    };
    let mut data = RequestData::from_t(payload);

    assert_eq!(data.len(), size_of::<SmallPayload>());
    assert_eq!(data.get_type_tag(), Some(SmallPayload::RUNTIME_TAG));
    assert_eq!(data.view::<SmallPayload>().unwrap().id, 0xAABB_CCDD);
    assert!(data.can_take_exact::<SmallPayload>());

    let moved = data.take_exact::<SmallPayload>().unwrap();
    assert_eq!(
        moved,
        SmallPayload {
            id: 0xAABB_CCDD,
            flags: 0x55AA,
        }
    );
    assert_eq!(
        data.take_exact::<SmallPayload>(),
        Err(RequestDataError::Missing)
    );
}

#[test]
fn request_data_stores_large_payloads_on_heap_and_drops_cleanly() {
    let payload = LargePayload { words: [9; 80] };
    let mut data = RequestData::from_t(payload);

    assert_eq!(data.len(), size_of::<LargePayload>());
    assert_eq!(data.view::<LargePayload>().unwrap().words[79], 9);

    let moved = data.require::<LargePayload>().unwrap();
    assert_eq!(moved.words[0], 9);
    assert_eq!(moved.words[79], 9);
    assert_eq!(
        data.require::<LargePayload>(),
        Err(RequestDataError::Missing)
    );
}

#[test]
fn request_data_vec_payload_round_trips_without_aliasing() {
    let mut data = RequestData::from_t(vec![1u8, 2, 3, 4]);

    assert_eq!(data.view::<Vec<u8>>().unwrap().as_slice(), &[1, 2, 3, 4]);
    assert!(!data.can_take_exact::<SmallPayload>());
    assert_eq!(
        data.take_exact::<SmallPayload>(),
        Err(RequestDataError::WrongType)
    );

    let mut owned = data.take_exact::<Vec<u8>>().unwrap();
    owned.push(5);
    assert_eq!(owned, vec![1, 2, 3, 4, 5]);
}

#[test]
fn borrowed_read_only_slice_cannot_be_mutated_or_consumed() {
    let bytes = [4u8, 5, 6, 7];
    let mut handle = RequestHandle::new(DeviceControl::new(0, RequestData::empty()));

    {
        let mut borrowed = BorrowedHandle::<_, [u8]>::read_only(&mut handle, &bytes);
        let view = borrowed.handle().data().read_only();
        assert_eq!(view.view::<[u8]>().unwrap(), &[4, 5, 6, 7]);
        assert!(!view.can_take_exact::<Vec<u8>>());
    }

    assert!(handle.data().read_only().view::<[u8]>().is_none());
}

#[test]
fn borrowed_writable_slice_exposes_mut_view_and_is_cleared_on_drop() {
    let mut bytes = [1u8, 2, 3];
    let mut handle = RequestHandle::new(DeviceControl::new(0, RequestData::empty()));

    {
        let mut borrowed = BorrowedHandle::<_, [u8]>::writable(&mut handle, &mut bytes);
        let mut view = borrowed.handle().data().try_writable().unwrap();
        let slice = view.view_mut::<[u8]>().unwrap();
        slice[1] = 9;
        assert_eq!(view.read_only().view::<[u8]>().unwrap(), &[1, 9, 3]);
    }

    assert!(handle.data().read_only().view::<[u8]>().is_none());
    drop(handle);
    assert_eq!(bytes, [1, 9, 3]);
}

#[test]
fn request_handle_owns_request_state_and_data_view() {
    let mut handle = RequestHandle::new(DeviceControl::new_t(
        0x100,
        SmallPayload { id: 7, flags: 3 },
    ));

    assert!(handle.is_owned());
    assert!(!handle.is_stack());
    assert_eq!(handle.status(), crate::status::DriverStatus::ContinueStep);
    assert_eq!(
        handle.read().traversal_policy,
        TraversalPolicy::FailIfUnhandled
    );
    assert_eq!(handle.read().body.code, 0x100);

    handle.set_traversal_policy(TraversalPolicy::ForwardLower);
    assert_eq!(
        handle.read().traversal_policy,
        TraversalPolicy::ForwardLower
    );

    let view = handle.data().try_writable().unwrap();
    assert_eq!(view.view::<SmallPayload>().unwrap().flags, 3);
}

#[test]
fn type_tags_ignore_outer_borrows_and_lifetimes() {
    assert_eq!(type_tag::<SmallPayload>(), type_tag::<&SmallPayload>());
    assert_eq!(type_tag::<SmallPayload>(), type_tag::<&mut SmallPayload>());

    let stripped = type_name_stripped::<&'static mut SmallPayload>();
    assert!(!stripped.contains('&'));
    assert!(!stripped.contains("'static"));
    assert!(stripped.ends_with("SmallPayload"));
}

#[test]
fn str_and_slice_raw_parts_rebuild_valid_views() {
    let text = String::from("kernel");
    let parts = <str as RequestPayload<'_>>::shared_raw_parts(text.as_str());
    let rebuilt = unsafe { <str as RequestPayload<'_>>::shared_from_raw_parts(parts) };
    assert_eq!(rebuilt, "kernel");

    let mut bytes = [10u8, 20, 30];
    let parts = <[u8] as RequestPayload<'_>>::mut_raw_parts(&mut bytes);
    let rebuilt = unsafe { <[u8] as RequestPayload<'_>>::mut_from_raw_parts(parts) };
    rebuilt[2] = 99;
    assert_eq!(bytes, [10, 20, 99]);
}
