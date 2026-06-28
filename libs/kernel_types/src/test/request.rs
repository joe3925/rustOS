use alloc::{string::String, vec, vec::Vec};
use core::mem::size_of;

use crate::request::{
    DeviceControl, IoctlData, IoctlDataError, RequestPayload, type_name_stripped, type_tag,
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
    let mut data = IoctlData::from_t(payload);

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
        Err(IoctlDataError::Missing)
    );
}

#[test]
fn request_data_stores_large_payloads_on_heap_and_drops_cleanly() {
    let payload = LargePayload { words: [9; 80] };
    let mut data = IoctlData::from_t(payload);

    assert_eq!(data.len(), size_of::<LargePayload>());
    assert_eq!(data.view::<LargePayload>().unwrap().words[79], 9);

    let moved = data.require::<LargePayload>().unwrap();
    assert_eq!(moved.words[0], 9);
    assert_eq!(moved.words[79], 9);
    assert_eq!(data.require::<LargePayload>(), Err(IoctlDataError::Missing));
}

#[test]
fn request_data_vec_payload_round_trips_without_aliasing() {
    let mut data = IoctlData::from_t(vec![1u8, 2, 3, 4]);

    assert_eq!(data.view::<Vec<u8>>().unwrap().as_slice(), &[1, 2, 3, 4]);
    assert!(!data.can_take_exact::<SmallPayload>());
    assert_eq!(
        data.take_exact::<SmallPayload>(),
        Err(IoctlDataError::WrongType)
    );

    let mut owned = data.take_exact::<Vec<u8>>().unwrap();
    owned.push(5);
    assert_eq!(owned, vec![1, 2, 3, 4, 5]);
}

#[test]
fn device_control_owns_mutable_ioctl_data() {
    let mut request = DeviceControl::new_t(0x100, SmallPayload { id: 7, flags: 3 });

    assert_eq!(request.code, 0x100);
    request.data.view_mut::<SmallPayload>().unwrap().flags = 9;
    assert_eq!(request.data.view::<SmallPayload>().unwrap().flags, 9);
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
