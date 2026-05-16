use crate::runtime::slab::{
    decode_joinable_slab_ptr, decode_slab_ptr, encode_joinable_slab_ptr, encode_slab_ptr,
    is_joinable_slab_ptr, is_slab_ptr, slab_stats, SlabConfigBuilder,
};

#[test]
fn slab_config_builder_clamps_capacity_and_preserves_fallback_policy() {
    let config = SlabConfigBuilder::new().capacity(1).fallback(false).build();

    assert!(config.slots_per_shard >= 64);
    assert!(!config.allow_fallback);

    let config = SlabConfigBuilder::new().slots_per_shard(usize::MAX).build();
    assert!(config.slots_per_shard <= 4096);
}

#[test]
fn slab_pointer_encoding_keeps_detached_and_joinable_namespaces_separate() {
    let detached = encode_slab_ptr(3, 0x0FFE, 0x1_2345);
    assert!(is_slab_ptr(detached));
    assert!(!is_joinable_slab_ptr(detached));
    assert_eq!(decode_slab_ptr(detached), Some((3, 0x0FFE, 0x2345)));
    assert_eq!(decode_joinable_slab_ptr(detached), None);

    let joinable = encode_joinable_slab_ptr(7, 0x0ABC, 0xCAFE);
    assert!(is_slab_ptr(joinable));
    assert!(is_joinable_slab_ptr(joinable));
    assert_eq!(
        decode_joinable_slab_ptr(joinable),
        Some((7, 0x0ABC, 0xCAFE))
    );
    assert_eq!(decode_slab_ptr(joinable), None);
}

#[test]
fn global_slab_stats_are_readable_after_default_initialization() {
    let _guard = super::global_runtime_lock();
    super::init_inline_runtime();

    let stats = slab_stats();
    assert!(stats.total_capacity >= 64);
    assert!(stats.currently_allocated <= stats.total_capacity);
}
