use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU64};

use kernel_types::irq::PlatformCpuId;
use spin::{Mutex, Once};

#[repr(C, align(64))]
pub struct PerCpu {
    pub is_in_interrupt: AtomicBool,
    pub reserved_interrupt_pad: [u8; 7],
    pub self_pointer: usize,
    pub mimalloc_heap: AtomicU64,
    pub reserved0: [u8; 0x40],

    pub tls_array_pointer: AtomicU64,
    pub exception_stack_top: AtomicU64,

    pub active_exception_fpu: AtomicU64,

    pub cpu_id: Once<usize>,
    pub platform_cpu_id: Once<PlatformCpuId>,
}

pub const PERCPU_IS_IN_INTERRUPT_OFF: usize = offset_of!(PerCpu, is_in_interrupt);
pub const PERCPU_SELF_POINTER_OFF: usize = offset_of!(PerCpu, self_pointer);
pub const PERCPU_MIMALLOC_HEAP_OFF: usize = offset_of!(PerCpu, mimalloc_heap);
pub const PERCPU_TLS_ARRAY_POINTER_OFF: usize = offset_of!(PerCpu, tls_array_pointer);
pub const PERCPU_EXCEPTION_STACK_TOP_OFF: usize = offset_of!(PerCpu, exception_stack_top);
pub const PERCPU_ACTIVE_EXCEPTION_FPU_OFF: usize = offset_of!(PerCpu, active_exception_fpu);

const _: () = {
    assert!(PERCPU_IS_IN_INTERRUPT_OFF == 0);
    assert!(PERCPU_MIMALLOC_HEAP_OFF == 0x10);
    assert!(PERCPU_TLS_ARRAY_POINTER_OFF == 0x58);
    assert!(PERCPU_EXCEPTION_STACK_TOP_OFF == 0x60);
    assert!(PERCPU_ACTIVE_EXCEPTION_FPU_OFF == 0x68);
};

static PERCPU_SLOTS: Mutex<Vec<Option<&'static PerCpu>>> = Mutex::new(Vec::new());

pub fn alloc_or_get_percpu(cpu_id: usize, platform_cpu_id: PlatformCpuId) -> &'static PerCpu {
    let mut slots = PERCPU_SLOTS.lock();

    if slots.len() <= cpu_id {
        slots.resize_with(cpu_id + 1, || None);
    }

    if let Some(percpu) = slots[cpu_id] {
        assert_eq!(percpu.platform_cpu_id.get().copied(), Some(platform_cpu_id));
        return percpu;
    }

    let percpu = Box::leak(Box::new(PerCpu {
        is_in_interrupt: AtomicBool::new(false),
        reserved_interrupt_pad: [0; 7],
        self_pointer: 0,
        mimalloc_heap: AtomicU64::new(0),
        reserved0: [0; 0x40],

        tls_array_pointer: AtomicU64::new(0),
        exception_stack_top: AtomicU64::new(0),
        active_exception_fpu: AtomicU64::new(0),

        cpu_id: Once::new(),
        platform_cpu_id: Once::new(),
    }));

    percpu.self_pointer = core::ptr::from_ref(&*percpu).expose_provenance();
    percpu.cpu_id.call_once(|| cpu_id);
    percpu.platform_cpu_id.call_once(|| platform_cpu_id);

    slots[cpu_id] = Some(percpu);
    percpu
}

pub fn percpu_by_id(cpu_id: usize) -> Option<&'static PerCpu> {
    PERCPU_SLOTS.lock().get(cpu_id).copied().flatten()
}
