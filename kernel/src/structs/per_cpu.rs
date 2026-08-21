use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU64};

use kernel_types::irq::PlatformCpuId;
use spin::{Mutex, Once};

#[repr(C, align(64))]
pub struct PerCpu {
    pub is_in_interrupt: AtomicBool,
    pub reserved_interrupt_pad: [u8; 0x7],
    pub reserved0: [u8; 0x50],
    pub tls_array_pointer: AtomicU64,
    pub cpu_id: Once<usize>,
    pub platform_cpu_id: Once<PlatformCpuId>,
}

pub const PERCPU_IS_IN_INTERRUPT_OFF: usize = offset_of!(PerCpu, is_in_interrupt);
pub const PERCPU_TLS_ARRAY_POINTER_OFF: usize = offset_of!(PerCpu, tls_array_pointer);

const _: () = assert!(PERCPU_IS_IN_INTERRUPT_OFF == 0);
const _: () = assert!(PERCPU_TLS_ARRAY_POINTER_OFF == 0x58);

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
        reserved_interrupt_pad: [0; 0x7],
        reserved0: [0; 0x50],
        tls_array_pointer: AtomicU64::new(0),
        cpu_id: Once::new(),
        platform_cpu_id: Once::new(),
    }));

    percpu.cpu_id.call_once(|| cpu_id);
    percpu.platform_cpu_id.call_once(|| platform_cpu_id);
    slots[cpu_id] = Some(percpu);
    percpu
}
