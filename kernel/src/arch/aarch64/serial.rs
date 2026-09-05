use crate::platform::ConsolePlatform;
use core::sync::atomic::{AtomicUsize, Ordering};
use kernel_types::arch::PhysAddr;
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;

use super::platform::Aarch64Platform;

const UART_BASE: usize = 0x0900_0000;
const UART_MAPPING_SIZE: u64 = 0x1000;
const UART_DATA: usize = 0;
const UART_FLAGS: usize = 6;
const UART_RX_EMPTY: u32 = 1 << 4;
const UART_TX_FULL: u32 = 1 << 5;
static UART_VIRT_BASE: AtomicUsize = AtomicUsize::new(UART_BASE);

#[inline]
fn register(index: usize) -> *mut u32 {
    (UART_VIRT_BASE.load(Ordering::Relaxed) as *mut u32).wrapping_add(index)
}

pub(crate) fn write_byte(byte: u8) {
    while !try_write_byte(byte) {
        core::hint::spin_loop();
    }
}

pub(crate) fn try_write_byte(byte: u8) -> bool {
    if unsafe { register(UART_FLAGS).read_volatile() } & UART_TX_FULL != 0 {
        false
    } else {
        unsafe { register(UART_DATA).write_volatile(byte as u32) };
        true
    }
}

pub(crate) fn try_read_byte() -> Option<u8> {
    if unsafe { register(UART_FLAGS).read_volatile() } & UART_RX_EMPTY != 0 {
        None
    } else {
        Some(unsafe { register(UART_DATA).read_volatile() as u8 })
    }
}

impl ConsolePlatform for Aarch64Platform {
    fn init_early_serial_mapping() -> Result<(), PageMapError> {
        let mapped = crate::memory::paging::mmio::map_physical_pages(
            PhysAddr::new(UART_BASE as u64),
            UART_MAPPING_SIZE,
            PhysicalMappingCache::Uncached,
        )?;
        UART_VIRT_BASE.store(mapped.as_u64() as usize, Ordering::Release);
        Ok(())
    }

    fn serial_write_bytes(bytes: &[u8]) {
        for &byte in bytes {
            write_byte(byte);
        }
    }
}
