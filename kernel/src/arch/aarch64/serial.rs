use crate::platform::ConsolePlatform;

use super::platform::Aarch64Platform;

const UART_BASE: usize = 0x0900_0000;
const UART_DATA: usize = 0;
const UART_FLAGS: usize = 6;
const UART_RX_EMPTY: u32 = 1 << 4;
const UART_TX_FULL: u32 = 1 << 5;

#[inline]
fn register(index: usize) -> *mut u32 {
    (UART_BASE as *mut u32).wrapping_add(index)
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
    fn serial_write_bytes(bytes: &[u8]) {
        for &byte in bytes {
            write_byte(byte);
        }
    }
}
