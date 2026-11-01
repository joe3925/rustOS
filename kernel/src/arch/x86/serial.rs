use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync_platform::IrqSafeMutex;
use x86_64::instructions::port::Port;

use crate::platform::ConsolePlatform;

use super::platform::X86Platform;

const COM1: u16 = 0x3f8;
const META_PREFIX: &[u8] = b"\x1eRUSTOS_META ";
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static WRITE_LOCK: IrqSafeMutex<()> = IrqSafeMutex::new(());

pub(crate) fn init_once() {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    #[cfg_attr(irq_check, irq::allow_incomplete(unsafe))]
    unsafe {
        Port::<u8>::new(COM1 + 1).write(0x00);
        Port::<u8>::new(COM1 + 3).write(0x80);
        Port::<u8>::new(COM1).write(0x03);
        Port::<u8>::new(COM1 + 1).write(0x00);
        Port::<u8>::new(COM1 + 3).write(0x03);
        Port::<u8>::new(COM1 + 2).write(0xc7);
        Port::<u8>::new(COM1 + 4).write(0x0b);
    }
}

#[inline]
fn can_transmit() -> bool {
    #[cfg_attr(irq_check, irq::allow_incomplete(unsafe))]
    unsafe { Port::<u8>::new(COM1 + 5).read() & 0x20 != 0 }
}

fn write_byte(byte: u8) {
    for _ in 0..100_000 {
        if can_transmit() {
            #[cfg_attr(irq_check, irq::allow_incomplete(unsafe))]
            unsafe {
                Port::<u8>::new(COM1).write(byte);
            }
            return;
        }
        core::hint::spin_loop();
    }
}

impl ConsolePlatform for X86Platform {
    fn serial_write_bytes(bytes: &[u8]) {
        super::debug::poll_rx_once();
        let _guard = WRITE_LOCK.lock();
        init_once();
        for &byte in bytes {
            if byte == b'\n' {
                write_byte(b'\r');
            }
            write_byte(byte);
        }
    }
}

pub(crate) fn try_read_byte() -> Option<u8> {
    init_once();

    let ready = {
        #[cfg_attr(irq_check, irq::allow_incomplete(unsafe))]
        unsafe { Port::<u8>::new(COM1 + 5).read() & 0x01 != 0 }
    };
    if ready {
        let byte = {
            #[cfg_attr(irq_check, irq::allow_incomplete(unsafe))]
            unsafe { Port::<u8>::new(COM1).read() }
        };
        Some(byte)
    } else {
        None
    }
}

pub(crate) fn write_metadata_bytes(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }

    let _guard = WRITE_LOCK.lock();
    init_once();
    let mut start = 0;

    for (index, &byte) in bytes.iter().enumerate() {
        if byte != b'\n' {
            continue;
        }

        for &byte in META_PREFIX.iter().chain(bytes[start..=index].iter()) {
            write_byte(byte);
        }

        start = index + 1;
    }

    if start < bytes.len() {
        for &byte in META_PREFIX.iter().chain(bytes[start..].iter()) {
            write_byte(byte);
        }
    }
}
