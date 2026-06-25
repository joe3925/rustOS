use core::sync::atomic::{AtomicBool, Ordering};

use x86_64::instructions::port::Port;

const COM1: u16 = 0x3f8;
static INITIALIZED: AtomicBool = AtomicBool::new(false);

fn init_once() {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

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
    unsafe { Port::<u8>::new(COM1 + 5).read() & 0x20 != 0 }
}

fn write_byte(byte: u8) {
    for _ in 0..100_000 {
        if can_transmit() {
            unsafe {
                Port::<u8>::new(COM1).write(byte);
            }
            return;
        }
        core::hint::spin_loop();
    }
}

pub(crate) fn write_bytes(bytes: &[u8]) {
    init_once();
    for &byte in bytes {
        if byte == b'\n' {
            write_byte(b'\r');
        }
        write_byte(byte);
    }
}
