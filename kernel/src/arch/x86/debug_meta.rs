use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::instructions::port::Port;

const COM2_BASE: u16 = 0x2F8;

const UART_DATA: u16 = 0;
const UART_IER: u16 = 1;
const UART_FCR: u16 = 2;
const UART_LCR: u16 = 3;
const UART_MCR: u16 = 4;
const UART_LSR: u16 = 5;

const LCR_DLAB: u8 = 0x80;
const LCR_8N1: u8 = 0x03;
const FCR_ENABLE_CLEAR: u8 = 0xC7;
const MCR_DTR_RTS_AUX: u8 = 0x0B;
const LSR_THR_EMPTY: u8 = 0x20;
const LSR_DATA_READY: u8 = 0x01;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

fn init_once() {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    unsafe {
        Port::<u8>::new(COM2_BASE + UART_IER).write(0x00);
        Port::<u8>::new(COM2_BASE + UART_LCR).write(LCR_DLAB);
        Port::<u8>::new(COM2_BASE + UART_DATA).write(0x01); // 115200 baud
        Port::<u8>::new(COM2_BASE + UART_IER).write(0x00);
        Port::<u8>::new(COM2_BASE + UART_LCR).write(LCR_8N1);
        Port::<u8>::new(COM2_BASE + UART_FCR).write(FCR_ENABLE_CLEAR);
        Port::<u8>::new(COM2_BASE + UART_MCR).write(MCR_DTR_RTS_AUX);
    }
}

#[inline]
fn can_transmit() -> bool {
    unsafe { Port::<u8>::new(COM2_BASE + UART_LSR).read() & LSR_THR_EMPTY != 0 }
}

fn transmit_byte(byte: u8) {
    for _ in 0..100_000_usize {
        if can_transmit() {
            unsafe { Port::<u8>::new(COM2_BASE + UART_DATA).write(byte); }
            return;
        }
        core::hint::spin_loop();
    }
}

pub(crate) fn com2_write_bytes(bytes: &[u8]) {
    init_once();
    for &byte in bytes {
        if byte == b'\n' {
            transmit_byte(b'\r');
        }
        transmit_byte(byte);
    }
}

#[inline]
fn rx_ready() -> bool {
    unsafe { Port::<u8>::new(COM2_BASE + UART_LSR).read() & LSR_DATA_READY != 0 }
}

#[inline]
fn try_rx_byte() -> Option<u8> {
    if rx_ready() {
        Some(unsafe { Port::<u8>::new(COM2_BASE + UART_DATA).read() })
    } else {
        None
    }
}

// Host sends this line; kernel responds with ACK then replays the snapshot.
const HELLO_LINE: &[u8] = b"RUSTOS_META_HELLO version=1\n";
const HELLO_ACK: &[u8] = b"RUSTOS_META_HELLO_ACK version=1\n";

static HELLO_PROGRESS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static HELLO_DONE: AtomicBool = AtomicBool::new(false);

pub(crate) fn poll_rx_once() {
    if HELLO_DONE.load(Ordering::Acquire) {
        return;
    }

    while let Some(byte) = try_rx_byte() {
        let progress = HELLO_PROGRESS.load(Ordering::Relaxed);

        if byte == HELLO_LINE[progress] {
            let new_progress = progress + 1;
            HELLO_PROGRESS.store(new_progress, Ordering::Relaxed);

            if new_progress == HELLO_LINE.len() {
                HELLO_DONE.store(true, Ordering::Release);
                com2_write_bytes(HELLO_ACK);
                crate::debug_metadata::replay_snapshot();
                return;
            }
        } else {
            HELLO_PROGRESS.store(0, Ordering::Relaxed);
        }
    }
}

pub(crate) fn metadata_sink(bytes: &[u8]) {
    init_once();
    poll_rx_once();
    com2_write_bytes(bytes);
}

pub(crate) fn init_debug_metadata_transport() {
    init_once();
    crate::debug_metadata::register_sink(metadata_sink);
}
