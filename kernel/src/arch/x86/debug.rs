use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use kernel_types::irq::IrqSafeMutex;
use x86_64::instructions::port::Port;
use x86_64::structures::idt::InterruptDescriptorTable;

use crate::platform::{DebugPlatform, DebugTransportPlatform};

use super::platform::X86Platform;

const COM2_BASE: u16 = 0x2f8;

const UART_DATA: u16 = 0;
const UART_IER: u16 = 1;
const UART_FCR: u16 = 2;
const UART_LCR: u16 = 3;
const UART_MCR: u16 = 4;
const UART_LSR: u16 = 5;

const LCR_DLAB: u8 = 0x80;
const LCR_8N1: u8 = 0x03;
const FCR_ENABLE_CLEAR: u8 = 0xc7;
const MCR_DTR_RTS_AUX: u8 = 0x0b;

const LSR_THR_EMPTY: u8 = 0x20;
const LSR_DATA_READY: u8 = 0x01;

const HELLO_COMMAND: &[u8] = b"RUSTOS_META_HELLO version=1";
const MODULE_READY_PREFIX: &[u8] = b"RUSTOS_MODULE_READY id=";

const RX_LINE_CAPACITY: usize = 128;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static AVAILABLE: AtomicBool = AtomicBool::new(false);
static LAST_READY_MODULE: AtomicU32 = AtomicU32::new(0);

struct RxState {
    bytes: [u8; RX_LINE_CAPACITY],
    len: usize,
    overflow: bool,
}

impl RxState {
    const fn new() -> Self {
        Self {
            bytes: [0; RX_LINE_CAPACITY],
            len: 0,
            overflow: false,
        }
    }

    fn reset(&mut self) {
        self.len = 0;
        self.overflow = false;
    }

    fn push(&mut self, byte: u8) {
        if self.overflow {
            return;
        }

        if self.len == self.bytes.len() {
            self.overflow = true;
            return;
        }

        self.bytes[self.len] = byte;
        self.len += 1;
    }
}

static RX_STATE: IrqSafeMutex<RxState> = IrqSafeMutex::new(RxState::new());

enum RxEvent {
    None,
    Hello,
    ModuleReady(u32),
}

fn init_once() {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    unsafe {
        if Port::<u8>::new(COM2_BASE + UART_LSR).read() == 0xff {
            return;
        }

        Port::<u8>::new(COM2_BASE + UART_IER).write(0x00);

        Port::<u8>::new(COM2_BASE + UART_LCR).write(LCR_DLAB);
        Port::<u8>::new(COM2_BASE + UART_DATA).write(0x01);
        Port::<u8>::new(COM2_BASE + UART_IER).write(0x00);

        Port::<u8>::new(COM2_BASE + UART_LCR).write(LCR_8N1);
        Port::<u8>::new(COM2_BASE + UART_FCR).write(FCR_ENABLE_CLEAR);
        Port::<u8>::new(COM2_BASE + UART_MCR).write(MCR_DTR_RTS_AUX);
    }

    AVAILABLE.store(true, Ordering::Release);
}

#[inline]
fn can_transmit() -> bool {
    unsafe { Port::<u8>::new(COM2_BASE + UART_LSR).read() & LSR_THR_EMPTY != 0 }
}

fn transmit_byte(byte: u8) {
    for _ in 0..100_000_usize {
        if can_transmit() {
            unsafe {
                Port::<u8>::new(COM2_BASE + UART_DATA).write(byte);
            }

            return;
        }

        core::hint::spin_loop();
    }
}

fn write_bytes(bytes: &[u8]) {
    init_once();

    if !AVAILABLE.load(Ordering::Acquire) {
        return;
    }

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

fn parse_decimal_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }

    let mut value = 0u32;

    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }

        value = value.checked_mul(10)?.checked_add((byte - b'0') as u32)?;
    }

    Some(value)
}

fn parse_rx_line(mut line: &[u8]) -> RxEvent {
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }

    if line == HELLO_COMMAND {
        return RxEvent::Hello;
    }

    let Some(id) = line
        .strip_prefix(MODULE_READY_PREFIX)
        .and_then(parse_decimal_u32)
    else {
        return RxEvent::None;
    };

    RxEvent::ModuleReady(id)
}

fn mark_module_ready(module_id: u32) {
    let mut current = LAST_READY_MODULE.load(Ordering::Acquire);

    while module_id > current {
        match LAST_READY_MODULE.compare_exchange_weak(
            current,
            module_id,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

pub(crate) fn poll_rx_once() {
    if !AVAILABLE.load(Ordering::Acquire) {
        return;
    }

    let mut hello_received = false;
    let mut highest_ready = 0u32;

    {
        let mut rx = RX_STATE.lock();

        while let Some(byte) = try_rx_byte() {
            if byte != b'\n' {
                rx.push(byte);
                continue;
            }

            if !rx.overflow {
                match parse_rx_line(&rx.bytes[..rx.len]) {
                    RxEvent::None => {}
                    RxEvent::Hello => {
                        hello_received = true;
                    }
                    RxEvent::ModuleReady(module_id) => {
                        highest_ready = highest_ready.max(module_id);
                    }
                }
            }

            rx.reset();
        }
    }

    if highest_ready != 0 {
        mark_module_ready(highest_ready);
    }

    if hello_received {
        crate::debug_metadata::host_hello_received();
    }
}

fn metadata_sink(bytes: &[u8]) {
    init_once();

    if !AVAILABLE.load(Ordering::Acquire) {
        return;
    }

    poll_rx_once();

    if !bytes.is_empty() {
        write_bytes(bytes);
    }
}

fn sync_debug_module_load(module_id: u32) {
    init_once();

    if !AVAILABLE.load(Ordering::Acquire) {
        return;
    }

    while LAST_READY_MODULE.load(Ordering::Acquire) < module_id {
        poll_rx_once();
        core::hint::spin_loop();
    }
}

impl DebugTransportPlatform for X86Platform {
    fn init_debug_metadata_transport() {
        init_once();

        if AVAILABLE.load(Ordering::Acquire) {
            crate::debug_metadata::register_sink(metadata_sink);
        }
    }

    fn sync_debug_module_load(module_id: u32) {
        sync_debug_module_load(module_id);
    }
}

impl DebugPlatform for X86Platform {
    fn breakpoint() {
        unsafe {
            asm!("int 3");
        }
    }

    fn fatal_reset() -> ! {
        static EMPTY_IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

        unsafe {
            EMPTY_IDT.load();
            asm!("ud2", options(noreturn));
        }
    }
}
