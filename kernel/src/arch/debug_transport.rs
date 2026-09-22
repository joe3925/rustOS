use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use kernel_types::irq::IrqSafeMutex;

const META_PREFIX: &[u8] = b"\x1eRUSTOS_META ";
const HELLO_COMMAND: &[u8] = b"RUSTOS_META_HELLO version=1";
const MODULE_READY_PREFIX: &[u8] = b"RUSTOS_MODULE_READY id=";
const RX_LINE_CAPACITY: usize = 128;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
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

fn parse_rx_line(mut line: &[u8]) -> RxEvent {
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    let Some(line) = line.strip_prefix(META_PREFIX) else {
        return RxEvent::None;
    };
    if line == HELLO_COMMAND {
        return RxEvent::Hello;
    }
    let Some(bytes) = line.strip_prefix(MODULE_READY_PREFIX) else {
        return RxEvent::None;
    };
    let mut value = 0u32;
    if bytes.is_empty() {
        return RxEvent::None;
    }
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return RxEvent::None;
        }
        let Some(next) = value
            .checked_mul(10)
            .and_then(|value| value.checked_add((byte - b'0') as u32))
        else {
            return RxEvent::None;
        };
        value = next;
    }
    RxEvent::ModuleReady(value)
}

pub fn begin_initialize() -> bool {
    INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

pub fn poll_rx_once(mut read_byte: impl FnMut() -> Option<u8>) {
    if !INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    let mut hello_received = false;
    let mut highest_ready = 0;
    {
        let mut rx = RX_STATE.lock();
        while let Some(byte) = read_byte() {
            if byte != b'\n' {
                rx.push(byte);
                continue;
            }
            if !rx.overflow {
                match parse_rx_line(&rx.bytes[..rx.len]) {
                    RxEvent::None => {}
                    RxEvent::Hello => hello_received = true,
                    RxEvent::ModuleReady(module_id) => {
                        highest_ready = highest_ready.max(module_id)
                    }
                }
            }
            rx.reset();
        }
    }
    if highest_ready != 0 {
        LAST_READY_MODULE.fetch_max(highest_ready, Ordering::AcqRel);
    }
    if hello_received {
        crate::debug_metadata::host_hello_received();
    }
}

pub fn metadata_sink(
    bytes: &[u8],
    read_byte: impl FnMut() -> Option<u8>,
    write_bytes: impl FnOnce(&[u8]),
) {
    poll_rx_once(read_byte);
    if !bytes.is_empty() {
        write_bytes(bytes);
    }
}

pub fn sync_debug_module_load(module_id: u32, mut poll: impl FnMut()) {
    while LAST_READY_MODULE.load(Ordering::Acquire) < module_id {
        poll();
        core::hint::spin_loop();
    }
}
