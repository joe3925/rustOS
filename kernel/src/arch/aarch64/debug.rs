use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use kernel_types::irq::IrqSafeMutex;

use crate::machine::machine_info;
use crate::platform::{CpuPlatform, DebugPlatform, DebugTransportPlatform};

use super::platform::Aarch64Platform;
use super::serial;

const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;

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

    let Some(line) = line.strip_prefix(META_PREFIX) else {
        return RxEvent::None;
    };

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
    LAST_READY_MODULE.fetch_max(module_id, Ordering::AcqRel);
}

pub(crate) fn poll_rx_once() {
    if !INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    let mut hello_received = false;
    let mut highest_ready = 0u32;

    {
        let mut rx = RX_STATE.lock();

        while let Some(byte) = serial::try_read_byte() {
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
    poll_rx_once();

    if !bytes.is_empty() {
        serial::write_metadata_bytes(bytes);
    }
}

pub(crate) fn init_debug_metadata_transport() {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    crate::debug_metadata::register_sink(metadata_sink);

    poll_rx_once();
}

fn sync_debug_module_load(module_id: u32) {
    while LAST_READY_MODULE.load(Ordering::Acquire) < module_id {
        poll_rx_once();
        core::hint::spin_loop();
    }
}

impl DebugTransportPlatform for Aarch64Platform {
    fn init_debug_metadata_transport() {
        init_debug_metadata_transport();
    }

    fn sync_debug_module_load(module_id: u32) {
        sync_debug_module_load(module_id);
    }
}

impl DebugPlatform for Aarch64Platform {
    fn breakpoint() {
        unsafe {
            asm!("brk #0", options(nomem, nostack));
        }
    }

    fn fatal_reset() -> ! {
        if let Some(conduit) = machine_info().cpu_topology().psci_conduit {
            super::cpu::psci_call(conduit, PSCI_SYSTEM_RESET, 0, 0, 0);
        }

        <Aarch64Platform as CpuPlatform>::halt()
    }
}
