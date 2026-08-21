use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::machine::machine_info;
use crate::platform::{CpuPlatform, DebugPlatform, DebugTransportPlatform};

use super::platform::Aarch64Platform;

const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const HELLO_LINE: &[u8] = b"RUSTOS_META_HELLO version=1\n";

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static HELLO_PROGRESS: AtomicUsize = AtomicUsize::new(0);
static HELLO_DONE: AtomicBool = AtomicBool::new(false);

fn transmit_byte(byte: u8) {
    for _ in 0..100_000_usize {
        if super::serial::try_write_byte(byte) {
            return;
        }
        core::hint::spin_loop();
    }
}

fn write_bytes(bytes: &[u8]) {
    for &byte in bytes {
        if byte == b'\n' {
            transmit_byte(b'\r');
        }
        transmit_byte(byte);
    }
}

pub(crate) fn poll_rx_once() {
    if !INITIALIZED.load(Ordering::Acquire) || HELLO_DONE.load(Ordering::Acquire) {
        return;
    }

    while let Some(byte) = super::serial::try_read_byte() {
        let progress = HELLO_PROGRESS.load(Ordering::Relaxed);
        if byte == HELLO_LINE[progress] {
            let new_progress = progress + 1;
            HELLO_PROGRESS.store(new_progress, Ordering::Relaxed);
            if new_progress == HELLO_LINE.len() {
                HELLO_DONE.store(true, Ordering::Release);
                crate::debug_metadata::host_hello_received();
                return;
            }
        } else {
            HELLO_PROGRESS.store(0, Ordering::Relaxed);
        }
    }
}

fn metadata_sink(bytes: &[u8]) {
    poll_rx_once();
    if !bytes.is_empty() {
        write_bytes(bytes);
    }
}

pub(crate) fn init_debug_metadata_transport() {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        crate::debug_metadata::register_sink(metadata_sink);
    }
}

impl DebugTransportPlatform for Aarch64Platform {
    fn init_debug_metadata_transport() {
        init_debug_metadata_transport();
    }
}

impl DebugPlatform for Aarch64Platform {
    fn breakpoint() {
        unsafe { asm!("brk #0", options(nomem, nostack)) };
    }

    fn fatal_reset() -> ! {
        if let Some(conduit) = machine_info().cpu_topology().psci_conduit {
            super::cpu::psci_call(conduit, PSCI_SYSTEM_RESET, 0, 0, 0);
        }
        <Aarch64Platform as CpuPlatform>::halt()
    }
}
