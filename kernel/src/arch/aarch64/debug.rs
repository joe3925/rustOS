use core::arch::asm;

use crate::arch::debug_transport;
use crate::machine::machine_info;
use crate::platform::{CpuPlatform, DebugPlatform, DebugTransportPlatform};

use super::platform::Aarch64Platform;
use super::serial;

const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;

pub(crate) fn poll_rx_once() {
    debug_transport::poll_rx_once(serial::try_read_byte);
}

fn metadata_sink(bytes: &[u8]) {
    debug_transport::metadata_sink(bytes, serial::try_read_byte, serial::write_metadata_bytes);
}

pub(crate) fn init_debug_metadata_transport() {
    if debug_transport::begin_initialize() {
        crate::debug_metadata::register_sink(metadata_sink);
        poll_rx_once();
    }
}

impl DebugTransportPlatform for Aarch64Platform {
    fn init_debug_metadata_transport() {
        init_debug_metadata_transport();
    }

    fn sync_debug_module_load(module_id: u32) {
        debug_transport::sync_debug_module_load(module_id, poll_rx_once);
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
