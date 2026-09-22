use core::arch::asm;

use x86_64::structures::idt::InterruptDescriptorTable;

use crate::arch::debug_transport;
use crate::platform::{DebugPlatform, DebugTransportPlatform};

use super::platform::X86Platform;
use super::serial;

pub(crate) fn poll_rx_once() {
    debug_transport::poll_rx_once(serial::try_read_byte);
}

fn metadata_sink(bytes: &[u8]) {
    debug_transport::metadata_sink(bytes, serial::try_read_byte, serial::write_metadata_bytes);
}

impl DebugTransportPlatform for X86Platform {
    fn init_debug_metadata_transport() {
        if debug_transport::begin_initialize() {
            serial::init_once();
            crate::debug_metadata::register_sink(metadata_sink);
            poll_rx_once();
        }
    }

    fn sync_debug_module_load(module_id: u32) {
        debug_transport::sync_debug_module_load(module_id, poll_rx_once);
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
