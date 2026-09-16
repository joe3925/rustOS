use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use device_tree::DeviceTree;
use kernel_types::arch::PhysAddr;
use kernel_types::memory::PhysicalMappingCache;

use crate::machine::machine_info;
use crate::platform::{CpuPlatform, DebugPlatform, DebugTransportPlatform};
use crate::util::boot_info;

use super::platform::Aarch64Platform;

const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const HELLO_LINE: &[u8] = b"RUSTOS_META_HELLO version=1\n";

// QEMU virt:
//   UART0 / normal console = 0x0900_0000
//   UART1 / metadata       = 0x0904_0000
const META_UART_BASE: usize = 0x0904_0000;
const META_UART_MAPPING_SIZE: u64 = 0x1000;

// ARM PL011 register offsets.
const UART_DR: usize = 0x000;
const UART_FR: usize = 0x018;
const UART_IBRD: usize = 0x024;
const UART_FBRD: usize = 0x028;
const UART_LCR_H: usize = 0x02c;
const UART_CR: usize = 0x030;
const UART_ICR: usize = 0x044;

// UART_FR bits.
const UART_FR_RXFE: u32 = 1 << 4;
const UART_FR_TXFF: u32 = 1 << 5;

// UART_LCR_H bits.
const UART_LCR_H_FEN: u32 = 1 << 4;
const UART_LCR_H_WLEN_8: u32 = 0b11 << 5;

// UART_CR bits.
const UART_CR_UARTEN: u32 = 1 << 0;
const UART_CR_TXE: u32 = 1 << 8;
const UART_CR_RXE: u32 = 1 << 9;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static AVAILABLE: AtomicBool = AtomicBool::new(false);
static HELLO_PROGRESS: AtomicUsize = AtomicUsize::new(0);
static HELLO_DONE: AtomicBool = AtomicBool::new(false);

static META_UART_VIRT_BASE: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
fn register(offset: usize) -> *mut u32 {
    (META_UART_VIRT_BASE.load(Ordering::Relaxed) + offset) as *mut u32
}

#[inline(always)]
fn read_reg(offset: usize) -> u32 {
    unsafe { register(offset).read_volatile() }
}

#[inline(always)]
fn write_reg(offset: usize, value: u32) {
    unsafe {
        register(offset).write_volatile(value);
    }
}

fn init_uart() {
    write_reg(UART_CR, 0);

    write_reg(UART_ICR, 0x7ff);

    write_reg(UART_IBRD, 13);
    write_reg(UART_FBRD, 1);

    write_reg(UART_LCR_H, UART_LCR_H_WLEN_8 | UART_LCR_H_FEN);

    write_reg(UART_CR, UART_CR_UARTEN | UART_CR_TXE | UART_CR_RXE);

    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}

#[inline(always)]
fn try_write_byte(byte: u8) -> bool {
    if !AVAILABLE.load(Ordering::Acquire) {
        return false;
    }

    if read_reg(UART_FR) & UART_FR_TXFF != 0 {
        return false;
    }

    write_reg(UART_DR, byte as u32);
    true
}

#[inline(always)]
fn try_read_byte() -> Option<u8> {
    if !AVAILABLE.load(Ordering::Acquire) {
        return None;
    }

    if read_reg(UART_FR) & UART_FR_RXFE != 0 {
        None
    } else {
        Some(read_reg(UART_DR) as u8)
    }
}

fn transmit_byte(byte: u8) {
    for _ in 0..100_000_usize {
        if try_write_byte(byte) {
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
    if !INITIALIZED.load(Ordering::Acquire)
        || !AVAILABLE.load(Ordering::Acquire)
        || HELLO_DONE.load(Ordering::Acquire)
    {
        return;
    }

    while let Some(byte) = try_read_byte() {
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
            let new_progress = if byte == HELLO_LINE[0] { 1 } else { 0 };
            HELLO_PROGRESS.store(new_progress, Ordering::Relaxed);
        }
    }
}

fn metadata_sink(bytes: &[u8]) {
    if !AVAILABLE.load(Ordering::Acquire) {
        return;
    }

    poll_rx_once();

    if !bytes.is_empty() {
        write_bytes(bytes);
    }
}

pub(crate) fn init_debug_metadata_transport() {
    let Some(header_ptr) = boot_info().fdt_header.into_option() else {
        return;
    };
    let header = unsafe { &*header_ptr.cast::<kernel_types::fdt::FdtHeader>() };
    if header.magic() != kernel_types::fdt::FdtHeader::MAGIC {
        return;
    }
    let blob = unsafe {
        core::slice::from_raw_parts(
            header as *const _ as *const u8,
            header.total_size() as usize,
        )
    };
    let Ok(tree) = DeviceTree::load(blob) else {
        return;
    };
    let Some(uart) = tree.find("/pl011@9040000") else {
        return;
    };
    if !uart.prop_raw("compatible").is_some_and(|value| {
        value
            .split(|byte| *byte == 0)
            .any(|part| part == b"arm,pl011")
    }) || matches!(uart.prop_str("status").ok(), Some("disabled" | "fail" | "failed"))
    {
        return;
    }
    let Some(reg) = uart.prop_raw("reg") else {
        return;
    };
    let Some(address) = reg
        .get(0..8)
        .and_then(|value| <[u8; 8]>::try_from(value).ok())
        .map(u64::from_be_bytes)
    else {
        return;
    };
    if address != META_UART_BASE as u64 {
        return;
    }

    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    let mapped = match crate::memory::paging::mmio::map_physical_pages(
        PhysAddr::new(META_UART_BASE as u64),
        META_UART_MAPPING_SIZE,
        PhysicalMappingCache::Uncached,
    ) {
        Ok(mapped) => mapped,
        Err(_) => {
            return;
        }
    };

    META_UART_VIRT_BASE.store(mapped.as_u64() as usize, Ordering::Release);

    init_uart();

    AVAILABLE.store(true, Ordering::Release);

    crate::debug_metadata::register_sink(metadata_sink);

    poll_rx_once();
}

impl DebugTransportPlatform for Aarch64Platform {
    fn init_debug_metadata_transport() {
        init_debug_metadata_transport();
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
