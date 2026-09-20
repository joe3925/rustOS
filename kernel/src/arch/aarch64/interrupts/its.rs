use aarch64_cpu::asm::barrier::{SY, dsb};
use kernel_types::arch::{PageFlags, PhysAddr, VirtAddr};
use kernel_types::irq::{
    IrqSafeMutex, MSI_KIND_MSI, MSI_KIND_MSIX, MSI_REQUESTER_PCI, MSI_TARGET_ANY,
    MSI_TARGET_PLATFORM_CPU, MsiBindingRequest, MsiMessage,
};
use kernel_types::memory::PhysicalMappingCache;
use spin::Mutex;

use crate::memory::paging::map::{allocate_auto_kernel_range_mapped_contiguous, virt_to_phys};
use crate::memory::paging::mmio::map_physical_pages;
use crate::platform::CpuPlatform;

use super::super::platform::Aarch64Platform;

const ITS_REGISTER_SIZE: u64 = 0x20_000;
const GITS_CTLR: usize = 0x0000;
const GITS_TYPER: usize = 0x0008;
const GITS_CBASER: usize = 0x0080;
const GITS_CWRITER: usize = 0x0088;
const GITS_CREADR: usize = 0x0090;
const GITS_BASER: usize = 0x0100;
const GITS_TRANSLATER: u64 = 0x1_0040;
const GITS_CTLR_ENABLE: u32 = 1;
const GITS_CTLR_QUIESCENT: u32 = 1 << 31;
const GITS_TYPER_PTA: u64 = 1 << 19;
const GITS_BASER_VALID: u64 = 1 << 63;
const GITS_BASER_TYPE_SHIFT: u32 = 56;
const GITS_BASER_TYPE_MASK: u64 = 0b111 << GITS_BASER_TYPE_SHIFT;
const GITS_BASER_ENTRY_SIZE_SHIFT: u32 = 48;
const GITS_BASER_ENTRY_SIZE_MASK: u64 = 0x1f << GITS_BASER_ENTRY_SIZE_SHIFT;
const GITS_CACHE_WB: u64 = 0b111 << 59 | 0b111 << 53;
const GITS_SHARE_INNER: u64 = 0b11 << 10;
const GITS_CMD_MAPD: u64 = 0x08;
const GITS_CMD_MAPC: u64 = 0x09;
const GITS_CMD_MAPTI: u64 = 0x0a;
const GITS_CMD_INVALL: u64 = 0x0d;
const GITS_CMD_DISCARD: u64 = 0x0f;
const GITS_CMD_SYNC: u64 = 0x05;
const GITS_CMD_QUEUE_SIZE: u64 = 0x1_0000;
const GITS_CMD_SIZE: u64 = 32;
const ITS_TABLE_SIZE: u64 = 0x1_0000;
const ITS_MAX_BINDINGS: usize = 224;
const ITS_MAX_DEVICES: usize = 64;
const LPI_BASE: u32 = 8192;
const LPI_ID_BITS: u64 = 13;
const LPI_PROPERTY_SIZE: u64 = 1 << (LPI_ID_BITS + 1);
const LPI_PENDING_SIZE: u64 = 0x1_0000;
const GICR_CTLR: u64 = 0x0000;
const GICR_PROPBASER: u64 = 0x0070;
const GICR_PENDBASER: u64 = 0x0078;
const GICR_CTLR_ENABLE_LPIS: u32 = 1;
const GICR_CTLR_RWP: u32 = 1 << 3;
const GICR_BASER_CACHE_WB: u64 = 0b111 << 7 | 0b111 << 56;
const GICR_BASER_SHARE_INNER: u64 = 0b01 << 10;

#[derive(Clone, Copy)]
struct Memory {
    virt: u64,
    phys: u64,
}

#[derive(Clone, Copy)]
struct Device {
    id: u32,
    itt: Memory,
    users: u16,
}

#[derive(Clone, Copy)]
struct Binding {
    vector: u8,
    lpi: u32,
    device: u32,
    event: u32,
    target: u64,
}

struct State {
    writer: u64,
    devices: [Option<Device>; ITS_MAX_DEVICES],
    bindings: [Option<Binding>; ITS_MAX_BINDINGS],
    collections: [bool; 256],
    collection_targets: [Option<u64>; 256],
    pending: [Option<Memory>; 256],
}

pub(super) struct Its {
    registers: usize,
    physical_base: u64,
    command_queue: Memory,
    property_table: Memory,
    itt_entry_size: u64,
    physical_targets: bool,
    state: IrqSafeMutex<State>,
}

unsafe impl Send for Its {}
unsafe impl Sync for Its {}

impl Its {
    pub(super) fn new(physical_base: u64) -> Option<Self> {
        let registers = map_physical_pages(
            PhysAddr::new(physical_base),
            ITS_REGISTER_SIZE,
            PhysicalMappingCache::Uncached,
        )
        .ok()?
        .as_u64() as usize;
        let command_queue = allocate_memory_aligned(GITS_CMD_QUEUE_SIZE, GITS_CMD_QUEUE_SIZE)?;
        let property_table = allocate_memory_aligned(LPI_PROPERTY_SIZE, 0x1_0000)?;
        unsafe {
            core::ptr::write_bytes(
                property_table.virt as *mut u8,
                0xa3,
                LPI_PROPERTY_SIZE as usize,
            )
        };
        crate::arch::aarch64::cpu::clean_to_poc(property_table.virt, LPI_PROPERTY_SIZE as usize);
        let typer = unsafe { ((registers + GITS_TYPER) as *const u64).read_volatile() };
        let itt_entry_size = ((typer >> 4) & 0xf) + 1;
        let its = Self {
            registers,
            physical_base,
            command_queue,
            property_table,
            itt_entry_size,
            physical_targets: typer & GITS_TYPER_PTA != 0,
            state: IrqSafeMutex::new(State {
                writer: 0,
                devices: [None; ITS_MAX_DEVICES],
                bindings: [None; ITS_MAX_BINDINGS],
                collections: [false; 256],
                collection_targets: [None; 256],
                pending: [None; 256],
            }),
        };
        its.initialize()?;
        Some(its)
    }

    fn initialize(&self) -> Option<()> {
        self.write32(GITS_CTLR, 0);
        let mut quiescent = false;
        for _ in 0..1_000_000 {
            if self.read32(GITS_CTLR) & GITS_CTLR_QUIESCENT != 0 {
                quiescent = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !quiescent {
            return None;
        }
        self.write64(
            GITS_CBASER,
            self.command_queue.phys
                | GITS_BASER_VALID
                | GITS_CACHE_WB
                | GITS_SHARE_INNER
                | (GITS_CMD_QUEUE_SIZE / 4096 - 1),
        );
        self.write64(GITS_CWRITER, 0);
        for index in 0..8 {
            let offset = GITS_BASER + index * 8;
            let original = self.read64(offset);
            let table_type = original & GITS_BASER_TYPE_MASK;
            if table_type == 0 {
                continue;
            }
            let memory = allocate_memory_aligned(ITS_TABLE_SIZE, ITS_TABLE_SIZE)?;
            let value = memory.phys
                | GITS_BASER_VALID
                | GITS_CACHE_WB
                | GITS_SHARE_INNER
                | table_type
                | (original & GITS_BASER_ENTRY_SIZE_MASK)
                | (ITS_TABLE_SIZE / 4096 - 1);
            self.write64(offset, value);
            if self.read64(offset) & GITS_BASER_VALID == 0 {
                return None;
            }
        }
        self.write32(GITS_CTLR, GITS_CTLR_ENABLE);
        (self.read32(GITS_CTLR) & GITS_CTLR_ENABLE != 0).then_some(())
    }

    pub(super) fn init_cpu(
        &self,
        redistributor: usize,
        redistributor_phys: u64,
        platform_cpu_id: u32,
    ) -> bool {
        let Ok(index) = usize::try_from(platform_cpu_id) else {
            return false;
        };
        if index >= 256 {
            return false;
        }
        let mut state = self.state.lock();
        let typer = unsafe { ((redistributor + 8) as *const u64).read_volatile() };
        state.collection_targets[index] = Some(if self.physical_targets {
            redistributor_phys
        } else {
            ((typer >> 8) & 0xffff) << 16
        });
        let pending = match state.pending[index] {
            Some(memory) => memory,
            None => {
                let Some(memory) = allocate_memory_aligned(LPI_PENDING_SIZE, LPI_PENDING_SIZE)
                else {
                    return false;
                };
                state.pending[index] = Some(memory);
                memory
            }
        };
        unsafe {
            ((redistributor as u64 + GICR_PROPBASER) as *mut u64).write_volatile(
                self.property_table.phys
                    | GICR_BASER_CACHE_WB
                    | GICR_BASER_SHARE_INNER
                    | LPI_ID_BITS,
            );
            ((redistributor as u64 + GICR_PENDBASER) as *mut u64)
                .write_volatile(pending.phys | GICR_BASER_CACHE_WB | GICR_BASER_SHARE_INNER);
            let ctlr = (redistributor as *mut u32).read_volatile();
            (redistributor as *mut u32).write_volatile(ctlr | GICR_CTLR_ENABLE_LPIS);
            while (redistributor as *const u32).read_volatile() & GICR_CTLR_RWP != 0 {
                core::hint::spin_loop();
            }
        }
        true
    }

    pub(super) fn bind(&self, request: &MsiBindingRequest, vector: u8) -> Option<MsiMessage> {
        if !matches!(request.kind, MSI_KIND_MSI | MSI_KIND_MSIX)
            || request.requester.kind != MSI_REQUESTER_PCI
        {
            return None;
        }
        let target_cpu = match request.target.mode {
            MSI_TARGET_ANY => Aarch64Platform::current_platform_cpu_id(),
            MSI_TARGET_PLATFORM_CPU => request.target.platform_cpu_id,
            _ => return None,
        };
        let collection = u16::try_from(target_cpu).ok()?;
        let device_id = request.requester.requester_id as u32;
        let event_id = request.table_index as u32;
        let mut state = self.state.lock();
        let target = state.collection_targets[collection as usize]?;
        let binding_index = state.bindings.iter().position(Option::is_none)?;
        let lpi = LPI_BASE + binding_index as u32;
        let device_index = match state
            .devices
            .iter()
            .position(|slot| slot.is_some_and(|device| device.id == device_id))
        {
            Some(index) => index,
            None => {
                let index = state.devices.iter().position(Option::is_none)?;
                let entries = 256u64;
                let itt =
                    allocate_memory_aligned((entries * self.itt_entry_size).max(4096), 0x1_0000)?;
                let size = entries.trailing_zeros() as u64 - 1;
                self.command(
                    &mut state,
                    [
                        GITS_CMD_MAPD | (device_id as u64) << 32,
                        size,
                        itt.phys | 1 << 63,
                        0,
                    ],
                )?;
                state.devices[index] = Some(Device {
                    id: device_id,
                    itt,
                    users: 0,
                });
                index
            }
        };
        if !state.collections[collection as usize] {
            self.command(
                &mut state,
                [GITS_CMD_MAPC, 0, target | collection as u64 | 1 << 63, 0],
            )?;
            self.command(&mut state, [GITS_CMD_INVALL, 0, collection as u64, 0])?;
            state.collections[collection as usize] = true;
        }
        self.command(
            &mut state,
            [
                GITS_CMD_MAPTI | (device_id as u64) << 32,
                event_id as u64 | (lpi as u64) << 32,
                collection as u64,
                0,
            ],
        )?;
        self.command(&mut state, [GITS_CMD_SYNC, 0, target, 0])?;
        state.devices[device_index].as_mut()?.users += 1;
        state.bindings[binding_index] = Some(Binding {
            vector,
            lpi,
            device: device_id,
            event: event_id,
            target,
        });
        Some(MsiMessage::new(
            self.physical_base + GITS_TRANSLATER,
            event_id,
        ))
    }

    pub(super) fn unbind(&self, vector: u8) {
        let mut state = self.state.lock();
        let Some(index) = state
            .bindings
            .iter()
            .position(|slot| slot.is_some_and(|binding| binding.vector == vector))
        else {
            return;
        };
        let binding = state.bindings[index].take().unwrap();
        let _ = self.command(
            &mut state,
            [
                GITS_CMD_DISCARD | (binding.device as u64) << 32,
                binding.event as u64,
                0,
                0,
            ],
        );
        let _ = self.command(&mut state, [GITS_CMD_SYNC, 0, binding.target, 0]);
        if let Some(device_index) = state
            .devices
            .iter()
            .position(|slot| slot.is_some_and(|device| device.id == binding.device))
        {
            let device = state.devices[device_index].as_mut().unwrap();
            device.users = device.users.saturating_sub(1);
            if device.users == 0 {
                let _ = self.command(
                    &mut state,
                    [GITS_CMD_MAPD | (binding.device as u64) << 32, 0, 0, 0],
                );
                state.devices[device_index] = None;
            }
        }
    }

    pub(super) fn vector_for_lpi(&self, lpi: u32) -> Option<u8> {
        self.state
            .lock()
            .bindings
            .iter()
            .flatten()
            .find(|binding| binding.lpi == lpi)
            .map(|binding| binding.vector)
    }

    fn command(&self, state: &mut State, words: [u64; 4]) -> Option<()> {
        let address = self.command_queue.virt + state.writer;
        unsafe {
            for (index, word) in words.into_iter().enumerate() {
                ((address + index as u64 * 8) as *mut u64).write_volatile(word);
            }
        }
        crate::arch::aarch64::cpu::clean_to_poc(address, GITS_CMD_SIZE as usize);
        dsb(SY);
        state.writer = (state.writer + GITS_CMD_SIZE) % GITS_CMD_QUEUE_SIZE;
        self.write64(GITS_CWRITER, state.writer);
        for _ in 0..1_000_000 {
            if self.read64(GITS_CREADR) & (GITS_CMD_QUEUE_SIZE - 1) == state.writer {
                return Some(());
            }
            core::hint::spin_loop();
        }
        None
    }

    fn read32(&self, offset: usize) -> u32 {
        unsafe { ((self.registers + offset) as *const u32).read_volatile() }
    }
    fn write32(&self, offset: usize, value: u32) {
        unsafe { ((self.registers + offset) as *mut u32).write_volatile(value) }
    }
    fn read64(&self, offset: usize) -> u64 {
        unsafe { ((self.registers + offset) as *const u64).read_volatile() }
    }
    fn write64(&self, offset: usize, value: u64) {
        unsafe { ((self.registers + offset) as *mut u64).write_volatile(value) }
    }
}

fn allocate_memory_aligned(bytes: u64, alignment: u64) -> Option<Memory> {
    let allocation_bytes = bytes.checked_add(alignment)?;
    let virt = allocate_auto_kernel_range_mapped_contiguous(
        allocation_bytes,
        PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NO_EXECUTE,
    )
    .ok()?;
    let (_, phys) = virt_to_phys(VirtAddr::new(virt.as_u64()))?;
    let aligned_phys = phys.as_u64().checked_add(alignment - 1)? & !(alignment - 1);
    let aligned_virt = virt.as_u64() + aligned_phys - phys.as_u64();
    unsafe { core::ptr::write_bytes(aligned_virt as *mut u8, 0, bytes as usize) };
    crate::arch::aarch64::cpu::clean_to_poc(aligned_virt, bytes as usize);
    Some(Memory {
        virt: aligned_virt,
        phys: aligned_phys,
    })
}
