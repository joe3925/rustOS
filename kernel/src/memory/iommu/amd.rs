//! AMD-Vi (IOMMU) backend.
//!
//! Register layout and command formats follow AMD I/O Virtualization
//! Technology (IOMMU) specification 48882.

use alloc::vec::Vec;

use kernel_types::dma::DmaPciDeviceIdentity;
use spin::Mutex;
use x86_64::PhysAddr;

use crate::memory::dma::{AmdIvhdDeviceEntry, AmdPlatformIommuInfo};
use crate::memory::iommu::alloc_zeroed_pages_contiguous;
use crate::memory::iommu::domain::{IommuDomain, IommuError};
use crate::memory::iommu::page_table::{self, AMD_IR, AMD_IW, PTE_ADDR_MASK, PTE_P};
use crate::memory::paging::mmio::map_mmio_region;
use crate::println;

const DEV_TAB_BAR: usize = 0x0000;
const CMD_BUF_BAR: usize = 0x0008;
const EVT_LOG_BAR: usize = 0x0010;
const CONTROL_REG: usize = 0x0018;
const CMD_HEAD: usize = 0x2000;
const CMD_TAIL: usize = 0x2008;
const EVT_HEAD: usize = 0x2010;
const EVT_TAIL: usize = 0x2018;
const STATUS_REG: usize = 0x2020;
const EXT_FEATURE_REG: usize = 0x0030;

const CTRL_IOMMU_EN: u64 = 1 << 0;
const CTRL_EVT_LOG_EN: u64 = 1 << 2;
const CTRL_COM_WAIT_INT_EN: u64 = 1 << 4;
const CTRL_CMD_BUF_EN: u64 = 1 << 12;
const CTRL_COMMON: u64 = CTRL_CMD_BUF_EN | CTRL_COM_WAIT_INT_EN | CTRL_EVT_LOG_EN | CTRL_IOMMU_EN;

const STATUS_EVENT_OVERFLOW: u64 = 1 << 0;
const STATUS_EVENT_LOG_INT: u64 = 1 << 1;
const STATUS_COM_WAIT_INT: u64 = 1 << 2;
const STATUS_EVENT_LOG_RUN: u64 = 1 << 3;
const STATUS_CMD_BUF_RUN: u64 = 1 << 4;
const STATUS_RW1C_MASK: u64 = STATUS_EVENT_OVERFLOW | STATUS_EVENT_LOG_INT | STATUS_COM_WAIT_INT;

const EXT_FEATURE_HATS_SHIFT: u64 = 10;
const EXT_FEATURE_HATS_MASK: u64 = 0b11 << EXT_FEATURE_HATS_SHIFT;
const EXT_FEATURE_HATS_RESERVED: u64 = 0b11;

const DEV_TABLE_PAGES: usize = 512;
const CMD_ENTRY_COUNT: u32 = 256;
const CMD_ENTRY_SIZE: usize = 16;
const EVT_ENTRY_COUNT: u32 = 256;
const EVT_ENTRY_SIZE: usize = 16;
const CMD_POLL_LIMIT: usize = 1_000_000;

pub struct AmdViBackend {
    inner: Mutex<AmdInner>,
}

struct AmdInner {
    units: Vec<AmdUnit>,
}

struct AmdUnit {
    register_base: u64,
    reg_base_va: *mut u8,
    dev_table_va: *mut u64,
    cmd_buf_va: *mut u8,
    evt_log_va: *mut u8,
    cmd_tail: u32,
    evt_head: u32,
    iova_end: u64,
    segment: u16,
    device_entries: Vec<AmdIvhdDeviceEntry>,
    next_domain_id: u32,
}

unsafe impl Send for AmdInner {}
unsafe impl Sync for AmdInner {}

impl AmdViBackend {
    pub fn init(info: &AmdPlatformIommuInfo) -> Result<Self, IommuError> {
        let mut units = Vec::with_capacity(info.remapper_units.len());
        let iova_end = calc_iova_end(info.virtual_address_size);

        for unit in &info.remapper_units {
            let reg_va = map_mmio_region(PhysAddr::new(unit.register_base), 0x3000)
                .map_err(|_| IommuError::HardwareError)?
                .as_mut_ptr::<u8>();
            let ext_features = unsafe { read_reg64(reg_va, EXT_FEATURE_REG) };
            require_host_dma_translation(unit.register_base, ext_features);

            let (dev_table_phys, dev_table_va) = alloc_zeroed_pages_contiguous(DEV_TABLE_PAGES)?;
            let (cmd_buf_phys, cmd_buf_va) = alloc_zeroed_pages_contiguous(1)?;
            let (evt_log_phys, evt_log_va) = alloc_zeroed_pages_contiguous(1)?;

            unsafe {
                write_reg64(reg_va, DEV_TAB_BAR, dev_table_phys.as_u64() | 511);
                write_reg64(reg_va, CMD_BUF_BAR, cmd_buf_phys.as_u64() | (8u64 << 56));
                write_reg64(reg_va, EVT_LOG_BAR, evt_log_phys.as_u64() | (8u64 << 56));

                write_reg64(reg_va, CONTROL_REG, CTRL_CMD_BUF_EN | CTRL_COM_WAIT_INT_EN);
                let _ = read_reg64(reg_va, CONTROL_REG);
                write_reg64(
                    reg_va,
                    CONTROL_REG,
                    CTRL_CMD_BUF_EN | CTRL_COM_WAIT_INT_EN | CTRL_EVT_LOG_EN,
                );
                write_reg64(reg_va, CONTROL_REG, CTRL_COMMON);
            }

            let status = unsafe { read_reg64(reg_va, STATUS_REG) };
            if (status & (STATUS_CMD_BUF_RUN | STATUS_EVENT_LOG_RUN))
                != (STATUS_CMD_BUF_RUN | STATUS_EVENT_LOG_RUN)
            {
                return Err(IommuError::HardwareError);
            }

            println!(
                "iommu: AMD-Vi up at {:#x}, segment={}, status={:#x}, ext_features={:#x}, va_bits={}",
                unit.register_base, unit.segment, status, ext_features, info.virtual_address_size
            );

            units.push(AmdUnit {
                register_base: unit.register_base,
                reg_base_va: reg_va,
                dev_table_va: dev_table_va.as_mut_ptr::<u64>(),
                cmd_buf_va: cmd_buf_va.as_mut_ptr::<u8>(),
                evt_log_va: evt_log_va.as_mut_ptr::<u8>(),
                cmd_tail: 0,
                evt_head: 0,
                iova_end,
                segment: unit.segment,
                device_entries: unit.device_entries.clone(),
                next_domain_id: 1,
            });
        }

        if units.is_empty() {
            return Err(IommuError::Unsupported);
        }

        Ok(Self {
            inner: Mutex::new(AmdInner { units }),
        })
    }

    pub fn create_domain(
        &self,
        identity: DmaPciDeviceIdentity,
    ) -> Result<IommuDomain, IommuError> {
        let (unit_index, domain_id, iova_end) = {
            let mut inner = self.inner.lock();
            let unit_index = inner.select_unit_index(identity.segment, identity.requester_id)?;
            let unit = &mut inner.units[unit_index];
            if unit.next_domain_id >= (u16::MAX as u32) {
                return Err(IommuError::HardwareError);
            }
            let domain_id = unit.next_domain_id as u16;
            unit.next_domain_id += 1;
            (unit_index, domain_id, unit.iova_end)
        };

        let root_phys = page_table::alloc_root_table()?;
        Ok(IommuDomain::new(
            root_phys,
            domain_id,
            identity.segment,
            identity.requester_id,
            unit_index as u32,
            iova_end,
        ))
    }

    pub fn attach(&self, domain: &IommuDomain) -> Result<(), IommuError> {
        let mut inner = self.inner.lock();
        let unit = inner
            .units
            .get_mut(domain.remapper_index as usize)
            .ok_or(IommuError::HardwareError)?;
        if unit.segment != domain.segment {
            return Err(IommuError::HardwareError);
        }

        let dte_requester_id = resolve_requester_id_alias(unit, domain.requester_id)
            .ok_or(IommuError::Unsupported)?;
        write_dte(unit.dev_table_va, dte_requester_id, domain);
        let commands = [
            invalidate_dte_cmd(dte_requester_id),
            invalidate_pages_cmd(domain.domain_id),
        ];
        submit_serialized(unit, &commands)
    }

    #[inline]
    pub fn map_pages(
        &self,
        domain: &IommuDomain,
        iova: u64,
        phys_pfns: &[u64],
    ) -> Result<(), IommuError> {
        let mut cur_iova = iova;
        for &pfn in phys_pfns {
            page_table::map_4k(
                domain.root_phys,
                cur_iova,
                pfn << 12,
                |level| PTE_P | AMD_IR | AMD_IW | (((level - 1) as u64) << 9),
                PTE_P | AMD_IR | AMD_IW,
                PTE_P,
            )?;
            cur_iova += 0x1000;
        }
        Ok(())
    }

    #[inline]
    pub fn unmap_pages(&self, domain: &IommuDomain, iova: u64, page_count: u32) {
        let mut cur = iova;
        for _ in 0..page_count {
            let _ = page_table::unmap_4k(domain.root_phys, cur, PTE_P);
            cur += 0x1000;
        }

        let mut inner = self.inner.lock();
        let Some(unit) = inner.units.get_mut(domain.remapper_index as usize) else {
            return;
        };
        if let Err(err) = submit_serialized(unit, &[invalidate_pages_cmd(domain.domain_id)]) {
            println!(
                "iommu: AMD-Vi invalidate failed after unmap for segment {} requester {:#06x}: {:?}",
                domain.segment,
                domain.requester_id,
                err
            );
        }
    }

    pub fn invalidate(&self, domain: &IommuDomain, _iova: u64, _len: u64) {
        let mut inner = self.inner.lock();
        let Some(unit) = inner.units.get_mut(domain.remapper_index as usize) else {
            return;
        };
        if let Err(err) = submit_serialized(unit, &[invalidate_pages_cmd(domain.domain_id)]) {
            println!(
                "iommu: AMD-Vi invalidate failed for segment {} requester {:#06x}: {:?}",
                domain.segment, domain.requester_id, err
            );
        }
    }
}

impl AmdInner {
    fn select_unit_index(&self, segment: u16, requester_id: u16) -> Result<usize, IommuError> {
        let mut segment_matches = 0usize;
        let mut only_segment_match = None;
        let mut routed_matches = 0usize;
        let mut routed_match = None;

        for (idx, unit) in self.units.iter().enumerate() {
            if unit.segment != segment {
                continue;
            }

            segment_matches += 1;
            only_segment_match = Some(idx);

            if unit_matches_requester_id(unit, requester_id) {
                routed_matches += 1;
                routed_match = Some(idx);
            }
        }

        if routed_matches == 1 {
            return Ok(routed_match.expect("missing AMD-Vi routed match"));
        }
        if segment_matches == 1 {
            return Ok(only_segment_match.expect("missing AMD-Vi segment match"));
        }

        Err(IommuError::Unsupported)
    }
}

fn calc_iova_end(va_bits: u8) -> u64 {
    let width = match va_bits {
        33..=48 => va_bits as u32,
        49..=63 => 48,
        _ => 48,
    };
    1u64 << width
}

fn require_host_dma_translation(register_base: u64, ext_features: u64) {
    let hats = (ext_features & EXT_FEATURE_HATS_MASK) >> EXT_FEATURE_HATS_SHIFT;
    if hats == EXT_FEATURE_HATS_RESERVED {
        panic!(
            "iommu: AMD-Vi host DMA translation is disabled at {:#x}; if using QEMU, pass -device amd-iommu,dma-translation=on,dma-remap=on",
            register_base
        );
    }
}

fn write_dte(dev_table_va: *mut u64, requester_id: u16, domain: &IommuDomain) {
    let idx = requester_id as usize * 4;
    let qw0 = PTE_P | (1 << 1) | (4u64 << 9) | (domain.root_phys & PTE_ADDR_MASK) | AMD_IR | AMD_IW;
    let qw1 = domain.domain_id as u64;
    unsafe {
        dev_table_va.add(idx + 1).write_volatile(qw1);
        dev_table_va.add(idx + 2).write_volatile(0);
        dev_table_va.add(idx + 3).write_volatile(0);
        dev_table_va.add(idx).write_volatile(qw0);
    }
}

#[inline]
fn invalidate_dte_cmd(requester_id: u16) -> (u64, u64) {
    ((0x2u64 << 60) | (requester_id as u64), 0)
}

#[inline]
fn invalidate_pages_cmd(domain_id: u16) -> (u64, u64) {
    let word0 = (0x3u64 << 60) | ((domain_id as u64) << 32);
    let word1 = 0x7fff_ffff_ffff_f003u64;
    (word0, word1)
}

#[inline]
fn completion_wait_cmd() -> (u64, u64) {
    ((0x1u64 << 60) | (1 << 2) | (1 << 1), 0)
}

fn submit_serialized(unit: &mut AmdUnit, commands: &[(u64, u64)]) -> Result<(), IommuError> {
    let required = commands.len() as u32 + 1;
    wait_for_command_slots(unit, required)?;
    clear_status_bits(unit.reg_base_va, STATUS_COM_WAIT_INT);

    for &(word0, word1) in commands {
        queue_command(unit, word0, word1);
    }
    let (wait0, wait1) = completion_wait_cmd();
    queue_command(unit, wait0, wait1);

    unsafe {
        write_reg64(
            unit.reg_base_va,
            CMD_TAIL,
            (unit.cmd_tail as u64) * CMD_ENTRY_SIZE as u64,
        );
    }

    wait_for_completion(unit)
}

fn wait_for_command_slots(unit: &mut AmdUnit, required: u32) -> Result<(), IommuError> {
    for _ in 0..CMD_POLL_LIMIT {
        let status = unsafe { read_reg64(unit.reg_base_va, STATUS_REG) };
        if (status & STATUS_CMD_BUF_RUN) == 0 {
            recover_command_path(unit);
            return Err(IommuError::HardwareError);
        }

        let head = command_head_slot(unit);
        let free = if head <= unit.cmd_tail {
            CMD_ENTRY_COUNT - (unit.cmd_tail - head) - 1
        } else {
            head - unit.cmd_tail - 1
        };
        if free >= required {
            return Ok(());
        }

        core::hint::spin_loop();
    }

    recover_command_path(unit);
    Err(IommuError::HardwareError)
}

fn wait_for_completion(unit: &mut AmdUnit) -> Result<(), IommuError> {
    for _ in 0..CMD_POLL_LIMIT {
        let status = unsafe { read_reg64(unit.reg_base_va, STATUS_REG) };
        if (status & STATUS_COM_WAIT_INT) != 0 {
            clear_status_bits(unit.reg_base_va, STATUS_COM_WAIT_INT);
            return Ok(());
        }
        if (status & STATUS_CMD_BUF_RUN) == 0 {
            recover_command_path(unit);
            return Err(IommuError::HardwareError);
        }
        core::hint::spin_loop();
    }

    recover_command_path(unit);
    Err(IommuError::HardwareError)
}

fn recover_command_path(unit: &mut AmdUnit) {
    drain_event_log(unit);
    clear_status_bits(unit.reg_base_va, STATUS_RW1C_MASK);
    unsafe {
        write_reg64(unit.reg_base_va, CONTROL_REG, CTRL_COMMON);
    }
}

fn drain_event_log(unit: &mut AmdUnit) {
    let tail = unsafe { read_reg64(unit.reg_base_va, EVT_TAIL) };
    let tail_slot = ((tail / EVT_ENTRY_SIZE as u64) % EVT_ENTRY_COUNT as u64) as u32;

    while unit.evt_head != tail_slot {
        let offset = unit.evt_head as usize * EVT_ENTRY_SIZE;
        let (word0, word1) = unsafe {
            let entry = unit.evt_log_va.add(offset) as *const u64;
            (entry.read_volatile(), entry.add(1).read_volatile())
        };
        println!(
            "iommu: AMD-Vi event at {:#x}: {:#018x} {:#018x}",
            unit.register_base, word0, word1
        );
        unit.evt_head = (unit.evt_head + 1) % EVT_ENTRY_COUNT;
    }

    unsafe {
        write_reg64(
            unit.reg_base_va,
            EVT_HEAD,
            (unit.evt_head as u64) * EVT_ENTRY_SIZE as u64,
        );
    }
}

#[inline]
fn queue_command(unit: &mut AmdUnit, word0: u64, word1: u64) {
    let offset = unit.cmd_tail as usize * CMD_ENTRY_SIZE;
    unsafe {
        let cmd_ptr = unit.cmd_buf_va.add(offset) as *mut u64;
        cmd_ptr.write_volatile(word0);
        cmd_ptr.add(1).write_volatile(word1);
    }
    unit.cmd_tail = (unit.cmd_tail + 1) % CMD_ENTRY_COUNT;
}

#[inline]
fn command_head_slot(unit: &AmdUnit) -> u32 {
    let head = unsafe { read_reg64(unit.reg_base_va, CMD_HEAD) };
    ((head / CMD_ENTRY_SIZE as u64) % CMD_ENTRY_COUNT as u64) as u32
}

fn unit_matches_requester_id(unit: &AmdUnit, requester_id: u16) -> bool {
    resolve_requester_id_alias(unit, requester_id).is_some()
}

fn resolve_requester_id_alias(unit: &AmdUnit, requester_id: u16) -> Option<u16> {
    enum RangeMapping {
        Identity,
        Alias(u16),
    }

    let mut fallback = None;
    let mut range_start = None;

    for entry in &unit.device_entries {
        match entry {
            AmdIvhdDeviceEntry::All { .. } => fallback = Some(requester_id),
            AmdIvhdDeviceEntry::Select {
                requester_id: entry_id,
                ..
            }
            | AmdIvhdDeviceEntry::ExtSelect {
                requester_id: entry_id,
                ..
            }
            | AmdIvhdDeviceEntry::AcpiHid {
                requester_id: entry_id,
                ..
            } => {
                if *entry_id == requester_id {
                    return Some(requester_id);
                }
            }
            AmdIvhdDeviceEntry::AliasSelect {
                requester_id: entry_id,
                used_id,
                ..
            }
            | AmdIvhdDeviceEntry::Special {
                requester_id: entry_id,
                used_id,
                ..
            } => {
                if *entry_id == requester_id {
                    return Some(*used_id);
                }
            }
            AmdIvhdDeviceEntry::StartRange {
                requester_id: entry_id,
                ..
            }
            | AmdIvhdDeviceEntry::ExtStartRange {
                requester_id: entry_id,
                ..
            } => range_start = Some((*entry_id, RangeMapping::Identity)),
            AmdIvhdDeviceEntry::AliasStartRange {
                requester_id: entry_id,
                used_id,
                ..
            } => range_start = Some((*entry_id, RangeMapping::Alias(*used_id))),
            AmdIvhdDeviceEntry::EndRange {
                requester_id: end_id,
                ..
            } => {
                if let Some((start_id, mapping)) = range_start.take() {
                    if requester_id >= start_id && requester_id <= *end_id {
                        return Some(match mapping {
                            RangeMapping::Identity => requester_id,
                            RangeMapping::Alias(used_id) => used_id,
                        });
                    }
                }
            }
            AmdIvhdDeviceEntry::Pad4
            | AmdIvhdDeviceEntry::Pad8
            | AmdIvhdDeviceEntry::Unknown { .. } => {}
        }
    }

    fallback
}

#[inline]
fn clear_status_bits(base: *mut u8, bits: u64) {
    if bits != 0 {
        unsafe { write_reg64(base, STATUS_REG, bits) };
    }
}

#[inline]
unsafe fn read_reg64(base: *mut u8, off: usize) -> u64 {
    unsafe { core::ptr::read_volatile(base.add(off) as *const u64) }
}

#[inline]
unsafe fn write_reg64(base: *mut u8, off: usize, v: u64) {
    unsafe { core::ptr::write_volatile(base.add(off) as *mut u64, v) }
}
