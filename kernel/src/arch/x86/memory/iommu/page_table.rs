//! Shared x86-64 4-level page-table walker for IOMMU domains.
//!
//! Intel VT-d second-level page tables (§9.3 of the VT-d spec) and
//! AMD-Vi I/O page tables (§2.2.3 of the AMD-Vi spec) share the
//! PML4/PDPT/PD/PT depth and PFN layout, but differ in the flag bits:
//! Intel uses bit 0=R / bit 1=W on every entry (presence is implicit
//! in R|W); AMD uses bit 0=P plus bits 61/62=IR/IW for permissions,
//! and non-leaf entries additionally carry a Next-Level field at
//! bits [11:9]. The walker therefore takes callbacks from the vendor
//! backend to supply the correct flag bits.
//!
//! Interior (non-leaf) page-table frames are deliberately **not tracked
//! per-mapping** — they grow monotonically with the domain's live IOVA
//! space and are reclaimed when the domain itself is destroyed. Tracking
//! them would force a Vec allocation on every `map_4k` call in the hot
//! path. The cost is bounded: the full tree for a 48-bit IOVA space is
//! <= 2 MiB of intermediate frames even if every L1 leaf is populated.

use super::domain::IommuError;
use crate::memory::device_mmu::DeviceMmuMapPermissions;
use crate::memory::paging::{allocate_auto_kernel_range_mapped_contiguous, virt_to_phys};
use x86_64::structures::paging::PageTableFlags;

pub const PTE_P: u64 = 1 << 0;
pub const PTE_RW: u64 = 1 << 1;
pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
pub const AMD_IR: u64 = 1 << 61;
pub const AMD_IW: u64 = 1 << 62;

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Once;

const IOMMU_TABLE_ARENA_SIZE: u64 = 8 * 1024 * 1024;
const IOMMU_TABLE_PAGE_SIZE: u64 = 0x1000;

struct IommuTableArenaInfo {
    phys_base: u64,
    virt_base: u64,
    size: u64,
}

static IOMMU_TABLE_ARENA_INFO: Once<IommuTableArenaInfo> = Once::new();
static IOMMU_TABLE_NEXT: AtomicU64 = AtomicU64::new(0);

pub fn init_table_arena() -> Result<(), IommuError> {
    if IOMMU_TABLE_ARENA_INFO.is_completed() {
        return Ok(());
    }

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let virt = allocate_auto_kernel_range_mapped_contiguous(IOMMU_TABLE_ARENA_SIZE, flags.into())
        .map_err(|_| IommuError::NoBackingFrame)?;
    let (_, phys) = virt_to_phys(virt).ok_or(IommuError::NoBackingFrame)?;

    IOMMU_TABLE_ARENA_INFO.call_once(|| IommuTableArenaInfo {
        phys_base: phys.as_u64(),
        virt_base: virt.as_u64(),
        size: IOMMU_TABLE_ARENA_SIZE,
    });

    Ok(())
}

#[inline(always)]
pub(crate) unsafe fn phys_to_mut<T>(phys: u64) -> *mut T {
    let arena = IOMMU_TABLE_ARENA_INFO.get().unwrap();

    debug_assert!(phys >= arena.phys_base);
    debug_assert!(phys < arena.phys_base + arena.size);

    (arena.virt_base + (phys - arena.phys_base)) as *mut T
}

#[inline]
fn read_entry(phys: u64, index: usize) -> u64 {
    unsafe { phys_to_mut::<u64>(phys).add(index).read_volatile() }
}

#[inline]
fn write_entry(phys: u64, index: usize, value: u64) {
    unsafe {
        phys_to_mut::<u64>(phys).add(index).write_volatile(value);
    }
}

#[inline]
fn iova_index(iova: u64, level: u32) -> usize {
    let shift = 12 + (level - 1) * 9;
    ((iova >> shift) & 0x1FF) as usize
}

/// Allocate one 4 KiB frame for a page-table level and zero it.
pub fn alloc_pt_frame_phys() -> Option<u64> {
    let arena = IOMMU_TABLE_ARENA_INFO.get()?;

    let offset = IOMMU_TABLE_NEXT.fetch_add(IOMMU_TABLE_PAGE_SIZE, Ordering::SeqCst);
    if offset + IOMMU_TABLE_PAGE_SIZE > arena.size {
        return None;
    }

    let phys = arena.phys_base + offset;
    let ptr = (arena.virt_base + offset) as *mut u64;

    unsafe {
        for i in 0..512 {
            ptr.add(i).write_volatile(0);
        }
    }
    Some(phys)
}

pub fn map_range(
    root_phys: u64,
    iova: u64,
    phys: u64,
    len: u64,
    permissions: DeviceMmuMapPermissions,
    format: X86IommuPageTableFormat,
) -> Result<(), IommuError> {
    if len == 0 {
        return Ok(());
    }

    if (iova & 0xFFF) != 0 || (phys & 0xFFF) != 0 || (len & 0xFFF) != 0 {
        return Err(IommuError::InvalidRange);
    }

    let mut cur_iova = iova;
    let mut cur_phys = phys;
    let mut remaining = len;

    while remaining > 0 {
        if remaining >= 1024 * 1024 * 1024
            && (cur_iova & ((1024 * 1024 * 1024) - 1)) == 0
            && (cur_phys & ((1024 * 1024 * 1024) - 1)) == 0
        {
            ensure_iommu_1gib_mapped(root_phys, cur_iova, cur_phys, permissions, format)?;

            cur_iova += 1024 * 1024 * 1024;
            cur_phys += 1024 * 1024 * 1024;
            remaining -= 1024 * 1024 * 1024;
        } else if remaining >= 2 * 1024 * 1024
            && (cur_iova & ((2 * 1024 * 1024) - 1)) == 0
            && (cur_phys & ((2 * 1024 * 1024) - 1)) == 0
        {
            ensure_iommu_2mib_mapped(root_phys, cur_iova, cur_phys, permissions, format)?;

            cur_iova += 2 * 1024 * 1024;
            cur_phys += 2 * 1024 * 1024;
            remaining -= 2 * 1024 * 1024;
        } else {
            map_4k(
                root_phys,
                cur_iova,
                cur_phys,
                |level| format.interior_flags(permissions, level),
                format.leaf_flags(permissions, 1),
                format.present_mask(),
            )?;

            cur_iova += 4096;
            cur_phys += 4096;
            remaining -= 4096;
        }
    }

    Ok(())
}

pub fn ensure_iommu_2mib_mapped(
    root_phys: u64,
    iova: u64,
    phys: u64,
    permissions: DeviceMmuMapPermissions,
    format: X86IommuPageTableFormat,
) -> Result<(), IommuError> {
    const SIZE_2MIB: u64 = 2 * 1024 * 1024;

    if (iova & (SIZE_2MIB - 1)) != 0 || (phys & (SIZE_2MIB - 1)) != 0 {
        return Err(IommuError::InvalidRange);
    }

    let mut table_phys = root_phys;

    for lvl in (3..=4).rev() {
        let idx = iova_index(iova, lvl);
        let entry = read_entry(table_phys, idx);

        if entry & format.present_mask() == 0 {
            let new_table = alloc_pt_frame_phys().ok_or(IommuError::NoBackingFrame)?;
            let new_entry = (new_table & PTE_ADDR_MASK) | format.interior_flags(permissions, lvl);

            write_entry(table_phys, idx, new_entry);
            table_phys = new_table;
        } else {
            table_phys = entry & PTE_ADDR_MASK;
        }
    }

    let idx = iova_index(iova, 2);
    let entry = read_entry(table_phys, idx);

    if entry & format.present_mask() == 0 {
        let leaf = (phys & PTE_ADDR_MASK) | format.leaf_flags(permissions, 2);
        write_entry(table_phys, idx, leaf);
    }

    Ok(())
}

pub fn ensure_iommu_1gib_mapped(
    root_phys: u64,
    iova: u64,
    phys: u64,
    permissions: DeviceMmuMapPermissions,
    format: X86IommuPageTableFormat,
) -> Result<(), IommuError> {
    const SIZE_1GIB: u64 = 1024 * 1024 * 1024;

    if (iova & (SIZE_1GIB - 1)) != 0 || (phys & (SIZE_1GIB - 1)) != 0 {
        return Err(IommuError::InvalidRange);
    }

    let mut table_phys = root_phys;

    let idx = iova_index(iova, 4);
    let entry = read_entry(table_phys, idx);

    if entry & format.present_mask() == 0 {
        let new_table = alloc_pt_frame_phys().ok_or(IommuError::NoBackingFrame)?;
        let new_entry = (new_table & PTE_ADDR_MASK) | format.interior_flags(permissions, 4);

        write_entry(table_phys, idx, new_entry);
        table_phys = new_table;
    } else {
        table_phys = entry & PTE_ADDR_MASK;
    }

    let idx = iova_index(iova, 3);
    let entry = read_entry(table_phys, idx);

    if entry & format.present_mask() == 0 {
        let leaf = (phys & PTE_ADDR_MASK) | format.leaf_flags(permissions, 3);
        write_entry(table_phys, idx, leaf);
    }

    Ok(())
}

pub fn map_4k<F: Fn(u32) -> u64>(
    root_phys: u64,
    iova: u64,
    phys: u64,
    interior_flags: F,
    leaf_flags: u64,
    present_mask: u64,
) -> Result<(), IommuError> {
    debug_assert_eq!(iova & 0xFFF, 0);
    debug_assert_eq!(phys & 0xFFF, 0);

    let mut table_phys = root_phys;

    for lvl in (2..=4).rev() {
        let idx = iova_index(iova, lvl);
        let entry = read_entry(table_phys, idx);
        if entry & present_mask != 0 {
            table_phys = entry & PTE_ADDR_MASK;
        } else {
            let np = alloc_pt_frame_phys().ok_or(IommuError::NoBackingFrame)?;
            write_entry(table_phys, idx, np | interior_flags(lvl));
            table_phys = np;
        }
    }

    let idx = iova_index(iova, 1);
    let leaf = (phys & PTE_ADDR_MASK) | leaf_flags;
    write_entry(table_phys, idx, leaf);
    Ok(())
}

/// Clear one 4 KiB leaf. Returns the physical address that was mapped, if any.
#[inline]
pub fn unmap_4k(root_phys: u64, iova: u64, present_mask: u64) -> Option<u64> {
    debug_assert_eq!(iova & 0xFFF, 0);

    let mut table_phys = root_phys;
    for lvl in (2..=4).rev() {
        let idx = iova_index(iova, lvl);
        let entry = read_entry(table_phys, idx);
        if entry & present_mask == 0 {
            return None;
        }
        table_phys = entry & PTE_ADDR_MASK;
    }

    let idx = iova_index(iova, 1);
    let entry = read_entry(table_phys, idx);
    if entry & present_mask == 0 {
        return None;
    }
    write_entry(table_phys, idx, 0);
    Some(entry & PTE_ADDR_MASK)
}

/// Identity-map a byte range at 4 KiB granularity.
#[allow(dead_code)]
pub fn identity_map_range(
    root_phys: u64,
    base: u64,
    limit: u64,
    interior_flags: impl Fn(u32) -> u64 + Copy,
    leaf_flags: u64,
    present_mask: u64,
) -> Result<(), IommuError> {
    let start = base & !0xFFFu64;
    let end = (limit + 0xFFF) & !0xFFFu64;
    let mut cur = start;
    while cur < end {
        map_4k(
            root_phys,
            cur,
            cur,
            interior_flags,
            leaf_flags,
            present_mask,
        )?;
        cur += 0x1000;
    }
    Ok(())
}

/// Allocate and zero a fresh root table frame. Returns the physical address.
pub fn alloc_root_table() -> Result<u64, IommuError> {
    alloc_pt_frame_phys().ok_or(IommuError::NoBackingFrame)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86IommuPageTableFormat {
    Intel,
    Amd,
}

impl X86IommuPageTableFormat {
    #[inline]
    fn interior_flags(self, permissions: DeviceMmuMapPermissions, level: u32) -> u64 {
        match self {
            Self::Intel => PTE_P | PTE_RW,
            Self::Amd => amd_permission_flags(permissions) | (((level - 1) as u64) << 9),
        }
    }

    #[inline]
    fn leaf_flags(self, permissions: DeviceMmuMapPermissions, level: u32) -> u64 {
        match self {
            Self::Intel => {
                let mut flags = intel_permission_flags(permissions);
                if level > 1 {
                    flags |= 1 << 7;
                }
                flags
            }
            Self::Amd => {
                let mut flags = amd_permission_flags(permissions);
                if level > 1 {
                    flags |= 0 << 9;
                }
                flags
            }
        }
    }

    #[inline]
    fn present_mask(self) -> u64 {
        match self {
            Self::Intel => PTE_P | PTE_RW,
            Self::Amd => PTE_P,
        }
    }
}

fn amd_permission_flags(permissions: DeviceMmuMapPermissions) -> u64 {
    let mut flags = PTE_P;
    if matches!(
        permissions,
        DeviceMmuMapPermissions::Read | DeviceMmuMapPermissions::ReadWrite
    ) {
        flags |= AMD_IR;
    }
    if matches!(
        permissions,
        DeviceMmuMapPermissions::Write | DeviceMmuMapPermissions::ReadWrite
    ) {
        flags |= AMD_IW;
    }
    flags
}

fn intel_permission_flags(permissions: DeviceMmuMapPermissions) -> u64 {
    let mut flags = PTE_P;
    if matches!(
        permissions,
        DeviceMmuMapPermissions::Write | DeviceMmuMapPermissions::ReadWrite
    ) {
        flags |= PTE_RW;
    }
    flags
}
