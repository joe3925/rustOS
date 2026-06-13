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

use crate::memory::iommu::domain::IommuError;
use crate::memory::paging::tables::virt_to_phys;
use crate::memory::paging::virt_tracker::allocate_auto_kernel_range_mapped_contiguous;
use spin::Mutex;
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
    let virt = allocate_auto_kernel_range_mapped_contiguous(IOMMU_TABLE_ARENA_SIZE, flags)
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

/// Map a single 4 KiB page. `leaf_flags` adds vendor-specific bits (e.g.
/// AMD `IR`/`IW`) on top of the shared `P | R/W` flags. Interior frames
/// allocated on the way down are intentionally not reported — see the
/// module docstring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuMapPermissions {
    Read,
    Write,
    ReadWrite,
}

impl IommuMapPermissions {
    pub(crate) fn amd_flags(self) -> u64 {
        let mut f = PTE_P;
        if matches!(self, Self::Read | Self::ReadWrite) {
            f |= AMD_IR;
        }
        if matches!(self, Self::Write | Self::ReadWrite) {
            f |= AMD_IW;
        }
        f
    }

    pub(crate) fn intel_flags(self) -> u64 {
        let mut f = PTE_P;
        if matches!(self, Self::Read | Self::ReadWrite) {
            f |= 1;
        } // R
        if matches!(self, Self::Write | Self::ReadWrite) {
            f |= 2;
        } // W
        f
    }
}

pub fn map_range(
    root_phys: u64,
    iova: u64,
    phys: u64,
    len: u64,
    permissions: IommuMapPermissions,
) -> Result<(), IommuError> {
    let mut cur_iova = iova;
    let mut cur_phys = phys;
    let mut remaining = len;

    let is_amd = matches!(super::backend(), Some(super::IommuBackend::Amd(_)));

    let interior_flags = |level: u32| -> u64 {
        if is_amd {
            permissions.amd_flags() | (((level - 1) as u64) << 9)
        } else {
            PTE_P | PTE_RW
        }
    };

    let leaf_flags = |level: u32| -> u64 {
        let mut flags = if is_amd {
            let mut f = permissions.amd_flags();
            if level > 1 {
                f |= 0 << 9; // Next Level = 0 for large pages
            }
            f
        } else {
            let mut f = permissions.intel_flags();
            if level > 1 {
                f |= 1 << 7; // PS bit
            }
            f
        };
        flags
    };

    while remaining > 0 {
        if remaining >= 1024 * 1024 * 1024
            && (cur_iova & ((1024 * 1024 * 1024) - 1)) == 0
            && (cur_phys & ((1024 * 1024 * 1024) - 1)) == 0
        {
            ensure_iommu_1gib_mapped(root_phys, cur_iova, cur_phys, remaining, permissions)?;
            cur_iova += 1024 * 1024 * 1024;
            cur_phys += 1024 * 1024 * 1024;
            remaining -= 1024 * 1024 * 1024;
        } else if remaining >= 2 * 1024 * 1024
            && (cur_iova & ((2 * 1024 * 1024) - 1)) == 0
            && (cur_phys & ((2 * 1024 * 1024) - 1)) == 0
        {
            ensure_iommu_2mib_mapped(root_phys, cur_iova, cur_phys, remaining, permissions)?;
            cur_iova += 2 * 1024 * 1024;
            cur_phys += 2 * 1024 * 1024;
            remaining -= 2 * 1024 * 1024;
        } else {
            map_4k(
                root_phys,
                cur_iova,
                cur_phys,
                interior_flags,
                leaf_flags(1),
                PTE_P,
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
    _len: u64,
    permissions: IommuMapPermissions,
) -> Result<(), IommuError> {
    let is_amd = matches!(super::backend(), Some(super::IommuBackend::Amd(_)));

    let interior_flags = |level: u32| -> u64 {
        if is_amd {
            permissions.amd_flags() | (((level - 1) as u64) << 9)
        } else {
            PTE_P | PTE_RW
        }
    };

    let mut leaf = if is_amd {
        permissions.amd_flags() | (0 << 9)
    } else {
        permissions.intel_flags() | (1 << 7)
    };

    let mut table_phys = root_phys;
    for lvl in (3..=4).rev() {
        let idx = iova_index(iova, lvl);
        let entry = read_entry(table_phys, idx);

        if entry & PTE_P == 0 {
            let new_table = alloc_pt_frame_phys().ok_or(IommuError::NoBackingFrame)?;
            let new_entry = (new_table & PTE_ADDR_MASK) | interior_flags(lvl);
            write_entry(table_phys, idx, new_entry);
            table_phys = new_table;
        } else {
            table_phys = entry & PTE_ADDR_MASK;
        }
    }

    let idx = iova_index(iova, 2);
    let entry = read_entry(table_phys, idx);
    if entry & PTE_P == 0 {
        write_entry(table_phys, idx, (phys & PTE_ADDR_MASK) | leaf);
    }

    Ok(())
}

pub fn ensure_iommu_1gib_mapped(
    root_phys: u64,
    iova: u64,
    phys: u64,
    _len: u64,
    permissions: IommuMapPermissions,
) -> Result<(), IommuError> {
    let is_amd = matches!(super::backend(), Some(super::IommuBackend::Amd(_)));

    let interior_flags = |level: u32| -> u64 {
        if is_amd {
            permissions.amd_flags() | (((level - 1) as u64) << 9)
        } else {
            PTE_P | PTE_RW
        }
    };

    let mut leaf = if is_amd {
        permissions.amd_flags() | (0 << 9)
    } else {
        permissions.intel_flags() | (1 << 7)
    };

    let mut table_phys = root_phys;
    let lvl = 4;
    let idx = iova_index(iova, lvl);
    let entry = read_entry(table_phys, idx);

    if entry & PTE_P == 0 {
        let new_table = alloc_pt_frame_phys().ok_or(IommuError::NoBackingFrame)?;
        let new_entry = (new_table & PTE_ADDR_MASK) | interior_flags(lvl);
        write_entry(table_phys, idx, new_entry);
        table_phys = new_table;
    } else {
        table_phys = entry & PTE_ADDR_MASK;
    }

    let idx = iova_index(iova, 3);
    let entry = read_entry(table_phys, idx);
    if entry & PTE_P == 0 {
        write_entry(table_phys, idx, (phys & PTE_ADDR_MASK) | leaf);
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
