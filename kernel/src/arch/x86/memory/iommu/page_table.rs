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

const IOMMU_TABLE_ARENA_SIZE: u64 = 8 * 1024 * 1024;
const IOMMU_TABLE_PAGE_SIZE: u64 = 0x1000;

static IOMMU_TABLE_ARENA: Mutex<IommuTableArena> = Mutex::new(IommuTableArena::empty());

struct IommuTableArena {
    phys_base: u64,
    virt_base: u64,
    size: u64,
    next: u64,
}

impl IommuTableArena {
    const fn empty() -> Self {
        Self {
            phys_base: 0,
            virt_base: 0,
            size: 0,
            next: 0,
        }
    }

    fn contains_phys(&self, phys: u64) -> bool {
        self.size != 0 && phys >= self.phys_base && phys < self.phys_base + self.size
    }

    fn virt_for_phys<T>(&self, phys: u64) -> Option<*mut T> {
        if !self.contains_phys(phys) {
            return None;
        }
        Some((self.virt_base + (phys - self.phys_base)) as *mut T)
    }

    fn alloc_page(&mut self) -> Option<(u64, *mut u64)> {
        let next = self.next.checked_add(IOMMU_TABLE_PAGE_SIZE)?;
        if next > self.size {
            return None;
        }

        let phys = self.phys_base + self.next;
        let ptr = (self.virt_base + self.next) as *mut u64;
        self.next = next;
        Some((phys, ptr))
    }
}

pub fn init_table_arena() -> Result<(), IommuError> {
    let mut arena = IOMMU_TABLE_ARENA.lock();
    if arena.size != 0 {
        return Ok(());
    }

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let virt = allocate_auto_kernel_range_mapped_contiguous(IOMMU_TABLE_ARENA_SIZE, flags)
        .map_err(|_| IommuError::NoBackingFrame)?;
    let (_, phys) = virt_to_phys(virt).ok_or(IommuError::NoBackingFrame)?;

    *arena = IommuTableArena {
        phys_base: phys.as_u64(),
        virt_base: virt.as_u64(),
        size: IOMMU_TABLE_ARENA_SIZE,
        next: 0,
    };
    Ok(())
}

#[inline]
pub(crate) unsafe fn phys_to_mut<T>(phys: u64) -> *mut T {
    IOMMU_TABLE_ARENA
        .lock()
        .virt_for_phys::<T>(phys)
        .expect("IOMMU table physical address is outside the table arena")
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
    let (phys, ptr) = IOMMU_TABLE_ARENA.lock().alloc_page()?;
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
#[inline]
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
