use core::cmp::min;

use crate::vec;
use crate::{drivers::drive::generic_drive::DriveInfo, util::BOOTSET_IMG};
use alloc::string::ToString;
use alloc::{boxed::Box, collections::btree_map::BTreeMap, vec::Vec};

use super::generic_drive::{Drive, DriveController};
use super::gpt::{GptPartitionEntry, Partition, PartitionController};

pub struct RamDiskController {
    sector_size: u32,                  // usually 512
    reported_sectors: u64,             // e.g., 10 GiB in sectors
    base: &'static [u8],               // bootset image (read-only)
    overlay: BTreeMap<u64, Box<[u8]>>, // LBA -> full sector (writable)
}

impl RamDiskController {
    pub fn from_bootset() -> Self {
        let sector_size = 512u32;
        let reported_bytes: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB reported
        let reported_sectors = reported_bytes / sector_size as u64;

        Self {
            sector_size,
            reported_sectors,
            base: BOOTSET_IMG,
            overlay: BTreeMap::new(),
        }
    }

    #[inline]
    fn ss(&self) -> usize {
        self.sector_size as usize
    }

    fn read_sector_into(&mut self, lba: u32, buf: &mut [u8]) {
        let ss = self.ss();
        if buf.len() < ss {
            return;
        }

        // 1) Prefer overlay (written) data
        if let Some(over) = self.overlay.get(&(lba as u64)) {
            buf[..ss].copy_from_slice(&over);
            return;
        }

        // 2) Fall back to the base bootset image
        let off = (lba as usize) * ss;
        if off >= self.base.len() {
            // beyond base and not written yet -> zeros
            buf[..ss].fill(0);
            return;
        }

        let end = min(off + ss, self.base.len());
        let n = end - off;
        buf[..n].copy_from_slice(&self.base[off..end]);
        if n < ss {
            buf[n..ss].fill(0);
        }
    }

    fn write_sector(&mut self, lba: u32, data: &[u8]) {
        let ss = self.ss();
        if data.is_empty() {
            return;
        }
        let mut dst = match self.overlay.get(&(lba as u64)) {
            Some(existing) => existing.clone(),
            None => {
                // Seed from base (or zeros) so partial writes behave nicely
                let mut seeded = vec![0u8; ss].into_boxed_slice();
                let off = (lba as usize) * ss;
                if off < self.base.len() {
                    let end = min(off + ss, self.base.len());
                    let n = end - off;
                    seeded[..n].copy_from_slice(&self.base[off..end]);
                }
                self.overlay.insert(lba as u64, seeded);
                self.overlay.get(&(lba as u64)).unwrap().clone()
            }
        };

        // Copy as much as provided (cap at sector)
        let n = min(ss, data.len());
        dst[..n].copy_from_slice(&data[..n]);
        self.overlay.insert(lba as u64, dst);
    }
    pub fn new_partition() -> Partition {
        let driver_controller = Self::from_bootset().factory();
        let controller =
            PartitionController::new(driver_controller, 0, (10 * 1024 * 1024 * 1024) / 512);

        let dummy = GptPartitionEntry {
            partition_type_guid: *(vec![0u8; 16].as_array().unwrap()),
            unique_partition_guid: *(vec![0u8; 16].as_array().unwrap()),
            first_lba: 0,
            last_lba: 0,
            attribute_flags: 0,
            partition_name: *(vec![0u16; 36].as_array().unwrap()),
        };
        Partition {
            gpt_entry: dummy,
            parent_drive_index: 9999,
            name: "Bootstrap".to_string(),
            label: "C:".to_string(),
            size: (10 * 1024 * 1024 * 1024) / 512,
            controller,
            is_fat: true,
        }
    }
}

impl DriveController for RamDiskController {
    fn read(&mut self, lba: u32, buffer: &mut [u8]) {
        self.read_sector_into(lba, buffer);
    }

    fn write(&mut self, lba: u32, data: &[u8]) {
        self.write_sector(lba, data);
    }

    fn enumerate_drives() -> Vec<Drive>
    where
        Self: Sized,
    {
        // Expose exactly one RAM disk sourced from the bootset image.
        let mut ctrl = RamDiskController::from_bootset();
        let cap = ctrl.reported_sectors * ctrl.sector_size as u64;

        let info = DriveInfo {
            model: "RAMDISK (bootset)".into(),
            serial: "BOOTSET".into(),
            port: 0,
            capacity: cap, // reported capacity
        };

        vec![Drive::new(-1, info, Box::new(ctrl))]
    }

    fn factory(&self) -> Box<dyn DriveController + Send + Sync> {
        // Clone a controller that sees the same base (overlay starts empty)
        Box::new(RamDiskController {
            sector_size: self.sector_size,
            reported_sectors: self.reported_sectors,
            base: self.base,
            overlay: BTreeMap::new(),
        })
    }

    fn is_controller(_: &crate::drivers::pci::device_collection::Device) -> bool
    where
        Self: Sized,
    {
        // Not PCI-backed
        false
    }
}
