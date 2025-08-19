use core::cmp::min;

use crate::drivers::drive::generic_drive::DriveInfo;
use crate::vec;
use alloc::string::ToString;
use alloc::{boxed::Box, collections::btree_map::BTreeMap, sync::Arc, vec::Vec};

use super::generic_drive::{Drive, DriveController};
use super::gpt::{GptPartitionEntry, Partition, PartitionController};
use spin::Mutex;

#[derive(Clone)]
pub enum SectorView {
    Slice { base: &'static [u8], off: usize },
}

pub struct RamDiskController {
    pub sector_size: u32,
    pub reported_sectors: u64,
    pub base: &'static [u8],
    // Shared across clones returned by `factory()`:
    pub overlay: Arc<Mutex<BTreeMap<u64, Box<[u8]>>>>, // LBA -> sector data (COW)
    pub views: Arc<Mutex<BTreeMap<u64, SectorView>>>,  // LBA -> zero-copy view
}

impl RamDiskController {
    #[inline]
    fn ss(&self) -> usize {
        self.sector_size as usize
    }

    pub fn new(sector_size: u32, reported_sectors: u64, base: &'static [u8]) -> Self {
        Self {
            sector_size,
            reported_sectors,
            base,
            overlay: Arc::new(Mutex::new(BTreeMap::new())),
            views: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
    pub fn map_lba_from_slice(&self, lba: u32, src: &'static [u8], offset: usize) {
        self.views.lock().insert(
            lba as u64,
            SectorView::Slice {
                base: src,
                off: offset,
            },
        );
    }

    fn read_sector_into(&mut self, lba: u32, buf: &mut [u8]) {
        let ss = self.ss();
        if buf.len() < ss {
            return;
        }

        if let Some(over) = self.overlay.lock().get(&(lba as u64)) {
            buf[..ss].copy_from_slice(over);
            return;
        }

        if let Some(view) = self.views.lock().get(&(lba as u64)) {
            match *view {
                SectorView::Slice { base, off } => {
                    let end = core::cmp::min(base.len(), off + ss);
                    let n = end.saturating_sub(off);
                    if n > 0 {
                        buf[..n].copy_from_slice(&base[off..end]);
                    }
                    if n < ss {
                        buf[n..ss].fill(0);
                    }
                    return;
                }
            }
        }

        let off = (lba as usize) * ss;
        if off >= self.base.len() {
            buf[..ss].fill(0);
            return;
        }
        let end = core::cmp::min(off + ss, self.base.len());
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

        let view_opt = { self.views.lock().get(&(lba as u64)).cloned() };

        let mut ol = self.overlay.lock();
        let dst = ol.entry(lba as u64).or_insert_with(|| {
            let mut seeded = vec![0u8; ss].into_boxed_slice();

            if let Some(SectorView::Slice { base, off }) = view_opt {
                let end = min(base.len(), off + ss);
                let n = end.saturating_sub(off);
                if n > 0 {
                    seeded[..n].copy_from_slice(&base[off..end]);
                }
            } else {
                let off = (lba as usize) * ss;
                if off < self.base.len() {
                    let end = min(off + ss, self.base.len());
                    let n = end - off;
                    seeded[..n].copy_from_slice(&self.base[off..end]);
                }
            }

            seeded
        });

        let n = min(ss, data.len());
        dst[..n].copy_from_slice(&data[..n]);
    }

    pub fn new_partition(&self) -> Partition {
        let driver_controller = self.factory();
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
        Vec::new()
    }

    fn factory(&self) -> Box<dyn DriveController + Send + Sync> {
        Box::new(RamDiskController {
            sector_size: self.sector_size,
            reported_sectors: self.reported_sectors,
            base: self.base,
            overlay: self.overlay.clone(),
            views: self.views.clone(),    
        })
    }

    fn is_controller(_: &crate::drivers::pci::device_collection::Device) -> bool
    where
        Self: Sized,
    {
        false
    }
}
