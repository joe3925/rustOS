use crate::drivers::drive::generic_drive::PartitionErrors::{BadName, NoSpace, NotGPT};
use crate::drivers::drive::gpt::{Gpt, GptHeader, GptPartitionEntry, VOLUMES};
use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::drive::ram_disk::RamDiskController;
use crate::drivers::drive::sata_disk_drivers::AHCIController;
// Trait for iterating over enum variants
use crate::drivers::pci::device_collection::Device;
use crate::file_system::fat::format_boot_drive;
use crate::println;
use crate::util::{print_mem_report, BootPkg};
use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use spin::mutex::Mutex;
use spin::Lazy;
use strum_macros::Display;

// Macro to derive iteration
pub static DRIVECOLLECTION: Lazy<Mutex<DriveCollection>> =
    Lazy::new(|| Mutex::new(DriveCollection::new()));
pub enum Controller {
    AHCI(AHCIController),
    IDE(IdeController),
}
impl Controller {
    fn enumerate_drives() {
        //AHCIController::enumerate_drives();
        //IdeController::enumerate_drives();
    }
}
#[derive(Debug, Display)]
pub enum FormatStatus {
    TooCorrupted,
    AlreadyFat32,
    DriveDoesntExist,
    AlreadyGPT,
    UnknownFail,
}
impl FormatStatus {
    pub fn to_str(&self) -> &'static str {
        match self {
            FormatStatus::TooCorrupted => "The former Fat32 filesystem is too corrupted to be formatted by this os please try a different formatter",
            FormatStatus::AlreadyFat32 => "The volume is already formated ",
            FormatStatus::DriveDoesntExist => "The drive specified could not be found",
            FormatStatus::AlreadyGPT => "Cannot format already GPT drive with normal format attempt force format",
            FormatStatus::UnknownFail => "Formatting failed for an unknown reason"
        }
    }
}
#[derive(Debug, Display)]
pub enum PartitionErrors {
    NoSpace,
    BadName,
    NotGPT,
}
impl PartitionErrors {
    pub fn to_str(&self) -> &'static str {
        match self {
            NoSpace => "Not enough space for partition",
            BadName => "Name is too long must be less then 72 characters",
            NotGPT => "The drive is not formatted as GPT",
        }
    }
}
pub enum DriveType {
    Master = 0xE0,
    Slave = 0xF0,
    AHCI = 0x00,
}
#[derive(Debug, Clone)]
pub struct DriveInfo {
    pub model: String,
    pub serial: String,
    pub port: u32,
    pub capacity: u64,
}
impl DriveInfo {
    pub fn print(&self) {
        println!("Drive port: {}", self.port);
        println!("Model: {}", self.model);
        println!("Serial Number: {}", self.serial);
        println!("Capacity: {} bytes", self.capacity);
        println!("--------------------------------");
    }
}

// All drives controllers must implement this trait
pub trait DriveController: Send + Sync {
    fn read(&mut self, sector: u32, buffer: &mut [u8]);
    fn write(&mut self, sector: u32, data: &[u8]);
    fn enumerate_drives() -> Vec<Drive>
    where
        Self: Sized;
    fn factory(&self) -> Box<dyn DriveController + Send + Sync>;
    fn is_controller(device: &Device) -> bool
    where
        Self: Sized;
}

pub struct Drive {
    pub info: DriveInfo,
    pub controller: Box<dyn DriveController + Send>,
    pub is_fat: bool,
    pub index: i64,
    pub gpt_data: Option<Gpt>,
}

impl Drive {
    pub fn new(index: i64, info: DriveInfo, controller: Box<dyn DriveController + Send>) -> Self {
        Drive {
            index,
            info,
            controller,
            is_fat: false,
            gpt_data: None,
        }
    }
}

pub struct DriveCollection {
    pub drives: Vec<Drive>,
}

impl DriveCollection {
    fn new() -> Self {
        DriveCollection { drives: Vec::new() }
    }

    pub(crate) fn new_drive(
        &mut self,
        index: i64,
        info: DriveInfo,
        controller: Box<dyn DriveController + Send>,
    ) {
        let drive = Drive::new(index, info, controller);
        self.drives.push(drive);
    }
    pub(crate) fn enumerate_drives(&mut self) {
        let mut drives: Vec<Drive> = Vec::new();
        drives.extend(<IdeController as DriveController>::enumerate_drives());
        //drives.extend(<AHCIController as DriveController>::enumerate_drives());
        for mut drive in drives {
            if (drive.index == -1) {
                drive.index = self.drives.len() as i64;
                let mut header_buffer = vec![0u8; 512];
                drive.controller.read(1, &mut header_buffer);
                if let Some(header) = GptHeader::new(&header_buffer) {
                    let mut partition_buffer = vec![0u8; 512];
                    let mut partitions = Vec::new();
                    for i in 2..33 {
                        drive.controller.read(i, &mut partition_buffer);
                        if let Some(part) = GptPartitionEntry::new(&partition_buffer) {
                            partitions.push(part);
                        }
                    }
                    let gpt = Gpt {
                        header,
                        entries: partitions,
                    };
                }
                self.drives.push(drive);
            }
        }
    }
    pub fn print_drives(&self) {
        if self.drives.is_empty() {
            println!("No drives in the collection.");
        } else {
            for (i, drive) in self.drives.iter().enumerate() {
                println!("Drive {}:", i + 1);
                println!("Index: {}", drive.index);
                drive.info.print();
            }
        }
    }
}
pub fn boot_part_init(boot: &[BootPkg]) {
    let mut ram = RamDiskController {
        sector_size: 512,
        reported_sectors: (10 * 1024 * 1024 * 1024) / 512,
        base: &[],
        overlay: Arc::new(Mutex::new(BTreeMap::new())),
        views: Arc::new(Mutex::new(BTreeMap::new())),
        runs: Arc::new(Mutex::new(BTreeMap::new())),
        cluster_bytes: 4096,
    };
    let mut part = ram.new_partition();

    part.label = "C:".to_string();
    part.name = "MAIN VOLUME".to_string();
    if let Err(e) = format_boot_drive(&mut part, &mut ram, boot) {
        println!("BOOT: format_boot_drive failed: {:?}", e);
        return;
    }

    VOLUMES.lock().parts.push(part);
}
