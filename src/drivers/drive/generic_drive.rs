use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::drive::sata_disk_drivers::AHCIController;
// Trait for iterating over enum variants
use crate::drivers::pci::device_collection::Device;
use crate::println;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use spin::mutex::Mutex;
use spin::Lazy;
use strum_macros::Display;

// Macro to derive iteration
pub static DRIVECOLLECTION: Lazy<Mutex<DriveCollection>> = Lazy::new(|| {
    Mutex::new(DriveCollection::new())
});
pub enum Controller {
    AHCI(AHCIController),
    IDE(IdeController),
}
impl Controller {
    fn enumerate_drives() {
        //AHCIController::enumerate_drives();
        IdeController::enumerate_drives();
    }
}
#[derive(Debug, Display)]
pub enum FormatStatus {
    TooCorrupted,
    AlreadyFat32,
    DriveDoesntExist,
}
impl FormatStatus {
    pub fn to_str(&self) -> &'static str {
        match self {
            FormatStatus::TooCorrupted => "The former Fat32 filesystem is too corrupted to be formatted by this OS please try a different formatter",
            FormatStatus::AlreadyFat32 => "File already exists",
            FormatStatus::DriveDoesntExist => "The drive specified could not be found"
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

// All drives must implement this trait
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
}

impl Drive {
    pub fn new(index: i64, info: DriveInfo, controller: Box<dyn DriveController + Send>) -> Self {
        Drive {
            index,
            info,
            controller,
            is_fat: false,
        }
    }
}


pub struct DriveCollection {
    pub drives: Vec<Drive>,

}

impl DriveCollection {
    fn new() -> Self {
        DriveCollection {
            drives: Vec::new(),
        }
    }

    pub(crate) fn new_drive(&mut self, index: i64, info: DriveInfo, controller: Box<dyn DriveController + Send>) {
        let drive = Drive::new(index, info, controller);
        self.drives.push(drive);
    }
    pub(crate) fn enumerate_drives(&mut self) {
        let mut drives = Vec::new();
        drives.extend(<IdeController as DriveController>::enumerate_drives());
        //drives.extend(<AHCIController as DriveController>::enumerate_drives());

        for mut drive in drives {
            if (drive.index == -1) {
                drive.index = self.drives.len() as i64;
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
                drive.info.print(); // Call the print method of DriveInfo
            }
        }
    }
}
