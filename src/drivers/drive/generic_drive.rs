use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::drive::sata_disk_drivers::AHCIController;
// Trait for iterating over enum variants
use crate::drivers::pci::device_collection::Device;
use crate::file_system::fat::FileSystem;
use crate::println;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use spin::mutex::Mutex;
use spin::Lazy;

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
        AHCIController::enumerate_drives();
        IdeController::enumerate_drives();
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
pub trait DriveController {
    fn read(&mut self, sector: u32, buffer: &mut [u8]);
    fn write(&mut self, sector: u32, data: &[u8]);
    fn enumerate_drives()
    where
        Self: Sized;
    fn is_controller(device: &Device) -> bool
    where
        Self: Sized;
}

pub struct Drive {
    pub label: String,
    pub info: DriveInfo,
    pub controller: Box<dyn DriveController + Send>,
    pub is_fat: bool, // New flag to indicate if the drive uses the FAT filesystem

}

impl Drive {
    pub fn new(label: String, info: DriveInfo, controller: Box<dyn DriveController + Send>) -> Self {
        Drive {
            label,
            info,
            controller,
            is_fat: false,
        }
    }
    pub fn format(&mut self) -> Result<(), &'static str> {
        let mut fs = FileSystem::new(self.label.clone());
        self.is_fat = fs.is_fat_present();
        if (self.is_fat == false) {
            return fs.format_drive();
        }
        Err("Drive is already formatted")
    }
    pub fn force_format(&mut self) -> Result<(), &'static str> {
        FileSystem::new(self.label.clone()).format_drive()
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

    pub(crate) fn new_drive(&mut self, label: String, info: DriveInfo, controller: Box<dyn DriveController + Send>) {
        let drive = Drive::new(label, info, controller);
        self.drives.push(drive);
    }
    pub(crate) fn enumerate_drives() {
        <IdeController as DriveController>::enumerate_drives();
        <AHCIController as DriveController>::enumerate_drives();
    }
    pub fn find_drive(&mut self, label: String) -> Option<&mut Drive> {
        for drive in self.drives.iter_mut() { // Iterate over mutable references
            if drive.label == label {
                return Some(drive); // Return the mutable reference
            }
        }
        None
    }
    pub fn print_drives(&self) {
        if self.drives.is_empty() {
            println!("No drives in the collection.");
        } else {
            for (i, drive) in self.drives.iter().enumerate() {
                println!("Drive {}:", i + 1);
                println!("Label: {}", drive.label);
                drive.info.print(); // Call the print method of DriveInfo
            }
        }
    }
    pub fn find_free_label(&self) -> Option<String> {
        let mut used_labels = [false; 26]; // A flag array for each letter A-Z

        // Mark used labels
        for drive in &self.drives {
            if let Some(first_char) = drive.label.chars().next() {
                if first_char.is_ascii_alphabetic() {
                    let index = (first_char.to_ascii_uppercase() as u8 - b'A') as usize;
                    if index < 26 {
                        used_labels[index] = true;
                    }
                }
            }
        }

        // Find the first unused label from A: to Z:
        for i in 0..26 {
            if !used_labels[i] {
                let letter = (b'A' + i as u8) as char;
                return Some(format!("{}:", letter)); // Correctly format the label (e.g., "A:")
            }
        }

        None // No free label found
    }
}
