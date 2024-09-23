use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use spin::Lazy;
use spin::mutex::Mutex;
use crate::drivers::drive::ide_disk_driver::{DriveInfo, IdeController};
use crate::drivers::drive::sata_disk_drivers::AHCIController;
use strum::IntoEnumIterator; // Trait for iterating over enum variants
use strum_macros::EnumIter;
use crate::drivers::pci::device_collection::Device;

// Macro to derive iteration
pub static DRIVECOLLECTION: Lazy<Mutex<DriveCollection>> = Lazy::new(|| {
    Mutex::new(DriveCollection::new())
});
pub enum Controller {
    AHCI(AHCIController),
    IDE(IdeController),
}
impl Controller{
    fn enumerate_drives(){
        AHCIController::enumerate_drives();
        IdeController::enumerate_drives();
    }

}

pub enum DriveType {
    Master = 0xE0,
    Slave = 0xF0,
    AHCI = 0x00,
}

// All drives must implement this trait
pub trait DriveController {
    fn read(&mut self, label: &str, sector: u32, buffer: &mut [u8]);
    fn write(&mut self, label: &str, sector: u32, data: &[u8]);
    fn enumerate_drives() where Self: Sized;
    fn isController(device: &Device) -> bool where Self: Sized;
}

pub struct Drive {
    pub label: String,
    pub info: DriveInfo,
    pub controller: Box<dyn DriveController + Send>,
}

impl Drive {
    pub fn new(label: String, info: DriveInfo, controller: Box<dyn DriveController + Send>) -> Self {
        Drive {
            label,
            info,
            controller,
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

    pub(crate) fn new_drive(&mut self, label: String, info: DriveInfo, controller: Box<dyn DriveController + Send>) {
        let drive = Drive::new(label, info, controller);
        self.drives.push(drive);
    }
    pub(crate) fn enumerate_drives(){
        <IdeController as DriveController>::enumerate_drives();
        <AHCIController as DriveController>::enumerate_drives();
    }
    pub fn find_free_label(&self) -> Option<String> {
        let mut used_labels = [false; 26]; // A flag array for each letter A-Z

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
                let letter = (b'A' + i as u8).to_string();

                return Some(":".to_owned() + &*letter);
            }
        }

        None // No free label found
    }
}
