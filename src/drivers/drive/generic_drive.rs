use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use lazy_static::lazy_static;
use spin::Lazy;
use spin::mutex::Mutex;
use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::drive::sata_disk_drivers::AHCIController;
use crate::drivers::pci::pci_bus::PciBus;
use crate::memory::allocator::Locked;

pub static DRIVECOLLECTION: Lazy<Mutex<DriveCollection>> = Lazy::new(|| {
    Mutex::new(DriveCollection::new())
});

pub enum Controller {
    AHCI(AHCIController),
    IDE(IdeController),
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
    fn size(&self, label: &str) -> Option<usize>;
    fn isController(class: u8, sub_class: u8) -> bool;
}

pub struct Drive {
    pub label: String,
    pub name: String,
    pub controller: Box<dyn DriveController + Send>,
}

impl Drive {
    pub fn new(label: String, name: String, controller: Box<dyn DriveController + Send>) -> Self {
        Drive {
            label,
            name,
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

    fn new_drive(&mut self, label: String, name: String, controller: Box<dyn DriveController + Send>) {
        let drive = Drive::new(label, name, controller);
        self.drives.push(drive);
    }
}
