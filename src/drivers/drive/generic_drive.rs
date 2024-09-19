//This file will enumerate all drives and assign each a generic read write function

use alloc::string::String;
use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::drive::sata_disk_drivers::AHCIController;

pub enum Controller {
    AHCI(AHCIController),
    IDE(IdeController),
}
//All drives must implement this trait
pub trait DriveOperations {
    fn read(&self, sector: u64, buffer: &mut [u8]);
    fn write(&self, sector: u64, data: &[u8]);
}

struct Drive {
    label: String,
    Name: String,
    controller: Controller
}

