
use alloc::string::String;
use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::drive::sata_disk_drivers::AHCIController;

pub enum Controller {
    AHCI(AHCIController),
    IDE(IdeController),
}
//All drives must implement this trait
pub trait DriveController {
    fn read(&mut self, label: String, sector: u32, buffer: &mut [u8]);
    fn write(&mut self, label: String, sector: u32, data: &[u8]);
    fn size(&self, label: String) -> Option<usize>;
}

pub struct Drive<'a> {
    pub label: String,
    pub Name: String,
    pub controller: &'a mut dyn DriveController, // A reference to any controller that implements the DriveController trait
} impl Drive{
    pub fn new<'a>(label: String, Name: String, controller: &'a mut dyn DriveController) -> Self{
        Drive{
            label,
            Name,
            controller
        }
    }
}

