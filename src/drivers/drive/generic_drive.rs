
use alloc::string::String;
use alloc::vec;
use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::drive::sata_disk_drivers::AHCIController;
use crate::drivers::pci::pci_bus::PciBus;
use crate::memory::allocator::Locked;

pub(crate) static mut DRIVECOLLECTION: Locked<DriveCollection> =
    Locked::new(DriveCollection::new());
pub enum Controller {
    AHCI(AHCIController),
    IDE(IdeController),
}
pub enum DriveType {
    Master = 0xE0,
    Slave = 0xF0,
    ACHI = 0x00,
}
//All drives must implement this trait
pub trait DriveController {
    fn read(&mut self, label: String, sector: u32, buffer: &mut [u8]);
    fn write(&mut self, label: String, sector: u32, data: &[u8]);
    fn size(&self, label: String) -> Option<usize>;
}

pub struct Drive<'a> {
    pub label: String,
    pub name: String,
    pub controller: &'a mut dyn DriveController, // A reference to any controller that implements the DriveController trait
}
impl Drive{
    pub fn new<'a>(label: String, name: String, controller: &'a mut dyn DriveController) -> Self{
        Drive{
            label,
            name,
            controller
        }
    }
}
pub struct DriveCollection<'a> {
    pub drives: vec<Drive<'a>>,
}
impl DriveCollection{
    fn new() -> Self{
        DriveCollection{
            drives: (),
        }
    }
    fn new_drive<'a>(&mut self, label: String, name: String, controller: &'a mut dyn DriveController,){
    }
}
