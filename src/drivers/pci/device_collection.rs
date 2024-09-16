use alloc::vec::Vec;



pub(crate) struct Device{
    pub(crate) bus: u8,
    pub(crate) device: u8,
    pub(crate) function: u8,
    pub(crate) id: u32,
    pub(crate) class_code: u8,
    pub(crate) subclass: u8,
}
impl Device{
    pub fn new(bus: u8, device: u8, function: u8, id: u32, class_code: u8, subclass: u8) -> Self {
        Device {
            bus,
            device,
            function,
            id,
            class_code,
            subclass,
        }
    }
}
pub(crate) struct DeviceCollection {
    pub(crate) devices: Vec<Device>,
}
impl DeviceCollection {
    pub fn new() -> Self {
        DeviceCollection {
            devices: Vec::new(),
        }
    }
    pub fn add_device(&mut self, device: Device) {
        self.devices.push(device);
    }
}