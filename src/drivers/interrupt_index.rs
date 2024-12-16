use pic8259::ChainedPics;


pub(crate) const PIC_1_OFFSET: u8 = 32;
pub(crate) const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub(crate) static PICS: spin::Mutex<ChainedPics> =
    spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });
#[derive(Debug, Clone, Copy)]
#[repr(u8)]

pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    KeyboardIndex = PIC_1_OFFSET + 1,
    PrimaryDrive = PIC_1_OFFSET + 14,
    SecondaryDrive = PIC_1_OFFSET + 15,

}

impl InterruptIndex {
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }
}
#[inline(never)]
pub fn send_eoi(irq: u8) {
    unsafe {
        PICS.force_unlock();
        PICS.lock().notify_end_of_interrupt(irq);
    }
}