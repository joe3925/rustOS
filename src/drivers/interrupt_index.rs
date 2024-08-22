use x86_64::instructions::port;
use x86_64::instructions::port::Port;
use pic8259::ChainedPics;
use spin;
use crate::drivers::interrupt_index::InterruptIndex::KeyboardIndex;
use crate::println;

pub(crate) const PIC_1_OFFSET: u8 = 32;
pub(crate) const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub(crate) static PICS: spin::Mutex<ChainedPics> =
    spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });
#[derive(Debug, Clone, Copy)]
#[repr(u8)]


pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    KeyboardIndex = PIC_1_OFFSET + 1,
}

impl InterruptIndex {
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }

    pub(crate) fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}
pub fn send_eoi(irq: u8) {
    unsafe {
        PICS.lock().notify_end_of_interrupt(irq);
    }
}