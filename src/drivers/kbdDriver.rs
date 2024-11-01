use lazy_static::lazy_static;
use x86_64::structures::idt::InterruptStackFrame;
use crate::drivers::interrupt_index::InterruptIndex::KeyboardIndex;
use crate::drivers::interrupt_index::send_eoi;
use crate::{print};
use x86_64::instructions::port::Port;
use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};
use spin::Mutex;


pub(crate) extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    lazy_static! {
        static ref KEYBOARD: Mutex<Keyboard<layouts::Us104Key, ScancodeSet1>> =
            Mutex::new(Keyboard::new(ScancodeSet1::new(),
                layouts::Us104Key, HandleControl::Ignore)
            );
    }

    unsafe {
        let mut port = Port::new(0x60);
        let scancode: u8 = port.read();

        let mut keyboard = KEYBOARD.lock();
        if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {

            if let Some(key) = keyboard.process_keyevent(key_event) {

                match key {
                    DecodedKey::Unicode(character) => print!("{}", character),
                    DecodedKey::RawKey(key) => print!("{:?}", key),
                }
            }
        }

        send_eoi(KeyboardIndex.as_u8());
    }
}