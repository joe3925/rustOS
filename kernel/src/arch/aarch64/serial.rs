use crate::platform::ConsolePlatform;

use super::platform::Aarch64Platform;

impl ConsolePlatform for Aarch64Platform {
    fn serial_write_bytes(bytes: &[u8]) {
        let uart = 0x0900_0000 as *mut u32;
        for &byte in bytes {
            unsafe {
                while uart.add(6).read_volatile() & (1 << 5) != 0 {
                    core::hint::spin_loop();
                }
                uart.write_volatile(byte as u32);
            }
        }
    }
}
