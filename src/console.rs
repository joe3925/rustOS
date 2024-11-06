
use core::fmt::Write;
use spin::Mutex;
use crate::scheduling::scheduler::thr_yield;
pub(crate) struct Console {
    pub(crate) current_line: usize,
    pub(crate) current_char_size: usize,
    pub(crate) vga_width: usize,
    pub(crate) cursor_pose: usize,
}

impl Console {
    pub const fn new() -> Self {
        Console {
            current_char_size: 0,
            vga_width: 80,
            cursor_pose: 0,
            current_line: 0,
        }
    }

    const fn vga_buffer() -> &'static mut [u8] {
        // Unsafe slice directly referencing the VGA memory at 0xB8000
        unsafe { core::slice::from_raw_parts_mut(0xB8000 as *mut u8, 80 * 25 * 2) }
    }

    pub(crate) fn print(&mut self, str: &[u8]) {
        let mut i = 0;
        let vga_buffer = Console::vga_buffer();
        while i < str.len() && self.cursor_pose + 2 <= 80 * 25 * 2 {
            // Correct cursor position if it's not even
            if self.cursor_pose % 2 != 0 {
                self.cursor_pose += 1;
            }

            // Handle newlines
            if self.cursor_pose > 80 * 25 * 2 {
                self.scroll_up();
            }

            if str[i] == b'\n' {
                self.cursor_pose += (self.vga_width * 2) - (self.cursor_pose % (self.vga_width * 2));
                self.current_line += 1;
                self.current_char_size = 0;
            }
            // Handle backspace
            else if str[i] == 0x08 {
                if vga_buffer[self.cursor_pose] == 0x0 {
                    while self.cursor_pose > 0 && vga_buffer[self.cursor_pose] == 0x0 {
                        self.cursor_pose -= 2;
                    }
                }
                if vga_buffer[self.cursor_pose] != 0x0 {
                    vga_buffer[self.cursor_pose] = 0x0; // Clear character
                    vga_buffer[self.cursor_pose + 1] = 0x07; // Reset attribute (white on black)
                    self.current_char_size = self.current_char_size.saturating_sub(1);
                }
            }
            // Handle regular character printing
            else {
                if self.current_line >= 24 {
                    self.scroll_up();
                    self.current_line = 23;
                    self.cursor_pose = self.current_line * self.vga_width * 2;
                }

                vga_buffer[self.cursor_pose] = str[i];
                vga_buffer[self.cursor_pose + 1] = 0x07; // White foreground, black background
                self.cursor_pose += 2;
                self.current_char_size += 1;
            }

            i += 1;
        }
    }

    pub unsafe fn reset_state(){
        CONSOLE.force_unlock();
        CONSOLE = Mutex::new(Console::new());
    }

    fn scroll_up(&mut self) {
        let mut vga_buffer = Console::vga_buffer();
        for y in 1..25 {
            for x in 0..self.vga_width {
                let from = (y * self.vga_width + x) * 2;
                let to = ((y - 1) * self.vga_width + x) * 2;

                vga_buffer[to] = vga_buffer[from];
                vga_buffer[to + 1] = vga_buffer[from + 1];
            }
        }

        // Clear the last line
        let last_line_start = (24 * self.vga_width)  * 2;
        for x in 0..self.vga_width  {
            vga_buffer[last_line_start + x * 2] = b' ';
            vga_buffer[last_line_start + x * 2 + 1] = 0x07;
        }

        // Adjust the cursor position after scrolling
        self.cursor_pose = (self.vga_width * 23 * 2) + (self.current_char_size * 2);
    }
}

pub(crate) static mut CONSOLE: Mutex<Console> = Mutex::new(Console::new());

#[allow(dead_code)]
pub(crate) fn clear_vga_buffer() {
    let vga_buffer = Console::vga_buffer();
    let mut i = 0;
    unsafe {
        while (i < 0xFA0) {
            vga_buffer[i] = 0x0;

            i += 2;
        }
    }
}
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n");
    };
    ($($arg:tt)*) => {
        $crate::print!("{}\n", format_args!($($arg)*))
    };
}

#[doc(hidden)]
pub(crate) fn _print(args: core::fmt::Arguments) {
    // Create a buffer to hold the formatted string
    let mut buffer = [0u8; 1024]; // Allocate a 1024-byte buffer
    let mut writer = BufferWriter::new(&mut buffer);

    // Write the formatted arguments into the buffer
    write!(writer, "{}", args).unwrap();
    // Print the formatted buffer using Console's print method
    unsafe {
        CONSOLE.lock().print(writer.as_bytes());
    }
}

// Helper structure to wrap the buffer and implement core::fmt::Write for it
struct BufferWriter<'a> {
    buffer: &'a mut [u8],
    position: usize,
}

impl<'a> BufferWriter<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        BufferWriter { buffer, position: 0 }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.position]
    }
}

impl<'a> Write for BufferWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let available_space = self.buffer.len() - self.position;
        let bytes_to_write = bytes.len().min(available_space);

        self.buffer[self.position..self.position + bytes_to_write]
            .copy_from_slice(&bytes[..bytes_to_write]);
        self.position += bytes_to_write;

        if bytes_to_write < bytes.len() {
            return Err(core::fmt::Error); // Buffer overflow
        }

        Ok(())
    }
}

