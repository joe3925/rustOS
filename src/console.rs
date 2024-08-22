use core::fmt::{Write};
use lazy_static::lazy_static;
use spin::Mutex;
pub(crate) struct Console{
    pub(crate) currentLine: isize,
    pub(crate) currentCharSize: isize,
    pub(crate) vga_width: isize,
    pub(crate) vga_height: isize,
    pub(crate) cursor_pose: isize,
}
impl Console {
    pub(crate) fn print(&mut self, str: &[u8]) {
        let mut i = 0;
        static mut VGA_BUFFER: *mut u8 = 0xB8000 as *mut u8;

        while i < str.len() {
            if self.cursor_pose % 2 != 0 {
                // Correct cursor position if it's not even
                self.cursor_pose += 1;
                break;
            }

            if str[i] == b'\n' {
                self.cursor_pose += (self.vga_width * 2) - (self.currentCharSize * 2);
                self.currentLine += 1;
                self.currentCharSize = 0;
            } else {
                unsafe {
                    // Check if we need to scroll
                    if self.currentLine >= 24 {
                        self.scroll_up();
                        self.currentLine = 23;
                        self.cursor_pose = self.currentLine * self.vga_width * 2;
                    }

                    // Print the character at the current cursor position
                    *VGA_BUFFER.offset(self.cursor_pose as isize) = str[i];
                    *VGA_BUFFER.offset((self.cursor_pose + 1) as isize) = 0x07; // White foreground, black background
                }
                self.cursor_pose += 2;
                self.currentCharSize += 1;
            }

            i += 1;
        }
    }

    fn scroll_up(&mut self) {
        unsafe {
            let VGA_BUFFER: *mut u8 = 0xB8000 as *mut u8;

            for y in 1..25 {
                for x in 0..self.vga_width {
                    let from = ((y * self.vga_width) + x) * 2;
                    let to = (((y - 1) * self.vga_width) + x) * 2;

                    *VGA_BUFFER.offset(to as isize) = *VGA_BUFFER.offset(from as isize);
                    *VGA_BUFFER.offset((to + 1) as isize) = *VGA_BUFFER.offset((from + 1) as isize);
                }
            }

            // Clear the last line
            let last_line_start = (24 * self.vga_width) * 2;
            for x in 0..self.vga_width {
                *VGA_BUFFER.offset((last_line_start + x * 2) as isize) = b' ';
                *VGA_BUFFER.offset((last_line_start + x * 2 + 1) as isize) = 0x07;
            }
        }
    }
}
lazy_static! {
     static ref CONSOLE: Mutex<Console> = Mutex::new(Console {
        currentCharSize: 0,
        vga_width: 80,
        vga_height: 25,
        cursor_pose: 0,
        currentLine: 0,
    });
}
pub(crate) fn clear_vga_buffer() {
    for y in 0..CONSOLE.lock().vga_height {
        for x in 0..CONSOLE.lock().vga_width {
            unsafe {
                let offset = (y * CONSOLE.lock().vga_width + x) * 2;
                *((0xB8000 as *mut u8).offset(offset as isize)) = b""[0];
                *((0xB8000 as *mut u8).offset(offset as isize)) = b""[0];
            }
        }
    }
    CONSOLE.lock().currentLine = 0;
    CONSOLE.lock().cursor_pose = 0;
}
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::_print(format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n");
    };
    ($($arg:tt)*) => {
        $crate::print!("{}\n", format_args!($($arg)*));
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
    CONSOLE.lock().print(writer.as_bytes());
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

