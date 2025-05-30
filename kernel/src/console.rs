use crate::util::{boot_info, KERNEL_INITIALIZED};
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use bootloader_api::info::PixelFormat;
use core::fmt::{Pointer, Write};
use core::sync::atomic::Ordering;
use embedded_graphics::mono_font::iso_8859_5::FONT_9X18;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::Rectangle;
use embedded_graphics::text::{Baseline, Text, TextStyleBuilder};
use lazy_static::lazy_static;
use spin::Mutex;

static mut QUEUE: VecDeque<Vec<u8>> = VecDeque::new();
pub(crate) struct Cursor {
    x: usize,
    y: usize,
}
pub struct Screen {
    pub buffer_start: &'static mut [u8],
    pub width: usize,
    pub height: usize,
    pub total_size: usize,
    pub bytes_per_pixel: usize,
    pub pixel_format: PixelFormat,
    red_offset: u8,
    green_offset: u8,
    blue_offset: u8,
    is_greyscale: bool,
}

impl Screen {
    pub fn new() -> Option<Self> {
        let mut boot_info = boot_info();
        if let Some(framebuffer) = boot_info.framebuffer.as_mut() {
            //byte offset
            let mut red_offset = 0;
            let mut green_offset = 0;
            let mut blue_offset = 0;
            let mut is_greyscale = false;
            match framebuffer.info().pixel_format {
                PixelFormat::Rgb => {
                    green_offset = 1;
                    blue_offset = 2;
                }
                PixelFormat::Bgr => {
                    red_offset = 2;
                    green_offset = 1;
                    blue_offset = 0;
                }
                PixelFormat::U8 => {
                    is_greyscale = true;
                }
                PixelFormat::Unknown {
                    red_position,
                    green_position,
                    blue_position,
                } => {
                    red_offset = red_position;
                    green_offset = green_position;
                    blue_offset = blue_position;
                }
                _ => {}
            }
            Some(Screen {
                width: framebuffer.info().width.clone(),
                height: framebuffer.info().height.clone(),
                total_size: framebuffer.info().byte_len.clone(),
                pixel_format: framebuffer.info().pixel_format.clone(),
                bytes_per_pixel: framebuffer.info().bytes_per_pixel.clone(),
                buffer_start: framebuffer.buffer_mut(),
                red_offset,
                green_offset,
                blue_offset,
                is_greyscale,
            })
        } else {
            None
        }
    }
    ///Draws to a given pixel, leave rgb blank for grayscale only set a
    pub fn set(&mut self, x: usize, y: usize, r: u8, g: u8, b: u8, a: u8) {
        let pixel_index = (y * self.width + x) * self.bytes_per_pixel;
        if (!self.is_greyscale) {
            self.buffer_start[pixel_index + self.red_offset as usize] = r;
            self.buffer_start[pixel_index + self.green_offset as usize] = g;
            self.buffer_start[pixel_index + self.blue_offset as usize] = b;
        } else {
            self.buffer_start[pixel_index] = a;
        }
    }
    pub fn clear(&mut self, start_x: usize, start_y: usize) {
        for x in start_x..start_x + FONT_WIDTH {
            for y in start_y..start_y + FONT_HEIGHT {
                self.set(x, y, 0, 0, 0, 0);
            }
        }
    }
}

impl Dimensions for Screen {
    fn bounding_box(&self) -> Rectangle {
        Rectangle::new(
            Point::zero(),
            Size::new(self.width as u32, self.height as u32),
        )
    }
}

impl DrawTarget for Screen {
    type Color = Rgb888;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(coord, color) in pixels {
            if coord.x >= 0 && coord.y >= 0 {
                let x = coord.x as usize;
                let y = coord.y as usize;
                if x < self.width && y < self.height {
                    self.set(x, y, color.r(), color.g(), color.b(), 0);
                }
            }
        }
        Ok(())
    }
}
const FONT_HEIGHT: usize = 18;
const FONT_WIDTH: usize = 9;

pub struct Console {
    pub screen: Screen,
    pub cursor_pose: Cursor,
}
impl Console {
    pub fn new() -> Self {
        let screen = Screen::new().unwrap();
        Console {
            screen,
            cursor_pose: Cursor {
                x: 0,
                y: FONT_HEIGHT,
            },
        }
    }

    pub(crate) fn print(&mut self, str: &[u8]) {
        let style = MonoTextStyle::new(&FONT_9X18, Rgb888::new(52, 100, 235));

        for &b in str {
            match b {
                b'\x08' => {
                    // backspace: move cursor back and overwrite with space
                    if self.cursor_pose.x >= FONT_WIDTH {
                        self.cursor_pose.x -= FONT_WIDTH;
                        Text::with_text_style(
                            " ",
                            Point::new(self.cursor_pose.x as i32, self.cursor_pose.y as i32),
                            style,
                            TextStyleBuilder::new().baseline(Baseline::Top).build(),
                        )
                        .draw(&mut self.screen)
                        .unwrap();
                    }
                }
                b'\n' => {
                    self.cursor_pose.x = 0;
                    self.cursor_pose.y += FONT_HEIGHT;
                    if self.cursor_pose.y + FONT_HEIGHT > self.screen.height {
                        self.scroll_up();
                    }
                }
                _ => {
                    let ch = b as char;
                    let buf = [ch as u8];
                    let s = core::str::from_utf8(&buf).unwrap();

                    Text::with_text_style(
                        s,
                        Point::new(self.cursor_pose.x as i32, self.cursor_pose.y as i32),
                        style,
                        TextStyleBuilder::new().baseline(Baseline::Top).build(),
                    )
                    .draw(&mut self.screen)
                    .unwrap();

                    self.cursor_pose.x += FONT_WIDTH;
                    if self.cursor_pose.x + FONT_WIDTH > self.screen.width {
                        self.cursor_pose.x = 0;
                        self.cursor_pose.y += FONT_HEIGHT;
                        if self.cursor_pose.y + FONT_HEIGHT > self.screen.height {
                            self.scroll_up();
                        }
                    }
                }
            }
        }
    }

    /*pub(crate) fn print(&mut self, str: &[u8]) {
        let style = MonoTextStyle::new(&FONT_7X14, Rgb888::new(255, 255, 255));
        let text = core::str::from_utf8(str).unwrap_or("Invalid UTF-8");

        Text::new(
            text,
            Point::new(self.cursor_pose.x as i32, self.cursor_pose.y as i32),
            style,
        )
            .draw(&mut self.screen)
            .unwrap();
        // self.cursor_pose.x += 7;
    }*/
    pub fn clear_screen(&mut self) {
        self.screen.buffer_start.fill(0);
    }
    fn scroll_up(&mut self) {
        let height = self.screen.height;
        let width = self.screen.width;
        let bytes_per_pixel = self.screen.bytes_per_pixel;
        let line_height = FONT_HEIGHT;

        let stride = width * bytes_per_pixel;
        let scroll_bytes = line_height * stride;
        let total_bytes = height * stride;

        let fb = &mut self.screen.buffer_start[..];

        fb.copy_within(scroll_bytes..total_bytes, 0);

        let start = total_bytes - scroll_bytes;
        fb[start..].fill(0);

        self.cursor_pose.y = height - line_height;
        self.cursor_pose.x = 0;
    }
}
pub fn clear_screen() {
    let mut console = CONSOLE.lock();
    (*console).clear_screen();
}
lazy_static! {
    pub static ref CONSOLE: Mutex<Console> = Mutex::new(Console::new());
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
pub(crate) unsafe fn print_queue() {
    CONSOLE.force_unlock();
    let mut console = CONSOLE.lock();
    while !QUEUE.is_empty() {
        console.print(&(QUEUE.pop_front().unwrap()))
    }
}
pub(crate) fn _print(args: core::fmt::Arguments) {
    let mut buffer = [0u8; 1024];
    let mut writer = BufferWriter::new(&mut buffer);

    write!(writer, "{}", args).unwrap();

    let data = writer.as_bytes();
    unsafe {
        if KERNEL_INITIALIZED.load(Ordering::SeqCst) {
            QUEUE.push_front(data.to_vec());
        } else {
            CONSOLE.lock().print(data);
        }
    }
}

struct BufferWriter<'a> {
    buffer: &'a mut [u8],
    position: usize,
}

impl<'a> BufferWriter<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        BufferWriter {
            buffer,
            position: 0,
        }
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
