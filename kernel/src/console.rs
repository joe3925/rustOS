use crate::util::boot_info;
use alloc::vec::Vec;
use bootloader_api::info::PixelFormat;
use core::fmt::{self, Write};
use embedded_graphics::mono_font::iso_8859_5::FONT_9X18;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::prelude::{
    DrawTarget, OriginDimensions, Point, RgbColor, Size,
};
use kernel_types::irq::IrqSafeMutex;

use embedded_graphics::text::{Baseline, Text, TextStyle, TextStyleBuilder};
use embedded_graphics::Drawable;
use lazy_static::lazy_static;
const FONT_HEIGHT: usize = 18;
const FONT_WIDTH: usize = 9;
const TAB_SPACES: usize = 4;

pub(crate) struct Cursor {
    pub x: usize,
    pub y: usize,
}

pub struct Screen {
    pub buffer_start: &'static mut [u8],
    pub width: usize,
    pub height: usize,
    pub total_size: usize,
    pub bytes_per_pixel: usize,
    pub pixel_format: PixelFormat,

    stride: usize,

    red_offset: usize,
    green_offset: usize,
    blue_offset: usize,
    is_greyscale: bool,
}

impl Screen {
    /// Zero the entire framebuffer if available. Safe to call before creating a `Screen`.
    pub fn clear_framebuffer() {
        let boot = boot_info();
        if let Some(fb) = boot.framebuffer.as_mut() {
            fb.buffer_mut().fill(0);
        }
    }

    pub fn new() -> Option<Self> {
        let boot = boot_info();
        let fb = boot.framebuffer.as_mut()?;
        let info = fb.info();

        let mut red_offset = 0usize;
        let mut green_offset = 0usize;
        let mut blue_offset = 0usize;
        let mut is_greyscale = false;

        match info.pixel_format {
            PixelFormat::Rgb => {
                red_offset = 0;
                green_offset = 1;
                blue_offset = 2;
            }
            PixelFormat::Bgr => {
                blue_offset = 0;
                green_offset = 1;
                red_offset = 2;
            }
            PixelFormat::U8 => {
                is_greyscale = true;
            }
            PixelFormat::Unknown {
                red_position,
                green_position,
                blue_position,
            } => {
                red_offset = red_position as usize;
                green_offset = green_position as usize;
                blue_offset = blue_position as usize;
            }
            _ => {}
        }

        let width = info.width as usize;
        let height = info.height as usize;
        let stride = info.stride as usize;
        let bpp = info.bytes_per_pixel as usize;

        Some(Self {
            width,
            height,
            stride,
            bytes_per_pixel: bpp,
            total_size: info.byte_len as usize,
            pixel_format: info.pixel_format,
            buffer_start: fb.buffer_mut(),
            red_offset,
            green_offset,
            blue_offset,
            is_greyscale,
        })
    }

    #[inline(always)]
    fn pixel_index_unchecked(&self, x: usize, y: usize) -> usize {
        (y * self.stride + x) * self.bytes_per_pixel
    }

    #[inline(always)]
    fn write_pixel_unchecked(&mut self, x: usize, y: usize, r: u8, g: u8, b: u8) {
        let idx = self.pixel_index_unchecked(x, y);
        let buf = &mut self.buffer_start;

        if self.is_greyscale {
            let v = ((r as u16 + g as u16 + b as u16) / 3) as u8;
            if idx < buf.len() {
                buf[idx] = v;
            }
            return;
        }

        if idx + self.bytes_per_pixel > buf.len() {
            return;
        }

        if self.bytes_per_pixel >= 3 {
            let ro = idx + self.red_offset;
            let go = idx + self.green_offset;
            let bo = idx + self.blue_offset;

            if ro < buf.len() {
                buf[ro] = r;
            }
            if go < buf.len() {
                buf[go] = g;
            }
            if bo < buf.len() {
                buf[bo] = b;
            }
        } else if self.bytes_per_pixel == 2 {
            buf[idx] = r;
            if idx + 1 < buf.len() {
                buf[idx + 1] = g;
            }
        } else if self.bytes_per_pixel == 1 {
            buf[idx] = r;
        }
    }

    #[inline(always)]
    pub fn set(&mut self, x: usize, y: usize, r: u8, g: u8, b: u8) {
        if x >= self.width || y >= self.height {
            return;
        }
        self.write_pixel_unchecked(x, y, r, g, b);
    }

    pub fn clear_all(&mut self) {
        self.buffer_start.fill(0);
    }

    pub fn clear_cell(&mut self, start_x: usize, start_y: usize) {
        if start_x >= self.width || start_y >= self.height {
            return;
        }

        let end_x = (start_x + FONT_WIDTH).min(self.width);
        let end_y = (start_y + FONT_HEIGHT).min(self.height);

        let line_bytes = self.stride * self.bytes_per_pixel;

        for y in start_y..end_y {
            let row_start = y * line_bytes;
            let px_start = row_start + start_x * self.bytes_per_pixel;
            let px_end = row_start + end_x * self.bytes_per_pixel;

            if px_start < self.buffer_start.len() {
                let end = px_end.min(self.buffer_start.len());
                self.buffer_start[px_start..end].fill(0);
            }
        }
    }

    pub fn scroll_up_pixels(&mut self, px_rows: usize) {
        if px_rows == 0 {
            return;
        }

        let line_bytes = self.stride * self.bytes_per_pixel;
        let scroll_bytes = px_rows.saturating_mul(line_bytes);
        let total_bytes = self.buffer_start.len();

        if scroll_bytes >= total_bytes {
            self.buffer_start.fill(0);
            return;
        }

        self.buffer_start.copy_within(scroll_bytes..total_bytes, 0);
        self.buffer_start[total_bytes - scroll_bytes..].fill(0);
    }
}

impl OriginDimensions for Screen {
    fn size(&self) -> Size {
        Size::new(self.width as u32, self.height as u32)
    }
}

impl DrawTarget for Screen {
    type Color = Rgb888;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = embedded_graphics::prelude::Pixel<Self::Color>>,
    {
        for embedded_graphics::prelude::Pixel(coord, color) in pixels {
            if coord.x < 0 || coord.y < 0 {
                continue;
            }
            let x = coord.x as usize;
            let y = coord.y as usize;

            if x >= self.width || y >= self.height {
                continue;
            }

            self.write_pixel_unchecked(x, y, color.r(), color.g(), color.b());
        }

        Ok(())
    }
}

pub struct Console {
    pub screen: Screen,
    pub cursor_pose: Cursor,

    style: MonoTextStyle<'static, Rgb888>,
    text_style: TextStyle,

    pending: Vec<u8>,
}

impl Console {
    pub fn new() -> Self {
        let screen = Screen::new().expect("No framebuffer available");

        let style = MonoTextStyle::new(&FONT_9X18, Rgb888::new(52, 100, 235));
        let text_style = TextStyleBuilder::new().baseline(Baseline::Top).build();

        let mut pending = Vec::new();
        pending.reserve(256);

        Self {
            screen,
            cursor_pose: Cursor { x: 0, y: 0 },
            style,
            text_style,
            pending,
        }
    }

    pub(crate) fn print(&mut self, bytes: &[u8]) {
        self.push_bytes(bytes);
        self.flush_pending();
    }

    #[inline(always)]
    fn newline(&mut self) {
        self.cursor_pose.x = 0;
        self.cursor_pose.y = self.cursor_pose.y.saturating_add(FONT_HEIGHT);

        if self.cursor_pose.y + FONT_HEIGHT > self.screen.height {
            self.screen.scroll_up_pixels(FONT_HEIGHT);
            self.cursor_pose.y = self.screen.height.saturating_sub(FONT_HEIGHT);
        }
    }

    #[inline(always)]
    fn carriage_return(&mut self) {
        self.cursor_pose.x = 0;
    }

    #[inline(always)]
    fn backspace(&mut self) {
        if self.cursor_pose.x >= FONT_WIDTH {
            self.cursor_pose.x -= FONT_WIDTH;
            self.screen
                .clear_cell(self.cursor_pose.x, self.cursor_pose.y);
        }
    }

    #[inline(always)]
    fn tab(&mut self) {
        let col = self.cursor_pose.x / FONT_WIDTH;
        let next = ((col / TAB_SPACES) + 1) * TAB_SPACES;
        let spaces = next.saturating_sub(col).max(1).min(TAB_SPACES);

        let mut i = 0;
        while i < spaces {
            self.pending.push(b' ');
            i += 1;
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            match b {
                b'\n' => {
                    self.flush_pending();
                    self.newline();
                }
                b'\r' => {
                    self.flush_pending();
                    self.carriage_return();
                }
                b'\x08' => {
                    self.flush_pending();
                    self.backspace();
                }
                b'\t' => {
                    self.flush_pending();
                    self.tab();
                    self.flush_pending();
                }
                0x20..=0x7E => {
                    self.pending.push(b);
                    let max_cols = self.screen.width / FONT_WIDTH;
                    let col = self.cursor_pose.x / FONT_WIDTH;
                    let avail = max_cols.saturating_sub(col);
                    if avail == 0 {
                        self.flush_pending();
                        self.newline();
                    } else if self.pending.len() >= avail {
                        self.flush_pending();
                    }
                }
                _ => {
                    self.pending.push(b'?');
                    let max_cols = self.screen.width / FONT_WIDTH;
                    let col = self.cursor_pose.x / FONT_WIDTH;
                    let avail = max_cols.saturating_sub(col);
                    if avail == 0 {
                        self.flush_pending();
                        self.newline();
                    } else if self.pending.len() >= avail {
                        self.flush_pending();
                    }
                }
            }
        }
    }

    fn flush_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }

        let max_cols = self.screen.width / FONT_WIDTH;
        if max_cols == 0 {
            self.pending.clear();
            return;
        }

        while !self.pending.is_empty() {
            let col = self.cursor_pose.x / FONT_WIDTH;
            let avail = max_cols.saturating_sub(col);

            if avail == 0 {
                self.newline();
                continue;
            }

            let take = self.pending.len().min(avail);
            let chunk = &self.pending[..take];

            let s = core::str::from_utf8(chunk).unwrap_or("?");

            let p = Point::new(self.cursor_pose.x as i32, self.cursor_pose.y as i32);
            let _ = Text::with_text_style(s, p, self.style, self.text_style).draw(&mut self.screen);

            self.cursor_pose.x = self.cursor_pose.x.saturating_add(take * FONT_WIDTH);

            self.pending.drain(..take);

            if self.cursor_pose.x + FONT_WIDTH > self.screen.width {
                self.newline();
            }
        }
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_bytes(s.as_bytes());
        Ok(())
    }
}

lazy_static! {
    pub static ref CONSOLE: IrqSafeMutex<Console> = IrqSafeMutex::new(Console::new());
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::_print(core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n");
    };
    ($($arg:tt)*) => {
        $crate::print!("{}\n", core::format_args!($($arg)*))
    };
}

pub(crate) fn _print(args: core::fmt::Arguments) {
    let mut tries = 0usize;
    while tries < 256 {
        if let Some(mut c) = CONSOLE.try_lock() {
            let _ = c.write_fmt(args);
            c.flush_pending();
            return;
        }
        core::hint::spin_loop();
        tries += 1;
    }
}
