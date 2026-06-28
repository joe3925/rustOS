use crate::util::take_framebuffer;
use core::fmt;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};
use crossbeam_queue::ArrayQueue;
use embedded_graphics::mono_font::iso_8859_5::FONT_9X18;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::prelude::DrawTarget;
use embedded_graphics::prelude::OriginDimensions;
use embedded_graphics::prelude::Point;
use embedded_graphics::prelude::RgbColor;
use embedded_graphics::prelude::Size;
use embedded_graphics::text::Baseline;
use embedded_graphics::text::Text;
use embedded_graphics::text::TextStyle;
use embedded_graphics::text::TextStyleBuilder;
use embedded_graphics::Drawable;
use kernel_abi::PixelFormat;
use kernel_types::irq::IrqSafeMutex;
use lazy_static::lazy_static;
const FRAMEBUFFER_CONSOLE: bool = true;
const FONT_HEIGHT: usize = 18;
const FONT_WIDTH: usize = 9;
const TAB_SPACES: usize = 4;
const PRINT_FLUSH_TRIES: usize = 256;

const PRINT_QUEUE_SLOTS: usize = 256;
const PRINT_SLOT_SIZE: usize = 1024;
const PRINT_SLOT_PAYLOAD: usize = PRINT_SLOT_SIZE - 1;

pub(crate) struct Cursor {
    pub x: usize,
    pub y: usize,
}

#[derive(Clone, Copy)]
struct PrintSlot {
    bytes: [u8; PRINT_SLOT_SIZE],
    len: usize,
}

impl PrintSlot {
    const fn new() -> Self {
        Self {
            bytes: [0; PRINT_SLOT_SIZE],
            len: 0,
        }
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    fn is_full(&self) -> bool {
        self.len == PRINT_SLOT_PAYLOAD
    }

    #[inline(always)]
    fn clear(&mut self) {
        self.len = 0;
        self.bytes[0] = 0;
    }

    #[inline(always)]
    fn push(&mut self, b: u8) {
        debug_assert!(self.len < PRINT_SLOT_PAYLOAD);
        self.bytes[self.len] = b;
        self.len += 1;
        self.bytes[self.len] = 0;
    }

    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

struct QueuedPrintWriter {
    slot: PrintSlot,
}

struct SerialPrintWriter;

impl fmt::Write for SerialPrintWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::arch::serial_write_bytes(s.as_bytes());
        Ok(())
    }
}

impl QueuedPrintWriter {
    fn new() -> Self {
        Self {
            slot: PrintSlot::new(),
        }
    }

    fn flush_slot(&mut self) {
        if self.slot.is_empty() {
            return;
        }

        let slot = self.slot;
        self.slot.clear();
        queue_slot(slot);
    }

    fn finish(mut self) {
        self.flush_slot();
    }
}

impl fmt::Write for QueuedPrintWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if self.slot.is_full() {
                self.flush_slot();
            }

            self.slot.push(b);
        }

        Ok(())
    }
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
    pub fn clear_framebuffer() {
        if let Some(mut console) = CONSOLE.try_lock() {
            console.screen.buffer_start.fill(0);
        }
    }

    pub fn new() -> Option<Self> {
        let mut fb = take_framebuffer()?;
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
        }

        let width = info.width as usize;
        let height = info.height as usize;
        let stride = info.stride as usize;
        let bpp = info.bytes_per_pixel as usize;

        let buffer_start = unsafe { fb.into_buffer_mut() };
        buffer_start.fill(0);

        Some(Self {
            width,
            height,
            stride,
            bytes_per_pixel: bpp,
            total_size: info.byte_len as usize,
            pixel_format: info.pixel_format,
            buffer_start,
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

    pending: [u8; PRINT_SLOT_SIZE],
    pending_len: usize,
}

impl Console {
    pub fn new() -> Self {
        let screen = Screen::new().expect("No framebuffer available");

        let style = MonoTextStyle::new(&FONT_9X18, Rgb888::new(52, 100, 235));
        let text_style = TextStyleBuilder::new().baseline(Baseline::Top).build();

        Self {
            screen,
            cursor_pose: Cursor { x: 0, y: 0 },
            style,
            text_style,
            pending: [0; PRINT_SLOT_SIZE],
            pending_len: 0,
        }
    }

    pub(crate) fn print(&mut self, bytes: &[u8]) {
        self.flush_queued_prints();
        self.push_bytes(bytes);
        self.flush_pending();
        self.flush_queued_prints();
    }

    fn flush_queued_prints(&mut self) {
        while let Some(slot) = PRINT_QUEUE.pop() {
            self.push_bytes(slot.as_bytes());
            self.flush_pending();
        }
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
            self.pending_push(b' ');
            i += 1;
        }
    }

    #[inline(always)]
    fn pending_push(&mut self, b: u8) {
        if self.pending_len == PRINT_SLOT_PAYLOAD {
            self.flush_pending();
        }

        self.pending[self.pending_len] = b;
        self.pending_len += 1;
        self.pending[self.pending_len] = 0;
    }

    fn push_printable_byte(&mut self, b: u8) {
        self.pending_push(b);

        let max_cols = self.screen.width / FONT_WIDTH;
        let col = self.cursor_pose.x / FONT_WIDTH;
        let avail = max_cols.saturating_sub(col);

        if avail == 0 {
            self.flush_pending();
            self.newline();
        } else if self.pending_len >= avail {
            self.flush_pending();
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
                    self.push_printable_byte(b);
                }
                _ => {
                    self.push_printable_byte(b'?');
                }
            }
        }
    }

    fn flush_pending(&mut self) {
        if self.pending_len == 0 {
            return;
        }

        let max_cols = self.screen.width / FONT_WIDTH;
        if max_cols == 0 {
            self.pending_len = 0;
            self.pending[0] = 0;
            return;
        }

        while self.pending_len != 0 {
            let col = self.cursor_pose.x / FONT_WIDTH;
            let avail = max_cols.saturating_sub(col);

            if avail == 0 {
                self.newline();
                continue;
            }

            let take = self.pending_len.min(avail);
            let chunk = &self.pending[..take];

            let s = core::str::from_utf8(chunk).unwrap_or("?");

            let p = Point::new(self.cursor_pose.x as i32, self.cursor_pose.y as i32);
            let _ = Text::with_text_style(s, p, self.style, self.text_style).draw(&mut self.screen);

            self.cursor_pose.x = self.cursor_pose.x.saturating_add(take * FONT_WIDTH);

            self.pending.copy_within(take..self.pending_len, 0);
            self.pending_len -= take;
            self.pending[self.pending_len] = 0;

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
    static ref PRINT_QUEUE: ArrayQueue<PrintSlot> = ArrayQueue::new(PRINT_QUEUE_SLOTS);
}

static PRINT_QUEUE_FULL_PANIC: AtomicBool = AtomicBool::new(false);

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

fn queue_slot(slot: PrintSlot) {
    if PRINT_QUEUE_FULL_PANIC.load(Ordering::Acquire) {
        return;
    }

    match PRINT_QUEUE.push(slot) {
        Ok(()) => {}
        Err(slot) => {
            print_queue_full_panic(slot);
        }
    }
}

fn queue_print(args: fmt::Arguments) {
    if PRINT_QUEUE_FULL_PANIC.load(Ordering::Acquire) {
        return;
    }

    let mut writer = QueuedPrintWriter::new();
    let _ = writer.write_fmt(args);
    writer.finish();
}

fn print_queue_full_panic(slot: PrintSlot) -> ! {
    if PRINT_QUEUE_FULL_PANIC.swap(true, Ordering::AcqRel) {
        loop {
            core::hint::spin_loop();
        }
    }

    loop {
        if let Some(mut c) = CONSOLE.try_lock() {
            c.flush_queued_prints();
            c.push_bytes(slot.as_bytes());
            c.flush_pending();
            c.flush_queued_prints();
            break;
        }

        core::hint::spin_loop();
    }

    panic!("print queue full");
}

fn try_flush_print_queue() -> bool {
    if let Some(mut c) = CONSOLE.try_lock() {
        c.flush_queued_prints();
        return true;
    }

    false
}

pub(crate) fn _print(args: fmt::Arguments) {
    let _ = SerialPrintWriter.write_fmt(args);
    if (FRAMEBUFFER_CONSOLE) {
        if PRINT_QUEUE_FULL_PANIC.load(Ordering::Acquire) {
            let _ = try_flush_print_queue();
            return;
        }

        if let Some(mut c) = CONSOLE.try_lock() {
            c.flush_queued_prints();
            let _ = c.write_fmt(args);
            c.flush_pending();
            c.flush_queued_prints();
            return;
        }

        queue_print(args);

        let mut tries = 0usize;
        while tries < PRINT_FLUSH_TRIES {
            if try_flush_print_queue() {
                return;
            }

            core::hint::spin_loop();
            tries += 1;
        }
    }
}
