use alloc::alloc::{Layout, alloc_zeroed, dealloc, handle_alloc_error};
use core::{fmt, ptr};

use spin::Once;

const PE_TLS_ARRAY_BYTES: usize = core::mem::size_of::<u64>();

static KERNEL_TLS_LAYOUT: Once<Option<KernelTlsLayout>> = Once::new();

#[derive(Clone, Copy)]
pub struct TlsDirectory {
    pub start: u64,
    pub end: u64,
    pub zero_fill: u32,
    pub characteristics: u32,
}

#[derive(Clone, Copy, Debug)]
struct KernelTlsLayout {
    template_start: usize,
    raw_data_size: usize,
    tls_block_offset: usize,
    alloc_align: usize,
    total_size: usize,
}

pub struct KernelTls {
    allocation: usize,
    allocation_layout: Layout,
}

impl KernelTls {
    pub fn new(directory: TlsDirectory) -> Option<Self> {
        let layout = KERNEL_TLS_LAYOUT
            .call_once(|| detect_kernel_tls_layout(directory))
            .as_ref()?;
        let allocation_layout = Layout::from_size_align(layout.total_size, layout.alloc_align)
            .expect("invalid kernel TLS allocation layout");
        let allocation = unsafe { alloc_zeroed(allocation_layout) };
        let allocation = if allocation.is_null() {
            handle_alloc_error(allocation_layout)
        } else {
            allocation as usize
        };
        unsafe {
            let tls_block = (allocation as *mut u8).add(layout.tls_block_offset);
            if layout.raw_data_size != 0 {
                ptr::copy_nonoverlapping(
                    layout.template_start as *const u8,
                    tls_block,
                    layout.raw_data_size,
                );
            }
            ptr::write_unaligned((allocation as *mut u8).cast::<u64>(), tls_block as u64);
        }
        Some(Self {
            allocation,
            allocation_layout,
        })
    }

    pub fn thread_pointer(&self) -> u64 {
        self.allocation as u64
    }
}

impl Drop for KernelTls {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.allocation as *mut u8, self.allocation_layout);
        }
    }
}

impl fmt::Debug for KernelTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelTls")
            .field("allocation", &format_args!("{:#x}", self.allocation))
            .field("allocation_layout", &self.allocation_layout)
            .finish()
    }
}

fn detect_kernel_tls_layout(directory: TlsDirectory) -> Option<KernelTlsLayout> {
    let raw_data_size = if directory.start == 0 && directory.end == 0 {
        0
    } else {
        if directory.end < directory.start {
            panic!("kernel PE TLS raw data range is backwards");
        }
        (directory.end - directory.start) as usize
    };
    let zero_fill_size = usize::try_from(directory.zero_fill)
        .expect("kernel PE TLS zero fill does not fit in usize");
    let tls_block_size = raw_data_size
        .checked_add(zero_fill_size)
        .expect("kernel PE TLS block size overflow");
    if tls_block_size == 0 {
        return None;
    }
    if directory.start == 0 && raw_data_size != 0 {
        panic!("kernel PE TLS has raw data but no raw data start");
    }
    let align = match (directory.characteristics >> 20) & 0xF {
        0x0 | 0x1 => 1,
        0x2 => 2,
        0x3 => 4,
        0x4 => 8,
        0x5 => 16,
        0x6 => 32,
        0x7 => 64,
        0x8 => 128,
        0x9 => 256,
        0xA => 512,
        0xB => 1024,
        0xC => 4096,
        0xD => 2048,
        0xE => 8192,
        _ => 1,
    }
    .max(core::mem::align_of::<u64>());
    let tls_block_offset = PE_TLS_ARRAY_BYTES
        .checked_add(align - 1)
        .expect("kernel TLS layout overflow")
        / align
        * align;
    Some(KernelTlsLayout {
        template_start: directory.start as usize,
        raw_data_size,
        tls_block_offset,
        alloc_align: align,
        total_size: tls_block_offset
            .checked_add(tls_block_size)
            .expect("kernel TLS allocation size overflow"),
    })
}
