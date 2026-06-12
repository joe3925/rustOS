use crate::drivers::interrupt_index::PERCPU_TLS_ARRAY_POINTER_OFF;
use crate::util::boot_info;
use alloc::alloc::{Layout, alloc_zeroed, dealloc, handle_alloc_error};
use alloc::sync::Arc;
use core::arch::asm;
use core::fmt;
use core::ptr;
use kernel_abi::PeTlsDirectory;
use kernel_types::runtime::BlockOnThreadState;
use spin::Mutex;
use spin::Once;
use x86_64::VirtAddr;

const PE_TLS_ARRAY_ENTRIES: usize = 1;
const PE_TLS_ARRAY_BYTES: usize = PE_TLS_ARRAY_ENTRIES * core::mem::size_of::<u64>();

static KERNEL_TLS_LAYOUT: Once<Option<KernelTlsLayout>> = Once::new();

static BLOCK_ON_THREAD_STATE: Mutex<Option<Arc<BlockOnThreadState>>> = Mutex::new(None);

#[derive(Clone, Copy, Debug)]
struct KernelTlsLayout {
    template_start: usize,
    raw_data_size: usize,
    tls_block_offset: usize,
    tls_block_size: usize,
    alloc_align: usize,
    total_size: usize,
}

pub struct KernelTls {
    allocation: usize,
    allocation_layout: Layout,
    tls_array_pointer: VirtAddr,
}

impl KernelTls {
    pub fn for_kernel_thread() -> Option<Self> {
        let layout = kernel_tls_layout()?;
        let allocation_layout = Layout::from_size_align(layout.total_size, layout.alloc_align)
            .expect("invalid kernel TLS allocation layout");
        let allocation = unsafe { alloc_zeroed(allocation_layout) };
        let allocation = match allocation.is_null() {
            true => handle_alloc_error(allocation_layout),
            false => allocation as usize,
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
            tls_array_pointer: VirtAddr::new(allocation as u64),
        })
    }

    #[inline(always)]
    pub fn thread_pointer(&self) -> u64 {
        self.tls_array_pointer.as_u64()
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
            .field("tls_array_pointer", &self.tls_array_pointer)
            .finish()
    }
}

#[inline(always)]
pub fn activate(tls_array_pointer: u64) {
    unsafe {
        asm!(
            "mov qword ptr gs:[{off}], {tls}",
            off = const PERCPU_TLS_ARRAY_POINTER_OFF,
            tls = in(reg) tls_array_pointer,
            options(nostack, preserves_flags)
        );
    }
}

#[inline(always)]
pub fn ensure_current_thread_runtime_initialized() {
    let mut state = BLOCK_ON_THREAD_STATE.lock();
    if state.is_none() {
        *state = Some(Arc::new(BlockOnThreadState::new()));
    }
}

pub fn current_block_on_thread_state() -> Arc<BlockOnThreadState> {
    BLOCK_ON_THREAD_STATE
        .lock()
        .as_ref()
        .cloned()
        .expect("kernel block_on state is not initialized for the current thread")
}

fn kernel_tls_layout() -> Option<&'static KernelTlsLayout> {
    KERNEL_TLS_LAYOUT
        .call_once(detect_kernel_tls_layout)
        .as_ref()
}

fn detect_kernel_tls_layout() -> Option<KernelTlsLayout> {
    let directory = boot_info().pe_tls_directory.as_ref().copied()?;
    let template_align = pe_tls_alignment(&directory);
    let raw_data_size = pe_tls_raw_data_size(&directory);
    let zero_fill_size = usize::try_from(directory.size_of_zero_fill)
        .expect("kernel PE TLS zero fill does not fit in usize");
    let tls_block_size = raw_data_size
        .checked_add(zero_fill_size)
        .expect("kernel PE TLS block size overflow");

    if tls_block_size == 0 {
        return None;
    }

    if directory.start_address_of_raw_data == 0 && raw_data_size != 0 {
        panic!(
            "kernel PE TLS has raw data size {} but no raw data start",
            raw_data_size
        );
    }

    let tls_block_offset = round_up(PE_TLS_ARRAY_BYTES, template_align);
    let alloc_align = template_align.max(core::mem::align_of::<u64>());
    let total_size = tls_block_offset
        .checked_add(tls_block_size)
        .expect("kernel PE TLS allocation size overflow");

    Some(KernelTlsLayout {
        template_start: directory.start_address_of_raw_data as usize,
        raw_data_size,
        tls_block_offset,
        tls_block_size,
        alloc_align,
        total_size,
    })
}

fn pe_tls_raw_data_size(directory: &PeTlsDirectory) -> usize {
    if directory.start_address_of_raw_data == 0 && directory.end_address_of_raw_data == 0 {
        return 0;
    }
    if directory.end_address_of_raw_data < directory.start_address_of_raw_data {
        panic!("kernel PE TLS raw data range is backwards");
    }

    u64_to_usize(
        directory.end_address_of_raw_data - directory.start_address_of_raw_data,
        "kernel PE TLS raw data size",
    )
}

fn pe_tls_alignment(directory: &PeTlsDirectory) -> usize {
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
    };
    align.max(core::mem::align_of::<u64>())
}

#[inline(always)]
fn round_up(value: usize, align: usize) -> usize {
    let remainder = value % align;
    if remainder == 0 {
        value
    } else {
        value
            .checked_add(align - remainder)
            .expect("kernel TLS layout overflow")
    }
}

#[inline(always)]
fn u64_to_usize(value: u64, what: &str) -> usize {
    usize::try_from(value).unwrap_or_else(|_| panic!("{what} does not fit in usize"))
}
