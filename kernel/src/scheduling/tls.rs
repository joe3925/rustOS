use crate::util::boot_info;
use alloc::alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout};
use alloc::sync::Arc;
use bootloader_api::info::TlsTemplate;
use core::fmt;
use core::ptr;
use core::slice;
use kernel_types::runtime::BlockOnThreadState;
use spin::Once;
use x86_64::registers::model_specific::FsBase;
use x86_64::VirtAddr;

const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
const ELF_CLASS_64: u8 = 2;
const ELF_LITTLE_ENDIAN: u8 = 1;
const PT_TLS: u32 = 7;
const PT_TLS_ALIGN_OFFSET: usize = 48;
const PT_TLS_FILE_SIZE_OFFSET: usize = 32;
const PT_TLS_MEM_SIZE_OFFSET: usize = 40;
const PROGRAM_HEADER_SIZE_64: usize = 56;
const MIN_TCB_BYTES: usize = 16;
const TCB_SELF_POINTER_OFFSET: usize = 0;
const TCB_RESERVED_OFFSET: usize = 8;

static KERNEL_TLS_LAYOUT: Once<Option<KernelTlsLayout>> = Once::new();

#[thread_local]
static mut BLOCK_ON_THREAD_STATE: Option<Arc<BlockOnThreadState>> = None;

#[derive(Clone, Copy, Debug)]
struct KernelTlsLayout {
    template_start: usize,
    file_size: usize,
    tls_offset: usize,
    alloc_align: usize,
    total_size: usize,
}

pub struct KernelTls {
    allocation: usize,
    allocation_layout: Layout,
    thread_pointer: VirtAddr,
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
            ptr::copy_nonoverlapping(
                layout.template_start as *const u8,
                allocation as *mut u8,
                layout.file_size,
            );
        }

        let thread_pointer = unsafe { (allocation as *mut u8).add(layout.tls_offset) };
        unsafe {
            ptr::write_unaligned(
                thread_pointer.add(TCB_SELF_POINTER_OFFSET).cast::<u64>(),
                thread_pointer as u64,
            );
            ptr::write_unaligned(thread_pointer.add(TCB_RESERVED_OFFSET).cast::<u64>(), 0);
        }

        Some(Self {
            allocation,
            allocation_layout,
            thread_pointer: VirtAddr::new(thread_pointer as u64),
        })
    }

    #[inline(always)]
    pub fn thread_pointer(&self) -> u64 {
        self.thread_pointer.as_u64()
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
            .field("thread_pointer", &self.thread_pointer)
            .finish()
    }
}

#[inline(always)]
pub fn activate(thread_pointer: u64) {
    FsBase::write(VirtAddr::new(thread_pointer));
}

#[inline(always)]
pub fn ensure_current_thread_runtime_initialized() {
    if FsBase::read().as_u64() == 0 {
        panic!("kernel TLS is not active for the current thread");
    }
    unsafe {
        if BLOCK_ON_THREAD_STATE.is_none() {
            BLOCK_ON_THREAD_STATE = Some(Arc::new(BlockOnThreadState::new()));
        }
    }
}

pub fn current_block_on_thread_state() -> Arc<BlockOnThreadState> {
    if FsBase::read().as_u64() == 0 {
        panic!("kernel TLS is not active for the current thread");
    }
    unsafe {
        BLOCK_ON_THREAD_STATE
            .as_ref()
            .cloned()
            .expect("kernel block_on TLS state is not initialized for the current thread")
    }
}

fn kernel_tls_layout() -> Option<&'static KernelTlsLayout> {
    KERNEL_TLS_LAYOUT
        .call_once(detect_kernel_tls_layout)
        .as_ref()
}

fn detect_kernel_tls_layout() -> Option<KernelTlsLayout> {
    let template = boot_info().tls_template.as_ref().copied()?;
    let template_align = kernel_tls_template_alignment(&template);
    let mem_size = u64_to_usize(template.mem_size, "kernel TLS mem_size");
    let file_size = u64_to_usize(template.file_size, "kernel TLS file_size");

    if file_size > mem_size {
        panic!(
            "kernel TLS file_size {} exceeds mem_size {}",
            file_size, mem_size
        );
    }

    let tls_offset = round_up(mem_size, template_align);
    let alloc_align = template_align.max(core::mem::align_of::<u64>());
    let total_size = tls_offset
        .checked_add(MIN_TCB_BYTES)
        .expect("kernel TLS allocation size overflow");

    Some(KernelTlsLayout {
        template_start: template.start_addr as usize,
        file_size,
        tls_offset,
        alloc_align,
        total_size,
    })
}

fn kernel_tls_template_alignment(template: &TlsTemplate) -> usize {
    let kernel_elf = kernel_elf_bytes();
    let phoff = u64_to_usize(read_u64(kernel_elf, 32), "kernel ELF program header offset");
    let phentsize = read_u16(kernel_elf, 54) as usize;
    let phnum = read_u16(kernel_elf, 56) as usize;

    if phentsize < PROGRAM_HEADER_SIZE_64 {
        panic!("unsupported kernel ELF program header size {phentsize}");
    }

    for index in 0..phnum {
        let header = phoff
            .checked_add(
                index
                    .checked_mul(phentsize)
                    .expect("kernel ELF program header index overflow"),
            )
            .expect("kernel ELF program header offset overflow");
        let Some(header_end) = header.checked_add(PROGRAM_HEADER_SIZE_64) else {
            panic!("kernel ELF PT_TLS header offset overflow");
        };
        if header_end > kernel_elf.len() {
            panic!("kernel ELF PT_TLS header is truncated");
        }

        let p_type = read_u32(kernel_elf, header);
        if p_type != PT_TLS {
            continue;
        }

        let file_size = read_u64(kernel_elf, header + PT_TLS_FILE_SIZE_OFFSET);
        let mem_size = read_u64(kernel_elf, header + PT_TLS_MEM_SIZE_OFFSET);
        if file_size != template.file_size || mem_size != template.mem_size {
            panic!(
                "bootloader TLS template ({}, {}) does not match kernel ELF PT_TLS ({}, {})",
                template.file_size, template.mem_size, file_size, mem_size
            );
        }

        let raw_align = read_u64(kernel_elf, header + PT_TLS_ALIGN_OFFSET);
        let align = u64_to_usize(raw_align.max(1), "kernel TLS alignment");
        if !align.is_power_of_two() {
            panic!("kernel TLS alignment {align} is not a power of two");
        }
        return align;
    }

    panic!("kernel ELF has TLS template but no PT_TLS program header");
}

fn kernel_elf_bytes() -> &'static [u8] {
    let boot = boot_info();
    let phys_offset = boot
        .physical_memory_offset
        .as_ref()
        .copied()
        .expect("kernel TLS requires physical memory mapping");
    let kernel_elf = phys_offset
        .checked_add(boot.kernel_addr)
        .expect("kernel ELF address overflow");
    let kernel_len = u64_to_usize(boot.kernel_len, "kernel ELF length");
    let bytes = unsafe { slice::from_raw_parts(kernel_elf as *const u8, kernel_len) };

    if bytes.len() < 64 || &bytes[..4] != ELF_MAGIC {
        panic!("kernel TLS requires a valid ELF64 kernel image");
    }
    if bytes[4] != ELF_CLASS_64 || bytes[5] != ELF_LITTLE_ENDIAN {
        panic!("kernel TLS currently expects a little-endian ELF64 kernel image");
    }

    bytes
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
fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let end = offset
        .checked_add(2)
        .expect("kernel ELF u16 offset overflow");
    u16::from_le_bytes(bytes[offset..end].try_into().unwrap())
}

#[inline(always)]
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let end = offset
        .checked_add(4)
        .expect("kernel ELF u32 offset overflow");
    u32::from_le_bytes(bytes[offset..end].try_into().unwrap())
}

#[inline(always)]
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let end = offset
        .checked_add(8)
        .expect("kernel ELF u64 offset overflow");
    u64::from_le_bytes(bytes[offset..end].try_into().unwrap())
}

#[inline(always)]
fn u64_to_usize(value: u64, what: &str) -> usize {
    usize::try_from(value).unwrap_or_else(|_| panic!("{what} does not fit in usize"))
}
