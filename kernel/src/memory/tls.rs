// kernel/src/memory/tls.rs
//
// Thread Local Storage (TLS) implementation for the rustOS kernel.
// Provides TLS support for BSP, APs, and tasks using a static bootstrap arena
// for early boot (before heap) and heap allocation for tasks.
//
// Layout follows System V ABI: %fs:0 points to TCB with self-pointer at offset 0.

#![allow(static_mut_refs)]

use bootloader_api::BootInfo;
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use raw_cpuid::CpuId;

// =============================================================================
// Constants
// =============================================================================

/// Maximum CPUs supported for bootstrap TLS blocks
pub const MAX_BOOTSTRAP_CPUS: usize = 256;

/// Size of each bootstrap TLS block (4KB should handle most kernels)
pub const BOOTSTRAP_BLOCK_SIZE: usize = 4096;

/// Total bootstrap arena size
pub const BOOTSTRAP_ARENA_SIZE: usize = MAX_BOOTSTRAP_CPUS * BOOTSTRAP_BLOCK_SIZE;

/// MSR addresses
const IA32_FS_BASE: u32 = 0xC000_0100;

// =============================================================================
// TLS Template - Cached bootloader info in .bss
// =============================================================================

/// Cached copy of bootloader's TLS template info.
/// Stored in .bss so it's available before heap initialization.
#[repr(C)]
pub struct TlsTemplate {
    /// Virtual address where .tdata section was loaded by bootloader
    pub start_addr: u64,
    /// Size of initialized data (.tdata)
    pub file_size: u64,
    /// Total TLS size including .tbss (file_size + bss_size)
    pub mem_size: u64,
    /// Required alignment for TLS blocks
    pub alignment: u64,
    /// Whether template is valid (bootloader provided TLS info)
    pub valid: bool,
}

impl TlsTemplate {
    pub const fn empty() -> Self {
        Self {
            start_addr: 0,
            file_size: 0,
            mem_size: 0,
            alignment: 16, // Default minimum alignment
            valid: false,
        }
    }
}

/// Global TLS template - extracted from boot_info early in init
pub static mut TLS_TEMPLATE: TlsTemplate = TlsTemplate::empty();

// =============================================================================
// Thread Control Block (TCB)
// =============================================================================

/// Thread Control Block - placed at %fs:0 per System V ABI.
/// The self-pointer at offset 0 is mandatory for TLS variable access.
#[repr(C, align(16))]
pub struct Tcb {
    /// Self-pointer: %fs:0 must point to TCB itself.
    /// Required by System V ABI for TLS access pattern: mov %fs:0, %rax
    pub self_ptr: *mut Tcb,

    /// CPU ID for this core
    pub cpu_id: u32,

    /// Padding for alignment
    pub _reserved: u32,

    /// Stack canary for stack smashing protection
    pub canary: u64,

    /// Pointer to task struct when in user-mode threads (null for boot CPUs)
    pub task_ptr: u64,
}

impl Tcb {
    pub const fn new() -> Self {
        Self {
            self_ptr: core::ptr::null_mut(),
            cpu_id: 0,
            _reserved: 0,
            canary: 0xDEAD_BEEF_CAFE_BABE,
            task_ptr: 0,
        }
    }

    pub const SIZE: usize = core::mem::size_of::<Tcb>();
}

// =============================================================================
// TLS Block - Represents an allocated TLS region
// =============================================================================

/// Represents an allocated TLS block (TCB + TLS data)
unsafe impl Send for TlsBlock {}
unsafe impl Sync for TlsBlock {}

#[derive(Debug)]
pub struct TlsBlock {
    /// Pointer to the TCB at the start of this block
    pub tcb: *mut Tcb,
    /// Total size of this block (TCB + aligned TLS data)
    pub size: usize,
    /// Whether this block is from bootstrap arena (static) or heap
    pub from_bootstrap: bool,
}

impl TlsBlock {
    /// Get the TLS data region pointer (immediately after TCB)
    #[allow(dead_code)]
    pub fn tls_data_ptr(&self) -> *mut u8 {
        unsafe { (self.tcb as *mut u8).add(Tcb::SIZE) }
    }
}

// =============================================================================
// Bootstrap Arena - Static memory for early boot TLS
// =============================================================================

/// Static bootstrap arena in .bss.
/// This memory is available before heap initialization.
#[repr(C, align(4096))]
pub struct BootstrapArena {
    pub data: [u8; BOOTSTRAP_ARENA_SIZE],
}

pub static mut BOOTSTRAP_ARENA: BootstrapArena = BootstrapArena {
    data: [0; BOOTSTRAP_ARENA_SIZE],
};

/// Next slot index for bootstrap allocation
static NEXT_BOOTSTRAP_SLOT: AtomicUsize = AtomicUsize::new(0);

/// Whether FSGSBASE is supported (cached after first check)
static mut FSGSBASE_SUPPORTED: Option<bool> = None;

// =============================================================================
// Helper Functions
// =============================================================================

/// Align value up to the given alignment
#[inline]
const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

/// Calculate actual block size needed based on TLS template
pub fn actual_block_size(template: &TlsTemplate) -> usize {
    if !template.valid {
        // No TLS data, just need TCB
        align_up(Tcb::SIZE as u64, 16) as usize
    } else {
        let tls_align = template.alignment.max(16);
        let total = Tcb::SIZE as u64 + template.mem_size;
        align_up(total, tls_align) as usize
    }
}

/// Validate that bootstrap arena blocks are large enough
pub fn validate_bootstrap_size(template: &TlsTemplate) -> Result<(), &'static str> {
    let needed = actual_block_size(template);
    if needed > BOOTSTRAP_BLOCK_SIZE {
        return Err("TLS template too large for bootstrap arena");
    }
    Ok(())
}

/// Generate stack canary using TSC for entropy

fn generate_canary() -> u64 {
    unsafe {
        let lo: u32;
        let hi: u32;

        asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );

        ((hi as u64) << 32 | (lo as u64)) ^ 0xDEAD_BEEF_CAFE_BABE
    }
}

// =============================================================================
// FSGSBASE Support
// =============================================================================

/// Check if FSGSBASE instructions are supported
pub fn has_fsgsbase() -> bool {
    unsafe {
        if let Some(supported) = FSGSBASE_SUPPORTED {
            return supported;
        }

        let cpuid = CpuId::new();
        let supported = cpuid
            .get_extended_feature_info()
            .map(|info| info.has_fsgsbase())
            .unwrap_or(false);

        FSGSBASE_SUPPORTED = Some(supported);
        supported
    }
}

/// Enable FSGSBASE instructions (set CR4.FSGSBASE bit).
/// Must be called once per CPU before using WRFSBASE.
///
/// # Safety
/// Requires ring 0, modifies CR4.
pub unsafe fn enable_fsgsbase() {
    if has_fsgsbase() {
        use x86_64::registers::control::{Cr4, Cr4Flags};

        let mut cr4 = Cr4::read();
        cr4 |= Cr4Flags::FSGSBASE;
        Cr4::write(cr4);
    }
}

// =============================================================================
// FS Base Register Operations
// =============================================================================

/// Set FS base register.
/// Uses WRFSBASE if available, falls back to WRMSR.
///
/// # Safety
/// base must point to valid TCB.
#[inline]
pub unsafe fn set_fs_base_impl(base: u64) {
    if has_fsgsbase() {
        // Fast path: use WRFSBASE instruction
        asm!(
            "wrfsbase {0}",
            in(reg) base,
            options(nostack, preserves_flags)
        );
    } else {
        // Fallback: use WRMSR to IA32_FS_BASE
        crate::cpu::write_msr(IA32_FS_BASE, base);
    }
}

/// Read current FS base
#[inline]
pub unsafe fn get_fs_base() -> u64 {
    if has_fsgsbase() {
        let base: u64;
        asm!(
            "rdfsbase {0}",
            out(reg) base,
            options(nostack, preserves_flags)
        );
        base
    } else {
        crate::cpu::read_msr(IA32_FS_BASE)
    }
}

// =============================================================================
// TLS Template Extraction
// =============================================================================

/// Extract TLS template from boot info into static storage.
/// MUST be called before init_heap() on BSP.
///
/// # Safety
/// Must be called exactly once, on BSP, with interrupts disabled.
pub unsafe fn extract_tls_template(boot_info: &BootInfo) {
    if let Some(tls) = boot_info.tls_template.into_option() {
        TLS_TEMPLATE = TlsTemplate {
            start_addr: tls.start_addr,
            file_size: tls.file_size,
            mem_size: tls.mem_size,
            alignment: 16, // bootloader_api doesn't expose alignment, assume 16
            valid: true,
        };
    }
    // If no TLS template, TLS_TEMPLATE remains empty/invalid
}

// =============================================================================
// Bootstrap TLS Block Allocation
// =============================================================================

/// Allocate a TLS block from the bootstrap arena.
/// Returns pointer to TCB, or None if arena exhausted.
///
/// # Safety
/// Arena access must be synchronized (uses atomic slot allocation).
pub unsafe fn alloc_bootstrap_tls_block() -> Option<*mut Tcb> {
    let slot = NEXT_BOOTSTRAP_SLOT.fetch_add(1, Ordering::AcqRel);
    if slot >= MAX_BOOTSTRAP_CPUS {
        return None;
    }

    let block_offset = slot * BOOTSTRAP_BLOCK_SIZE;
    let block_ptr = BOOTSTRAP_ARENA.data.as_mut_ptr().add(block_offset);

    Some(block_ptr as *mut Tcb)
}

// =============================================================================
// TLS Block Materialization
// =============================================================================

/// Materialize a TLS block: initialize TCB, copy .tdata, zero .tbss.
///
/// # Arguments
/// * `tcb_ptr` - Pointer to allocated TCB location
/// * `cpu_id` - CPU ID to store in TCB
///
/// # Safety
/// tcb_ptr must point to valid, properly aligned memory.
pub unsafe fn materialize_tls_block(tcb_ptr: *mut Tcb, cpu_id: u32) {
    // Initialize TCB
    let tcb = &mut *tcb_ptr;
    tcb.self_ptr = tcb_ptr;
    tcb.cpu_id = cpu_id;
    tcb._reserved = 0;
    tcb.canary = generate_canary();
    tcb.task_ptr = 0;

    let template = &TLS_TEMPLATE;
    if !template.valid || template.mem_size == 0 {
        return; // No TLS data to copy
    }

    // TLS data starts immediately after TCB
    let tls_data = (tcb_ptr as *mut u8).add(Tcb::SIZE);

    // Copy .tdata (initialized data)
    if template.file_size > 0 {
        core::ptr::copy_nonoverlapping(
            template.start_addr as *const u8,
            tls_data,
            template.file_size as usize,
        );
    }

    // Zero .tbss (uninitialized data)
    let bss_size = template.mem_size - template.file_size;
    if bss_size > 0 {
        core::ptr::write_bytes(
            tls_data.add(template.file_size as usize),
            0,
            bss_size as usize,
        );
    }
}

// =============================================================================
// High-Level Per-CPU TLS Initialization
// =============================================================================

/// Initialize TLS for the current CPU (BSP or AP).
/// MUST be called before any heap allocation or allocator use.
///
/// # Arguments
/// * `cpu_id` - Logical CPU ID for this processor
///
/// # Returns
/// The initialized TlsBlock info.
///
/// # Safety
/// Must be called once per CPU during early initialization.
pub unsafe fn init_cpu_tls(cpu_id: u32) -> TlsBlock {
    // Enable FSGSBASE if supported (idempotent, safe to call multiple times)
    enable_fsgsbase();

    // Allocate from bootstrap arena
    let tcb_ptr = alloc_bootstrap_tls_block().expect("Bootstrap TLS arena exhausted");

    // Materialize the block (init TCB, copy template)
    materialize_tls_block(tcb_ptr, cpu_id);

    // Set FS base to point to TCB
    set_fs_base_impl(tcb_ptr as u64);

    TlsBlock {
        tcb: tcb_ptr,
        size: actual_block_size(&TLS_TEMPLATE),
        from_bootstrap: true,
    }
}

// =============================================================================
// Heap-Based TLS for Tasks/Threads (post-heap initialization)
// =============================================================================

/// Allocate a TLS block from the heap for a new task.
/// Called after heap is available, for user tasks.
pub fn alloc_heap_tls_block() -> Option<TlsBlock> {
    let template = unsafe { &TLS_TEMPLATE };
    let block_size = actual_block_size(template);
    let align = template.alignment.max(16) as usize;

    // Allocate from heap with proper alignment
    let layout = core::alloc::Layout::from_size_align(block_size, align).ok()?;
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };

    if ptr.is_null() {
        return None;
    }

    Some(TlsBlock {
        tcb: ptr as *mut Tcb,
        size: block_size,
        from_bootstrap: false,
    })
}

/// Initialize a heap-allocated TLS block for a task.
///
/// # Arguments
/// * `block` - The allocated TlsBlock
/// * `task_ptr` - Pointer to associated Task struct
///
/// # Safety
/// block.tcb must point to valid allocated memory.
pub unsafe fn init_task_tls(block: &TlsBlock, task_ptr: u64) {
    materialize_tls_block(block.tcb, 0); // cpu_id set dynamically on schedule
    (*block.tcb).task_ptr = task_ptr;
}

/// Free a heap-allocated TLS block.
///
/// # Safety
/// block must have been allocated via alloc_heap_tls_block() and not already freed.
pub unsafe fn free_heap_tls_block(block: TlsBlock) {
    if block.from_bootstrap {
        return; // Bootstrap blocks are never freed
    }

    let template = &TLS_TEMPLATE;
    let align = template.alignment.max(16) as usize;
    let layout =
        core::alloc::Layout::from_size_align(block.size, align).expect("Invalid TLS layout");

    alloc::alloc::dealloc(block.tcb as *mut u8, layout);
}

/// Load a task's TLS block for context switch.
///
/// # Arguments
/// * `block` - The task's TLS block
/// * `cpu_id` - Current CPU ID to update in TCB
///
/// # Safety
/// block.tcb must point to valid TLS block.
pub unsafe fn load_task_tls(block: &TlsBlock, cpu_id: u32) {
    (*block.tcb).cpu_id = cpu_id;
    set_fs_base_impl(block.tcb as u64);
}
