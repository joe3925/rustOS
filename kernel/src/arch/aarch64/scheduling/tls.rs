use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use kernel_types::runtime::BlockOnThreadState;
use spin::Mutex;

use crate::arch::tls::TlsDirectory;
use crate::platform::CpuPlatform;
use crate::util::boot_info;

use super::super::platform::Aarch64Platform;

pub use crate::arch::tls::KernelTls;

static BLOCK_ON_THREAD_STATE: Mutex<Option<Arc<BlockOnThreadState>>> = Mutex::new(None);

pub fn for_kernel_thread() -> Option<KernelTls> {
    let directory = boot_info().arch_info.pe_tls_directory.as_ref().copied()?;
    KernelTls::new(TlsDirectory {
        start: directory.start_address_of_raw_data,
        end: directory.end_address_of_raw_data,
        zero_fill: directory.size_of_zero_fill,
        characteristics: directory.characteristics,
    })
}

pub(crate) unsafe fn activate(tls_array_pointer: u64) {
    Aarch64Platform::current_percpu()
        .tls_array_pointer
        .store(tls_array_pointer, Ordering::Release);
}

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
