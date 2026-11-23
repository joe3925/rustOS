#[cfg(not(windows))]
use ::std::sync::{Condvar, Mutex};
use core::cell::Cell;
#[cfg(windows)]
use core::ffi::c_void;
use std::format;

use super::WorkerPlatform;

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(
        attributes: *mut c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u16,
    ) -> *mut c_void;
    fn WaitForSingleObject(handle: *mut c_void, timeout: u32) -> u32;
    fn SetEvent(handle: *mut c_void) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

#[cfg(windows)]
#[repr(transparent)]
pub struct WaitHandle(usize);

#[cfg(not(windows))]
pub struct WaitHandle {
    permit: Mutex<bool>,
    changed: Condvar,
}

#[cfg(windows)]
impl Drop for WaitHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0 as *mut c_void) };
    }
}

::std::thread_local! {
    static WORKER_INDEX: Cell<usize> = const { Cell::new(usize::MAX) };
}

pub enum StdWorkerPlatform {}

impl WorkerPlatform for StdWorkerPlatform {
    type WaitHandle = WaitHandle;

    #[inline(always)]
    fn create_wait_handle() -> Self::WaitHandle {
        #[cfg(windows)]
        {
            let event = unsafe { CreateEventW(core::ptr::null_mut(), 0, 0, core::ptr::null()) };
            assert!(!event.is_null(), "failed to create runtime worker event");
            WaitHandle(event as usize)
        }
        #[cfg(not(windows))]
        {
            WaitHandle {
                permit: Mutex::new(false),
                changed: Condvar::new(),
            }
        }
    }

    #[inline(always)]
    fn init_worker(index: usize, _wait_handle: &Self::WaitHandle) {
        WORKER_INDEX.set(index);
    }

    #[inline(always)]
    fn wait(wait_handle: &Self::WaitHandle) {
        #[cfg(windows)]
        {
            assert_eq!(
                unsafe { WaitForSingleObject(wait_handle.0 as *mut c_void, u32::MAX) },
                0,
                "runtime worker wait failed"
            );
        }
        #[cfg(not(windows))]
        {
            let mut permit = wait_handle
                .permit
                .lock()
                .expect("runtime worker wait poisoned");
            while !*permit {
                permit = wait_handle
                    .changed
                    .wait(permit)
                    .expect("runtime worker wait poisoned");
            }
            *permit = false;
        }
    }

    #[inline(always)]
    fn signal(wait_handle: &Self::WaitHandle) {
        #[cfg(windows)]
        {
            assert_ne!(unsafe { SetEvent(wait_handle.0 as *mut c_void) }, 0);
        }
        #[cfg(not(windows))]
        {
            let mut permit = wait_handle
                .permit
                .lock()
                .expect("runtime worker wait poisoned");
            *permit = true;
            wait_handle.changed.notify_one();
        }
    }

    #[inline]
    fn spawn_worker(index: usize, work: impl FnOnce() + Send + 'static) {
        ::std::thread::Builder::new()
            .name(format!("executor_worker_{index}"))
            .spawn(work)
            .expect("failed to spawn executor worker");
    }

    #[inline(always)]
    fn worker_index() -> usize {
        WORKER_INDEX.get()
    }
}
