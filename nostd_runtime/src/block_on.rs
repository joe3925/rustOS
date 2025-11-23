use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::Future;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

/// A simple notification signal used to wake the blocking thread.
#[repr(C)]
struct ThreadNotify {
    /// Whether the future has signaled it is ready to be polled again.
    ready: AtomicBool,
}

impl ThreadNotify {
    fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
        }
    }
}

// We implement the standard Wake trait to easily create a Waker from an Arc.
impl Wake for ThreadNotify {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // Signal that the future is ready to proceed.
        // Release ordering ensures any memory writes done by the future
        // are visible to the thread waking up.
        self.ready.store(true, Ordering::Release);
    }
}

/// Runs a future to completion on the current thread.
///
/// This function will block the caller until the given future has resolved.
/// It yields the CPU (via `hlt`) while waiting for interrupts/signals.
///
/// # Safety
/// This function assumes that interrupts are enabled. If run with interrupts
/// disabled, `hlt` may hang the CPU indefinitely if the future is waiting
/// on an I/O interrupt.
pub fn block_on<F: Future>(future: F) -> F::Output {
    // 1. Pin the future on the heap.
    // We need it pinned to poll it.
    let mut pinned_future = Box::pin(future);

    // 2. Create the notification signal.
    let notify = Arc::new(ThreadNotify::new());

    // 3. Convert the Arc<ThreadNotify> into a Waker.
    // The `Wake` trait impl handles the vtable construction for us.
    let waker = Waker::from(notify.clone());

    // 4. Create the polling context.
    let mut cx = Context::from_waker(&waker);

    // 5. The Drive Loop
    loop {
        // Poll the future
        match pinned_future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => {
                // The future is not ready. We wait until `wake()` is called.

                // We check the atomic flag. If it is true, we swap it to false
                // and immediately loop back to poll again.
                // If it is false, we halt the CPU to save power until an interrupt occurs.
                //
                // Acquire ordering ensures we see the data written by the task
                // before it woke us up.
                while !notify.ready.swap(false, Ordering::Acquire) {
                    // Execute x86 HLT instruction.
                    // This pauses the CPU until the next hardware interrupt (e.g., timer, I/O).
                    // When an interrupt fires, the CPU wakes up, the ISR runs,
                    // completion routines run (setting our atomic bool), and execution resumes.
                    unsafe {
                        core::arch::asm!("hlt");
                    }
                }
            }
        }
    }
}
