use alloc::string::String;
use kernel_types::status::TaskError;

pub fn create_kernel_task(entry: extern "win64" fn(usize), ctx: usize, name: String) -> u64 {
    unsafe { kernel_sys::create_kernel_task(entry, ctx, name) }
}
pub unsafe fn sleep_self() {
    kernel_sys::sleep_self();
}
pub unsafe fn sleep_self_and_yield() {
    kernel_sys::sleep_self_and_yield();
}
pub unsafe fn kill_kernel_task_by_id(id: u64) -> Result<(), TaskError> {
    kernel_sys::kill_kernel_task_by_id(id)
}
pub fn wake_task(id: u64) {
    unsafe { kernel_sys::wake_task(id) };
}
