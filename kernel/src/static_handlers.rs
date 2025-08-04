use core::alloc::{GlobalAlloc, Layout};

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    console::CONSOLE,
    drivers::interrupt_index::wait_millis,
    file_system::file::{File, FileStatus, OpenFlags},
    memory::{allocator::ALLOCATOR, paging::constants::KERNEL_STACK_SIZE},
    scheduling::{
        scheduler::{TaskError, SCHEDULER},
        task::Task,
    },
};

pub extern "win64" fn create_kernel_task(entry: usize, name: String) -> Result<u64, TaskError> {
    let task = Task::new_kernel_mode(entry, KERNEL_STACK_SIZE, name, 0);
    SCHEDULER.lock().add_task(task)
}
pub extern "win64" fn kill_kernel_task_by_id(id: u64) -> Result<(), TaskError> {
    SCHEDULER.lock().delete_task(id)
}
pub extern "win64" fn kernel_alloc(layout: Layout) -> *mut u8 {
    unsafe { GlobalAlloc::alloc(&ALLOCATOR, layout) }
}
pub extern "win64" fn kernel_free(ptr: *mut u8, layout: Layout) {
    unsafe {
        GlobalAlloc::dealloc(&ALLOCATOR, ptr, layout);
    };
}
pub extern "win64" fn print(str: &[u8]) {
    CONSOLE.lock().print(str);
}
pub extern "win64" fn wait_ms(ms: u64) {
    wait_millis(ms);
}
#[no_mangle]
pub extern "win64" fn file_open(path: &str, flags: &[OpenFlags]) -> Result<File, FileStatus> {
    File::open(path, flags)
}

#[no_mangle]
pub extern "win64" fn fs_list_dir(path: &str) -> Result<Vec<String>, FileStatus> {
    File::list_dir(path)
}

#[no_mangle]
pub extern "win64" fn fs_remove_dir(path: &str) -> Result<(), FileStatus> {
    File::remove_dir(path.to_string())
}

#[no_mangle]
pub extern "win64" fn fs_make_dir(path: &str) -> Result<(), FileStatus> {
    File::make_dir(path.to_string())
}

#[no_mangle]
pub extern "win64" fn file_read(file: &File) -> Result<Vec<u8>, FileStatus> {
    file.read()
}

#[no_mangle]
pub extern "win64" fn file_write(file: &mut File, data: &[u8]) -> Result<(), FileStatus> {
    file.write(data)
}

#[no_mangle]
pub extern "win64" fn file_delete(file: &mut File) -> Result<(), FileStatus> {
    file.delete()
}
