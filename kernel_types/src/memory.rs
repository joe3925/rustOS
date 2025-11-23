use alloc::{string::String, vec::Vec};
use x86_64::VirtAddr;

#[derive(Clone, Debug)]
pub struct Module {
    pub title: String,
    pub image_path: String,
    pub parent_pid: u64,
    pub image_base: VirtAddr,
    pub symbols: Vec<(String, usize)>,
}
