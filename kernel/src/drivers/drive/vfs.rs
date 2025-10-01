use alloc::{string::String, sync::Arc, vec::Vec};
use spin::RwLock;

#[derive(Debug)]
pub enum FsError {}
pub struct FileSystemNode {
    // Symlink to a fs driver that is expected to be able to handle at least
    // Dir list
    // File open
    fs_symlink: String,
}
impl FileSystemNode {
    pub fn new(symlink: String) -> Result<Self, FsError> {
        Ok(FileSystemNode {
            fs_symlink: symlink,
        })
    }
}
pub struct Vfs {
    mounted_fs: Arc<RwLock<Vec<FileSystemNode>>>,
}
impl Vfs {
    pub fn mount(&self, symlink: String) {
        self.mounted_fs
            .write()
            .push(FileSystemNode::new(symlink).expect("Todo"));
    }
}
