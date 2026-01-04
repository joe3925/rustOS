use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use crate::file_system::file;
use crate::file_system::file_provider::FileProvider;
use crate::util::BootPkg;
use kernel_types::{
    async_ffi::{FfiFuture, FutureExt},
    fs::{Path, *},
    request::Request,
    status::{DriverStatus, FileStatus},
};

const C_PREFIX: &str = "C:/";
const REG_DIR: &str = "C:/system/registry";
const REG_SNAP_PATH: &str = "C:/system/registry/registry.snap";
const REG_WAL_PATH: &str = "C:/system/registry/registry.wal";
const DRIVER_ROOT: &str = "C:/install/drivers";

fn norm_upcase(p: &str) -> String {
    let s = p.replace('\\', "/");
    if !s.starts_with(C_PREFIX) {
        return s.to_uppercase();
    }
    let mut out = String::from("C:/");
    let mut last_was_slash = true;
    for ch in s["C:/".len()..].chars() {
        if ch == '/' {
            if !last_was_slash {
                out.push('/');
            }
            last_was_slash = true;
        } else {
            out.push(ch.to_ascii_uppercase());
            last_was_slash = false;
        }
    }
    if out.ends_with('/') && out.len() > 3 {
        out.pop();
    }
    out
}
fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map(|(a, _)| a).unwrap_or("C:/")
}
fn leaf_of(path: &str) -> &str {
    path.rsplit_once('/').map(|(_, b)| b).unwrap_or(path)
}

enum DataRef<'a> {
    Static(&'a [u8]),
    Ram(Vec<u8>),
    Alias(String),
}

struct Node<'a> {
    is_dir: bool,
    data: Option<DataRef<'a>>,
    children: BTreeMap<String, String>,
}

impl<'a> Node<'a> {
    fn dir() -> Self {
        Self {
            is_dir: true,
            data: None,
            children: BTreeMap::new(),
        }
    }
    fn file(data: DataRef<'a>) -> Self {
        Self {
            is_dir: false,
            data: Some(data),
            children: BTreeMap::new(),
        }
    }
    fn size(&self, fs: &BootstrapProvider<'a>, path: &str) -> u64 {
        if self.is_dir {
            return 0;
        }
        match self.data.as_ref().unwrap() {
            DataRef::Static(b) => b.len() as u64,
            DataRef::Ram(v) => v.len() as u64,
            DataRef::Alias(t) => fs.size_of(t) as u64,
        }
    }
}

pub struct BootstrapProvider<'a> {
    nodes: RwLock<BTreeMap<String, Node<'a>>>,
    next_id: AtomicU64,
    handles: RwLock<BTreeMap<u64, String>>,
}

impl<'a> BootstrapProvider<'a> {
    pub fn new(boot: &'a [BootPkg]) -> Self {
        let prov = Self {
            nodes: RwLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            handles: RwLock::new(BTreeMap::new()),
        };
        prov.init_tree(boot);
        prov
    }

    fn init_tree(&self, boot: &'a [BootPkg]) {
        let mut n = self.nodes.write();

        for d in [
            "C:/",
            "C:/install",
            DRIVER_ROOT,
            "C:/system",
            "C:/system/toml",
            "C:/system/mod",
            REG_DIR,
        ] {
            let dk = norm_upcase(d);
            n.entry(dk.clone()).or_insert_with(Node::dir);
        }

        // Add registry directory to system's children
        n.get_mut(&norm_upcase("C:/system"))
            .unwrap()
            .children
            .insert("registry".into(), norm_upcase(REG_DIR));

        // Create registry.snap file (RAM-backed)
        let snap_key = norm_upcase(REG_SNAP_PATH);
        n.insert(snap_key.clone(), Node::file(DataRef::Ram(Vec::new())));
        n.get_mut(&norm_upcase(REG_DIR))
            .unwrap()
            .children
            .insert("registry.snap".into(), snap_key);

        // Create registry.wal file (RAM-backed)
        let wal_key = norm_upcase(REG_WAL_PATH);
        n.insert(wal_key.clone(), Node::file(DataRef::Ram(Vec::new())));
        n.get_mut(&norm_upcase(REG_DIR))
            .unwrap()
            .children
            .insert("registry.wal".into(), wal_key);

        for bp in boot {
            let ddir = norm_upcase(&alloc::format!("{}/{}", DRIVER_ROOT, bp.name));
            n.entry(ddir.clone()).or_insert_with(Node::dir);

            n.get_mut(&norm_upcase(DRIVER_ROOT))
                .unwrap()
                .children
                .insert(bp.name.clone().to_string(), ddir.clone());

            let toml_name = alloc::format!("{}.toml", bp.name);
            let dll_name = alloc::format!("{}.dll", bp.name);

            let toml_src = norm_upcase(&alloc::format!("{}/{}", ddir, toml_name));
            let dll_src = norm_upcase(&alloc::format!("{}/{}", ddir, dll_name));

            n.insert(toml_src.clone(), Node::file(DataRef::Static(bp.toml)));
            n.insert(dll_src.clone(), Node::file(DataRef::Static(bp.image)));

            n.get_mut(&ddir)
                .unwrap()
                .children
                .insert(toml_name.clone(), toml_src.clone());
            n.get_mut(&ddir)
                .unwrap()
                .children
                .insert(dll_name.clone(), dll_src.clone());

            let toml_target = norm_upcase(&alloc::format!("C:/system/toml/{}", toml_name));
            let dll_target = norm_upcase(&alloc::format!("C:/system/mod/{}", dll_name));

            n.insert(toml_target.clone(), Node::file(DataRef::Alias(toml_src)));
            n.insert(dll_target.clone(), Node::file(DataRef::Alias(dll_src)));

            n.get_mut(&norm_upcase("C:/system/toml"))
                .unwrap()
                .children
                .insert(toml_name, toml_target);

            n.get_mut(&norm_upcase("C:/system/mod"))
                .unwrap()
                .children
                .insert(dll_name, dll_target);
        }
    }

    fn must_c(&self, path: &str) -> Result<String, FileStatus> {
        let p = norm_upcase(path);
        if !p.starts_with(C_PREFIX) {
            return Err(FileStatus::PathNotFound);
        }
        Ok(p)
    }

    fn size_of(&self, path: &str) -> usize {
        let map = self.nodes.read();
        match map.get(path) {
            None => 0,
            Some(n) => {
                if n.is_dir {
                    0
                } else {
                    match n.data.as_ref().unwrap() {
                        DataRef::Static(b) => b.len(),
                        DataRef::Ram(v) => v.len(),
                        DataRef::Alias(t) => self.size_of(t),
                    }
                }
            }
        }
    }

    fn is_registry_file(path: &str) -> bool {
        let p = norm_upcase(path);
        p == norm_upcase(REG_SNAP_PATH) || p == norm_upcase(REG_WAL_PATH)
    }

    fn seek_handle_sync(
        &self,
        file_id: u64,
        offset: i64,
        origin: FsSeekWhence,
    ) -> (FsSeekResult, DriverStatus) {
        let path = match self.handles.read().get(&file_id) {
            Some(p) => p.clone(),
            None => {
                return (
                    FsSeekResult {
                        pos: 0,
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        };

        let size = self.size_of(&path) as i128;

        let base: i128 = match origin {
            FsSeekWhence::Set => 0,
            FsSeekWhence::Cur => 0,
            FsSeekWhence::End => size,
        };

        let new_pos_i = base + offset as i128;
        let new_pos = if new_pos_i < 0 { 0 } else { new_pos_i as u64 };

        (
            FsSeekResult {
                pos: new_pos,
                error: None,
            },
            DriverStatus::Success,
        )
    }

    fn read_slice(&self, path: &str, offset: u64, len: u32) -> Result<Vec<u8>, FileStatus> {
        let mut cur = path.to_string();

        let data_vec = loop {
            let map = self.nodes.read();
            let node = map.get(&cur).ok_or(FileStatus::PathNotFound)?;

            if node.is_dir {
                return Err(FileStatus::BadPath);
            }

            match node.data.as_ref().unwrap() {
                DataRef::Static(b) => break b.to_vec(),
                DataRef::Ram(v) => break v.clone(),
                DataRef::Alias(t) => {
                    cur = t.clone();
                }
            }
        };

        let total = data_vec.len();
        let off = core::cmp::min(offset as usize, total);
        let take = core::cmp::min(len as usize, total.saturating_sub(off));
        Ok(data_vec[off..off + take].to_vec())
    }

    fn write_slice(&self, path: &str, offset: u64, data: &[u8]) -> Result<u32, FileStatus> {
        let mut map = self.nodes.write();
        let node = map.get_mut(path).ok_or(FileStatus::PathNotFound)?;

        if node.is_dir {
            return Err(FileStatus::BadPath);
        }

        match node.data.as_mut().unwrap() {
            DataRef::Ram(v) => {
                let need = (offset as usize).saturating_add(data.len());
                if v.len() < need {
                    v.resize(need, 0);
                }
                v[offset as usize..offset as usize + data.len()].copy_from_slice(data);
                Ok(data.len() as u32)
            }
            DataRef::Static(_) => Err(FileStatus::UnknownFail),
            DataRef::Alias(_t) => Ok(data.len() as u32),
        }
    }

    fn ensure_dir(&self, p: &str) -> Result<(), FileStatus> {
        let p = norm_upcase(p);
        if !p.starts_with(C_PREFIX) {
            return Err(FileStatus::PathNotFound);
        }
        let mut map = self.nodes.write();
        if map.contains_key(&p) {
            let is_dir = map.get(&p).unwrap().is_dir;
            if is_dir {
                return Ok(());
            }
            return Err(FileStatus::BadPath);
        }
        let parent = parent_of(&p).to_string();
        if !map.contains_key(&parent) {
            return Err(FileStatus::BadPath);
        }
        map.insert(p.clone(), Node::dir());
        map.get_mut(&parent)
            .unwrap()
            .children
            .insert(leaf_of(&p).to_string(), p);
        Ok(())
    }

    fn create_file_if_missing(&self, path: &str) -> Result<(), FileStatus> {
        let p = norm_upcase(path);
        if !p.starts_with(C_PREFIX) {
            return Err(FileStatus::PathNotFound);
        }

        let mut map = self.nodes.write();

        // Already exists
        if map.contains_key(&p) {
            return Ok(());
        }

        // Check parent exists and is a directory
        let parent = parent_of(&p).to_string();
        match map.get(&parent) {
            Some(n) if n.is_dir => {}
            Some(_) => return Err(FileStatus::BadPath),
            None => return Err(FileStatus::PathNotFound),
        }

        // Create empty RAM-backed file
        let leaf = leaf_of(&p).to_string();
        map.insert(p.clone(), Node::file(DataRef::Ram(Vec::new())));
        map.get_mut(&parent).unwrap().children.insert(leaf, p);

        Ok(())
    }
}

impl<'a> BootstrapProvider<'a> {
    fn open_path_sync(&self, path: &str, flags: &[OpenFlags]) -> (FsOpenResult, DriverStatus) {
        let p = match self.must_c(path) {
            Ok(p) => p,
            Err(e) => {
                return (
                    FsOpenResult {
                        fs_file_id: 0,
                        is_dir: false,
                        size: 0,
                        error: Some(e),
                    },
                    DriverStatus::Success,
                )
            }
        };

        // Check create flags (order in slice does not matter)
        let wants_create_new = flags.iter().any(|f| matches!(f, OpenFlags::CreateNew));
        let wants_create = wants_create_new || flags.iter().any(|f| matches!(f, OpenFlags::Create));

        let (exists, is_dir) = {
            let map = self.nodes.read();
            match map.get(&p) {
                Some(n) => (true, n.is_dir),
                None => (false, false),
            }
        };

        if !exists {
            if wants_create {
                // Try to create the file
                if let Err(e) = self.create_file_if_missing(&p) {
                    return (
                        FsOpenResult {
                            fs_file_id: 0,
                            is_dir: false,
                            size: 0,
                            error: Some(e),
                        },
                        DriverStatus::Success,
                    );
                }
            } else {
                return (
                    FsOpenResult {
                        fs_file_id: 0,
                        is_dir: false,
                        size: 0,
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                );
            }
        } else if wants_create_new {
            return (
                FsOpenResult {
                    fs_file_id: 0,
                    is_dir: false,
                    size: 0,
                    error: Some(FileStatus::FileAlreadyExist),
                },
                DriverStatus::Success,
            );
        }

        let id = self.next_id.fetch_add(1, Ordering::AcqRel).max(1);
        self.handles.write().insert(id, p.clone());

        // Re-check after potential creation
        let (is_dir, size) = {
            let map = self.nodes.read();
            match map.get(&p) {
                Some(n) => (n.is_dir, n.size(self, &p)),
                None => (false, 0),
            }
        };

        (
            FsOpenResult {
                fs_file_id: id,
                is_dir,
                size,
                error: None,
            },
            DriverStatus::Success,
        )
    }

    fn close_handle_sync(&self, file_id: u64) -> (FsCloseResult, DriverStatus) {
        let removed = self.handles.write().remove(&file_id).is_some();
        (
            FsCloseResult {
                error: if removed {
                    None
                } else {
                    Some(FileStatus::PathNotFound)
                },
            },
            DriverStatus::Success,
        )
    }

    fn read_at_sync(&self, file_id: u64, offset: u64, len: u32) -> (FsReadResult, DriverStatus) {
        let path = match self.handles.read().get(&file_id) {
            Some(p) => p.clone(),
            None => {
                return (
                    FsReadResult {
                        data: Vec::new(),
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        };
        match self.read_slice(&path, offset, len) {
            Ok(v) => (
                FsReadResult {
                    data: v,
                    error: None,
                },
                DriverStatus::Success,
            ),
            Err(e) => (
                FsReadResult {
                    data: Vec::new(),
                    error: Some(e),
                },
                DriverStatus::Success,
            ),
        }
    }

    fn write_at_sync(
        &self,
        file_id: u64,
        offset: u64,
        data: &[u8],
    ) -> (FsWriteResult, DriverStatus) {
        let path = match self.handles.read().get(&file_id) {
            Some(p) => p.clone(),
            None => {
                return (
                    FsWriteResult {
                        written: 0,
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        };
        match self.write_slice(&path, offset, data) {
            Ok(w) => (
                FsWriteResult {
                    written: w as usize,
                    error: None,
                },
                DriverStatus::Success,
            ),
            Err(e) => (
                FsWriteResult {
                    written: 0,
                    error: Some(e),
                },
                DriverStatus::Success,
            ),
        }
    }

    fn flush_handle_sync(&self, _file_id: u64) -> (FsFlushResult, DriverStatus) {
        (FsFlushResult { error: None }, DriverStatus::Success)
    }

    fn get_info_sync(&self, file_id: u64) -> (FsGetInfoResult, DriverStatus) {
        let path = match self.handles.read().get(&file_id) {
            Some(p) => p.clone(),
            None => {
                return (
                    FsGetInfoResult {
                        size: 0,
                        is_dir: false,
                        attrs: 0,
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        };
        let (exists, is_dir, size) = {
            let map = self.nodes.read();
            match map.get(&path) {
                None => (false, false, 0u64),
                Some(n) => (true, n.is_dir, n.size(self, &path)),
            }
        };
        if !exists {
            return (
                FsGetInfoResult {
                    size: 0,
                    is_dir: false,
                    attrs: 0,
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        }
        (
            FsGetInfoResult {
                size,
                is_dir,
                attrs: 0,
                error: None,
            },
            DriverStatus::Success,
        )
    }

    fn list_dir_path_sync(&self, path: &str) -> (FsListDirResult, DriverStatus) {
        let p = match self.must_c(path) {
            Ok(p) => p,
            Err(e) => {
                return (
                    FsListDirResult {
                        names: Vec::new(),
                        error: Some(e),
                    },
                    DriverStatus::Success,
                )
            }
        };
        let (exists, is_dir, names) = {
            let map = self.nodes.read();
            match map.get(&p) {
                Some(n) if n.is_dir => {
                    let mut v = Vec::new();
                    for (name, _) in n.children.iter() {
                        v.push(name.clone());
                    }
                    (true, true, v)
                }
                Some(_) => (true, false, Vec::new()),
                None => (false, false, Vec::new()),
            }
        };
        if !exists {
            return (
                FsListDirResult {
                    names: Vec::new(),
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        }
        if !is_dir {
            return (
                FsListDirResult {
                    names: Vec::new(),
                    error: Some(FileStatus::BadPath),
                },
                DriverStatus::Success,
            );
        }
        (
            FsListDirResult { names, error: None },
            DriverStatus::Success,
        )
    }

    fn make_dir_path_sync(&self, path: &str) -> (FsCreateResult, DriverStatus) {
        let r = self.ensure_dir(path).err();
        (
            FsCreateResult {
                error: r.map(|e| e),
            },
            DriverStatus::Success,
        )
    }

    fn remove_dir_path_sync(&self, _path: &str) -> (FsCreateResult, DriverStatus) {
        (
            FsCreateResult {
                error: Some(FileStatus::UnknownFail),
            },
            DriverStatus::Success,
        )
    }

    fn rename_path_sync(&self, src: &str, dst: &str) -> (FsRenameResult, DriverStatus) {
        let s = match self.must_c(src) {
            Ok(p) => p,
            Err(e) => return (FsRenameResult { error: Some(e) }, DriverStatus::Success),
        };
        let d = match self.must_c(dst) {
            Ok(p) => p,
            Err(e) => return (FsRenameResult { error: Some(e) }, DriverStatus::Success),
        };

        let mut map = self.nodes.write();

        let src_node_exists = match map.get(&s) {
            Some(n) if !n.is_dir => true,
            Some(_) => {
                return (
                    FsRenameResult {
                        error: Some(FileStatus::BadPath),
                    },
                    DriverStatus::Success,
                )
            }
            None => {
                return (
                    FsRenameResult {
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        };

        if !src_node_exists {
            return (
                FsRenameResult {
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        }

        let dparent = parent_of(&d).to_string();
        let dleaf = leaf_of(&d).to_string();
        match map.get(&dparent) {
            Some(n) if n.is_dir => {}
            Some(_) => {
                return (
                    FsRenameResult {
                        error: Some(FileStatus::BadPath),
                    },
                    DriverStatus::Success,
                )
            }
            None => {
                return (
                    FsRenameResult {
                        error: Some(FileStatus::BadPath),
                    },
                    DriverStatus::Success,
                )
            }
        }

        map.insert(d.clone(), Node::file(DataRef::Alias(s.clone())));
        map.get_mut(&dparent)
            .unwrap()
            .children
            .insert(dleaf, d.clone());

        (FsRenameResult { error: None }, DriverStatus::Success)
    }

    fn delete_path_sync(&self, path: &str) -> (FsCreateResult, DriverStatus) {
        let p = match self.must_c(path) {
            Ok(p) => p,
            Err(e) => return (FsCreateResult { error: Some(e) }, DriverStatus::Success),
        };

        // Handle registry files specially - clear content instead of deleting
        if Self::is_registry_file(&p) {
            let mut map = self.nodes.write();
            if let Some(Node {
                data: Some(DataRef::Ram(v)),
                ..
            }) = map.get_mut(&p)
            {
                v.clear();
                return (FsCreateResult { error: None }, DriverStatus::Success);
            }
        }

        // For other files, attempt actual deletion
        let mut map = self.nodes.write();

        // Check if file exists and is not a directory
        match map.get(&p) {
            Some(n) if !n.is_dir => {}
            Some(_) => {
                return (
                    FsCreateResult {
                        error: Some(FileStatus::BadPath),
                    },
                    DriverStatus::Success,
                )
            }
            None => {
                return (
                    FsCreateResult {
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        }

        // Remove from parent's children
        let parent = parent_of(&p).to_string();
        let leaf = leaf_of(&p).to_string();
        if let Some(parent_node) = map.get_mut(&parent) {
            parent_node.children.remove(&leaf);
        }

        // Remove the node itself
        map.remove(&p);

        (FsCreateResult { error: None }, DriverStatus::Success)
    }

    fn set_len_sync(&self, file_id: u64, new_size: u64) -> (FsSetLenResult, DriverStatus) {
        let path = match self.handles.read().get(&file_id) {
            Some(p) => p.clone(),
            None => {
                return (
                    FsSetLenResult {
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        };

        let mut map = self.nodes.write();
        let node = match map.get_mut(&path) {
            Some(n) => n,
            None => {
                return (
                    FsSetLenResult {
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        };

        if node.is_dir {
            return (
                FsSetLenResult {
                    error: Some(FileStatus::AccessDenied),
                },
                DriverStatus::Success,
            );
        }

        match node.data.as_mut() {
            Some(DataRef::Ram(v)) => {
                v.resize(new_size as usize, 0);
                (FsSetLenResult { error: None }, DriverStatus::Success)
            }
            Some(DataRef::Static(_)) => (
                FsSetLenResult {
                    error: Some(FileStatus::AccessDenied),
                },
                DriverStatus::Success,
            ),
            Some(DataRef::Alias(_)) => (
                FsSetLenResult {
                    error: Some(FileStatus::AccessDenied),
                },
                DriverStatus::Success,
            ),
            None => (
                FsSetLenResult {
                    error: Some(FileStatus::UnknownFail),
                },
                DriverStatus::Success,
            ),
        }
    }

    fn append_sync(&self, file_id: u64, data: &[u8]) -> (FsAppendResult, DriverStatus) {
        let path = match self.handles.read().get(&file_id) {
            Some(p) => p.clone(),
            None => {
                return (
                    FsAppendResult {
                        written: 0,
                        new_size: 0,
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        };

        let mut map = self.nodes.write();
        let node = match map.get_mut(&path) {
            Some(n) => n,
            None => {
                return (
                    FsAppendResult {
                        written: 0,
                        new_size: 0,
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        };

        if node.is_dir {
            return (
                FsAppendResult {
                    written: 0,
                    new_size: 0,
                    error: Some(FileStatus::AccessDenied),
                },
                DriverStatus::Success,
            );
        }

        match node.data.as_mut() {
            Some(DataRef::Ram(v)) => {
                v.extend_from_slice(data);
                let new_size = v.len() as u64;
                (
                    FsAppendResult {
                        written: data.len(),
                        new_size,
                        error: None,
                    },
                    DriverStatus::Success,
                )
            }
            Some(DataRef::Static(_)) => (
                FsAppendResult {
                    written: 0,
                    new_size: 0,
                    error: Some(FileStatus::AccessDenied),
                },
                DriverStatus::Success,
            ),
            Some(DataRef::Alias(_)) => (
                FsAppendResult {
                    written: 0,
                    new_size: 0,
                    error: Some(FileStatus::AccessDenied),
                },
                DriverStatus::Success,
            ),
            None => (
                FsAppendResult {
                    written: 0,
                    new_size: 0,
                    error: Some(FileStatus::UnknownFail),
                },
                DriverStatus::Success,
            ),
        }
    }

    fn zero_range_sync(
        &self,
        file_id: u64,
        offset: u64,
        len: u64,
    ) -> (FsZeroRangeResult, DriverStatus) {
        let path = match self.handles.read().get(&file_id) {
            Some(p) => p.clone(),
            None => {
                return (
                    FsZeroRangeResult {
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        };

        let mut map = self.nodes.write();
        let node = match map.get_mut(&path) {
            Some(n) => n,
            None => {
                return (
                    FsZeroRangeResult {
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                )
            }
        };

        if node.is_dir {
            return (
                FsZeroRangeResult {
                    error: Some(FileStatus::AccessDenied),
                },
                DriverStatus::Success,
            );
        }

        match node.data.as_mut() {
            Some(DataRef::Ram(v)) => {
                let file_len = v.len() as u64;
                if offset > file_len {
                    return (
                        FsZeroRangeResult {
                            error: Some(FileStatus::BadPath),
                        },
                        DriverStatus::Success,
                    );
                }
                let end = (offset.saturating_add(len)).min(file_len);
                let zero_len = end.saturating_sub(offset) as usize;
                if zero_len > 0 {
                    let start = offset as usize;
                    for i in start..start + zero_len {
                        v[i] = 0;
                    }
                }
                (FsZeroRangeResult { error: None }, DriverStatus::Success)
            }
            Some(DataRef::Static(_)) => (
                FsZeroRangeResult {
                    error: Some(FileStatus::AccessDenied),
                },
                DriverStatus::Success,
            ),
            Some(DataRef::Alias(_)) => (
                FsZeroRangeResult {
                    error: Some(FileStatus::AccessDenied),
                },
                DriverStatus::Success,
            ),
            None => (
                FsZeroRangeResult {
                    error: Some(FileStatus::UnknownFail),
                },
                DriverStatus::Success,
            ),
        }
    }
}

impl<'a> FileProvider for BootstrapProvider<'a> {
    fn open_path(
        &self,
        path: &Path,
        flags: &[OpenFlags],
    ) -> FfiFuture<(FsOpenResult, DriverStatus)> {
        let res = self.open_path_sync(&path.to_string(), flags);
        async move { res }.into_ffi()
    }

    fn close_handle(&self, file_id: u64) -> FfiFuture<(FsCloseResult, DriverStatus)> {
        let res = self.close_handle_sync(file_id);
        async move { res }.into_ffi()
    }
    fn seek_handle(
        &self,
        file_id: u64,
        offset: i64,
        origin: FsSeekWhence,
    ) -> FfiFuture<(FsSeekResult, DriverStatus)> {
        let res = self.seek_handle_sync(file_id, offset, origin);
        async move { res }.into_ffi()
    }
    fn read_at(
        &self,
        file_id: u64,
        offset: u64,
        len: u32,
    ) -> FfiFuture<(FsReadResult, DriverStatus)> {
        let res = self.read_at_sync(file_id, offset, len);
        async move { res }.into_ffi()
    }

    fn write_at(
        &self,
        file_id: u64,
        offset: u64,
        data: &[u8],
    ) -> FfiFuture<(FsWriteResult, DriverStatus)> {
        let res = self.write_at_sync(file_id, offset, data);
        async move { res }.into_ffi()
    }

    fn flush_handle(&self, file_id: u64) -> FfiFuture<(FsFlushResult, DriverStatus)> {
        let res = self.flush_handle_sync(file_id);
        async move { res }.into_ffi()
    }

    fn get_info(&self, file_id: u64) -> FfiFuture<(FsGetInfoResult, DriverStatus)> {
        let res = self.get_info_sync(file_id);
        async move { res }.into_ffi()
    }

    fn list_dir_path(&self, path: &Path) -> FfiFuture<(FsListDirResult, DriverStatus)> {
        let res = self.list_dir_path_sync(&path.to_string());
        async move { res }.into_ffi()
    }

    fn make_dir_path(&self, path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)> {
        let res = self.make_dir_path_sync(&path.to_string());
        async move { res }.into_ffi()
    }

    fn remove_dir_path(&self, path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)> {
        let res = self.remove_dir_path_sync(&path.to_string());
        async move { res }.into_ffi()
    }

    fn rename_path(&self, src: &Path, dst: &Path) -> FfiFuture<(FsRenameResult, DriverStatus)> {
        let res = self.rename_path_sync(&src.to_string(), &dst.to_string());
        async move { res }.into_ffi()
    }

    fn delete_path(&self, path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)> {
        let res = self.delete_path_sync(&path.to_string());
        async move { res }.into_ffi()
    }

    fn set_len(&self, file_id: u64, new_size: u64) -> FfiFuture<(FsSetLenResult, DriverStatus)> {
        let res = self.set_len_sync(file_id, new_size);
        async move { res }.into_ffi()
    }

    fn append(&self, file_id: u64, data: &[u8]) -> FfiFuture<(FsAppendResult, DriverStatus)> {
        let res = self.append_sync(file_id, data);
        async move { res }.into_ffi()
    }

    fn zero_range(
        &self,
        file_id: u64,
        offset: u64,
        len: u64,
    ) -> FfiFuture<(FsZeroRangeResult, DriverStatus)> {
        let res = self.zero_range_sync(file_id, offset, len);
        async move { res }.into_ffi()
    }
}
