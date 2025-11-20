// bootstrap_file.rs
#![no_std]

extern crate alloc;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use crate::file_system::file_structs::{
    FsCloseParams, FsCloseResult, FsCreateParams, FsCreateResult, FsFlushParams, FsFlushResult,
    FsGetInfoParams, FsGetInfoResult, FsListDirParams, FsListDirResult, FsOpenParams, FsOpenResult,
    FsReadParams, FsReadResult, FsRenameParams, FsRenameResult, FsSeekParams, FsSeekResult,
    FsSeekWhence, FsWriteParams, FsWriteResult,
};
use crate::file_system::{file::FileStatus, file_provider::FileProvider};
use crate::util::BootPkg;
use crate::{drivers::pnp::driver_object::DriverStatus, file_system::file::OpenFlags};

const C_PREFIX: &str = "C:\\";
const REG_PATH: &str = "C:\\SYSTEM\\REGISTRY.BIN";
const DRIVER_ROOT: &str = "C:\\INSTALL\\DRIVERS";

fn norm_upcase(p: &str) -> String {
    let s = p.replace('/', "\\");
    if !s.starts_with(C_PREFIX) {
        return s.to_uppercase();
    }
    let mut out = String::from("C:\\");
    let mut last_was_slash = true;
    for ch in s["C:\\".len()..].chars() {
        if ch == '\\' {
            if !last_was_slash {
                out.push('\\');
            }
            last_was_slash = true;
        } else {
            out.push(ch.to_ascii_uppercase());
            last_was_slash = false;
        }
    }
    if out.ends_with('\\') && out.len() > 3 {
        out.pop();
    }
    out
}
fn parent_of(path: &str) -> &str {
    path.rsplit_once('\\').map(|(a, _)| a).unwrap_or("C:\\")
}
fn leaf_of(path: &str) -> &str {
    path.rsplit_once('\\').map(|(_, b)| b).unwrap_or(path)
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
            "C:\\",
            "C:\\INSTALL",
            DRIVER_ROOT,
            "C:\\SYSTEM",
            "C:\\SYSTEM\\TOML",
            "C:\\SYSTEM\\MOD",
        ] {
            let dk = norm_upcase(d);
            n.entry(dk.clone()).or_insert_with(Node::dir);
        }

        let reg_key = norm_upcase(REG_PATH);
        n.insert(reg_key.clone(), Node::file(DataRef::Ram(Vec::new())));
        n.get_mut(&norm_upcase("C:\\SYSTEM"))
            .unwrap()
            .children
            .insert("registry.bin".into(), reg_key);

        for bp in boot {
            let ddir = norm_upcase(&alloc::format!("{}\\{}", DRIVER_ROOT, bp.name));
            n.entry(ddir.clone()).or_insert_with(Node::dir);

            n.get_mut(&norm_upcase(DRIVER_ROOT))
                .unwrap()
                .children
                .insert(bp.name.clone().to_string(), ddir.clone());

            let toml_name = alloc::format!("{}.toml", bp.name);
            let dll_name = alloc::format!("{}.dll", bp.name);

            let toml_src = norm_upcase(&alloc::format!("{}\\{}", ddir, toml_name));
            let dll_src = norm_upcase(&alloc::format!("{}\\{}", ddir, dll_name));

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

            let toml_target = norm_upcase(&alloc::format!("C:\\SYSTEM\\TOML\\{}", toml_name));
            let dll_target = norm_upcase(&alloc::format!("C:\\SYSTEM\\MOD\\{}", dll_name));

            n.insert(toml_target.clone(), Node::file(DataRef::Alias(toml_src)));
            n.insert(dll_target.clone(), Node::file(DataRef::Alias(dll_src)));

            n.get_mut(&norm_upcase("C:\\SYSTEM\\TOML"))
                .unwrap()
                .children
                .insert(toml_name, toml_target);

            n.get_mut(&norm_upcase("C:\\SYSTEM\\MOD"))
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
}

impl<'a> FileProvider for BootstrapProvider<'a> {
    fn open_path(&self, path: &str, _flags: &[OpenFlags]) -> (FsOpenResult, DriverStatus) {
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

        let (exists, is_dir) = {
            let map = self.nodes.read();
            match map.get(&p) {
                Some(n) => (true, n.is_dir),
                None => (false, false),
            }
        };
        if !exists {
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

        let id = self.next_id.fetch_add(1, Ordering::AcqRel).max(1);
        self.handles.write().insert(id, p.clone());

        (
            FsOpenResult {
                fs_file_id: id,
                is_dir,
                size: self.size_of(&p) as u64,
                error: None,
            },
            DriverStatus::Success,
        )
    }

    fn close_handle(&self, file_id: u64) -> (FsCloseResult, DriverStatus) {
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

    fn read_at(&self, file_id: u64, offset: u64, len: u32) -> (FsReadResult, DriverStatus) {
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

    fn write_at(&self, file_id: u64, offset: u64, data: &[u8]) -> (FsWriteResult, DriverStatus) {
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
                    written: w as usize, // FsWriteResult expects usize
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

    fn flush_handle(&self, _file_id: u64) -> (FsFlushResult, DriverStatus) {
        (FsFlushResult { error: None }, DriverStatus::Success)
    }

    fn get_info(&self, file_id: u64) -> (FsGetInfoResult, DriverStatus) {
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

    // ---- Path ops ----

    fn list_dir_path(&self, path: &str) -> (FsListDirResult, DriverStatus) {
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

    fn make_dir_path(&self, path: &str) -> (FsCreateResult, DriverStatus) {
        let r = self.ensure_dir(path).err();
        (
            FsCreateResult {
                error: r.map(|e| e),
            },
            DriverStatus::Success,
        )
    }

    fn remove_dir_path(&self, _path: &str) -> (FsCreateResult, DriverStatus) {
        (
            FsCreateResult {
                error: Some(FileStatus::UnknownFail),
            },
            DriverStatus::Success,
        )
    }

    fn rename_path(&self, src: &str, dst: &str) -> (FsRenameResult, DriverStatus) {
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

    fn delete_path(&self, path: &str) -> (FsCreateResult, DriverStatus) {
        let p = match self.must_c(path) {
            Ok(p) => p,
            Err(e) => return (FsCreateResult { error: Some(e) }, DriverStatus::Success),
        };
        if norm_upcase(&p) == REG_PATH {
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
        (
            FsCreateResult {
                error: Some(FileStatus::UnknownFail),
            },
            DriverStatus::Success,
        )
    }

    fn open_path_async(
        &self,
        path: &str,
        flags: &[OpenFlags],
    ) -> Result<Arc<RwLock<crate::drivers::pnp::driver_object::Request>>, FileStatus> {
        todo!()
    }

    fn read_at_async(
        &self,
        file_id: u64,
        offset: u64,
        len: u32,
    ) -> Result<Arc<RwLock<crate::drivers::pnp::driver_object::Request>>, FileStatus> {
        todo!()
    }

    fn write_at_async(
        &self,
        file_id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<Arc<RwLock<crate::drivers::pnp::driver_object::Request>>, FileStatus> {
        todo!()
    }
}
