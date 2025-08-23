// ───────────────────────── updated: object_manager.rs (ID allocation fix) ─────────────────────────
#![allow(dead_code)]

use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    any::Any,
    sync::atomic::{AtomicU64, Ordering},
};
use lazy_static::lazy_static;
use spin::RwLock;

// ---- external object types we want to host in the OM ----------------------
use crate::drivers::pnp::driver_object::DeviceObject;
use crate::executable::program::{MessageQueue, ModuleHandle, ProgramHandle};
use crate::scheduling::scheduler::TaskHandle;

pub type TaskQueueRef = Arc<RwLock<MessageQueue>>;
pub type ObjRef = Arc<dyn Any + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OmError {
    InvalidPath,
    NotFound,
    AlreadyExists,
    NotDirectory,
    IsDirectory,
    IsSymlink,
    LoopDetected,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectTag {
    Directory,
    Symlink,
    Generic,

    Program,
    Thread,
    Queue,
    Module,
    Device,
}

#[derive(Debug)]
pub struct DirectoryBody {
    pub children: RwLock<BTreeMap<String, Arc<Object>>>,
}
impl DirectoryBody {
    fn new() -> Self {
        Self {
            children: RwLock::new(BTreeMap::new()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SymlinkBody {
    pub target: String,
}
impl SymlinkBody {
    fn new(target: String) -> Self {
        Self { target }
    }
}

#[derive(Debug)]
pub enum ObjectPayload {
    Directory(DirectoryBody),
    Symlink(SymlinkBody),

    Generic(ObjRef),

    Program(ProgramHandle),
    Thread(TaskHandle),
    Queue(TaskQueueRef),
    Module(ModuleHandle),
    Device(Arc<DeviceObject>),
}

#[derive(Debug)]
pub struct Object {
    pub id: u64,
    pub tag: ObjectTag,
    pub name: RwLock<Option<String>>,
    pub payload: ObjectPayload,
}

impl Object {
    #[inline]
    pub fn new(tag: ObjectTag, payload: ObjectPayload) -> Arc<Self> {
        let id = OBJECT_MANAGER.alloc_id();
        Arc::new(Self {
            id,
            tag,
            name: RwLock::new(None),
            payload,
        })
    }

    #[inline]
    pub fn with_name(tag: ObjectTag, name: String, payload: ObjectPayload) -> Arc<Self> {
        let id = OBJECT_MANAGER.alloc_id();
        Arc::new(Self {
            id,
            tag,
            name: RwLock::new(Some(name)),
            payload,
        })
    }

    #[inline]
    pub fn set_name(&self, name: String) {
        *self.name.write() = Some(name);
    }
    #[inline]
    pub fn clear_name(&self) {
        *self.name.write() = None;
    }

    fn new_directory_with_id(id: u64) -> Arc<Self> {
        Arc::new(Self {
            id,
            tag: ObjectTag::Directory,
            name: RwLock::new(None),
            payload: ObjectPayload::Directory(DirectoryBody::new()),
        })
    }
    fn new_symlink_with_id(id: u64, target: String) -> Arc<Self> {
        Arc::new(Self {
            id,
            tag: ObjectTag::Symlink,
            name: RwLock::new(None),
            payload: ObjectPayload::Symlink(SymlinkBody::new(target)),
        })
    }
    fn new_generic_with_id(id: u64, obj: ObjRef) -> Arc<Self> {
        Arc::new(Self {
            id,
            tag: ObjectTag::Generic,
            name: RwLock::new(None),
            payload: ObjectPayload::Generic(obj),
        })
    }

    pub fn downcast_arc<T: Any + Send + Sync>(self: &Arc<Self>) -> Option<Arc<T>> {
        match &self.payload {
            ObjectPayload::Generic(inner) => {
                let cloned: Arc<dyn Any + Send + Sync> = inner.clone();
                cloned.downcast::<T>().ok()
            }
            _ => None,
        }
    }
}

pub struct ObjectManager {
    root: Arc<Object>,
    next_id: AtomicU64,
    id_index: RwLock<BTreeMap<u64, Arc<Object>>>,
}

lazy_static! {
    pub static ref OBJECT_MANAGER: ObjectManager = ObjectManager::new();
}

impl ObjectManager {
    pub fn new() -> Self {
        let root = Object::new_directory_with_id(1);
        let mut id_index = BTreeMap::new();
        id_index.insert(1, root.clone());
        ObjectManager {
            root,
            next_id: AtomicU64::new(2),
            id_index: RwLock::new(id_index),
        }
    }

    #[inline]
    fn alloc_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
    #[inline]
    fn index_object(&self, obj: &Arc<Object>) {
        self.id_index.write().insert(obj.id, obj.clone());
    }

    pub fn open(&self, path: String) -> Result<Arc<Object>, OmError> {
        let comps = Self::split_path(path)?;
        self.walk(&self.root, &comps, 16)
    }

    pub fn open_by_id(&self, id: u64) -> Option<Arc<Object>> {
        self.id_index.read().get(&id).cloned()
    }

    pub fn mkdirp(&self, path: String) -> Result<Arc<Object>, OmError> {
        let comps = Self::split_path(path)?;
        let mut cur = self.root.clone();
        for name in comps {
            cur = self.ensure_directory_child(&cur, name)?;
        }
        Ok(cur)
    }

    pub fn mkdir_p(&self, path: String) -> Result<Arc<Object>, OmError> {
        self.mkdirp(path)
    }

    pub fn link(&self, path: String, obj: &Arc<Object>) -> Result<(), OmError> {
        let (parent, leaf) = self.parent_and_leaf(path, true)?;
        let dir = Self::as_directory(&parent)?;
        let mut map = dir.children.write();
        if map.contains_key(&leaf) {
            return Err(OmError::AlreadyExists);
        }
        obj.set_name(leaf.clone());
        map.insert(leaf, obj.clone());
        self.index_object(obj);
        Ok(())
    }

    pub fn publish(
        &self,
        path: String,
        obj: ObjRef,
        auto_mkdir: bool,
    ) -> Result<Arc<Object>, OmError> {
        let (parent, leaf) = self.parent_and_leaf(path, auto_mkdir)?;
        self.insert_child_generic(parent, leaf, obj)
    }

    pub fn symlink(
        &self,
        link_path: String,
        target: String,
        auto_mkdir: bool,
    ) -> Result<Arc<Object>, OmError> {
        let (parent, leaf) = self.parent_and_leaf(link_path, auto_mkdir)?;
        self.insert_child_symlink(parent, leaf, target)
    }

    pub fn unlink(&self, path: String) -> Result<(), OmError> {
        let (parent, leaf) = self.parent_and_leaf(path, false)?;
        let dir = Self::as_directory(&parent)?;
        let mut map = dir.children.write();
        if map.remove(&leaf).is_none() {
            return Err(OmError::NotFound);
        }
        Ok(())
    }

    pub fn list(&self, path: String) -> Result<Vec<String>, OmError> {
        let obj = self.open(path)?;
        let dir = Self::as_directory(&obj)?;
        let names = {
            let map = dir.children.read();
            map.keys().cloned().collect::<Vec<String>>()
        };
        Ok(names)
    }

    // ---- helpers ----

    fn split_path(path: String) -> Result<Vec<String>, OmError> {
        if path.is_empty() {
            return Err(OmError::InvalidPath);
        }
        let normalized = path.replace('\\', "/");
        let trimmed = if normalized.starts_with('/') {
            &normalized[1..]
        } else {
            &normalized
        };
        let mut comps = Vec::new();
        for c in trimmed.split('/') {
            if c.is_empty() || c == "." {
                continue;
            }
            if c == ".." {
                return Err(OmError::Unsupported);
            }
            comps.push(c.to_string());
        }
        Ok(comps)
    }

    fn parent_and_leaf(
        &self,
        path: String,
        auto_mkdir: bool,
    ) -> Result<(Arc<Object>, String), OmError> {
        let mut comps = Self::split_path(path)?;
        if comps.is_empty() {
            return Err(OmError::InvalidPath);
        }
        let leaf = comps.pop().unwrap();

        let parent = if comps.is_empty() {
            self.root.clone()
        } else if auto_mkdir {
            let mut cur = self.root.clone();
            for name in comps {
                cur = self.ensure_directory_child(&cur, name)?;
            }
            cur
        } else {
            self.walk(&self.root, &comps, 16)?
        };
        Ok((parent, leaf))
    }

    fn ensure_directory_child(
        &self,
        dir_obj: &Arc<Object>,
        name: String,
    ) -> Result<Arc<Object>, OmError> {
        let dir = Self::as_directory(dir_obj)?;
        if let Some(existing) = dir.children.read().get(&name) {
            if existing.tag == ObjectTag::Directory {
                return Ok(existing.clone());
            }
            return Err(OmError::AlreadyExists);
        }
        let child = Object::new_directory_with_id(self.alloc_id());
        *child.name.write() = Some(name.clone());
        dir.children.write().insert(name, child.clone());
        self.index_object(&child);
        Ok(child)
    }

    fn insert_child_generic(
        &self,
        parent: Arc<Object>,
        name: String,
        obj: ObjRef,
    ) -> Result<Arc<Object>, OmError> {
        let dir = Self::as_directory(&parent)?;
        let mut map = dir.children.write();
        if map.contains_key(&name) {
            return Err(OmError::AlreadyExists);
        }
        let node = Object::new_generic_with_id(self.alloc_id(), obj);
        *node.name.write() = Some(name.clone());
        map.insert(name, node.clone());
        self.index_object(&node);
        Ok(node)
    }

    fn insert_child_symlink(
        &self,
        parent: Arc<Object>,
        name: String,
        target: String,
    ) -> Result<Arc<Object>, OmError> {
        let dir = Self::as_directory(&parent)?;
        let mut map = dir.children.write();
        if map.contains_key(&name) {
            return Err(OmError::AlreadyExists);
        }
        let node = Object::new_symlink_with_id(self.alloc_id(), target);
        *node.name.write() = Some(name.clone());
        map.insert(name, node.clone());
        self.index_object(&node);
        Ok(node)
    }

    fn as_directory(obj: &Arc<Object>) -> Result<&DirectoryBody, OmError> {
        match &obj.payload {
            ObjectPayload::Directory(d) => Ok(d),
            _ => Err(OmError::NotDirectory),
        }
    }

    fn walk(
        &self,
        start: &Arc<Object>,
        comps: &[String],
        mut budget: usize,
    ) -> Result<Arc<Object>, OmError> {
        let mut cur = start.clone();
        let mut idx = 0;

        while idx < comps.len() {
            if budget == 0 {
                return Err(OmError::LoopDetected);
            }
            budget -= 1;

            let name: &String = &comps[idx];
            let dir = Self::as_directory(&cur)?;
            let next = {
                let map = dir.children.read();
                map.get(name).cloned()
            }
            .ok_or(OmError::NotFound)?;

            match next.tag {
                ObjectTag::Directory => {
                    cur = next;
                    idx += 1;
                }
                ObjectTag::Generic
                | ObjectTag::Program
                | ObjectTag::Thread
                | ObjectTag::Queue
                | ObjectTag::Module
                | ObjectTag::Device => {
                    if idx + 1 == comps.len() {
                        return Ok(next);
                    }
                    return Err(OmError::NotDirectory);
                }
                ObjectTag::Symlink => {
                    let target = match &next.payload {
                        ObjectPayload::Symlink(s) => s.target.clone(),
                        _ => unreachable!(),
                    };
                    let target_abs = target.starts_with('/') || target.starts_with('\\');
                    if target_abs {
                        let mut new_comps = Self::split_path(target)?;
                        new_comps.extend_from_slice(&comps[idx + 1..]);
                        return self.walk(&self.root, &new_comps, budget);
                    } else {
                        let mut new_comps: Vec<String> = Vec::new();
                        new_comps.extend_from_slice(&comps[..idx]);
                        new_comps.extend(Self::split_path(target)?);
                        new_comps.extend_from_slice(&comps[idx + 1..]);
                        return self.walk(&self.root, &new_comps, budget);
                    }
                }
            }
        }
        Ok(cur)
    }
}
