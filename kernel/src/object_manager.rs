#![allow(dead_code)]

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    any::Any,
    hash::{BuildHasherDefault, Hasher},
    sync::atomic::{AtomicU64, Ordering},
};

use hashbrown::HashMap;
use kernel_types::device::{DeviceObject, ModuleHandle};
use lazy_static::lazy_static;
use spin::RwLock;

use crate::executable::program::{MessageQueue, ProgramHandle};
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

#[derive(Default)]
struct Fnv1aHasher {
    state: u64,
}

impl Hasher for Fnv1aHasher {
    fn finish(&self) -> u64 {
        self.state
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut h = if self.state == 0 {
            0xcbf29ce484222325u64
        } else {
            self.state
        };

        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3u64);
        }

        self.state = h;
    }
}

type OmBuildHasher = BuildHasherDefault<Fnv1aHasher>;
type ChildMap = HashMap<Arc<str>, Arc<Object>, OmBuildHasher>;

#[derive(Debug)]
pub struct DirectoryBody {
    pub children: RwLock<ChildMap>,
}

impl DirectoryBody {
    fn new() -> Self {
        Self {
            children: RwLock::new(HashMap::with_hasher(OmBuildHasher::default())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SymlinkBody {
    pub target: Arc<str>,
    pub is_abs: bool,
    pub comps: Box<[Arc<str>]>,
}

impl SymlinkBody {
    fn new(target: String) -> Result<Self, OmError> {
        let t: Arc<str> = Arc::<str>::from(target.into_boxed_str());
        let is_abs = t.as_bytes().first().copied() == Some(b'/')
            || t.as_bytes().first().copied() == Some(b'\\');

        let borrowed = split_path_borrowed(&t)?;
        let mut comps: Vec<Arc<str>> = Vec::with_capacity(borrowed.len());
        for c in borrowed {
            comps.push(Arc::<str>::from(c));
        }

        Ok(Self {
            target: t,
            is_abs,
            comps: comps.into_boxed_slice(),
        })
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
    pub name: RwLock<Option<Arc<str>>>,
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
        let n: Arc<str> = Arc::<str>::from(name.into_boxed_str());
        Arc::new(Self {
            id,
            tag,
            name: RwLock::new(Some(n)),
            payload,
        })
    }

    #[inline]
    pub fn set_name(&self, name: String) {
        *self.name.write() = Some(Arc::<str>::from(name.into_boxed_str()));
    }

    #[inline]
    pub fn set_name_arc(&self, name: Arc<str>) {
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

    fn new_symlink_with_id(id: u64, target: SymlinkBody) -> Arc<Self> {
        Arc::new(Self {
            id,
            tag: ObjectTag::Symlink,
            name: RwLock::new(None),
            payload: ObjectPayload::Symlink(target),
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
    id_index: RwLock<Vec<Option<Arc<Object>>>>,
}

impl ObjectManager {
    pub fn new() -> Self {
        let root = Object::new_directory_with_id(1);
        let mut id_index: Vec<Option<Arc<Object>>> = Vec::new();
        id_index.resize(2, None);
        id_index[1] = Some(root.clone());

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
        let id = obj.id as usize;
        let mut idx = self.id_index.write();
        if id >= idx.len() {
            idx.resize(id + 1, None);
        }
        idx[id] = Some(obj.clone());
    }

    #[inline]
    fn unindex_object(&self, id: u64) {
        let id = id as usize;
        let mut idx = self.id_index.write();
        if id < idx.len() {
            idx[id] = None;
        }
    }

    pub fn open<P: AsRef<str>>(&self, path: P) -> Result<Arc<Object>, OmError> {
        let comps = split_path_borrowed(path.as_ref())?;
        self.walk_borrowed(&self.root, &comps, 16)
    }

    pub fn open_by_id(&self, id: u64) -> Option<Arc<Object>> {
        let id = id as usize;
        let idx = self.id_index.read();
        idx.get(id).and_then(|o| o.as_ref().cloned())
    }

    pub fn mkdirp<P: AsRef<str>>(&self, path: P) -> Result<Arc<Object>, OmError> {
        let comps = split_path_borrowed(path.as_ref())?;
        let mut cur = self.root.clone();
        for name in comps {
            cur = self.ensure_directory_child(&cur, name)?;
        }
        Ok(cur)
    }

    pub fn mkdir_p<P: AsRef<str>>(&self, path: P) -> Result<Arc<Object>, OmError> {
        self.mkdirp(path)
    }

    pub fn link<P: AsRef<str>>(&self, path: P, obj: &Arc<Object>) -> Result<(), OmError> {
        let (parent, leaf) = self.parent_and_leaf(path.as_ref(), true)?;
        let dir = Self::as_directory(&parent)?;

        let mut map = dir.children.write();
        if map.contains_key(leaf.as_ref()) {
            return Err(OmError::AlreadyExists);
        }

        obj.set_name_arc(leaf.clone());
        map.insert(leaf, obj.clone());
        drop(map);

        self.index_object(obj);
        Ok(())
    }

    pub fn publish<P: AsRef<str>>(
        &self,
        path: P,
        obj: ObjRef,
        auto_mkdir: bool,
    ) -> Result<Arc<Object>, OmError> {
        let (parent, leaf) = self.parent_and_leaf(path.as_ref(), auto_mkdir)?;
        self.insert_child_generic(parent, leaf, obj)
    }

    pub fn symlink<P: AsRef<str>>(
        &self,
        link_path: P,
        target: String,
        auto_mkdir: bool,
    ) -> Result<Arc<Object>, OmError> {
        let (parent, leaf) = self.parent_and_leaf(link_path.as_ref(), auto_mkdir)?;
        self.insert_child_symlink(parent, leaf, target)
    }

    pub fn unlink<P: AsRef<str>>(&self, path: P) -> Result<(), OmError> {
        let (parent, leaf) = self.parent_and_leaf(path.as_ref(), false)?;
        let dir = Self::as_directory(&parent)?;

        let removed = dir.children.write().remove(leaf.as_ref());
        let Some(removed) = removed else {
            return Err(OmError::NotFound);
        };

        self.unindex_object(removed.id);
        Ok(())
    }

    pub fn list<P: AsRef<str>>(&self, path: P) -> Result<Vec<String>, OmError> {
        let obj = self.open(path)?;
        let dir = Self::as_directory(&obj)?;
        let map = dir.children.read();

        let mut keys: Vec<&str> = Vec::with_capacity(map.len());
        for k in map.keys() {
            keys.push(k.as_ref());
        }
        keys.sort_unstable();

        let mut out: Vec<String> = Vec::with_capacity(keys.len());
        for k in keys {
            out.push(k.to_string());
        }
        Ok(out)
    }

    fn parent_and_leaf(
        &self,
        path: &str,
        auto_mkdir: bool,
    ) -> Result<(Arc<Object>, Arc<str>), OmError> {
        let mut comps = split_path_borrowed(path)?;
        if comps.is_empty() {
            return Err(OmError::InvalidPath);
        }

        let leaf_str = comps.pop().unwrap();
        let leaf: Arc<str> = Arc::<str>::from(leaf_str);

        let parent = if comps.is_empty() {
            self.root.clone()
        } else if auto_mkdir {
            let mut cur = self.root.clone();
            for name in comps {
                cur = self.ensure_directory_child(&cur, name)?;
            }
            cur
        } else {
            self.walk_borrowed(&self.root, &comps, 16)?
        };

        Ok((parent, leaf))
    }

    fn ensure_directory_child(
        &self,
        dir_obj: &Arc<Object>,
        name: &str,
    ) -> Result<Arc<Object>, OmError> {
        let dir = Self::as_directory(dir_obj)?;

        let mut map = dir.children.write();

        if let Some(existing) = map.get(name) {
            if existing.tag == ObjectTag::Directory {
                return Ok(existing.clone());
            }
            return Err(OmError::AlreadyExists);
        }

        let child = Object::new_directory_with_id(self.alloc_id());
        let nm: Arc<str> = Arc::<str>::from(name);
        *child.name.write() = Some(nm.clone());
        map.insert(nm, child.clone());
        drop(map);

        self.index_object(&child);
        Ok(child)
    }

    fn insert_child_generic(
        &self,
        parent: Arc<Object>,
        name: Arc<str>,
        obj: ObjRef,
    ) -> Result<Arc<Object>, OmError> {
        let dir = Self::as_directory(&parent)?;
        let mut map = dir.children.write();

        if map.contains_key(name.as_ref()) {
            return Err(OmError::AlreadyExists);
        }

        let node = Object::new_generic_with_id(self.alloc_id(), obj);
        *node.name.write() = Some(name.clone());
        map.insert(name, node.clone());
        drop(map);

        self.index_object(&node);
        Ok(node)
    }

    fn insert_child_symlink(
        &self,
        parent: Arc<Object>,
        name: Arc<str>,
        target: String,
    ) -> Result<Arc<Object>, OmError> {
        let dir = Self::as_directory(&parent)?;
        let mut map = dir.children.write();

        if map.contains_key(name.as_ref()) {
            return Err(OmError::AlreadyExists);
        }

        let sl = SymlinkBody::new(target)?;
        let node = Object::new_symlink_with_id(self.alloc_id(), sl);
        *node.name.write() = Some(name.clone());
        map.insert(name, node.clone());
        drop(map);

        self.index_object(&node);
        Ok(node)
    }

    fn as_directory(obj: &Arc<Object>) -> Result<&DirectoryBody, OmError> {
        match &obj.payload {
            ObjectPayload::Directory(d) => Ok(d),
            _ => Err(OmError::NotDirectory),
        }
    }

    fn walk_borrowed(
        &self,
        start: &Arc<Object>,
        comps: &[&str],
        mut budget: usize,
    ) -> Result<Arc<Object>, OmError> {
        let mut cur = start.clone();
        let mut idx = 0usize;

        while idx < comps.len() {
            if budget == 0 {
                return Err(OmError::LoopDetected);
            }
            budget -= 1;

            let dir = Self::as_directory(&cur)?;
            let next = {
                let map = dir.children.read();
                map.get(comps[idx]).cloned()
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
                    let (is_abs, target_comps) = match &next.payload {
                        ObjectPayload::Symlink(s) => (s.is_abs, &s.comps),
                        _ => unreachable!(),
                    };

                    let prefix_len = if is_abs { 0 } else { idx };
                    let suffix = &comps[idx + 1..];

                    let mut new_comps: Vec<Arc<str>> =
                        Vec::with_capacity(prefix_len + target_comps.len() + suffix.len());

                    if !is_abs {
                        for &c in &comps[..idx] {
                            new_comps.push(Arc::<str>::from(c));
                        }
                    }

                    for c in target_comps.iter() {
                        new_comps.push(c.clone());
                    }

                    for &c in suffix {
                        new_comps.push(Arc::<str>::from(c));
                    }

                    return self.walk_owned(&self.root, &new_comps, budget);
                }
            }
        }

        Ok(cur)
    }

    fn walk_owned(
        &self,
        start: &Arc<Object>,
        comps: &[Arc<str>],
        mut budget: usize,
    ) -> Result<Arc<Object>, OmError> {
        let mut cur = start.clone();
        let mut idx = 0usize;

        while idx < comps.len() {
            if budget == 0 {
                return Err(OmError::LoopDetected);
            }
            budget -= 1;

            let dir = Self::as_directory(&cur)?;
            let next = {
                let map = dir.children.read();
                map.get(comps[idx].as_ref()).cloned()
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
                    let (is_abs, target_comps) = match &next.payload {
                        ObjectPayload::Symlink(s) => (s.is_abs, &s.comps),
                        _ => unreachable!(),
                    };

                    let suffix = &comps[idx + 1..];

                    let mut new_comps: Vec<Arc<str>> = Vec::with_capacity(
                        (if is_abs { 0 } else { idx }) + target_comps.len() + suffix.len(),
                    );

                    if !is_abs {
                        for c in &comps[..idx] {
                            new_comps.push(c.clone());
                        }
                    }

                    for c in target_comps.iter() {
                        new_comps.push(c.clone());
                    }

                    for c in suffix {
                        new_comps.push(c.clone());
                    }

                    return self.walk_owned(&self.root, &new_comps, budget);
                }
            }
        }

        Ok(cur)
    }
}

fn split_path_borrowed<'a>(path: &'a str) -> Result<Vec<&'a str>, OmError> {
    if path.is_empty() {
        return Err(OmError::InvalidPath);
    }

    let b = path.as_bytes();
    let mut i = 0usize;

    if b[0] == b'/' || b[0] == b'\\' {
        i = 1;
    }

    let mut comps: Vec<&'a str> = Vec::new();

    while i < b.len() {
        while i < b.len() && (b[i] == b'/' || b[i] == b'\\') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }

        let start = i;
        while i < b.len() && b[i] != b'/' && b[i] != b'\\' {
            i += 1;
        }
        let part = &path[start..i];

        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(OmError::Unsupported);
        }

        comps.push(part);
    }

    Ok(comps)
}

lazy_static! {
    pub static ref OBJECT_MANAGER: ObjectManager = ObjectManager::new();
}
