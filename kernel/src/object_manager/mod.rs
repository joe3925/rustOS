use alloc::{
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    any::Any,
    hash::{BuildHasherDefault, Hasher},
    sync::atomic::{AtomicU8, AtomicU64, Ordering},
};
use kernel_types::object_manager::ObjectTag;
use kernel_types::object_manager::OmError;

use hashbrown::HashMap;
use kernel_types::device::{DeviceObject, ModuleHandle};
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};

use crate::executable::program::{MessageQueue, ProgramHandle};
use crate::memory::io_buffer::MappedIoBufferBacking;
use crate::scheduling::task::TaskHandle;
use crate::structs::completion_queue::CompletionQueue;
use crate::structs::io_request::FileObject;

pub mod behavior;
pub use behavior::{
    AccessContext, AccessPolicy, CapabilityAccessPolicy, InterfaceMask, ObjectBehavior,
    ObjectOperation,
};

const OBJECT_ALIVE: u8 = 0;
const OBJECT_DEAD: u8 = 1;

pub type TaskQueueRef = Arc<RwLock<MessageQueue>>;
pub type ObjRef = Arc<dyn Any + Send + Sync>;

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
    pub target: Arc<Object>,
    pub exposed: InterfaceMask,
}

impl SymlinkBody {
    fn new(target: Arc<Object>, exposed: InterfaceMask) -> Self {
        Self { target, exposed }
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
    CompletionQueue(Arc<CompletionQueue>),
    File(Arc<FileObject>),
    Module(ModuleHandle),
    Device(Arc<DeviceObject>),
    IoBufferBacking(Arc<MappedIoBufferBacking>),
}

#[derive(Debug)]
pub struct Object {
    pub id: u64,
    pub tag: ObjectTag,
    pub name: RwLock<Option<Arc<str>>>,
    canonical_path: RwLock<Option<Arc<str>>>,
    pub payload: ObjectPayload,
    state: AtomicU8,
    symlinks: Mutex<Vec<Weak<Object>>>,
}

impl Object {
    #[inline]
    pub fn new(tag: ObjectTag, payload: ObjectPayload) -> Arc<Self> {
        let id = OBJECT_MANAGER.alloc_id();
        Arc::new(Self {
            id,
            tag,
            name: RwLock::new(None),
            canonical_path: RwLock::new(None),
            payload,
            state: AtomicU8::new(OBJECT_ALIVE),
            symlinks: Mutex::new(Vec::new()),
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
            canonical_path: RwLock::new(None),
            payload,
            state: AtomicU8::new(OBJECT_ALIVE),
            symlinks: Mutex::new(Vec::new()),
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
            canonical_path: RwLock::new(None),
            payload: ObjectPayload::Directory(DirectoryBody::new()),
            state: AtomicU8::new(OBJECT_ALIVE),
            symlinks: Mutex::new(Vec::new()),
        })
    }

    fn new_symlink_with_id(id: u64, target: SymlinkBody) -> Arc<Self> {
        Arc::new(Self {
            id,
            tag: ObjectTag::Symlink,
            name: RwLock::new(None),
            canonical_path: RwLock::new(None),
            payload: ObjectPayload::Symlink(target),
            state: AtomicU8::new(OBJECT_ALIVE),
            symlinks: Mutex::new(Vec::new()),
        })
    }

    fn new_generic_with_id(id: u64, obj: ObjRef) -> Arc<Self> {
        Arc::new(Self {
            id,
            tag: ObjectTag::Generic,
            name: RwLock::new(None),
            canonical_path: RwLock::new(None),
            payload: ObjectPayload::Generic(obj),
            state: AtomicU8::new(OBJECT_ALIVE),
            symlinks: Mutex::new(Vec::new()),
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

    #[inline]
    pub fn behavior(&self) -> &dyn ObjectBehavior {
        match &self.payload {
            ObjectPayload::Directory(body) => body,
            ObjectPayload::Symlink(body) => body,
            ObjectPayload::Generic(body) => body,
            ObjectPayload::Program(body) => body,
            ObjectPayload::Thread(body) => body,
            ObjectPayload::Queue(body) => body,
            ObjectPayload::CompletionQueue(body) => body,
            ObjectPayload::File(body) => body,
            ObjectPayload::Module(body) => body,
            ObjectPayload::Device(body) => body,
            ObjectPayload::IoBufferBacking(body) => body,
        }
    }

    pub async fn destroy(&self) -> crate::structs::io_request::IoRequestOutput {
        use crate::structs::io_request::{IO_STATUS_INVALID_PARAMETER, IoRequestOutput};

        match &self.payload {
            ObjectPayload::IoBufferBacking(_) => IoRequestOutput::success(0, 0),
            ObjectPayload::Queue(queue) => {
                queue.write().shutdown();
                IoRequestOutput::success(0, 0)
            }
            ObjectPayload::CompletionQueue(queue) => {
                queue.shutdown();
                IoRequestOutput::success(0, 0)
            }
            ObjectPayload::File(file) => {
                file.take().await.close();
                IoRequestOutput::success(0, 0)
            }
            ObjectPayload::Program(program) => {
                let pid = program.read().pid;
                match crate::executable::program::PROGRAM_MANAGER.kill_program(pid) {
                    Ok(()) => IoRequestOutput::success(0, 0),
                    Err(_) => IoRequestOutput::error(IO_STATUS_INVALID_PARAMETER),
                }
            }
            ObjectPayload::Thread(task) => {
                match crate::scheduling::scheduler::SCHEDULER.delete_task(task.task_id()) {
                    Ok(()) => IoRequestOutput::success(0, 0),
                    Err(_) => IoRequestOutput::error(IO_STATUS_INVALID_PARAMETER),
                }
            }
            ObjectPayload::Directory(_)
            | ObjectPayload::Symlink(_)
            | ObjectPayload::Generic(_)
            | ObjectPayload::Module(_)
            | ObjectPayload::Device(_) => IoRequestOutput::error(IO_STATUS_INVALID_PARAMETER),
        }
    }

    #[inline]
    pub fn is_alive(&self) -> bool {
        self.state.load(Ordering::Acquire) == OBJECT_ALIVE
    }

    #[inline]
    pub fn mark_dead(&self) {
        if self.state.swap(OBJECT_DEAD, Ordering::AcqRel) == OBJECT_DEAD {
            return;
        }
        let symlinks = core::mem::take(&mut *self.symlinks.lock());
        for symlink in symlinks {
            if let Some(symlink) = symlink.upgrade() {
                let _ = OBJECT_MANAGER.unlink_object(&symlink);
            }
        }
    }

    pub fn canonical_path(&self) -> Option<Arc<str>> {
        self.canonical_path.read().clone()
    }
}

macro_rules! impl_object_behavior {
    ($ty:ty, $tag:expr) => {
        impl ObjectBehavior for $ty {
            fn class(&self) -> ObjectTag {
                $tag
            }

            fn supported_interfaces(&self) -> InterfaceMask {
                behavior::standard_interfaces($tag)
            }

            fn required_interface(&self, operation: ObjectOperation) -> Option<InterfaceMask> {
                Some(behavior::interface_for_operation($tag, operation))
            }
        }
    };
}

impl ObjectBehavior for DirectoryBody {
    fn class(&self) -> ObjectTag {
        ObjectTag::Directory
    }
    fn supported_interfaces(&self) -> InterfaceMask {
        behavior::standard_interfaces(ObjectTag::Directory)
    }
    fn required_interface(&self, _: ObjectOperation) -> Option<InterfaceMask> {
        None
    }
}

impl ObjectBehavior for SymlinkBody {
    fn class(&self) -> ObjectTag {
        ObjectTag::Symlink
    }
    fn supported_interfaces(&self) -> InterfaceMask {
        behavior::standard_interfaces(ObjectTag::Symlink)
    }
    fn required_interface(&self, _: ObjectOperation) -> Option<InterfaceMask> {
        None
    }
}

impl_object_behavior!(ObjRef, ObjectTag::Generic);
impl_object_behavior!(ModuleHandle, ObjectTag::Module);
impl_object_behavior!(Arc<DeviceObject>, ObjectTag::Device);

impl ObjectBehavior for Arc<MappedIoBufferBacking> {
    fn class(&self) -> ObjectTag {
        ObjectTag::IoBufferBacking
    }

    fn supported_interfaces(&self) -> InterfaceMask {
        behavior::standard_interfaces(ObjectTag::IoBufferBacking)
    }

    fn required_interface(&self, operation: ObjectOperation) -> Option<InterfaceMask> {
        Some(behavior::interface_for_operation(
            ObjectTag::IoBufferBacking,
            operation,
        ))
    }
}

impl ObjectBehavior for TaskQueueRef {
    fn class(&self) -> ObjectTag {
        ObjectTag::Queue
    }
    fn supported_interfaces(&self) -> InterfaceMask {
        behavior::standard_interfaces(ObjectTag::Queue)
    }
    fn required_interface(&self, operation: ObjectOperation) -> Option<InterfaceMask> {
        Some(behavior::interface_for_operation(
            ObjectTag::Queue,
            operation,
        ))
    }
}

impl ObjectBehavior for Arc<CompletionQueue> {
    fn class(&self) -> ObjectTag {
        ObjectTag::CompletionQueue
    }
    fn supported_interfaces(&self) -> InterfaceMask {
        behavior::standard_interfaces(ObjectTag::CompletionQueue)
    }
    fn required_interface(&self, operation: ObjectOperation) -> Option<InterfaceMask> {
        Some(behavior::interface_for_operation(
            ObjectTag::CompletionQueue,
            operation,
        ))
    }
}

impl ObjectBehavior for Arc<FileObject> {
    fn class(&self) -> ObjectTag {
        ObjectTag::File
    }
    fn supported_interfaces(&self) -> InterfaceMask {
        behavior::standard_interfaces(ObjectTag::File)
    }
    fn required_interface(&self, operation: ObjectOperation) -> Option<InterfaceMask> {
        Some(behavior::interface_for_operation(
            ObjectTag::File,
            operation,
        ))
    }
}

impl ObjectBehavior for ProgramHandle {
    fn class(&self) -> ObjectTag {
        ObjectTag::Program
    }
    fn supported_interfaces(&self) -> InterfaceMask {
        behavior::standard_interfaces(ObjectTag::Program)
    }
    fn required_interface(&self, operation: ObjectOperation) -> Option<InterfaceMask> {
        Some(behavior::interface_for_operation(
            ObjectTag::Program,
            operation,
        ))
    }
}

impl ObjectBehavior for TaskHandle {
    fn class(&self) -> ObjectTag {
        ObjectTag::Thread
    }
    fn supported_interfaces(&self) -> InterfaceMask {
        behavior::standard_interfaces(ObjectTag::Thread)
    }
    fn required_interface(&self, operation: ObjectOperation) -> Option<InterfaceMask> {
        Some(behavior::interface_for_operation(
            ObjectTag::Thread,
            operation,
        ))
    }
}

pub struct ObjectManager {
    root: Arc<Object>,
    next_id: AtomicU64,
    id_index: RwLock<Vec<Option<Weak<Object>>>>,
    policy: Arc<dyn AccessPolicy>,
}

impl ObjectManager {
    pub fn new() -> Self {
        let root = Object::new_directory_with_id(1);
        let mut id_index: Vec<Option<Weak<Object>>> = Vec::new();
        id_index.resize(2, None);
        id_index[1] = Some(Arc::downgrade(&root));

        ObjectManager {
            root,
            next_id: AtomicU64::new(2),
            id_index: RwLock::new(id_index),
            policy: Arc::new(CapabilityAccessPolicy),
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
        idx[id] = Some(Arc::downgrade(obj));
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
        idx.get(id).and_then(|o| o.as_ref()?.upgrade())
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
        let path = path.as_ref();
        let (parent, leaf) = self.parent_and_leaf(path, true)?;
        let dir = Self::as_directory(&parent)?;

        let mut map = dir.children.write();
        let key = normalize_component(leaf.as_ref());
        if map.contains_key(key.as_str()) {
            return Err(OmError::AlreadyExists);
        }

        obj.set_name_arc(leaf.clone());
        *obj.canonical_path.write() = Some(Arc::<str>::from(path));
        map.insert(Arc::<str>::from(key.into_boxed_str()), obj.clone());
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
        let link_path = link_path.as_ref();
        let target = self.open(target)?;
        if matches!(
            target.payload,
            ObjectPayload::Directory(_) | ObjectPayload::Symlink(_)
        ) {
            return Err(OmError::Unsupported);
        }
        let exposed = target.behavior().supported_interfaces();
        self.symlink_object(link_path, target, exposed, auto_mkdir)
    }

    pub fn policy(&self) -> &dyn AccessPolicy {
        self.policy.as_ref()
    }

    pub fn symlink_object<P: AsRef<str>>(
        &self,
        link_path: P,
        target: Arc<Object>,
        exposed: InterfaceMask,
        auto_mkdir: bool,
    ) -> Result<Arc<Object>, OmError> {
        if matches!(
            target.payload,
            ObjectPayload::Directory(_) | ObjectPayload::Symlink(_)
        ) || !target.behavior().supported_interfaces().contains(exposed)
        {
            return Err(OmError::Unsupported);
        }
        let link_path = link_path.as_ref();
        let (parent, leaf) = self.parent_and_leaf(link_path, auto_mkdir)?;
        let node = self.insert_child_symlink(parent, leaf, target, exposed)?;
        *node.canonical_path.write() = Some(Arc::<str>::from(link_path));
        Ok(node)
    }

    pub fn namespace_entry<P: AsRef<str>>(&self, path: P) -> Result<Arc<Object>, OmError> {
        let (parent, leaf) = self.parent_and_leaf(path.as_ref(), false)?;
        let directory = Self::as_directory(&parent)?;
        let key = normalize_component(leaf.as_ref());
        directory
            .children
            .read()
            .get(key.as_str())
            .cloned()
            .ok_or(OmError::NotFound)
    }

    pub fn unlink<P: AsRef<str>>(&self, path: P) -> Result<(), OmError> {
        let (parent, leaf) = self.parent_and_leaf(path.as_ref(), false)?;
        let dir = Self::as_directory(&parent)?;

        let key = normalize_component(leaf.as_ref());
        let removed = dir.children.write().remove(key.as_str());
        let Some(removed) = removed else {
            return Err(OmError::NotFound);
        };

        self.unindex_tree(&removed);
        removed.canonical_path.write().take();
        Ok(())
    }

    pub fn ensure_standard_roots(&self) -> Result<(), OmError> {
        self.mkdir_p("\\Process")?;
        self.mkdir_p("\\Links\\Applications")?;
        self.mkdir_p("\\Links\\Services")?;
        self.mkdir_p("\\Links\\Devices")?;
        Ok(())
    }

    pub fn unlink_object(&self, object: &Arc<Object>) -> Result<(), OmError> {
        let path = object.canonical_path().ok_or(OmError::NotFound)?;
        self.unlink(path.as_ref())
    }

    pub fn retire_subtree<P: AsRef<str>>(&self, path: P) -> Result<(), OmError> {
        let object = self.open(path.as_ref())?;
        self.mark_tree_dead(&object);
        self.unlink(path)
    }

    fn mark_tree_dead(&self, object: &Arc<Object>) {
        if let ObjectPayload::Directory(directory) = &object.payload {
            let children: Vec<Arc<Object>> = directory.children.read().values().cloned().collect();
            for child in children {
                self.mark_tree_dead(&child);
            }
        } else {
            object.mark_dead();
        }
    }

    fn unindex_tree(&self, object: &Arc<Object>) {
        self.unindex_object(object.id);
        if let ObjectPayload::Directory(directory) = &object.payload {
            let children: Vec<Arc<Object>> = directory.children.read().values().cloned().collect();
            for child in children {
                self.unindex_tree(&child);
            }
        }
    }

    pub fn list<P: AsRef<str>>(&self, path: P) -> Result<Vec<String>, OmError> {
        let obj = self.open(path)?;
        let dir = Self::as_directory(&obj)?;
        let map = dir.children.read();

        let mut keys: Vec<Arc<str>> = Vec::with_capacity(map.len());
        for child in map.values() {
            if let Some(name) = child.name.read().as_ref() {
                keys.push(name.clone());
            }
        }
        keys.sort_unstable_by(|a, b| {
            a.to_ascii_lowercase()
                .cmp(&b.to_ascii_lowercase())
                .then_with(|| a.cmp(b))
        });

        let mut out: Vec<String> = Vec::with_capacity(keys.len());
        for k in keys {
            out.push(k.as_ref().to_string());
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

        let key = normalize_component(name);
        if let Some(existing) = map.get(key.as_str()) {
            if existing.tag == ObjectTag::Directory {
                return Ok(existing.clone());
            }
            return Err(OmError::AlreadyExists);
        }

        let child = Object::new_directory_with_id(self.alloc_id());
        let nm: Arc<str> = Arc::<str>::from(name);
        *child.name.write() = Some(nm.clone());
        map.insert(Arc::<str>::from(key.into_boxed_str()), child.clone());
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

        let key = normalize_component(name.as_ref());
        if map.contains_key(key.as_str()) {
            return Err(OmError::AlreadyExists);
        }

        let node = Object::new_generic_with_id(self.alloc_id(), obj);
        *node.name.write() = Some(name.clone());
        map.insert(Arc::<str>::from(key.into_boxed_str()), node.clone());
        drop(map);

        self.index_object(&node);
        Ok(node)
    }

    fn insert_child_symlink(
        &self,
        parent: Arc<Object>,
        name: Arc<str>,
        target: Arc<Object>,
        exposed: InterfaceMask,
    ) -> Result<Arc<Object>, OmError> {
        let dir = Self::as_directory(&parent)?;
        let mut map = dir.children.write();

        let key = normalize_component(name.as_ref());
        if map.contains_key(key.as_str()) {
            return Err(OmError::AlreadyExists);
        }

        let sl = SymlinkBody::new(target.clone(), exposed);
        let node = Object::new_symlink_with_id(self.alloc_id(), sl);
        *node.name.write() = Some(name.clone());
        map.insert(Arc::<str>::from(key.into_boxed_str()), node.clone());
        drop(map);

        target.symlinks.lock().push(Arc::downgrade(&node));
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
                let key = normalize_component(comps[idx]);
                map.get(key.as_str()).cloned()
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
                | ObjectTag::CompletionQueue
                | ObjectTag::File
                | ObjectTag::Module
                | ObjectTag::Device
                | ObjectTag::IoBufferBacking => {
                    if idx + 1 == comps.len() {
                        return Ok(next);
                    }
                    return Err(OmError::NotDirectory);
                }
                ObjectTag::Symlink => match &next.payload {
                    ObjectPayload::Symlink(s) if idx + 1 == comps.len() => {
                        return Ok(s.target.clone());
                    }
                    ObjectPayload::Symlink(_) => return Err(OmError::NotDirectory),
                    _ => unreachable!(),
                },
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
                let key = normalize_component(comps[idx].as_ref());
                map.get(key.as_str()).cloned()
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
                | ObjectTag::CompletionQueue
                | ObjectTag::File
                | ObjectTag::Module
                | ObjectTag::Device
                | ObjectTag::IoBufferBacking => {
                    if idx + 1 == comps.len() {
                        return Ok(next);
                    }
                    return Err(OmError::NotDirectory);
                }
                ObjectTag::Symlink => match &next.payload {
                    ObjectPayload::Symlink(s) if idx + 1 == comps.len() => {
                        return Ok(s.target.clone());
                    }
                    ObjectPayload::Symlink(_) => return Err(OmError::NotDirectory),
                    _ => unreachable!(),
                },
            }
        }

        Ok(cur)
    }
}

#[inline]
fn normalize_component(component: &str) -> String {
    component.to_ascii_lowercase()
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
