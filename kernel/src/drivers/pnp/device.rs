use crate::drivers::pnp::driver_object::DeviceObject;
use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, Ordering};
use spin::RwLock;

#[derive(Debug, Clone)]
pub struct DeviceIds {
    pub hardware: Vec<String>,
    pub compatible: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevNodeState {
    Empty,
    Initialized,
    DriversBound,
    Started,
    Stopped,
    SurpriseRemoved,
    Deleted,
    Faulted,
}

#[derive(Debug, Clone)]
pub struct StackLayer {
    pub driver: Arc<crate::drivers::pnp::driver_object::DriverObject>,
    pub devobj: Option<Arc<DeviceObject>>,
}

#[derive(Debug)]
pub struct DeviceStack {
    pub pdo_bus_service: Option<String>,
    pub lower: Vec<StackLayer>,
    pub function: Option<StackLayer>,
    pub upper: Vec<StackLayer>,
}

impl DeviceStack {
    pub fn new() -> Self {
        Self {
            pdo_bus_service: None,
            lower: Vec::new(),
            function: None,
            upper: Vec::new(),
        }
    }
    pub fn get_top_device_object(&self) -> Option<Arc<DeviceObject>> {
        self.upper
            .last()
            .and_then(|l| l.devobj.clone())
            .or_else(|| self.function.as_ref().and_then(|l| l.devobj.clone()))
            .or_else(|| self.lower.last().and_then(|l| l.devobj.clone()))
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct DevNode {
    pub name: String,
    pub parent: RwLock<Option<alloc::sync::Weak<DevNode>>>,
    pub children: RwLock<Vec<Arc<DevNode>>>,
    pub instance_path: String,
    pub ids: DeviceIds,
    pub class: Option<String>,
    pub state: AtomicU8,
    pub pdo: RwLock<Option<Arc<DeviceObject>>>,
    pub stack: RwLock<Option<DeviceStack>>,
}

impl DevNode {
    pub fn new_root() -> Arc<Self> {
        Arc::new(Self {
            name: "ROOT".into(),
            parent: RwLock::new(None),
            children: RwLock::new(Vec::new()),
            instance_path: "ROOT".into(),
            ids: DeviceIds {
                hardware: Vec::new(),
                compatible: Vec::new(),
            },
            class: None,
            state: AtomicU8::new(DevNodeState::Initialized as u8),
            pdo: RwLock::new(None),
            stack: RwLock::new(Some(DeviceStack::new())),
        })
    }

    pub fn new_child(
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
        parent: &Arc<DevNode>,
    ) -> Arc<Self> {
        let dn = Arc::new(Self {
            name,
            parent: RwLock::new(Some(Arc::downgrade(parent))),
            children: RwLock::new(Vec::new()),
            instance_path,
            ids,
            class,
            state: AtomicU8::new(DevNodeState::Initialized as u8),
            pdo: RwLock::new(None),
            stack: RwLock::new(Some(DeviceStack::new())),
        });
        parent.children.write().push(dn.clone());
        dn
    }

    pub fn find_child_by_path(&self, path: &str) -> Option<Arc<DevNode>> {
        for child in self.children.read().iter() {
            if child.instance_path == path {
                return Some(child.clone());
            }
            if let Some(found) = child.find_child_by_path(path) {
                return Some(found);
            }
        }
        None
    }

    pub fn set_pdo(&self, pdo: Arc<DeviceObject>) {
        *self.pdo.write() = Some(pdo);
    }
    pub fn get_pdo(&self) -> Option<Arc<DeviceObject>> {
        self.pdo.read().clone()
    }
    pub fn set_state(&self, s: DevNodeState) {
        self.state.store(s as u8, Ordering::Release);
    }
    pub fn get_state(&self) -> DevNodeState {
        unsafe { core::mem::transmute(self.state.load(Ordering::Acquire)) }
    }
}
