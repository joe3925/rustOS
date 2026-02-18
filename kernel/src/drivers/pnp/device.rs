use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, Ordering};
use kernel_types::{
    device::{DevNode, DevNodeState, DeviceObject, DeviceStack},
    pnp::DeviceIds,
};
use spin::{Once, RwLock};

pub trait DevNodeExt {
    fn new_root() -> Arc<Self>;

    fn new_child(
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
        parent: &Arc<Self>,
    ) -> Arc<Self>;

    fn find_child_by_path(&self, path: &str) -> Option<Arc<Self>>;
    fn set_pdo(&self, pdo: Arc<DeviceObject>);
    fn get_pdo(&self) -> Option<Arc<DeviceObject>>;
    fn set_state(&self, s: DevNodeState);
    fn get_state(&self) -> DevNodeState;
}

impl DevNodeExt for DevNode {
    fn new_root() -> Arc<Self> {
        Arc::new(Self {
            name: "ROOT".into(),
            parent: Once::new(),
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

    fn new_child(
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
        parent: &Arc<Self>,
    ) -> Arc<Self> {
        let parent_once = Once::new();
        parent_once.call_once(|| Arc::downgrade(parent));

        let dn = Arc::new(Self {
            name,
            parent: parent_once,
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

    fn find_child_by_path(&self, path: &str) -> Option<Arc<Self>> {
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

    fn set_pdo(&self, pdo: Arc<DeviceObject>) {
        *self.pdo.write() = Some(pdo);
    }

    fn get_pdo(&self) -> Option<Arc<DeviceObject>> {
        self.pdo.read().clone()
    }

    fn set_state(&self, s: DevNodeState) {
        self.state.store(s as u8, Ordering::Release);
    }

    fn get_state(&self) -> DevNodeState {
        unsafe { core::mem::transmute(self.state.load(Ordering::Acquire) as u32) }
    }
}
