use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_types::arch::VirtAddr;
use spin::{Mutex, MutexGuard};

use crate::{
    memory::paging::{AddressSpaceRoot, current_address_space_root, switch_address_space_root},
    platform,
    structs::range_tracker::RangeTracker,
};

#[derive(Debug)]
struct PinNode {
    start: u64,
    end: u64,
    id: u64,
    height: u8,
    max_end: u64,
    left: Option<Box<PinNode>>,
    right: Option<Box<PinNode>>,
}

impl PinNode {
    fn new(start: u64, end: u64, id: u64) -> Self {
        Self {
            start,
            end,
            id,
            height: 1,
            max_end: end,
            left: None,
            right: None,
        }
    }

    fn key(&self) -> (u64, u64) {
        (self.start, self.id)
    }

    fn refresh(&mut self) {
        self.height = 1 + height(&self.left).max(height(&self.right));
        self.max_end = self.end.max(max_end(&self.left)).max(max_end(&self.right));
    }
}

fn height(node: &Option<Box<PinNode>>) -> u8 {
    node.as_ref().map_or(0, |node| node.height)
}

fn max_end(node: &Option<Box<PinNode>>) -> u64 {
    node.as_ref().map_or(0, |node| node.max_end)
}

fn rotate_left(mut root: Box<PinNode>) -> Box<PinNode> {
    let mut pivot = root.right.take().expect("AVL right child");
    root.right = pivot.left.take();
    root.refresh();
    pivot.left = Some(root);
    pivot.refresh();
    pivot
}

fn rotate_right(mut root: Box<PinNode>) -> Box<PinNode> {
    let mut pivot = root.left.take().expect("AVL left child");
    root.left = pivot.right.take();
    root.refresh();
    pivot.right = Some(root);
    pivot.refresh();
    pivot
}

fn rebalance(mut node: Box<PinNode>) -> Box<PinNode> {
    node.refresh();
    let balance = i16::from(height(&node.left)) - i16::from(height(&node.right));
    if balance > 1 {
        let left = node.left.as_ref().expect("left-heavy AVL node");
        if height(&left.right) > height(&left.left) {
            node.left = node.left.take().map(rotate_left);
        }
        return rotate_right(node);
    }
    if balance < -1 {
        let right = node.right.as_ref().expect("right-heavy AVL node");
        if height(&right.left) > height(&right.right) {
            node.right = node.right.take().map(rotate_right);
        }
        return rotate_left(node);
    }
    node
}

fn insert(root: Option<Box<PinNode>>, node: Box<PinNode>) -> Box<PinNode> {
    let Some(mut root) = root else {
        return node;
    };
    if node.key() < root.key() {
        root.left = Some(insert(root.left.take(), node));
    } else {
        root.right = Some(insert(root.right.take(), node));
    }
    rebalance(root)
}

fn take_min(mut root: Box<PinNode>) -> (Option<Box<PinNode>>, Box<PinNode>) {
    let Some(left) = root.left.take() else {
        let right = root.right.take();
        root.refresh();
        return (right, root);
    };
    let (new_left, minimum) = take_min(left);
    root.left = new_left;
    (Some(rebalance(root)), minimum)
}

fn remove(root: Option<Box<PinNode>>, key: (u64, u64)) -> Option<Box<PinNode>> {
    let mut root = root?;
    if key < root.key() {
        root.left = remove(root.left.take(), key);
        return Some(rebalance(root));
    }
    if key > root.key() {
        root.right = remove(root.right.take(), key);
        return Some(rebalance(root));
    }

    match (root.left.take(), root.right.take()) {
        (None, right) => right,
        (left, None) => left,
        (left, Some(right)) => {
            let (new_right, mut successor) = take_min(right);
            successor.left = left;
            successor.right = new_right;
            Some(rebalance(successor))
        }
    }
}

fn overlaps(root: &Option<Box<PinNode>>, start: u64, end: u64) -> bool {
    let Some(node) = root else {
        return false;
    };
    if node.left.as_ref().is_some_and(|left| left.max_end > start)
        && overlaps(&node.left, start, end)
    {
        return true;
    }
    if node.start < end && start < node.end {
        return true;
    }
    node.start < end && overlaps(&node.right, start, end)
}

#[derive(Debug)]
struct PinTree {
    root: Option<Box<PinNode>>,
    deferred_teardown: Option<DeferredTeardown>,
}

impl Default for PinTree {
    fn default() -> Self {
        Self {
            root: None,
            deferred_teardown: None,
        }
    }
}

#[derive(Debug)]
struct DeferredTeardown {
    root: AddressSpaceRoot,
    tracker: Arc<RangeTracker>,
}

impl PinTree {
    fn insert(&mut self, start: u64, end: u64, id: u64) -> Result<(), ()> {
        let node = Box::try_new(PinNode::new(start, end, id)).map_err(|_| ())?;
        self.root = Some(insert(self.root.take(), node));
        Ok(())
    }

    fn remove(&mut self, start: u64, id: u64) {
        self.root = remove(self.root.take(), (start, id));
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        overlaps(&self.root, start, end)
    }
}

#[derive(Debug, Default)]
pub struct UserMemoryPins {
    next_id: AtomicU64,
    tree: Mutex<PinTree>,
}

impl UserMemoryPins {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lock(self: &Arc<Self>) -> UserMemoryLock<'_> {
        UserMemoryLock {
            owner: self,
            tree: self.tree.lock(),
        }
    }

    /// Tears down immediately when there are no pins, otherwise transfers
    /// teardown ownership to the final `UserRangePin`.
    pub fn teardown_or_defer(&self, root: AddressSpaceRoot, tracker: Arc<RangeTracker>) {
        let mut tree = self.tree.lock();
        if tree.root.is_some() {
            debug_assert!(tree.deferred_teardown.is_none());
            tree.deferred_teardown = Some(DeferredTeardown { root, tracker });
            return;
        }
        drop(tree);
        teardown_user_mappings(root, &tracker);
    }
}

pub struct UserMemoryLock<'a> {
    owner: &'a Arc<UserMemoryPins>,
    tree: MutexGuard<'a, PinTree>,
}

impl UserMemoryLock<'_> {
    pub fn is_pinned(&self, start: u64, end: u64) -> bool {
        start < end && self.tree.overlaps(start, end)
    }

    pub fn pin(&mut self, start: u64, end: u64) -> Result<UserRangePin, ()> {
        debug_assert!(start < end);
        debug_assert!(self.tree.deferred_teardown.is_none());
        let id = self.owner.next_id.fetch_add(1, Ordering::Relaxed);
        self.tree.insert(start, end, id)?;
        Ok(UserRangePin {
            owner: self.owner.clone(),
            start,
            id,
        })
    }
}

#[derive(Debug)]
pub struct UserRangePin {
    owner: Arc<UserMemoryPins>,
    start: u64,
    id: u64,
}

impl Drop for UserRangePin {
    fn drop(&mut self) {
        let teardown = {
            let mut tree = self.owner.tree.lock();
            tree.remove(self.start, self.id);
            if tree.root.is_none() {
                tree.deferred_teardown.take()
            } else {
                None
            }
        };
        if let Some(teardown) = teardown {
            teardown_user_mappings(teardown.root, &teardown.tracker);
        }
    }
}

fn teardown_user_mappings(root: AddressSpaceRoot, tracker: &RangeTracker) {
    let old_root = current_address_space_root();
    platform::with_interrupts_disabled(|| unsafe {
        switch_address_space_root(root);
        for (start, size) in tracker.get_allocations() {
            crate::memory::paging::unmap_range_unchecked(VirtAddr::new(start).into(), size);
        }
        switch_address_space_root(old_root);
    });
}
