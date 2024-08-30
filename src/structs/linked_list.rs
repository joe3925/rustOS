use alloc::boxed::Box;
use core::alloc::Layout;
use core::mem;
use x86_64::VirtAddr;
use crate::memory::heap::{HEAP_SIZE, HEAP_START};
use crate::println;

pub struct ListNode {
    pub(crate) size: usize,
    pub(crate) next: Option<&'static mut ListNode>,
}
impl ListNode {
    pub const fn new(size: usize) -> Self {
        ListNode { size, next: None }
    }
    pub const fn newHead(size: usize, next: Option<&'static mut ListNode>) -> Self {
        ListNode { size, next: next }
    }

    pub fn start_addr(&self) -> usize {
        self as *const Self as usize
    }
    pub fn mut_start_addr(&mut self) -> usize {
        self as *const Self as usize
    }
    pub fn mut_end_addr(&mut self) -> usize {
        self.mut_start_addr() + self.size
    }

    pub fn end_addr(&self) -> usize {
        self.start_addr() + self.size
    }
}

pub struct LinkedList {
    pub(crate) head: ListNode,
}

impl LinkedList {
    pub const fn new() -> Self {
        LinkedList {
            head: ListNode::new(0),
        }
    }


    pub fn get_tail(&mut self) -> &mut ListNode {
        let mut current = &mut self.head;
        loop {
            if current.next.is_none() {
                return current;
            }
            current = current.next.as_mut().unwrap();
        }
    }
    pub fn printList(&mut self){
        let mut current = &mut self.head;
        loop {
            println!("{}",current.size);
            if current.next.is_none() {
                break;
            }

            current = current.next.as_mut().unwrap();
        }
    }


}
