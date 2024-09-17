
use crate::println;

pub struct ListNode {
    pub(crate) size: usize,
    pub(crate) next: Option<&'static mut ListNode>,
}
impl ListNode {
    pub const fn new(size: usize) -> Self {
        ListNode { size, next: None }
    }

    pub fn start_addr(&self) -> usize {
        self as *const Self as usize
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


    pub fn printList(&mut self) {
        let mut current = &mut self.head;
        loop {
            // Print the size and the memory range (start to end) of each node
            println!(
                "Node size: {}, Start address: 0x{:x}, End address: 0x{:x}",
                current.size,
                current.start_addr(),
                current.end_addr()
            );

            // If the next node is None, break the loop
            if current.next.is_none() {
                break;
            }

            // Move to the next node
            current = current.next.as_mut().unwrap();
        }
    }


}
