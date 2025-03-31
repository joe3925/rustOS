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

    pub fn count_nodes(&self) -> usize {
        let mut count = 0;
        let mut current = &self.head;

        while let Some(ref next_node) = current.next {
            count += 1;
            current = next_node;
        }

        count
    }
    pub fn get_last(&mut self) -> &mut ListNode {
        let mut current = &mut self.head;
        loop {
            if current.next.is_none() {
                return current;
            }

            current = current.next.as_mut().unwrap();
        }
    }

    pub fn print_list(&mut self) {
        let mut current = &mut self.head;
        loop {
            println!(
                "Node size: {}, Start address: 0x{:x}, End address: 0x{:x}",
                current.size,
                current.start_addr(),
                current.end_addr()
            );

            if current.next.is_none() {
                break;
            }

            current = current.next.as_mut().unwrap();
        }
    }
}
