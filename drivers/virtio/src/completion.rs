use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU16, Ordering};
use core::task::{Context, Poll, Waker};

use spin::Mutex;

pub const MAX_COMPLETION_SLOTS: usize = 1024;

const INVALID_INDEX: u16 = u16::MAX;

const PHASE_FREE: u8 = 0;
const PHASE_ALLOCATED: u8 = 1;
const PHASE_WAITING: u8 = 2;
const PHASE_COMPLETE: u8 = 3;
const PHASE_CANCELED: u8 = 4;
const PHASE_ABANDONED: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionError {
    Canceled,
}

struct CompletionHeadSlot {
    cell: Mutex<Option<u16>>,
}

impl CompletionHeadSlot {
    pub const fn new() -> Self {
        Self {
            cell: Mutex::new(None),
        }
    }

    fn put(&self, cell_idx: u16) {
        let mut guard = self.cell.lock();
        if guard.is_some() {
            panic!("virtio: completion head slot already occupied");
        }
        *guard = Some(cell_idx);
    }

    fn take(&self) -> Option<u16> {
        self.cell.lock().take()
    }
}

struct CompletionCellState {
    generation: u32,
    phase: u8,
    status: u8,
    waker: Option<Waker>,
}

impl CompletionCellState {
    pub const fn new() -> Self {
        Self {
            generation: 0,
            phase: PHASE_FREE,
            status: 0xFF,
            waker: None,
        }
    }
}

struct CompletionCell {
    state: Mutex<CompletionCellState>,
    next_free: AtomicU16,
}

impl CompletionCell {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(CompletionCellState::new()),
            next_free: AtomicU16::new(INVALID_INDEX),
        }
    }

    fn prepare_allocated(&self) -> u32 {
        let mut state = self.state.lock();
        if state.phase != PHASE_FREE {
            panic!("virtio: allocated completion cell was not free");
        }

        state.generation = state.generation.wrapping_add(1).max(1);
        state.phase = PHASE_ALLOCATED;
        state.status = 0xFF;
        state.waker = None;
        state.generation
    }
}

struct CompletionFreeList {
    head: u16,
    count: u16,
}

pub struct CompletionTable {
    heads: [CompletionHeadSlot; MAX_COMPLETION_SLOTS],
    cells: [CompletionCell; MAX_COMPLETION_SLOTS],
    free: Mutex<CompletionFreeList>,
    len: usize,
}

unsafe impl Send for CompletionTable {}
unsafe impl Sync for CompletionTable {}

impl CompletionTable {
    pub fn new(len: usize) -> Option<Self> {
        if len == 0 || len > MAX_COMPLETION_SLOTS {
            return None;
        }

        let table = Self {
            heads: [const { CompletionHeadSlot::new() }; MAX_COMPLETION_SLOTS],
            cells: [const { CompletionCell::new() }; MAX_COMPLETION_SLOTS],
            free: Mutex::new(CompletionFreeList {
                head: 0,
                count: len as u16,
            }),
            len,
        };

        for idx in 0..len {
            let next = if idx + 1 < len {
                (idx + 1) as u16
            } else {
                INVALID_INDEX
            };
            table.cells[idx].next_free.store(next, Ordering::Relaxed);
        }

        Some(table)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn alloc(&self) -> Option<CompletionToken<'_>> {
        let cell_idx = {
            let mut free = self.free.lock();
            if free.head == INVALID_INDEX {
                return None;
            }

            let idx = free.head;
            free.head = self.cells[idx as usize].next_free.load(Ordering::Relaxed);
            free.count = free.count.saturating_sub(1);
            idx
        };

        let generation = self.cells[cell_idx as usize].prepare_allocated();
        Some(CompletionToken {
            table: self,
            cell_idx,
            generation,
            active: true,
        })
    }

    pub fn attach(&self, head: u16, token: &CompletionToken<'_>) {
        if !core::ptr::eq(token.table, self) {
            panic!("virtio: completion token attached to the wrong table");
        }
        if head as usize >= self.len {
            panic!("virtio: completion head index outside table");
        }

        {
            let mut state = self.cells[token.cell_idx as usize].state.lock();
            if state.generation != token.generation || state.phase != PHASE_ALLOCATED {
                panic!("virtio: completion token was not attachable");
            }
            state.phase = PHASE_WAITING;
        }

        self.heads[head as usize].put(token.cell_idx);
    }

    pub fn complete_head(&self, head: u16, status: u8) -> bool {
        if head as usize >= self.len {
            return false;
        }

        let Some(cell_idx) = self.heads[head as usize].take() else {
            return false;
        };

        self.complete_cell(cell_idx, status);
        true
    }

    pub fn cancel_all(&self) {
        for head in 0..self.len {
            if let Some(cell_idx) = self.heads[head].take() {
                self.cancel_cell(cell_idx);
            }
        }
    }

    fn complete_cell(&self, cell_idx: u16, status: u8) {
        let mut wake = None;
        let mut should_free = false;

        {
            let cell = &self.cells[cell_idx as usize];
            let mut state = cell.state.lock();
            match state.phase {
                PHASE_WAITING => {
                    state.status = status;
                    state.phase = PHASE_COMPLETE;
                    wake = state.waker.take();
                }
                PHASE_ABANDONED => {
                    state.status = 0xFF;
                    state.phase = PHASE_FREE;
                    state.waker = None;
                    should_free = true;
                }
                _ => panic!("virtio: completion cell finished in invalid state"),
            }
        }

        if should_free {
            self.push_free(cell_idx);
        }
        if let Some(waker) = wake {
            waker.wake();
        }
    }

    fn cancel_cell(&self, cell_idx: u16) {
        let mut wake = None;
        let mut should_free = false;

        {
            let cell = &self.cells[cell_idx as usize];
            let mut state = cell.state.lock();
            match state.phase {
                PHASE_WAITING => {
                    state.phase = PHASE_CANCELED;
                    wake = state.waker.take();
                }
                PHASE_ABANDONED => {
                    state.phase = PHASE_FREE;
                    state.waker = None;
                    should_free = true;
                }
                PHASE_COMPLETE | PHASE_CANCELED => {}
                _ => {}
            }
        }

        if should_free {
            self.push_free(cell_idx);
        }
        if let Some(waker) = wake {
            waker.wake();
        }
    }

    fn poll_token(
        &self,
        cell_idx: u16,
        generation: u32,
        cx: &Context<'_>,
    ) -> Poll<Result<u8, CompletionError>> {
        let mut ready = None;

        {
            let cell = &self.cells[cell_idx as usize];
            let mut state = cell.state.lock();
            if state.generation != generation {
                return Poll::Ready(Err(CompletionError::Canceled));
            }

            match state.phase {
                PHASE_COMPLETE => {
                    ready = Some(Ok(state.status));
                    state.status = 0xFF;
                    state.phase = PHASE_FREE;
                    state.waker = None;
                }
                PHASE_CANCELED => {
                    ready = Some(Err(CompletionError::Canceled));
                    state.status = 0xFF;
                    state.phase = PHASE_FREE;
                    state.waker = None;
                }
                PHASE_WAITING => {
                    let replace = match state.waker.as_ref() {
                        Some(existing) => !existing.will_wake(cx.waker()),
                        None => true,
                    };
                    if replace {
                        state.waker = Some(cx.waker().clone());
                    }
                }
                PHASE_ALLOCATED => {}
                _ => return Poll::Ready(Err(CompletionError::Canceled)),
            }
        }

        if let Some(result) = ready {
            self.push_free(cell_idx);
            Poll::Ready(result)
        } else {
            Poll::Pending
        }
    }

    fn try_recv_token(
        &self,
        cell_idx: u16,
        generation: u32,
    ) -> Result<Option<u8>, CompletionError> {
        let mut ready = None;

        {
            let cell = &self.cells[cell_idx as usize];
            let mut state = cell.state.lock();
            if state.generation != generation {
                return Err(CompletionError::Canceled);
            }

            match state.phase {
                PHASE_COMPLETE => {
                    ready = Some(Ok(state.status));
                    state.status = 0xFF;
                    state.phase = PHASE_FREE;
                    state.waker = None;
                }
                PHASE_CANCELED => {
                    ready = Some(Err(CompletionError::Canceled));
                    state.status = 0xFF;
                    state.phase = PHASE_FREE;
                    state.waker = None;
                }
                PHASE_WAITING | PHASE_ALLOCATED => {}
                _ => return Err(CompletionError::Canceled),
            }
        }

        match ready {
            Some(Ok(status)) => {
                self.push_free(cell_idx);
                Ok(Some(status))
            }
            Some(Err(err)) => {
                self.push_free(cell_idx);
                Err(err)
            }
            None => Ok(None),
        }
    }

    fn drop_token(&self, cell_idx: u16, generation: u32) {
        let mut should_free = false;

        {
            let cell = &self.cells[cell_idx as usize];
            let mut state = cell.state.lock();
            if state.generation != generation {
                return;
            }

            match state.phase {
                PHASE_ALLOCATED | PHASE_COMPLETE | PHASE_CANCELED => {
                    state.status = 0xFF;
                    state.phase = PHASE_FREE;
                    state.waker = None;
                    should_free = true;
                }
                PHASE_WAITING => {
                    state.phase = PHASE_ABANDONED;
                    state.waker = None;
                }
                _ => {}
            }
        }

        if should_free {
            self.push_free(cell_idx);
        }
    }

    fn push_free(&self, cell_idx: u16) {
        let mut free = self.free.lock();
        self.cells[cell_idx as usize]
            .next_free
            .store(free.head, Ordering::Relaxed);
        free.head = cell_idx;
        free.count = free.count.saturating_add(1);
        if free.count as usize > self.len {
            panic!("virtio: completion cell double-free");
        }
    }
}

pub struct CompletionToken<'a> {
    table: &'a CompletionTable,
    cell_idx: u16,
    generation: u32,
    active: bool,
}

impl CompletionToken<'_> {
    pub fn try_recv(&mut self) -> Result<Option<u8>, CompletionError> {
        if !self.active {
            return Err(CompletionError::Canceled);
        }

        match self.table.try_recv_token(self.cell_idx, self.generation) {
            Ok(Some(status)) => {
                self.active = false;
                Ok(Some(status))
            }
            Err(err) => {
                self.active = false;
                Err(err)
            }
            Ok(None) => Ok(None),
        }
    }
}

impl Future for CompletionToken<'_> {
    type Output = Result<u8, CompletionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.active {
            return Poll::Ready(Err(CompletionError::Canceled));
        }

        match self.table.poll_token(self.cell_idx, self.generation, cx) {
            Poll::Ready(result) => {
                self.active = false;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for CompletionToken<'_> {
    fn drop(&mut self) {
        if self.active {
            self.table.drop_token(self.cell_idx, self.generation);
            self.active = false;
        }
    }
}
