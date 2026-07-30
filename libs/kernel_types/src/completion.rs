use core::num::NonZeroUsize;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TaskToken(NonZeroUsize);

impl TaskToken {
    #[inline]
    pub const fn from_raw(raw: usize) -> Option<Self> {
        match NonZeroUsize::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    #[inline]
    pub const fn raw(self) -> usize {
        self.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskOutcome<T> {
    Completed(T),
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskCompletion<T> {
    pub task: TaskToken,
    pub key: u64,
    pub outcome: TaskOutcome<T>,
}

pub trait CompletionPermit<T>: Send + 'static {
    fn complete(self, completion: TaskCompletion<T>);
}
