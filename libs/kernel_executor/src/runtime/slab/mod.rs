mod config;
mod constants;
mod ptr;
pub(crate) mod slot;
mod storage;
mod task_slab;

#[cfg(test)]
mod tests;

pub use config::{SlabConfig, SlabConfigBuilder, SlabStats};
pub use constants::*;
pub use ptr::{
    decode_slab_task_ptr, encode_slab_task_ptr, enqueue_slab_task, slab_task_poll_trampoline,
};
pub use slot::{TaskSlot, WakeAction};
pub use task_slab::{
    SlotHandle, TaskTable, get_task_table, init_task_table, init_task_table_with, slab_stats,
};
