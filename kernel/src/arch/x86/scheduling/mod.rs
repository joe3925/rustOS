mod entry;
pub(crate) mod state;
pub(crate) mod tls;

pub(crate) use entry::{idle_task, ipi_entry, task_return_trampoline, yield_interrupt_entry};

pub type TaskEntry = extern "C" fn(usize);
