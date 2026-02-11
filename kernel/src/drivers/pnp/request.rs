//! DPC (Deferred Procedure Call) queue and request routing delegation.
//!
//! Request routing logic is now in the `kernel_routing` crate which compiles per-driver.
//! This module only contains DPC queue functionality that requires kernel internals.

use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::scheduling::runtime::runtime::spawn_detached;
use alloc::collections::vec_deque::VecDeque;
use spin::Mutex;

use super::manager::PnpManager;

#[derive(Clone, Copy)]
pub struct Dpc {
    pub func: DpcFn,
    pub arg: usize,
}

pub type DpcFn = extern "win64" fn(usize);

lazy_static::lazy_static! {
    static ref GLOBAL_DPCQ: Mutex<VecDeque<Dpc>> = Mutex::new(VecDeque::new());
}

impl PnpManager {
    pub fn queue_dpc(&self, func: extern "win64" fn(usize), arg: usize) {
        GLOBAL_DPCQ.lock().push_back(Dpc { func, arg });
        spawn_detached(PNP_MANAGER.run_one_dpc());
    }

    async fn run_one_dpc(&self) {
        let dpc_opt = { GLOBAL_DPCQ.lock().pop_front() };
        let Some(dpc) = dpc_opt else {
            return;
        };
        (dpc.func)(dpc.arg);
    }
}
