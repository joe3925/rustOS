#![allow(unused_imports)]

pub use crate::sync_platform::{mpmc_channel, MpmcReceiver as Receiver, MpmcSender as Sender};
pub use kernel_sync::mpmc::{RecvError, SendError, TryRecvError};
