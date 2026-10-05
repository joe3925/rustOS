#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod channels;
pub mod completion;
pub mod locks;
pub mod platform;
pub mod queues;
mod sync;
pub mod workers;

pub use platform::contract::{Platform, ThreadEntry};

#[cfg(all(test, feature = "std", not(any(loom, feature = "loom"))))]
mod test;

#[cfg(all(test, any(loom, feature = "loom")))]
mod loom_tests;
