use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::{max, min};
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr;
use core::slice;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

#[cfg(not(any(test, feature = "hosted-tests")))]
use crate::arch::{PagingPlatform, Platform};
use crate::arch::{PhysAddr, VirtAddr};
use crate::device::DeviceObject;

mod backing;
mod buffer;
mod construction;
mod descriptors;
mod segments;

pub use backing::*;
pub use buffer::*;
pub use descriptors::*;
pub use segments::*;
