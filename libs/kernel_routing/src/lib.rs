#![no_std]
extern crate alloc;

mod routing;

pub use routing::*;

#[cfg(test)]
mod test;
