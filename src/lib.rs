//! A FAT filesystem library implemented in Rust.
//!
//! # Usage
//!
//! This crate is [on crates.io](https://crates.io/crates/fatfs) and can be
//! used by adding `fatfs` to the dependencies in your project's `Cargo.toml`.
//!
//! ```toml
//! [dependencies]
//! fatfs = "0.4"
//! ```

#![crate_type = "lib"]
#![crate_name = "fatfs"]
#![no_std]
// Disable warnings to not clutter code with cfg too much
#![cfg_attr(not(all(feature = "alloc", feature = "lfn")), allow(dead_code, unused_imports))]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_truncation,
    clippy::bool_to_int_with_if, // less readable
    clippy::uninlined_format_args, // not supported before Rust 1.58.0
)]

extern crate log;

#[cfg(feature = "alloc")]
extern crate alloc;

#[macro_use]
mod log_macros;

mod boot_sector;
mod dir;
mod dir_entry;
mod error;
mod file;
mod fs;
mod io;
mod table;
mod time;

pub use crate::dir::*;
pub use crate::dir_entry::*;
pub use crate::error::*;
pub use crate::file::*;
pub use crate::fs::*;
pub use crate::io::*;
pub use crate::time::*;
