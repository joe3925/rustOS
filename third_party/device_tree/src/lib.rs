#![no_std]

extern crate alloc;

pub mod util;

use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::str;
use util::{align, SliceRead, SliceReadError};

const MAGIC_NUMBER: u32 = 0xd00dfeed;
const SUPPORTED_VERSION: u32 = 17;
const OF_DT_BEGIN_NODE: u32 = 0x00000001;
const OF_DT_END_NODE: u32 = 0x00000002;
const OF_DT_PROP: u32 = 0x00000003;

#[derive(Debug)]
pub enum DeviceTreeError {
    InvalidMagicNumber,
    SizeMismatch,
    SliceReadError(SliceReadError),
    ParseError(usize),
    Utf8Error,
    VersionNotSupported,
}

#[derive(Debug)]
pub struct DeviceTree {
    pub version: u32,
    pub boot_cpuid_phys: u32,
    pub reserved: Vec<(u64, u64)>,
    pub root: Node,
}

#[derive(Debug)]
pub struct Node {
    pub name: String,
    pub props: Vec<(String, Vec<u8>)>,
    pub children: Vec<Node>,
}

#[derive(Debug)]
pub enum PropError {
    NotFound,
    Utf8Error,
    Missing0,
    SliceReadError(SliceReadError),
}

impl From<SliceReadError> for DeviceTreeError {
    fn from(e: SliceReadError) -> DeviceTreeError {
        DeviceTreeError::SliceReadError(e)
    }
}

impl From<str::Utf8Error> for DeviceTreeError {
    fn from(_: str::Utf8Error) -> DeviceTreeError {
        DeviceTreeError::Utf8Error
    }
}

impl DeviceTree {
    pub fn load(buffer: &[u8]) -> Result<DeviceTree, DeviceTreeError> {
        if buffer.read_be_u32(0)? != MAGIC_NUMBER {
            return Err(DeviceTreeError::InvalidMagicNumber);
        }

        if buffer.read_be_u32(4)? as usize != buffer.len() {
            return Err(DeviceTreeError::SizeMismatch);
        }

        let version = buffer.read_be_u32(20)?;
        if version != SUPPORTED_VERSION {
            return Err(DeviceTreeError::VersionNotSupported);
        }

        let off_dt_struct = buffer.read_be_u32(8)? as usize;
        let off_dt_strings = buffer.read_be_u32(12)? as usize;
        let off_mem_rsvmap = buffer.read_be_u32(16)? as usize;
        let boot_cpuid_phys = buffer.read_be_u32(28)?;

        let mut reserved = Vec::new();
        let mut pos = off_mem_rsvmap;

        loop {
            let offset = buffer.read_be_u64(pos)?;
            pos += 8;
            let size = buffer.read_be_u64(pos)?;
            pos += 8;

            reserved.push((offset, size));

            if size == 0 {
                break;
            }
        }

        let (_, root) = Node::load(buffer, off_dt_struct, off_dt_strings)?;

        Ok(DeviceTree {
            version,
            boot_cpuid_phys,
            reserved,
            root,
        })
    }

    pub fn find<'a>(&'a self, path: &str) -> Option<&'a Node> {
        if !path.starts_with('/') {
            return None;
        }

        self.root.find(&path[1..])
    }
}

impl Node {
    fn load(
        buffer: &[u8],
        start: usize,
        off_dt_strings: usize,
    ) -> Result<(usize, Node), DeviceTreeError> {
        if buffer.read_be_u32(start)? != OF_DT_BEGIN_NODE {
            return Err(DeviceTreeError::ParseError(start));
        }

        let raw_name = buffer.read_bstring0(start + 4)?;
        let mut pos = align(start + 4 + raw_name.len() + 1, 4);
        let mut props = Vec::new();

        while buffer.read_be_u32(pos)? == OF_DT_PROP {
            let val_size = buffer.read_be_u32(pos + 4)? as usize;
            let name_offset = buffer.read_be_u32(pos + 8)? as usize;

            let val_start = pos + 12;
            let val_end = val_start + val_size;
            let val = buffer.subslice(val_start, val_end)?;
            let prop_name = buffer.read_bstring0(off_dt_strings + name_offset)?;

            props.push((str::from_utf8(prop_name)?.to_owned(), val.to_owned()));

            pos = align(val_end, 4);
        }

        let mut children = Vec::new();

        while buffer.read_be_u32(pos)? == OF_DT_BEGIN_NODE {
            let (new_pos, child_node) = Node::load(buffer, pos, off_dt_strings)?;
            pos = new_pos;

            children.push(child_node);
        }

        if buffer.read_be_u32(pos)? != OF_DT_END_NODE {
            return Err(DeviceTreeError::ParseError(pos));
        }

        pos += 4;

        Ok((
            pos,
            Node {
                name: str::from_utf8(raw_name)?.to_owned(),
                props,
                children,
            },
        ))
    }

    pub fn find<'a>(&'a self, path: &str) -> Option<&'a Node> {
        if path == "" {
            return Some(self);
        }

        match path.find('/') {
            Some(idx) => {
                let (l, r) = path.split_at(idx);
                let subpath = &r[1..];

                for child in self.children.iter() {
                    if child.name == l {
                        return child.find(subpath);
                    }
                }

                None
            }
            None => self.children.iter().find(|n| n.name == path),
        }
    }

    pub fn has_prop(&self, name: &str) -> bool {
        self.prop_raw(name).is_some()
    }

    pub fn prop_str<'a>(&'a self, name: &str) -> Result<&'a str, PropError> {
        let raw = self.prop_raw(name).ok_or(PropError::NotFound)?;

        let l = raw.len();
        if l < 1 || raw[l - 1] != 0 {
            return Err(PropError::Missing0);
        }

        Ok(str::from_utf8(&raw[..(l - 1)])?)
    }

    pub fn prop_raw<'a>(&'a self, name: &str) -> Option<&'a Vec<u8>> {
        for &(ref key, ref val) in self.props.iter() {
            if key == name {
                return Some(val);
            }
        }
        None
    }

    pub fn prop_u64(&self, name: &str) -> Result<u64, PropError> {
        let raw = self.prop_raw(name).ok_or(PropError::NotFound)?;

        Ok(raw.as_slice().read_be_u64(0)?)
    }

    pub fn prop_u32(&self, name: &str) -> Result<u32, PropError> {
        let raw = self.prop_raw(name).ok_or(PropError::NotFound)?;

        Ok(raw.as_slice().read_be_u32(0)?)
    }
}

impl From<str::Utf8Error> for PropError {
    fn from(_: str::Utf8Error) -> PropError {
        PropError::Utf8Error
    }
}

impl From<SliceReadError> for PropError {
    fn from(e: SliceReadError) -> PropError {
        PropError::SliceReadError(e)
    }
}
