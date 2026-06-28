#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcamSegment {
    pub base: u64,
    pub seg: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl EcamSegment {
    #[inline]
    pub const fn new(base: u64, seg: u16, start_bus: u8, end_bus: u8) -> Self {
        Self {
            base,
            seg,
            start_bus,
            end_bus,
        }
    }

    #[inline]
    pub const fn contains_bus(&self, bus: u8) -> bool {
        bus >= self.start_bus && bus <= self.end_bus
    }

    #[inline]
    pub const fn config_space_phys_addr(&self, bus: u8, dev: u8, func: u8, offset: u16) -> u64 {
        self.base
            + ((bus as u64) << 20)
            + ((dev as u64) << 15)
            + ((func as u64) << 12)
            + (offset as u64)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PciConfigAddress {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub offset: u16,
}

impl PciConfigAddress {
    #[inline]
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8, offset: u16) -> Self {
        Self {
            segment,
            bus,
            device,
            function,
            offset,
        }
    }

    #[inline]
    pub const fn aligned_u32_offset(self) -> u16 {
        self.offset & !3
    }
}

use alloc::vec::Vec;
use alloc::sync::Arc;
use crate::device::{Protocol, ProtocolId, ProtocolVersion, DeviceObject};
use crate::status::DriverStatus;

#[derive(Clone, Copy, Debug)]
pub struct PrtEntry {
    pub device: u8,
    pub pin: u8,
    pub gsi: u16,
}



#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarKind { None, Io, Mem32, Mem64 }

#[derive(Clone, Copy, Debug)]
pub struct Bar {
    pub kind: BarKind,
    pub base: u64,
    pub size: u64,
    pub prefetch: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsixInfo {
    pub cap_offset: u16,
    pub table_bar: u8,
    pub table_offset: u32,
    pub table_size: u16,
    pub pba_bar: u8,
    pub pba_offset: u32,
}



impl Default for Bar {
    fn default() -> Self {
        Bar {
            kind: BarKind::None,
            base: 0,
            size: 0,
            prefetch: false,
        }
    }
}
