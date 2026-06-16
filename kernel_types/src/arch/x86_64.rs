use crate::arch::{Platform, PortIoPlatform};
use crate::port::PortAccess;

pub struct X86Platform;

impl Platform for X86Platform {
    const NAME: &'static str = "x86_64";
    fn cycle_counter() -> u64 {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags)
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }
}

impl PortIoPlatform for X86Platform {
    #[inline]
    unsafe fn read_port_u8(port: u16) -> u8 {
        let mut port = x86_64::instructions::port::Port::<u8>::new(port);
        unsafe { port.read() }
    }

    #[inline]
    unsafe fn read_port_u16(port: u16) -> u16 {
        let mut port = x86_64::instructions::port::Port::<u16>::new(port);
        unsafe { port.read() }
    }

    #[inline]
    unsafe fn read_port_u32(port: u16) -> u32 {
        let mut port = x86_64::instructions::port::Port::<u32>::new(port);
        unsafe { port.read() }
    }

    #[inline]
    unsafe fn write_port_u8(port: u16, value: u8) {
        let mut port = x86_64::instructions::port::Port::<u8>::new(port);
        unsafe { port.write(value) }
    }

    #[inline]
    unsafe fn write_port_u16(port: u16, value: u16) {
        let mut port = x86_64::instructions::port::Port::<u16>::new(port);
        unsafe { port.write(value) }
    }

    #[inline]
    unsafe fn write_port_u32(port: u16, value: u32) {
        let mut port = x86_64::instructions::port::Port::<u32>::new(port);
        unsafe { port.write(value) }
    }
}

impl PortAccess for X86Platform {
    #[inline]
    unsafe fn read_u8(port: u16) -> u8 {
        unsafe { <Self as PortIoPlatform>::read_port_u8(port) }
    }

    #[inline]
    unsafe fn read_u16(port: u16) -> u16 {
        unsafe { <Self as PortIoPlatform>::read_port_u16(port) }
    }

    #[inline]
    unsafe fn read_u32(port: u16) -> u32 {
        unsafe { <Self as PortIoPlatform>::read_port_u32(port) }
    }

    #[inline]
    unsafe fn write_u8(port: u16, value: u8) {
        unsafe { <Self as PortIoPlatform>::write_port_u8(port, value) }
    }

    #[inline]
    unsafe fn write_u16(port: u16, value: u16) {
        unsafe { <Self as PortIoPlatform>::write_port_u16(port, value) }
    }

    #[inline]
    unsafe fn write_u32(port: u16, value: u32) {
        unsafe { <Self as PortIoPlatform>::write_port_u32(port, value) }
    }
}
