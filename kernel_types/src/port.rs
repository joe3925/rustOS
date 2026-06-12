use core::marker::PhantomData;

pub trait PortAccess {
    unsafe fn read_u8(port: u16) -> u8;
    unsafe fn read_u16(port: u16) -> u16;
    unsafe fn read_u32(port: u16) -> u32;

    unsafe fn write_u8(port: u16, value: u8);
    unsafe fn write_u16(port: u16, value: u16);
    unsafe fn write_u32(port: u16, value: u32);
}

pub trait PortValue: Copy {
    unsafe fn read_from<A: PortAccess>(port: u16) -> Self;
    unsafe fn write_to<A: PortAccess>(port: u16, value: Self);
}

impl PortValue for u8 {
    #[inline]
    unsafe fn read_from<A: PortAccess>(port: u16) -> Self {
        unsafe { A::read_u8(port) }
    }

    #[inline]
    unsafe fn write_to<A: PortAccess>(port: u16, value: Self) {
        unsafe { A::write_u8(port, value) }
    }
}

impl PortValue for u16 {
    #[inline]
    unsafe fn read_from<A: PortAccess>(port: u16) -> Self {
        unsafe { A::read_u16(port) }
    }

    #[inline]
    unsafe fn write_to<A: PortAccess>(port: u16, value: Self) {
        unsafe { A::write_u16(port, value) }
    }
}

impl PortValue for u32 {
    #[inline]
    unsafe fn read_from<A: PortAccess>(port: u16) -> Self {
        unsafe { A::read_u32(port) }
    }

    #[inline]
    unsafe fn write_to<A: PortAccess>(port: u16, value: Self) {
        unsafe { A::write_u32(port, value) }
    }
}

pub type NativePortAccess = crate::arch::ActivePlatform;

#[repr(transparent)]
pub struct Port<T, A = NativePortAccess> {
    port: u16,
    _marker: PhantomData<fn() -> (T, A)>,
}

impl<T, A> Port<T, A> {
    #[inline]
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl<T, A> Port<T, A>
where
    T: PortValue,
    A: PortAccess,
{
    #[inline]
    pub unsafe fn read(&mut self) -> T {
        unsafe { T::read_from::<A>(self.port) }
    }

    #[inline]
    pub unsafe fn write(&mut self, value: T) {
        unsafe { T::write_to::<A>(self.port, value) }
    }
}
