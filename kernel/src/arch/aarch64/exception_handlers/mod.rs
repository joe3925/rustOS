mod handlers;
mod syndrome;
mod wrapper;

pub(crate) use handlers::{dispatch_serror, dispatch_sync, handle_fiq};

#[derive(Clone, Copy, Debug)]
#[repr(u64)]
pub(crate) enum Aarch64ExceptionOrigin {
    CurrentElSp0 = 0,
    CurrentElSpx = 1,
    LowerElAarch64 = 2,
    LowerElAarch32 = 3,
}

impl Aarch64ExceptionOrigin {
    pub(crate) fn from_raw(value: u64) -> Self {
        match value {
            0 => Self::CurrentElSp0,
            1 => Self::CurrentElSpx,
            2 => Self::LowerElAarch64,
            3 => Self::LowerElAarch32,
            _ => panic!("invalid AArch64 exception origin {value}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct Aarch64ExceptionInfo {
    pub origin: Aarch64ExceptionOrigin,
    pub syndrome: u64,
    pub fault_address: u64,
}
