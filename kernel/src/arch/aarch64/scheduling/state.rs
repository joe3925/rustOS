#[derive(Clone, Copy, Debug)]
#[repr(C, align(16))]
pub struct TaskContext {
    pub x: [u64; 31],
    pub sp: u64,
    pub elr: u64,
    pub spsr: u64,
}

impl TaskContext {
    pub const fn new() -> Self {
        Self {
            x: [0; 31],
            sp: 0,
            elr: 0,
            spsr: 0,
        }
    }
}

impl Default for TaskContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, align(16))]
pub struct FpuState {
    pub q: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}

impl FpuState {
    pub const fn new() -> Self {
        Self {
            q: [0; 32],
            fpcr: 0,
            fpsr: 0,
        }
    }
}

impl Default for FpuState {
    fn default() -> Self {
        Self::new()
    }
}

pub type TaskEntry = extern "C" fn(usize);

const _: () = {
    assert!(core::mem::size_of::<TaskContext>() == 272);
    assert!(core::mem::offset_of!(TaskContext, x) == 0);
    assert!(core::mem::offset_of!(TaskContext, sp) == 248);
    assert!(core::mem::offset_of!(TaskContext, elr) == 256);
    assert!(core::mem::offset_of!(TaskContext, spsr) == 264);

    assert!(core::mem::size_of::<FpuState>() == 528);
    assert!(core::mem::offset_of!(FpuState, q) == 0);
    assert!(core::mem::offset_of!(FpuState, fpcr) == 512);
    assert!(core::mem::offset_of!(FpuState, fpsr) == 520);
};
