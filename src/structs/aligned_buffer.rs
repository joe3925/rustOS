#[repr(align(1024))]
pub(crate) struct AlignedBuffer1024 {
    pub(crate) buffer: [u8; 1024],
}
impl AlignedBuffer1024 {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0; 1024], // Initialize the buffer with zeros
        }
    }
}
#[repr(align(256))]
pub(crate) struct AlignedBuffer256 {
    pub(crate) buffer: [u8; 256],
}
impl AlignedBuffer256 {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0; 256], // Initialize the buffer with zeros
        }
    }
}
#[repr(align(128))]
pub(crate) struct AlignedBuffer128 {
    pub(crate) buffer: [u8; 8192],
}
impl AlignedBuffer128 {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0; 8192], // Initialize the buffer with zeros
        }
    }
}