use alloc::string::String;

#[derive(Debug)]
#[repr(C)]
pub enum LoadError {
    IsNotExecutable,
    Not64Bit,
    NoEntryPoint,
    InvalidSubsystem,
    InvalidDllCharacteristics,
    UnsupportedRelocationFormat,
    MissingSections,
    UnsupportedImageBase,
    NotImplemented,
    NoMemory,
    BadPID,
    NotDLL,
    NoFile,
    NoMainThread,
    NoSuchSymbol(String),
    PageError(PageMapError),
}

impl From<PageMapError> for LoadError {
    fn from(error: PageMapError) -> Self {
        Self::PageError(error)
    }
}

#[derive(Debug)]
#[repr(u32)]
pub enum PageMapError {
    Page4KiB(PageMapFailure),
    Page2MiB(PageMapFailure),
    Page1GiB(PageMapFailure),
    TranslationFailed(),
    NoMemory(),
    NoMemoryMap(),
    RangePinned(),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PageMapFailure {
    FrameAllocationFailed,
    PageAlreadyMapped,
    ParentEntryHugePage,
}

#[derive(Debug)]
#[repr(u32)]
pub enum TaskError {
    NotFound(u64),
    BadName,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Data {
    #[prost(uint32, tag = "1")]
    U32(u32),
    #[prost(uint64, tag = "2")]
    U64(u64),
    #[prost(sint32, tag = "3")]
    I32(i32),
    #[prost(sint64, tag = "4")]
    I64(i64),
    #[prost(bool, tag = "5")]
    Bool(bool),
    #[prost(string, tag = "6")]
    Str(String),
}
