use kernel_types::object_manager::ObjectTag;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceMask {
    class: ObjectTag,
    bits: u64,
}

impl InterfaceMask {
    pub const fn new(class: ObjectTag, bits: u64) -> Self {
        Self { class, bits }
    }

    pub const fn class(self) -> ObjectTag {
        self.class
    }

    pub const fn bits(self) -> u64 {
        self.bits
    }

    pub const fn from_raw(class: ObjectTag, bits: u64) -> Self {
        Self::new(class, bits)
    }

    pub fn contains(self, other: Self) -> bool {
        self.class == other.class && (self.bits & other.bits) == other.bits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectOperation {
    Observe,
    Submit,
    Consume,
    Wait,
    Configure,
    Message,
    Destroy,
}

#[derive(Debug, Clone, Copy)]
pub struct AccessContext {
    pub caller_pid: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ObjectQueryContext {
    pub caller_pid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectQueryError {
    UnsupportedClass,
    InvalidObject,
    ResultTooLarge,
}

pub const MAX_OBJECT_QUERY_SIZE: usize = 128;

/// An ABI value whose initialized representation contains no padding bytes.
///
/// # Safety
/// Implementors must be `Copy` and have no uninitialized padding because the
/// complete value representation is copied into a user-visible query buffer.
pub unsafe trait ObjectQueryInfo: Copy {}

pub struct ObjectQueryBuffer {
    bytes: [u8; MAX_OBJECT_QUERY_SIZE],
    len: usize,
}

impl ObjectQueryBuffer {
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_OBJECT_QUERY_SIZE],
            len: 0,
        }
    }

    pub fn write<T: ObjectQueryInfo>(&mut self, value: &T) -> Result<(), ObjectQueryError> {
        let len = core::mem::size_of::<T>();
        if len > self.bytes.len() {
            return Err(ObjectQueryError::ResultTooLarge);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                (value as *const T).cast::<u8>(),
                self.bytes.as_mut_ptr(),
                len,
            );
        }
        self.len = len;
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

pub trait AccessPolicy: Send + Sync {
    fn authorize(
        &self,
        context: AccessContext,
        target: &dyn ObjectBehavior,
        requested: InterfaceMask,
    ) -> Result<(), ()>;
}

pub struct CapabilityAccessPolicy;

impl AccessPolicy for CapabilityAccessPolicy {
    fn authorize(
        &self,
        _context: AccessContext,
        target: &dyn ObjectBehavior,
        requested: InterfaceMask,
    ) -> Result<(), ()> {
        target
            .supported_interfaces()
            .contains(requested)
            .then_some(())
            .ok_or(())
    }
}

pub trait ObjectBehavior: Send + Sync {
    fn class(&self) -> ObjectTag;
    fn supported_interfaces(&self) -> InterfaceMask;
    fn required_interface(&self, operation: ObjectOperation) -> Option<InterfaceMask>;

    fn query(
        &self,
        _context: ObjectQueryContext,
        _information_class: u32,
        _output: &mut ObjectQueryBuffer,
    ) -> Result<(), ObjectQueryError> {
        Err(ObjectQueryError::UnsupportedClass)
    }

    fn matches(&self, granted: InterfaceMask, operation: ObjectOperation) -> bool {
        self.required_interface(operation)
            .is_some_and(|required| granted.contains(required))
    }
}

pub const OBSERVE_BIT: u64 = 1 << 0;
pub const SUBMIT_BIT: u64 = 1 << 1;
pub const CONSUME_BIT: u64 = 1 << 2;
pub const WAIT_BIT: u64 = 1 << 3;
pub const CONFIGURE_BIT: u64 = 1 << 4;
pub const MESSAGE_BIT: u64 = 1 << 5;
pub const DESTROY_BIT: u64 = 1 << 6;

pub const fn standard_interfaces(class: ObjectTag) -> InterfaceMask {
    let bits = match class {
        ObjectTag::Program => OBSERVE_BIT | MESSAGE_BIT | DESTROY_BIT,
        ObjectTag::Thread => OBSERVE_BIT | WAIT_BIT | CONFIGURE_BIT | DESTROY_BIT,
        ObjectTag::Queue => OBSERVE_BIT | SUBMIT_BIT | CONSUME_BIT | CONFIGURE_BIT | DESTROY_BIT,
        ObjectTag::CompletionQueue => {
            OBSERVE_BIT | SUBMIT_BIT | CONSUME_BIT | WAIT_BIT | CONFIGURE_BIT | DESTROY_BIT
        }
        ObjectTag::File => OBSERVE_BIT | SUBMIT_BIT | WAIT_BIT | CONFIGURE_BIT | DESTROY_BIT,
        ObjectTag::Module => OBSERVE_BIT | DESTROY_BIT,
        ObjectTag::Device => OBSERVE_BIT | SUBMIT_BIT | CONFIGURE_BIT,
        ObjectTag::IoBufferBacking => OBSERVE_BIT | SUBMIT_BIT | DESTROY_BIT,
        ObjectTag::ExecutorDomain => OBSERVE_BIT | SUBMIT_BIT | CONFIGURE_BIT | DESTROY_BIT,
        ObjectTag::Generic => {
            OBSERVE_BIT | SUBMIT_BIT | CONSUME_BIT | WAIT_BIT | CONFIGURE_BIT | DESTROY_BIT
        }
        ObjectTag::Directory | ObjectTag::Symlink => 0,
    };
    InterfaceMask::new(class, bits)
}

pub const fn interface_for_operation(
    class: ObjectTag,
    operation: ObjectOperation,
) -> InterfaceMask {
    let bit = match operation {
        ObjectOperation::Observe => OBSERVE_BIT,
        ObjectOperation::Submit => SUBMIT_BIT,
        ObjectOperation::Consume => CONSUME_BIT,
        ObjectOperation::Wait => WAIT_BIT,
        ObjectOperation::Configure => CONFIGURE_BIT,
        ObjectOperation::Message => MESSAGE_BIT,
        ObjectOperation::Destroy => DESTROY_BIT,
    };
    InterfaceMask::new(class, bit)
}
