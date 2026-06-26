pub enum ToDevice {}
pub enum FromDevice {}
pub enum Bidirectional {}

mod sealed {
    pub trait IoBufferAccess {}
    pub trait WritableAccess {}
}

pub trait IoBufferAccess: sealed::IoBufferAccess {}
impl<T: sealed::IoBufferAccess> IoBufferAccess for T {}

pub trait WritableIoBufferAccess: IoBufferAccess + sealed::WritableAccess {}
impl<T: IoBufferAccess + sealed::WritableAccess> WritableIoBufferAccess for T {}

impl sealed::IoBufferAccess for ToDevice {}
impl sealed::IoBufferAccess for FromDevice {}
impl sealed::IoBufferAccess for Bidirectional {}

impl sealed::WritableAccess for FromDevice {}
impl sealed::WritableAccess for Bidirectional {}
