use crate::vec;
use crate::{
    drivers::pnp::driver_object::{FsOp, Request, RequestType},
    file_system::{
        self,
        file::{FileStatus, OpenFlags},
    },
};
use alloc::vec::Vec;
use alloc::{boxed::Box, string::String};

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsOpenParams {
    pub flags: OpenFlags,
    pub path: String,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsOpenResult {
    pub fs_file_id: u64,
    pub is_dir: bool,
    pub size: u64,
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsCloseParams {
    pub fs_file_id: u64,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsCloseResult {
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsReadHeader {
    pub fs_file_id: u64,
    pub offset: u64,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsReadResultHeader {
    pub read_len: usize,
    pub error: Option<FileStatus>,
}

pub const FS_READ_HDR_AREA: usize = {
    const A: usize = core::mem::size_of::<FsReadHeader>();
    const B: usize = core::mem::size_of::<FsReadResultHeader>();
    if A > B {
        A
    } else {
        B
    }
};

pub struct ReadView<'a> {
    pub hdr: FsReadHeader,
    pub buf: &'a mut [u8],
}

pub fn fs_read_view_from_data(data: &mut Box<[u8]>) -> Option<ReadView<'_>> {
    let hdr_area = FS_READ_HDR_AREA;
    if data.len() < hdr_area {
        return None;
    }

    let total = data.len();
    let data_len = total - hdr_area;

    // header is stored at the end, unaligned
    let hdr =
        unsafe { core::ptr::read_unaligned(data.as_ptr().add(data_len) as *const FsReadHeader) };

    if hdr.len > data_len {
        return None;
    }

    let buf = &mut data[..hdr.len];

    Some(ReadView { hdr, buf })
}

pub fn fs_read_result_into_data(
    data: &mut Box<[u8]>,
    read_len: usize,
    error: Option<FileStatus>,
) -> bool {
    let hdr_area = FS_READ_HDR_AREA;
    if data.len() < hdr_area {
        return false;
    }

    let total = data.len();
    let data_len = total - hdr_area;
    if read_len > data_len {
        return false;
    }

    let hdr = FsReadResultHeader { read_len, error };
    let hdr_ptr = unsafe { data.as_mut_ptr().add(data_len) as *mut FsReadResultHeader };
    unsafe {
        core::ptr::write_unaligned(hdr_ptr, hdr);
    }
    true
}

pub fn make_read_request(fs_file_id: u64, offset: u64, buf_cap: usize) -> Request {
    let hdr_area = FS_READ_HDR_AREA;
    let total = hdr_area + buf_cap;
    let mut data = vec![0u8; total].into_boxed_slice();

    let data_len = total - hdr_area;
    let hdr = FsReadHeader {
        fs_file_id,
        offset,
        len: buf_cap,
    };

    let hdr_ptr = unsafe { data.as_mut_ptr().add(data_len) as *mut FsReadHeader };
    unsafe {
        core::ptr::write_unaligned(hdr_ptr, hdr);
    }

    Request::new(RequestType::Fs(FsOp::Read), data)
}

pub fn interpret_read_result(data: Box<[u8]>) -> (usize, Option<FileStatus>, Box<[u8]>) {
    let hdr_area = FS_READ_HDR_AREA;
    let total = data.len();
    if total < hdr_area {
        return (0, Some(FileStatus::UnknownFail), data);
    }

    let data_len = total - hdr_area;
    let result = unsafe {
        core::ptr::read_unaligned(data.as_ptr().add(data_len) as *const FsReadResultHeader)
    };

    (result.read_len, result.error, data)
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsWriteHeader {
    pub fs_file_id: u64,
    pub offset: u64,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsWriteResultHeader {
    pub written: usize,
    pub error: Option<FileStatus>,
}

pub const FS_WRITE_HDR_AREA: usize = {
    const A: usize = core::mem::size_of::<FsWriteHeader>();
    const B: usize = core::mem::size_of::<FsWriteResultHeader>();
    if A > B {
        A
    } else {
        B
    }
};

pub struct WriteView<'a> {
    pub hdr: FsWriteHeader,
    pub buf: &'a [u8],
}

pub fn fs_write_view_from_data(data: &Box<[u8]>) -> Option<WriteView<'_>> {
    let hdr_area = FS_WRITE_HDR_AREA;
    if data.len() < hdr_area {
        return None;
    }

    let total = data.len();
    let data_len = total - hdr_area;

    let hdr =
        unsafe { core::ptr::read_unaligned(data.as_ptr().add(data_len) as *const FsWriteHeader) };
    if hdr.len > data_len {
        return None;
    }

    let buf = &data[..hdr.len];

    Some(WriteView { hdr, buf })
}

pub fn fs_write_result_into_data(
    data: &mut Box<[u8]>,
    written: usize,
    error: Option<FileStatus>,
) -> bool {
    let hdr_area = FS_WRITE_HDR_AREA;
    if data.len() < hdr_area {
        return false;
    }

    let total = data.len();
    let data_len = total - hdr_area;
    if written > data_len {
        return false;
    }

    let hdr = FsWriteResultHeader { written, error };
    let hdr_ptr = unsafe { data.as_mut_ptr().add(data_len) as *mut FsWriteResultHeader };
    unsafe {
        core::ptr::write_unaligned(hdr_ptr, hdr);
    }
    true
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FsSeekWhence {
    Set,
    Cur,
    End,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsSeekParams {
    pub fs_file_id: u64,
    pub origin: FsSeekWhence,
    pub offset: i64,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsSeekResult {
    pub pos: u64,
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsFlushParams {
    pub fs_file_id: u64,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsFlushResult {
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsCreateParams {
    pub path: String,
    pub dir: bool,
    pub flags: OpenFlags,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsCreateResult {
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsRenameParams {
    pub src: String,
    pub dst: String,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsRenameResult {
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsListDirParams {
    pub path: String,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsListDirResult {
    pub names: Vec<String>,
    pub error: Option<FileStatus>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsGetInfoParams {
    pub fs_file_id: u64,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FsGetInfoResult {
    pub size: u64,
    pub is_dir: bool,
    pub attrs: u32,
    pub error: Option<FileStatus>,
}
