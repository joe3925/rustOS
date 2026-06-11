use alloc::{string::String, vec::Vec};

use crate::arch::VirtAddr;
use crate::fs::Path;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct PeInfo {
    pub is_64: bool,
    pub is_dll: bool,
    pub machine: u16,
    pub characteristics: u16,
    pub time_date_stamp: u32,
    pub optional_magic: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub preferred_image_base: u64,
    pub loaded_image_base: VirtAddr,
    pub entry_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_code: u64,
    pub size_of_initialized_data: u64,
    pub size_of_uninitialized_data: u64,
    pub stack_reserve: u64,
    pub stack_commit: u64,
    pub heap_reserve: u64,
    pub heap_commit: u64,
    pub aslr: bool,
    pub relocated: bool,
    pub sections: Vec<PeSectionInfo>,
    pub imports: Vec<PeImportInfo>,
    pub exports: Vec<PeExportInfo>,
    pub pdb: Option<PePdbInfo>,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct PeSectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct PeImportInfo {
    pub dll: String,
    pub name: String,
    pub ordinal: u16,
    pub import_address_table_rva: u64,
    pub hint_name_table_rva: u64,
    pub thunk_size: usize,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct PeExportInfo {
    pub name: Option<String>,
    pub rva: u64,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct PePdbInfo {
    pub format: PePdbFormat,
    pub path: String,
    pub age: u32,
    pub guid: Option<[u8; 16]>,
    pub signature: Option<u32>,
    pub codeview_offset: Option<u32>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PePdbFormat {
    Pdb70,
    Pdb20,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct Module {
    pub title: String,
    pub image_path: Path,
    pub parent_pid: u64,
    pub image_base: VirtAddr,
    pub symbols: Vec<(String, usize)>,
    pub pe_info: Option<PeInfo>,
}
