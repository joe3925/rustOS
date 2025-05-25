use core::mem::transmute;

use crate::file_system::file::{File, OpenFlags};
use crate::memory::paging::new_user_mode_page_table;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use goblin::pe::PE;
use goblin::Object;

pub struct PELoader {
    buffer: Box<[u8]>,
    pe: PE<'static>,
    path: String,
}


impl PELoader {
    /// Opens and prepares a PE loader from the given path.
    pub fn new(path: &str) -> Option<Self> {
        let open_flags = [OpenFlags::Open, OpenFlags::ReadOnly];
        let file_handle = File::open(path, &open_flags).ok()?;
        let file_data: Vec<u8> = file_handle.read().ok()?;

        let boxed: Box<[u8]> = file_data.into_boxed_slice();

        let slice: &[u8] = &boxed;

        let pe = match Object::parse(slice).ok()? {
            Object::PE(pe) => pe,
            _ => return None,
        };

        let pe_static: PE<'static> = unsafe { transmute::<PE<'_>, PE<'static>>(pe) };

        Some(Self {
            buffer: boxed,
            pe: pe_static,
            path: path.to_string(),
        })
    }


    pub fn get_path(&self) -> String {
        self.path.clone()
    }

    /// Loads the PE into memory and prepares it for execution.
    /// 
    /// Error: LoadError
    /// 
    /// Ok: PID of the loaded program
    pub fn load(&self) -> Result<u64, LoadError> {
        let pe = &self.pe;
        if pe.is_lib {
            return Err(LoadError::IsNotExecutable);
        }

        if !pe.is_64 {
            return Err(LoadError::Not64Bit);
        }

        let entry = pe.entry;
        if entry == 0 {
            return Err(LoadError::NoEntryPoint);
        }

        let opt_hdr = pe.header.optional_header.as_ref().ok_or(LoadError::MissingSections)?;

        if pe.sections.is_empty() {
            return Err(LoadError::MissingSections);
        }

        let image_base = opt_hdr.windows_fields.image_base;
        if image_base % 0x10000 != 0 {
            return Err(LoadError::UnsupportedImageBase);
        }

        let (table_phys, table_virt) = new_user_mode_page_table().unwrap();

        Err(LoadError::NotImplemented)
    }
}

/// Placeholder error type for loading failures.
#[derive(Debug)]
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
}

