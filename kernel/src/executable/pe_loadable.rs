use crate::file_system::file::{File, OpenFlags};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use goblin::pe::PE;
use goblin::Object;

pub struct PELoader {
    file_data: Vec<u8>,
    path: String,
}


impl PELoader {
    /// Opens and prepares a PE loader from the given path.
    pub fn new(path: &str) -> Option<Self> {
        let open_flags = [OpenFlags::Open, OpenFlags::ReadOnly];
        let file_handle = File::open(path, &open_flags).ok()?;
        let file_data = file_handle.read().ok()?;
        match Object::parse(&file_data).ok()? {
            Object::PE(pe) => Some(Self { file_data, path: path.to_string() }),
            _ => None,
        }
    }

    /// Returns the parsed PE object.
    pub fn pe(&self) -> PE<'_> {
        match Object::parse(&self.file_data).expect("invalid object format") {
            Object::PE(pe) => pe,
            _ => panic!("file is not a PE"),
        }
    }
    pub fn get_path(&self) -> String {
        self.path.clone()
    }

    /// Loads the PE into memory and prepares it for execution.
    pub fn load(&self) -> Result<(), LoadError> {
        let pe = self.pe();

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
}

