use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::drivers::drive::generic_drive::DRIVECOLLECTION;
use crate::file_system::FAT::FileSystem;

#[derive(Debug, Clone, Copy)]
pub(crate) enum FileAttribute {
    ReadOnly = 0x01,
    Hidden = 0x02,
    System = 0x04,
    VolumeLabel = 0x08,
    Directory = 0x10,
    Archive = 0x20,
}
impl From<FileAttribute> for u8 {
    fn from(attribute: FileAttribute) -> Self {
        attribute as u8
    }
}
pub(crate) enum FileStatus {
    Success = 0x00,
    FileAlreadyExist = 0x01,
    PathNotFound = 0x02,
    UnknownFail = 0x03,
}

impl FileStatus {
    pub fn to_str(&self) -> &'static str {
        match self {
            FileStatus::Success => "Success",
            FileStatus::FileAlreadyExist => "File already exists",
            FileStatus::PathNotFound => "Path not found",
            FileStatus::UnknownFail => "The operation failed for an unknown reason"
        }
    }
}
pub struct File {
    pub name: String,
    pub extension: String,
    pub size: u64,
    pub starting_cluster: u32,
    pub drive_label: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFlags {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    Create,      // Creates the file if it doesn't exist
    CreateNew,   // Creates the file only if it doesn't already exist (fails if it exists)
}

impl File {
    /// Open a file from the given path and drive.
    pub fn open(
        path: &str,
        flags: &[OpenFlags], // Accept flags as a slice
    ) -> Result<Self, FileStatus> {
        let drive_letter = File::get_drive_letter(path.as_bytes()).ok_or(FileStatus::PathNotFound)?;

        let mut file_system = {
            let mut drive_collection = DRIVECOLLECTION.lock();
            if let Some(drive) = drive_collection.find_drive(drive_letter) {
                if !drive.is_fat {
                    return Err(FileStatus::UnknownFail); // Drive is not FAT
                }
                FileSystem::new(drive.label.clone())
            } else {
                return Err(FileStatus::UnknownFail);
            }
        };

        // Check if the file exists
        if let Some(file_entry) = file_system.find_file(path) {
            Ok(File {
                name: file_entry.file_name.clone(),
                extension: file_entry.file_extension.clone(),
                size: file_entry.file_size,
                starting_cluster: file_entry.starting_cluster,
                drive_label: file_entry.drive_label.clone(),
            })
        } else {
            // If file doesn't exist, check flags for creation
            if flags.contains(&OpenFlags::Create) {
                let (file_name, file_extension) = Self::split_file_name_and_extension(path);
                match file_system.create_file(&file_name, &file_extension, path) {
                    FileStatus::Success => {
                        if let Some(file_entry) = file_system.find_file(path) {
                            Ok(File {
                                name: file_entry.file_name.clone(),
                                extension: file_entry.file_extension.clone(),
                                size: file_entry.file_size,
                                starting_cluster: file_entry.starting_cluster,
                                drive_label: file_system.label.clone(),
                            })
                        } else {
                            Err(FileStatus::UnknownFail)
                        }
                    }
                    status => Err(status),
                }
            } else {
                Err(FileStatus::PathNotFound)
            }
        }
    }

    /// Helper function to split file name and extension from the full path
    fn split_file_name_and_extension(path: &str) -> (String, String) {
        let parts: Vec<&str> = path.split('\\').collect();
        if let Some(file) = parts.last() {
            if let Some(dot_pos) = file.rfind('.') {
                let file_name = file[..dot_pos].to_string();
                let file_extension = file[dot_pos + 1..].to_string();
                return (file_name, file_extension);
            }
        }
        (String::new(), String::new())
    }

    /// Read data from the file.
    pub fn read(&mut self) -> Result<Vec<u8>, FileStatus> {
        let mut drive_collection = DRIVECOLLECTION.lock();
        if let Some(drive) = drive_collection.find_drive(self.drive_label.clone()) {
            if !drive.is_fat {
                return Err(FileStatus::UnknownFail);
            }

            let mut file_system = FileSystem::new(self.drive_label.clone());
            file_system.read_file(self.name.as_str()).ok_or(FileStatus::UnknownFail)
        } else {
            Err(FileStatus::PathNotFound)
        }
    }

    /// Write data to the file (overwrites).
    pub fn write(&mut self, data: &[u8]) -> Result<(), FileStatus> {
        let mut drive_collection = DRIVECOLLECTION.lock();
        if let Some(drive) = drive_collection.find_drive(self.drive_label.clone()) {
            if !drive.is_fat {
                return Err(FileStatus::UnknownFail);
            }

            let mut file_system = FileSystem::new(self.drive_label.clone());
            match file_system.write_file(self.name.as_str(), self.extension.as_str(), data, "/") {
                FileStatus::Success => Ok(()),
                status => Err(status),
            }
        } else {
            Err(FileStatus::PathNotFound)
        }
    }
    pub fn get_drive_letter(path: &[u8]) -> Option<String> {
        // Ensure the path has at least 3 bytes: the letter, the colon, and the backslash.
        if path.len() >= 3 {
            // Check if the first byte is a valid ASCII alphabetic character, second is colon, and third is backslash
            if (path[0] as char).is_ascii_alphabetic() && path[1] == b':' && path[2] == b'\\' {
                return Some(String::from_utf8_lossy(&path[0..2]).to_string());
            }
        }
        None
    }
}

