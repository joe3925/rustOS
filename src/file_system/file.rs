use crate::drivers::drive::gpt::PARTITIONS;
use crate::file_system::fat::FileSystem;
use crate::println;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::PartialEq;

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
#[derive(Debug)]
pub(crate) enum FileStatus {
    Success = 0x00,
    FileAlreadyExist = 0x01,
    PathNotFound = 0x02,
    UnknownFail = 0x03,
    NotFat = 0x04,
    DriveNotFound,
    IncompatibleFlags,
    CorruptFat,
}


impl FileStatus {
    pub fn to_str(&self) -> &'static str {
        match self {
            FileStatus::Success => "Success",
            FileStatus::FileAlreadyExist => "File already exists",
            FileStatus::PathNotFound => "Path not found",
            FileStatus::UnknownFail => "The operation failed for an unknown reason",
            FileStatus::NotFat => "The partition is unformatted or not supported",
            FileStatus::DriveNotFound => "The drive specified doesnt exist",
            FileStatus::IncompatibleFlags => "The flags can contain CreateNew and Create",
            FileStatus::CorruptFat => "The File Allocation Table is corrupt this drive should be reformated and backed up if still possible"
        }
    }
}
#[derive(Debug)]
pub(crate) struct File {
    pub name: String,
    pub extension: String,
    pub size: u64,
    pub starting_cluster: u32,
    pub drive_label: String,
    pub path: String,
    pub deleted: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFlags {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    /// Creates the file if it doesn't exist
    Create,
    /// Creates the file only if it doesn't already exist (fails if it exists)
    CreateNew,
}

impl PartialEq for FileStatus {
    fn eq(&self, other: &FileStatus) -> bool {
        if (self.to_str() == other.to_str()) {
            return true;
        }
        false
    }
}

impl File {
    /// Open a file from the given path and drive.
    pub fn open(
        path: &str,
        flags: &[OpenFlags], // Accept flags as a slice
    ) -> Result<Self, FileStatus> {
        let drive_letter = File::get_drive_letter(path.as_bytes()).ok_or(FileStatus::PathNotFound)?;
        let path = Self::remove_drive_from_path(path);
        if (flags.contains(&OpenFlags::Create) && flags.contains(&OpenFlags::CreateNew)) {
            return Err(FileStatus::IncompatibleFlags);
        }
        let mut file_system = {
            let mut partitions = PARTITIONS.lock();
            if let Some(part) = partitions.find_volume(drive_letter.clone()) {
                if !part.is_fat {
                    return Err(FileStatus::NotFat); // Drive is not FAT
                }
                FileSystem::new(part.label.clone(), part.size)
            } else {
                return Err(FileStatus::DriveNotFound);
            }
        };
        // Check if the file exists
        println!("here1");
        let file_entry = file_system.find_file(path);
        match file_entry {
            Ok(file_entry) => {
                if (!flags.contains(&OpenFlags::CreateNew)) {
                    Ok(File {
                        name: file_entry.file_name.clone(),
                        extension: file_entry.file_extension.clone(),
                        size: file_entry.file_size,
                        starting_cluster: file_entry.starting_cluster,
                        drive_label: file_entry.drive_label.clone(),
                        path: path.to_string(),
                        deleted: false,
                    })
                } else {
                    Err(FileStatus::FileAlreadyExist)
                }
            }
            Err(FileStatus::PathNotFound) => {
                // If file doesn't exist, check flags for creation
                if flags.contains(&OpenFlags::Create) || flags.contains(&OpenFlags::CreateNew) {
                    let name = FileSystem::file_parser(path);
                    let file_name = FileSystem::get_text_before_last_dot(name[name.len() - 1]);
                    let file_extension = FileSystem::get_text_after_last_dot(name[name.len() - 1]);

                    file_system.create_dir(File::remove_file_from_path(path))?;

                    match file_system.create_file(&file_name, &file_extension, path) {
                        Ok(_) => {
                            let file_entry = file_system.find_file(path);
                            match file_entry {
                                Ok(file_entry) => {
                                    Ok(File {
                                        name: file_entry.file_name.clone(),
                                        extension: file_entry.file_extension.clone(),
                                        size: file_entry.file_size,
                                        starting_cluster: file_entry.starting_cluster,
                                        drive_label: file_system.label.clone(),
                                        path: path.to_string(),
                                        deleted: false,
                                    })
                                }
                                Err(e) => {
                                    Err(e)
                                }
                            }
                        }
                        Err(status) => Err(status),
                    }
                } else {
                    Err(FileStatus::PathNotFound)
                }
            }
            Err(e) => {
                Err(e)
            }
        }
    }

    /// Helper function to split file name and extension from the full path
    pub fn remove_drive_from_path(path: &str) -> &str {
        if path.len() >= 3 && path[1..2] == ":".to_string() && path[2..3] == "\\".to_string() {
            &path[3..]
        } else {
            path
        }
    }
    pub fn remove_file_from_path(path: &str) -> &str {
        if let Some(pos) = path.rfind('\\') {
            &path[..pos]
        } else {
            path
        }
    }


    /// Read data from the file.
    pub fn read(&mut self) -> Result<Vec<u8>, FileStatus> {
        let mut file_system = {
            let mut partition = PARTITIONS.lock();
            if let Some(part) = partition.find_volume(self.drive_label.clone()) {
                if !part.is_fat {
                    return Err(FileStatus::UnknownFail); // Drive is not FAT
                }
                FileSystem::new(part.label.clone(), part.size)
            } else {
                return Err(FileStatus::UnknownFail);
            }
        };
        file_system.read_file(self.path.as_str())
    }
    /// Write data to the file (overwrites).
    pub fn write(&mut self, data: &[u8]) -> Result<(), FileStatus> {
        let mut file_system = {
            let mut partition = PARTITIONS.lock();
            if let Some(part) = partition.find_volume(self.drive_label.clone()) {
                if !part.is_fat {
                    return Err(FileStatus::UnknownFail); // Drive is not FAT
                }
                FileSystem::new(part.label.clone(), part.size)
            } else {
                return Err(FileStatus::UnknownFail);
            }
        };
        file_system.write_file(data, self.path.as_str())
    }
    pub fn delete(&mut self) -> Result<(), FileStatus> {
        let mut file_system = {
            let mut partition = PARTITIONS.lock();
            if let Some(part) = partition.find_volume(self.drive_label.clone()) {
                if !part.is_fat {
                    return Err(FileStatus::UnknownFail); // Drive is not FAT
                }
                FileSystem::new(part.label.clone(), part.size)
            } else {
                return Err(FileStatus::UnknownFail);
            }
        };
        let status = file_system.delete_file(self.path.as_str());
        match status {
            Ok(_) => {
                self.deleted = true;
                Ok(())
            }
            Err(_) => status,
        }
    }
    pub fn get_drive_letter(path: &[u8]) -> Option<String> {
        // Ensure the path has at least 3 bytes: the letter, the colon, and the backslash.
        if path.len() >= 3 {
            if (path[0] as char).is_ascii_alphabetic() && path[1] == b':' && path[2] == b'\\' {
                return Some(String::from_utf8_lossy(&path[0..2]).to_string());
            }
        }
        None
    }
}

