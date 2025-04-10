use crate::drivers::drive::gpt::VOLUMES;
use crate::file_system::fat::FileSystem;
use crate::file_system::file::FileStatus::DriveNotFound;
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
    InternalError,
    BadPath,
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
            FileStatus::CorruptFat => "The File Allocation Table is corrupt this drive should be reformated and backed up if still possible",
            FileStatus::InternalError => "An unknown Error has happened likely due to a code logic error",
            FileStatus::BadPath => "File name must be no more then 8 chars file Extension must be no more then 3 chars and every letter must be capital"
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
        Self::check_path(path)?;
        if let Some(drive_letter) = File::get_drive_letter(path.as_bytes())
        {
            let path = Self::remove_drive_from_path(path);
            if (flags.contains(&OpenFlags::Create) && flags.contains(&OpenFlags::CreateNew)) {
                return Err(FileStatus::IncompatibleFlags);
            }
            if let Some(part) = VOLUMES.lock().find_volume(drive_letter.clone()) {
                // Check if the file exists
                let file_entry = FileSystem::find_file(part, path);
                match file_entry {
                    Ok(file_entry) => {
                        if (!flags.contains(&OpenFlags::CreateNew)) {
                            Ok(File {
                                name: file_entry.get_name().clone(),
                                extension: file_entry.get_extension().clone(),
                                size: file_entry.file_size as u64,
                                starting_cluster: file_entry.get_cluster(),
                                drive_label: drive_letter.clone(),
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

                            FileSystem::create_dir(part, File::remove_file_from_path(path))?;

                            match FileSystem::create_file(part, &file_name, &file_extension, path) {
                                Ok(_) => {
                                    let file_entry = FileSystem::find_file(part, path);
                                    match file_entry {
                                        Ok(file_entry) => {
                                            Ok(File {
                                                name: file_entry.get_name().clone(),
                                                extension: file_entry.get_extension().clone(),
                                                size: file_entry.file_size as u64,
                                                starting_cluster: file_entry.get_cluster(),
                                                drive_label: drive_letter.clone(),
                                                path: path.to_string(),
                                                deleted: false,
                                            })
                                        }
                                        Err(e) => {
                                            Err(FileStatus::UnknownFail)
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
            } else {
                Err(FileStatus::DriveNotFound)
            }
        } else {
            Err(FileStatus::DriveNotFound)
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
        let parent = path.rsplit_once('\\').map_or("", |(parent, _)| parent);

        if parent.is_empty() {
            "\\"
        } else if parent == "\\\\" {
            "\\"
        } else {
            parent
        }
    }


    /// Read data from the file.
    pub fn read(&self) -> Result<Vec<u8>, FileStatus> {
        if let Some(part) = VOLUMES.lock().find_volume(self.drive_label.clone()) {
            if !part.is_fat {
                return Err(FileStatus::NotFat); // Drive is not FAT
            }
            FileSystem::read_file(part, self.path.as_str())
        } else {
            Err(DriveNotFound)
        }
    }
    /// Write data to the file (overwrites).
    pub fn write(&mut self, data: &[u8]) -> Result<(), FileStatus> {
        if let Some(part) = VOLUMES.lock().find_volume(self.drive_label.clone()) {
            if !part.is_fat {
                return Err(FileStatus::NotFat); // Drive is not FAT
            }
            FileSystem::write_file(part, data, self.path.as_str())
        } else {
            Err(DriveNotFound)
        }
    }
    pub fn delete(&mut self) -> Result<(), FileStatus> {
        if let Some(part) = VOLUMES.lock().find_volume(self.drive_label.clone()) {
            if !part.is_fat {
                return Err(FileStatus::NotFat); // Drive is not FAT
            }
            let status = FileSystem::delete_file(part, self.path.as_str());
            match status {
                Ok(_) => {
                    self.deleted = true;
                    Ok(())
                }
                Err(_) => status,
            }
        } else {
            Err(DriveNotFound)
        }
    }
    pub fn remove_dir(path: String) -> Result<(), FileStatus> {
        Self::check_path(path.as_str())?;
        if let Some(label) = Self::get_drive_letter(path.as_bytes()) {
            if let Some(part) = VOLUMES.lock().find_volume(label) {
                if !part.is_fat {
                    return Err(FileStatus::NotFat); // Drive is not FAT
                }
                FileSystem::remove_dir(part, Self::remove_drive_from_path(path.as_str()).to_string())?;
            }
        }
        Err(FileStatus::DriveNotFound)
    }
    pub fn make_dir(path: String) -> Result<(), FileStatus> {
        Self::check_path(path.as_str())?;
        if let Some(label) = Self::get_drive_letter(path.as_bytes()) {
            if let Some(part) = VOLUMES.lock().find_volume(label) {
                if !part.is_fat {
                    return Err(FileStatus::NotFat); // Drive is not FAT
                }
                FileSystem::create_dir(part, path.as_str())?;
                match FileSystem::find_dir(part, path.as_str()) {
                    Ok(_) => {
                        Ok(())
                    }
                    Err(e) => {
                        Err(e)
                    }
                }
            } else {
                Err(DriveNotFound)
            }
        } else {
            Err(DriveNotFound)
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
    pub fn check_path(path: &str) -> Result<(), FileStatus> {
        // Remove the drive letter from the path
        let sanitized_path = File::remove_drive_from_path(path);

        // Parse the path into individual components (directories and file name)
        let components = FileSystem::file_parser(sanitized_path);

        // Iterate through each component and validate it
        for component in components {
            // Extract name and extension (if applicable)
            let name = FileSystem::get_text_before_last_dot(component);
            let extension = FileSystem::get_text_after_last_dot(component);

            // Validate the name length (directories should not have extensions)
            if name.len() > 8 {
                return Err(FileStatus::BadPath);
            }

            // Validate the extension length (only applicable to files)
            if !extension.is_empty() && extension.len() > 3 {
                return Err(FileStatus::BadPath);
            }

            // Check for lowercase letters in the name
            if name.chars().any(|c| c.is_ascii_lowercase()) {
                return Err(FileStatus::BadPath);
            }

            // Check for lowercase letters in the extension
            if !extension.is_empty() && extension.chars().any(|c| c.is_ascii_lowercase()) {
                return Err(FileStatus::BadPath);
            }
        }

        Ok(())
    }
}

