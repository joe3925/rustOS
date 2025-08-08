use crate::drivers::drive::gpt::VOLUMES;
use crate::file_system::fat::FileSystem;
use crate::file_system::file::FileStatus::DriveNotFound;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::PartialEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileAttribute {
    ReadOnly = 0x01,
    Hidden = 0x02,
    System = 0x04,
    VolumeLabel = 0x08,
    LFN = 0x0F,
    Directory = 0x10,
    Archive = 0x20,
    Unknown = 0xFF,
}
impl From<FileAttribute> for u8 {
    fn from(attribute: FileAttribute) -> Self {
        attribute as u8
    }
}

impl TryFrom<u8> for FileAttribute {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(FileAttribute::ReadOnly),
            0x02 => Ok(FileAttribute::Hidden),
            0x04 => Ok(FileAttribute::System),
            0x08 => Ok(FileAttribute::VolumeLabel),
            0x0F => Ok(FileAttribute::LFN),
            0x10 => Ok(FileAttribute::Directory),
            0x20 => Ok(FileAttribute::Archive),
            _ => Ok(FileAttribute::Unknown),
        }
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
            FileStatus::DriveNotFound => "The drive specified doesn't exist",
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

    /// Creates the file if it doesn't exist opens it if it does
    Create,
    /// Creates the file only if it doesn't already exist (fails if it exists)
    CreateNew,
    /// Opens the file only if it exists fails if it doesn't (this is default behavior if you have no create flags)
    Open,
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
    /// Opens a file from the given `path` using the specified set of `OpenFlags`.
    ///
    /// # Arguments
    ///
    /// * `path` - A string slice representing the full path to the file, including the drive letter.
    /// * `flags` - A slice of `OpenFlags` specifying the intended access and behavior.
    ///
    /// # Behavior
    ///
    /// The behavior of this function depends on the combination of `OpenFlags` provided:
    ///
    /// - `OpenFlags::ReadOnly`, `WriteOnly`, `ReadWrite`: These specify the intended access mode.
    ///   (Note: Access mode is currently unused but reserved for future access control enforcement.)
    ///
    /// - `OpenFlags::Create`: If the file does not exist, it will be created. If it exists, it will be opened.
    ///
    /// - `OpenFlags::CreateNew`: The file will be created only if it doesn't already exist. If it exists, an error is returned.
    ///
    /// - `OpenFlags::Open`: The file must already exist. This is the default behavior if neither `Create` nor `CreateNew` are provided.
    ///
    /// # Returns
    ///
    /// * `Ok(File)` - On success, returns an instance of `File` pointing to the opened or newly created file.
    /// * `Err(FileStatus)` - If the operation fails, returns a `FileStatus` indicating the error:
    ///   - `FileStatus::DriveNotFound` if the drive letter is invalid or not mounted.
    ///   - `FileStatus::PathNotFound` if the file doesn't exist and creation flags aren't set.
    ///   - `FileStatus::FileAlreadyExist` if `CreateNew` is used and the file exists.
    ///   - `FileStatus::IncompatibleFlags` if both `Create` and `CreateNew` are used together.
    ///   - `FileStatus::UnknownFail` if file creation appears successful but lookup fails.
    ///
    /// # Panics
    ///
    /// This function does not panic, but will return errors via the `Result` type if path or drive validation fails.
    ///
    /// # Example
    ///
    /// ```
    /// let file = File::open("C:/docs/readme.txt", &[OpenFlags::ReadOnly, OpenFlags::Open])?;
    /// ```
    ///
    /// # Notes
    ///
    /// - File creation implicitly creates any missing directories in the path.
    /// - Conflicting flags (`Create` + `CreateNew`) are rejected early.
    /// - This function assumes that the caller has already mounted or prepared the drive structure (`VOLUMES`).
    pub extern "win64" fn open(
        path: &str,
        flags: &[OpenFlags], // Accept flags as a slice
    ) -> Result<Self, FileStatus> {
        Self::check_path(path)?;
        if let Some(drive_letter) = File::get_drive_letter(path.as_bytes()) {
            let path = Self::remove_drive_from_path(path);
            if (flags.contains(&OpenFlags::Create) && flags.contains(&OpenFlags::CreateNew)) {
                return Err(FileStatus::IncompatibleFlags);
            }
            if let Some(part) = VOLUMES.lock().find_volume(drive_letter.clone()) {
                // Check if the file exists
                let file_entry = FileSystem::find_file(part, path);
                let name = FileSystem::file_parser(path);
                let file_name = FileSystem::get_text_before_last_dot(name[name.len() - 1]);
                let file_extension = FileSystem::get_text_after_last_dot(name[name.len() - 1]);
                match file_entry {
                    Ok(file_entry) => {
                        if (!flags.contains(&OpenFlags::CreateNew)) {
                            Ok(File {
                                name: file_name.to_string(),
                                extension: file_extension.to_string(),
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
                        if flags.contains(&OpenFlags::Create)
                            || flags.contains(&OpenFlags::CreateNew)
                        {
                            match FileSystem::create_dir(part, File::remove_file_from_path(path)) {
                                Ok(_) => {}
                                Err(FileStatus::FileAlreadyExist) => {}
                                Err(e) => return Err(e),
                            };

                            match FileSystem::create_file(
                                part,
                                &file_name,
                                &file_extension,
                                File::remove_file_from_path(path),
                            ) {
                                Ok(_) => {
                                    let file_entry = FileSystem::find_file(part, path);
                                    match file_entry {
                                        Ok(file_entry) => Ok(File {
                                            name: (file_name).to_string(),
                                            extension: (file_extension).to_string(),
                                            size: file_entry.file_size as u64,
                                            starting_cluster: file_entry.get_cluster(),
                                            drive_label: drive_letter.clone(),
                                            path: path.to_string(),
                                            deleted: false,
                                        }),
                                        Err(e) => Err(FileStatus::UnknownFail),
                                    }
                                }
                                Err(status) => Err(status),
                            }
                        } else {
                            Err(FileStatus::PathNotFound)
                        }
                    }
                    Err(e) => Err(e),
                }
            } else {
                Err(FileStatus::DriveNotFound)
            }
        } else {
            Err(FileStatus::DriveNotFound)
        }
    }

    pub extern "win64" fn remove_drive_from_path(path: &str) -> &str {
        let b = path.as_bytes();
        if b.len() >= 2 && b[1] == b':' {
            &path[2..]
        } else {
            path
        }
    }
    pub extern "win64" fn remove_file_from_path(path: &str) -> &str {
        let parent = path.rsplit_once('\\').map_or("", |(parent, _)| parent);

        if parent.is_empty() {
            "\\"
        } else if parent == "\\\\" {
            "\\"
        } else {
            parent
        }
    }
    pub extern "win64" fn list_dir(path: &str) -> Result<Vec<String>, FileStatus> {
        let label = File::get_drive_letter(path.as_bytes()).ok_or(FileStatus::DriveNotFound)?;
        if let Some(part) = VOLUMES.lock().find_volume(label) {
            if !part.is_fat {
                return Err(FileStatus::NotFat); // Drive is not FAT
            }
            let path = Self::remove_drive_from_path(path);
            return FileSystem::list_dir(part, path);
        } else {
            Err(FileStatus::DriveNotFound)
        }
    }

    /// Read data from the file.
    pub extern "win64" fn read(&self) -> Result<Vec<u8>, FileStatus> {
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
    pub extern "win64" fn write(&mut self, data: &[u8]) -> Result<(), FileStatus> {
        if let Some(part) = VOLUMES.lock().find_volume(self.drive_label.clone()) {
            if !part.is_fat {
                return Err(FileStatus::NotFat); // Drive is not FAT
            }
            FileSystem::write_file(part, data, self.path.as_str())
        } else {
            Err(DriveNotFound)
        }
    }
    pub extern "win64" fn delete(&mut self) -> Result<(), FileStatus> {
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
    pub extern "win64" fn remove_dir(path: String) -> Result<(), FileStatus> {
        Self::check_path(path.as_str())?;
        if let Some(label) = Self::get_drive_letter(path.as_bytes()) {
            if let Some(part) = VOLUMES.lock().find_volume(label) {
                if !part.is_fat {
                    return Err(FileStatus::NotFat); // Drive is not FAT
                }

                FileSystem::remove_dir(
                    part,
                    Self::remove_drive_from_path(path.as_str()).to_string(),
                )?;
            }
        }
        Err(FileStatus::DriveNotFound)
    }
    pub extern "win64" fn make_dir(path: String) -> Result<(), FileStatus> {
        Self::check_path(path.as_str())?;
        if let Some(label) = Self::get_drive_letter(path.as_bytes()) {
            if let Some(part) = VOLUMES.lock().find_volume(label) {
                let path = Self::remove_drive_from_path(&path);
                if !part.is_fat {
                    return Err(FileStatus::NotFat); // Drive is not FAT
                }
                FileSystem::create_dir(part, path)?;
                match FileSystem::find_dir(part, path) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e),
                }
            } else {
                Err(DriveNotFound)
            }
        } else {
            Err(DriveNotFound)
        }
    }
    pub extern "win64" fn get_drive_letter(path: &[u8]) -> Option<String> {
        // Ensure the path has at least 3 bytes: the letter, the colon, and the backslash.
        if path.len() >= 3 {
            if (path[0] as char).is_ascii_alphabetic() && path[1] == b':' && path[2] == b'\\' {
                return Some(String::from_utf8_lossy(&path[0..2]).to_string());
            }
        }
        None
    }
    pub extern "win64" fn check_path(path: &str) -> Result<(), FileStatus> {
        let sanitized_path = File::remove_drive_from_path(path);
        let components = FileSystem::file_parser(sanitized_path);

        for component in components {
            if component.is_empty() || component == "." || component == ".." {
                return Err(FileStatus::BadPath);
            }

            if component.chars().count() > 255 {
                return Err(FileStatus::BadPath);
            }

            if component.ends_with(' ') || component.ends_with('.') {
                return Err(FileStatus::BadPath);
            }

            let invalid = ['\\', '/', ':', '*', '?', '"', '<', '>', '|'];
            for ch in component.chars() {
                if ch < '\u{20}' || invalid.contains(&ch) {
                    return Err(FileStatus::BadPath);
                }
            }
        }

        Ok(())
    }
}
