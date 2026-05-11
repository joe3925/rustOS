use alloc::{string::String, vec::Vec};
use async_lock::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use kernel_types::{
    bench_archive::{
        BenchArchiveFormat, BenchArchiveRecordKind, BenchArchiveRecordMeta, BENCH_ARCHIVE_FORMAT,
    },
    fs::{OpenFlags, Path},
    status::FileStatus,
};

use crate::file_system::file::File;

pub trait BenchArchiveFormatExt {
    fn open_append_only(&self, path: String) -> BenchArchive;
}

impl BenchArchiveFormatExt for BenchArchiveFormat {
    fn open_append_only(&self, path: String) -> BenchArchive {
        BenchArchive::new(path)
    }
}

pub struct BenchArchive {
    path: String,
    state: AsyncMutex<BenchArchiveState>,
}

struct BenchArchiveState {
    next_record_sequence: u64,
    next_persist_id: u64,
}

pub struct BenchArchivePersist<'a> {
    archive: &'a BenchArchive,
    state: AsyncMutexGuard<'a, BenchArchiveState>,
    persist_id: u64,
}

pub struct BenchArchiveRecord {
    pub kind: BenchArchiveRecordKind,
    pub path: String,
    pub data: Vec<u8>,
    pub timestamp_ns: u64,
}

impl BenchArchiveRecord {
    pub fn data(path: String, data: Vec<u8>, timestamp_ns: u64) -> Self {
        Self {
            kind: BenchArchiveRecordKind::Data,
            path,
            data,
            timestamp_ns,
        }
    }

    pub fn manifest(path: String, data: Vec<u8>, timestamp_ns: u64) -> Self {
        Self {
            kind: BenchArchiveRecordKind::Manifest,
            path,
            data,
            timestamp_ns,
        }
    }

    pub fn persist_commit(path: String, data: Vec<u8>, timestamp_ns: u64) -> Self {
        Self {
            kind: BenchArchiveRecordKind::PersistCommit,
            path,
            data,
            timestamp_ns,
        }
    }
}

impl BenchArchive {
    fn new(path: String) -> Self {
        Self {
            path,
            state: AsyncMutex::new(BenchArchiveState {
                next_record_sequence: 1,
                next_persist_id: 1,
            }),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub async fn begin_persist(&self) -> BenchArchivePersist<'_> {
        let mut state = self.state.lock().await;
        let persist_id = state.next_persist_id;
        state.next_persist_id = state.next_persist_id.wrapping_add(1).max(1);

        BenchArchivePersist {
            archive: self,
            state,
            persist_id,
        }
    }

    async fn open_file(&self) -> Result<File, FileStatus> {
        let parent = File::remove_file_from_path(&self.path);
        let _ = File::make_dir(&Path::from_string(parent)).await;

        let path = Path::from_string(&self.path);
        match File::open(
            &path,
            &[
                OpenFlags::Create,
                OpenFlags::ReadWrite,
                OpenFlags::WriteThrough,
            ],
        )
        .await
        {
            Ok(f) => Ok(f),
            Err(_) => {
                File::open(
                    &path,
                    &[
                        OpenFlags::Open,
                        OpenFlags::ReadWrite,
                        OpenFlags::WriteThrough,
                    ],
                )
                .await
            }
        }
    }
}

impl BenchArchivePersist<'_> {
    pub fn persist_id(&self) -> u64 {
        self.persist_id
    }

    pub async fn append_records(
        &mut self,
        records: &[BenchArchiveRecord],
    ) -> Result<(), FileStatus> {
        if records.is_empty() {
            return Ok(());
        }

        let mut file = self.archive.open_file().await?;

        if file.size == 0 {
            append_exact(&mut file, &BENCH_ARCHIVE_FORMAT.file_header()).await?;
        }

        for record in records {
            self.append_record_to_file(&mut file, record).await?;
        }

        file.flush().await?;
        file.close().await
    }

    async fn append_record_to_file(
        &mut self,
        file: &mut File,
        record: &BenchArchiveRecord,
    ) -> Result<(), FileStatus> {
        let path_bytes = record.path.as_bytes();
        if path_bytes.len() > u32::MAX as usize {
            return Err(FileStatus::BadPath);
        }

        let sequence = self.state.next_record_sequence;
        self.state.next_record_sequence = self.state.next_record_sequence.wrapping_add(1).max(1);

        let meta = BenchArchiveRecordMeta {
            kind: record.kind,
            flags: 0,
            path_len: path_bytes.len() as u32,
            data_len: record.data.len() as u64,
            sequence,
            timestamp_ns: record.timestamp_ns,
            path_hash: BENCH_ARCHIVE_FORMAT.hash_bytes(path_bytes),
            data_hash: BENCH_ARCHIVE_FORMAT.hash_bytes(&record.data),
        };

        let header = BENCH_ARCHIVE_FORMAT.record_header(meta);
        append_exact(file, &header).await?;
        append_exact(file, path_bytes).await?;
        append_exact(file, &record.data).await
    }
}

async fn append_exact(file: &mut File, bytes: &[u8]) -> Result<(), FileStatus> {
    let written = file.append(bytes).await?;
    if written == bytes.len() {
        Ok(())
    } else {
        Err(FileStatus::FileTooLarge)
    }
}

pub fn bench_archive_for_path(path: String) -> BenchArchive {
    BENCH_ARCHIVE_FORMAT.open_append_only(path)
}
