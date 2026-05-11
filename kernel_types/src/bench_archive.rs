//! Append-only benchmark archive format.
//!
//! A benchmark session is stored as one `.benchpack` file. The format is meant
//! to be readable after every completed `persist()` and does not require a
//! footer, central directory, compression stream, or finalization step.
//!
//! # Physical Layout
//!
//! The file starts with one fixed-size file header, followed by zero or more
//! independent records:
//!
//! ```text
//! file_header
//! record_header path_bytes data_bytes
//! record_header path_bytes data_bytes
//! ...
//! ```
//!
//! There is no padding between records. All integer fields are little-endian.
//!
//! File header, 32 bytes:
//!
//! ```text
//! 0..8    magic       b"RSBPAK1\0"
//! 8..10   version     u16, currently 1
//! 10..12  header_len  u16, currently 32
//! 12..32  reserved    zero
//! ```
//!
//! Record header, 64 bytes:
//!
//! ```text
//! 0..8    magic        b"RSBPRC1\0"
//! 8..10   version      u16, currently 1
//! 10..12  header_len   u16, currently 64
//! 12..14  kind         u16: 1=data, 2=manifest, 3=persist commit
//! 14..16  flags        u16, currently 0
//! 16..20  path_len     u32
//! 20..24  reserved     zero
//! 24..32  data_len     u64
//! 32..40  sequence     u64, monotonically increasing within this archive
//! 40..48  timestamp_ns u64, kernel monotonic timestamp
//! 48..56  path_hash    u64 FNV-1a(path_bytes)
//! 56..64  data_hash    u64 FNV-1a(data_bytes)
//! ```
//!
//! # Logical Contents
//!
//! A record path is a UTF-8 virtual path using `/` separators. It is not a host
//! filesystem path. Current benchmark records are written under:
//!
//! ```text
//! windows/<window>/runs/run_<run_id>/persists/persist_<persist_id>/...
//! ```
//!
//! The `<window>` component is the benchmark window name sanitized to ASCII
//! letters, digits, `-`, `_`, and `.`. Other characters are replaced with `_`.
//! If a session creates more than one window with the same name, later windows
//! may receive a numeric suffix such as `drive-1`.
//!
//! Per-persist CSV chunks are written as data records:
//!
//! ```text
//! windows/<window>/runs/run_000001/persists/persist_000001/chunks/chunk_000000/avg/samples.csv
//! windows/<window>/runs/run_000001/persists/persist_000001/chunks/chunk_000000/avg/spans.csv
//! windows/<window>/runs/run_000001/persists/persist_000001/chunks/chunk_000000/avg/memory.csv
//! windows/<window>/runs/run_000001/persists/persist_000001/chunks/chunk_000000/core/000/samples.csv
//! ```
//!
//! Debug metadata, when enabled, is written as a manifest record:
//!
//! ```text
//! windows/<window>/runs/run_000001/persists/persist_000001/debug_metadata.json
//! ```
//!
//! Each completed persist ends with a persist-commit record:
//!
//! ```text
//! windows/<window>/runs/run_000001/persists/persist_000001/persist_commit.json
//! ```
//!
//! A reader should treat data and manifest records as usable only after the
//! matching persist-commit record has been seen and validated.
//!
//! # CSV Payloads
//!
//! `samples.csv` records contain:
//!
//! ```text
//! run_id,timestamp_ns,core,rip,depth,frame0,frame1,...
//! ```
//!
//! The number of `frameN` columns may differ across chunks. Parse each chunk by
//! its own header before combining samples.
//!
//! `spans.csv` records contain:
//!
//! ```text
//! run_id,tag,object_id,core,start_ns,duration_ns
//! ```
//!
//! `memory.csv` records contain:
//!
//! ```text
//! run_id,timestamp_ns,core,used_bytes,total_bytes,heap_used_bytes,heap_total_bytes,core_sched_ns,core_switches
//! ```
//!
//! `debug_metadata.json` contains the run time range, the active program, and
//! loaded module/debug information for symbolization.
//!
//! # Reader Algorithm
//!
//! To parse a `.benchpack`:
//!
//! 1. Read and validate the 32-byte file header.
//! 2. Repeatedly read a 64-byte record header.
//! 3. If EOF occurs exactly where the next header would start, stop normally.
//! 4. If a header is incomplete, has invalid magic/version/header length, an
//!    unknown kind, or impossible lengths, stop and ignore that partial tail.
//! 5. Read `path_len` bytes and `data_len` bytes.
//! 6. If either payload is incomplete, stop and ignore that record and tail.
//! 7. Validate `path_hash` and `data_hash` with 64-bit FNV-1a.
//! 8. Decode the path as UTF-8.
//! 9. Group records by the `windows/.../runs/.../persists/...` prefix.
//! 10. When a valid `PersistCommit` record is found, mark that group committed.
//! 11. At EOF, discard any group without a valid commit record.
//!
//! To list windows, collect the `<window>` component from committed records whose
//! paths start with `windows/`.
//!
//! To export the CSVs for one window, filter committed records with the
//! `windows/<window>/` prefix, then collect `samples.csv`, `spans.csv`, and
//! `memory.csv` records. Sort by run id, persist id, chunk id, and record
//! sequence before concatenating or loading into a table.
//!
//! To read debug metadata for one window, filter committed manifest records with
//! the `windows/<window>/` prefix whose path ends in `/debug_metadata.json`.
//!
//! # Recovery Guarantees
//!
//! Writers append records only; existing bytes are never rewritten. Each
//! successful `persist()` appends all records for that persist, appends a
//! `PersistCommit`, then flushes the archive file. If the system shuts down
//! during a persist, the reader stops at the first incomplete or invalid record
//! and still has every previously committed persist.
//!
//! The checksum is for corruption and torn-write detection, not security.

pub const BENCH_ARCHIVE_EXTENSION: &str = ".benchpack";

pub const BENCH_ARCHIVE_FILE_MAGIC: [u8; 8] = *b"RSBPAK1\0";
pub const BENCH_ARCHIVE_RECORD_MAGIC: [u8; 8] = *b"RSBPRC1\0";

pub const BENCH_ARCHIVE_VERSION: u16 = 1;
pub const BENCH_ARCHIVE_FILE_HEADER_LEN: usize = 32;
pub const BENCH_ARCHIVE_RECORD_HEADER_LEN: usize = 64;

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BenchArchiveFormat;

pub const BENCH_ARCHIVE_FORMAT: BenchArchiveFormat = BenchArchiveFormat;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchArchiveRecordKind {
    Data = 1,
    Manifest = 2,
    PersistCommit = 3,
}

impl BenchArchiveRecordKind {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BenchArchiveRecordMeta {
    pub kind: BenchArchiveRecordKind,
    pub flags: u16,
    pub path_len: u32,
    pub data_len: u64,
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub path_hash: u64,
    pub data_hash: u64,
}

impl BenchArchiveFormat {
    pub fn file_header(self) -> [u8; BENCH_ARCHIVE_FILE_HEADER_LEN] {
        let mut out = [0u8; BENCH_ARCHIVE_FILE_HEADER_LEN];
        out[0..8].copy_from_slice(&BENCH_ARCHIVE_FILE_MAGIC);
        put_u16(&mut out, 8, BENCH_ARCHIVE_VERSION);
        put_u16(&mut out, 10, BENCH_ARCHIVE_FILE_HEADER_LEN as u16);
        put_u32(&mut out, 12, 0);
        put_u64(&mut out, 16, 0);
        put_u64(&mut out, 24, 0);
        out
    }

    pub fn record_header(
        self,
        meta: BenchArchiveRecordMeta,
    ) -> [u8; BENCH_ARCHIVE_RECORD_HEADER_LEN] {
        let mut out = [0u8; BENCH_ARCHIVE_RECORD_HEADER_LEN];
        out[0..8].copy_from_slice(&BENCH_ARCHIVE_RECORD_MAGIC);
        put_u16(&mut out, 8, BENCH_ARCHIVE_VERSION);
        put_u16(&mut out, 10, BENCH_ARCHIVE_RECORD_HEADER_LEN as u16);
        put_u16(&mut out, 12, meta.kind.as_u16());
        put_u16(&mut out, 14, meta.flags);
        put_u32(&mut out, 16, meta.path_len);
        put_u32(&mut out, 20, 0);
        put_u64(&mut out, 24, meta.data_len);
        put_u64(&mut out, 32, meta.sequence);
        put_u64(&mut out, 40, meta.timestamp_ns);
        put_u64(&mut out, 48, meta.path_hash);
        put_u64(&mut out, 56, meta.data_hash);
        out
    }

    pub fn hash_bytes(self, bytes: &[u8]) -> u64 {
        fnv1a_update(FNV_OFFSET_BASIS, bytes)
    }

    pub fn hash_parts(self, parts: &[&[u8]]) -> u64 {
        let mut h = FNV_OFFSET_BASIS;
        for part in parts {
            h = fnv1a_update(h, part);
        }
        h
    }
}

fn fnv1a_update(mut h: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

fn put_u16(out: &mut [u8], off: usize, v: u16) {
    out[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(out: &mut [u8], off: usize, v: u32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(out: &mut [u8], off: usize, v: u64) {
    out[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
