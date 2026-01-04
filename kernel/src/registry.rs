use crate::file_system::file::File;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use bincode::{Decode, Encode};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kernel_types::{
    fs::{FsSeekWhence, OpenFlags, Path},
    status::{Data, RegError},
};
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};

// File paths
const SNAP_PATH: &str = "C:/system/registry/registry.snap";
const WAL_PATH: &str = "C:/system/registry/registry.wal";

fn snap_path() -> Path {
    Path::from_string(SNAP_PATH)
}

fn wal_path() -> Path {
    Path::from_string(WAL_PATH)
}

// WAL configuration
const WAL_MAGIC: u32 = 0x57414C52; // "WALR"
const WAL_VERSION: u16 = 1;
const SNAPSHOT_DELTA_THRESHOLD: u64 = 100;

// Device class catalog
const CLASS_LIST: &[(&str, &str)] = &[
    ("disk", "Disk devices / block storage"),
    ("volume", "Mountable partitions"),
    ("kbd", "Keyboards"),
    ("mouse", "Pointing devices (mouse, touch)"),
    ("hid", "Human Interface Devices"),
    ("display", "Display controller (generic)"),
    ("gpu", "3D accelerator / graphics adapter"),
    ("net", "Network adapters"),
    ("usb", "USB host controllers / hubs"),
    ("battery", "Battery / power sources"),
    ("wifi", "Wireless LAN"),
    ("serial", "Serial ports / UART"),
    ("parallel", "Parallel ports"),
];

#[derive(Debug, Clone, Encode, Decode)]
pub struct Key {
    pub values: BTreeMap<String, Data>,
    pub sub_keys: BTreeMap<String, Key>,
}

impl Key {
    pub const fn empty() -> Self {
        Self {
            values: BTreeMap::new(),
            sub_keys: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq)]
pub enum RegDelta {
    CreateKey {
        path: String,
    },
    DeleteKey {
        path: String,
    },
    SetValue {
        key_path: String,
        name: String,
        data: Data,
    },
    DeleteValue {
        key_path: String,
        name: String,
    },
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct Registry {
    pub root: BTreeMap<String, Key>,
}

impl Registry {
    pub const fn empty() -> Self {
        Self {
            root: BTreeMap::new(),
        }
    }
}

/// WAL record header for power-loss tolerant persistence
#[derive(Debug, Clone, Encode, Decode)]
struct WalRecordHeader {
    magic: u32,
    version: u16,
    kind: u16,
    seq: u64,
    payload_len: u32,
    payload_hash: u64,
}

impl WalRecordHeader {
    const SIZE: usize = 4 + 2 + 2 + 8 + 4 + 8; // 28 bytes
}

/// Simple non-crypto hash for corruption detection (FNV-1a 64-bit)
fn fnv1a_hash(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

lazy_static! {
    static ref REGISTRY: RwLock<Arc<Registry>> = RwLock::new(Arc::new(Registry::empty()));
    static ref WAL_SEQ: AtomicU64 = AtomicU64::new(0);
    static ref DELTAS_SINCE_SNAPSHOT: AtomicU64 = AtomicU64::new(0);
}

static REGISTRY_INIT: AtomicBool = AtomicBool::new(false);
static REGISTRY_INIT_LOCK: Mutex<()> = Mutex::new(());

fn init_class_catalog(reg: &mut Registry) {
    let system = reg.root.entry("SYSTEM".into()).or_insert_with(Key::empty);
    let ccset = system
        .sub_keys
        .entry("CurrentControlSet".into())
        .or_insert_with(Key::empty);
    let class_root = ccset
        .sub_keys
        .entry("Class".into())
        .or_insert_with(Key::empty);

    for &(id, desc) in CLASS_LIST {
        let ck = class_root
            .sub_keys
            .entry(id.to_string())
            .or_insert_with(Key::empty);

        ck.values
            .entry("Class".into())
            .or_insert(Data::Str(String::new()));

        ck.values
            .entry("Description".into())
            .or_insert(Data::Str(desc.to_string()));

        ck.sub_keys
            .entry("UpperFilters".into())
            .or_insert_with(Key::empty);
        ck.sub_keys
            .entry("LowerFilters".into())
            .or_insert_with(Key::empty);
        ck.sub_keys
            .entry("Members".into())
            .or_insert_with(Key::empty);

        ck.values.entry("Version".into()).or_insert(Data::U32(1));
    }
}

/// Apply a single delta to the registry in-memory
fn apply_delta(reg: &mut Registry, delta: &RegDelta) {
    match delta {
        RegDelta::CreateKey { path } => {
            let mut node_map = &mut reg.root;
            for seg in path.split('/').filter(|s| !s.is_empty()) {
                node_map = &mut node_map
                    .entry(seg.to_string())
                    .or_insert_with(Key::empty)
                    .sub_keys;
            }
        }
        RegDelta::DeleteKey { path } => {
            let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if segs.is_empty() {
                return;
            }
            let (parent_segs, last) = segs.split_at(segs.len() - 1);

            let mut node_map = &mut reg.root;
            for seg in parent_segs {
                if let Some(key) = node_map.get_mut(*seg) {
                    node_map = &mut key.sub_keys;
                } else {
                    return;
                }
            }
            node_map.remove(last[0]);
        }
        RegDelta::SetValue {
            key_path,
            name,
            data,
        } => {
            if let Some(key) = walk_mut(&mut reg.root, key_path) {
                key.values.insert(name.clone(), data.clone());
            }
        }
        RegDelta::DeleteValue { key_path, name } => {
            if let Some(key) = walk_mut(&mut reg.root, key_path) {
                key.values.remove(name);
            }
        }
    }
}

/// Load snapshot from disk
async fn load_snapshot() -> Option<Registry> {
    let snap_path = snap_path();
    let mut f = File::open(&snap_path, &[OpenFlags::ReadWrite, OpenFlags::Open])
        .await
        .ok()?;
    let buf = f.read().await.ok()?;
    let (reg, _) =
        bincode::decode_from_slice::<Registry, _>(&buf, bincode::config::standard()).ok()?;
    Some(reg)
}

/// Save snapshot to disk
async fn save_snapshot(reg: &Registry) -> Result<(), kernel_types::status::RegError> {
    use kernel_types::status::RegError;

    let bytes = bincode::encode_to_vec(reg, bincode::config::standard())
        .map_err(|_| RegError::EncodingFailed)?;

    let snap_path = snap_path();
    let mut file = File::open(&snap_path, &[OpenFlags::ReadWrite, OpenFlags::Create]).await?;
    file.write(&bytes)
        .await
        .map_err(|_| RegError::EncodingFailed)?;
    Ok(())
}

/// Parse a single WAL record from bytes, returning (header, delta, bytes_consumed) or None
fn parse_wal_record(data: &[u8]) -> Option<(WalRecordHeader, RegDelta, usize)> {
    if data.len() < WalRecordHeader::SIZE {
        return None;
    }

    // Parse header fields manually (little-endian)
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != WAL_MAGIC {
        return None;
    }

    let version = u16::from_le_bytes([data[4], data[5]]);
    if version != WAL_VERSION {
        return None;
    }

    let kind = u16::from_le_bytes([data[6], data[7]]);
    let seq = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);
    let payload_len = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
    let payload_hash = u64::from_le_bytes([
        data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
    ]);

    let total_len = WalRecordHeader::SIZE + payload_len;
    if data.len() < total_len {
        return None;
    }

    let payload = &data[WalRecordHeader::SIZE..total_len];

    // Verify hash
    if fnv1a_hash(payload) != payload_hash {
        return None;
    }

    // Decode delta
    let (delta, _) =
        bincode::decode_from_slice::<RegDelta, _>(payload, bincode::config::standard()).ok()?;

    let header = WalRecordHeader {
        magic,
        version,
        kind,
        seq,
        payload_len: payload_len as u32,
        payload_hash,
    };

    Some((header, delta, total_len))
}

/// Load and replay WAL records, returning the highest sequence number seen
async fn replay_wal(reg: &mut Registry) -> u64 {
    let wal_path = wal_path();
    let f = match File::open(&wal_path, &[OpenFlags::ReadWrite, OpenFlags::Open]).await {
        Ok(f) => f,
        Err(_) => return 0,
    };

    let buf = match f.read().await {
        Ok(b) => b,
        Err(_) => return 0,
    };

    let mut offset = 0;
    let mut max_seq = 0u64;
    let mut count = 0u64;

    while offset < buf.len() {
        match parse_wal_record(&buf[offset..]) {
            Some((header, delta, consumed)) => {
                apply_delta(reg, &delta);
                max_seq = max_seq.max(header.seq);
                offset += consumed;
                count += 1;
            }
            None => break, // Stop at first invalid/partial record
        }
    }

    DELTAS_SINCE_SNAPSHOT.store(count, Ordering::Release);
    max_seq
}

/// Encode a WAL record to bytes
fn encode_wal_record(seq: u64, delta: &RegDelta) -> Result<Vec<u8>, ()> {
    let payload = bincode::encode_to_vec(delta, bincode::config::standard()).map_err(|_| ())?;
    let payload_hash = fnv1a_hash(&payload);

    let mut record = Vec::with_capacity(WalRecordHeader::SIZE + payload.len());

    // Write header
    record.extend_from_slice(&WAL_MAGIC.to_le_bytes());
    record.extend_from_slice(&WAL_VERSION.to_le_bytes());
    record.extend_from_slice(&0u16.to_le_bytes()); // kind (reserved)
    record.extend_from_slice(&seq.to_le_bytes());
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(&payload_hash.to_le_bytes());

    // Write payload
    record.extend_from_slice(&payload);

    Ok(record)
}

/// Append a delta to the WAL
async fn append_wal(delta: &RegDelta) -> Result<(), kernel_types::status::RegError> {
    use kernel_types::fs::FsSeekWhence;
    use kernel_types::status::RegError;

    let seq = WAL_SEQ.fetch_add(1, Ordering::SeqCst) + 1;
    let record = encode_wal_record(seq, delta).map_err(|_| RegError::EncodingFailed)?;

    let wal_path = wal_path();
    let mut file = File::open(&wal_path, &[OpenFlags::ReadWrite, OpenFlags::Create]).await?;

    file.seek(0, FsSeekWhence::End)
        .await
        .map_err(|_| RegError::EncodingFailed)?;

    file.write(&record)
        .await
        .map_err(|_| RegError::EncodingFailed)?;

    Ok(())
}
/// Clear the WAL file
async fn clear_wal() -> Result<(), kernel_types::status::RegError> {
    let wal_path = wal_path();
    if let Ok(mut file) = File::open(&wal_path, &[OpenFlags::ReadWrite, OpenFlags::Open]).await {
        let _ = file.delete().await;
    }

    let _ = File::open(&wal_path, &[OpenFlags::ReadWrite, OpenFlags::Create]).await?;
    Ok(())
}

/// Check if we should snapshot and do so if needed
async fn maybe_snapshot(reg: &Registry) -> Result<(), kernel_types::status::RegError> {
    let count = DELTAS_SINCE_SNAPSHOT.load(Ordering::Acquire);
    if count >= SNAPSHOT_DELTA_THRESHOLD {
        save_snapshot(reg).await?;
        clear_wal().await?;
        DELTAS_SINCE_SNAPSHOT.store(0, Ordering::Release);
    }
    Ok(())
}

async fn ensure_loaded() {
    if REGISTRY_INIT.load(Ordering::Acquire) {
        return;
    }

    let _guard = REGISTRY_INIT_LOCK.lock();

    if REGISTRY_INIT.load(Ordering::Acquire) {
        return;
    }

    // 1. Load latest valid snapshot (or empty)
    let mut reg = load_snapshot().await.unwrap_or_else(Registry::empty);

    // 2. Replay WAL
    let max_seq = replay_wal(&mut reg).await;
    WAL_SEQ.store(max_seq, Ordering::Release);

    // If no snapshot existed and no WAL, initialize defaults
    if reg.root.is_empty() {
        let system = reg.root.entry("SYSTEM".into()).or_insert_with(Key::empty);
        let setup = system
            .sub_keys
            .entry("SETUP".into())
            .or_insert_with(Key::empty);
        setup.values.insert("FirstBoot".into(), Data::Bool(true));
        init_class_catalog(&mut reg);

        // Save initial snapshot
        if let Err(_) = save_snapshot(&reg).await {
            // Log error but continue
        }
    }

    *REGISTRY.write() = Arc::new(reg);
    REGISTRY_INIT.store(true, Ordering::Release);
}

fn walk<'a>(root: &'a BTreeMap<String, Key>, path: &str) -> Option<&'a Key> {
    let mut node_map = root;
    let mut last: Option<&Key> = None;

    for seg in path.split('/').filter(|s| !s.is_empty()) {
        let k = node_map.get(seg)?;
        last = Some(k);
        node_map = &k.sub_keys;
    }

    last
}

fn walk_mut<'a>(root: &'a mut BTreeMap<String, Key>, path: &str) -> Option<&'a mut Key> {
    use core::ptr::NonNull;

    let mut node_map = root;
    let mut last: Option<NonNull<Key>> = None;

    for seg in path.split('/').filter(|s| !s.is_empty()) {
        let ptr = node_map.entry(seg.to_string()).or_insert_with(Key::empty) as *mut Key;
        last = NonNull::new(ptr);
        unsafe { node_map = &mut (*ptr).sub_keys };
    }

    last.map(|nn| unsafe { &mut *nn.as_ptr() })
}

pub mod reg {
    use kernel_types::status::{Data, RegError};

    use super::*;
    use crate::println;

    pub async fn get_key(path: &str) -> Option<Key> {
        ensure_loaded().await;
        walk(&REGISTRY.read().root, path).cloned()
    }

    pub async fn create_key(path: String) -> Result<(), RegError> {
        ensure_loaded().await;

        // Check if key already exists
        {
            let reg = REGISTRY.read();
            let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if !segs.is_empty() {
                let parent_path = segs[..segs.len() - 1].join("/");
                let last = segs[segs.len() - 1];
                if let Some(parent) = walk(&reg.root, &parent_path) {
                    if parent.sub_keys.contains_key(last) {
                        return Err(RegError::KeyAlreadyExists);
                    }
                } else if segs.len() == 1 && reg.root.contains_key(last) {
                    return Err(RegError::KeyAlreadyExists);
                }
            }
        }

        let delta = RegDelta::CreateKey { path: path.clone() };

        // Apply to in-memory registry
        {
            let mut new = (**REGISTRY.read()).clone();
            apply_delta(&mut new, &delta);
            *REGISTRY.write() = Arc::new(new);
        }

        // Append to WAL
        append_wal(&delta).await?;
        DELTAS_SINCE_SNAPSHOT.fetch_add(1, Ordering::SeqCst);

        // Maybe snapshot
        maybe_snapshot(&REGISTRY.read()).await?;

        Ok(())
    }

    pub async fn delete_key(path: &str) -> Result<bool, RegError> {
        ensure_loaded().await;

        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segs.is_empty() {
            return Ok(false);
        }

        // Check if key exists
        let exists = {
            let reg = REGISTRY.read();
            walk(&reg.root, path).is_some()
        };

        if !exists {
            return Ok(false);
        }

        let delta = RegDelta::DeleteKey {
            path: path.to_string(),
        };

        // Apply to in-memory registry
        {
            let mut new = (**REGISTRY.read()).clone();
            apply_delta(&mut new, &delta);
            *REGISTRY.write() = Arc::new(new);
        }

        // Append to WAL
        append_wal(&delta).await?;
        DELTAS_SINCE_SNAPSHOT.fetch_add(1, Ordering::SeqCst);

        // Maybe snapshot
        maybe_snapshot(&REGISTRY.read()).await?;

        Ok(true)
    }

    pub async fn get_value(key_path: &str, name: &str) -> Option<Data> {
        ensure_loaded().await;
        walk(&REGISTRY.read().root, key_path)
            .and_then(|k| k.values.get(name))
            .cloned()
    }

    pub async fn set_value(key_path: &str, name: &str, data: Data) -> Result<(), RegError> {
        ensure_loaded().await;

        // Verify key exists
        {
            let reg = REGISTRY.read();
            if walk(&reg.root, key_path).is_none() {
                return Err(RegError::KeyNotFound);
            }
        }

        let delta = RegDelta::SetValue {
            key_path: key_path.to_string(),
            name: name.to_string(),
            data: data.clone(),
        };

        // Apply to in-memory registry
        {
            let mut new = (**REGISTRY.read()).clone();
            apply_delta(&mut new, &delta);
            *REGISTRY.write() = Arc::new(new);
        }

        // Append to WAL
        append_wal(&delta).await?;
        DELTAS_SINCE_SNAPSHOT.fetch_add(1, Ordering::SeqCst);

        // Maybe snapshot
        maybe_snapshot(&REGISTRY.read()).await?;

        Ok(())
    }

    pub async fn delete_value(key_path: &str, name: &str) -> Result<bool, RegError> {
        ensure_loaded().await;

        // Check if value exists
        let exists = {
            let reg = REGISTRY.read();
            walk(&reg.root, key_path)
                .map(|k| k.values.contains_key(name))
                .unwrap_or(false)
        };

        if !exists {
            return Ok(false);
        }

        let delta = RegDelta::DeleteValue {
            key_path: key_path.to_string(),
            name: name.to_string(),
        };

        // Apply to in-memory registry
        {
            let mut new = (**REGISTRY.read()).clone();
            apply_delta(&mut new, &delta);
            *REGISTRY.write() = Arc::new(new);
        }

        // Append to WAL
        append_wal(&delta).await?;
        DELTAS_SINCE_SNAPSHOT.fetch_add(1, Ordering::SeqCst);

        // Maybe snapshot
        maybe_snapshot(&REGISTRY.read()).await?;

        Ok(true)
    }

    pub async fn print_tree() {
        fn dump(name: &str, key: &Key, depth: usize) {
            let mut indent = alloc::string::String::new();
            for _ in 0..depth {
                indent.push_str("  ");
            }
            println!("{}[{}]", indent, name);

            for (val_name, data) in &key.values {
                match data {
                    Data::U32(v) => println!("{}  {} = U32({})", indent, val_name, v),
                    Data::U64(v) => println!("{}  {} = U64({})", indent, val_name, v),
                    Data::I32(v) => println!("{}  {} = I32({})", indent, val_name, v),
                    Data::I64(v) => println!("{}  {} = I64({})", indent, val_name, v),
                    Data::Bool(v) => println!("{}  {} = Bool({})", indent, val_name, v),
                    Data::Str(s) => println!("{}  {} = Str(\"{}\")", indent, val_name, s),
                }
            }

            for (sub_name, sub_key) in &key.sub_keys {
                dump(sub_name, sub_key, depth + 1);
            }
        }

        ensure_loaded().await;
        let reg = REGISTRY.read();
        for (root_name, root_key) in &reg.root {
            dump(root_name, root_key, 0);
        }
    }

    /// Force a snapshot now (useful for graceful shutdown)
    pub async fn force_snapshot() -> Result<(), RegError> {
        ensure_loaded().await;
        let reg = REGISTRY.read();
        save_snapshot(&reg).await?;
        clear_wal().await?;
        DELTAS_SINCE_SNAPSHOT.store(0, Ordering::Release);
        Ok(())
    }

    pub async fn list_keys(base_path: &str) -> Result<Vec<String>, RegError> {
        fn join(base: &str, seg: &str) -> String {
            if base.is_empty() {
                seg.to_string()
            } else {
                alloc::format!("{}/{}", base, seg)
            }
        }
        fn dfs(prefix: &str, key: &Key, out: &mut Vec<String>) {
            for (name, sub) in &key.sub_keys {
                let abs = join(prefix, name);
                out.push(abs.clone());
                dfs(&abs, sub, out);
            }
        }

        ensure_loaded().await;
        let base_norm = base_path.trim_matches('/');
        let reg = REGISTRY.read();
        let start = if base_norm.is_empty() {
            let mut tmp = Key::empty();
            tmp.sub_keys = reg.root.clone();

            let mut v = Vec::new();
            dfs("", &tmp, &mut v);
            return Ok(v);
        } else {
            walk(&reg.root, base_norm).ok_or(RegError::KeyNotFound)?
        };

        let mut out = Vec::new();
        dfs(base_norm, start, &mut out);
        Ok(out)
    }

    pub async fn list_values(base_path: &str) -> Result<Vec<String>, RegError> {
        fn join(base: &str, seg: &str) -> String {
            if base.is_empty() {
                seg.to_string()
            } else {
                alloc::format!("{}/{}", base, seg)
            }
        }

        ensure_loaded().await;
        let base_norm = base_path.trim_matches('/');
        let reg = REGISTRY.read();

        if base_norm.is_empty() {
            return Ok(Vec::new());
        }

        let key = walk(&reg.root, base_norm).ok_or(RegError::KeyNotFound)?;
        let mut out = Vec::new();
        for (val_name, _) in &key.values {
            out.push(join(base_norm, val_name));
        }
        Ok(out)
    }

    fn diff_maps(base_path: &str, from: &Key, to: &Key, out: &mut Vec<RegDelta>) {
        for (k, v_to) in &to.values {
            match from.values.get(k) {
                Some(v_from) if v_from == v_to => {}
                _ => out.push(RegDelta::SetValue {
                    key_path: base_path.to_string(),
                    name: k.clone(),
                    data: v_to.clone(),
                }),
            }
        }
        for k in from.values.keys() {
            if !to.values.contains_key(k) {
                out.push(RegDelta::DeleteValue {
                    key_path: base_path.to_string(),
                    name: k.clone(),
                });
            }
        }

        for (name, sub_to) in &to.sub_keys {
            let child_path = if base_path.is_empty() {
                name.clone()
            } else {
                alloc::format!("{}/{}", base_path, name)
            };

            if let Some(sub_from) = from.sub_keys.get(name) {
                diff_maps(&child_path, sub_from, sub_to, out);
            } else {
                out.push(RegDelta::CreateKey {
                    path: child_path.clone(),
                });
                diff_maps(&child_path, &Key::empty(), sub_to, out);
            }
        }
        for (name, _) in &from.sub_keys {
            if !to.sub_keys.contains_key(name) {
                let child_path = if base_path.is_empty() {
                    name.clone()
                } else {
                    alloc::format!("{}/{}", base_path, name)
                };
                out.push(RegDelta::DeleteKey { path: child_path });
            }
        }
    }

    pub fn diff_registry(from: &Registry, to: &Registry) -> Vec<RegDelta> {
        let mut root_from = Key::empty();
        root_from.sub_keys = from.root.clone();
        let mut root_to = Key::empty();
        root_to.sub_keys = to.root.clone();

        let mut out = Vec::new();
        diff_maps("", &root_from, &root_to, &mut out);
        out
    }

    /// Get current WAL statistics
    pub fn wal_stats() -> (u64, u64) {
        (
            WAL_SEQ.load(Ordering::Acquire),
            DELTAS_SINCE_SNAPSHOT.load(Ordering::Acquire),
        )
    }
}

pub async fn is_first_boot() -> bool {
    matches!(
        reg::get_value("SYSTEM/SETUP", "FirstBoot").await,
        Some(Data::Bool(true))
    )
}

async fn append_wal_many(deltas: &[RegDelta]) -> Result<(), RegError> {
    if deltas.is_empty() {
        return Ok(());
    }

    let n = deltas.len() as u64;
    let start_seq = WAL_SEQ.fetch_add(n, Ordering::SeqCst) + 1;

    let mut buf = Vec::new();
    for (i, delta) in deltas.iter().enumerate() {
        let seq = start_seq + (i as u64);
        let rec = encode_wal_record(seq, delta).map_err(|_| RegError::EncodingFailed)?;
        buf.extend_from_slice(&rec);
    }

    let wal_path = wal_path();
    let mut file = File::open(&wal_path, &[OpenFlags::ReadWrite, OpenFlags::Create]).await?;
    file.seek(0, FsSeekWhence::End)
        .await
        .map_err(|_| RegError::EncodingFailed)?;
    file.write(&buf)
        .await
        .map_err(|_| RegError::EncodingFailed)?;
    Ok(())
}
/// Called after provider switch - replay in-memory WAL to disk, snapshot, clear WAL
pub async fn rebind_and_persist_after_provider_switch() -> Result<(), RegError> {
    ensure_loaded().await;

    let _ = File::make_dir(&Path::from_string("C:\\system\\registry")).await;

    let current = (**REGISTRY.read()).clone();

    let mut disk_reg = load_snapshot().await.unwrap_or_else(Registry::empty);
    let _ = replay_wal(&mut disk_reg).await;

    let deltas = reg::diff_registry(&disk_reg, &current);

    append_wal_many(&deltas).await?;

    save_snapshot(&current).await?;
    clear_wal().await?;
    DELTAS_SINCE_SNAPSHOT.store(0, Ordering::Release);

    Ok(())
}
