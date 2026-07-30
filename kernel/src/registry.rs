// We explictly use File::close everywhere here because its used in early boot and nested block on is forbiden.
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use kernel_types::async_types::AsyncMutex;
use kernel_types::error::{KernelError, RegistryErrorKind, ResultErrorContext};
use kernel_types::fs::{OpenFlags, Path};
use kernel_types::status::Data;
use prost::Message;
use registry_format::{CreateKey, DeleteKey, DeleteValue, Delta, Key, Registry, SetValue, Value};
use spin::{Once, RwLock};

use crate::error::error;
use crate::file_system::file::File;
use crate::println;

const REG_PATH: &str = "C:\\system\\registry\\registry.pb";
const WAL_PATH: &str = "C:\\system\\registry\\registry.wal";

const REGISTRY_SCHEMA_VERSION: u32 = 1;
const SNAPSHOT_VERSION: u32 = 1;
const WAL_VERSION: u32 = 2;

const SNAPSHOT_DELTA_THRESHOLD: u64 = 100;

const CLASS_LIST: &[(&str, &str)] = &[
    ("disk", "Block storage"),
    ("volume", "Mountable partitions"),
    ("kbd", "Keyboards"),
    ("mouse", "Pointing devices"),
    ("hid", "Human Interface Devices"),
    ("display", "Display controller"),
    ("gpu", "3D accelerator"),
    ("net", "Network adapters"),
    ("usb", "USB host controllers / hubs"),
    ("battery", "Battery / power sources"),
    ("wifi", "Wireless LAN"),
    ("serial", "Serial ports / UART"),
    ("parallel", "Parallel ports"),
];

#[derive(Clone, Debug, PartialEq)]
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

struct RegistryState {
    registry: Registry,
    wal_seq: u64,
    deltas_since_snapshot: u64,
}

struct RegistryStore {
    state: RwLock<RegistryState>,
    io: AsyncMutex<()>,
}

static REGISTRY: Once<RegistryStore> = Once::new();

struct WalReplay {
    max_seq: u64,
    applied: u64,
    valid_len: u64,
    file_len: u64,
}

fn value_from_data(data: &Data) -> Value {
    let value = match data {
        Data::U32(value) => registry_format::value::Value::U32(*value),
        Data::U64(value) => registry_format::value::Value::U64(*value),
        Data::I32(value) => registry_format::value::Value::I32(*value),
        Data::I64(value) => registry_format::value::Value::I64(*value),
        Data::Bool(value) => registry_format::value::Value::Bool(*value),
        Data::Str(value) => registry_format::value::Value::Str(value.clone()),
    };
    Value { value: Some(value) }
}

fn data_from_value(value: Value) -> Result<Data, KernelError> {
    match value
        .value
        .ok_or_else(|| error(RegistryErrorKind::EncodingFailed))?
    {
        registry_format::value::Value::U32(value) => Ok(Data::U32(value)),
        registry_format::value::Value::U64(value) => Ok(Data::U64(value)),
        registry_format::value::Value::I32(value) => Ok(Data::I32(value)),
        registry_format::value::Value::I64(value) => Ok(Data::I64(value)),
        registry_format::value::Value::Bool(value) => Ok(Data::Bool(value)),
        registry_format::value::Value::Str(value) => Ok(Data::Str(value)),
    }
}

impl RegistryStore {
    async fn create_key(&self, path: String) -> Result<(), KernelError> {
        let _io = self.io.lock().await;

        {
            let state = self.state.read();

            if path_parts(&path).next().is_none() {
                return Err(error(RegistryErrorKind::KeyAlreadyExists));
            }

            if walk(&state.registry, &path).is_some() {
                return Ok(());
            }
        }

        let seq = self.state.read().wal_seq + 1;

        let delta = Delta {
            delta: Some(registry_format::delta::Delta::CreateKey(CreateKey { path })),
        };

        append_wal(seq, &delta).await?;

        let Some(registry_format::delta::Delta::CreateKey(delta)) = delta.delta else {
            unreachable!();
        };

        {
            let mut state = self.state.write();

            create_key_inner(&mut state.registry, &delta.path);

            state.wal_seq = seq;
            state.deltas_since_snapshot += 1;
        }

        self.checkpoint_if_needed().await;

        Ok(())
    }

    async fn delete_key(&self, path: &str) -> Result<bool, KernelError> {
        let _io = self.io.lock().await;

        if walk(&self.state.read().registry, path).is_none() {
            return Ok(false);
        }

        let seq = self.state.read().wal_seq + 1;

        let delta = Delta {
            delta: Some(registry_format::delta::Delta::DeleteKey(DeleteKey {
                path: path.to_string(),
            })),
        };

        append_wal(seq, &delta).await?;

        {
            let mut state = self.state.write();

            delete_key_inner(&mut state.registry, path);

            state.wal_seq = seq;
            state.deltas_since_snapshot += 1;
        }

        self.checkpoint_if_needed().await;

        Ok(true)
    }

    async fn set_value(&self, key_path: &str, name: &str, data: Data) -> Result<(), KernelError> {
        let _io = self.io.lock().await;

        {
            let state = self.state.read();
            let key = walk(&state.registry, key_path)
                .ok_or_else(|| error(RegistryErrorKind::KeyNotFound))?;

            if key.values.get(name) == Some(&value_from_data(&data)) {
                return Ok(());
            }
        }

        let seq = self.state.read().wal_seq + 1;

        let delta = Delta {
            delta: Some(registry_format::delta::Delta::SetValue(SetValue {
                key_path: key_path.to_string(),
                name: name.to_string(),
                data: Some(value_from_data(&data)),
            })),
        };

        append_wal(seq, &delta).await?;

        {
            let mut state = self.state.write();
            let key = walk_mut(&mut state.registry, key_path)
                .ok_or_else(|| error(RegistryErrorKind::KeyNotFound))?;

            key.values.insert(name.to_string(), value_from_data(&data));

            state.wal_seq = seq;
            state.deltas_since_snapshot += 1;
        }

        self.checkpoint_if_needed().await;

        Ok(())
    }

    async fn delete_value(&self, key_path: &str, name: &str) -> Result<bool, KernelError> {
        let _io = self.io.lock().await;

        {
            let state = self.state.read();

            if walk(&state.registry, key_path)
                .and_then(|key| key.values.get(name))
                .is_none()
            {
                return Ok(false);
            }
        }

        let seq = self.state.read().wal_seq + 1;

        let delta = Delta {
            delta: Some(registry_format::delta::Delta::DeleteValue(DeleteValue {
                key_path: key_path.to_string(),
                name: name.to_string(),
            })),
        };

        append_wal(seq, &delta).await?;

        {
            let mut state = self.state.write();

            if let Some(key) = walk_mut(&mut state.registry, key_path) {
                key.values.remove(name);
            }

            state.wal_seq = seq;
            state.deltas_since_snapshot += 1;
        }

        self.checkpoint_if_needed().await;

        Ok(true)
    }

    async fn checkpoint_if_needed(&self) {
        let bytes = {
            let state = self.state.read();

            if state.deltas_since_snapshot < SNAPSHOT_DELTA_THRESHOLD {
                return;
            }

            match encode_snapshot(&state.registry, state.wal_seq) {
                Ok(bytes) => bytes,
                Err(_) => return,
            }
        };

        if persist_snapshot(&bytes).await.is_err() {
            return;
        }

        if clear_wal().await.is_err() {
            return;
        }

        self.state.write().deltas_since_snapshot = 0;
    }
}

fn path_parts(path: &str) -> impl Iterator<Item = &str> {
    path.split(|ch| ch == '/' || ch == '\\')
        .filter(|part| !part.is_empty())
}

fn walk<'a>(registry: &'a Registry, path: &str) -> Option<&'a Key> {
    let mut parts = path_parts(path);
    let mut key = registry.root.get(parts.next()?)?;

    for part in parts {
        key = key.sub_keys.get(part)?;
    }

    Some(key)
}

fn walk_mut<'a>(registry: &'a mut Registry, path: &str) -> Option<&'a mut Key> {
    let mut parts = path_parts(path);
    let mut key = registry.root.get_mut(parts.next()?)?;

    for part in parts {
        key = key.sub_keys.get_mut(part)?;
    }

    Some(key)
}

fn get_or_create_key_mut<'a>(registry: &'a mut Registry, path: &str) -> Option<&'a mut Key> {
    let mut parts = path_parts(path);
    let mut key = registry.root.entry(parts.next()?.to_string()).or_default();

    for part in parts {
        key = key.sub_keys.entry(part.to_string()).or_default();
    }

    Some(key)
}

fn create_key_inner(registry: &mut Registry, path: &str) {
    let mut parts = path_parts(path);

    let Some(first) = parts.next() else {
        return;
    };

    let mut key = registry.root.entry(first.to_string()).or_default();

    for part in parts {
        key = key.sub_keys.entry(part.to_string()).or_default();
    }
}

fn delete_key_inner(registry: &mut Registry, path: &str) -> bool {
    let mut parts = path_parts(path).peekable();

    let Some(first) = parts.next() else {
        return false;
    };

    if parts.peek().is_none() {
        return registry.root.remove(first).is_some();
    }

    let Some(mut key) = registry.root.get_mut(first) else {
        return false;
    };

    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return key.sub_keys.remove(part).is_some();
        }

        let Some(next) = key.sub_keys.get_mut(part) else {
            return false;
        };

        key = next;
    }

    false
}

fn fresh_registry() -> Registry {
    let mut registry = Registry {
        schema_version: REGISTRY_SCHEMA_VERSION,
        ..Registry::default()
    };

    get_or_create_key_mut(&mut registry, "SYSTEM/SETUP")
        .unwrap()
        .values
        .insert("FirstBoot".to_string(), value_from_data(&Data::Bool(true)));

    for (class, description) in CLASS_LIST {
        let path = format!("SYSTEM/CurrentControlSet/Class/{class}");
        let key = get_or_create_key_mut(&mut registry, &path).unwrap();

        key.values.insert(
            "Class".to_string(),
            value_from_data(&Data::Str(String::new())),
        );

        key.values.insert(
            "Description".to_string(),
            value_from_data(&Data::Str((*description).to_string())),
        );

        key.values
            .insert("Version".to_string(), value_from_data(&Data::U32(1)));

        key.sub_keys.entry("UpperFilters".to_string()).or_default();

        key.sub_keys.entry("LowerFilters".to_string()).or_default();

        key.sub_keys.entry("Members".to_string()).or_default();
    }

    registry
}

fn encode_snapshot(registry: &Registry, last_wal_seq: u64) -> Result<Vec<u8>, KernelError> {
    registry_format::encode_frame(SNAPSHOT_VERSION, last_wal_seq, registry)
        .map_err(|_| error(RegistryErrorKind::EncodingFailed))
}

fn decode_snapshot(bytes: &[u8]) -> Result<(Registry, u64), KernelError> {
    let (last_wal_seq, payload, frame_len) = registry_format::decode_frame(bytes, SNAPSHOT_VERSION)
        .map_err(|_| error(RegistryErrorKind::EncodingFailed))?;

    if frame_len != bytes.len() {
        return Err(error(RegistryErrorKind::EncodingFailed));
    }

    let registry =
        Registry::decode(payload).map_err(|_| error(RegistryErrorKind::EncodingFailed))?;
    if registry.schema_version != REGISTRY_SCHEMA_VERSION {
        return Err(error(RegistryErrorKind::EncodingFailed));
    }

    Ok((registry, last_wal_seq))
}

async fn read_file(path: &str) -> Result<Vec<u8>, KernelError> {
    let file = File::open(
        &Path::from_string(path),
        &[OpenFlags::Open, OpenFlags::ReadOnly],
    )
    .await?;

    let mut bytes = alloc::vec![0; file.size as usize];

    let read = match file.read(&mut bytes).await {
        Ok(read) => read,
        Err(error) => {
            return Err(close_preserving_error(file, error, "after a registry read failed").await);
        }
    };

    file.close().await?;

    bytes.truncate(read);

    Ok(bytes)
}

async fn close_preserving_error(file: File, error: KernelError, context: &str) -> KernelError {
    match file.close().await {
        Ok(()) => error,
        Err(close_error) => error.with_related_error(
            format!("{context}; closing the registry file also failed"),
            close_error,
        ),
    }
}

async fn load_best_snapshot() -> Result<(Registry, u64), KernelError> {
    let bytes = read_file(REG_PATH).await?;
    decode_snapshot(&bytes)
}

async fn persist_snapshot(bytes: &[u8]) -> Result<(), KernelError> {
    let mut file = match File::open(
        &Path::from_string(REG_PATH),
        &[OpenFlags::Create, OpenFlags::WriteThrough],
    )
    .await
    {
        Ok(file) => file,

        Err(error)
            if error.kind()
                == kernel_types::error::ErrorKind::File(
                    kernel_types::error::FileErrorKind::AlreadyExists,
                ) =>
        {
            File::open(
                &Path::from_string(REG_PATH),
                &[
                    OpenFlags::Open,
                    OpenFlags::ReadWrite,
                    OpenFlags::WriteThrough,
                ],
            )
            .await?
        }
        Err(error) => {
            return Err(error.with_context("creating the registry snapshot file"));
        }
    };

    if let Err(error) = file.set_len(0).await {
        return Err(
            close_preserving_error(file, error, "after truncating the snapshot failed").await,
        );
    }

    let written = match file.write_at(0, bytes).await {
        Ok(written) => written,
        Err(error) => {
            return Err(
                close_preserving_error(file, error, "after writing the snapshot failed").await,
            );
        }
    };

    if written != bytes.len() {
        let error = error(RegistryErrorKind::PersistenceFailed).with_context(format!(
            "snapshot write was short: wrote {written} of {} bytes",
            bytes.len()
        ));
        return Err(close_preserving_error(file, error, "after a short snapshot write").await);
    }

    file.close().await?;

    Ok(())
}

async fn append_wal(seq: u64, delta: &Delta) -> Result<(), KernelError> {
    let record = registry_format::encode_frame(WAL_VERSION, seq, delta)
        .map_err(|_| error(RegistryErrorKind::EncodingFailed))?;

    let mut file = match File::open(
        &Path::from_string(WAL_PATH),
        &[OpenFlags::Create, OpenFlags::WriteThrough],
    )
    .await
    {
        Ok(file) => file,

        Err(error)
            if error.kind()
                == kernel_types::error::ErrorKind::File(
                    kernel_types::error::FileErrorKind::AlreadyExists,
                ) =>
        {
            File::open(
                &Path::from_string(WAL_PATH),
                &[
                    OpenFlags::Open,
                    OpenFlags::ReadWrite,
                    OpenFlags::WriteThrough,
                ],
            )
            .await?
        }
        Err(error) => {
            return Err(error.with_context("creating the registry WAL file"));
        }
    };

    let original_len = file.size;

    let written = match file.append(&record).await {
        Ok(written) => written,
        Err(error) => {
            return Err(
                close_preserving_error(file, error, "after appending the WAL failed").await,
            );
        }
    };

    if written != record.len() {
        let mut error = error(RegistryErrorKind::PersistenceFailed).with_context(format!(
            "WAL append was short: wrote {written} of {} bytes",
            record.len()
        ));
        if let Err(restore_error) = file.set_len(original_len).await {
            error = error.with_context(format!(
                "restoring the WAL to {original_len} bytes also failed: {restore_error}"
            ));
        }
        return Err(close_preserving_error(file, error, "after a short WAL append").await);
    }

    file.close().await?;

    Ok(())
}

async fn clear_wal() -> Result<(), KernelError> {
    let mut file = match File::open(
        &Path::from_string(WAL_PATH),
        &[
            OpenFlags::Open,
            OpenFlags::ReadWrite,
            OpenFlags::WriteThrough,
        ],
    )
    .await
    {
        Ok(file) => file,
        Err(error)
            if error.kind()
                == kernel_types::error::ErrorKind::File(
                    kernel_types::error::FileErrorKind::PathNotFound,
                ) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error.with_context("opening the WAL for clearing")),
    };

    if let Err(error) = file.set_len(0).await {
        return Err(close_preserving_error(file, error, "after clearing the WAL failed").await);
    }

    file.close().await?;

    Ok(())
}

async fn truncate_wal(len: u64) -> Result<(), KernelError> {
    let mut file = File::open(
        &Path::from_string(WAL_PATH),
        &[
            OpenFlags::Open,
            OpenFlags::ReadWrite,
            OpenFlags::WriteThrough,
        ],
    )
    .await?;

    if let Err(error) = file.set_len(len).await {
        return Err(close_preserving_error(file, error, "after truncating the WAL failed").await);
    }

    file.close().await?;

    Ok(())
}

fn apply_wal_delta(registry: &mut Registry, delta: Delta) -> Result<(), KernelError> {
    match delta
        .delta
        .ok_or_else(|| error(RegistryErrorKind::EncodingFailed))?
    {
        registry_format::delta::Delta::CreateKey(delta) => {
            if path_parts(&delta.path).next().is_none() {
                return Err(error(RegistryErrorKind::EncodingFailed));
            }

            create_key_inner(registry, &delta.path);
        }

        registry_format::delta::Delta::DeleteKey(delta) => {
            delete_key_inner(registry, &delta.path);
        }

        registry_format::delta::Delta::SetValue(delta) => {
            let key = walk_mut(registry, &delta.key_path)
                .ok_or_else(|| error(RegistryErrorKind::KeyNotFound))?;

            key.values.insert(
                delta.name,
                delta
                    .data
                    .ok_or_else(|| error(RegistryErrorKind::EncodingFailed))?,
            );
        }

        registry_format::delta::Delta::DeleteValue(delta) => {
            if let Some(key) = walk_mut(registry, &delta.key_path) {
                key.values.remove(&delta.name);
            }
        }
    }

    Ok(())
}

async fn replay_wal(registry: &mut Registry, snapshot_seq: u64) -> Result<WalReplay, KernelError> {
    let bytes = match read_file(WAL_PATH).await {
        Ok(bytes) => bytes,

        Err(_) => {
            return Ok(WalReplay {
                max_seq: snapshot_seq,
                applied: 0,
                valid_len: 0,
                file_len: 0,
            });
        }
    };

    let mut offset = 0;
    let mut previous_seq = None;
    let mut max_seq = snapshot_seq;
    let mut applied = 0;

    while offset < bytes.len() {
        let Ok((seq, payload, frame_len)) =
            registry_format::decode_frame(&bytes[offset..], WAL_VERSION)
        else {
            break;
        };

        if previous_seq.is_some_and(|previous| seq <= previous) {
            break;
        }

        if seq > snapshot_seq {
            if max_seq == u64::MAX || seq != max_seq + 1 {
                break;
            }

            let Ok(delta) = Delta::decode(payload) else {
                break;
            };

            if apply_wal_delta(registry, delta).is_err() {
                break;
            }

            max_seq = seq;
            applied += 1;
        }

        previous_seq = Some(seq);
        offset += frame_len;
    }

    Ok(WalReplay {
        max_seq,
        applied,
        valid_len: offset as u64,
        file_len: bytes.len() as u64,
    })
}

async fn load_registry_state() -> Result<RegistryState, KernelError> {
    let (mut registry, snapshot_seq) = match load_best_snapshot().await {
        Ok(snapshot) => snapshot,

        Err(_) => {
            let registry = fresh_registry();
            let bytes = encode_snapshot(&registry, 0)?;

            persist_snapshot(&bytes).await?;
            clear_wal().await?;

            return Ok(RegistryState {
                registry,
                wal_seq: 0,
                deltas_since_snapshot: 0,
            });
        }
    };

    let replay = replay_wal(&mut registry, snapshot_seq).await?;

    if replay.valid_len < replay.file_len {
        truncate_wal(replay.valid_len).await?;
    }

    Ok(RegistryState {
        registry,
        wal_seq: replay.max_seq,
        deltas_since_snapshot: replay.applied,
    })
}

pub async fn init() -> Result<(), KernelError> {
    if REGISTRY.get().is_some() {
        return Ok(());
    }

    let state = load_registry_state().await?;

    REGISTRY.call_once(|| RegistryStore {
        state: RwLock::new(state),
        io: AsyncMutex::new(()),
    });

    Ok(())
}

fn join_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{base}/{name}")
    }
}

fn emit_created_tree(path: &str, key: &Key, out: &mut Vec<RegDelta>) {
    out.push(RegDelta::CreateKey {
        path: path.to_string(),
    });

    for (name, data) in &key.values {
        out.push(RegDelta::SetValue {
            key_path: path.to_string(),
            name: name.clone(),
            data: data_from_value(data.clone())
                .expect("registry contains a value without a value kind"),
        });
    }

    for (name, child) in &key.sub_keys {
        emit_created_tree(&join_path(path, name), child, out);
    }
}

fn diff_key(path: &str, from: &Key, to: &Key, out: &mut Vec<RegDelta>) {
    for (name, value) in &from.values {
        match to.values.get(name) {
            None => out.push(RegDelta::DeleteValue {
                key_path: path.to_string(),
                name: name.clone(),
            }),

            Some(next) if next != value => out.push(RegDelta::SetValue {
                key_path: path.to_string(),
                name: name.clone(),
                data: data_from_value(next.clone())
                    .expect("registry contains a value without a value kind"),
            }),

            Some(_) => {}
        }
    }

    for (name, value) in &to.values {
        if !from.values.contains_key(name) {
            out.push(RegDelta::SetValue {
                key_path: path.to_string(),
                name: name.clone(),
                data: data_from_value(value.clone())
                    .expect("registry contains a value without a value kind"),
            });
        }
    }

    for name in from.sub_keys.keys() {
        if !to.sub_keys.contains_key(name) {
            out.push(RegDelta::DeleteKey {
                path: join_path(path, name),
            });
        }
    }

    for (name, key) in &to.sub_keys {
        let child_path = join_path(path, name);

        match from.sub_keys.get(name) {
            Some(previous) => {
                diff_key(&child_path, previous, key, out);
            }

            None => {
                emit_created_tree(&child_path, key, out);
            }
        }
    }
}

pub fn diff_registry(from: &Registry, to: &Registry) -> Vec<RegDelta> {
    let mut deltas = Vec::new();

    for name in from.root.keys() {
        if !to.root.contains_key(name) {
            deltas.push(RegDelta::DeleteKey { path: name.clone() });
        }
    }

    for (name, key) in &to.root {
        match from.root.get(name) {
            Some(previous) => {
                diff_key(name, previous, key, &mut deltas);
            }

            None => {
                emit_created_tree(name, key, &mut deltas);
            }
        }
    }

    deltas
}

fn print_key(name: &str, key: &Key, depth: usize) {
    let indent = "  ".repeat(depth);

    println!("{}{}", indent, name);

    for (value_name, value) in &key.values {
        println!("{}  {} = {:?}", indent, value_name, value);
    }

    for (child_name, child) in &key.sub_keys {
        print_key(child_name, child, depth + 1);
    }
}

pub mod reg {
    use super::*;

    pub async fn get_key(path: &str) -> Option<Key> {
        let store = REGISTRY.get()?;
        walk(&store.state.read().registry, path).cloned()
    }

    pub async fn create_key(path: String) -> Result<(), KernelError> {
        REGISTRY
            .get()
            .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?
            .create_key(path)
            .await
    }

    pub async fn delete_key(path: &str) -> Result<bool, KernelError> {
        REGISTRY
            .get()
            .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?
            .delete_key(path)
            .await
    }

    pub async fn get_value(key_path: &str, name: &str) -> Option<Data> {
        let store = REGISTRY.get()?;
        let state = store.state.read();

        data_from_value(walk(&state.registry, key_path)?.values.get(name)?.clone()).ok()
    }

    pub async fn set_value(key_path: &str, name: &str, data: Data) -> Result<(), KernelError> {
        REGISTRY
            .get()
            .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?
            .set_value(key_path, name, data)
            .await
    }

    pub async fn delete_value(key_path: &str, name: &str) -> Result<bool, KernelError> {
        REGISTRY
            .get()
            .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?
            .delete_value(key_path, name)
            .await
    }

    pub async fn print_tree() {
        let Some(store) = REGISTRY.get() else {
            return;
        };

        let state = store.state.read();

        for (name, key) in &state.registry.root {
            print_key(name, key, 0);
        }
    }

    pub async fn list_keys(base_path: &str) -> Result<Vec<String>, KernelError> {
        let store = REGISTRY
            .get()
            .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?;

        let state = store.state.read();

        let key = walk(&state.registry, base_path)
            .ok_or_else(|| error(RegistryErrorKind::KeyNotFound))?;

        Ok(key
            .sub_keys
            .keys()
            .map(|name| join_path(base_path, name))
            .collect())
    }

    pub async fn list_values(base_path: &str) -> Result<Vec<String>, KernelError> {
        let store = REGISTRY
            .get()
            .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?;

        let state = store.state.read();

        let key = walk(&state.registry, base_path)
            .ok_or_else(|| error(RegistryErrorKind::KeyNotFound))?;

        Ok(key.values.keys().cloned().collect())
    }
}

pub async fn rebind_and_persist_after_provider_switch() -> Result<(), KernelError> {
    let store = REGISTRY
        .get()
        .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?;

    let _io = store.io.lock().await;

    let bytes = {
        let state = store.state.read();
        encode_snapshot(&state.registry, state.wal_seq)?
    };

    persist_snapshot(&bytes).await?;
    clear_wal().await?;

    store.state.write().deltas_since_snapshot = 0;

    Ok(())
}

pub async fn is_first_boot() -> bool {
    matches!(
        reg::get_value("SYSTEM/SETUP", "FirstBoot").await,
        Some(Data::Bool(true))
    )
}
