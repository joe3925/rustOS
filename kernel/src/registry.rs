// We explictly use File::close everywhere here because its used in early boot and nested block on is forbiden.
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use kernel_types::async_types::AsyncMutex;
use kernel_types::error::{KernelError, RegistryErrorKind, ResultErrorContext};
use kernel_types::fs::{OpenFlags, Path};
use kernel_types::status::Data;
use prost::Message;
use registry_format::{
    BootOwnership, CreateKey, DeleteKey, DeleteValue, Delta, Key, Registry, RegistryBatch,
    RegistrySnapshot, SetValue, Value,
};
use spin::{Once, RwLock};

use crate::error::error;
use crate::file_system::file::File;
use crate::println;

const REG_PATH: &str = "C:\\system\\registry\\registry.pb";
const WAL_PATH: &str = "C:\\system\\registry\\registry.wal";

const REGISTRY_SCHEMA_VERSION: u32 = 1;
const SNAPSHOT_VERSION: u32 = 1;
const WAL_VERSION: u32 = 2;

const SNAPSHOT_PATHS: [&str; 2] = [
    "C:\\system\\registry\\registry.0.pb",
    "C:\\system\\registry\\registry.1.pb",
];
const OWNED_SNAPSHOT_VERSION: u32 = 2;
const MIN_CHECKPOINT_BYTES: u64 = 256 * 1024;
use crate::file_system::file_provider::{Provider, ProviderKind, install_file_provider};

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
    bootstrap: bool,
    ownership: BootOwnership,
    boot_deletes: Vec<Delta>,
    wal_bytes: u64,
    snapshot_slot: Option<usize>,
}

struct RegistryStore {
    state: RwLock<RegistryState>,
    io: AsyncMutex<RegistryIo>,
}

#[derive(Default)]
struct RegistryIo {
    wal: Option<File>,
}

static REGISTRY: Once<RegistryStore> = Once::new();

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
        let mut io = self.io.lock().await;

        {
            let state = self.state.read();

            if path_parts(&path).next().is_none() {
                return Err(error(RegistryErrorKind::KeyAlreadyExists));
            }

            if walk(&state.registry, &path).is_some() {
                return Ok(());
            }
        }

        let seq = self
            .state
            .read()
            .wal_seq
            .checked_add(1)
            .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?;

        let delta = Delta {
            delta: Some(registry_format::delta::Delta::CreateKey(CreateKey { path })),
        };

        if !self.state.read().bootstrap {
            append_wal(&mut io, seq, &delta).await?;
        }

        let Some(registry_format::delta::Delta::CreateKey(delta)) = delta.delta else {
            unreachable!();
        };

        {
            let mut state = self.state.write();

            create_key_inner(&mut state.registry, &delta.path);

            state.wal_seq = seq;
            state.deltas_since_snapshot += 1;
            if !state.bootstrap {
                state.wal_bytes = io.wal.as_ref().map_or(0, |f| f.size);
            }
        }

        self.checkpoint_if_needed(&mut io).await;

        Ok(())
    }

    async fn delete_key(&self, path: &str) -> Result<bool, KernelError> {
        let mut io = self.io.lock().await;
        {
            let mut state = self.state.write();
            if state.bootstrap {
                state.boot_deletes.push(Delta {
                    delta: Some(registry_format::delta::Delta::DeleteKey(DeleteKey {
                        path: registry_format::reconcile::canonical_path(path),
                    })),
                });
            }
        }

        if walk(&self.state.read().registry, path).is_none() {
            return Ok(false);
        }

        let seq = self
            .state
            .read()
            .wal_seq
            .checked_add(1)
            .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?;

        let delta = Delta {
            delta: Some(registry_format::delta::Delta::DeleteKey(DeleteKey {
                path: path.to_string(),
            })),
        };

        if !self.state.read().bootstrap {
            append_wal(&mut io, seq, &delta).await?;
        }

        {
            let mut state = self.state.write();

            delete_key_inner(&mut state.registry, path);

            state.wal_seq = seq;
            state.deltas_since_snapshot += 1;
            if !state.bootstrap {
                state.wal_bytes = io.wal.as_ref().map_or(0, |f| f.size);
            }
        }

        self.checkpoint_if_needed(&mut io).await;

        Ok(true)
    }

    async fn set_value(&self, key_path: &str, name: &str, data: Data) -> Result<(), KernelError> {
        let mut io = self.io.lock().await;

        {
            let state = self.state.read();
            let key = walk(&state.registry, key_path)
                .ok_or_else(|| error(RegistryErrorKind::KeyNotFound))?;

            if key.values.get(name) == Some(&value_from_data(&data)) {
                return Ok(());
            }
        }

        let seq = self
            .state
            .read()
            .wal_seq
            .checked_add(1)
            .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?;

        let delta = Delta {
            delta: Some(registry_format::delta::Delta::SetValue(SetValue {
                key_path: key_path.to_string(),
                name: name.to_string(),
                data: Some(value_from_data(&data)),
            })),
        };

        if !self.state.read().bootstrap {
            append_wal(&mut io, seq, &delta).await?;
        }

        {
            let mut state = self.state.write();
            let key = walk_mut(&mut state.registry, key_path)
                .ok_or_else(|| error(RegistryErrorKind::KeyNotFound))?;

            key.values.insert(name.to_string(), value_from_data(&data));

            state.wal_seq = seq;
            state.deltas_since_snapshot += 1;
            if !state.bootstrap {
                state.wal_bytes = io.wal.as_ref().map_or(0, |f| f.size);
            }
        }

        self.checkpoint_if_needed(&mut io).await;

        Ok(())
    }

    async fn delete_value(&self, key_path: &str, name: &str) -> Result<bool, KernelError> {
        let mut io = self.io.lock().await;
        {
            let mut state = self.state.write();
            if state.bootstrap {
                state.boot_deletes.push(Delta {
                    delta: Some(registry_format::delta::Delta::DeleteValue(DeleteValue {
                        key_path: registry_format::reconcile::canonical_path(key_path),
                        name: name.to_string(),
                    })),
                });
            }
        }

        {
            let state = self.state.read();

            if walk(&state.registry, key_path)
                .and_then(|key| key.values.get(name))
                .is_none()
            {
                return Ok(false);
            }
        }

        let seq = self
            .state
            .read()
            .wal_seq
            .checked_add(1)
            .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?;

        let delta = Delta {
            delta: Some(registry_format::delta::Delta::DeleteValue(DeleteValue {
                key_path: key_path.to_string(),
                name: name.to_string(),
            })),
        };

        if !self.state.read().bootstrap {
            append_wal(&mut io, seq, &delta).await?;
        }

        {
            let mut state = self.state.write();

            if let Some(key) = walk_mut(&mut state.registry, key_path) {
                key.values.remove(name);
            }

            state.wal_seq = seq;
            state.deltas_since_snapshot += 1;
            if !state.bootstrap {
                state.wal_bytes = io.wal.as_ref().map_or(0, |f| f.size);
            }
        }

        self.checkpoint_if_needed(&mut io).await;

        Ok(true)
    }

    async fn checkpoint_if_needed(&self, io: &mut RegistryIo) {
        let (bytes, slot) = {
            let state = self.state.read();
            if state.bootstrap || state.wal_bytes < MIN_CHECKPOINT_BYTES {
                return;
            }
            let Ok(bytes) = encode_owned_snapshot(&state) else {
                return;
            };
            if state.wal_bytes <= (bytes.len() as u64).max(MIN_CHECKPOINT_BYTES) {
                return;
            }
            (bytes, state.snapshot_slot.map_or(0, |slot| 1 - slot))
        };
        if persist_snapshot_at(SNAPSHOT_PATHS[slot], &bytes)
            .await
            .is_err()
        {
            return;
        }
        // Publish the new slot before clearing the log. Either log state can
        // be replayed with this durable snapshot after an interrupted clear.
        self.state.write().snapshot_slot = Some(slot);
        if let Some(file) = io.wal.as_mut() {
            if file.set_len(0).await.is_err() || file.flush().await.is_err() {
                return;
            }
        }
        let mut state = self.state.write();
        state.wal_bytes = 0;
        state.deltas_since_snapshot = 0;
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
    let file = File::open_on(
        Provider::Vfs,
        &Path::from_string(path),
        &[OpenFlags::Open, OpenFlags::ReadOnly],
    )
    .await?;

    let mut bytes = alloc::vec![0; file.size as usize];

    let mut offset = 0;
    while offset < bytes.len() {
        match file.read_at(offset as u64, &mut bytes[offset..]).await {
            Ok(0) => {
                return Err(close_preserving_error(
                    file,
                    error(RegistryErrorKind::EncodingFailed),
                    "unexpected end of registry file",
                )
                .await);
            }
            Ok(n) => offset += n,
            Err(error) => {
                return Err(close_preserving_error(file, error, "reading registry file").await);
            }
        }
    }
    file.close().await?;

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

async fn persist_snapshot_at(path: &str, bytes: &[u8]) -> Result<(), KernelError> {
    let mut file = match File::open_on(
        Provider::Vfs,
        &Path::from_string(path),
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
            File::open_on(
                Provider::Vfs,
                &Path::from_string(path),
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

    if let Err(error) = file.flush().await {
        return Err(close_preserving_error(file, error, "flushing snapshot").await);
    }
    file.close().await?;

    Ok(())
}

fn missing(error: &KernelError) -> bool {
    error.kind()
        == kernel_types::error::ErrorKind::File(kernel_types::error::FileErrorKind::PathNotFound)
}

async fn open_wal() -> Result<File, KernelError> {
    let path = Path::from_string(WAL_PATH);
    match File::open_on(
        Provider::Vfs,
        &path,
        &[
            OpenFlags::Open,
            OpenFlags::ReadWrite,
            OpenFlags::WriteThrough,
        ],
    )
    .await
    {
        Ok(file) => Ok(file),
        Err(error) if missing(&error) => {
            File::open_on(
                Provider::Vfs,
                &path,
                &[OpenFlags::Create, OpenFlags::WriteThrough],
            )
            .await
        }
        Err(error) => Err(error),
    }
}

async fn append_wal(io: &mut RegistryIo, seq: u64, delta: &Delta) -> Result<(), KernelError> {
    let record = registry_format::encode_frame(WAL_VERSION, seq, delta)
        .map_err(|_| error(RegistryErrorKind::EncodingFailed))?;
    if io.wal.is_none() {
        io.wal = Some(open_wal().await?);
    }
    let file = io.wal.as_mut().unwrap();
    let original_len = file.size;
    let result = match file.append(&record).await {
        Ok(n) if n == record.len() => file.flush().await,
        Ok(_) => Err(error(RegistryErrorKind::PersistenceFailed).with_context("short WAL append")),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        // Never append beyond a failed/torn record on a subsequent operation.
        if file.set_len(original_len).await.is_err() || file.flush().await.is_err() {
            panic!("registry WAL rollback failed after: {error}");
        }
        return Err(error);
    }
    Ok(())
}

fn encode_owned_snapshot(state: &RegistryState) -> Result<Vec<u8>, KernelError> {
    registry_format::encode_frame(
        OWNED_SNAPSHOT_VERSION,
        state.wal_seq,
        &RegistrySnapshot {
            registry: Some(state.registry.clone()),
            boot_ownership: Some(state.ownership.clone()),
        },
    )
    .map_err(|_| error(RegistryErrorKind::EncodingFailed))
}

fn empty_state(registry: Registry, bootstrap: bool) -> RegistryState {
    RegistryState {
        registry,
        wal_seq: 0,
        deltas_since_snapshot: 0,
        bootstrap,
        ownership: BootOwnership::default(),
        boot_deletes: Vec::new(),
        wal_bytes: 0,
        snapshot_slot: None,
    }
}

async fn load_registry_state() -> Result<(RegistryState, u64, bool), KernelError> {
    let mut best: Option<RegistryState> = None;
    let mut corrupt = false;
    for (slot, path) in SNAPSHOT_PATHS.iter().enumerate() {
        let bytes = match read_file(path).await {
            Ok(bytes) => bytes,
            Err(error) if missing(&error) => continue,
            Err(error) => return Err(error),
        };
        let decoded = (|| {
            let (seq, registry, ownership) =
                registry_format::reconcile::decode_owned_snapshot(&bytes, REGISTRY_SCHEMA_VERSION)
                    .ok()?;
            let mut state = empty_state(registry, false);
            state.wal_seq = seq;
            state.ownership = ownership;
            state.snapshot_slot = Some(slot);
            Some(state)
        })();
        match decoded {
            Some(state) if best.as_ref().is_none_or(|old| state.wal_seq > old.wal_seq) => {
                best = Some(state)
            }
            Some(_) => {}
            None => corrupt = true,
        }
    }
    if best.is_none() {
        match load_best_snapshot().await {
            Ok((registry, seq)) => {
                let mut state = empty_state(registry, false);
                state.wal_seq = seq;
                best = Some(state);
            }
            Err(error) if missing(&error) && !corrupt => {}
            Err(error) => return Err(error.with_context("no valid registry snapshot")),
        }
        if best.is_none() && corrupt {
            return Err(error(RegistryErrorKind::EncodingFailed));
        }
    }
    let is_new = best.is_none();
    let mut state = best.unwrap_or_else(|| empty_state(fresh_registry(), false));
    let bytes = match read_file(WAL_PATH).await {
        Ok(bytes) => bytes,
        Err(error) if missing(&error) => Vec::new(),
        Err(error) => return Err(error),
    };
    if is_new && !bytes.is_empty() {
        return Err(error(RegistryErrorKind::EncodingFailed)
            .with_context("WAL exists without a registry snapshot"));
    }
    let replay = registry_format::reconcile::replay(
        &mut state.registry,
        &mut state.ownership,
        state.wal_seq,
        &bytes,
    )
    .map_err(|message| error(RegistryErrorKind::EncodingFailed).with_context(message))?;
    state.wal_seq = replay.sequence;
    state.deltas_since_snapshot = replay.applied;
    state.wal_bytes = replay.valid_len as u64;
    Ok((state, bytes.len() as u64, is_new))
}

pub async fn init() -> Result<(), KernelError> {
    REGISTRY.call_once(|| RegistryStore {
        state: RwLock::new(empty_state(fresh_registry(), true)),
        io: AsyncMutex::new(RegistryIo::default()),
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

/// Returns true only for the caller that completes the transition.
pub async fn rebind_and_persist_after_provider_switch() -> Result<bool, KernelError> {
    let store = REGISTRY
        .get()
        .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?;
    let mut io = store.io.lock().await;
    if !store.state.read().bootstrap {
        return Ok(false);
    }
    #[cfg(feature = "boot-timings")]
    let timing = crate::structs::stopwatch::Stopwatch::start();
    let (mut runtime, file_len, is_new) = load_registry_state().await?;
    #[cfg(feature = "boot-timings")]
    let load_ms = timing.elapsed_millis();
    let before = runtime.registry.clone();
    let previous = runtime.ownership.clone();
    let ownership = {
        let boot = store.state.read();
        registry_format::reconcile::merge(
            &mut runtime.registry,
            &previous,
            &boot.registry,
            &boot.boot_deletes,
        )
        .map_err(|message| error(RegistryErrorKind::EncodingFailed).with_context(message))?
    };
    let changes: Vec<Delta> = diff_registry(&before, &runtime.registry)
        .into_iter()
        .map(|delta| Delta {
            delta: Some(match delta {
                RegDelta::CreateKey { path } => {
                    registry_format::delta::Delta::CreateKey(CreateKey { path })
                }
                RegDelta::DeleteKey { path } => {
                    registry_format::delta::Delta::DeleteKey(DeleteKey { path })
                }
                RegDelta::SetValue {
                    key_path,
                    name,
                    data,
                } => registry_format::delta::Delta::SetValue(SetValue {
                    key_path,
                    name,
                    data: Some(value_from_data(&data)),
                }),
                RegDelta::DeleteValue { key_path, name } => {
                    registry_format::delta::Delta::DeleteValue(DeleteValue { key_path, name })
                }
            }),
        })
        .collect();
    #[cfg(feature = "boot-timings")]
    let merge_ms = timing.elapsed_millis();
    #[cfg(feature = "boot-timings")]
    let change_count = changes.len();
    #[cfg(feature = "boot-timings")]
    let writes_batch = !is_new && (!changes.is_empty() || previous != ownership);
    // Repair a torn tail before any subsequent append, including normal runtime writes.
    if runtime.wal_bytes < file_len {
        if io.wal.is_none() {
            io.wal = Some(open_wal().await?);
        }
        let wal = io.wal.as_mut().unwrap();
        wal.set_len(runtime.wal_bytes).await?;
        wal.flush().await?;
    }
    if is_new {
        runtime.ownership = ownership;
        let bytes = encode_owned_snapshot(&runtime)?;
        persist_snapshot_at(SNAPSHOT_PATHS[0], &bytes).await?;
        runtime.snapshot_slot = Some(0);
    } else if !changes.is_empty() || previous != ownership {
        let seq = runtime
            .wal_seq
            .checked_add(1)
            .ok_or_else(|| error(RegistryErrorKind::PersistenceFailed))?;
        let batch = Delta {
            delta: Some(registry_format::delta::Delta::Batch(RegistryBatch {
                changes,
                boot_ownership: Some(ownership.clone()),
            })),
        };
        append_wal(&mut io, seq, &batch).await?;
        runtime.wal_seq = seq;
        runtime.ownership = ownership;
        runtime.wal_bytes = io.wal.as_ref().unwrap().size;
        runtime.deltas_since_snapshot += 1;
    }
    // Registry mutations remain excluded until both publications are complete.
    {
        let mut state = store.state.write();
        *state = runtime;
        install_file_provider(ProviderKind::Vfs);
    }
    #[cfg(feature = "boot-timings")]
    println!(
        "registry handoff: load={}ms merge={}ms persist={}ms changes={} batch={} snapshot={}",
        load_ms,
        merge_ms - load_ms,
        timing.elapsed_millis() - merge_ms,
        change_count,
        writes_batch,
        is_new
    );
    Ok(true)
}

pub async fn is_first_boot() -> bool {
    matches!(
        reg::get_value("SYSTEM/SETUP", "FirstBoot").await,
        Some(Data::Bool(true))
    )
}
