//! Pure boot/runtime reconciliation, shared with host-side validation.
use crate::{BootOwnership, Delta, Key, Registry, ValuePath};
use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};

pub fn canonical_path(path: &str) -> String {
    path.split(['/', '\\'])
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}
fn key_mut<'a>(tree: &'a mut Registry, path: &str) -> Option<&'a mut Key> {
    let mut parts = path.split(['/', '\\']).filter(|p| !p.is_empty());
    let mut key = tree.root.get_mut(parts.next()?)?;
    for part in parts {
        key = key.sub_keys.get_mut(part)?;
    }
    Some(key)
}
fn remove_key(tree: &mut Registry, path: &str, empty_only: bool) {
    let path = canonical_path(path);
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", &path));
    let map = if parent.is_empty() {
        &mut tree.root
    } else {
        let Some(key) = key_mut(tree, parent) else {
            return;
        };
        &mut key.sub_keys
    };
    if map
        .get(name)
        .is_some_and(|key| !empty_only || (key.values.is_empty() && key.sub_keys.is_empty()))
    {
        map.remove(name);
    }
}
pub fn ownership(tree: &Registry) -> BootOwnership {
    fn visit(path: String, key: &Key, out: &mut BootOwnership) {
        out.keys.push(path.clone());
        for name in key.values.keys() {
            out.values.push(ValuePath {
                key: path.clone(),
                name: name.clone(),
            });
        }
        for (name, child) in &key.sub_keys {
            visit(alloc::format!("{path}/{name}"), child, out);
        }
    }
    let mut out = BootOwnership::default();
    for (name, key) in &tree.root {
        visit(name.clone(), key, &mut out);
    }
    out
}
pub fn merge(
    runtime: &mut Registry,
    previous: &BootOwnership,
    boot: &Registry,
    deletes: &[Delta],
) -> Result<BootOwnership, &'static str> {
    let current = ownership(boot);
    let current_values: BTreeSet<_> = current
        .values
        .iter()
        .map(|v| (v.key.as_str(), v.name.as_str()))
        .collect();
    let current_keys: BTreeSet<_> = current.keys.iter().map(String::as_str).collect();
    for value in &previous.values {
        if !current_values.contains(&(value.key.as_str(), value.name.as_str())) {
            if let Some(key) = key_mut(runtime, &value.key) {
                key.values.remove(&value.name);
            }
        }
    }
    for delta in deletes {
        apply(runtime, delta)?;
    }
    fn overlay(dst: &mut Key, src: &Key) {
        dst.values.extend(src.values.clone());
        for (name, key) in &src.sub_keys {
            overlay(dst.sub_keys.entry(name.clone()).or_default(), key);
        }
    }
    for (name, key) in &boot.root {
        overlay(runtime.root.entry(name.clone()).or_default(), key);
    }
    let mut old = previous.keys.clone();
    old.sort_by_key(|path| core::cmp::Reverse(path.matches('/').count()));
    for path in old {
        if !current_keys.contains(path.as_str()) {
            remove_key(runtime, &path, true);
        }
    }
    Ok(current)
}
/// Apply a single legacy operation. Nested batches are deliberately rejected.
pub fn apply(tree: &mut Registry, delta: &Delta) -> Result<(), &'static str> {
    use crate::delta::Delta as Op;
    match delta.delta.as_ref().ok_or("empty registry operation")? {
        Op::CreateKey(d) => {
            let path = canonical_path(&d.path);
            let mut parts = path.split('/');
            let first = parts
                .next()
                .filter(|s| !s.is_empty())
                .ok_or("empty key path")?;
            let mut key = tree.root.entry(first.to_string()).or_default();
            for part in parts {
                key = key.sub_keys.entry(part.to_string()).or_default();
            }
        }
        Op::DeleteKey(d) => remove_key(tree, &d.path, false),
        Op::SetValue(d) => {
            let data = d
                .data
                .clone()
                .filter(|v| v.value.is_some())
                .ok_or("missing value")?;
            key_mut(tree, &d.key_path)
                .ok_or("missing key")?
                .values
                .insert(d.name.clone(), data);
        }
        Op::DeleteValue(d) => {
            if let Some(key) = key_mut(tree, &d.key_path) {
                key.values.remove(&d.name);
            }
        }
        Op::Batch(_) => return Err("nested registry batch"),
    }
    Ok(())
}
/// Validate the whole transaction on a private tree before publishing anything.
pub fn apply_batch(
    tree: &mut Registry,
    owner: &mut BootOwnership,
    batch: &crate::RegistryBatch,
) -> Result<(), &'static str> {
    let mut next = tree.clone();
    for delta in &batch.changes {
        apply(&mut next, delta)?;
    }
    *tree = next;
    if let Some(next) = &batch.boot_ownership {
        *owner = next.clone();
    }
    Ok(())
}

pub struct Replay {
    pub sequence: u64,
    pub applied: u64,
    pub valid_len: usize,
}

/// Framing errors terminate the valid prefix. Semantic errors in complete,
/// checksummed records are not treated as disposable tail damage.
pub fn replay(
    tree: &mut Registry,
    owner: &mut BootOwnership,
    snapshot_seq: u64,
    bytes: &[u8],
) -> Result<Replay, &'static str> {
    use prost::Message;
    let mut out = Replay {
        sequence: snapshot_seq,
        applied: 0,
        valid_len: 0,
    };
    let mut previous = None;
    while out.valid_len < bytes.len() {
        let (seq, payload, len) = match crate::decode_frame(&bytes[out.valid_len..], 2) {
            Ok(frame) => frame,
            Err(crate::FrameError::WrongVersion) => return Err("unsupported WAL version"),
            Err(_) => break,
        };
        if previous.is_some_and(|old| seq <= old) {
            return Err("WAL sequence is not increasing");
        }
        if seq > snapshot_seq {
            if out.sequence.checked_add(1) != Some(seq) {
                return Err("WAL sequence gap");
            }
            let delta = Delta::decode(payload).map_err(|_| "invalid WAL operation")?;
            match delta.delta.as_ref() {
                Some(crate::delta::Delta::Batch(batch)) => apply_batch(tree, owner, batch)?,
                _ => apply(tree, &delta)?,
            }
            out.sequence = seq;
            out.applied += 1;
        }
        previous = Some(seq);
        out.valid_len += len;
    }
    Ok(out)
}

pub fn decode_owned_snapshot(
    bytes: &[u8],
    schema_version: u32,
) -> Result<(u64, Registry, BootOwnership), &'static str> {
    use prost::Message;
    let (seq, payload, len) =
        crate::decode_frame(bytes, 2).map_err(|_| "invalid snapshot frame")?;
    if len != bytes.len() {
        return Err("trailing snapshot bytes");
    }
    let snapshot =
        crate::RegistrySnapshot::decode(payload).map_err(|_| "invalid snapshot payload")?;
    let registry = snapshot.registry.ok_or("missing snapshot registry")?;
    if registry.schema_version != schema_version {
        return Err("unsupported registry schema");
    }
    Ok((seq, registry, snapshot.boot_ownership.unwrap_or_default()))
}
