use crate::file_system::file::{File, OpenFlags};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use bincode::{Decode, Encode};
use lazy_static::lazy_static;
use spin::{Once, RwLock};

/// ----------------------------------------------
///  File location & on-disk format
/// ----------------------------------------------
const REG_PATH: &str = "C:\\SYSTEM\\REGISTRY.BIN";

/* ---------- data layer -------------- */
#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub enum Data {
    U32(u32),
    U64(u64),
    I32(i32),
    I64(i64),
    Bool(bool),
    Str(String),
}
#[derive(Debug)]
pub enum RegError {
    File(crate::file_system::file::FileStatus),
    KeyAlreadyExists,
    KeyNotFound,
    ValueNotFound,
    PersistenceFailed,
    EncodingFailed,
}

impl From<crate::file_system::file::FileStatus> for RegError {
    fn from(e: crate::file_system::file::FileStatus) -> Self {
        RegError::File(e)
    }
}
#[derive(Debug, Clone, Encode, Decode)]
pub struct Key {
    /// name → Data
    pub values: BTreeMap<String, Data>,
    /// sub-key name → Key
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

lazy_static! {
    static ref REGISTRY: RwLock<Arc<Registry>> = RwLock::new(Arc::new(Registry::empty()));
}

fn ensure_loaded() {
    use bincode::config::standard;
    static LOADER: Once = Once::new();

    LOADER.call_once(|| {
        if let Ok(mut f) = File::open(REG_PATH, &[OpenFlags::ReadWrite, OpenFlags::Open]) {
            if let Ok(buf) = f.read() {
                if let Ok((disk_reg, _)) =
                    bincode::decode_from_slice::<Registry, _>(&buf, standard())
                {
                    *REGISTRY.write() = Arc::new(disk_reg);
                    return;
                }
            }
        }

        let mut reg = Registry::empty();

        let system = reg.root.entry("SYSTEM".into()).or_insert_with(Key::empty);

        let setup = system
            .sub_keys
            .entry("SETUP".into())
            .or_insert_with(Key::empty);

        setup.values.insert("FirstBoot".into(), Data::Bool(true));

        if let Ok(mut f) = File::open(REG_PATH, &[OpenFlags::ReadWrite, OpenFlags::Create]) {
            let bytes = bincode::encode_to_vec(&reg, standard()).unwrap();
            let _ = f.write(&bytes);
        }

        *REGISTRY.write() = Arc::new(reg);
    });
}
pub mod reg {
    use super::*;
    use crate::{
        file_system::file::{File, FileStatus, OpenFlags},
        println,
    };

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

    pub fn get_key(path: &str) -> Option<Key> {
        ensure_loaded();
        walk(&REGISTRY.read().root, path).cloned()
    }

    pub fn create_key(path: &str) -> Result<(), RegError> {
        ensure_loaded();
        let mut new: Registry = (**REGISTRY.read()).clone();

        let mut node_map = &mut new.root;
        let mut segments = path.split('/').filter(|s| !s.is_empty()).peekable();

        while let Some(seg) = segments.next() {
            let is_last = segments.peek().is_none();

            if is_last {
                if node_map.contains_key(seg) {
                    return Err(RegError::KeyAlreadyExists);
                } else {
                    node_map.insert(seg.to_string(), Key::empty());
                }
            } else {
                node_map = &mut node_map
                    .entry(seg.to_string())
                    .or_insert_with(Key::empty)
                    .sub_keys;
            }
        }

        persist(&new)
    }

    pub fn delete_key(path: &str) -> Result<bool, RegError> {
        ensure_loaded();
        let mut segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segs.is_empty() {
            return Ok(false);
        }
        let last = segs.pop().unwrap();
        let mut new: Registry = (**REGISTRY.read()).clone();
        let parent = walk_mut(&mut new.root, &segs.join("/")).ok_or(RegError::KeyNotFound)?;
        let removed = parent.sub_keys.remove(last).is_some();
        if removed {
            persist(&new)?;
        }
        Ok(removed)
    }

    /* -----------------------------------------------------------------
     *  VALUE API
     * ----------------------------------------------------------------- */
    pub fn get_value(key_path: &str, name: &str) -> Option<Data> {
        ensure_loaded();
        walk(&REGISTRY.read().root, key_path)
            .and_then(|k| k.values.get(name))
            .cloned()
    }

    pub fn set_value(key_path: &str, name: &str, data: Data) -> Result<(), RegError> {
        ensure_loaded();
        let mut new: Registry = (**REGISTRY.read()).clone();
        let key = walk_mut(&mut new.root, key_path).ok_or(RegError::KeyNotFound)?;
        key.values.insert(name.to_string(), data);
        persist(&new)
    }

    pub fn delete_value(key_path: &str, name: &str) -> Result<bool, RegError> {
        ensure_loaded();
        let mut new: Registry = (**REGISTRY.read()).clone();
        let key = walk_mut(&mut new.root, key_path).ok_or(RegError::KeyNotFound)?;
        let removed = key.values.remove(name).is_some();
        if removed {
            persist(&new)?;
        }
        Ok(removed)
    }
    pub fn print_tree() {
        fn dump(name: &str, key: &Key, depth: usize) {
            // build indentation without std
            let mut indent = alloc::string::String::new();
            for _ in 0..depth {
                indent.push_str("  ");
            }
            println!("{}[{}]", indent, name);

            // print values under this key
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

            // recurse into sub-keys
            for (sub_name, sub_key) in &key.sub_keys {
                dump(sub_name, sub_key, depth + 1);
            }
        }

        ensure_loaded();
        let reg = REGISTRY.read();
        for (root_name, root_key) in &reg.root {
            dump(root_name, root_key, 0);
        }
    }
    fn persist(new_reg: &Registry) -> Result<(), RegError> {
        let bytes = bincode::encode_to_vec(new_reg, bincode::config::standard())
            .map_err(|_| RegError::EncodingFailed)?;

        *REGISTRY.write() = Arc::new(new_reg.clone());

        let mut file = File::open(REG_PATH, &[OpenFlags::ReadWrite, OpenFlags::Create])?;
        file.write(&bytes).map_err(RegError::from)
    }
}
pub fn is_first_boot() -> bool {
    matches!(
        reg::get_value("SYSTEM/SETUP", "FirstBoot"),
        Some(Data::Bool(true))
    )
}
