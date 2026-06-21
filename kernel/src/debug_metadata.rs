use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

// Protocol (line-based UTF-8, \n terminated; COM2 sink adds \r before \n):
//
//   RUSTOS_MODULE_BEGIN id=<N> name="<name>" path="<path>" preferred=0x<HEX> loaded=0x<HEX>
//   RUSTOS_MODULE_SECTION id=<N> name="<section>" addr=0x<HEX> size=0x<HEX>
//   RUSTOS_MODULE_END id=<N>
//
//   RUSTOS_META_HELLO version=1          (host → kernel)
//   RUSTOS_META_HELLO_ACK version=1      (kernel → host, followed by full snapshot)

pub struct DebugLoadedSection<'a> {
    pub name: &'a str,
    pub runtime_addr: u64,
    pub size: u64,
}

pub struct DebugLoadedModule<'a> {
    pub name: &'a str,
    pub path: Option<&'a str>,
    pub preferred_image_base: u64,
    pub loaded_image_base: u64,
    pub sections: &'a [DebugLoadedSection<'a>],
}

pub enum DebugModuleEvent<'a> {
    Loaded(DebugLoadedModule<'a>),
}

const MAX_SNAPSHOT_MODULES: usize = 64;

struct SnapshotSection {
    name: String,
    runtime_addr: u64,
    size: u64,
}

struct SnapshotModule {
    id: u32,
    name: String,
    path: Option<String>,
    preferred_image_base: u64,
    loaded_image_base: u64,
    sections: Vec<SnapshotSection>,
}

static SNAPSHOT: Mutex<Vec<SnapshotModule>> = Mutex::new(Vec::new());
static NEXT_MODULE_ID: AtomicU32 = AtomicU32::new(1);
static HOST_HELLO_RECEIVED: AtomicBool = AtomicBool::new(false);

type MetaSinkFn = fn(&[u8]);

static META_SINK: Mutex<Option<MetaSinkFn>> = Mutex::new(None);

#[inline(always)]
pub fn debug_metadata_dev_build() -> bool {
    cfg!(debug_assertions)
}

#[inline(always)]
pub fn debug_metadata_should_wait_for_host() -> bool {
    debug_metadata_dev_build()
}

#[inline(always)]
pub fn debug_metadata_host_ready() -> bool {
    HOST_HELLO_RECEIVED.load(Ordering::Acquire)
}

#[inline(always)]
fn debug_metadata_live_emit_allowed() -> bool {
    debug_metadata_dev_build() || debug_metadata_host_ready()
}

pub fn register_sink(sink: MetaSinkFn) {
    *META_SINK.lock() = Some(sink);
}

pub fn host_hello_received() {
    HOST_HELLO_RECEIVED.store(true, Ordering::Release);

    let mut buf = arrayfmt::ArrayFmt::<64>::new();
    let _ = core::fmt::Write::write_str(&mut buf, "RUSTOS_META_HELLO_ACK version=1\n");
    sink_write(buf.as_bytes());

    replay_snapshot();
}

fn sink_write(bytes: &[u8]) {
    if !debug_metadata_live_emit_allowed() {
        return;
    }

    let sink = *META_SINK.lock();

    if let Some(sink) = sink {
        sink(bytes);
    }
}

fn write_quoted(buf: &mut impl core::fmt::Write, value: &str) {
    debug_assert!(
        !value.contains('"') && !value.contains('\\'),
        "debug_metadata: name/path requires escaping: {value:?}"
    );

    let _ = core::fmt::Write::write_fmt(buf, format_args!("\"{}\"", value));
}

fn emit_module(id: u32, module: &DebugLoadedModule<'_>) {
    if !debug_metadata_live_emit_allowed() {
        return;
    }

    {
        let mut buf = arrayfmt::ArrayFmt::<512>::new();

        let _ = core::fmt::Write::write_fmt(
            &mut buf,
            format_args!("RUSTOS_MODULE_BEGIN id={} name=", id),
        );

        write_quoted(&mut buf, module.name);

        let _ = core::fmt::Write::write_str(&mut buf, " path=");

        match module.path {
            Some(path) => write_quoted(&mut buf, path),
            None => {
                let _ = core::fmt::Write::write_str(&mut buf, "\"\"");
            }
        }

        let _ = core::fmt::Write::write_fmt(
            &mut buf,
            format_args!(
                " preferred={:#018x} loaded={:#018x}\n",
                module.preferred_image_base, module.loaded_image_base
            ),
        );

        sink_write(buf.as_bytes());
    }

    for section in module.sections {
        let mut buf = arrayfmt::ArrayFmt::<256>::new();

        let _ = core::fmt::Write::write_fmt(
            &mut buf,
            format_args!("RUSTOS_MODULE_SECTION id={} name=", id),
        );

        write_quoted(&mut buf, section.name);

        let _ = core::fmt::Write::write_fmt(
            &mut buf,
            format_args!(
                " addr={:#018x} size={:#018x}\n",
                section.runtime_addr, section.size
            ),
        );

        sink_write(buf.as_bytes());
    }

    {
        let mut buf = arrayfmt::ArrayFmt::<64>::new();

        let _ =
            core::fmt::Write::write_fmt(&mut buf, format_args!("RUSTOS_MODULE_END id={}\n", id));

        sink_write(buf.as_bytes());
    }
}

pub fn module_loaded(module: &DebugLoadedModule<'_>) {
    let id = NEXT_MODULE_ID.fetch_add(1, Ordering::Relaxed);

    {
        let mut snapshot = SNAPSHOT.lock();

        if snapshot.len() < MAX_SNAPSHOT_MODULES {
            snapshot.push(SnapshotModule {
                id,
                name: String::from(module.name),
                path: module.path.map(String::from),
                preferred_image_base: module.preferred_image_base,
                loaded_image_base: module.loaded_image_base,
                sections: module
                    .sections
                    .iter()
                    .map(|section| SnapshotSection {
                        name: String::from(section.name),
                        runtime_addr: section.runtime_addr,
                        size: section.size,
                    })
                    .collect(),
            });
        }
    }

    emit_module(id, module);
}

pub fn replay_snapshot() {
    if !debug_metadata_live_emit_allowed() {
        return;
    }

    let snapshot = SNAPSHOT.lock();

    for module in snapshot.iter() {
        let sections: Vec<DebugLoadedSection<'_>> = module
            .sections
            .iter()
            .map(|section| DebugLoadedSection {
                name: section.name.as_str(),
                runtime_addr: section.runtime_addr,
                size: section.size,
            })
            .collect();

        emit_module(
            module.id,
            &DebugLoadedModule {
                name: module.name.as_str(),
                path: module.path.as_deref(),
                preferred_image_base: module.preferred_image_base,
                loaded_image_base: module.loaded_image_base,
                sections: &sections,
            },
        );
    }
}

mod arrayfmt {
    use core::fmt;

    pub struct ArrayFmt<const N: usize> {
        buf: [u8; N],
        len: usize,
    }

    impl<const N: usize> ArrayFmt<N> {
        pub const fn new() -> Self {
            Self {
                buf: [0u8; N],
                len: 0,
            }
        }

        pub fn as_bytes(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }

    impl<const N: usize> fmt::Write for ArrayFmt<N> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let remaining = N.saturating_sub(self.len);
            let to_copy = s.len().min(remaining);

            self.buf[self.len..self.len + to_copy].copy_from_slice(&s.as_bytes()[..to_copy]);
            self.len += to_copy;

            Ok(())
        }
    }
}
