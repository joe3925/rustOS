use alloc::string::ToString;
use core::str;

use kernel_types::fs::{OpenFlags, Path};

use crate::file_system::file::File;

const STATE_DIRECTORY: &str = "C:\\bench";
const STATE_PATH: &str = "C:\\bench\\runner-state";

pub async fn current_repetition() -> usize {
    if let Some(bytes) = host_file(b"opt/rustos/bench-repetition", 32) {
        if let Some(repetition) = str::from_utf8(&bytes).ok()
            .and_then(|value| value.trim_end_matches('\0').parse::<usize>().ok())
            .filter(|&value| value > 0)
        {
            return repetition;
        }
    }
    let Ok(file) = File::open(
        &Path::from_string(STATE_PATH),
        &[OpenFlags::Open, OpenFlags::ReadOnly],
    )
    .await
    else {
        return 1;
    };

    let mut bytes = [0; 32];
    let read = file.read(&mut bytes).await.ok();
    let _ = file.close().await;

    read.and_then(|len| str::from_utf8(&bytes[..len]).ok())
        .and_then(|value| value.trim().parse().ok())
        .filter(|repetition| *repetition > 0)
        .unwrap_or(1)
}

pub async fn persist_next_repetition(current: usize) -> bool {
    if File::make_dir(&Path::from_string(STATE_DIRECTORY))
        .await
        .is_err()
    {
        return false;
    }

    let path = Path::from_string(STATE_PATH);
    let mut file = match File::open(&path, &[OpenFlags::Create, OpenFlags::WriteThrough]).await {
        Ok(file) => file,
        Err(_) => {
            match File::open(
                &path,
                &[
                    OpenFlags::Open,
                    OpenFlags::ReadWrite,
                    OpenFlags::WriteThrough,
                ],
            )
            .await
            {
                Ok(file) => file,
                Err(_) => return false,
            }
        }
    };

    let encoded = current.saturating_add(1).to_string();
    let written = file.set_len(0).await.is_ok() && file.write(encoded.as_bytes()).await.is_ok();
    let closed = file.close().await.is_ok();
    written && closed
}

// QEMU's x86 port interface and ARM virt MMIO interface expose the same file directory.
// Only the benchmark runner uses this transport, before running any workloads.
pub fn host_file(name: &[u8], limit: usize) -> Option<alloc::vec::Vec<u8>> {
    static LOCK: spin::Mutex<()> = spin::Mutex::new(());
    let _guard = LOCK.lock();
    #[cfg(target_arch = "x86_64")]
    let (select, read) = (
        |key: u16| unsafe { x86_64::instructions::port::Port::<u16>::new(0x510).write(key) },
        || unsafe { x86_64::instructions::port::Port::<u8>::new(0x511).read() },
    );
    #[cfg(target_arch = "aarch64")]
    let mapping = crate::memory::paging::mmio::map_physical_pages(
        kernel_types::arch::PhysAddr::new(0x0902_0000),
        crate::memory::paging::layout::base_page_size(),
        kernel_types::memory::PhysicalMappingCache::Uncached,
    ).ok()?;
    #[cfg(target_arch = "aarch64")]
    let (select, read) = (
        |key: u16| unsafe {
            // Explicit single-register accesses also work with HVF's MMIO emulation.
            core::arch::asm!("strh {value:w}, [{address}]",
                value = in(reg) u32::from(key.to_be()),
                address = in(reg) mapping.address().as_u64() + 8,
                options(nostack, preserves_flags));
        },
        || unsafe {
            let value: u32;
            core::arch::asm!("ldrb {value:w}, [{address}]",
                value = out(reg) value, address = in(reg) mapping.address().as_u64(),
                options(nostack, preserves_flags));
            value as u8
        },
    );
    select(0);
    if core::array::from_fn(|_| read()) != *b"QEMU" { return None; }
    select(0x19);
    let count = u32::from_be_bytes(core::array::from_fn(|_| read()));
    for _ in 0..count.min(u32::from(u16::MAX)) {
        let entry: [u8; 64] = core::array::from_fn(|_| read());
        let end = entry[8..].iter().position(|&byte| byte == 0)?;
        if &entry[8..8 + end] != name { continue; }
        let size = u32::from_be_bytes(entry[..4].try_into().ok()?) as usize;
        if size > limit { return None; }
        select(u16::from_be_bytes([entry[4], entry[5]]));
        return Some((0..size).map(|_| read()).collect());
    }
    None
}
