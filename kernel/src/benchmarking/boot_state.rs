use alloc::string::ToString;
use core::str;

use kernel_types::fs::{OpenFlags, Path};

use crate::file_system::file::File;

const STATE_DIRECTORY: &str = "C:\\bench";
const STATE_PATH: &str = "C:\\bench\\runner-state";

pub async fn current_repetition() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        use x86_64::instructions::port::Port;
        static HOST_REPETITION: spin::Once<Option<usize>> = spin::Once::new();
        if let Some(repetition) = *HOST_REPETITION.call_once(|| unsafe {
            let mut selector = Port::<u16>::new(0x510);
            let mut data = Port::<u8>::new(0x511);
            selector.write(0);
            if core::array::from_fn(|_| data.read()) != *b"QEMU" {
                return None;
            }
            selector.write(0x19);
            let entries = u32::from_be_bytes(core::array::from_fn(|_| data.read()));
            for _ in 0..entries.min(u32::from(u16::MAX)) {
                let entry: [u8; 64] = core::array::from_fn(|_| data.read());
                if !entry[8..].starts_with(b"opt/rustos/bench-repetition\0") {
                    continue;
                }
                let size = u32::from_be_bytes(entry[..4].try_into().unwrap()) as usize;
                let mut bytes = [0u8; 32];
                let value = bytes.get_mut(..size)?;
                selector.write(u16::from_be_bytes([entry[4], entry[5]]));
                for byte in &mut *value {
                    *byte = data.read();
                }
                return str::from_utf8(value)
                    .ok()?
                    .trim_end_matches('\0')
                    .parse()
                    .ok()
                    .filter(|&index| index > 0);
            }
            None
        }) {
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
