use alloc::string::ToString;
use core::str;

use kernel_types::fs::{OpenFlags, Path};

use crate::file_system::file::File;

const STATE_DIRECTORY: &str = "C:\\bench";
const STATE_PATH: &str = "C:\\bench\\runner-state";

pub async fn current_repetition() -> usize {
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
