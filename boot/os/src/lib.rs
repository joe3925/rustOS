use bootloader::{BootConfig, UefiBoot};
use std::path::{Path, PathBuf};

/// Packages a bootloader-visible kernel stub as a UEFI disk image.
pub fn create_uefi_image(stub: &Path, output: &Path) -> Result<PathBuf, String> {
    if !stub.is_file() {
        return Err(format!("kernel stub does not exist: {}", stub.display()));
    }

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create boot image directory {}: {err}",
                parent.display()
            )
        })?;
    }

    let config = BootConfig::default();
    let mut boot = UefiBoot::new(stub);
    boot.set_boot_config(&config);
    boot.create_disk_image(output)
        .map_err(|err| format!("failed to create UEFI image {}: {err}", output.display()))?;

    Ok(output.to_path_buf())
}
