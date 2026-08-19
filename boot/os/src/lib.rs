use bootloader::{BootConfig, UefiBoot};
use serde::Deserialize;
use serde_json::Value;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const AARCH64_BOOTLOADER_MANIFEST: &str = "third_party/aarch64-bootloader/bootloader/Cargo.toml";
const AARCH64_BOOTLOADER_PACKAGE: &str = "aarch64-bootloader";
const AARCH64_BOOTLOADER_TARGET: &str = "aarch64-unknown-uefi";
const AARCH64_EFI_PATH: &str = "/EFI/BOOT/BOOTAA64.EFI";
const AARCH64_STARTUP_PATH: &str = "/startup.nsh";
const AARCH64_STARTUP: &[u8] = b"FS0:\\EFI\\BOOT\\BOOTAA64.EFI\r\n";
const AARCH64_CONFIG_ENV: &str = "RUSTOS_BOOT_CONFIG_PATH";
const MIB: u64 = 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct BootloaderSpec {
    pub provider: String,
    pub firmware: String,
    #[serde(default)]
    pub config_path: String,
    #[serde(default)]
    pub payload_path: String,
    #[serde(default)]
    pub framebuffer_width: String,
    #[serde(default)]
    pub framebuffer_height: String,
}

pub struct ImageRequest<'a> {
    pub workspace_root: &'a Path,
    pub platform_id: &'a str,
    pub stub: &'a Path,
    pub output: &'a Path,
    pub release: bool,
    pub offline: bool,
    pub bootloader: &'a BootloaderSpec,
}

pub fn create_uefi_image(request: ImageRequest<'_>) -> Result<PathBuf, String> {
    if !request.stub.is_file() {
        return Err(format!(
            "kernel stub does not exist: {}",
            request.stub.display()
        ));
    }
    ensure_output_parent(request.output)?;

    match request.bootloader.provider.as_str() {
        "rust-osdev-x86_64" => {
            require_uefi(&request.bootloader.firmware, "rust-osdev-x86_64")?;
            create_x86_64_image(request.stub, request.output)?;
        }
        "rustos-aarch64" => {
            require_uefi(&request.bootloader.firmware, "rustos-aarch64")?;
            let layout = Aarch64ImageLayout::new(
                &request.bootloader.config_path,
                &request.bootloader.payload_path,
                &request.bootloader.framebuffer_width,
                &request.bootloader.framebuffer_height,
            )?;
            let bootloader = build_aarch64_bootloader(&request, &layout)?;
            create_aarch64_image(&bootloader, request.stub, request.output, &layout)?;
        }
        provider => return Err(format!("unsupported bootloader provider `{provider}`")),
    }

    Ok(request.output.to_path_buf())
}

fn require_uefi(firmware: &str, provider: &str) -> Result<(), String> {
    if firmware == "uefi" {
        Ok(())
    } else {
        Err(format!(
            "bootloader provider `{provider}` does not support firmware `{firmware}`"
        ))
    }
}

fn ensure_output_parent(output: &Path) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create boot image directory {}: {err}",
                parent.display()
            )
        })?;
    }
    Ok(())
}

fn create_x86_64_image(stub: &Path, output: &Path) -> Result<(), String> {
    let config = BootConfig::default();
    let mut boot = UefiBoot::new(stub);
    boot.set_boot_config(&config);
    boot.create_disk_image(output)
        .map_err(|err| format!("failed to create UEFI image {}: {err}", output.display()))
}

struct Aarch64ImageLayout {
    config_path: ImagePath,
    payload_path: ImagePath,
    framebuffer_width: String,
    framebuffer_height: String,
}

impl Aarch64ImageLayout {
    fn new(
        config_path: &str,
        payload_path: &str,
        framebuffer_width: &str,
        framebuffer_height: &str,
    ) -> Result<Self, String> {
        let config_path = ImagePath::parse(config_path, "AArch64 boot config path")?;
        let payload_path = ImagePath::parse(payload_path, "AArch64 stub payload path")?;
        let efi_path = ImagePath::parse(AARCH64_EFI_PATH, "AArch64 EFI path")?;
        if config_path.collides_with(&payload_path)
            || config_path.collides_with(&efi_path)
            || payload_path.collides_with(&efi_path)
        {
            return Err("AArch64 boot image paths must not collide".to_string());
        }
        Ok(Self {
            config_path,
            payload_path,
            framebuffer_width: framebuffer_width.to_string(),
            framebuffer_height: framebuffer_height.to_string(),
        })
    }

    fn config(&self) -> Vec<u8> {
        format!(
            "kernel={}\nframebuffer_width={}\nframebuffer_height={}\n",
            self.payload_path.as_uefi_path(),
            self.framebuffer_width,
            self.framebuffer_height
        )
        .into_bytes()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ImagePath {
    uefi: String,
    fat: String,
}

impl ImagePath {
    fn parse(value: &str, what: &str) -> Result<Self, String> {
        if !value.starts_with('/') || value.contains('\\') {
            return Err(format!(
                "{what} must be an absolute slash-separated path: `{value}`"
            ));
        }
        let mut parts = Vec::new();
        for part in value[1..].split('/') {
            if part.is_empty() || part == "." || part == ".." {
                return Err(format!("{what} contains an invalid component: `{value}`"));
            }
            parts.push(part);
        }
        if parts.is_empty() {
            return Err(format!("{what} must name a file: `{value}`"));
        }
        let fat = parts.join("/");
        Ok(Self {
            uefi: format!("\\{}", parts.join("\\")),
            fat,
        })
    }

    fn as_uefi_path(&self) -> &str {
        &self.uefi
    }

    fn as_fat_path(&self) -> &str {
        &self.fat
    }

    fn collides_with(&self, other: &Self) -> bool {
        self.fat.eq_ignore_ascii_case(&other.fat)
    }
}

fn build_aarch64_bootloader(
    request: &ImageRequest<'_>,
    layout: &Aarch64ImageLayout,
) -> Result<PathBuf, String> {
    let manifest = request.workspace_root.join(AARCH64_BOOTLOADER_MANIFEST);
    if !manifest.is_file() {
        return Err(format!(
            "AArch64 bootloader manifest does not exist: {}",
            manifest.display()
        ));
    }

    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let target_dir = request
        .workspace_root
        .join("target/cargo")
        .join(request.platform_id)
        .join("bootloader");
    let mut command = Command::new(cargo);
    command
        .current_dir(request.workspace_root)
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest)
        .args(["-p", AARCH64_BOOTLOADER_PACKAGE, "--target"])
        .arg(AARCH64_BOOTLOADER_TARGET)
        .args(["--message-format", "json-render-diagnostics"])
        .env("CARGO_TARGET_DIR", target_dir)
        .env(AARCH64_CONFIG_ENV, layout.config_path.as_uefi_path());
    if request.release {
        command.arg("--release");
    }
    if request.offline {
        command.arg("--offline");
    }
    if let Some(path) = path_with_rust_linkers() {
        command.env("PATH", path);
    }

    let output = command
        .output()
        .map_err(|err| format!("failed to execute Cargo for AArch64 bootloader: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        emit_cargo_diagnostics(&stdout);
        return Err(format!(
            "building AArch64 bootloader failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    find_cargo_executable(&stdout, AARCH64_BOOTLOADER_PACKAGE).ok_or_else(|| {
        "Cargo did not report the AArch64 bootloader executable artifact".to_string()
    })
}

fn emit_cargo_diagnostics(stdout: &str) {
    for line in stdout.lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(rendered) = message
            .get("message")
            .and_then(|message| message.get("rendered"))
            .and_then(Value::as_str)
        {
            eprint!("{rendered}");
        }
    }
}

fn find_cargo_executable(stdout: &str, package: &str) -> Option<PathBuf> {
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|message| {
            if message.get("reason")?.as_str()? != "compiler-artifact"
                || message.get("target")?.get("name")?.as_str()? != package
            {
                return None;
            }
            let kinds = message.get("target")?.get("kind")?.as_array()?;
            if !kinds.iter().any(|kind| kind.as_str() == Some("bin")) {
                return None;
            }
            message.get("executable")?.as_str().map(PathBuf::from)
        })
}

fn path_with_rust_linkers() -> Option<OsString> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sysroot = String::from_utf8_lossy(&output.stdout);
    let rustlib = PathBuf::from(sysroot.trim()).join("lib").join("rustlib");
    let mut paths = Vec::new();
    for entry in fs::read_dir(rustlib).ok()?.flatten() {
        let bin = entry.path().join("bin");
        let gcc_ld = bin.join("gcc-ld");
        if gcc_ld.is_dir() {
            paths.push(gcc_ld);
        }
        if bin.is_dir() {
            paths.push(bin);
        }
    }
    paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
    env::join_paths(paths).ok()
}

fn create_aarch64_image(
    bootloader: &Path,
    stub: &Path,
    output: &Path,
    layout: &Aarch64ImageLayout,
) -> Result<(), String> {
    let config = layout.config();
    let partition_size = fat_partition_size(&[
        file_len(bootloader, "AArch64 EFI bootloader")?,
        file_len(stub, "AArch64 stub")?,
        config.len() as u64,
    ])?;
    let fat_file = tempfile::NamedTempFile::new()
        .map_err(|err| format!("failed to create temporary FAT image: {err}"))?;
    fat_file
        .as_file()
        .set_len(partition_size)
        .map_err(|err| format!("failed to size temporary FAT image: {err}"))?;
    fatfs::format_volume(
        fat_file.as_file(),
        fatfs::FormatVolumeOptions::new().volume_label(*b"RUSTOSBOOT "),
    )
    .map_err(|err| format!("failed to format AArch64 EFI partition: {err}"))?;

    {
        let filesystem = fatfs::FileSystem::new(fat_file.as_file(), fatfs::FsOptions::new())
            .map_err(|err| format!("failed to open AArch64 EFI partition: {err}"))?;
        let root = filesystem.root_dir();
        write_host_file(&root, AARCH64_EFI_PATH, bootloader)?;
        write_bytes(&root, AARCH64_STARTUP_PATH, AARCH64_STARTUP)?;
        write_host_file(&root, layout.payload_path.as_fat_path(), stub)?;
        write_bytes(&root, layout.config_path.as_fat_path(), &config)?;
    }

    create_gpt_disk(fat_file.path(), output)
}

fn fat_partition_size(file_sizes: &[u64]) -> Result<u64, String> {
    let contents = file_sizes.iter().try_fold(0u64, |sum, size| {
        sum.checked_add(*size)
            .ok_or_else(|| "AArch64 boot image contents are too large".to_string())
    })?;
    let wanted = contents
        .checked_add(MIB)
        .ok_or_else(|| "AArch64 boot image size overflow".to_string())?;
    let rounded = wanted
        .checked_add(MIB - 1)
        .ok_or_else(|| "AArch64 boot image size overflow".to_string())?
        / MIB
        * MIB;
    Ok(rounded.max(4 * MIB))
}

fn file_len(path: &Path, what: &str) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|err| format!("failed to read {what} {}: {err}", path.display()))
}

fn write_host_file<T: fatfs::ReadWriteSeek>(
    root: &fatfs::Dir<'_, T>,
    image_path: &str,
    source: &Path,
) -> Result<(), String> {
    let mut source_file = File::open(source)
        .map_err(|err| format!("failed to open image input {}: {err}", source.display()))?;
    let mut destination = create_fat_file(root, image_path)?;
    destination
        .truncate()
        .map_err(|err| format!("failed to truncate FAT file {image_path}: {err}"))?;
    io::copy(&mut source_file, &mut destination)
        .map_err(|err| format!("failed to copy {} to {image_path}: {err}", source.display()))?;
    Ok(())
}

fn write_bytes<T: fatfs::ReadWriteSeek>(
    root: &fatfs::Dir<'_, T>,
    image_path: &str,
    contents: &[u8],
) -> Result<(), String> {
    let mut destination = create_fat_file(root, image_path)?;
    destination
        .truncate()
        .map_err(|err| format!("failed to truncate FAT file {image_path}: {err}"))?;
    destination
        .write_all(contents)
        .map_err(|err| format!("failed to write FAT file {image_path}: {err}"))
}

fn create_fat_file<'a, T: fatfs::ReadWriteSeek>(
    root: &fatfs::Dir<'a, T>,
    image_path: &str,
) -> Result<fatfs::File<'a, T>, String> {
    let normalized = image_path.trim_start_matches('/');
    let mut parts = normalized.split('/').peekable();
    let mut directory = root.clone();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return directory
                .create_file(part)
                .map_err(|err| format!("failed to create FAT file {image_path}: {err}"));
        }
        directory = match directory.open_dir(part) {
            Ok(existing) => existing,
            Err(_) => directory
                .create_dir(part)
                .map_err(|err| format!("failed to create FAT directory for {image_path}: {err}"))?,
        };
    }
    Err(format!("image path does not name a file: {image_path}"))
}

fn create_gpt_disk(fat_image: &Path, output: &Path) -> Result<(), String> {
    let mut disk = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(output)
        .map_err(|err| format!("failed to create GPT image {}: {err}", output.display()))?;
    let partition_size = file_len(fat_image, "temporary FAT image")?;
    let disk_size = partition_size
        .checked_add(64 * 1024)
        .ok_or_else(|| "AArch64 GPT image size overflow".to_string())?;
    disk.set_len(disk_size)
        .map_err(|err| format!("failed to size GPT image {}: {err}", output.display()))?;

    let mbr = gpt::mbr::ProtectiveMBR::with_lb_size(
        u32::try_from((disk_size / 512).saturating_sub(1)).unwrap_or(u32::MAX),
    );
    mbr.overwrite_lba0(&mut disk)
        .map_err(|err| format!("failed to write protective MBR: {err}"))?;

    let block_size = gpt::disk::LogicalBlockSize::Lb512;
    let mut table = gpt::GptConfig::new()
        .writable(true)
        .initialized(false)
        .logical_block_size(block_size)
        .create_from_device(Box::new(&mut disk), None)
        .map_err(|err| format!("failed to initialize GPT: {err}"))?;
    table
        .update_partitions(Default::default())
        .map_err(|err| format!("failed to initialize GPT partitions: {err}"))?;
    let id = table
        .add_partition("boot", partition_size, gpt::partition_types::EFI, 0, None)
        .map_err(|err| format!("failed to add EFI System Partition: {err}"))?;
    let start = table
        .partitions()
        .get(&id)
        .ok_or_else(|| "new EFI System Partition is missing".to_string())?
        .bytes_start(block_size)
        .map_err(|err| format!("failed to locate EFI System Partition: {err}"))?;
    table
        .write()
        .map_err(|err| format!("failed to write GPT: {err}"))?;

    disk.seek(io::SeekFrom::Start(start))
        .map_err(|err| format!("failed to seek to EFI System Partition: {err}"))?;
    io::copy(
        &mut File::open(fat_image)
            .map_err(|err| format!("failed to reopen temporary FAT image: {err}"))?,
        &mut disk,
    )
    .map_err(|err| format!("failed to copy EFI System Partition into GPT image: {err}"))?;
    Ok(())
}
