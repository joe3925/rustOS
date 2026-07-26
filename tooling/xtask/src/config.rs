use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct PlatformFile {
    pub schema: u32,
    pub id: String,
    pub kernel: KernelFile,
    pub drivers: DriversFile,
    pub stub: StubFile,
    pub bootloader: BootloaderFile,
}

#[derive(Debug, Deserialize)]
pub struct KernelFile {
    pub manifest: PathBuf,
    pub package: String,
    pub binary: String,
    pub target: PathBuf,
    pub import_library_machine: String,
    #[serde(default)]
    pub no_default_features: bool,
    #[serde(default)]
    pub features: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DriversFile {
    pub target: PathBuf,
    #[serde(default)]
    pub boot_packages: Vec<BootPackageFile>,
}

#[derive(Debug, Deserialize)]
pub struct BootPackageFile {
    pub source: BootPackageSourceFile,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BootPackageSourceFile {
    LocalCargo {
        manifest: PathBuf,
    },
    LocalFiles {
        configuration: PathBuf,
        binary: PathBuf,
    },
    GitCargo {
        repository: String,
        revision: String,
        manifest: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
pub struct StubFile {
    pub manifest: PathBuf,
    pub package: String,
    pub binary: String,
    pub target: String,
    pub rustflags: String,
}

#[derive(Debug, Deserialize)]
pub struct BootloaderFile {
    pub provider: String,
    pub firmware: String,
    pub output: PathBuf,
}

#[derive(Debug)]
pub struct BuildPlan {
    pub id: String,
    pub kernel: KernelPlan,
    pub drivers: DriversPlan,
    pub stub: StubPlan,
    pub bootloader: BootloaderPlan,
}

#[derive(Debug)]
pub struct KernelPlan {
    pub manifest: PathBuf,
    pub package: String,
    pub binary: String,
    pub target: PathBuf,
    pub import_library_machine: String,
    pub no_default_features: bool,
    pub features: Vec<String>,
}

#[derive(Debug)]
pub struct DriversPlan {
    pub target: PathBuf,
    pub boot_packages: Vec<BootPackageSource>,
}

#[derive(Debug)]
pub enum BootPackageSource {
    LocalCargo {
        manifest: PathBuf,
    },
    LocalFiles {
        configuration: PathBuf,
        binary: PathBuf,
    },
    GitCargo {
        repository: String,
        revision: String,
        manifest: PathBuf,
    },
}

#[derive(Debug)]
pub struct StubPlan {
    pub manifest: PathBuf,
    pub package: String,
    pub binary: String,
    pub target: String,
    pub rustflags: String,
}

#[derive(Debug)]
pub struct BootloaderPlan {
    pub output: PathBuf,
}

#[derive(Debug, Deserialize)]
struct LaunchFile {
    schema: u32,
    id: String,
    provider: String,
    executable: String,
    compatible_platforms: Vec<String>,
    supported_hosts: Vec<String>,
    #[serde(default)]
    supported_host_arches: Vec<String>,
    firmware_files: Vec<PathBuf>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    debug_args: Vec<String>,
    #[serde(default)]
    lldb_metadata_args: Vec<String>,
    defaults: LaunchDefaults,
    capabilities: LaunchCapabilities,
}

#[derive(Debug, Deserialize)]
pub struct LaunchDefaults {
    pub memory: String,
    pub cpus: String,
}

#[derive(Debug, Deserialize)]
pub struct LaunchCapabilities {
    pub debug: bool,
    pub lldb_metadata: bool,
}

#[derive(Debug)]
pub struct LaunchPlan {
    pub id: String,
    pub executable: String,
    pub compatible_platforms: Vec<String>,
    pub supported_hosts: Vec<String>,
    pub supported_host_arches: Vec<String>,
    pub firmware_files: Vec<PathBuf>,
    pub args: Vec<String>,
    pub debug_args: Vec<String>,
    pub lldb_metadata_args: Vec<String>,
    pub defaults: LaunchDefaults,
    pub capabilities: LaunchCapabilities,
}

#[derive(Debug, Deserialize)]
struct HostFile {
    schema: u32,
    id: String,
    os: String,
    qemu: QemuHostFile,
}

#[derive(Debug, Deserialize)]
struct QemuHostFile {
    #[serde(default)]
    executable_patterns: Vec<PathBuf>,
    #[serde(default)]
    data_directories: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct HostPlan {
    pub id: String,
    pub os: String,
    pub executable_patterns: Vec<PathBuf>,
    pub data_directories: Vec<PathBuf>,
}

pub fn load_platform(root: &Path, selector: &str) -> Result<BuildPlan, String> {
    let platform_file = resolve_manifest(root, "platforms", selector)?;
    let base = manifest_parent(&platform_file)?;
    let parsed: PlatformFile = parse_manifest(&platform_file)?;

    require_schema(parsed.schema, &platform_file)?;
    require_id(&parsed.id, &platform_file)?;
    if parsed.bootloader.provider != "local" {
        return Err(format!(
            "unsupported bootloader provider `{}`; only `local` is implemented",
            parsed.bootloader.provider
        ));
    }
    if parsed.bootloader.firmware != "uefi" {
        return Err(format!(
            "unsupported firmware `{}`; only `uefi` is implemented",
            parsed.bootloader.firmware
        ));
    }

    let kernel_manifest = canonical_file(&base.join(parsed.kernel.manifest), "kernel manifest")?;
    let kernel_target = canonical_file(&base.join(parsed.kernel.target), "kernel target")?;
    let driver_target = canonical_file(&base.join(parsed.drivers.target), "driver target")?;
    let stub_manifest = canonical_file(&base.join(parsed.stub.manifest), "stub manifest")?;
    let mut boot_packages = Vec::with_capacity(parsed.drivers.boot_packages.len());
    for package in parsed.drivers.boot_packages {
        boot_packages.push(match package.source {
            BootPackageSourceFile::LocalCargo { manifest } => BootPackageSource::LocalCargo {
                manifest: canonical_file(&base.join(manifest), "driver Cargo manifest")?,
            },
            BootPackageSourceFile::LocalFiles {
                configuration,
                binary,
            } => BootPackageSource::LocalFiles {
                configuration: canonical_file(&base.join(configuration), "driver configuration")?,
                binary: canonical_file(&base.join(binary), "driver binary")?,
            },
            BootPackageSourceFile::GitCargo {
                repository,
                revision,
                manifest,
            } => {
                if revision.trim().is_empty() {
                    return Err(format!(
                        "git driver `{repository}` requires a pinned revision"
                    ));
                }
                if manifest.is_absolute() {
                    return Err(format!(
                        "git driver manifest must be repository-relative: {}",
                        manifest.display()
                    ));
                }
                BootPackageSource::GitCargo {
                    repository,
                    revision,
                    manifest,
                }
            }
        });
    }

    Ok(BuildPlan {
        id: parsed.id,
        kernel: KernelPlan {
            manifest: kernel_manifest,
            package: parsed.kernel.package,
            binary: parsed.kernel.binary,
            target: kernel_target,
            import_library_machine: parsed.kernel.import_library_machine,
            no_default_features: parsed.kernel.no_default_features,
            features: parsed.kernel.features,
        },
        drivers: DriversPlan {
            target: driver_target,
            boot_packages,
        },
        stub: StubPlan {
            manifest: stub_manifest,
            package: parsed.stub.package,
            binary: parsed.stub.binary,
            target: parsed.stub.target,
            rustflags: parsed.stub.rustflags,
        },
        bootloader: BootloaderPlan {
            output: parsed.bootloader.output,
        },
    })
}

pub fn load_launch(root: &Path, selector: &str) -> Result<LaunchPlan, String> {
    let path = resolve_manifest(root, "launches", selector)?;
    let parsed: LaunchFile = parse_manifest(&path)?;
    require_schema(parsed.schema, &path)?;
    require_id(&parsed.id, &path)?;
    if parsed.provider != "qemu" {
        return Err(format!(
            "unsupported launch provider `{}` in {}; only `qemu` is implemented",
            parsed.provider,
            path.display()
        ));
    }
    if parsed.compatible_platforms.is_empty() {
        return Err(format!(
            "launch must declare at least one compatible platform: {}",
            path.display()
        ));
    }
    if parsed.supported_hosts.is_empty() {
        return Err(format!(
            "launch must declare at least one supported host: {}",
            path.display()
        ));
    }

    Ok(LaunchPlan {
        id: parsed.id,
        executable: parsed.executable,
        compatible_platforms: parsed.compatible_platforms,
        supported_hosts: parsed.supported_hosts,
        supported_host_arches: parsed.supported_host_arches,
        firmware_files: parsed.firmware_files,
        args: parsed.args,
        debug_args: parsed.debug_args,
        lldb_metadata_args: parsed.lldb_metadata_args,
        defaults: parsed.defaults,
        capabilities: parsed.capabilities,
    })
}

pub fn load_host(root: &Path, selector: &str) -> Result<HostPlan, String> {
    let path = resolve_manifest(root, "hosts", selector)?;
    let base = manifest_parent(&path)?;
    let parsed: HostFile = parse_manifest(&path)?;
    require_schema(parsed.schema, &path)?;
    require_id(&parsed.id, &path)?;

    Ok(HostPlan {
        id: parsed.id,
        os: parsed.os,
        executable_patterns: parsed
            .qemu
            .executable_patterns
            .into_iter()
            .map(|path| resolve_candidate(base, path))
            .collect(),
        data_directories: parsed
            .qemu
            .data_directories
            .into_iter()
            .map(|path| resolve_candidate(base, path))
            .collect(),
    })
}

fn resolve_manifest(root: &Path, directory: &str, selector: &str) -> Result<PathBuf, String> {
    let requested = Path::new(selector);
    let path = if requested.extension().and_then(|value| value.to_str()) == Some("toml")
        || requested.components().count() > 1
    {
        if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            root.join(requested)
        }
    } else {
        root.join(directory).join(format!("{selector}.toml"))
    };
    canonical_file(&path, &format!("{directory} manifest"))
}

fn parse_manifest<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let source = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    toml::from_str(&source).map_err(|err| format!("failed to parse {}: {err}", path.display()))
}

fn manifest_parent(path: &Path) -> Result<&Path, String> {
    path.parent()
        .ok_or_else(|| format!("manifest has no parent: {}", path.display()))
}

fn require_schema(schema: u32, path: &Path) -> Result<(), String> {
    if schema == 1 {
        Ok(())
    } else {
        Err(format!(
            "unsupported schema {schema} in {}; expected 1",
            path.display()
        ))
    }
}

fn require_id(id: &str, path: &Path) -> Result<(), String> {
    if id.trim().is_empty() {
        Err(format!("id cannot be empty in {}", path.display()))
    } else {
        Ok(())
    }
}

fn resolve_candidate(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn canonical_file(path: &Path, what: &str) -> Result<PathBuf, String> {
    if !path.is_file() {
        return Err(format!("{what} does not exist: {}", path.display()));
    }
    dunce::canonicalize(path)
        .map_err(|err| format!("failed to canonicalize {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{load_host, load_launch, load_platform, BootPackageFile, BootPackageSourceFile};
    use std::path::Path;

    #[test]
    fn parses_all_boot_package_source_kinds() {
        let local: BootPackageFile =
            toml::from_str(r#"source = { kind = "local-cargo", manifest = "driver/Cargo.toml" }"#)
                .unwrap();
        assert!(matches!(
            local.source,
            BootPackageSourceFile::LocalCargo { .. }
        ));

        let files: BootPackageFile = toml::from_str(
            r#"source = { kind = "local-files", configuration = "driver.toml", binary = "driver.dll" }"#,
        )
        .unwrap();
        assert!(matches!(
            files.source,
            BootPackageSourceFile::LocalFiles { .. }
        ));

        let git: BootPackageFile = toml::from_str(
            r#"source = { kind = "git-cargo", repository = "https://example.invalid/driver.git", revision = "deadbeef", manifest = "Cargo.toml" }"#,
        )
        .unwrap();
        assert!(matches!(git.source, BootPackageSourceFile::GitCargo { .. }));
    }

    #[test]
    fn loads_repository_configuration_layers() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let platform = load_platform(root, "x86_64-uefi").unwrap();
        let tcg = load_launch(root, "qemu-x86_64-q35-tcg").unwrap();
        let whpx = load_launch(root, "qemu-x86_64-q35-whpx").unwrap();
        let aarch64 = load_platform(root, "aarch64-uefi").unwrap();
        let aarch64_tcg = load_launch(root, "qemu-aarch64-virt-tcg").unwrap();
        let aarch64_hvf = load_launch(root, "qemu-aarch64-virt-hvf").unwrap();
        let aarch64_kvm = load_launch(root, "qemu-aarch64-virt-kvm").unwrap();
        let windows = load_host(root, "windows").unwrap();

        assert_eq!(platform.id, "x86_64-uefi");
        assert!(tcg.capabilities.debug);
        assert!(!whpx.capabilities.debug);
        assert_eq!(aarch64.id, "aarch64-uefi");
        assert!(aarch64.kernel.no_default_features);
        assert_eq!(aarch64.kernel.features, ["allocator-mimalloc"]);
        assert!(aarch64_tcg.capabilities.debug);
        assert!(!aarch64_hvf.capabilities.debug);
        assert!(!aarch64_kvm.capabilities.debug);
        assert_eq!(windows.id, "windows");
        assert_eq!(windows.os, "windows");
    }
}
