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
    pub runner: RunnerFile,
}

#[derive(Debug, Deserialize)]
pub struct KernelFile {
    pub manifest: PathBuf,
    pub package: String,
    pub binary: String,
    pub target: PathBuf,
    pub import_library_machine: String,
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

#[derive(Debug, Deserialize)]
pub struct RunnerFile {
    pub provider: String,
    pub executable: String,
    #[serde(default)]
    pub executable_fallbacks: Vec<PathBuf>,
    #[serde(default)]
    pub firmware_candidates: Vec<PathBuf>,
    #[serde(default)]
    pub firmware_files_from_qemu: Vec<PathBuf>,
    pub machine: String,
    pub cpu: String,
    pub default_memory: String,
    pub iommu: String,
    pub iommu_whpx: String,
}

#[derive(Debug)]
pub struct BuildPlan {
    pub id: String,
    pub kernel: KernelPlan,
    pub drivers: DriversPlan,
    pub stub: StubPlan,
    pub bootloader: BootloaderPlan,
    pub runner: RunnerPlan,
}

#[derive(Debug)]
pub struct KernelPlan {
    pub manifest: PathBuf,
    pub package: String,
    pub binary: String,
    pub target: PathBuf,
    pub import_library_machine: String,
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

#[derive(Debug)]
pub struct RunnerPlan {
    pub executable: String,
    pub executable_fallbacks: Vec<PathBuf>,
    pub firmware_candidates: Vec<PathBuf>,
    pub firmware_files_from_qemu: Vec<PathBuf>,
    pub machine: String,
    pub cpu: String,
    pub default_memory: String,
    pub iommu: String,
    pub iommu_whpx: String,
}

pub fn load(root: &Path, selector: &str) -> Result<BuildPlan, String> {
    let requested = Path::new(selector);
    let platform_file = if requested.extension().and_then(|value| value.to_str()) == Some("toml")
        || requested.components().count() > 1
    {
        if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            root.join(requested)
        }
    } else {
        root.join("platforms").join(format!("{selector}.toml"))
    };
    let platform_file = canonical_file(&platform_file, "platform manifest")?;
    let base = platform_file.parent().ok_or_else(|| {
        format!(
            "platform manifest has no parent: {}",
            platform_file.display()
        )
    })?;
    let source = fs::read_to_string(&platform_file)
        .map_err(|err| format!("failed to read {}: {err}", platform_file.display()))?;
    let parsed: PlatformFile = toml::from_str(&source)
        .map_err(|err| format!("failed to parse {}: {err}", platform_file.display()))?;

    if parsed.schema != 1 {
        return Err(format!(
            "unsupported platform schema {} in {}; expected 1",
            parsed.schema,
            platform_file.display()
        ));
    }
    if parsed.id.trim().is_empty() {
        return Err("platform id cannot be empty".to_string());
    }
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
    if parsed.runner.provider != "qemu" {
        return Err(format!(
            "unsupported runner `{}`; only `qemu` is implemented",
            parsed.runner.provider
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
        runner: RunnerPlan {
            executable: parsed.runner.executable,
            executable_fallbacks: parsed
                .runner
                .executable_fallbacks
                .into_iter()
                .map(|path| resolve_candidate(base, path))
                .collect(),
            firmware_candidates: parsed
                .runner
                .firmware_candidates
                .into_iter()
                .map(|path| resolve_candidate(base, path))
                .collect(),
            firmware_files_from_qemu: parsed.runner.firmware_files_from_qemu,
            machine: parsed.runner.machine,
            cpu: parsed.runner.cpu,
            default_memory: parsed.runner.default_memory,
            iommu: parsed.runner.iommu,
            iommu_whpx: parsed.runner.iommu_whpx,
        },
    })
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
    use super::{BootPackageFile, BootPackageSourceFile};

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
}
