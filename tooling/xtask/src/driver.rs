use crate::artifacts::{DriverPackageArtifact, DriverProvenance, KernelSdkArtifact};
use crate::config::{BootPackageSource, BuildPlan};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{hash_map::DefaultHasher, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::thread;

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
    metadata: Value,
    targets: Vec<CargoTarget>,
}

#[derive(Debug, Deserialize)]
struct CargoTarget {
    name: String,
    crate_types: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DriverConfiguration {
    image: String,
}

pub fn resolve_all(
    root: &Path,
    plan: &BuildPlan,
    sdk: &KernelSdkArtifact,
    release: bool,
    offline: bool,
) -> Result<Vec<DriverPackageArtifact>, String> {
    let mut packages = Vec::with_capacity(plan.drivers.boot_packages.len());
    let mut names = HashSet::new();
    for source in &plan.drivers.boot_packages {
        let package = match source {
            BootPackageSource::LocalCargo { manifest } => build_cargo_driver(
                root,
                plan,
                manifest,
                sdk,
                release,
                DriverProvenance::LocalCargo {
                    manifest: manifest.clone(),
                },
            )?,
            BootPackageSource::LocalFiles {
                configuration,
                binary,
            } => resolve_files(configuration, binary, DriverProvenance::LocalFiles)?,
            BootPackageSource::GitCargo {
                repository,
                revision,
                manifest,
            } => {
                let checkout = checkout_git(root, repository, revision, offline)?;
                let checkout = dunce::canonicalize(&checkout).map_err(|err| {
                    format!(
                        "failed to canonicalize git checkout {}: {err}",
                        checkout.display()
                    )
                })?;
                let local_manifest = checkout.join(manifest);
                let local_manifest = dunce::canonicalize(&local_manifest).map_err(|err| {
                    format!(
                        "failed to resolve git driver manifest {}: {err}",
                        local_manifest.display()
                    )
                })?;
                if !local_manifest.starts_with(&checkout) || !local_manifest.is_file() {
                    return Err(format!(
                        "git driver manifest escapes its checkout: {}",
                        manifest.display()
                    ));
                }
                build_cargo_driver(
                    root,
                    plan,
                    &local_manifest,
                    sdk,
                    release,
                    DriverProvenance::GitCargo {
                        repository: repository.clone(),
                        revision: revision.clone(),
                        manifest: manifest.clone(),
                    },
                )?
            }
        };
        if !names.insert(package.name.clone()) {
            return Err(format!("duplicate boot package `{}`", package.name));
        }
        packages.push(package);
    }
    Ok(packages)
}

fn build_cargo_driver(
    root: &Path,
    plan: &BuildPlan,
    manifest: &Path,
    sdk: &KernelSdkArtifact,
    release: bool,
    provenance: DriverProvenance,
) -> Result<DriverPackageArtifact, String> {
    let package = package_metadata(manifest)?;
    let driver_meta = package.metadata.get("rustos-driver").ok_or_else(|| {
        format!(
            "driver package `{}` is missing [package.metadata.rustos-driver]",
            package.name
        )
    })?;
    let configuration = driver_meta
        .get("configuration")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "driver package `{}` is missing rustos-driver.configuration",
                package.name
            )
        })?;
    let configuration = dunce::canonicalize(
        manifest
            .parent()
            .expect("Cargo manifest should have a parent")
            .join(configuration),
    )
    .map_err(|err| format!("failed to resolve driver configuration: {err}"))?;
    let selected_target = driver_meta.get("target").and_then(Value::as_str);
    let mut cdylibs = package
        .targets
        .iter()
        .filter(|target| target.crate_types.iter().any(|kind| kind == "cdylib"))
        .filter(|target| selected_target.is_none_or(|name| target.name == name));
    let target = cdylibs.next().ok_or_else(|| {
        format!(
            "driver package `{}` has no selected cdylib target",
            package.name
        )
    })?;
    if cdylibs.next().is_some() {
        return Err(format!(
            "driver package `{}` has multiple cdylib targets; set rustos-driver.target",
            package.name
        ));
    }

    let target_dir = root
        .join("target")
        .join("cargo")
        .join(&plan.id)
        .join("drivers");
    let mut command = super::cargo(root);
    command
        .arg("build")
        .args(["--manifest-path"])
        .arg(manifest)
        .args(["-p", &package.id, "--target"])
        .arg(&plan.drivers.target)
        .args(super::build_std_args())
        .args([
            "--message-format",
            "json-render-diagnostics",
            "--color",
            "always",
        ])
        .env("CARGO_TARGET_DIR", target_dir)
        .env("RUSTOS_KERNEL_IMPORT_LIBRARY", &sdk.import_library);
    if release {
        command.arg("--release");
    }
    let binary = cargo_artifact(command, &package.id, &target.name, "dll", "building driver")?;
    resolve_files(&configuration, &binary, provenance)
}

fn package_metadata(manifest: &Path) -> Result<CargoPackage, String> {
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(manifest)
        .output()
        .map_err(|err| {
            format!(
                "failed to run cargo metadata for {}: {err}",
                manifest.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed for {}:\n{}",
            manifest.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse cargo metadata: {err}"))?;
    let canonical = dunce::canonicalize(manifest).map_err(|err| {
        format!(
            "failed to canonicalize driver manifest {}: {err}",
            manifest.display()
        )
    })?;
    metadata
        .packages
        .into_iter()
        .find(|package| {
            dunce::canonicalize(&package.manifest_path).is_ok_and(|path| path == canonical)
        })
        .ok_or_else(|| {
            format!(
                "cargo metadata did not contain package at {}",
                manifest.display()
            )
        })
}

pub fn cargo_package_identity(manifest: &Path) -> Result<(String, String), String> {
    let package = package_metadata(manifest)?;
    Ok((package.id, package.name))
}

fn resolve_files(
    configuration: &Path,
    binary: &Path,
    provenance: DriverProvenance,
) -> Result<DriverPackageArtifact, String> {
    if !configuration.is_file() || !binary.is_file() {
        return Err(format!(
            "driver package files are missing: {} and {}",
            configuration.display(),
            binary.display()
        ));
    }
    let contents = fs::read_to_string(configuration)
        .map_err(|err| format!("failed to read {}: {err}", configuration.display()))?;
    let parsed: DriverConfiguration = toml::from_str(&contents)
        .map_err(|err| format!("failed to parse {}: {err}", configuration.display()))?;
    let expected = Path::new(&parsed.image)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid driver image name `{}`", parsed.image))?;
    if expected != parsed.image {
        return Err(format!(
            "driver image must be a plain filename: `{}`",
            parsed.image
        ));
    }
    let actual = binary
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "driver binary filename is not valid UTF-8: {}",
                binary.display()
            )
        })?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "driver configuration expects `{expected}`, but Cargo produced `{actual}`"
        ));
    }
    let name = Path::new(expected)
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid driver image name `{expected}`"))?
        .to_string();
    Ok(DriverPackageArtifact {
        name,
        configuration: configuration.to_path_buf(),
        binary: binary.to_path_buf(),
        source: provenance,
    })
}

pub fn cargo_artifact(
    mut command: Command,
    package_id: &str,
    target_name: &str,
    extension: &str,
    step: &str,
) -> Result<PathBuf, String> {
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|err| format!("failed to start {step}: {err}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("failed to capture stdout for {step}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("failed to capture stderr for {step}"))?;

    let stderr_thread = thread::spawn(move || -> Vec<u8> {
        let mut reader = BufReader::new(stderr);
        let mut captured = Vec::new();
        let mut buffer = [0u8; 4096];

        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    captured.extend_from_slice(&buffer[..read]);
                    let _ = std::io::stdout().write_all(&buffer[..read]);
                    let _ = std::io::stdout().flush();
                }
                Err(_) => break,
            }
        }

        captured
    });

    let mut artifact = None;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    loop {
        line.clear();

        let read = reader
            .read_line(&mut line)
            .map_err(|err| format!("failed to read cargo output for {step}: {err}"))?;

        if read == 0 {
            break;
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);

        if trimmed.is_empty() {
            continue;
        }

        let Ok(message) = serde_json::from_str::<Value>(trimmed) else {
            println!("{trimmed}");
            continue;
        };

        if let Some(rendered) = message
            .get("message")
            .and_then(|value| value.get("rendered"))
            .and_then(Value::as_str)
        {
            print!("{rendered}");
            let _ = std::io::stdout().flush();
        }

        if message.get("reason").and_then(Value::as_str) != Some("compiler-artifact")
            || message.get("package_id").and_then(Value::as_str) != Some(package_id)
            || message
                .get("target")
                .and_then(|target| target.get("name"))
                .and_then(Value::as_str)
                != Some(target_name)
        {
            continue;
        }

        let Some(path) = message
            .get("filenames")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(PathBuf::from)
            .find(|path| {
                if extension.is_empty() {
                    path.file_name().and_then(|value| value.to_str()) == Some(target_name)
                } else {
                    path.extension()
                        .and_then(|value| value.to_str())
                        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
                }
            })
        else {
            continue;
        };

        artifact = Some(path);
    }

    let status = child
        .wait()
        .map_err(|err| format!("failed to wait for {step}: {err}"))?;

    let stderr = stderr_thread
        .join()
        .map_err(|_| format!("stderr forwarding thread panicked during {step}"))?;

    if !status.success() {
        return Err(format!(
            "{step} failed with {}:\n{}",
            status,
            String::from_utf8_lossy(&stderr)
        ));
    }

    artifact.ok_or_else(|| {
        format!("{step} succeeded but did not report `{target_name}` as an artifact")
    })
}

fn checkout_git(
    root: &Path,
    repository: &str,
    revision: &str,
    offline: bool,
) -> Result<PathBuf, String> {
    let mut hasher = DefaultHasher::new();
    repository.hash(&mut hasher);
    let repository_key = format!("{:016x}", hasher.finish());
    let revision_key: String = revision
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    let checkout = root
        .join("target/rustos/sources/git")
        .join(repository_key)
        .join(revision_key);
    if checkout.join(".git").exists() {
        return Ok(checkout);
    }
    if offline {
        return Err(format!(
            "git driver {repository}@{revision} is not cached and --offline was requested"
        ));
    }
    let parent = checkout
        .parent()
        .expect("git checkout should have a parent");
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create git cache {}: {err}", parent.display()))?;
    let status = Command::new("git")
        .args(["clone", "--no-checkout", repository])
        .arg(&checkout)
        .status()
        .map_err(|err| format!("failed to clone {repository}: {err}"))?;
    if !status.success() {
        return Err(format!("git clone failed for {repository} with {status}"));
    }
    let status = Command::new("git")
        .arg("-C")
        .arg(&checkout)
        .args(["checkout", "--detach", revision])
        .status()
        .map_err(|err| format!("failed to check out {repository}@{revision}: {err}"))?;
    if !status.success() {
        return Err(format!(
            "git checkout failed for {repository}@{revision} with {status}"
        ));
    }
    Ok(checkout)
}
