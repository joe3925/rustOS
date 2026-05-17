use bootloader::{BootConfig, UefiBoot};
use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let target_dir = out_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let kernel_path = kernel_stub_path();
    let image_path = target_dir.join("boot.img");
    let efi_path = target_dir.join("kernel.efi");

    let config = BootConfig::default();
    let mut uefi_boot = UefiBoot::new(&kernel_path);
    uefi_boot.set_boot_config(&config);
    uefi_boot
        .create_disk_image(&image_path)
        .expect("Failed to create UEFI image");

    fs::copy(&kernel_path, &efi_path).expect("Failed to copy EFI file");

    println!("cargo:rustc-env=BOOTLOADER_IMAGE={}", image_path.display());
    println!("cargo:rustc-env=KERNEL_EFI={}", efi_path.display());
}

fn kernel_stub_path() -> PathBuf {
    let path = artifact_path("KERNEL_STUB");
    assert!(
        path.is_file(),
        "kernel_stub artifact points to a missing or non-file path: {}",
        path.display()
    );
    println!("cargo:rerun-if-changed={}", path.display());
    path
}

fn artifact_path(dep_name: &str) -> PathBuf {
    let prefix = format!("CARGO_BIN_FILE_{dep_name}");
    let mut matches = env::vars_os()
        .filter_map(|(key, value)| {
            let key = key.into_string().ok()?;
            key.starts_with(&prefix).then_some((key, value))
        })
        .collect::<Vec<_>>();

    matches.sort_by(|left, right| left.0.cmp(&right.0));
    let mut paths = matches
        .iter()
        .map(|(_, path)| PathBuf::from(path))
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();

    match paths.as_slice() {
        [path] => path.clone(),
        [] => panic!(
            "Cargo did not provide a {dep_name} binary artifact; check os/Cargo.toml build-dependencies"
        ),
        many => panic!(
            "Cargo provided multiple distinct {dep_name} binary artifacts: {}",
            many.iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}
