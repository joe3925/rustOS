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
    println!("cargo:rerun-if-env-changed=KERNEL_STUB_PATH");
    let path = env::var_os("KERNEL_STUB_PATH")
        .map(PathBuf::from)
        .expect("KERNEL_STUB_PATH is not set; build through `cargo run -p xtask` so the kernel stub is built first");

    assert!(
        path.is_file(),
        "KERNEL_STUB_PATH points to a missing or non-file path: {}",
        path.display()
    );
    println!("cargo:rerun-if-changed={}", path.display());
    path
}
