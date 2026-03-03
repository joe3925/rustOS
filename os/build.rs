use bootloader::{BootConfig, UefiBoot};
use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let kernel_path =
        env::var("CARGO_BIN_FILE_KERNEL_kernel").expect("Could not find kernel binary");
    let kernel_path = PathBuf::from(kernel_path);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let target_dir = out_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let root_dir = target_dir.parent().unwrap().parent().unwrap();
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
