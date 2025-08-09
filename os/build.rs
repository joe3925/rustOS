use bootloader::{BiosBoot, BootConfig, UefiBoot};
use std::{
    env, fs,
    path::PathBuf,
    process::{Command, Stdio},
};

const UEFI: bool = true;

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
    let kernel_source = root_dir.join("kernel").join("src");
    let image_path = target_dir.join("boot.img");
    let efi_path = target_dir.join("kernel.efi");

    let asm_src = kernel_source.join("ap_startup.asm");
    let asm_bin = target_dir.parent().unwrap().join("ap_startup.bin");

    let status = Command::new("nasm")
        .args(&["-f", "bin", "-o"])
        .arg(&asm_bin)
        .arg(&asm_src)
        .status()
        .expect("Failed to run nasm");
    assert!(status.success(), "nasm failed");

    println!("cargo:rerun-if-changed=src/ap_startup.asm");

    if UEFI {
        let config = BootConfig::default();
        let mut uefi_boot = UefiBoot::new(&kernel_path);
        uefi_boot.set_boot_config(&config);
        uefi_boot
            .create_disk_image(&image_path)
            .expect("Failed to create UEFI image");
    } else {
        BiosBoot::new(&kernel_path)
            .create_disk_image(&image_path)
            .expect("Failed to create BIOS image");
    }

    fs::copy(&kernel_path, &efi_path).expect("Failed to copy EFI file");

    println!("cargo:rustc-env=BOOTLOADER_IMAGE={}", image_path.display());
    println!("cargo:rustc-env=KERNEL_EFI={}", efi_path.display());
}
