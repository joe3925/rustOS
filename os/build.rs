use bootloader::{BiosBoot, UefiBoot};
use std::{env, fs, path::PathBuf};
// Make sure both are imported

const UEFI: bool = true; // true = build UEFI, false = build BIOS

fn main() {
    let kernel_path = env::var("CARGO_BIN_FILE_KERNEL_kernel")
        .expect("Could not find kernel binary");
    let kernel_path = PathBuf::from(kernel_path);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let target_dir = out_dir
        .parent().unwrap()
        .parent().unwrap()
        .parent().unwrap();

    let image_path = target_dir.join("boot.img");
    let efi_path = target_dir.join("kernel.efi");

    // Create boot image
    if UEFI {
        UefiBoot::new(&kernel_path)
            .create_disk_image(&image_path)
            .expect("Failed to create UEFI image");
    } else {
        BiosBoot::new(&kernel_path)
            .create_disk_image(&image_path)
            .expect("Failed to create BIOS image");
    }

    // Copy the kernel .efi binary for GDB usage
    fs::copy(&kernel_path, &efi_path).expect("Failed to copy EFI file");

    // Let cargo know where the bootloader image is
    println!("cargo:rustc-env=BOOTLOADER_IMAGE={}", image_path.display());
    // Also export EFI path if needed
    println!("cargo:rustc-env=KERNEL_EFI={}", efi_path.display());
}
