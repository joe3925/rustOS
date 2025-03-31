use bootloader::{BiosBoot, DiskImageBuilder};
use std::env;
use std::path::PathBuf;

fn main() {
    // Path to your kernel binary
    let kernel_path = env::var("CARGO_BIN_FILE_KERNEL_kernel")
        .expect("Could not find kernel binary");

    let kernel_path = PathBuf::from(kernel_path);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let bios_path = out_dir.join("boot-bios.img");
    BiosBoot::new(&kernel_path)
        .create_disk_image(&bios_path)
        .expect("Failed to create BIOS image");

    println!("cargo:rustc-env=BOOTLOADER_BIOS_IMAGE={}", bios_path.display());
}
