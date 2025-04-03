use bootloader::BiosBoot;
use std::env;
use std::path::PathBuf;


fn main() {
    let kernel_path = env::var("CARGO_BIN_FILE_KERNEL_kernel")
        .expect("Could not find kernel binary");

    let kernel_path = PathBuf::from(kernel_path);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Go back 3 directories from OUT_DIR
    let target_dir = out_dir
        .parent().unwrap()
        .parent().unwrap()
        .parent().unwrap();

    let bios_path = target_dir.join("boot.img");

    BiosBoot::new(&kernel_path)
        .create_disk_image(&bios_path)
        .expect("Failed to create BIOS image");

    println!("cargo:rustc-env=BOOTLOADER_BIOS_IMAGE={}", bios_path.display());
}