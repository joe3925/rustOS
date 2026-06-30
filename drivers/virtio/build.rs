use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTOS_KERNEL_IMPORT_LIBRARY");
    let kernel_lib = env::var_os("RUSTOS_KERNEL_IMPORT_LIBRARY")
        .map(PathBuf::from)
        .expect("RUSTOS_KERNEL_IMPORT_LIBRARY is not set; build through xtask");
    let krnl_lib_path = kernel_lib
        .parent()
        .expect("kernel import library has no parent");
    println!("cargo:rustc-link-search=native={}", krnl_lib_path.display());
    println!("cargo:rustc-link-lib=static=kernel");

    println!("cargo:rerun-if-changed=build.rs");
}
