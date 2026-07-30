use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTOS_KERNEL_IMPORT_LIBRARY");
    println!("cargo:rerun-if-changed=../build_driver.rs");
    let Some(kernel_lib) = env::var_os("RUSTOS_KERNEL_IMPORT_LIBRARY").map(PathBuf::from) else {
        return;
    };
    let kernel_lib_dir = kernel_lib
        .parent()
        .expect("kernel import library has no parent");
    println!("cargo:rustc-link-search=native={}", kernel_lib_dir.display());
    println!("cargo:rustc-link-lib=static=kernel");
}
