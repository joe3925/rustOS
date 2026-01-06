use std::{env, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let krnl_lib_path = manifest_dir.join("../../target");
    println!("cargo:rustc-link-search=native={}", krnl_lib_path.display());
    println!("cargo:rustc-link-lib=static=KRNL");
    println!("cargo:rerun-if-changed=build.rs");
}
