use std::{env, path::PathBuf};

const DRIVER_IMAGE: &str = "volmgr"; // must match the DLL name and TOML basename

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let krnl_lib_path = manifest_dir.join("../../target");
    println!("cargo:rustc-link-search=native={}", krnl_lib_path.display());
    println!("cargo:rustc-link-lib=static=KRNL");

    let ws_root = manifest_dir.parent().unwrap().parent().unwrap();

    let crate_name = DRIVER_IMAGE;
    let drivers_root = ws_root.join("target").join("DRIVERS");
    let dest_dir = drivers_root.join(crate_name);

    let out_file = dest_dir.join(format!("{crate_name}.dll"));
    println!("cargo:rustc-link-arg=/OUT:{}", out_file.display());

    // ensure rerun
    println!("cargo:rerun-if-changed=build.rs");
}
