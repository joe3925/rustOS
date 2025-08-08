use std::{env, fs, path::PathBuf};

const DRIVER_IMAGE: &str = "BASE";

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let krnl_lib_path = manifest_dir.join("../../target");
    println!("cargo:rustc-link-search=native={}", krnl_lib_path.display());
    println!("cargo:rustc-link-lib=static=KRNL");

    // workspace root
    let ws_root = manifest_dir
        .parent()
        .expect("driver is in workspace/driver/")
        .parent()
        .expect("workspace root is 2 levels up");

    let crate_name = DRIVER_IMAGE;

    // ensure only our DLL target dir exists
    let drivers_root = ws_root.join("target").join("DRIVERS");
    fs::create_dir_all(&drivers_root).expect("create target/DRIVERS");

    let dest_dir = drivers_root.join(crate_name);
    fs::create_dir_all(&dest_dir).expect("create target/DRIVERS/<name>");

    // Override only the DLL output location
    if cfg!(target_env = "msvc") {
        let out_file = dest_dir.join(format!("{crate_name}.dll"));
        println!("cargo:rustc-link-arg=/OUT:{}", out_file.display());
    } else {
        let out_file = dest_dir.join(format!("lib{crate_name}.so"));
        println!("cargo:rustc-link-arg=-o{}", out_file.display());
    }

    // Copy the TOML alongside the DLL
    let toml_src = manifest_dir.join("src").join(format!("{crate_name}.toml"));
    if toml_src.exists() {
        let toml_dst = dest_dir.join(toml_src.file_name().unwrap());
        fs::copy(&toml_src, toml_dst).expect("copy .toml");
    }

    println!("cargo:rerun-if-changed={}", toml_src.display());
}
