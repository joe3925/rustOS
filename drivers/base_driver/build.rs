use std::{env, fs, path::PathBuf};
const DRIVER_IMAGE: &str = "BASE";
fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let krnl_lib_path = manifest_dir.join("../../target");

    println!("cargo:rustc-link-search=native={}", krnl_lib_path.display());
    println!("cargo:rustc-link-lib=static=KRNL");
    // names & paths ----------------------------------------------------
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ws_root = manifest_dir
        .parent()
        .expect("driver is in workspace/driver/")
        .parent()
        .expect("workspace root is 2 levels up");
    let crate_name = DRIVER_IMAGE.to_string();

    let dest_dir = ws_root.join("target").join("DRIVERS").join(&crate_name);
    fs::create_dir_all(&dest_dir).unwrap();

    if cfg!(target_env = "msvc") {
        let out_file = dest_dir.join(format!("{crate_name}.dll"));
        println!("cargo:rustc-link-arg=/OUT:{}", out_file.display());
    } else {
        // lld / gcc-style
        let out_file = dest_dir.join(format!("lib{crate_name}.so"));
        println!("cargo:rustc-link-arg=-o{}", out_file.display());
    }

    let toml_src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("src")
        .join(format!("{crate_name}.toml"));
    if toml_src.exists() {
        fs::copy(&toml_src, dest_dir.join(toml_src.file_name().unwrap())).expect("copy .toml");
    }

    println!("cargo:rerun-if-changed={}", toml_src.display());
}
