use std::env;
use std::path::PathBuf;
fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let krnl_lib_path = manifest_dir.join("../../kernel");

    println!("cargo:rustc-link-search=native={}", krnl_lib_path.display());
    println!("cargo:rustc-link-lib=static=KRNL"); 
}
