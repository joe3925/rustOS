use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use implib::{Flavor, ImportLibrary, MachineType};

fn generate_def_file(exports_path: &PathBuf, def_out_path: &PathBuf) -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string(exports_path)?;

    let start = contents
        .find('{')
        .ok_or("Missing opening `{` in export! macro")?;
    let end = contents
        .rfind('}')
        .ok_or("Missing closing `}` in export! macro")?;
    let export_body = &contents[start + 1..end];

    let mut lines = Vec::new();
    lines.push("LIBRARY KRNL".to_string());
    lines.push("EXPORTS".to_string());

    for line in export_body.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if !trimmed.is_empty() {
            lines.push(format!("    {}", trimmed));
        }
    }

    fs::write(def_out_path, lines.join("\n"))?;
    Ok(())
}

fn machine_from_target(target: &str) -> MachineType {
    if target.contains("aarch64") {
        MachineType::ARM64
    } else if target.contains("arm") {
        MachineType::ARMNT
    } else if target.contains("i686") || (target.contains("x86") && !target.contains("x86_64")) {
        MachineType::I386
    } else {
        MachineType::AMD64
    }
}

fn flavor_from_target(target: &str) -> Flavor {
    if target.contains("gnu") {
        Flavor::Gnu
    } else {
        Flavor::Msvc
    }
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap();

    let exports_path = manifest_dir.join("src").join("exports.rs");
    println!("cargo:rerun-if-changed={}", exports_path.display());

    let def_path = out_dir.join("KRNL.def");
    generate_def_file(&exports_path, &def_path).expect("Failed to generate .def file");

    let def_text = fs::read_to_string(&def_path).expect("Failed to read generated .def");

    let machine = machine_from_target(&target);
    let flavor = flavor_from_target(&target);

    let lib_out = out_dir.join("KRNL.lib");
    let lib = ImportLibrary::new(&def_text, machine, flavor).expect("implib failed");
    let mut f = fs::File::create(&lib_out).expect("Failed to create KRNL.lib");
    lib.write_to(&mut f).expect("Failed to write KRNL.lib");

    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            out_dir
                .ancestors()
                .nth(5) // .../target/<profile>/build/<pkg>/out -> target is 4 up
                .expect("unexpected OUT_DIR layout")
                .to_path_buf()
        });

    let shared_lib = target_dir.join("KRNL.lib");
    fs::copy(&lib_out, &shared_lib).expect("Failed to copy KRNL.lib to target/");

    println!("cargo:rerun-if-changed=build.rs");
}
