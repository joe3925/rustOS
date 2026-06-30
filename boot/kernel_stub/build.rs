use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
struct PackageManifest {
    schema: u32,
    packages: Vec<PackageEntry>,
}

#[derive(Deserialize)]
struct PackageEntry {
    name: String,
    configuration: PathBuf,
    binary: PathBuf,
}

#[derive(Clone, Copy)]
struct KernelPeTarget {
    machine: u16,
    machine_name: &'static str,
    optional_magic: u16,
    image_base: u64,
}

fn kernel_pe_target() -> KernelPeTarget {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    match target_arch.as_str() {
        "x86_64" => KernelPeTarget {
            machine: 0x8664,
            machine_name: "x86_64",
            optional_magic: 0x20B,
            image_base: 0xFFFF_8500_0000_0000,
        },
        _ => panic!("kernel_stub build does not have an implementation for target architecture `{target_arch}`"),
    }
}

fn main() {
    let kernel_pe = kernel_pe_path();
    validate_kernel_pe(&kernel_pe, kernel_pe_target());
    generate_boot_packages();

    println!("cargo:rerun-if-changed={}", kernel_pe.display());
    println!("cargo:rustc-env=KERNEL_PE_PATH={}", kernel_pe.display());
}

fn kernel_pe_path() -> PathBuf {
    println!("cargo:rerun-if-env-changed=KERNEL_PE_PATH");
    if let Some(path) = env::var_os("KERNEL_PE_PATH").map(PathBuf::from) {
        if !path.is_file() {
            panic!(
                "KERNEL_PE_PATH points to a missing or non-file path: {}",
                path.display()
            );
        }

        return path;
    }

    panic!("KERNEL_PE_PATH is not set; build through `cargo run -p xtask` so the PE kernel is built first")
}

fn generate_boot_packages() {
    println!("cargo:rerun-if-env-changed=RUSTOS_BOOT_PACKAGES_MANIFEST");
    let manifest_path = env::var_os("RUSTOS_BOOT_PACKAGES_MANIFEST")
        .map(PathBuf::from)
        .expect("RUSTOS_BOOT_PACKAGES_MANIFEST is not set; build through xtask");
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    let source = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", manifest_path.display()));
    let manifest: PackageManifest = toml::from_str(&source)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", manifest_path.display()));
    assert_eq!(
        manifest.schema, 1,
        "unsupported boot package manifest schema"
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let package_dir = out_dir.join("boot_packages");
    fs::create_dir_all(&package_dir).expect("failed to create boot package output directory");
    let mut generated =
        String::from("pub static EMBEDDED_BOOT_PACKAGES: &[kernel_abi::BootPackage] = &[\n");
    for (index, package) in manifest.packages.iter().enumerate() {
        assert!(
            !package.name.is_empty(),
            "boot package name cannot be empty"
        );
        assert!(
            package
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
            "boot package name contains unsupported characters: {}",
            package.name
        );
        assert!(
            package.configuration.is_file(),
            "missing boot package configuration: {}",
            package.configuration.display()
        );
        assert!(
            package.binary.is_file(),
            "missing boot package binary: {}",
            package.binary.display()
        );
        println!("cargo:rerun-if-changed={}", package.configuration.display());
        println!("cargo:rerun-if-changed={}", package.binary.display());
        fs::copy(
            &package.configuration,
            package_dir.join(format!("{index}.toml")),
        )
        .expect("failed to stage boot package configuration");
        fs::copy(&package.binary, package_dir.join(format!("{index}.dll")))
            .expect("failed to stage boot package binary");
        generated.push_str(&format!(
            "kernel_abi::BootPackage::from_static(b{:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/boot_packages/{index}.toml\")), include_bytes!(concat!(env!(\"OUT_DIR\"), \"/boot_packages/{index}.dll\"))),\n",
            package.name
        ));
    }
    generated.push_str("];\n");
    fs::write(out_dir.join("boot_packages.rs"), generated)
        .expect("failed to generate boot package descriptors");
}

fn validate_kernel_pe(path: &PathBuf, target: KernelPeTarget) {
    let bytes = fs::read(path).unwrap_or_else(|err| {
        panic!(
            "failed to read kernel PE artifact {}: {err}",
            path.display()
        )
    });

    let pe_offset = read_u32(&bytes, 0x3c) as usize;
    if read_u16(&bytes, 0) != 0x5A4D {
        panic!("kernel artifact is not an MZ/PE image: {}", path.display());
    }
    if read_u32(&bytes, pe_offset) != 0x0000_4550 {
        panic!(
            "kernel artifact has an invalid PE signature: {}",
            path.display()
        );
    }

    let coff = pe_offset + 4;
    let optional = coff + 20;
    let machine = read_u16(&bytes, coff);
    let magic = read_u16(&bytes, optional);
    let image_base = read_u64(&bytes, optional + 24);

    if machine != target.machine {
        panic!(
            "kernel PE machine is not {}: 0x{machine:x}",
            target.machine_name
        );
    }
    if magic != target.optional_magic {
        panic!("kernel PE is not PE32+: 0x{magic:x}");
    }
    if image_base != target.image_base {
        panic!(
            "kernel PE image base is 0x{image_base:x}, expected 0x{:x}; build it through the kernel_stub artifact dependency",
            target.image_base
        );
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let data = bytes
        .get(offset..offset + 2)
        .unwrap_or_else(|| panic!("kernel PE is truncated at offset 0x{offset:x}"));
    u16::from_le_bytes(data.try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let data = bytes
        .get(offset..offset + 4)
        .unwrap_or_else(|| panic!("kernel PE is truncated at offset 0x{offset:x}"));
    u32::from_le_bytes(data.try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let data = bytes
        .get(offset..offset + 8)
        .unwrap_or_else(|| panic!("kernel PE is truncated at offset 0x{offset:x}"));
    u64::from_le_bytes(data.try_into().unwrap())
}
