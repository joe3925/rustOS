use std::{
    env, fs,
    path::{Path, PathBuf},
};

const KERNEL_PE_BASE: u64 = 0xFFFF_8500_0000_0000;

fn main() {
    let kernel_pe = kernel_pe_path();
    validate_kernel_pe(&kernel_pe);
    publish_stable_kernel_artifacts(&kernel_pe);

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

fn publish_stable_kernel_artifacts(kernel_pe: &Path) {
    let stable_kernel_pe = stable_target_path("kernel.exe");
    copy_artifact(kernel_pe, &stable_kernel_pe, "kernel PE");

    let kernel_pdb = kernel_pe.with_extension("pdb");
    if kernel_pdb.is_file() {
        copy_artifact(
            &kernel_pdb,
            &stable_kernel_pe.with_extension("pdb"),
            "kernel PDB",
        );
        println!("cargo:rerun-if-changed={}", kernel_pdb.display());
    }
}

fn stable_target_path(file_name: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent()
        .expect("kernel_stub should live under workspace root");
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());

    workspace_root.join("target").join(profile).join(file_name)
}

fn copy_artifact(source: &Path, destination: &Path, what: &str) {
    let destination_dir = destination.parent().unwrap_or_else(|| {
        panic!(
            "stable {what} path has no parent: {}",
            destination.display()
        )
    });

    fs::create_dir_all(destination_dir).unwrap_or_else(|err| {
        panic!(
            "failed to create stable {what} directory {}: {err}",
            destination_dir.display()
        )
    });
    fs::copy(source, destination).unwrap_or_else(|err| {
        panic!(
            "failed to copy {what} from {} to {}: {err}",
            source.display(),
            destination.display()
        )
    });
}

fn validate_kernel_pe(path: &PathBuf) {
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

    if machine != 0x8664 {
        panic!("kernel PE machine is not x86_64: 0x{machine:x}");
    }
    if magic != 0x20B {
        panic!("kernel PE is not PE32+: 0x{magic:x}");
    }
    if image_base != KERNEL_PE_BASE {
        panic!(
            "kernel PE image base is 0x{image_base:x}, expected 0x{KERNEL_PE_BASE:x}; build it through the kernel_stub artifact dependency"
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
