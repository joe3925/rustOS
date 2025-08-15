use bootloader::{BiosBoot, BootConfig, UefiBoot};
use fatfs::FatType;
use std::{
    env, fs,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
};

/// Flip to false if you want a BIOS image instead.
const UEFI: bool = true;
const BOOTSTRAP_DRIVERS: &[&str] = &["acpi", "pci", "BASE"];
const BYTES_PER_CLUSTER: u32 = 32768;
const BYTES_PER_SECTOR: u16 = 512;
fn main() {
    // --- existing: get paths, build AP trampoline ---------------------------------
    let kernel_path =
        env::var("CARGO_BIN_FILE_KERNEL_kernel").expect("Could not find kernel binary");
    let kernel_path = PathBuf::from(kernel_path);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let target_dir = out_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap(); // .../target/<profile>

    let root_dir = target_dir.parent().unwrap().parent().unwrap(); // workspace root
    let kernel_source = root_dir.join("kernel").join("src");
    let image_path = target_dir.join("boot.img");
    let efi_path = target_dir.join("kernel.efi");

    let asm_src = kernel_source.join("ap_startup.asm");
    let asm_bin = target_dir.parent().unwrap().join("ap_startup.bin");

    let status = Command::new("nasm")
        .args(&["-f", "bin", "-o"])
        .arg(&asm_bin)
        .arg(&asm_src)
        .status()
        .expect("Failed to run nasm");
    assert!(status.success(), "nasm failed");

    println!("cargo:rerun-if-changed={}", asm_src.display());

    // --- NEW: build tiny FAT32 image that contains your bootstrap drivers ----------

    let bootset_img_path = pack_bootset_image(&root_dir, &target_dir);

    // Tell rustc where the image is so the kernel can `include_bytes!` it.

    // --- existing: make bootloader disk image -------------------------------------
    if UEFI {
        let config = BootConfig::default();
        let mut uefi_boot = UefiBoot::new(&kernel_path);
        uefi_boot.set_boot_config(&config);
        uefi_boot
            .create_disk_image(&image_path)
            .expect("Failed to create UEFI image");
    } else {
        BiosBoot::new(&kernel_path)
            .create_disk_image(&image_path)
            .expect("Failed to create BIOS image");
    }

    fs::copy(&kernel_path, &efi_path).expect("Failed to copy EFI file");

    println!("cargo:rustc-env=BOOTLOADER_IMAGE={}", image_path.display());
    println!("cargo:rustc-env=KERNEL_EFI={}", efi_path.display());
}

fn pack_bootset_image(root_dir: &Path, out_dir: &Path) -> PathBuf {
    use fatfs::{format_volume, FileSystem, FormatVolumeOptions, FsOptions};
    use std::fs::File as HostFile;
    use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
    use std::path::Path;
    use walkdir::WalkDir;

    if BOOTSTRAP_DRIVERS.is_empty() {
        println!("cargo:rerun-if-env-changed=DRIVER_ROOT");
        println!("cargo:rerun-if-env-changed=BOOTSET_DRIVERS");
    }

    let default_driver_root = root_dir.join("target").join("DRIVERS");
    let driver_root = std::env::var("DRIVER_ROOT")
        .map(PathBuf::from)
        .unwrap_or(default_driver_root);

    let wanted: Vec<String> = if !BOOTSTRAP_DRIVERS.is_empty() {
        BOOTSTRAP_DRIVERS.iter().map(|s| s.to_string()).collect()
    } else {
        std::env::var("BOOTSET_DRIVERS")
            .ok()
            .and_then(|s| {
                let v: Vec<String> = s
                    .split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect();
                if v.is_empty() {
                    None
                } else {
                    Some(v)
                }
            })
            .unwrap_or_else(|| {
                driver_root
                    .read_dir()
                    .ok()
                    .into_iter()
                    .flat_map(|rd| rd)
                    .filter_map(|e| {
                        let p = e.unwrap().path();
                        if p.is_dir() {
                            p.file_name().map(|n| n.to_string_lossy().to_string())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
    };

    for pkg in &wanted {
        let pkg_path = driver_root.join(pkg);
        println!("cargo:rerun-if-changed={}", pkg_path.display());
        if let Ok(rd) = pkg_path.read_dir() {
            for e in rd.flatten() {
                if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    println!("cargo:rerun-if-changed={}", e.path().display());
                }
            }
        }
    }

    const IMG_SIZE: u64 = 64 * 1024 * 1024; // 64 MiB
    let mut backing = Cursor::new(vec![0u8; IMG_SIZE as usize]);

    // Format FAT (keep whatever options you already use)
    let mut opts = FormatVolumeOptions::new()
        .bytes_per_sector(BYTES_PER_SECTOR)
        .bytes_per_cluster(BYTES_PER_CLUSTER)
        .fat_type(FatType::Fat32);

    format_volume(&mut backing, opts).expect("format FAT image");

    {
        // ---------- all FAT work in this inner scope ----------
        backing.seek(SeekFrom::Start(0)).unwrap();
        let fs = FileSystem::new(&mut backing, FsOptions::new()).expect("mount FAT image");
        let root = fs.root_dir();

        // INSTALL/DRIVERS hierarchy
        let install_dir = root
            .create_dir("INSTALL")
            .or_else(|_| root.open_dir("INSTALL"))
            .unwrap();
        let drv_dir = install_dir
            .create_dir("DRIVERS")
            .or_else(|_| install_dir.open_dir("DRIVERS"))
            .unwrap();

        for pkg in &wanted {
            let pkg_dir = drv_dir
                .create_dir(pkg)
                .or_else(|_| drv_dir.open_dir(pkg))
                .unwrap();
            let pkg_path = driver_root.join(pkg);
            if !pkg_path.is_dir() {
                eprintln!(
                    "warning: missing driver package folder: {}",
                    pkg_path.display()
                );
                continue;
            }

            // Prefer {pkg}.dll and {pkg}.toml if they exist; else copy all top-level files
            let preferred = [
                pkg_path.join(format!("{pkg}.dll")),
                pkg_path.join(format!("{pkg}.toml")),
            ];
            let mut wrote_any = false;

            for host in &preferred {
                if host.exists() {
                    wrote_any = true;
                    let name = host.file_name().unwrap().to_string_lossy().to_string();
                    let mut src = HostFile::open(host).expect("open driver file");
                    let mut dst = pkg_dir.create_file(&name).unwrap();
                    io::copy(&mut src, &mut dst).expect("copy driver file");
                }
            }

            if !wrote_any {
                for entry in WalkDir::new(&pkg_path).min_depth(1).max_depth(1) {
                    let entry = entry.unwrap();
                    if entry.file_type().is_file() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        let mut src = HostFile::open(entry.path()).unwrap();
                        let mut dst = pkg_dir.create_file(&name).unwrap();
                        io::copy(&mut src, &mut dst).expect("copy driver file");
                    }
                }
            }
        }
        // ---------- fs, dirs, files dropped here ----------
    }

    // Shrink: find last non-zero byte to avoid embedding 64 MiB.
    let mut vec = backing.into_inner();
    let mut used = vec.len();
    while used > 0 && vec[used - 1] == 0 {
        used -= 1;
    }
    vec.truncate(used);

    let out_path = out_dir.join("bootset.img");
    std::fs::write(&out_path, &vec).expect("write bootset.img");
    out_path
}
