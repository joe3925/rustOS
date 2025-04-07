use crate::file_system::file::{File, OpenFlags};
use alloc::vec::Vec;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use x86_64::VirtAddr;

struct ElfAllocation {
    size: usize,
    virt_address: VirtAddr,
}
struct ElfRuntimeGuide {
    needed_pages: Vec<ElfAllocation>,
    entry_point: u64,
}
pub fn parse_elf(path: &str) {
    let open_flags = [OpenFlags::CreateNew, OpenFlags::ReadOnly];
    //add result handling later
    let file_handle = File::open(path, &open_flags).expect("failed to find elf");
    let file = file_handle.read().expect("elf read failed");
    let elf = ElfBytes::<AnyEndian>::minimal_parse(file.as_slice()).expect("elf parse failed");
    elf.segments();
}