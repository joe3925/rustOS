use crate::file_system::file::{File, OpenFlags};
use crate::println;
use alloc::vec::Vec;
use goblin::Object;
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
    match Object::parse(&file) {
        Object::Elf(elf) => {
            println!("elf: {:#?}", &elf);
        }
        Object::PE(pe) => {
            println!("pe: {:#?}", &pe);
        }
        Object::COFF(coff) => {
            println!("coff: {:#?}", &coff);
        }
        Object::Mach(mach) => {
            println!("mach: {:#?}", &mach);
        }
        Object::Archive(archive) => {
            println!("archive: {:#?}", &archive);
        }
        Object::Unknown(magic) => { println!("unknown magic: {:#x}", magic) }
        _ => {}
    }
}