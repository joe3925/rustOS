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
        Ok(Object::Elf(elf)) => {
            println!("elf: {:#?}", &elf);
        }
        Ok(Object::PE(pe)) => {
            println!("pe: {:#?}", &pe);
        }
        Ok(Object::COFF(coff)) => {
            println!("coff: {:#?}", &coff);
        }
        Ok(Object::Mach(mach)) => {
            println!("mach: {:#?}", &mach);
        }
        Ok(Object::Archive(archive)) => {
            println!("archive: {:#?}", &archive);
        }
        Ok(Object::Unknown(magic)) => { println!("unknown magic: {:#x}", magic) }
        _ => {}
    }
}