use core::mem::transmute;
use core::ptr::{copy_nonoverlapping, read_unaligned, write_unaligned};

use crate::file_system::file::File;
use crate::memory::paging::base_page_size;
use crate::platform;
use crate::println;
use crate::profiling::unwind::register_pe_unwind_module;
use crate::scheduling::task::Task;
use crate::structs::range_tracker::RangeTracker;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use goblin::pe::dll_characteristic::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
use goblin::pe::PE;
use kernel_types::arch::VirtAddr;
use kernel_types::device::ModuleHandle;
use kernel_types::fs::{OpenFlags, Path};
use kernel_types::memory::{
    Module, PeExportInfo, PeImportInfo, PeInfo, PePdbFormat, PePdbInfo, PeSectionInfo,
};
use kernel_types::status::LoadError;
use spin::rwlock::RwLock;

use super::program::{Program, PROGRAM_MANAGER};

pub struct PELoader {
    buffer: Box<[u8]>,
    pe: PE<'static>,
    path: Path,
    current_base: VirtAddr,
}

struct PeProcessLayout {
    image_size: u64,
    guard_size: u64,
    stack_size: u64,
    heap_size: u64,
    total_size: u64,
}

impl PeProcessLayout {
    fn stack_base(&self, image_base: VirtAddr) -> VirtAddr {
        image_base + self.image_size + self.guard_size
    }

    fn stack_top(&self, image_base: VirtAddr) -> VirtAddr {
        self.stack_base(image_base) + self.stack_size
    }

    fn stack_heap_size(&self) -> Option<u64> {
        self.stack_size.checked_add(self.heap_size)
    }
}

impl PELoader {
    pub async fn new(path: &Path) -> Option<Self> {
        let open_flags = [OpenFlags::Open, OpenFlags::ReadOnly];
        let file_handle = File::open(path, &open_flags).await.ok()?;
        let mut file_data = alloc::vec![0u8; file_handle.size as usize];
        let n = file_handle.read(&mut file_data).await.ok()?;
        file_data.truncate(n);

        let boxed: Box<[u8]> = file_data.into_boxed_slice();
        let slice: &[u8] = &boxed;

        let pe = PE::parse(slice).ok()?;
        let pe_static: PE<'static> = unsafe { transmute::<PE<'_>, PE<'static>>(pe) };
        let base = VirtAddr::new(pe_static.image_base as u64);

        Some(Self {
            buffer: boxed,
            pe: pe_static,
            path: path.clone(),
            current_base: base,
        })
    }

    pub fn list_import_dlls(&self) -> Vec<String> {
        let mut dlls = Vec::new();

        for imp in &self.pe.imports {
            dlls.push(imp.dll.to_string().to_ascii_lowercase());
        }

        dlls
    }

    pub fn is_pic(&self) -> bool {
        let dll_chars = self
            .pe
            .header
            .optional_header
            .as_ref()
            .map(|h| h.windows_fields.dll_characteristics)
            .unwrap_or(0);

        if dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0 {
            return false;
        }

        self.reloc_table().is_none()
    }

    pub fn is_aslr(&self) -> bool {
        let dll_chars = self
            .pe
            .header
            .optional_header
            .as_ref()
            .map(|h| h.windows_fields.dll_characteristics)
            .unwrap_or(0);

        dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0
    }

    pub fn needs_relocation(&self) -> bool {
        self.is_aslr() && self.reloc_table().is_some()
    }

    pub fn reloc_table(&self) -> Option<impl Iterator<Item = RelocationEntry> + '_> {
        let section = self
            .pe
            .sections
            .iter()
            .find(|s| matches!(s.name(), Ok(".reloc")))?;

        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let buffer = self.buffer.get(start..start.checked_add(size)?)?;

        Some(parse_base_relocations(buffer))
    }

    fn image_allocation_size(&self) -> Result<u64, LoadError> {
        let opt_hdr = self
            .pe
            .header
            .optional_header
            .as_ref()
            .ok_or(LoadError::MissingSections)?;

        align_up(
            opt_hdr.windows_fields.size_of_image as u64,
            base_page_size(),
        )
        .ok_or(LoadError::NoMemory)
    }

    fn process_layout(&self) -> Result<PeProcessLayout, LoadError> {
        let opt_hdr = self
            .pe
            .header
            .optional_header
            .as_ref()
            .ok_or(LoadError::MissingSections)?;

        let page_size = base_page_size();

        let image_size = align_up(opt_hdr.windows_fields.size_of_image as u64, page_size)
            .ok_or(LoadError::NoMemory)?;
        let stack_size = align_up(opt_hdr.windows_fields.size_of_stack_reserve, page_size)
            .ok_or(LoadError::NoMemory)?;
        let heap_size = align_up(opt_hdr.windows_fields.size_of_heap_reserve, page_size)
            .ok_or(LoadError::NoMemory)?;
        let guard_size = page_size;

        let total_size = image_size
            .checked_add(guard_size)
            .and_then(|v| v.checked_add(stack_size))
            .and_then(|v| v.checked_add(heap_size))
            .ok_or(LoadError::NoMemory)?;

        Ok(PeProcessLayout {
            image_size,
            guard_size,
            stack_size,
            heap_size,
            total_size,
        })
    }

    fn map_into_program(
        &mut self,
        program: &mut Program,
    ) -> Result<(ModuleHandle, Vec<(String, usize)>, u64), LoadError> {
        let opt = self
            .pe
            .header
            .optional_header
            .as_ref()
            .ok_or(LoadError::MissingSections)?;

        let image_size = self.image_allocation_size()?;
        let preferred_base = opt.windows_fields.image_base;
        let has_relocs = self.reloc_table().is_some();
        let preferred_reserved = program.tracker.alloc(preferred_base, image_size).is_ok();
        let wants_aslr = self.is_aslr() && has_relocs;
        let need_reloc = !preferred_reserved || wants_aslr;

        if need_reloc && !has_relocs {
            return Err(LoadError::UnsupportedRelocationFormat);
        }

        let exports = self.collect_exports();

        if need_reloc {
            if preferred_reserved {
                program.tracker.dealloc(preferred_base, image_size);
            }

            let new_base = self.allocate_relocation_base_for_size(&program.tracker, image_size)?;
            self.current_base = new_base;

            unsafe {
                program.virtual_map(new_base, image_size as usize)?;
            }

            self.load_sections()?;
            self.relocate()?;
        } else {
            self.current_base = VirtAddr::new(preferred_base);

            unsafe {
                program.virtual_map(self.current_base, image_size as usize)?;
            }

            self.load_sections()?;
        }

        let base = self.current_base.as_u64();
        let relocated = base != preferred_base;
        let pe_info = self.collect_pe_info(relocated)?;
        register_pe_unwind_module(base, image_size, &pe_info.sections);

        let title = self.path.file_name().unwrap_or("unknown").to_string();
        let pdb_path = pe_info
            .pdb
            .as_ref()
            .map(|pdb| pdb.path.as_str())
            .unwrap_or("<none>");

        println!(
            "DBG: Loaded DLL '{}' at VMM Range: {:#x} - {:#x} (Size: {:#x}) PDB at: {}",
            title,
            base,
            base + image_size,
            image_size,
            pdb_path
        );

        {
            let path_str = self.path.to_string();
            let debug_sections: Vec<crate::debug_metadata::DebugLoadedSection<'_>> = pe_info
                .sections
                .iter()
                .map(|s| crate::debug_metadata::DebugLoadedSection {
                    name: s.name.as_str(),
                    runtime_addr: base + s.virtual_address as u64,
                    size: s.virtual_size as u64,
                })
                .collect();

            crate::debug_metadata::module_loaded(&crate::debug_metadata::DebugLoadedModule {
                name: title.as_str(),
                path: Some(path_str.as_str()),
                preferred_image_base: preferred_base,
                loaded_image_base: base,
                sections: &debug_sections,
            });
        }

        let module = Module {
            title,
            image_path: self.path.clone(),
            parent_pid: program.pid,
            image_base: self.current_base.into(),
            symbols: exports.clone(),
            pe_info: Some(pe_info),
        };

        let handle = Arc::new(RwLock::new(module));
        program.modules.write().push(handle.clone());

        Ok((handle, exports, image_size))
    }

    fn patch_imports_sync(&mut self, program: &mut Program) -> Result<(), LoadError> {
        self.patch_imports(program)
    }

    pub async fn dll_load(&mut self, program: &mut Program) -> Result<ModuleHandle, LoadError> {
        if !self.pe.is_lib {
            return Err(LoadError::NotDLL);
        }

        if !self.pe.is_64 {
            return Err(LoadError::Not64Bit);
        }

        let new_address_space_root = program.address_space_root;
        let old_address_space_root = crate::memory::paging::current_address_space_root();

        let were_enabled = platform::interrupts_enabled();
        if were_enabled {
            platform::disable_interrupts();
        }

        unsafe {
            crate::memory::paging::switch_address_space_root(new_address_space_root);
        }

        let map_result = self.map_into_program(program);

        unsafe {
            crate::memory::paging::switch_address_space_root(old_address_space_root);
        }

        if were_enabled {
            platform::enable_interrupts();
        }

        let (handle, _exports, _image_size) = map_result?;

        let old_address_space_root = crate::memory::paging::current_address_space_root();

        let were_enabled = platform::interrupts_enabled();
        if were_enabled {
            platform::disable_interrupts();
        }

        unsafe {
            crate::memory::paging::switch_address_space_root(new_address_space_root);
        }

        let patch_result = self.patch_imports_sync(program);

        unsafe {
            crate::memory::paging::switch_address_space_root(old_address_space_root);
        }

        if were_enabled {
            platform::enable_interrupts();
        }

        patch_result?;

        Ok(handle)
    }

    pub async fn load(&mut self) -> Result<u64, LoadError> {
        if self.pe.is_lib {
            return Err(LoadError::IsNotExecutable);
        }

        if !self.pe.is_64 {
            return Err(LoadError::Not64Bit);
        }

        let entry = self.pe.entry;
        if entry == 0 {
            return Err(LoadError::NoEntryPoint);
        }

        let opt_hdr = self
            .pe
            .header
            .optional_header
            .as_ref()
            .ok_or(LoadError::MissingSections)?;

        if self.pe.sections.is_empty() {
            return Err(LoadError::MissingSections);
        }

        let layout = self.process_layout()?;
        let range_tracker = Arc::new(RangeTracker::new(base_page_size(), 0x00007FFFFFFFFFFFu64));

        let preferred_image_base = opt_hdr.windows_fields.image_base;
        let has_relocs = self.reloc_table().is_some();
        let wants_aslr = self.is_aslr() && has_relocs;

        let preferred_reserved = if wants_aslr {
            false
        } else {
            range_tracker
                .alloc(preferred_image_base, layout.total_size)
                .is_ok()
        };

        if !preferred_reserved {
            if !has_relocs {
                return Err(LoadError::UnsupportedRelocationFormat);
            }

            self.current_base =
                self.allocate_relocation_base_for_size(&range_tracker, layout.total_size)?;
        } else {
            self.current_base = VirtAddr::new(preferred_image_base);
        }

        let new_frame = crate::memory::paging::create_user_address_space()?;
        let old_address_space_root = crate::memory::paging::current_address_space_root();

        let stack_base = layout.stack_base(self.current_base);
        let stack_top = layout.stack_top(self.current_base);
        let stack_heap_size = layout.stack_heap_size().ok_or(LoadError::NoMemory)?;

        let title = self.path.file_name().unwrap_or("unknown").to_string();

        let mut program = Program::new(
            title,
            self.path.clone(),
            self.current_base,
            new_frame,
            range_tracker,
        );

        program.pe_info =
            Some(self.collect_pe_info(self.current_base.as_u64() != preferred_image_base)?);

        let were_enabled = platform::interrupts_enabled();
        if were_enabled {
            platform::disable_interrupts();
        }

        unsafe {
            crate::memory::paging::switch_address_space_root(new_frame);
        }

        let map_result = (|| -> Result<(), LoadError> {
            unsafe {
                program.virtual_map(program.image_base, layout.image_size as usize)?;
            }

            if stack_heap_size != 0 {
                unsafe {
                    program.virtual_map(stack_base, stack_heap_size as usize)?;
                }
            }

            self.load_sections()?;

            if self.current_base.as_u64() != preferred_image_base {
                self.relocate()?;
            }

            Ok(())
        })();

        unsafe {
            crate::memory::paging::switch_address_space_root(old_address_space_root);
        }

        if were_enabled {
            platform::enable_interrupts();
        }

        map_result?;

        let entry_addr = self
            .current_base
            .as_u64()
            .checked_add(entry as u64)
            .ok_or(LoadError::NoEntryPoint)?;

        let entry_fn = unsafe { transmute::<usize, extern "C" fn(usize)>(entry_addr as usize) };

        let thread = Task::new_user_mode(
            entry_fn,
            0,
            layout.stack_size,
            self.path
                .parent()
                .map(|p| p.to_string())
                .unwrap_or_default(),
            stack_top,
            0,
        );

        program.main_thread = Some(thread);

        self.resolve_imports(&mut program).await?;

        let old_address_space_root = crate::memory::paging::current_address_space_root();

        let were_enabled = platform::interrupts_enabled();
        if were_enabled {
            platform::disable_interrupts();
        }

        unsafe {
            crate::memory::paging::switch_address_space_root(new_frame);
        }

        let patch_result = self.patch_imports(&mut program);

        unsafe {
            crate::memory::paging::switch_address_space_root(old_address_space_root);
        }

        if were_enabled {
            platform::enable_interrupts();
        }

        patch_result?;

        let pid = PROGRAM_MANAGER.add_program(program);
        PROGRAM_MANAGER.start_pid(pid);

        Ok(pid)
    }

    pub async fn resolve_imports(&mut self, program: &mut Program) -> Result<(), LoadError> {
        loop {
            let mut added = false;

            let (dlls, present): (Vec<String>, alloc::collections::BTreeSet<String>) = {
                let snapshot = program.modules.read();
                let dlls = self.list_import_dlls();
                let present = snapshot.iter().map(|m| m.read().title.clone()).collect();
                (dlls, present)
            };

            for dll in dlls {
                if present.contains(&dll) {
                    continue;
                }

                let path = Path::from_string(r"C:\BIN\MOD").join(&dll);
                program.load_module(path).await?;
                added = true;
            }

            if !added {
                break;
            }
        }

        Ok(())
    }

    pub fn calculate_allocation_size(&self) -> Result<usize, LoadError> {
        let layout = self.process_layout()?;
        usize::try_from(layout.total_size).map_err(|_| LoadError::NoMemory)
    }

    pub fn load_sections(&self) -> Result<(), LoadError> {
        let base = self.current_base;
        let buffer = &self.buffer;

        for section in &self.pe.sections {
            let virt_offset = section.virtual_address as u64;
            let virt_size = section.virtual_size as usize;
            let raw_offset = section.pointer_to_raw_data as usize;
            let raw_size = section.size_of_raw_data as usize;

            let raw_end = raw_offset
                .checked_add(raw_size)
                .ok_or(LoadError::MissingSections)?;

            if raw_end > buffer.len() {
                return Err(LoadError::MissingSections);
            }

            let dst = (base + virt_offset).as_mut_ptr::<u8>();

            unsafe {
                let src_ptr = buffer.as_ptr().add(raw_offset);
                copy_nonoverlapping(src_ptr, dst, raw_size);

                if virt_size > raw_size {
                    dst.add(raw_size).write_bytes(0, virt_size - raw_size);
                }
            }
        }

        Ok(())
    }

    pub fn relocate(&mut self) -> Result<(), LoadError> {
        let opt_hdr = self
            .pe
            .header
            .optional_header
            .as_ref()
            .ok_or(LoadError::MissingSections)?;

        let old_base = opt_hdr.windows_fields.image_base;
        let delta = self.current_base.as_u64().wrapping_sub(old_base);

        let relocs = self
            .reloc_table()
            .ok_or(LoadError::UnsupportedRelocationFormat)?;

        for entry in relocs {
            match entry.relocation_type {
                BaseRelocType::Absolute => continue,
                BaseRelocType::Dir64 => {
                    let target = self.current_base.as_u64() + entry.virtual_address as u64;

                    unsafe {
                        let p = target as *mut u8;
                        let current = read_unaligned(p as *const u64);
                        write_unaligned(p as *mut u64, current.wrapping_add(delta));
                    }
                }
                _ => return Err(LoadError::UnsupportedRelocationFormat),
            }
        }

        Ok(())
    }

    pub fn allocate_relocation_base(
        &mut self,
        range_tracker: &RangeTracker,
    ) -> Result<VirtAddr, LoadError> {
        let alloc_size = if self.pe.is_lib {
            self.image_allocation_size()?
        } else {
            self.process_layout()?.total_size
        };

        self.allocate_relocation_base_for_size(range_tracker, alloc_size)
    }

    fn allocate_relocation_base_for_size(
        &mut self,
        range_tracker: &RangeTracker,
        alloc_size: u64,
    ) -> Result<VirtAddr, LoadError> {
        let alloc_size = align_up(alloc_size, base_page_size()).ok_or(LoadError::NoMemory)?;

        let new_base = range_tracker
            .alloc_auto(alloc_size)
            .ok_or(LoadError::NoMemory)?;

        Ok(new_base.into())
    }

    fn collect_exports(&self) -> Vec<(String, usize)> {
        let mut out = Vec::new();

        for export in &self.pe.exports {
            if let Some(name) = export.name {
                out.push((name.to_string(), export.rva));
            }
        }

        out
    }

    fn collect_pe_info(&self, relocated: bool) -> Result<PeInfo, LoadError> {
        let opt_hdr = self
            .pe
            .header
            .optional_header
            .as_ref()
            .ok_or(LoadError::MissingSections)?;

        let coff = &self.pe.header.coff_header;
        let standard = &opt_hdr.standard_fields;
        let windows = &opt_hdr.windows_fields;

        Ok(PeInfo {
            is_64: self.pe.is_64,
            is_dll: self.pe.is_lib,
            machine: coff.machine,
            characteristics: coff.characteristics,
            time_date_stamp: coff.time_date_stamp,
            optional_magic: standard.magic,
            subsystem: windows.subsystem,
            dll_characteristics: windows.dll_characteristics,
            preferred_image_base: windows.image_base,
            loaded_image_base: self.current_base.into(),
            entry_rva: self.pe.entry,
            size_of_image: windows.size_of_image,
            size_of_headers: windows.size_of_headers,
            section_alignment: windows.section_alignment,
            file_alignment: windows.file_alignment,
            size_of_code: standard.size_of_code,
            size_of_initialized_data: standard.size_of_initialized_data,
            size_of_uninitialized_data: standard.size_of_uninitialized_data,
            stack_reserve: windows.size_of_stack_reserve,
            stack_commit: windows.size_of_stack_commit,
            heap_reserve: windows.size_of_heap_reserve,
            heap_commit: windows.size_of_heap_commit,
            aslr: self.is_aslr(),
            relocated,
            sections: self.collect_section_info(),
            imports: self.collect_import_info(),
            exports: self.collect_export_info(),
            pdb: self.collect_pdb_info(),
        })
    }

    fn collect_section_info(&self) -> Vec<PeSectionInfo> {
        self.pe
            .sections
            .iter()
            .map(|section| PeSectionInfo {
                name: section.name().unwrap_or("unknown").to_string(),
                virtual_address: section.virtual_address,
                virtual_size: section.virtual_size,
                raw_offset: section.pointer_to_raw_data,
                raw_size: section.size_of_raw_data,
                characteristics: section.characteristics,
            })
            .collect()
    }

    fn collect_import_info(&self) -> Vec<PeImportInfo> {
        self.pe
            .imports
            .iter()
            .map(|import| PeImportInfo {
                dll: import.dll.to_string(),
                name: import.name.to_string(),
                ordinal: import.ordinal,
                import_address_table_rva: import.offset as u64,
                hint_name_table_rva: import.rva as u64,
                thunk_size: import.size,
            })
            .collect()
    }

    fn collect_export_info(&self) -> Vec<PeExportInfo> {
        self.pe
            .exports
            .iter()
            .map(|export| PeExportInfo {
                name: export.name.map(|name| name.to_string()),
                rva: export.rva as u64,
            })
            .collect()
    }

    fn collect_pdb_info(&self) -> Option<PePdbInfo> {
        let debug = self.pe.debug_data.as_ref()?;

        if let Some(pdb) = debug.codeview_pdb70_debug_info {
            return Some(PePdbInfo {
                format: PePdbFormat::Pdb70,
                path: pdb_path_to_string(pdb.filename),
                age: pdb.age,
                guid: Some(pdb.signature),
                signature: None,
                codeview_offset: None,
            });
        }

        if let Some(pdb) = debug.codeview_pdb20_debug_info {
            return Some(PePdbInfo {
                format: PePdbFormat::Pdb20,
                path: pdb_path_to_string(pdb.filename),
                age: pdb.age,
                guid: None,
                signature: Some(pdb.signature),
                codeview_offset: Some(pdb.codeview_offset),
            });
        }

        None
    }

    pub fn patch_imports(&mut self, program: &mut Program) -> Result<(), LoadError> {
        for imp in &self.pe.imports {
            let dll_name = imp.dll.to_ascii_lowercase();
            let symbol_name = &imp.name;

            let abs_addr =
                program.find_import(dll_name.as_str(), symbol_name.to_string().as_str())?;

            let slot_va = self.current_base.as_u64() + imp.offset as u64;

            unsafe {
                (slot_va as *mut u64).write(abs_addr.as_u64());
            }
        }

        Ok(())
    }
}

fn pdb_path_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());

    core::str::from_utf8(&bytes[..end])
        .unwrap_or("")
        .to_string()
}

pub struct RelocationEntry {
    pub relocation_type: BaseRelocType,
    pub virtual_address: u32,
}

pub fn parse_base_relocations(reloc_data: &[u8]) -> impl Iterator<Item = RelocationEntry> + '_ {
    let mut offset = 0;

    core::iter::from_fn(move || {
        if offset + 8 > reloc_data.len() {
            return None;
        }

        let va = u32::from_le_bytes(reloc_data[offset..offset + 4].try_into().unwrap());
        let block_size = u32::from_le_bytes(reloc_data[offset + 4..offset + 8].try_into().unwrap());

        if block_size < 8 {
            return None;
        }

        let entry_count = ((block_size - 8) / 2) as usize;

        if offset + block_size as usize > reloc_data.len() {
            return None;
        }

        let entries_start = offset + 8;
        offset += block_size as usize;

        Some((0..entry_count).map(move |i| {
            let raw = u16::from_le_bytes(
                reloc_data[entries_start + i * 2..entries_start + i * 2 + 2]
                    .try_into()
                    .unwrap(),
            );

            let reloc_offset = raw & 0x0FFF;
            let reloc_type = BaseRelocType::try_from(raw >> 12).unwrap();

            RelocationEntry {
                relocation_type: reloc_type,
                virtual_address: va + reloc_offset as u32,
            }
        }))
    })
    .flatten()
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BaseRelocType {
    Absolute = 0x0000,
    HighLow = 0x0003,
    Dir64 = 0x000A,
}

impl core::convert::TryFrom<u16> for BaseRelocType {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0000 => Ok(BaseRelocType::Absolute),
            0x0003 => Ok(BaseRelocType::HighLow),
            0x000A => Ok(BaseRelocType::Dir64),
            _ => Err(()),
        }
    }
}

fn align_up(value: u64, align: u64) -> Option<u64> {
    if align == 0 || !align.is_power_of_two() {
        return None;
    }

    Some(value.checked_add(align - 1)? & !(align - 1))
}
