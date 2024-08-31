use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use crate::drivers::ideDiskDriver::IdeController;
use crate::println;

const CLUSTER_SIZE: u64 = 32; //in KiB
const CLUSTER_OFFSET: u64 = CLUSTER_SIZE * 1024;
const RESERVED_SECTORS: u64 = 2;
const SECTORS_FOR_TABLE: u64 = 10;
const DATA_REGION_START: u64 = (SECTORS_FOR_TABLE + RESERVED_SECTORS) - 1;
#[derive(Debug)]
struct FileEntry {
    file_name: String,          // File name without extension
    file_extension: String,     // File extension
    attributes: u8,             // File attributes (e.g., read-only, hidden, etc.)
    creation_date: String,      // Creation date in format YYYY-MM-DD
    creation_time: String,      // Creation time in format HH:MM
    last_modified_date: String, // Last modified date in format YYYY-MM-DD
    last_modified_time: String, // Last modified time in format HH:MM
    starting_cluster: u32,      // Starting cluster number (assumed u32 for generality)
    file_size: u64,             // File size in bytes
}
#[derive(Debug)]
struct InfoSector{
    signature: u32, //offset: 0x0
    free_clusters: u32, //offset 0x1E8
    recently_allocated_cluster: u32, //offset: 0x1EC
    //one more signature at offset 0x1FC

}
#[derive(Debug)]
struct FileSystem {
    info: InfoSector,
    allocation_table: Vec<u32>, // FAT table, where each entry points to the next cluster
}

impl FileSystem {
    // Initialize the file system with a formatted drive
    pub fn new() -> Self {
        FileSystem {
            info: InfoSector {
                signature: 0xAA55,             // Some default signature
                free_clusters: 0xFFFFFFFF ,
                recently_allocated_cluster: 0xFFFFFFFF ,
            },
            allocation_table: vec![0xFFFFFFFF; 100], // Initialize FAT table with 100 entries, all free
        }
    }

    pub fn format_drive(&mut self, ide_controller: &mut IdeController, drive_label: &str) -> Result<(), &'static str> {
        let reserved_area_size = RESERVED_SECTORS * 512; // 512 bytes per sector


        let drive_size;
        if(drive_label == "C:"){
            drive_size = ide_controller.drives[0].capacity;
        }else{
            drive_size = ide_controller.drives[1].capacity;
        }
        let total_clusters = drive_size / CLUSTER_OFFSET;
        let total_size = reserved_area_size + total_clusters;
        let mut buffer = vec![0u8; 512]; // Buffer of one sector size (512 bytes)

        // Zero out reserved sectors
        for i in 0..RESERVED_SECTORS {
            ide_controller.write_sector(drive_label, i as u32, &buffer);
        }

        // Initialize the FAT table in memory
        self.allocation_table = vec![0xFFFFFFFF; total_clusters as usize]; // Mark all clusters as free

        // Write the FAT table to the drive
        for i in 0..total_clusters {
            let offset:usize = (i * 512) as usize;
            for j in 0..512 {
                buffer[j] = if offset + j < (self.allocation_table.len() as u32 * 4) as usize {
                    // Convert FAT table entry to bytes and write it to the buffer
                    let cluster_entry = self.allocation_table[(offset + j) as usize / 4];
                    let byte_offset = (j % 4) as u32;
                    ((cluster_entry >> (byte_offset * 8)) & 0xFF) as u8
                } else {
                    0
                };
            }
            ide_controller.write_sector(drive_label, (RESERVED_SECTORS + i) as u32, &buffer);
        }

        // Initialize the InfoSector
        self.info.free_clusters = self.allocation_table.len() as u32;
        self.info.recently_allocated_cluster = 0;

        println!("Drive {} formatted successfully.", drive_label);
        Ok(())
    }


}