use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use crate::drivers::ideDiskDriver::IdeController;
use crate::println;

const CLUSTER_SIZE: u32 = 32; //in KiB
const CLUSTER_OFFSET: u32 = CLUSTER_SIZE * 1024;
const SECTORS_PER_CLUSTER: u32 = (CLUSTER_SIZE * 1024) / 512;
const RESERVED_SECTORS: u32 = 2;
const INFO_SECTOR: u32 = RESERVED_SECTORS;
const SECTORS_FOR_TABLE: u32 = 10;
const DATA_REGION_START: u32 = (SECTORS_FOR_TABLE + RESERVED_SECTORS);
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
struct Dir {
    files: Vec<FileEntry>,
    next_cluster: u8,
}
#[derive(Debug)]
pub struct FileSystem {
    info: InfoSector,
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
        }
    }
//TODO: figure out why sector 1 is being formatted as a data sector
    pub fn format_drive(&mut self, ide_controller: &mut IdeController, drive_label: &str) -> Result<(), &'static str> {
        let reserved_area_size = RESERVED_SECTORS * 512; // 512 bytes per sector

        let drive_size;
        if(drive_label == "C:"){
            drive_size = ide_controller.drives[0].capacity;
        }else{
            drive_size = ide_controller.drives[1].capacity;
        }
        let mut info_sec_buffer = vec![0x0; 512];
        info_sec_buffer[0x0] = self.info.signature as u8;
        info_sec_buffer[0x1E8] = self.info.free_clusters as u8;
        info_sec_buffer[0x1FC] = self.info.recently_allocated_cluster as u8;
        //create the info sector

        let total_clusters = drive_size as u32 / CLUSTER_OFFSET;
        let mut buffer = vec![0u8; 512]; // Buffer of one sector size (512 bytes)

        for i in 0..RESERVED_SECTORS {
            ide_controller.write_sector(drive_label, i, &buffer);
        }
        ide_controller.write_sector(drive_label, INFO_SECTOR, &info_sec_buffer);


        for j in 0..512 {
            buffer[j] = 0xFF;
        }


        // Write the FAT table to the drive
        let itr = total_clusters / 512;
        println!("{}", total_clusters);
        println!("{}", itr);

        for i in RESERVED_SECTORS..itr + RESERVED_SECTORS {
            ide_controller.write_sector(drive_label, (i + 1), &buffer);
            if(i % 10 == 0) {
                println!("{}", i);
            }
        }
        let mut readBuffer = vec![0u8; 512]; // Buffer of one sector size (512 bytes)

    //validate data sectors
        for i in RESERVED_SECTORS..itr + RESERVED_SECTORS{
            ide_controller.read_sector(drive_label, (i + 1), &mut readBuffer);
            for j in 0..512{
                if (readBuffer[j] != buffer[j]){
                    println!("Sector {} is invalid", i);
                    break;
                }
            }
        }

        // Initialize the InfoSector
        self.info.free_clusters = total_clusters as u32;
        self.info.recently_allocated_cluster = 0;

        println!("Drive {} formatted successfully.", drive_label);
        Ok(())
    }



}