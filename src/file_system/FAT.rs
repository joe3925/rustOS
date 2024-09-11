use alloc::string::{String, ToString};
use alloc::{format, vec};
use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use crate::drivers::ideDiskDriver::IdeController;
use crate::{print, println};
//TODO: find out why theres a memory leak maybe because the create file loop never ends could also be leaving data in buffer
const CLUSTER_SIZE: u32 = 32; //in KiB
const CLUSTER_OFFSET: u32 = CLUSTER_SIZE * 1024;
const SECTORS_PER_CLUSTER: u32 = (CLUSTER_SIZE * 1024) / 512;
const RESERVED_SECTORS: u32 = 2;
const INFO_SECTOR: u32 = RESERVED_SECTORS;
#[derive(Debug)]
struct FileEntry {
    file_name: String,          // 0x00 - 0x17 : 24 bytes
    file_extension: String,     // 0x18 - 0x2F : 24 bytes
    attributes: u8,             // 0x30        : 1 byte
    // 3 bytes padding for alignment          : 0x31 - 0x33
    creation_date: String,      // 0x34 - 0x4B : 24 bytes
    creation_time: String,      // 0x4C - 0x63 : 24 bytes
    last_modified_date: String, // 0x64 - 0x7B : 24 bytes
    last_modified_time: String, // 0x7C - 0x93 : 24 bytes
    starting_cluster: u32,      // 0x94 - 0x97 : 4 bytes
    file_size: u64,             // 0x98 - 0x9F : 8 bytes
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
pub struct FileSystem{
    info: InfoSector,
    drive_label: String,

}

impl FileSystem{
    // Initialize the file system with a formatted drive
    pub fn new(label: String) -> Self {

        FileSystem {
            info: InfoSector {
                signature: 0xAA55,             // Some default signature
                free_clusters: 0xFFFFFFFF ,
                recently_allocated_cluster: 0xFFFFFFFF ,
            },
            drive_label: label,
        }
    }
    //TODO: figure out why sector 1 is being formatted as a data sector
    pub fn format_drive(&mut self, ide_controller: &mut IdeController) -> Result<(), &'static str> {

        let drive_size;
        let drive_label = self.drive_label.clone();
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
            ide_controller.write_sector(drive_label.clone(), i, &mut buffer, 1);
        }
        ide_controller.write_sector(drive_label.clone(), INFO_SECTOR, &mut info_sec_buffer, 1);


        for j in 0..512 {
            buffer[j] = 0x00;
        }


        // Write the FAT table to the drive
        let itr = total_clusters / 512;

        for i in RESERVED_SECTORS..itr + RESERVED_SECTORS {
            ide_controller.write_sector(drive_label.clone(), (i + 1), &mut buffer, 1);

        }
        let mut readBuffer = vec![0u8; 512]; // Buffer of one sector size (512 bytes)

        //validate data sectors
        for i in RESERVED_SECTORS..itr + RESERVED_SECTORS{
            ide_controller.read_sector(drive_label.clone(), (i + 1), &mut readBuffer, 1);
            for j in 0..512{
                if (readBuffer[j] != buffer[j]){
                    println!("Sector {} is invalid", i);
                    break;
                }
            }
        }
        self.update_fat(ide_controller, 0, 0xFFFFFFFF);
        // Initialize the InfoSector
        self.info.free_clusters = total_clusters;
        self.info.recently_allocated_cluster = 0;


        println!("Drive {} formatted successfully.", self.drive_label);
        Ok(())
    }

    fn update_fat(
        &mut self,
        mut ide_controller: &mut IdeController,
        cluster_number: u32,
        next_cluster: u32,
    ) {
        // Calculate which sector the FAT entry is in
        let fat_offset = cluster_number * 4;
        let sector_number = (fat_offset / 512) + RESERVED_SECTORS + 1;
        let entry_offset = (fat_offset % 512) as usize;

        // Read the sector containing the FAT entry
        let mut buffer = vec![0u8; 512];
        ide_controller.read_sector(self.drive_label.clone(), sector_number, &mut buffer, 1);

        // Update the FAT entry in the buffer
        buffer[entry_offset] = (next_cluster & 0xFF) as u8;
        buffer[entry_offset + 1] = ((next_cluster >> 8) & 0xFF) as u8;
        buffer[entry_offset + 2] = ((next_cluster >> 16) & 0xFF) as u8;
        buffer[entry_offset + 3] = ((next_cluster >> 24) & 0xFF) as u8;

        // Write the updated sector back to the disk
        ide_controller.write_sector(self.drive_label.clone(), sector_number, &mut buffer, 1);
    }
    //TODO: update to support multi cluster root dirs
    pub fn read_root_dir(
        &mut self,
        ide_controller: &mut IdeController,
    ) -> Vec<FileEntry> {
        // 1. Allocate space for the root directory (assume one cluster for simplicity)
        let mut root_dir = vec![0u8; (SECTORS_PER_CLUSTER * 512) as usize];
        self.read_cluster(ide_controller, 0, &mut root_dir);

        // 2. Parse directory entries (each entry is 32 bytes)
        let entry_size = 32;
        let mut file_entries = Vec::new();

        for i in (0..root_dir.len()).step_by(entry_size) {
            // Check if the entry is valid (not empty or deleted)
            if root_dir[i] == 0x00 {
                // End of directory, stop parsing
                break;
            } else if root_dir[i] == 0xE5 {
                // Deleted entry, skip it
                continue;
            }

            // 3. Extract file information (assuming the fields are stored sequentially)
            let file_name = String::from_utf8_lossy(&root_dir[i..i + 8]).trim().to_string();
            let file_extension = String::from_utf8_lossy(&root_dir[i + 8..i + 11]).trim().to_string();
            let attributes = root_dir[i + 11];
            let starting_cluster = u32::from_le_bytes([root_dir[i + 26], root_dir[i + 27], 0, 0]);
            let file_size = u64::from_le_bytes([
                root_dir[i + 28], root_dir[i + 29], root_dir[i + 30], root_dir[i + 31],
                0, 0, 0, 0,
            ]);

            // Create a FileEntry and push it to the vector
            let file_entry = FileEntry {
                file_name,
                file_extension,
                attributes,
                creation_date: "".to_string(),  // Placeholder for creation date/time
                creation_time: "".to_string(),  // Placeholder for creation date/time
                last_modified_date: "".to_string(),
                last_modified_time: "".to_string(),
                starting_cluster,
                file_size,
            };

            file_entries.push(file_entry);
        }

        file_entries
    }
    //fc000
    pub fn create_and_write_file(
        &mut self,
        mut ide_controller: &mut IdeController,
        file_name: &str,
        file_extension: &str,
        file_data: &[u8],
    )
    {

        let cluster_size = CLUSTER_OFFSET as usize;
        let clusters_needed = file_data.len() / cluster_size;
        let mut free_cluster = self.find_free_cluster(ide_controller, 0);

        self.write_file_to_root(ide_controller, file_name, file_extension, free_cluster, file_data.len() as u64);

        for i in 0..clusters_needed{
            let mut next_cluster = 0xFFFFFFFF;
            if (i != clusters_needed - 1){
                next_cluster = self.find_free_cluster(ide_controller, free_cluster);
            }
            let data_offset = i * cluster_size;
            let mut buffer = vec!(0u8; cluster_size);

            for j in 0..buffer.len() {
                buffer[j] = file_data[j + data_offset]
            }
            println!("{}", free_cluster);
            self.write_cluster(ide_controller, free_cluster, &buffer);
            self.update_fat(ide_controller, free_cluster,next_cluster);
            free_cluster = next_cluster;
        }
    }

    pub fn read_file(
        &mut self,
        ide_controller: &mut IdeController,
        file_name: &str,
        file_extension: &str,
    ) -> Option<Vec<u8>> {
        let file_entries = self.read_root_dir(ide_controller);

        if(file_entries.len() == 0){
            return None;
        }
        let mut entry = &file_entries[0];
        //find the correct entry
        for i in 0..file_entries.len(){
            if(file_entries[i].file_name == file_name && file_entries[i].file_extension == file_extension){
                entry = &file_entries[i];
            }
        }
        let mut file_data = vec![0u8; entry.file_size as usize]; // Initialize the vector with zeros
        let remainder = entry.file_size % CLUSTER_OFFSET as u64;
        let clusters = self.get_all_clusters(ide_controller, entry.starting_cluster);
        for i in 0..clusters.len(){
            let mut cluster = vec!(0u8; CLUSTER_OFFSET as usize);
            self.read_cluster(ide_controller, clusters[i], &mut cluster);
            let base_offset = i * CLUSTER_OFFSET as usize;

            if (i + 1) != clusters.len() || remainder == 0{
                for j in 0..cluster.len() {

                    file_data[j + base_offset] = cluster[j];
                }
            }else{
                for j in 0..remainder as usize {

                    file_data[j + base_offset] = cluster[j];
                }
            }
        }

        Some(file_data)
    }
    //set ignore cluster to 0 to ignore no clusters
    fn find_free_cluster(&mut self, mut ide_controller: &mut IdeController, ignore_cluster: u32) -> u32 {
        let fat_sectors = self.calculate_data_region_start(ide_controller) - RESERVED_SECTORS;

        for i in 0..fat_sectors {
            let mut buffer = vec![0u8; 512];
            ide_controller.read_sector(self.drive_label.to_string(), i + RESERVED_SECTORS + 1, &mut buffer, 1);
            for j in 0..128 { // 128 = 512 bytes / 4 bytes per FAT entry
                let entry = u32::from_le_bytes([
                    buffer[j * 4],
                    buffer[j * 4 + 1],
                    buffer[j * 4 + 2],
                    buffer[j * 4 + 3],
                ]);
                if entry == 0x00000000 && (i * 128 + j as u32 != ignore_cluster){ // A free cluster is indicated by 0x00000000
                    //don't allow an overwrite of the root dir
                    if((i * 128 + j as u32) == 0){
                        return self.find_free_cluster(ide_controller, ignore_cluster);
                    }
                    return (i * 128 + j as u32); // Calculate the cluster number
                }
            }
        }

        0xFFFFFFFF // Return a special value indicating no free cluster was found
    }
    //TODO: modify to allocate a new cluster when full
    pub fn write_file_to_root(
        &mut self,
        mut ide_controller: &mut IdeController,
        file_name: &str,
        file_extension: &str,
        start_cluster: u32,
        size: u64
    ) {
        // Read the current root directory (one cluster)
        let mut root_dir = vec![0u8; (SECTORS_PER_CLUSTER * 512) as usize];
        self.read_cluster(&mut ide_controller, 0, &mut root_dir);

        // Find the first empty entry in the root directory (assuming 32-byte entries)
        let entry_size = 32; // FAT directory entry is always 32 bytes
        let mut entry_offset = None;
        for i in (0..root_dir.len()).step_by(entry_size) {
            if root_dir[i] == 0x00 || root_dir[i] == 0xE5 {
                entry_offset = Some(i);
                break;
            }
        }

        if let Some(offset) = entry_offset {
            // Write the file entry to the root directory at the found offset

            // File name (8 bytes, space padded)
            let mut name_bytes = [0x20; 8]; // 0x20 is space
            let name_slice = &file_name.as_bytes()[0..file_name.len().min(8)];
            name_bytes[..name_slice.len()].copy_from_slice(name_slice);
            root_dir[offset..offset + 8].copy_from_slice(&name_bytes);

            // File extension (3 bytes, space padded)
            let mut ext_bytes = [0x20; 3]; // 0x20 is space
            let ext_slice = &file_extension.as_bytes()[0..file_extension.len().min(3)];
            ext_bytes[..ext_slice.len()].copy_from_slice(ext_slice);
            root_dir[offset + 8..offset + 11].copy_from_slice(&ext_bytes);

            // File attributes (1 byte)
            root_dir[offset + 11] = 0x20; // Regular file (no special attributes)

            // Reserved (10 bytes)
            for i in 12..22 {
                root_dir[offset + i] = 0x00; // Clear reserved bytes
            }

            // Starting cluster (2 bytes, low 16 bits)
            let cluster_bytes = (start_cluster as u16).to_le_bytes();
            root_dir[offset + 26..offset + 28].copy_from_slice(&cluster_bytes);

            // File size (4 bytes)
            let size_bytes = (size as u32).to_le_bytes(); // FAT stores size as 32-bit value
            root_dir[offset + 28..offset + 32].copy_from_slice(&size_bytes);

            // Write the updated root directory back to disk
            self.write_cluster(&mut ide_controller, 0, &mut root_dir);
        } else {
            // Handle the case where no free entry was found
            println!("No free directory entry found!");
        }
    }
    fn write_cluster(&self, mut ide_controller: &mut IdeController, cluster: u32, buffer: &[u8]) {
        let start_sector = self.cluster_to_sector(cluster, ide_controller);
        ide_controller.write_sector(self.drive_label.clone(), start_sector, buffer, SECTORS_PER_CLUSTER as u8);
    }

    fn read_cluster(&self, mut ide_controller: &mut IdeController, cluster: u32, buffer: &mut [u8]) {
        let start_sector = self.cluster_to_sector(cluster, ide_controller);
        ide_controller.read_sector(self.drive_label.clone(), start_sector, buffer, SECTORS_PER_CLUSTER as u8);
    }
    fn get_next_cluster(&self, ide_controller: &mut IdeController, current_cluster: u32) -> u32 {
        // Calculate which sector the FAT entry is in
        let fat_offset = current_cluster * 4; // FAT32 uses 4 bytes per entry
        let sector_number = (fat_offset / 512) + RESERVED_SECTORS;
        let entry_offset = (fat_offset % 512) as usize;

        // Read the sector containing the FAT entry
        let mut buffer = vec![0u8; 512];
        ide_controller.read_sector(self.drive_label.clone(), sector_number, &mut buffer, 1);

        // Retrieve the FAT entry, which points to the next cluster in the chain
        let next_cluster = u32::from_le_bytes([
            buffer[entry_offset],
            buffer[entry_offset + 1],
            buffer[entry_offset + 2],
            buffer[entry_offset + 3],
        ]);

        next_cluster
    }
    fn sector_for_cluster(cluster: u32) -> u32{
        (cluster / (512/4)) + RESERVED_SECTORS + 1
    }
    fn is_cluster_in_sector(&self, cluster: u32, sector: u32) -> bool{
        if(FileSystem::sector_for_cluster(cluster) != sector){
            return false;
        }
        true
    }
    fn cluster_in_sector (cluster: u32) -> usize{
        ((cluster as usize % (512 / 4) ) * 4)
    }
    fn get_all_clusters(&self, ide_controller: &mut IdeController, mut starting_cluster: u32) -> Vec<u32> {
        let mut out_vec: Vec<u32> = Vec::new();
        out_vec.push(starting_cluster);
        let mut entry = 0x00000000;
        while (entry != 0xFFFFFFFF){
            let mut sector = vec!(0u8; 512);
            let starting_sector = FileSystem::sector_for_cluster(starting_cluster);
            let sector_index = FileSystem::cluster_in_sector(starting_cluster);
            ide_controller.read_sector(self.drive_label.clone(), starting_sector, &mut sector, 1);
            entry = u32::from_le_bytes([
                sector[sector_index],
                sector[sector_index + 1],
                sector[sector_index + 2],
                sector[sector_index + 3],
            ]);
            if(entry != 0xFFFFFFFF) {
                out_vec.push(entry);
            }
            starting_cluster = entry;
        }
        out_vec
    }
    fn calculate_data_region_start(&self, ide_controller: &mut IdeController) -> u32 {
        // Determine the drive size
        let drive_size = if self.drive_label == "C:" {
            ide_controller.drives[0].capacity
        } else {
            ide_controller.drives[1].capacity
        };

        // Calculate the total number of clusters
        let total_clusters = drive_size / CLUSTER_OFFSET as u64;
        ((total_clusters / 512) + RESERVED_SECTORS as u64) as u32


    }
    fn cluster_to_sector(&self, cluster: u32, ide_controller: &mut IdeController) -> u32{
        let cluster_offset = SECTORS_PER_CLUSTER;
        let cluster_start = cluster_offset * cluster + self.calculate_data_region_start(ide_controller);
        cluster_start
    }
}