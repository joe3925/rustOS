use alloc::string::{String, ToString};
use alloc::{format, vec};
use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use crate::drivers::ideDiskDriver::IdeController;
use crate::println;

const CLUSTER_SIZE: u32 = 32; //in KiB
const CLUSTER_OFFSET: u32 = CLUSTER_SIZE * 1024;
const SECTORS_PER_CLUSTER: u32 = (CLUSTER_SIZE * 1024) / 512;
const RESERVED_SECTORS: u32 = 2;
const INFO_SECTOR: u32 = RESERVED_SECTORS;#[derive(Debug)]
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
            ide_controller.write_sector(drive_label.clone(), i, &buffer);
        }
        ide_controller.write_sector(drive_label.clone(), INFO_SECTOR, &info_sec_buffer);


        for j in 0..512 {
            buffer[j] = 0x00;
        }


        // Write the FAT table to the drive
        let itr = total_clusters / 512;
        println!("{}", total_clusters);
        println!("{}", itr);

        for i in RESERVED_SECTORS..itr + RESERVED_SECTORS {
            ide_controller.write_sector(drive_label.clone(), (i + 1), &buffer);
            if(i % 10 == 0) {
                println!("{}", i);
            }
        }
        let mut readBuffer = vec![0u8; 512]; // Buffer of one sector size (512 bytes)

        //validate data sectors
        for i in RESERVED_SECTORS..itr + RESERVED_SECTORS{
            ide_controller.read_sector(drive_label.clone(), (i + 1), &mut readBuffer);
            for j in 0..512{
                if (readBuffer[j] != buffer[j]){
                    println!("Sector {} is invalid", i);
                    break;
                }
            }
        }

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
        let sector_number = (fat_offset / 512) + RESERVED_SECTORS;
        let entry_offset = (fat_offset % 512) as usize;

        // Read the sector containing the FAT entry
        let mut buffer = vec![0u8; 512];
        ide_controller.read_sector(self.drive_label.clone(), sector_number, &mut buffer);

        // Update the FAT entry in the buffer
        buffer[entry_offset] = (next_cluster & 0xFF) as u8;
        buffer[entry_offset + 1] = ((next_cluster >> 8) & 0xFF) as u8;
        buffer[entry_offset + 2] = ((next_cluster >> 16) & 0xFF) as u8;
        buffer[entry_offset + 3] = ((next_cluster >> 24) & 0xFF) as u8;

        // Write the updated sector back to the disk
        ide_controller.write_sector(self.drive_label.clone(), sector_number, &buffer);
    }
    fn read_root_directory(&self, ide_controller: &mut IdeController) -> Option<Vec<u8>> {
        // Calculate the start of the root directory
        let drive_size: u32;
        let drive_label = self.drive_label.clone();

        if drive_label == "C:" {
            drive_size = ide_controller.drives[0].capacity as u32;
        } else {
            drive_size = ide_controller.drives[1].capacity as u32;
        }

        // Calculate total number of clusters
        let total_clusters = drive_size / CLUSTER_OFFSET;

        // Calculate the number of sectors occupied by the FAT table
        let fat_sectors = (total_clusters * 4 + 511) / 512; // Each FAT entry is 4 bytes

        // Calculate the start of the root directory
        let root_dir_sector = fat_sectors + RESERVED_SECTORS;

        // Assume the root directory spans SECTORS_PER_CLUSTER sectors
        let mut root_dir = vec![0u8; (SECTORS_PER_CLUSTER * 512) as usize];

        // Read the root directory from the disk
        self.read_cluster(ide_controller, root_dir_sector, &mut root_dir);

        Some(root_dir)
    }
    //fc000
    pub fn create_and_write_file(
        &mut self,
        ide_controller: &mut IdeController,
        file_name: &str,
        file_extension: &str,
        file_data: &[u8],
    ) {
        // Calculate how many clusters the file will need
        let cluster_size = CLUSTER_SIZE as usize * 1024;
        let num_clusters = (file_data.len() + cluster_size - 1) / cluster_size; // Ceiling division
        let data_region_start = self.calculate_data_region_start(ide_controller);

        if num_clusters == 0 {
            println!("No data to write.");
            return;
        }

        // Find the first free cluster and begin allocation
        let mut current_cluster = self.find_free_cluster(ide_controller);
        if current_cluster == 0xFFFFFFFF {
            println!("No free clusters available!");
            return;
        }

        let first_cluster = current_cluster;
        let mut previous_cluster = None;

        // Write data to clusters and update FAT
        for cluster_index in 0..num_clusters {
            let cluster_data_start = cluster_index * cluster_size;
            let cluster_data_end = ((cluster_index + 1) * cluster_size).min(file_data.len());
            let cluster_data = &file_data[cluster_data_start..cluster_data_end];

            // Write the current cluster data
            let mut buffer = vec![0u8; cluster_size];
            buffer[..cluster_data.len()].copy_from_slice(cluster_data);
            self.write_cluster(
                ide_controller,
                data_region_start + (current_cluster - 2) * SECTORS_PER_CLUSTER,
                &mut buffer,
            );

            // Find the next free cluster
            let next_cluster = if cluster_index < num_clusters - 1 {
                self.find_free_cluster(ide_controller)
            } else {
                0xFFFFFFFF // Last cluster in the chain, marking the end
            };

            if next_cluster == 0xFFFFFFFF && cluster_index < num_clusters - 1 {
                println!("Not enough space to write the entire file.");
                return;
            }

            // Update the FAT entry for the current cluster
            self.update_fat(ide_controller, current_cluster, next_cluster);

            if let Some(prev_cluster) = previous_cluster {
                // Link the previous cluster to the current one in the FAT
                self.update_fat(ide_controller, prev_cluster, current_cluster);
            }

            previous_cluster = Some(current_cluster);
            current_cluster = next_cluster;
        }

        // Finally, write the file entry to the root directory
        self.write_file_to_root(
            ide_controller,
            file_name,
            file_extension,
            first_cluster,
            file_data.len() as u64,
        );

        println!("File '{}' created and written successfully.", file_name);
    }

    pub fn read_file(
        &mut self,
        ide_controller: &mut IdeController,
        file_name: &str,
        file_extension: &str,
    ) -> Option<Vec<u8>> {
        // Locate the file entry in the root directory
        let root_dir = self.read_root_directory(ide_controller)?;
        let (starting_cluster, file_size) = self.find_file_entry(&root_dir, file_name, file_extension)?;

        // Read the file data by following the cluster chain
        let mut file_data = Vec::with_capacity(file_size as usize);
        let mut current_cluster = starting_cluster;
        let data_region_start = self.calculate_data_region_start(ide_controller);

        while current_cluster != 0xFFFFFFFF {
            // Calculate the sector number for the current cluster
            let sector_number = data_region_start + (current_cluster - 2) * SECTORS_PER_CLUSTER;

            // Read the cluster data
            let mut buffer = vec![0u8; (CLUSTER_SIZE as usize) * 1024];
            self.read_cluster(ide_controller, sector_number, &mut buffer);

            // Append the cluster data to the file data
            let bytes_to_read = file_size as usize - file_data.len();
            let data_to_append = &buffer[..bytes_to_read.min(buffer.len())];
            file_data.extend_from_slice(data_to_append);

            // Follow the FAT chain to the next cluster
            current_cluster = self.get_next_cluster(ide_controller, current_cluster);
        }

        Some(file_data)
    }
    fn find_free_cluster(&mut self, mut ide_controller: &mut IdeController) -> u32 {
        let drive_size: u32;
        let drive_label = self.drive_label.clone();

        if drive_label == "C:" {
            drive_size = ide_controller.drives[0].capacity as u32;
        } else {
            drive_size = ide_controller.drives[1].capacity as u32;
        }

        // Calculate total number of clusters
        let total_clusters = drive_size / CLUSTER_OFFSET;

        // Calculate the number of sectors occupied by the FAT table
        let fat_sectors = (total_clusters * 4 + 511) / 512; // Each FAT entry is 4 bytes

        for i in 0..fat_sectors {
            let mut buffer = vec![0u8; 512];
            ide_controller.read_sector(drive_label.to_string(), i + RESERVED_SECTORS + 1, &mut buffer);

            for j in 0..128 { // 128 = 512 bytes / 4 bytes per FAT entry
                let entry = u32::from_le_bytes([
                    buffer[j * 4],
                    buffer[j * 4 + 1],
                    buffer[j * 4 + 2],
                    buffer[j * 4 + 3],
                ]);

                if entry == 0x00000000 { // A free cluster is indicated by 0x00000000
                    return (i * 128 + j as u32) as u32; // Calculate the cluster number
                }
            }
        }

        0xFFFFFFFF // Return a special value indicating no free cluster was found
    }
    pub fn write_file_to_root(
        &mut self,
        mut ide_controller: &mut IdeController,
        file_name: &str,
        file_extension: &str,
        start_cluster: u32,
        size: u64
    ) {
        // 1. Create a FileEntry struct (assuming it has been defined similarly to your previous example)
        let file_entry = FileEntry {
            file_name: file_name.to_string(),
            file_extension: file_extension.to_string(),
            attributes: 0x00, // Default attributes, can be adjusted
            creation_date: "2024-09-04".to_string(), // Example creation date
            creation_time: "12:00".to_string(), // Example creation time
            last_modified_date: "2024-09-04".to_string(),
            last_modified_time: "12:00".to_string(),
            starting_cluster: start_cluster, // We'll assume the first cluster for simplicity
            file_size: size,
        };

        // 2. Calculate the start of the root directory
        let drive_size: u32;
        let drive_label = self.drive_label.clone();

        if drive_label == "C:" {
            drive_size = ide_controller.drives[0].capacity as u32;
        } else {
            drive_size = ide_controller.drives[1].capacity as u32;
        }

        // Calculate total number of clusters
        let total_clusters = drive_size / CLUSTER_OFFSET;

        // Calculate the number of sectors occupied by the FAT table
        let fat_sectors = (total_clusters * 4 + 511) / 512; // Each FAT entry is 4 bytes
        let root_dir_sector = fat_sectors + 1;
        // 3. Read the current root directory to find a free spot
        let mut root_dir = vec![0u8; (SECTORS_PER_CLUSTER * 512) as usize];
        self.read_cluster(&mut ide_controller, root_dir_sector, &mut root_dir);

        // 4. Find the first empty entry in the root directory (assuming 32-byte entries)
        let entry_size = 32; // Typically 32 bytes for a directory entry
        let mut entry_offset = None;
        for i in (0..root_dir.len()).step_by(entry_size) {
            if root_dir[i] == 0x00 || root_dir[i] == 0xE5 {
                entry_offset = Some(i);
                break;
            }
        }

        if let Some(offset) = entry_offset {
            // 5. Write the file entry to the root directory at the found offset
            // This is a simplified way to serialize the FileEntry structure
            // You need to write each field into the directory entry (simplified here)
            let entry = format!(
                "{:<8}{:<3}{:02X}{:<10}{:<5}{:<10}{:<5}{:<10}{:<20}",
                file_entry.file_name,
                file_entry.file_extension,
                file_entry.attributes,
                file_entry.creation_date,
                file_entry.creation_time,
                file_entry.last_modified_date,
                file_entry.last_modified_time,
                file_entry.starting_cluster,
                file_entry.file_size
            );
            let entry_bytes = entry.as_bytes();

            for (i, &byte) in entry_bytes.iter().enumerate() {
                root_dir[offset + i] = byte;
            }

            // 6. Write the updated root directory back to disk
            self.write_cluster(&mut ide_controller, root_dir_sector, &mut root_dir);

        } else {
            // Handle the case where no free entry was found
            println!("No free directory entry found!");
        }
    }
    fn write_cluster(&self, mut ide_controller: &mut IdeController, start_sector: u32, buffer: &[u8]) {
        let sector_count = buffer.len() as u32 / 512;
        for i in 0..sector_count {
            let sector = &buffer[(i * 512) as usize..((i + 1) * 512) as usize];
            ide_controller.write_sector(self.drive_label.clone(), start_sector + i, sector);
        }
    }

    fn read_cluster(&self, mut ide_controller: &mut IdeController, start_sector: u32, buffer: &mut [u8]) {
        let sector_count = buffer.len() as u32 / 512;
        for i in 0..sector_count {
            let mut sector = [0u8; 512];
            ide_controller.read_sector(self.drive_label.clone(), start_sector + i, &mut sector);
            buffer[(i * 512) as usize..((i + 1) * 512) as usize].copy_from_slice(&sector);
        }
    }
    fn get_next_cluster(&self, ide_controller: &mut IdeController, current_cluster: u32) -> u32 {
        // Calculate which sector the FAT entry is in
        let fat_offset = current_cluster * 4; // FAT32 uses 4 bytes per entry
        let sector_number = (fat_offset / 512) + RESERVED_SECTORS;
        let entry_offset = (fat_offset % 512) as usize;

        // Read the sector containing the FAT entry
        let mut buffer = vec![0u8; 512];
        ide_controller.read_sector(self.drive_label.clone(), sector_number, &mut buffer);

        // Retrieve the FAT entry, which points to the next cluster in the chain
        let next_cluster = u32::from_le_bytes([
            buffer[entry_offset],
            buffer[entry_offset + 1],
            buffer[entry_offset + 2],
            buffer[entry_offset + 3],
        ]);

        next_cluster
    }
    fn find_file_entry(
        &self,
        root_dir: &[u8],
        file_name: &str,
        file_extension: &str,
    ) -> Option<(u32, u64)> {
        let entry_size = 32; // Typically 32 bytes for a directory entry
        let padded_name = format!("{:<8}", file_name).as_bytes().to_vec();
        let padded_extension = format!("{:<3}", file_extension).as_bytes().to_vec();

        for i in (0..root_dir.len()).step_by(entry_size) {
            if &root_dir[i..i + 8] == &padded_name[..8] && &root_dir[i + 8..i + 11] == &padded_extension[..3] {
                let starting_cluster = u32::from_le_bytes([
                    root_dir[i + 20],
                    root_dir[i + 21],
                    root_dir[i + 22],
                    root_dir[i + 23],
                ]);

                let file_size = u64::from_le_bytes([
                    root_dir[i + 28],
                    root_dir[i + 29],
                    root_dir[i + 30],
                    root_dir[i + 31],
                    0,
                    0,
                    0,
                    0,
                ]);

                return Some((starting_cluster, file_size));
            }
        }

        None
    }
    fn calculate_data_region_start(&self, ide_controller: &mut IdeController) -> u32 {
        // Determine the drive size
        let drive_size = if self.drive_label == "C:" {
            ide_controller.drives[0].capacity as u32
        } else {
            ide_controller.drives[1].capacity as u32
        };

        // Calculate the total number of clusters
        let total_clusters = drive_size / CLUSTER_OFFSET;

        // Each FAT entry is 4 bytes (as in FAT32), so calculate the number of sectors per FAT
        let sectors_per_fat = (total_clusters * 4 + 511) / 512; // Round up to the next full sector

        // Calculate the start of the data region
        let data_region_start = RESERVED_SECTORS + sectors_per_fat * 2; // Assuming 2 FATs (primary and backup)

        data_region_start
    }
}
