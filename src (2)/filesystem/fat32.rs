use crate::device::Device;
use crate::errors::{RecoveryError, Result};
use crate::filesystem::{DeletedFile, FilesystemInfo, FilesystemParser, RecoveryStatus};
use byteorder::{ByteOrder, LittleEndian};
use log::warn;
use std::collections::HashSet;

#[derive(Debug)]
pub struct Fat32Parser {
    pub oem_name: String,
    pub sector_size: u32,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fat_count: u8,
    pub sectors_per_fat: u32,
    pub total_sectors: u64,
    pub root_cluster: u32,
    pub serial_number: u32,
    pub data_start_sector: u64,
    pub bytes_per_cluster: u32,
}

impl Fat32Parser {
    /// Detects if the device contains a FAT32 filesystem.
    pub fn detect(device: &Device) -> Result<bool> {
        let mut boot_sector = vec![0u8; 512];
        if device.read_at(0, &mut boot_sector)? < 512 {
            return Ok(false);
        }

        // Validate the boot sector signature [0x55, 0xAA] at the end of the sector.
        if boot_sector[510] != 0x55 || boot_sector[511] != 0xAA {
            return Ok(false);
        }

        // Check bytes per sector (must be 512, 1024, 2048, or 4096).
        let bytes_per_sec = LittleEndian::read_u16(&boot_sector[11..13]) as u32;
        if ![512, 1024, 2048, 4096].contains(&bytes_per_sec) {
            return Ok(false);
        }

        // Sectors per cluster must be a power of 2 (1, 2, 4, 8, 16, 32, 64, 128).
        let sectors_per_clus = boot_sector[13];
        if sectors_per_clus == 0 || (sectors_per_clus & (sectors_per_clus - 1)) != 0 {
            return Ok(false);
        }

        // sectors_per_fat_16 must be 0 for FAT32.
        let sectors_per_fat_16 = LittleEndian::read_u16(&boot_sector[22..24]);
        if sectors_per_fat_16 != 0 {
            return Ok(false);
        }

        // sectors_per_fat_32 must be > 0.
        let sectors_per_fat_32 = LittleEndian::read_u32(&boot_sector[36..40]);
        if sectors_per_fat_32 == 0 {
            return Ok(false);
        }

        // Validate filesystem type label (usually contains "FAT32   ").
        let fs_type_label = String::from_utf8_lossy(&boot_sector[82..90]);
        if !fs_type_label.contains("FAT32") {
            return Ok(false);
        }

        Ok(true)
    }

    /// Creates a new Fat32Parser instance.
    pub fn new(device: &Device) -> Result<Self> {
        let mut boot_sector = vec![0u8; 512];
        device.read_at(0, &mut boot_sector)?;

        let oem_name = String::from_utf8_lossy(&boot_sector[3..11]).trim().to_string();
        let sector_size = LittleEndian::read_u16(&boot_sector[11..13]) as u32;
        let sectors_per_cluster = boot_sector[13];
        let reserved_sectors = LittleEndian::read_u16(&boot_sector[14..16]);
        let fat_count = boot_sector[16];
        
        let total_sectors_16 = LittleEndian::read_u16(&boot_sector[19..21]) as u64;
        let total_sectors_32 = LittleEndian::read_u32(&boot_sector[32..36]) as u64;
        let total_sectors = if total_sectors_16 == 0 { total_sectors_32 } else { total_sectors_16 };

        let sectors_per_fat = LittleEndian::read_u32(&boot_sector[36..40]);
        let root_cluster = LittleEndian::read_u32(&boot_sector[44..48]);
        let serial_number = LittleEndian::read_u32(&boot_sector[67..71]);

        let data_start_sector = reserved_sectors as u64 + (fat_count as u64 * sectors_per_fat as u64);
        let bytes_per_cluster = sectors_per_cluster as u32 * sector_size;

        Ok(Self {
            oem_name,
            sector_size,
            sectors_per_cluster,
            reserved_sectors,
            fat_count,
            sectors_per_fat,
            total_sectors,
            root_cluster,
            serial_number,
            data_start_sector,
            bytes_per_cluster,
        })
    }

    /// Read the FAT entry for a specific cluster.
    /// FAT32 entries are 32-bit, with the top 4 bits reserved.
    pub fn read_fat_entry(&self, device: &Device, cluster: u32) -> Result<u32> {
        let fat_offset = (self.reserved_sectors as u64 * self.sector_size as u64) + (cluster as u64 * 4);
        let mut entry_bytes = [0u8; 4];
        match device.read_at(fat_offset, &mut entry_bytes) {
            Ok(_) => {
                let entry = LittleEndian::read_u32(&entry_bytes) & 0x0F_FF_FF_FF;
                Ok(entry)
            }
            Err(e) => {
                warn!(
                    "Bad sector or I/O error reading FAT entry for cluster {} at offset {}: {}. Assuming cluster is free.",
                    cluster, fat_offset, e
                );
                Ok(0) // Return 0 (free) to allow scanning to continue
            }
        }
    }

    /// Returns the absolute byte offset of a cluster.
    pub fn cluster_offset(&self, cluster: u32) -> u64 {
        if cluster < 2 {
            return 0;
        }
        (self.data_start_sector + (cluster as u64 - 2) * self.sectors_per_cluster as u64) * self.sector_size as u64
    }

    /// Evaluates the allocation status of a deleted file's clusters.
    fn check_recovery_status(&self, device: &Device, start_cluster: u32, size: u64) -> RecoveryStatus {
        if start_cluster < 2 {
            return RecoveryStatus::Overwritten; // No valid cluster
        }

        let num_clusters = size.div_ceil(self.bytes_per_cluster as u64);
        if num_clusters == 0 {
            return RecoveryStatus::Recoverable;
        }

        let mut free_count = 0;
        let mut occupied_count = 0;

        for i in 0..num_clusters {
            let cluster = start_cluster + i as u32;
            match self.read_fat_entry(device, cluster) {
                Ok(entry) => {
                    if entry == 0 {
                        free_count += 1;
                    } else {
                        occupied_count += 1;
                    }
                }
                Err(_) => {
                    return RecoveryStatus::Corrupted;
                }
            }
        }

        if occupied_count == 0 {
            RecoveryStatus::Recoverable
        } else if free_count == 0 {
            RecoveryStatus::Overwritten
        } else {
            RecoveryStatus::Partial
        }
    }

    /// Recursively crawls directory entries in a cluster chain to find deleted items.
    fn scan_directory(
        &self,
        device: &Device,
        start_cluster: u32,
        current_path: &str,
        deleted_files: &mut Vec<DeletedFile>,
        visited: &mut HashSet<u32>,
        id_gen: &mut u32,
    ) -> Result<()> {
        if visited.contains(&start_cluster) || start_cluster < 2 {
            return Ok(());
        }
        visited.insert(start_cluster);

        // Read the directory cluster chain
        let mut cluster = start_cluster;
        let mut dir_data = Vec::new();
        let mut cluster_buf = vec![0u8; self.bytes_per_cluster as usize];

        loop {
            let offset = self.cluster_offset(cluster);
            if offset == 0 {
                break;
            }
            match device.read_at(offset, &mut cluster_buf) {
                Ok(bytes_read) => {
                    if bytes_read < cluster_buf.len() {
                        break;
                    }
                    dir_data.extend_from_slice(&cluster_buf);
                }
                Err(e) => {
                    warn!(
                        "Bad sector or I/O error reading directory cluster {} at offset {}: {}. Skipping this directory sector.",
                        cluster, offset, e
                    );
                    break; // Skip this bad sector but continue scanning other files
                }
            }

            // Follow FAT chain
            let next_clus = self.read_fat_entry(device, cluster)?;
            if !(2..0x0F_FF_FF_F8).contains(&next_clus) {
                break;
            }
            cluster = next_clus;
            if visited.contains(&cluster) {
                break; // Prevent circular reference loops
            }
        }

        let mut lfn_entries: Vec<(u8, String)> = Vec::new();
        let mut offset = 0;

        while offset + 32 <= dir_data.len() {
            let entry = &dir_data[offset..offset + 32];
            let first_byte = entry[0];

            if first_byte == 0x00 {
                break; // End of directory entries
            }

            let attr = entry[11];

            if attr == 0x0F {
                // Long File Name (LFN) entry
                let seq = entry[0];
                // Assemble UTF-16 character buffers
                let mut name_utf16 = Vec::new();
                for &i in &[1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30] {
                    let char_u16 = LittleEndian::read_u16(&entry[i..i + 2]);
                    if char_u16 == 0x0000 || char_u16 == 0xFFFF {
                        break;
                    }
                    name_utf16.push(char_u16);
                }
                if let Ok(name_part) = String::from_utf16(&name_utf16) {
                    lfn_entries.push((seq, name_part));
                }
            } else {
                // Short File Name (SFN) entry
                // Skip dot directory references (. and ..)
                if first_byte != 0x2E {
                    let is_deleted = first_byte == 0xE5;

                    // Reconstruct filename
                    let mut name = if !lfn_entries.is_empty() {
                        if is_deleted {
                            lfn_entries.reverse();
                        } else {
                            lfn_entries.sort_by_key(|a| a.0 & 0x1F);
                        }
                        let mut full_name = String::new();
                        for (_, part) in &lfn_entries {
                            full_name.push_str(part);
                        }
                        full_name.trim().to_string()
                    } else {
                        // Generate SFN name (8.3 structure)
                        let mut sfn_name = String::new();
                        let raw_name = &entry[0..8];
                        let raw_ext = &entry[8..11];

                        let clean_name = if is_deleted {
                            let mut temp = raw_name.to_vec();
                            temp[0] = b'_'; // Replace E5 marker with underscore for readability
                            String::from_utf8_lossy(&temp).trim().to_string()
                        } else {
                            String::from_utf8_lossy(raw_name).trim().to_string()
                        };

                        let clean_ext = String::from_utf8_lossy(raw_ext).trim().to_string();

                        sfn_name.push_str(&clean_name);
                        if !clean_ext.is_empty() {
                            sfn_name.push('.');
                            sfn_name.push_str(&clean_ext);
                        }
                        sfn_name
                    };

                    // Filter out unprintable/garbage control characters
                    name = name.chars().filter(|c| !c.is_control()).collect();

                    let file_size = LittleEndian::read_u32(&entry[28..32]) as u64;
                    let start_cluster_low = LittleEndian::read_u16(&entry[26..28]) as u32;
                    let start_cluster_high = LittleEndian::read_u16(&entry[20..22]) as u32;
                    let start_cluster = (start_cluster_high << 16) | start_cluster_low;

                    let is_dir = (attr & 0x10) != 0;

                    if is_deleted {
                        if !is_dir {
                            let status = self.check_recovery_status(device, start_cluster, file_size);
                            let relative_path = if current_path.is_empty() {
                                name.clone()
                            } else {
                                format!("{}/{}", current_path, name)
                            };

                            let crt_time = LittleEndian::read_u16(&entry[14..16]);
                            let crt_date = LittleEndian::read_u16(&entry[16..18]);
                            let lst_acc_date = LittleEndian::read_u16(&entry[18..20]);
                            let wrt_time = LittleEndian::read_u16(&entry[22..24]);
                            let wrt_date = LittleEndian::read_u16(&entry[24..26]);

                            let created = crate::utils::dos_to_unix_time(crt_date, crt_time);
                            let modified = crate::utils::dos_to_unix_time(wrt_date, wrt_time);
                            let accessed = crate::utils::dos_to_unix_time(lst_acc_date, 0);

                            deleted_files.push(DeletedFile {
                                id: *id_gen,
                                name: relative_path,
                                size: file_size,
                                start_cluster,
                                status,
                                filesystem: "FAT32".to_string(),
                                created,
                                modified,
                                accessed,
                            });
                            *id_gen += 1;
                        } else if start_cluster >= 2 {
                            // If it's a deleted directory, we can still attempt to crawl it!
                            let dir_path = if current_path.is_empty() {
                                name.clone()
                            } else {
                                format!("{}/{}", current_path, name)
                            };
                            let _ = self.scan_directory(device, start_cluster, &dir_path, deleted_files, visited, id_gen);
                        }
                    } else if is_dir && start_cluster >= 2 {
                        // Recurse into active subdirectory
                        let dir_path = if current_path.is_empty() {
                            name.clone()
                        } else {
                            format!("{}/{}", current_path, name)
                        };
                        let _ = self.scan_directory(device, start_cluster, &dir_path, deleted_files, visited, id_gen);
                    }
                }
                // SFN encountered, clear LFN register
                lfn_entries.clear();
            }

            offset += 32;
        }

        Ok(())
    }
}

impl FilesystemParser for Fat32Parser {
    fn get_info(&self) -> FilesystemInfo {
        FilesystemInfo {
            fs_type: "FAT32".to_string(),
            sector_size: self.sector_size,
            cluster_size: self.bytes_per_cluster,
            total_sectors: self.total_sectors,
            serial_number: self.serial_number,
            oem_name: self.oem_name.clone(),
            fat_count: self.fat_count,
            reserved_sectors: self.reserved_sectors,
            sectors_per_fat: self.sectors_per_fat,
            root_dir_start: self.cluster_offset(self.root_cluster),
        }
    }

    fn scan_deleted(&self, device: &Device) -> Result<Vec<DeletedFile>> {
        let mut deleted_files = Vec::new();
        let mut visited = HashSet::new();
        let mut id_gen = 1;

        self.scan_directory(
            device,
            self.root_cluster,
            "",
            &mut deleted_files,
            &mut visited,
            &mut id_gen,
        )?;

        Ok(deleted_files)
    }

    fn read_file(&self, device: &Device, file: &DeletedFile) -> Result<Vec<u8>> {
        if file.start_cluster < 2 {
            return Err(RecoveryError::RecoveryFailed("File has no valid start cluster.".to_string()));
        }

        let mut data = Vec::with_capacity(file.size as usize);
        let mut bytes_remaining = file.size;
        let mut cluster = file.start_cluster;
        let mut cluster_buf = vec![0u8; self.bytes_per_cluster as usize];

        // Reconstruct cluster chain.
        while bytes_remaining > 0 {
            let offset = self.cluster_offset(cluster);
            if offset == 0 || offset >= device.size() {
                break;
            }

            let to_read = std::cmp::min(bytes_remaining, self.bytes_per_cluster as u64) as usize;
            match device.read_at(offset, &mut cluster_buf) {
                Ok(_) => {
                    data.extend_from_slice(&cluster_buf[0..to_read]);
                }
                Err(e) => {
                    warn!(
                        "Bad sector or I/O error reading file data at cluster {} (offset {}): {}. Filling with zeroes.",
                        cluster, offset, e
                    );
                    data.extend(std::iter::repeat_n(0, to_read));
                }
            }

            bytes_remaining -= to_read as u64;

            // In contiguous carving, we move to the next logical cluster.
            cluster += 1;
        }

        if data.len() < file.size as usize {
            warn!(
                "Reconstructed file data size {} is smaller than expected metadata size {}",
                data.len(),
                file.size
            );
        }

        Ok(data)
    }

    fn get_file_offset(&self, file: &DeletedFile) -> Option<u64> {
        let offset = self.cluster_offset(file.start_cluster);
        if offset > 0 { Some(offset) } else { None }
    }
}
