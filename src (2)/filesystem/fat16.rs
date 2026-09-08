use crate::device::Device;
use crate::errors::{RecoveryError, Result};
use crate::filesystem::{DeletedFile, FilesystemInfo, FilesystemParser, RecoveryStatus};
use byteorder::{ByteOrder, LittleEndian};
use log::warn;
use std::collections::HashSet;

#[derive(Debug)]
pub struct Fat16Parser {
    pub oem_name: String,
    pub sector_size: u32,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fat_count: u8,
    pub sectors_per_fat: u16,
    pub root_entry_count: u16,
    pub total_sectors: u64,
    pub serial_number: u32,
    pub root_dir_start_sector: u64,
    pub data_start_sector: u64,
    pub bytes_per_cluster: u32,
}

impl Fat16Parser {
    /// Detects if the device contains a FAT16 filesystem.
    pub fn detect(device: &Device) -> Result<bool> {
        let mut boot_sector = vec![0u8; 512];
        if device.read_at(0, &mut boot_sector)? < 512 {
            return Ok(false);
        }

        // Validate boot sector signature
        if boot_sector[510] != 0x55 || boot_sector[511] != 0xAA {
            return Ok(false);
        }

        // Sector size validation (512, 1024, 2048, 4096)
        let bytes_per_sec = LittleEndian::read_u16(&boot_sector[11..13]) as u32;
        if ![512, 1024, 2048, 4096].contains(&bytes_per_sec) {
            return Ok(false);
        }

        // Sectors per cluster must be power of 2
        let sectors_per_clus = boot_sector[13];
        if sectors_per_clus == 0 || (sectors_per_clus & (sectors_per_clus - 1)) != 0 {
            return Ok(false);
        }

        // sectors_per_fat_16 must be > 0 for FAT16.
        let sectors_per_fat_16 = LittleEndian::read_u16(&boot_sector[22..24]);
        if sectors_per_fat_16 == 0 {
            return Ok(false);
        }

        // root_entry_count must be > 0 (typically 512).
        let root_entries = LittleEndian::read_u16(&boot_sector[17..19]);
        if root_entries == 0 {
            return Ok(false);
        }

        // Validate filesystem label ("FAT16   ").
        let fs_type_label = String::from_utf8_lossy(&boot_sector[54..62]);
        if !fs_type_label.contains("FAT16") && !fs_type_label.contains("FAT12") {
            // Note: FAT12 shares the same layout with smaller FAT entries, but we check label.
            return Ok(false);
        }

        Ok(true)
    }

    /// Creates a new Fat16Parser.
    pub fn new(device: &Device) -> Result<Self> {
        let mut boot_sector = vec![0u8; 512];
        device.read_at(0, &mut boot_sector)?;

        let oem_name = String::from_utf8_lossy(&boot_sector[3..11]).trim().to_string();
        let sector_size = LittleEndian::read_u16(&boot_sector[11..13]) as u32;
        let sectors_per_cluster = boot_sector[13];
        let reserved_sectors = LittleEndian::read_u16(&boot_sector[14..16]);
        let fat_count = boot_sector[16];
        let root_entry_count = LittleEndian::read_u16(&boot_sector[17..19]);
        
        let total_sectors_16 = LittleEndian::read_u16(&boot_sector[19..21]) as u64;
        let total_sectors_32 = LittleEndian::read_u32(&boot_sector[32..36]) as u64;
        let total_sectors = if total_sectors_16 == 0 { total_sectors_32 } else { total_sectors_16 };

        let sectors_per_fat = LittleEndian::read_u16(&boot_sector[22..24]);
        let serial_number = LittleEndian::read_u32(&boot_sector[39..43]);

        let root_dir_start_sector = reserved_sectors as u64 + (fat_count as u64 * sectors_per_fat as u64);
        let root_dir_size_sectors = (root_entry_count as u32 * 32).div_ceil(sector_size);
        let data_start_sector = root_dir_start_sector + root_dir_size_sectors as u64;
        let bytes_per_cluster = sectors_per_cluster as u32 * sector_size;

        Ok(Self {
            oem_name,
            sector_size,
            sectors_per_cluster,
            reserved_sectors,
            fat_count,
            sectors_per_fat,
            root_entry_count,
            total_sectors,
            serial_number,
            root_dir_start_sector,
            data_start_sector,
            bytes_per_cluster,
        })
    }

    /// Read the FAT entry for a specific cluster.
    /// FAT16 entries are 16-bit.
    pub fn read_fat_entry(&self, device: &Device, cluster: u32) -> Result<u16> {
        let fat_offset = (self.reserved_sectors as u64 * self.sector_size as u64) + (cluster as u64 * 2);
        let mut entry_bytes = [0u8; 2];
        match device.read_at(fat_offset, &mut entry_bytes) {
            Ok(_) => {
                let entry = LittleEndian::read_u16(&entry_bytes);
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

    /// Evaluates the allocation status of a deleted file's clusters in FAT16.
    fn check_recovery_status(&self, device: &Device, start_cluster: u32, size: u64) -> RecoveryStatus {
        if start_cluster < 2 {
            return RecoveryStatus::Overwritten;
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

    /// Parses directory entries from a memory buffer.
    fn parse_directory_buffer(
        &self,
        device: &Device,
        dir_data: &[u8],
        current_path: &str,
        deleted_files: &mut Vec<DeletedFile>,
        visited: &mut HashSet<u32>,
        id_gen: &mut u32,
    ) -> Result<()> {
        let mut lfn_entries: Vec<(u8, String)> = Vec::new();
        let mut offset = 0;

        while offset + 32 <= dir_data.len() {
            let entry = &dir_data[offset..offset + 32];
            let first_byte = entry[0];

            if first_byte == 0x00 {
                break; // End of directory
            }

            let attr = entry[11];

            if attr == 0x0F {
                // LFN
                let seq = entry[0];
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
                // SFN
                if first_byte != 0x2E {
                    let is_deleted = first_byte == 0xE5;

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
                        let mut sfn_name = String::new();
                        let raw_name = &entry[0..8];
                        let raw_ext = &entry[8..11];

                        let clean_name = if is_deleted {
                            let mut temp = raw_name.to_vec();
                            temp[0] = b'_';
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

                    name = name.chars().filter(|c| !c.is_control()).collect();

                    let file_size = LittleEndian::read_u32(&entry[28..32]) as u64;
                    let start_cluster = LittleEndian::read_u16(&entry[26..28]) as u32;

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
                                filesystem: "FAT16".to_string(),
                                created,
                                modified,
                                accessed,
                            });
                            *id_gen += 1;
                        } else if start_cluster >= 2 {
                            let dir_path = if current_path.is_empty() {
                                name.clone()
                            } else {
                                format!("{}/{}", current_path, name)
                            };
                            let _ = self.scan_subdirectory(device, start_cluster, &dir_path, deleted_files, visited, id_gen);
                        }
                    } else if is_dir && start_cluster >= 2 {
                        let dir_path = if current_path.is_empty() {
                            name.clone()
                        } else {
                            format!("{}/{}", current_path, name)
                        };
                        let _ = self.scan_subdirectory(device, start_cluster, &dir_path, deleted_files, visited, id_gen);
                    }
                }
                lfn_entries.clear();
            }

            offset += 32;
        }

        Ok(())
    }

    /// Crawls a FAT16 subdirectory stored in a cluster chain.
    fn scan_subdirectory(
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
                    break;
                }
            }

            // Follow FAT16 chain
            let next_clus = self.read_fat_entry(device, cluster)? as u32;
            if !(2..0xFFF8).contains(&next_clus) {
                break;
            }
            cluster = next_clus;
            if visited.contains(&cluster) {
                break;
            }
        }

        self.parse_directory_buffer(device, &dir_data, current_path, deleted_files, visited, id_gen)
    }
}

impl FilesystemParser for Fat16Parser {
    fn get_info(&self) -> FilesystemInfo {
        FilesystemInfo {
            fs_type: "FAT16".to_string(),
            sector_size: self.sector_size,
            cluster_size: self.bytes_per_cluster,
            total_sectors: self.total_sectors,
            serial_number: self.serial_number,
            oem_name: self.oem_name.clone(),
            fat_count: self.fat_count,
            reserved_sectors: self.reserved_sectors,
            sectors_per_fat: self.sectors_per_fat as u32,
            root_dir_start: self.root_dir_start_sector * self.sector_size as u64,
        }
    }

    fn scan_deleted(&self, device: &Device) -> Result<Vec<DeletedFile>> {
        let mut deleted_files = Vec::new();
        let mut visited = HashSet::new();
        let mut id_gen = 1;

        // FAT16 Root directory is static. Let's read it directly.
        let root_dir_offset = self.root_dir_start_sector * self.sector_size as u64;
        let root_dir_size = self.root_entry_count as usize * 32;
        let mut root_data = vec![0u8; root_dir_size];

        device.read_at(root_dir_offset, &mut root_data)?;

        self.parse_directory_buffer(
            device,
            &root_data,
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

        // Recover contiguous sectors
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
