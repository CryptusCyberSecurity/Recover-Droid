use crate::device::Device;
use crate::errors::Result;
use crate::filesystem::{DeletedFile, FilesystemInfo, FilesystemParser, RecoveryStatus};
use byteorder::{ByteOrder, LittleEndian};
use std::collections::HashSet;

#[derive(Debug)]
pub struct ExFatParser {
    pub sector_size: u32,
    pub cluster_size: u32,
    pub total_sectors: u64,
    pub serial_number: u32,
    pub fat_offset: u64,
    pub cluster_heap_offset: u64,
    pub root_cluster: u32,
}

impl ExFatParser {
    /// Detects if the device contains an exFAT filesystem.
    pub fn detect(device: &Device) -> Result<bool> {
        let mut boot_sector = vec![0u8; 512];
        if device.read_at(0, &mut boot_sector)? < 512 {
            return Ok(false);
        }

        // Validate boot sector signature
        if boot_sector[510] != 0x55 || boot_sector[511] != 0xAA {
            return Ok(false);
        }

        // Check OEM name (must be "EXFAT   ")
        let oem_name = &boot_sector[3..11];
        if oem_name != b"EXFAT   " {
            return Ok(false);
        }

        Ok(true)
    }

    /// Creates a new ExFatParser.
    pub fn new(device: &Device) -> Result<Self> {
        let mut boot_sector = vec![0u8; 512];
        device.read_at(0, &mut boot_sector)?;

        let sector_shift = boot_sector[108];
        let cluster_shift = boot_sector[109];

        let sector_size = if (9..=12).contains(&sector_shift) {
            1u32 << sector_shift
        } else {
            512
        };

        // In exFAT, offset 109 is SectorsPerClusterShift, not BytesPerClusterShift.
        // ClusterSize = (1 << SectorsPerClusterShift) * SectorSize.
        let sectors_per_cluster = if cluster_shift <= 25 {
            1u32 << cluster_shift
        } else {
            8 // Fallback to 8 sectors (4096 bytes if sector size is 512)
        };
        let cluster_size = sectors_per_cluster * sector_size;

        let total_sectors = LittleEndian::read_u64(&boot_sector[72..80]);
        let serial_number = LittleEndian::read_u32(&boot_sector[100..104]);

        let fat_offset_sectors = LittleEndian::read_u32(&boot_sector[80..84]);
        let cluster_heap_offset_sectors = LittleEndian::read_u32(&boot_sector[88..92]);
        let root_cluster = LittleEndian::read_u32(&boot_sector[96..100]);

        let fat_offset = fat_offset_sectors as u64 * sector_size as u64;
        let cluster_heap_offset = cluster_heap_offset_sectors as u64 * sector_size as u64;

        if let Ok(mut diag) = std::fs::OpenOptions::new().create(true).append(true).open("carve_diagnostics.txt") {
            use std::io::Write;
            let _ = writeln!(diag, "--- ExFatParser::new ---");
            let _ = writeln!(diag, "sector_shift: {}", sector_shift);
            let _ = writeln!(diag, "cluster_shift: {}", cluster_shift);
            let _ = writeln!(diag, "sector_size: {}", sector_size);
            let _ = writeln!(diag, "cluster_size: {}", cluster_size);
            let _ = writeln!(diag, "total_sectors: {}", total_sectors);
            let _ = writeln!(diag, "fat_offset: {}", fat_offset);
            let _ = writeln!(diag, "cluster_heap_offset: {}", cluster_heap_offset);
            let _ = writeln!(diag, "root_cluster: {}", root_cluster);
        }

        Ok(Self {
            sector_size,
            cluster_size,
            total_sectors,
            serial_number,
            fat_offset,
            cluster_heap_offset,
            root_cluster,
        })
    }

    pub fn read_fat_entry(&self, device: &Device, cluster: u32) -> Result<u32> {
        if cluster < 2 {
            return Ok(0);
        }
        let fat_entry_offset = self.fat_offset + (cluster as u64 * 4);
        let mut entry_bytes = [0u8; 4];
        device.read_at(fat_entry_offset, &mut entry_bytes)?;
        Ok(LittleEndian::read_u32(&entry_bytes))
    }

    pub fn cluster_offset(&self, cluster: u32) -> u64 {
        if cluster < 2 {
            return 0;
        }
        self.cluster_heap_offset + (cluster as u64 - 2) * self.cluster_size as u64
    }

    fn check_recovery_status(&self, device: &Device, start_cluster: u32, size: u64, no_fat_chain: bool) -> RecoveryStatus {
        if size == 0 {
            return RecoveryStatus::Recoverable;
        }
        if start_cluster < 2 {
            return RecoveryStatus::Overwritten;
        }

        let num_clusters = size.div_ceil(self.cluster_size as u64);
        if num_clusters == 0 {
            return RecoveryStatus::Recoverable;
        }

        let mut free_count = 0;
        let mut occupied_count = 0;

        let mut cluster = start_cluster;
        for i in 0..num_clusters {
            let current_cluster = if no_fat_chain { start_cluster + i as u32 } else { cluster };
            
            if current_cluster < 2 {
                occupied_count += 1;
                continue;
            }

            match self.read_fat_entry(device, current_cluster) {
                Ok(entry) => {
                    if entry == 0 {
                        free_count += 1;
                    } else {
                        occupied_count += 1;
                    }

                    if !no_fat_chain && (2..0xFFFFFFF0).contains(&entry) {
                        cluster = entry;
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

    fn read_cluster_chain(&self, device: &Device, start_cluster: u32, size: u64, no_fat_chain: bool) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        let mut cluster = start_cluster;
        let mut bytes_remaining = size;
        let mut visited = HashSet::new();

        while bytes_remaining > 0 && (2..0xFFFFFFF0).contains(&cluster) {
            let offset = self.cluster_offset(cluster);
            if offset == 0 {
                break;
            }

            let to_read = std::cmp::min(self.cluster_size as u64, bytes_remaining) as usize;
            let mut cluster_buf = vec![0u8; to_read];
            device.read_at(offset, &mut cluster_buf)?;
            data.extend_from_slice(&cluster_buf);
            bytes_remaining -= to_read as u64;

            if no_fat_chain {
                cluster += 1;
            } else {
                if visited.contains(&cluster) {
                    break;
                }
                visited.insert(cluster);
                let next_clus = self.read_fat_entry(device, cluster)?;
                if !(2..0xFFFFFFF8).contains(&next_clus) {
                    break;
                }
                cluster = next_clus;
            }
        }
        Ok(data)
    }

    fn scan_directory(
        &self,
        device: &Device,
        start_cluster: u32,
        no_fat_chain: bool,
        current_path: &str,
        deleted_files: &mut Vec<DeletedFile>,
        visited: &mut HashSet<u32>,
        id_gen: &mut u32,
    ) -> Result<()> {
        let mut cluster = start_cluster;
        let mut dir_data = Vec::new();
        let mut cluster_buf = vec![0u8; self.cluster_size as usize];
        let mut visited_clusters = HashSet::new();

        loop {
            if !(2..0xFFFFFFF0).contains(&cluster) || visited_clusters.contains(&cluster) {
                break;
            }
            visited_clusters.insert(cluster);

            let offset = self.cluster_offset(cluster);
            if let Ok(mut diag) = std::fs::OpenOptions::new().create(true).append(true).open("carve_diagnostics.txt") {
                use std::io::Write;
                let _ = writeln!(diag, "  scan_directory: cluster {}, offset {}, current_path: '{}'", cluster, offset, current_path);
            }
            if offset == 0 {
                break;
            }

            match device.read_at(offset, &mut cluster_buf) {
                Ok(n) => {
                    if n < cluster_buf.len() {
                        if let Ok(mut diag) = std::fs::OpenOptions::new().create(true).append(true).open("carve_diagnostics.txt") {
                            use std::io::Write;
                            let _ = writeln!(diag, "    read truncated: {}/{} bytes", n, cluster_buf.len());
                        }
                        break;
                    }
                }
                Err(e) => {
                    if let Ok(mut diag) = std::fs::OpenOptions::new().create(true).append(true).open("carve_diagnostics.txt") {
                        use std::io::Write;
                        let _ = writeln!(diag, "    read error: {}", e);
                    }
                    break;
                }
            }
            dir_data.extend_from_slice(&cluster_buf);

            if no_fat_chain {
                cluster += 1;
            } else {
                let next_clus = match self.read_fat_entry(device, cluster) {
                    Ok(nc) => nc,
                    Err(e) => {
                        if let Ok(mut diag) = std::fs::OpenOptions::new().create(true).append(true).open("carve_diagnostics.txt") {
                            use std::io::Write;
                            let _ = writeln!(diag, "    FAT read error for cluster {}: {}", cluster, e);
                        }
                        break;
                    }
                };
                if !(2..0xFFFFFFF8).contains(&next_clus) {
                    break;
                }
                cluster = next_clus;
            }

            if dir_data.len() > 10 * 1024 * 1024 {
                break; // Safety limit
            }
        }

        if let Ok(mut diag) = std::fs::OpenOptions::new().create(true).append(true).open("carve_diagnostics.txt") {
            use std::io::Write;
            let _ = writeln!(diag, "  scan_directory: dir_data length for '{}' is {} bytes", current_path, dir_data.len());
        }

        let mut offset = 0;
        while offset + 32 <= dir_data.len() {
            let entry = &dir_data[offset..offset + 32];
            let entry_type = entry[0];

            if let Ok(mut diag) = std::fs::OpenOptions::new().create(true).append(true).open("carve_diagnostics.txt") {
                use std::io::Write;
                let _ = writeln!(diag, "    offset {}: entry_type 0x{:02X}", offset, entry_type);
            }

            if entry_type == 0x00 {
                break; // End of directory
            }

            if entry_type == 0x85 || entry_type == 0x05 {
                let is_deleted = entry_type == 0x05;
                let secondary_count = entry[1];
                let file_attributes = LittleEndian::read_u16(&entry[4..6]);
                let is_directory = (file_attributes & 0x0010) != 0;

                if offset + 32 + (secondary_count as usize * 32) <= dir_data.len() {
                    let stream_entry = &dir_data[offset + 32..offset + 64];
                    let stream_type = stream_entry[0];

                    if stream_type == 0xC0 || stream_type == 0x40 {
                        let secondary_flags = stream_entry[1];
                        let no_fat_chain_file = (secondary_flags & 0x02) != 0;
                        let name_len = stream_entry[3] as usize;
                        let first_cluster = LittleEndian::read_u32(&stream_entry[20..24]);
                        let data_length = LittleEndian::read_u64(&stream_entry[24..32]);

                        let mut name_utf16 = Vec::new();
                        let name_entries_count = (secondary_count - 1) as usize;
                        
                        for i in 0..name_entries_count {
                            let name_entry_offset = offset + 64 + (i * 32);
                            if name_entry_offset + 32 <= dir_data.len() {
                                let name_entry = &dir_data[name_entry_offset..name_entry_offset + 32];
                                let name_type = name_entry[0];
                                if name_type == 0xC1 || name_type == 0x41 {
                                    for c_idx in 0..15 {
                                        let char_offset = 2 + c_idx * 2;
                                        let char_u16 = LittleEndian::read_u16(&name_entry[char_offset..char_offset + 2]);
                                        if char_u16 == 0 {
                                            break;
                                        }
                                        name_utf16.push(char_u16);
                                    }
                                }
                            }
                        }

                        let mut file_name = String::from_utf16_lossy(&name_utf16);
                        if file_name.len() > name_len {
                            file_name.truncate(name_len);
                        }
                        file_name = file_name.trim().to_string();

                        let full_path = if current_path.is_empty() {
                            file_name.clone()
                        } else {
                            format!("{}/{}", current_path, file_name)
                        };

                        if is_deleted
                            && !is_directory {
                                *id_gen += 1;
                                let status = self.check_recovery_status(device, first_cluster, data_length, no_fat_chain_file);
                                
                                let crt_ts = LittleEndian::read_u32(&entry[8..12]);
                                let wrt_ts = LittleEndian::read_u32(&entry[12..16]);
                                let acc_ts = LittleEndian::read_u32(&entry[16..20]);

                                let created = crate::utils::dos_to_unix_time((crt_ts >> 16) as u16, crt_ts as u16);
                                let modified = crate::utils::dos_to_unix_time((wrt_ts >> 16) as u16, wrt_ts as u16);
                                let accessed = crate::utils::dos_to_unix_time((acc_ts >> 16) as u16, acc_ts as u16);

                                deleted_files.push(DeletedFile {
                                    id: *id_gen,
                                    name: full_path.clone(),
                                    size: data_length,
                                    start_cluster: first_cluster,
                                    status,
                                    filesystem: "exFAT".to_string(),
                                    created,
                                    modified,
                                    accessed,
                                });
                            }

                        if is_directory && first_cluster >= 2
                            && !visited.contains(&first_cluster) {
                                visited.insert(first_cluster);
                                self.scan_directory(
                                    device,
                                    first_cluster,
                                    no_fat_chain_file,
                                    &full_path,
                                    deleted_files,
                                    visited,
                                    id_gen,
                                )?;
                            }
                    }
                }
                
                offset += 32 + (secondary_count as usize * 32);
            } else {
                offset += 32;
            }
        }

        Ok(())
    }
}

impl FilesystemParser for ExFatParser {
    fn get_info(&self) -> FilesystemInfo {
        FilesystemInfo {
            fs_type: "exFAT".to_string(),
            sector_size: self.sector_size,
            cluster_size: self.cluster_size,
            total_sectors: self.total_sectors,
            serial_number: self.serial_number,
            oem_name: "EXFAT   ".to_string(),
            fat_count: 1,
            reserved_sectors: 0,
            sectors_per_fat: 0,
            root_dir_start: self.cluster_offset(self.root_cluster),
        }
    }

    fn scan_deleted(&self, device: &Device) -> Result<Vec<DeletedFile>> {
        if let Ok(mut diag) = std::fs::OpenOptions::new().create(true).append(true).open("carve_diagnostics.txt") {
            use std::io::Write;
            let _ = writeln!(diag, "--- ExFatParser::scan_deleted ---");
            let _ = writeln!(diag, "Device size: {}, path: {}", device.size(), device.path());
            let _ = writeln!(diag, "Root cluster offset calculated: {}", self.cluster_offset(self.root_cluster));
        }

        let mut deleted_files = Vec::new();
        let mut visited = HashSet::new();
        let mut id_gen = 0;

        visited.insert(self.root_cluster);
        self.scan_directory(
            device,
            self.root_cluster,
            false,
            "",
            &mut deleted_files,
            &mut visited,
            &mut id_gen,
        )?;

        if let Ok(mut diag) = std::fs::OpenOptions::new().create(true).append(true).open("carve_diagnostics.txt") {
            use std::io::Write;
            let _ = writeln!(diag, "ExFatParser::scan_deleted completed. Found {} deleted files.", deleted_files.len());
        }

        Ok(deleted_files)
    }

    fn read_file(&self, device: &Device, file: &DeletedFile) -> Result<Vec<u8>> {
        let entry = self.read_fat_entry(device, file.start_cluster).unwrap_or(0);
        let no_fat_chain = entry == 0;
        self.read_cluster_chain(device, file.start_cluster, file.size, no_fat_chain)
    }

    fn get_file_offset(&self, file: &DeletedFile) -> Option<u64> {
        let offset = self.cluster_offset(file.start_cluster);
        if offset > 0 { Some(offset) } else { None }
    }
}
