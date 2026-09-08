use crate::device::Device;
use crate::errors::Result;
use log::debug;
use std::fmt::Debug;

pub mod exfat;
pub mod fat16;
pub mod fat32;
pub mod ntfs;

/// Represents the status of a deleted file's recoverability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RecoveryStatus {
    Recoverable,
    Partial,
    Overwritten,
    Corrupted,
}

impl std::fmt::Display for RecoveryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryStatus::Recoverable => write!(f, "Recoverable"),
            RecoveryStatus::Partial => write!(f, "Partial"),
            RecoveryStatus::Overwritten => write!(f, "Overwritten"),
            RecoveryStatus::Corrupted => write!(f, "Corrupted"),
        }
    }
}

/// Metadata about a detected deleted file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeletedFile {
    pub id: u32,
    pub name: String,
    pub size: u64,
    pub start_cluster: u32,
    pub status: RecoveryStatus,
    pub filesystem: String,
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub accessed: Option<u64>,
    pub hash: Option<String>,
}

/// System-level metadata about a parsed filesystem.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FilesystemInfo {
    pub fs_type: String,
    pub sector_size: u32,
    pub cluster_size: u32,
    pub total_sectors: u64,
    pub serial_number: u32,
    pub oem_name: String,
    pub fat_count: u8,
    pub reserved_sectors: u16,
    pub sectors_per_fat: u32,
    pub root_dir_start: u64,
}

/// The common trait that all filesystem parsers must implement.
pub trait FilesystemParser: Debug + Send + Sync {
    /// Returns basic details about the parsed filesystem.
    fn get_info(&self) -> FilesystemInfo;

    /// Scans the filesystem structures to locate deleted files and directories.
    fn scan_deleted(&self, device: &Device) -> Result<Vec<DeletedFile>>;

    /// Reads/reconstructs the data content of a deleted file.
    fn read_file(&self, device: &Device, file: &DeletedFile) -> Result<Vec<u8>>;

    /// Returns the absolute byte offset of a deleted file if possible.
    fn get_file_offset(&self, file: &DeletedFile) -> Option<u64>;
}

#[derive(Debug)]
pub struct PartitionParserWrapper {
    pub inner: Box<dyn FilesystemParser>,
    pub partition_offset: u64,
}

impl FilesystemParser for PartitionParserWrapper {
    fn get_info(&self) -> FilesystemInfo {
        let mut info = self.inner.get_info();
        info.root_dir_start += self.partition_offset;
        info
    }

    fn scan_deleted(&self, device: &Device) -> Result<Vec<DeletedFile>> {
        let sub_dev = device.clone_with_offset(self.partition_offset)?;
        self.inner.scan_deleted(&sub_dev)
    }

    fn read_file(&self, device: &Device, file: &DeletedFile) -> Result<Vec<u8>> {
        let sub_dev = device.clone_with_offset(self.partition_offset)?;
        self.inner.read_file(&sub_dev, file)
    }

    fn get_file_offset(&self, file: &DeletedFile) -> Option<u64> {
        self.inner.get_file_offset(file).map(|off| off + self.partition_offset)
    }
}

fn detect_btrfs(device: &Device) -> Result<bool> {
    if device.size() < 0x10048 {
        return Ok(false);
    }
    let mut buf = [0u8; 8];
    device.read_at(0x10040, &mut buf)?;
    Ok(&buf == b"_BHRfS_M")
}

fn detect_ext4(device: &Device) -> Result<bool> {
    if device.size() < 0x43a {
        return Ok(false);
    }
    let mut buf = [0u8; 2];
    device.read_at(0x438, &mut buf)?;
    Ok(buf[0] == 0x53 && buf[1] == 0xEF)
}

fn try_detect_filesystem_direct(device: &Device) -> Result<Box<dyn FilesystemParser>> {
    // 1. Try FAT32
    if fat32::Fat32Parser::detect(device)? {
        debug!("Detected FAT32 filesystem on '{}'", device.path());
        return Ok(Box::new(fat32::Fat32Parser::new(device)?));
    }

    // 2. Try FAT16
    if fat16::Fat16Parser::detect(device)? {
        debug!("Detected FAT16 filesystem on '{}'", device.path());
        return Ok(Box::new(fat16::Fat16Parser::new(device)?));
    }

    // 3. Try exFAT
    if exfat::ExFatParser::detect(device)? {
        debug!("Detected exFAT filesystem on '{}'", device.path());
        return Ok(Box::new(exfat::ExFatParser::new(device)?));
    }

    // 4. Try NTFS
    if ntfs::NtfsParser::detect(device)? {
        debug!("Detected NTFS filesystem on '{}'", device.path());
        return Ok(Box::new(ntfs::NtfsParser::new(device)?));
    }

    // 5. Try Btrfs
    if detect_btrfs(device)? {
        return Err(crate::errors::RecoveryError::UnknownFilesystem(format!(
            "Btrfs detected on '{}'. Btrfs is a Copy-on-Write (CoW) filesystem that physically purges deleted metadata from directory structures. Quick Scan is unsupported on Btrfs. Please switch to Deep Carving mode.",
            device.path()
        )));
    }

    // 6. Try Ext4
    if detect_ext4(device)? {
        return Err(crate::errors::RecoveryError::UnknownFilesystem(format!(
            "Ext4 detected on '{}'. Quick Scan is currently only supported for FAT16, FAT32, exFAT, and NTFS. Please switch to Deep Carving mode.",
            device.path()
        )));
    }

    Err(crate::errors::RecoveryError::UnknownFilesystem(format!(
        "No supported filesystem was detected on device '{}'.",
        device.path()
    )))
}

pub fn detect_filesystem(device: &Device) -> Result<Box<dyn FilesystemParser>> {
    // 1. Try direct detection first
    if let Ok(parser) = try_detect_filesystem_direct(device) {
        return Ok(parser);
    }

    // 2. Try parsing GPT partition table
    use byteorder::{ByteOrder, LittleEndian};
    let mut sector1 = vec![0u8; 512];
    if device.size() >= 1024 && device.read_at(512, &mut sector1).is_ok() && &sector1[0..8] == b"EFI PART" {
        let entries_lba = LittleEndian::read_u64(&sector1[72..80]);
        let num_entries = LittleEndian::read_u32(&sector1[80..84]) as usize;
        let entry_size = LittleEndian::read_u32(&sector1[84..88]) as usize;
        let sector_size = device.sector_size() as u64;
        
        let mut entries_buf = vec![0u8; std::cmp::min(num_entries * entry_size, 32768)];
        if device.read_at(entries_lba * sector_size, &mut entries_buf).is_ok() {
            for part_idx in 0..std::cmp::min(num_entries, entries_buf.len() / entry_size) {
                let entry_offset = part_idx * entry_size;
                let type_guid = &entries_buf[entry_offset..entry_offset + 16];
                if type_guid.iter().any(|&b| b != 0) {
                    let start_lba = LittleEndian::read_u64(&entries_buf[entry_offset + 32..entry_offset + 40]);
                    let start_offset = start_lba * sector_size;
                    if start_offset > 0 && start_offset < device.size() {
                        if let Ok(sub_dev) = device.clone_with_offset(start_offset) {
                            if let Ok(parser) = try_detect_filesystem_direct(&sub_dev) {
                                debug!("Detected GPT partition {} at offset {}", part_idx + 1, start_offset);
                                return Ok(Box::new(PartitionParserWrapper {
                                    inner: parser,
                                    partition_offset: start_offset,
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Try parsing MBR partition table
    let mut sector0 = vec![0u8; 512];
    if device.read_at(0, &mut sector0).is_ok() && sector0[510] == 0x55 && sector0[511] == 0xAA {
        for part_idx in 0..4 {
            let entry_offset = 446 + part_idx * 16;
            let part_type = sector0[entry_offset + 4];
            if part_type != 0 {
                let start_lba = LittleEndian::read_u32(&sector0[entry_offset + 8..entry_offset + 12]) as u64;
                let sector_size = device.sector_size() as u64;
                let start_offset = start_lba * sector_size;
                if start_offset > 0 && start_offset < device.size() {
                    if let Ok(sub_dev) = device.clone_with_offset(start_offset) {
                        if let Ok(parser) = try_detect_filesystem_direct(&sub_dev) {
                            debug!("Detected MBR partition {} at offset {} (type: 0x{:02X})", part_idx + 1, start_offset, part_type);
                            return Ok(Box::new(PartitionParserWrapper {
                                inner: parser,
                                partition_offset: start_offset,
                            }));
                        }
                    }
                }
            }
        }
    }

    Err(crate::errors::RecoveryError::UnknownFilesystem(format!(
        "No supported filesystem was detected on device '{}'. \
         Quick Scan requires parsing specific file allocation tables or metadata index structures (like FAT or NTFS MFT). \
         If this partition is raw, corrupted, or formatted with a different filesystem (like Ext4, Btrfs, APFS, or HFS+), \
         Quick Scan cannot read directory entries. Please switch to Deep Carving mode to scan raw sectors directly.",
        device.path()
    )))
}
