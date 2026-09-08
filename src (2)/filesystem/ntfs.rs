use crate::device::Device;
use crate::errors::Result;
use crate::filesystem::{DeletedFile, FilesystemInfo, FilesystemParser};
use byteorder::{ByteOrder, LittleEndian};

#[derive(Debug)]
pub struct NtfsParser {
    pub sector_size: u32,
    pub cluster_size: u32,
    pub total_sectors: u64,
    pub serial_number: u64,
    pub mft_start_cluster: u64,
}

impl NtfsParser {
    /// Detects if the device contains an NTFS filesystem.
    pub fn detect(device: &Device) -> Result<bool> {
        let mut boot_sector = vec![0u8; 512];
        if device.read_at(0, &mut boot_sector)? < 512 {
            return Ok(false);
        }

        // Validate boot sector signature
        if boot_sector[510] != 0x55 || boot_sector[511] != 0xAA {
            return Ok(false);
        }

        // Check OEM name (must be "NTFS    ")
        let oem_name = &boot_sector[3..11];
        if oem_name != b"NTFS    " {
            return Ok(false);
        }

        Ok(true)
    }

    /// Creates a new NtfsParser.
    pub fn new(device: &Device) -> Result<Self> {
        let mut boot_sector = vec![0u8; 512];
        device.read_at(0, &mut boot_sector)?;

        let sector_size = LittleEndian::read_u16(&boot_sector[11..13]) as u32;
        let sectors_per_cluster = boot_sector[13] as u32;
        let cluster_size = sectors_per_cluster * sector_size;

        let total_sectors = LittleEndian::read_u64(&boot_sector[40..48]);
        let mft_start_cluster = LittleEndian::read_u64(&boot_sector[48..56]);
        let serial_number = LittleEndian::read_u64(&boot_sector[72..80]);

        Ok(Self {
            sector_size,
            cluster_size,
            total_sectors,
            serial_number,
            mft_start_cluster,
        })
    }
}

impl FilesystemParser for NtfsParser {
    fn get_info(&self) -> FilesystemInfo {
        FilesystemInfo {
            fs_type: "NTFS".to_string(),
            sector_size: self.sector_size,
            cluster_size: self.cluster_size,
            total_sectors: self.total_sectors,
            serial_number: (self.serial_number & 0xFFFF_FFFF) as u32, // Truncated or stored as serial
            oem_name: "NTFS    ".to_string(),
            fat_count: 0,
            reserved_sectors: 0,
            sectors_per_fat: 0,
            root_dir_start: self.mft_start_cluster * self.cluster_size as u64,
        }
    }

    fn scan_deleted(&self, _device: &Device) -> Result<Vec<DeletedFile>> {
        // Phase 3: NTFS deleted file scanning is not implemented yet.
        // Returning a clean, empty list.
        Ok(Vec::new())
    }

    fn read_file(&self, _device: &Device, _file: &DeletedFile) -> Result<Vec<u8>> {
        Err(crate::errors::RecoveryError::RecoveryFailed(
            "NTFS file recovery is not supported in Phase 1.".to_string(),
        ))
    }

    fn get_file_offset(&self, _file: &DeletedFile) -> Option<u64> {
        None
    }
}
