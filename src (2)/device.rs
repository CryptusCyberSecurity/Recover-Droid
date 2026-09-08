use crate::errors::{RecoveryError, Result};
use log::debug;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::path::Path;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

/// Information about a connected storage device.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StorageDevice {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub sector_size: u32,
    pub device_type: String, // "Physical", "Partition", "Logical", "File"
}

/// A handle to an open, read-only storage device or disk image.
pub struct Device {
    path: String,
    file: File,
    size: u64,
    sector_size: u32,
    base_offset: u64,
}

impl Device {
    /// Opens a device or image file in strictly read-only mode.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();

        // On Windows, if the raw device path (starts with \\.\) has a trailing backslash, strip it.
        #[cfg(windows)]
        let path_str = {
            let mut s = path_str;
            if s.starts_with(r"\\.\") && s.ends_with('\\') {
                s.pop();
            }
            s
        };

        let mut options = OpenOptions::new();
        options.read(true);

        // On Windows, raw drives require sharing flags to prevent access conflicts.
        #[cfg(windows)]
        {
            // FILE_SHARE_READ (1) | FILE_SHARE_WRITE (2)
            options.share_mode(3);
        }

        let file = options.open(&path_str).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                RecoveryError::PermissionDenied(format!(
                    "Failed to open '{}' read-only. Please run with administrative privileges.",
                    path_str
                ))
            } else {
                RecoveryError::DeviceNotFound(format!("Failed to open '{}': {}", path_str, e))
            }
        })?;

        // Determine the size and sector size of the device.
        let size = Self::query_device_size(&file, &path_str)?;
        let sector_size = Self::query_sector_size(&file, &path_str).unwrap_or(512);

        debug!(
            "Opened device '{}' (Size: {}, Sector Size: {} bytes)",
            path_str, size, sector_size
        );

        Ok(Self {
            path: path_str,
            file,
            size,
            sector_size,
            base_offset: 0,
        })
    }

    /// Read data from the device at a specific offset into the buffer.
    /// This operation is completely thread-safe and concurrent because it does not
    /// modify the internal file cursor.
    #[cfg(windows)]
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        use std::os::windows::fs::FileExt;
        
        let abs_offset = self.base_offset + offset;
        let virtual_size = self.size - self.base_offset;
        if offset >= virtual_size {
            return Ok(0);
        }

        let mut len = buf.len();
        if offset + len as u64 > virtual_size {
            len = (virtual_size - offset) as usize;
        }

        if len == 0 {
            return Ok(0);
        }

        let sector_size = self.sector_size as u64;
        let start = abs_offset;
        let end = start + len as u64;

        // Calculate sector-aligned offsets
        let aligned_start = (start / sector_size) * sector_size;
        let mut aligned_end = ((end + sector_size - 1) / sector_size) * sector_size;
        aligned_end = std::cmp::min(aligned_end, self.size);
        let aligned_len = (aligned_end - aligned_start) as usize;

        // If the read is already aligned and fits perfectly, perform direct read
        if start == aligned_start && len as u64 == (aligned_end - aligned_start) {
            return self.file.seek_read(&mut buf[..len], abs_offset).map_err(RecoveryError::Io);
        }

        // Allocate a sector-aligned temporary buffer
        let mut temp_buf = vec![0u8; aligned_len];
        
        // Perform the read from the aligned offset
        let bytes_read = self.file.seek_read(&mut temp_buf, aligned_start).map_err(RecoveryError::Io)?;

        if bytes_read == 0 {
            return Ok(0);
        }

        // Determine how many bytes we can actually copy to `buf`
        let relative_start = (start - aligned_start) as usize;
        if relative_start >= bytes_read {
            return Ok(0);
        }

        let available_bytes = bytes_read - relative_start;
        let copy_len = std::cmp::min(len, available_bytes);

        buf[..copy_len].copy_from_slice(&temp_buf[relative_start..relative_start + copy_len]);
        Ok(copy_len)
    }

    /// Read data from the device at a specific offset into the buffer (Unix implementation).
    #[cfg(not(windows))]
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        use std::os::unix::fs::FileExt;
        let abs_offset = self.base_offset + offset;
        let virtual_size = self.size - self.base_offset;
        if offset >= virtual_size {
            return Ok(0);
        }
        let to_read = std::cmp::min(buf.len() as u64, virtual_size - offset) as usize;
        if to_read == 0 {
            return Ok(0);
        }
        self.file.read_at(&mut buf[..to_read], abs_offset).map_err(RecoveryError::Io)
    }

    /// Returns the path of the device.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the capacity of the device in bytes.
    pub fn size(&self) -> u64 {
        self.size - self.base_offset
    }

    /// Returns the sector size of the device in bytes.
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Returns the total number of sectors on the device.
    pub fn total_sectors(&self) -> u64 {
        (self.size - self.base_offset) / self.sector_size as u64
    }

    /// Creates a virtual sub-device view starting at a specific byte offset.
    pub fn clone_with_offset(&self, offset: u64) -> Result<Self> {
        let file = self.file.try_clone().map_err(RecoveryError::Io)?;
        Ok(Self {
            path: self.path.clone(),
            file,
            size: self.size,
            sector_size: self.sector_size,
            base_offset: self.base_offset + offset,
        })
    }

    /// Query the size of the device.
    fn query_device_size(file: &File, path: &str) -> Result<u64> {
        // First try standard file metadata (works for files and disk images).
        if let Ok(metadata) = file.metadata() {
            let len = metadata.len();
            if len > 0 {
                return Ok(len);
            }
        }

        // Platform-specific raw device size querying.
        #[cfg(windows)]
        {
            if let Some(size) = Self::get_windows_device_size(file) {
                return Ok(size);
            }
        }

        // Fallback: Seek to the end of the file.
        let mut f = file;
        if let Ok(size) = f.seek(SeekFrom::End(0)) {
            let _ = f.seek(SeekFrom::Start(0)); // Reset cursor
            if size > 0 {
                return Ok(size);
            }
        }

        Err(RecoveryError::DeviceNotFound(format!(
            "Could not determine the capacity of the device '{}'",
            path
        )))
    }

    #[cfg(windows)]
    fn get_windows_device_size(file: &File) -> Option<u64> {
        use std::mem;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::IO::DeviceIoControl;
        use windows_sys::Win32::System::Ioctl::IOCTL_DISK_GET_LENGTH_INFO;

        let handle = file.as_raw_handle();
        let mut length: u64 = 0;
        let mut bytes_returned: u32 = 0;

        let success = unsafe {
            DeviceIoControl(
                handle as _,
                IOCTL_DISK_GET_LENGTH_INFO,
                std::ptr::null_mut(),
                0,
                &mut length as *mut _ as *mut _,
                mem::size_of::<u64>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };

        if success != 0 {
            Some(length)
        } else {
            None
        }
    }

    /// Query the hardware sector size of the device.
    fn query_sector_size(file: &File, _path: &str) -> Option<u32> {
        let _ = file;
        #[cfg(windows)]
        {
            use std::mem;
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::IO::DeviceIoControl;
            use windows_sys::Win32::System::Ioctl::IOCTL_DISK_GET_DRIVE_GEOMETRY;

            // Structure definition for DISK_GEOMETRY in windows-sys
            // We only need the SectorSize field.
            #[repr(C)]
            struct DiskGeometry {
                cylinders: u64,
                media_type: u32,
                tracks_per_cylinder: u32,
                sectors_per_track: u32,
                bytes_per_sector: u32,
            }

            let handle = file.as_raw_handle();
            let mut geom = DiskGeometry {
                cylinders: 0,
                media_type: 0,
                tracks_per_cylinder: 0,
                sectors_per_track: 0,
                bytes_per_sector: 0,
            };
            let mut bytes_returned: u32 = 0;

            let success = unsafe {
                DeviceIoControl(
                    handle as _,
                    IOCTL_DISK_GET_DRIVE_GEOMETRY,
                    std::ptr::null_mut(),
                    0,
                    &mut geom as *mut _ as *mut _,
                    mem::size_of::<DiskGeometry>() as u32,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };

            if success != 0 && geom.bytes_per_sector > 0 {
                return Some(geom.bytes_per_sector);
            }
        }

        // Default fallback to standard 512 bytes.
        Some(512)
    }
}

/// Lists all connected storage devices.
#[cfg(target_os = "windows")]
pub fn list_devices() -> Result<Vec<StorageDevice>> {
    let mut devices = Vec::new();

    // 1. Try physical drives (PhysicalDrive0 to PhysicalDrive15)
    for i in 0..16 {
        let drive_path = format!(r"\\.\PhysicalDrive{}", i);
        if let Ok(dev) = Device::open(&drive_path) {
            devices.push(StorageDevice {
                path: drive_path.clone(),
                name: format!("Physical Drive {}", i),
                size: dev.size(),
                sector_size: dev.sector_size(),
                device_type: "Physical".to_string(),
            });
        }
    }

    // 2. Try logical drives (A: to Z:), only querying active letters to prevent long blocking timeouts
    let drives_mask = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
    for letter in b'A'..=b'Z' {
        let bit = letter - b'A';
        if (drives_mask & (1 << bit)) == 0 {
            continue;
        }

        let drive_path = format!(r"\\.\{}:", letter as char);
        if let Ok(dev) = Device::open(&drive_path) {
            devices.push(StorageDevice {
                path: drive_path.clone(),
                name: format!("Drive {}:", letter as char),
                size: dev.size(),
                sector_size: dev.sector_size(),
                device_type: "Logical".to_string(),
            });
        }
    }

    Ok(devices)
}

/// Lists all connected storage devices (Linux implementation).
#[cfg(target_os = "linux")]
pub fn list_devices() -> Result<Vec<StorageDevice>> {
    use std::fs;
    let mut devices = Vec::new();

    let block_dir = "/sys/class/block";
    if let Ok(entries) = fs::read_dir(block_dir) {
        for entry in entries.filter_map(std::result::Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            
            // Skip loop, ram, and other virtual block devices
            if name.starts_with("loop") || name.starts_with("ram") {
                continue;
            }

            let path = format!("/dev/{}", name);
            let sys_path = format!("{}/{}", block_dir, name);

            // Read size (sectors)
            let size_file = format!("{}/size", sys_path);
            if let Ok(size_str) = fs::read_to_string(&size_file) {
                if let Ok(sectors) = size_str.trim().parse::<u64>() {
                    if sectors == 0 {
                        continue;
                    }

                    // Read sector size
                    let sec_size_file = format!("{}/queue/hw_sector_size", sys_path);
                    let sector_size = fs::read_to_string(&sec_size_file)
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        .unwrap_or(512);

                    let size_bytes = sectors * 512; // Linux sysfs 'size' is always in 512-byte units

                    let is_partition = fs::metadata(format!("{}/partition", sys_path)).is_ok();
                    let device_type = if is_partition { "Partition" } else { "Physical" }.to_string();

                    devices.push(StorageDevice {
                        path,
                        name: name.clone(),
                        size: size_bytes,
                        sector_size,
                        device_type,
                    });
                }
        }
    }

    Ok(devices)
}

/// Lists all connected storage devices (macOS / generic Unix fallback implementation).
#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
pub fn list_devices() -> Result<Vec<StorageDevice>> {
    // Standard Unix implementation: scan /dev/disk*
    let mut devices = Vec::new();
    
    for i in 0..16 {
        // Scan both raw and buffered disk entries
        for prefix in &["disk", "rdisk"] {
            let disk_path = format!("/dev/{}{}", prefix, i);
            if let Ok(dev) = Device::open(&disk_path) {
                devices.push(StorageDevice {
                    path: disk_path.clone(),
                    name: format!("Disk {}{}", prefix, i),
                    size: dev.size(),
                    sector_size: dev.sector_size(),
                    device_type: "Physical".to_string(),
                });
            }
            
            // Try common partition suffixes
            for partition in 1..=4 {
                let part_path = format!("/dev/{}{}s{}", prefix, i, partition);
                if let Ok(dev) = Device::open(&part_path) {
                    devices.push(StorageDevice {
                        path: part_path.clone(),
                        name: format!("Disk {}{} Partition {}", prefix, i, partition),
                        size: dev.size(),
                        sector_size: dev.sector_size(),
                        device_type: "Partition".to_string(),
                    });
                }
            }
        }
    }
    
    Ok(devices)
}
