use crate::device::Device;
use crate::errors::{RecoveryError, Result};
use crate::filesystem::{DeletedFile, FilesystemParser};
use crate::scanner::CarvedFile;
use indicatif::{ProgressBar, ProgressStyle};
use log::{info, warn};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Writes a recovered file buffer safely to the destination path, creating directories if needed, and setting timestamps if provided.
pub fn write_file_safe<P: AsRef<Path>>(
    output_dir: P,
    rel_path: &str,
    data: &[u8],
    modified: Option<u64>,
    accessed: Option<u64>,
) -> Result<String> {
    let mut safe_rel_path = std::path::PathBuf::new();
    
    // Walk components and only keep Normal ones, filtering out RootDir, ParentDir (..), CurDir (.), etc.
    for component in Path::new(rel_path).components() {
        if let std::path::Component::Normal(name) = component {
            safe_rel_path.push(name);
        }
    }

    let dest_path = output_dir.as_ref().join(safe_rel_path);

    // 1. Resolve ancestor file conflicts: if any parent component in the path exists as a file, rename it.
    let mut ancestor = output_dir.as_ref().to_path_buf();
    if let Some(parent) = dest_path.parent() {
        if let Ok(relative_parent) = parent.strip_prefix(&output_dir) {
            for component in relative_parent.components() {
                ancestor.push(component);
                if ancestor.exists() && ancestor.is_file() {
                    let mut new_name = ancestor.clone();
                    new_name.set_extension("file_conflict");
                    let mut counter = 1;
                    while new_name.exists() {
                        new_name = ancestor.clone();
                        new_name.set_extension(format!("file_conflict_{}", counter));
                        counter += 1;
                    }
                    fs::rename(&ancestor, &new_name).map_err(RecoveryError::Io)?;
                    info!(
                        "Renamed conflicting file '{}' to '{}' to allow folder creation.",
                        ancestor.display(),
                        new_name.display()
                    );
                }
            }
        }
    }

    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent).map_err(RecoveryError::Io)?;
    }

    // 2. Resolve destination folder conflicts: if the file we want to write exists as a directory, rename it.
    if dest_path.exists() && dest_path.is_dir() {
        let mut new_name = dest_path.clone();
        new_name.set_extension("dir_conflict");
        let mut counter = 1;
        while new_name.exists() {
            new_name = dest_path.clone();
            new_name.set_extension(format!("dir_conflict_{}", counter));
            counter += 1;
        }
        fs::rename(&dest_path, &new_name).map_err(RecoveryError::Io)?;
        info!(
            "Renamed conflicting directory '{}' to '{}' to allow file writing.",
            dest_path.display(),
            new_name.display()
        );
    }

    fs::write(&dest_path, data).map_err(RecoveryError::Io)?;

    // Preserve original file timestamps if available
    if modified.is_some() || accessed.is_some() {
        if let Ok(file) = File::options().write(true).open(&dest_path) {
            let mut times = std::fs::FileTimes::new();
            if let Some(mod_ts) = modified {
                times = times.set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(mod_ts));
            }
            if let Some(acc_ts) = accessed {
                times = times.set_accessed(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(acc_ts));
            }
            let _ = file.set_times(times);
        }
    }

    let hash = crate::utils::compute_sha256_bytes(data);
    info!("Successfully wrote file: {} (SHA-256: {})", dest_path.display(), hash);
    Ok(hash)
}

/// Recovers a single file from the device given its metadata.
pub fn recover_file(device: &Device, parser: &dyn FilesystemParser, file: &DeletedFile, output_dir: &str) -> Result<String> {
    info!("Starting recovery for file ID {}: {}", file.id, file.name);
    let data = parser.read_file(device, file)?;
    let hash = write_file_safe(output_dir, &file.name, &data, file.modified, file.accessed)?;
    Ok(hash)
}

fn get_category_name(ext: &str) -> &'static str {
    match ext.to_lowercase().as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tiff" => "Images",
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "txt" | "csv" | "rtf" => "Documents",
        "zip" | "rar" | "7z" | "tar" | "gz" => "Archives",
        "mp3" | "wav" | "flac" | "ogg" | "m4a" => "Audio",
        "mp4" | "mov" | "avi" | "mkv" | "webm" => "Video",
        "sqlite" | "db" => "Databases",
        "exe" | "dll" | "elf" | "bin" => "Executables",
        _ => "Other",
    }
}

/// Carves a list of files from raw signatures and organizes them into category subfolders.
pub fn write_carved_files(device: &Device, carved: &[CarvedFile], output_dir: &str) -> Result<()> {
    fs::create_dir_all(output_dir).map_err(RecoveryError::Io)?;
    let mut buffer = vec![0u8; 1024 * 1024 * 8]; // 8 MB buffer for high-speed sequential transfer

    // Scan for deleted files on the filesystem to map carved offsets to original filenames and metadata
    let mut deleted_files_map = std::collections::HashMap::new();
    if let Ok(parser) = crate::filesystem::detect_filesystem(device) {
        if let Ok(deleted) = parser.scan_deleted(device) {
            for df in deleted {
                if let Some(offset) = parser.get_file_offset(&df) {
                    deleted_files_map.insert(offset, df);
                }
            }
        }
    }

    println!("\n[Phase 3/3] Saving {} carved files to '{}'...", carved.len(), output_dir);
    let pb = ProgressBar::new(carved.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:15.cyan/blue}] {percent}% | Saving carved files: {pos}/{len} | ETA: {eta}")
            .map_err(|e| RecoveryError::General(e.to_string()))?
            .progress_chars("#>-")
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    for file in carved {
        let category = get_category_name(&file.signature.extension);
        let category_dir = Path::new(output_dir).join(category);
        fs::create_dir_all(&category_dir).map_err(RecoveryError::Io)?;

        let (filename, modified, accessed) = if let Some(ref name) = file.name {
            let path_filename = Path::new(name)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(name)
                .to_string();
            if let Some(orig_df) = deleted_files_map.get(&file.offset) {
                (path_filename, orig_df.modified, orig_df.accessed)
            } else {
                (path_filename, None, None)
            }
        } else if let Some(orig_df) = deleted_files_map.get(&file.offset) {
            // Extract only the filename component to prevent directory transversal/corruption issues
            let path_filename = Path::new(&orig_df.name)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(&orig_df.name)
                .to_string();
            (path_filename, orig_df.modified, orig_df.accessed)
        } else {
            (format!("carved_file_{}_{}.{}", file.id, file.offset, file.signature.extension), None, None)
        };
        let dest_path = category_dir.join(&filename);
        
        let mut out_file = File::create(&dest_path).map_err(RecoveryError::Io)?;
        let mut bytes_remaining = file.size;
        let mut current_offset = file.offset;

        while bytes_remaining > 0 {
            let to_read = std::cmp::min(buffer.len() as u64, bytes_remaining) as usize;
            match device.read_at(current_offset, &mut buffer[..to_read]) {
                Ok(_) => {
                    out_file.write_all(&buffer[..to_read]).map_err(RecoveryError::Io)?;
                }
                Err(e) => {
                    warn!(
                        "Bad sector or I/O error carving file at offset {}: {}. Filling with zeroes.",
                        current_offset, e
                    );
                    let zero_buffer = vec![0u8; to_read];
                    out_file.write_all(&zero_buffer).map_err(RecoveryError::Io)?;
                }
            }

            bytes_remaining -= to_read as u64;
            current_offset += to_read as u64;
        }

        // Set timestamps on carved file if matched
        if modified.is_some() || accessed.is_some() {
            if let Ok(file_handle) = File::options().write(true).open(&dest_path) {
                let mut times = std::fs::FileTimes::new();
                if let Some(mod_ts) = modified {
                    times = times.set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(mod_ts));
                }
                if let Some(acc_ts) = accessed {
                    times = times.set_accessed(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(acc_ts));
                }
                let _ = file_handle.set_times(times);
            }
        }

        // Compute and log SHA-256 hash for forensic integrity
        if let Ok(hash) = crate::utils::compute_hash(&dest_path, "sha256") {
            info!("Carved file: {} (SHA-256: {})", filename, hash);
        }

        pb.inc(1);
    }

    pb.finish_with_message("Completed");
    println!("\n[Phase 3/3] Saving completed successfully.");
    Ok(())
}

/// Verifies integrity of a recovered file by checking signature structures.
pub fn verify_file_integrity<P: AsRef<Path>>(path: P) -> Result<bool> {
    let path_ref = path.as_ref();
    let mut file = File::open(path_ref).map_err(RecoveryError::Io)?;
    let metadata = file.metadata().map_err(RecoveryError::Io)?;
    let size = metadata.len();

    if size < 4 {
        return Ok(false);
    }

    let mut head = [0u8; 16];
    let to_read_head = std::cmp::min(size as usize, 16);
    file.read_exact(&mut head[..to_read_head]).map_err(RecoveryError::Io)?;

    let mut tail = vec![0u8; 1024];
    let to_read_tail = std::cmp::min(size, 1024) as usize;
    if size > 1024 {
        file.seek(SeekFrom::End(-(to_read_tail as i64))).map_err(RecoveryError::Io)?;
    } else {
        file.seek(SeekFrom::Start(0)).map_err(RecoveryError::Io)?;
    }
    file.read_exact(&mut tail[..to_read_tail]).map_err(RecoveryError::Io)?;

    let ext = path_ref
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "jpg" | "jpeg" => {
            let has_header = head[0..3] == [0xFF, 0xD8, 0xFF];
            let has_footer = tail.windows(2).any(|w| w == [0xFF, 0xD9]);
            Ok(has_header && has_footer)
        }
        "png" => {
            let has_header = head[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
            let has_footer = tail.windows(4).any(|w| w == b"IEND");
            Ok(has_header && has_footer)
        }
        "pdf" => {
            let has_header = head[0..4] == *b"%PDF";
            let has_footer = tail.windows(5).any(|w| w == b"%%EOF");
            Ok(has_header && has_footer)
        }
        "zip" | "docx" | "xlsx" | "pptx" => {
            let has_header = head[0..4] == *b"PK\x03\x04";
            let has_footer = tail.windows(4).any(|w| w == *b"PK\x05\x06");
            Ok(has_header && has_footer)
        }
        "sqlite" => {
            Ok(head[0..15] == *b"SQLite format 3")
        }
        "exe" => {
            Ok(head[0..2] == *b"MZ")
        }
        "elf" => {
            Ok(head[0..4] == [0x7F, 0x45, 0x4C, 0x46])
        }
        _ => {
            // General heuristic: file has contents
            Ok(size > 0)
        }
    }
}
