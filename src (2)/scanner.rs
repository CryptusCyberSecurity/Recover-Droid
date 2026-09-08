use crate::device::Device;
use crate::errors::{RecoveryError, Result};
use crate::signatures::{self, Signature};
use crate::utils;
use byteorder::{BigEndian, ByteOrder};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, warn};
use std::time::Instant;
use std::sync::mpsc::Sender;

/// Progress message sent during raw sector scanning.
#[derive(Clone, Debug)]
pub enum ScanProgress {
    Started { total_sectors: u64 },
    Update {
        current_sector: u64,
        speed: f64,
        recovered_count: u32,
        new_files: Vec<CarvedFile>,
    },
    ResolvingProgress {
        current: u64,
        total: u64,
    },
    Finished(Vec<CarvedFile>),
}

/// Represents a file successfully carved via signature scanning.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CarvedFile {
    pub id: u32,
    pub offset: u64,
    pub size: u64,
    pub is_exact: bool,
    pub signature: Signature,
    pub name: Option<String>,
    pub filesystem: Option<String>,
}

/// Helper function to find a subslice inside a larger slice.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Resolves a file's size directly from the device in a memory-efficient manner.
fn resolve_size_from_device(device: &Device, offset: u64, sig: &Signature) -> Option<u64> {
    let parser_type = sig.size_parser.as_deref()?;
    let dev_size = device.size();
    
    if offset >= dev_size {
        return None;
    }
    let max_size = std::cmp::min(sig.max_size, dev_size - offset);

    match parser_type {
        "png" => {
            let mut chunk_offset = 8u64;
            let mut header_buf = [0u8; 8];
            while chunk_offset.checked_add(12).is_some_and(|sum| sum <= max_size) {
                if device.read_at(offset + chunk_offset, &mut header_buf).is_err() {
                    break;
                }
                let chunk_len = BigEndian::read_u32(&header_buf[0..4]) as u64;
                let chunk_type = &header_buf[4..8];
                
                if chunk_type == b"IEND" {
                    return Some(chunk_offset + 12);
                }
                
                if let Some(next_offset) = chunk_offset.checked_add(chunk_len).and_then(|o| o.checked_add(12)) {
                    if next_offset <= chunk_offset {
                        break;
                    }
                    chunk_offset = next_offset;
                } else {
                    break;
                }
            }
            None
        }
        "mp4" => {
            let mut box_offset = 0u64;
            let mut header_buf = [0u8; 16];
            while box_offset < max_size {
                if box_offset.checked_add(8).is_none_or(|sum| sum > max_size) {
                    break;
                }
                if device.read_at(offset + box_offset, &mut header_buf[..8]).is_err() {
                    break;
                }
                let box_size_raw = BigEndian::read_u32(&header_buf[0..4]) as u64;
                let box_type = &header_buf[4..8];
                
                let mut valid_type = true;
                for &b in box_type {
                    if !(b.is_ascii_alphanumeric() || b == b' ' || b == b'_') {
                        valid_type = false;
                        break;
                    }
                }
                if !valid_type {
                    if box_offset > 0 {
                        return Some(box_offset);
                    } else {
                        return None;
                    }
                }
                
                let box_size = if box_size_raw == 1 {
                    if box_offset.checked_add(16).is_none_or(|sum| sum > max_size) {
                        break;
                    }
                    if device.read_at(offset + box_offset + 8, &mut header_buf[8..16]).is_err() {
                        break;
                    }
                    BigEndian::read_u64(&header_buf[8..16])
                } else if box_size_raw == 0 {
                    break;
                } else {
                    box_size_raw
                };
                
                if box_size < 8 {
                    break;
                }
                
                if let Some(next_offset) = box_offset.checked_add(box_size) {
                    box_offset = next_offset;
                } else {
                    break;
                }
            }
            if box_offset > 0 {
                Some(box_offset)
            } else {
                None
            }
        }
        "mkv" => {
            let limit = std::cmp::min(1024, max_size) as usize;
            let mut buf = vec![0u8; limit];
            if let Ok(bytes_read) = device.read_at(offset, &mut buf) {
                if let Some(size) = sig.parse_size(&buf[..bytes_read]) {
                    return Some(size);
                }
            }
            None
        }
        "pe" => {
            let limit = std::cmp::min(65536, max_size) as usize;
            let mut buf = vec![0u8; limit];
            if let Ok(bytes_read) = device.read_at(offset, &mut buf) {
                if let Some(size) = sig.parse_size(&buf[..bytes_read]) {
                    return Some(size);
                }
            }
            None
        }
        "mp3" => {
            let mut buffer = Vec::new();
            let chunk_size = 1024 * 1024;
            let mut current_read_offset = 0u64;
            
            while current_read_offset < max_size {
                let to_read = std::cmp::min(chunk_size, max_size - current_read_offset) as usize;
                let mut temp_buf = vec![0u8; to_read];
                match device.read_at(offset + current_read_offset, &mut temp_buf) {
                    Ok(bytes_read) => {
                        if bytes_read == 0 {
                            break;
                        }
                        buffer.extend_from_slice(&temp_buf[..bytes_read]);
                        current_read_offset += bytes_read as u64;
                        
                        let (size, truncated) = sig.parse_size_detail(&buffer);
                        if let Some(parsed_size) = size {
                            return Some(parsed_size);
                        }
                        if !truncated {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            None
        }
        _ => {
            let limit = std::cmp::min(1024 * 1024, max_size) as usize;
            let mut buf = vec![0u8; limit];
            if let Ok(bytes_read) = device.read_at(offset, &mut buf) {
                if let Some(size) = sig.parse_size(&buf[..bytes_read]) {
                    return Some(size);
                }
            }
            None
        }
    }
}

/// Scans forward to find a signature's footer, returning the relative size of the file.
fn find_footer_offset(device: &Device, start_offset: u64, sig: &Signature) -> Option<u64> {
    if sig.footers.is_empty() {
        return None;
    }
    const BUFFER_SIZE: usize = 1024 * 1024 * 4; // 4 MB buffer for high-speed sequential reading
    let mut search_buf = vec![0u8; BUFFER_SIZE];
    let mut current_offset = start_offset;
    let max_offset = std::cmp::min(start_offset + sig.max_size, device.size());
    let max_footer_len = sig.footers.iter().map(|f| f.len()).max().unwrap_or(0);

    while current_offset < max_offset {
        let to_read = std::cmp::min(BUFFER_SIZE as u64, max_offset - current_offset) as usize;
        if to_read < max_footer_len {
            break;
        }

        match device.read_at(current_offset, &mut search_buf[..to_read]) {
            Ok(bytes_read) => {
                if bytes_read < max_footer_len {
                    break;
                }
                let slice = &search_buf[..bytes_read];
                for footer in &sig.footers {
                    if let Some(pos) = find_subslice(slice, footer) {
                        return Some(current_offset + pos as u64 + footer.len() as u64 - start_offset);
                    }
                }
                
                // Ensure we ALWAYS advance by at least 1 byte to prevent infinite loops
                let advance = bytes_read as u64 - max_footer_len as u64;
                if advance == 0 {
                    break;
                }
                current_offset += advance;
            }
            Err(_) => break,
        }
    }
    None
}

/// Reads a block of data from the device, falling back to sector-by-sector reading if it fails (bad sector recovery).
fn read_with_fallback(device: &Device, offset: u64, buffer: &mut [u8]) -> Result<()> {
    match device.read_at(offset, buffer) {
        Ok(bytes_read) => {
            if bytes_read < buffer.len() {
                buffer[bytes_read..].fill(0);
            }
            Ok(())
        }
        Err(e) => {
            warn!(
                "Read error at offset {} (size {}): {}. Retrying with hierarchical fallback...",
                offset,
                buffer.len(),
                e
            );
            
            let sector_size = device.sector_size() as usize;
            let block_size = 65536; // 64 KB blocks
            let mut consecutive_failures = 0;
            const MAX_CONSECUTIVE_FAILURES: usize = 64; // Max consecutive sector failures before skipping the rest of the chunk
            
            let mut buf_idx = 0;
            while buf_idx < buffer.len() {
                let block_len = std::cmp::min(block_size, buffer.len() - buf_idx);
                let block_offset = offset + buf_idx as u64;
                let block_buf = &mut buffer[buf_idx..buf_idx + block_len];
                
                match device.read_at(block_offset, block_buf) {
                    Ok(bytes_read) => {
                        consecutive_failures = 0;
                        if bytes_read < block_buf.len() {
                            block_buf[bytes_read..].fill(0);
                        }
                        buf_idx += block_len;
                    }
                    Err(_) => {
                        // If the 64 KB block fails, read sector-by-sector within this block
                        let mut sector_idx = 0;
                        while sector_idx < block_len {
                            let sec_len = std::cmp::min(sector_size, block_len - sector_idx);
                            let sec_offset = block_offset + sector_idx as u64;
                            let sec_buf = &mut block_buf[sector_idx..sector_idx + sec_len];
                            
                            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                                sec_buf.fill(0);
                                consecutive_failures += 1;
                            } else {
                                match device.read_at(sec_offset, sec_buf) {
                                    Ok(bytes_read) => {
                                        consecutive_failures = 0;
                                        if bytes_read < sec_buf.len() {
                                            sec_buf[bytes_read..].fill(0);
                                        }
                                    }
                                    Err(_) => {
                                        sec_buf.fill(0);
                                        consecutive_failures += 1;
                                    }
                                }
                            }
                            sector_idx += sec_len;
                        }
                        buf_idx += block_len;
                    }
                }
            }
            Ok(())
        }
    }
}

/// Scans a single chunk of sectors for signatures using a pre-indexed header lookup table.
fn scan_chunk(
    device: &Device,
    start_sector: u64,
    sector_count: u64,
    sig_lookup: &[Vec<&Signature>; 256],
    recovered_count: &mut u32,
) -> Vec<CarvedFile> {
    let sector_size = device.sector_size() as u64;
    let chunk_size_bytes = sector_count * sector_size;
    let mut buffer = vec![0u8; chunk_size_bytes as usize];
    let offset = start_sector * sector_size;

    if let Err(e) = read_with_fallback(device, offset, &mut buffer) {
        error!("Fatal read error on sectors {}..{}: {}", start_sector, start_sector + sector_count, e);
        return Vec::new();
    }

    let mut local_findings = Vec::new();

    for i in 0..sector_count {
        let offset_in_buf = (i * sector_size) as usize;
        let sector_offset = offset + (i * sector_size);
        let slice = &buffer[offset_in_buf..];

        let first_byte = slice[0];
        let candidates = &sig_lookup[first_byte as usize];

        if !candidates.is_empty() {
            for sig in candidates {
                for header in &sig.headers {
                    if signatures::matches_header(slice, header) {
                        // Try parsing size dynamically first
                        let (size, is_exact) = if let Some(size) = sig.parse_size(slice) {
                            (size, true)
                        } else if !sig.footers.is_empty() || sig.size_parser.is_some() {
                            // Defer walk/parse to Phase 2 to read directly from device
                            (0, false)
                        } else {
                            // Fallback for footerless/parserless signatures
                            (sig.max_size, false)
                        };

                        local_findings.push(CarvedFile {
                            id: 0,
                            offset: sector_offset,
                            size,
                            is_exact,
                            signature: (*sig).clone(),
                            name: None,
                            filesystem: None,
                        });
                        *recovered_count += 1;
                    }
                }
            }
        }
    }

    local_findings
}

/// Scans the entire raw device using a single-threaded sequential reader and carves files matching signatures.
pub fn carve_device(
    device: &Device,
    signatures: &[Signature],
    progress_tx: Option<&Sender<ScanProgress>>,
) -> Result<Vec<CarvedFile>> {
    let total_sectors = device.total_sectors();
    let sector_size = device.sector_size() as u64;
    let chunk_size_sectors = 16384; // Optimized: 8 MB chunks for faster sequential reads

    debug!(
        "Carving device '{}' (Total sectors: {}) using sequential reading and fallback recovery",
        device.path(),
        total_sectors
    );

    if let Some(tx) = progress_tx {
        let _ = tx.send(ScanProgress::Started { total_sectors });
    }

    // Build the fast first-byte lookup table
    let mut sig_lookup: [Vec<&Signature>; 256] = std::array::from_fn(|_| Vec::new());
    for sig in signatures {
        for header in &sig.headers {
            if let Some(&first) = header.first()
                && !sig_lookup[first as usize].iter().any(|s| s.extension == sig.extension) {
                    sig_lookup[first as usize].push(sig);
                }
        }
    }

    // Set up progress bar with a compact, safe template to prevent carriage return wrapping bugs on narrow terminals
    let pb_opt = if progress_tx.is_none() {
        let pb = ProgressBar::new(total_sectors);
        if let Ok(style) = ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:15.cyan/blue}] {percent}% | {msg} | ETA: {eta}")
            .map_err(|e| RecoveryError::General(e.to_string()))
        {
            pb.set_style(style.progress_chars("#>-"));
        }
        // Enable steady tick so the spinner animates immediately
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        pb.set_message("Initializing...");
        Some(pb)
    } else {
        None
    };

    let start_time = Instant::now();
    let mut carved_files = Vec::new();
    let mut recovered_count = 0u32;

    let mut current_sector = 0;
    while current_sector < total_sectors {
        let count = std::cmp::min(chunk_size_sectors, total_sectors - current_sector);
        
        let findings = scan_chunk(device, current_sector, count, &sig_lookup, &mut recovered_count);
        
        if let Some(tx) = progress_tx {
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = if elapsed > 0.1 {
                (current_sector * sector_size) as f64 / elapsed
            } else {
                0.0
            };
            let _ = tx.send(ScanProgress::Update {
                current_sector,
                speed,
                recovered_count,
                new_files: findings.clone(),
            });
        }
        
        carved_files.extend(findings);
        
        current_sector += count;
        if let Some(ref pb) = pb_opt {
            pb.set_position(current_sector);

            // Update progress bar status details with compact sector units
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.1 {
                let bytes_read = current_sector * sector_size;
                let speed = bytes_read as f64 / elapsed;
                
                let sector_fmt = if total_sectors >= 1_000_000 {
                    format!("{:.1}M/{:.1}M", current_sector as f64 / 1_000_000.0, total_sectors as f64 / 1_000_000.0)
                } else if total_sectors >= 1_000 {
                    format!("{:.1}K/{:.1}K", current_sector as f64 / 1_000.0, total_sectors as f64 / 1_000.0)
                } else {
                    format!("{}/{}", current_sector, total_sectors)
                };

                pb.set_message(format!(
                    "{} | {} | Found: {}",
                    utils::format_speed(speed),
                    sector_fmt,
                    recovered_count
                ));
            }
        }
    }

    if let Some(ref pb) = pb_opt {
        pb.finish_with_message("Completed");
        println!("\n[Phase 1/3] Raw sector scan completed. Found {} potential files.", recovered_count);
    }

    // Sort findings by offset
    carved_files.sort_by_key(|f| f.offset);

    // Resolve deferred footers sequentially (prevents random disk seeks during main scan)
    if !carved_files.is_empty() {
        let footer_walk_count = carved_files.iter().filter(|f| f.size == 0).count() as u64;
        if footer_walk_count > 0 {
            let fp_pb_opt = if progress_tx.is_none() {
                println!("\n[Phase 2/3] Resolving file sizes & footers for {} files...", footer_walk_count);
                let fp_pb = ProgressBar::new(footer_walk_count);
                if let Ok(style) = ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:15.cyan/blue}] {percent}% | Resolving sizes: {pos}/{len} | ETA: {eta}")
                    .map_err(|e| RecoveryError::General(e.to_string()))
                {
                    fp_pb.set_style(style.progress_chars("#>-"));
                }
                fp_pb.enable_steady_tick(std::time::Duration::from_millis(100));
                Some(fp_pb)
            } else {
                None
            };

            let mut resolved_count_phase2 = 0u64;
            for file in &mut carved_files {
                if file.size == 0 {
                    if let Some(tx) = progress_tx {
                        let _ = tx.send(ScanProgress::ResolvingProgress {
                            current: resolved_count_phase2,
                            total: footer_walk_count,
                        });
                    }

                    let mut resolved = false;
                    let mut should_do_footer_walk = true;
                    // 1. Try size parser if available
                    if file.signature.size_parser.is_some() {
                        should_do_footer_walk = false;
                        // Stage 1: Try parsing with a small 64 KB buffer first
                        let small_read = std::cmp::min(file.signature.max_size, 65536) as usize;
                        let mut buf = vec![0u8; small_read];
                        let mut is_truncated = false;
                        if let Ok(bytes_read) = device.read_at(file.offset, &mut buf[..small_read]) {
                            let (parsed_size, truncated) = file.signature.parse_size_detail(&buf[..bytes_read]);
                            if let Some(parsed_size) = parsed_size {
                                file.size = parsed_size;
                                file.is_exact = true;
                                resolved = true;
                            }
                            is_truncated = truncated;
                        }

                        // Stage 2: If parsing failed due to buffer truncation, read dynamically from device (or delegate to footer walk for JPEG)
                        if !resolved && is_truncated {
                            if file.signature.size_parser.as_deref() == Some("jpeg") {
                                should_do_footer_walk = true;
                            } else {
                                if let Some(parsed_size) = resolve_size_from_device(device, file.offset, &file.signature) {
                                    file.size = parsed_size;
                                    file.is_exact = true;
                                    resolved = true;
                                }
                                if !resolved && !file.signature.footers.is_empty() {
                                    should_do_footer_walk = true;
                                }
                            }
                        }
                    }
                    // 2. Try footer walk if size parser was not used or failed but allowed
                    if !resolved {
                        if should_do_footer_walk {
                            if let Some(resolved_size) = find_footer_offset(device, file.offset, &file.signature) {
                                file.size = resolved_size;
                                file.is_exact = true;
                                resolved = true;
                            }
                        }
                        if !resolved {
                            file.size = file.signature.max_size;
                            file.is_exact = false;
                        }
                    }
                    resolved_count_phase2 += 1;
                    if let Some(ref fp_pb) = fp_pb_opt {
                        fp_pb.inc(1);
                    }
                }
            }
            if let Some(tx) = progress_tx {
                let _ = tx.send(ScanProgress::ResolvingProgress {
                    current: footer_walk_count,
                    total: footer_walk_count,
                });
            }
            if let Some(ref fp_pb) = fp_pb_opt {
                fp_pb.finish_with_message("Completed");
                println!("\n[Phase 2/3] File sizes & footers resolved successfully.");
            }
        } else {
            if progress_tx.is_none() {
                println!("\n[Phase 2/3] No deferred file sizes/footers need resolution.");
            }
        }
    }

    // Filter out overlapping/nested files to prevent redundant duplicate carving
    let mut filtered_carved: Vec<CarvedFile> = Vec::new();
    for file in carved_files {
        let mut should_keep = true;
        
        // Check overlap against already accepted files
        for prev in &mut filtered_carved {
            let prev_end = prev.offset + prev.size;
            if file.offset >= prev.offset && file.offset < prev_end {
                // There is an overlap!
                if prev.is_exact {
                    // Discard the new file since it starts inside an exact file
                    should_keep = false;
                    break;
                } else {
                    // Truncate the previous fallback file to end exactly where this new file starts
                    prev.size = file.offset - prev.offset;
                    prev.is_exact = true; // It's now bounded exactly by the next file
                }
            }
        }

        if should_keep {
            filtered_carved.push(file);
        }
    }

    // Scan for deleted files on the filesystem to map carved offsets to original filenames
    let mut deleted_files_map = std::collections::HashMap::new();
    let mut fs_type = None;
    let mut scan_error = None;
    if let Ok(parser) = crate::filesystem::detect_filesystem(device) {
        fs_type = Some(parser.get_info().fs_type);
        match parser.scan_deleted(device) {
            Ok(deleted) => {
                for df in deleted {
                    if let Some(offset) = parser.get_file_offset(&df) {
                        deleted_files_map.insert(offset, df.name);
                    }
                }
            }
            Err(e) => {
                scan_error = Some(e.to_string());
            }
        }
    }

    // Write diagnostic log
    if let Ok(mut diag_file) = std::fs::File::create("carve_diagnostics.txt") {
        use std::io::Write;
        let _ = writeln!(diag_file, "Detected Filesystem: {:?}", fs_type);
        if let Some(ref err_msg) = scan_error {
            let _ = writeln!(diag_file, "Scan Deleted Error: {}", err_msg);
        }
        let _ = writeln!(diag_file, "Deleted Files Map (Total: {}):", deleted_files_map.len());
        for (offset, name) in &deleted_files_map {
            let _ = writeln!(diag_file, "  Offset: 0x{:X} ({}) -> Name: {}", offset, offset, name);
        }
        let _ = writeln!(diag_file, "\nCarved Files (Total: {}):", filtered_carved.len());
        for file in &filtered_carved {
            let _ = writeln!(diag_file, "  Offset: 0x{:X} ({}) -> Ext: {}", file.offset, file.offset, file.signature.extension);
        }
    }

    // Assign final sequential IDs and map names
    for (i, file) in filtered_carved.iter_mut().enumerate() {
        file.id = (i + 1) as u32;
        file.filesystem = fs_type.clone();
        if let Some(orig_name) = deleted_files_map.get(&file.offset) {
            file.name = Some(orig_name.clone());
        }
    }

    if let Some(tx) = progress_tx {
        let _ = tx.send(ScanProgress::Finished(filtered_carved.clone()));
    }

    Ok(filtered_carved)
}
