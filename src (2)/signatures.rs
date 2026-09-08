use crate::errors::{RecoveryError, Result};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use log::debug;
use serde::{Deserialize, Serialize};
use std::fs;

/// A signature definition for file carving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub name: String,
    pub extension: String,
    pub headers: Vec<Vec<u8>>,
    pub footers: Vec<Vec<u8>>,
    pub max_size: u64,
    pub size_parser: Option<String>,
}

fn parse_mp3_size_detail(header_data: &[u8], max_size: u64) -> (Option<u64>, bool) {
    let mut offset = 0;

    // 1. Check for ID3v2 header
    if header_data.len() >= 10 && &header_data[0..3] == b"ID3" {
        let flags = header_data[5];
        let has_footer = (flags & 0x10) != 0;
        let tag_size = (((header_data[6] as u32) & 0x7F) << 21)
            | (((header_data[7] as u32) & 0x7F) << 14)
            | (((header_data[8] as u32) & 0x7F) << 7)
            | ((header_data[9] as u32) & 0x7F);
        
        let mut total_tag_size = tag_size + 10;
        if has_footer {
            total_tag_size += 10;
        }
        offset = total_tag_size as usize;
    }

    let initial_offset = offset;
    let mut last_valid_offset = offset;
    let mut reached_end_of_buffer = false;

    // 2. Scan audio frames
    while (offset as u64) < max_size {
        if offset == header_data.len() {
            break;
        }
        if offset.checked_add(4).is_none_or(|sum| sum > header_data.len()) {
            reached_end_of_buffer = true;
            break;
        }

        // Check for ID3v1 "TAG" marker which can appear at the end of MP3 files
        if offset.checked_add(128).is_some_and(|sum| sum <= header_data.len()) && &header_data[offset..offset+3] == b"TAG" {
            offset += 128;
            last_valid_offset = offset;
            break;
        }

        let b0 = header_data[offset];
        let b1 = header_data[offset + 1];

        // Sync: check first 11 bits (0xFF and top 3 bits of next byte)
        if b0 != 0xFF || (b1 & 0xE0) != 0xE0 {
            break;
        }

        let version = (b1 >> 3) & 0x03;
        let layer = (b1 >> 1) & 0x03;

        if version == 1 || layer == 0 {
            break; // Reserved/invalid values
        }

        let b2 = header_data[offset + 2];
        let bitrate_idx = (b2 >> 4) & 0x0F;
        let sample_rate_idx = (b2 >> 2) & 0x03;
        let padding = ((b2 >> 1) & 0x01) as usize;

        if bitrate_idx == 0 || bitrate_idx == 15 || sample_rate_idx == 3 {
            break;
        }

        // Bitrate lookup table for Layer I, II, III
        let bitrate = match version {
            3 => { // MPEG-1
                match layer {
                    3 => { // Layer I
                        match bitrate_idx {
                            1 => 32000, 2 => 64000, 3 => 96000, 4 => 128000, 5 => 160000,
                            6 => 192000, 7 => 224000, 8 => 256000, 9 => 288000, 10 => 320000,
                            11 => 352000, 12 => 384000, 13 => 416000, 14 => 448000, _ => 0
                        }
                    }
                    2 => { // Layer II
                        match bitrate_idx {
                            1 => 32000, 2 => 48000, 3 => 56000, 4 => 64000, 5 => 80000,
                            6 => 96000, 7 => 112000, 8 => 128000, 9 => 160000, 10 => 192000,
                            11 => 224000, 12 => 256000, 13 => 320000, 14 => 384000, _ => 0
                        }
                    }
                    1 => { // Layer III
                        match bitrate_idx {
                            1 => 32000, 2 => 40000, 3 => 48000, 4 => 56000, 5 => 64000,
                            6 => 80000, 7 => 96000, 8 => 112000, 9 => 128000, 10 => 160000,
                            11 => 192000, 12 => 224000, 13 => 256000, 14 => 320000, _ => 0
                        }
                    }
                    _ => 0
                }
            }
            0 | 2 => { // MPEG-2 or MPEG-2.5
                match layer {
                    3 => { // Layer I
                        match bitrate_idx {
                            1 => 32000, 2 => 48000, 3 => 56000, 4 => 64000, 5 => 80000,
                            6 => 96000, 7 => 112000, 8 => 128000, 9 => 144000, 10 => 160000,
                            11 => 176000, 12 => 192000, 13 => 224000, 14 => 256000, _ => 0
                        }
                    }
                    1 | 2 => { // Layer II & III
                        match bitrate_idx {
                            1 => 8000, 2 => 16000, 3 => 24000, 4 => 32000, 5 => 40000,
                            6 => 48000, 7 => 56000, 8 => 64000, 9 => 80000, 10 => 96000,
                            11 => 112000, 12 => 128000, 13 => 144000, 14 => 160000, _ => 0
                        }
                    }
                    _ => 0
                }
            }
            _ => 0,
        };

        // Sample rate lookup table
        let sample_rate = match version {
            3 => { // MPEG-1
                match sample_rate_idx {
                    0 => 44100, 1 => 48000, 2 => 32000,
                    _ => 0,
                }
            }
            2 => { // MPEG-2
                match sample_rate_idx {
                    0 => 22050, 1 => 24000, 2 => 16000,
                    _ => 0,
                }
            }
            0 => { // MPEG-2.5
                match sample_rate_idx {
                    0 => 11025, 1 => 12000, 2 => 8000,
                    _ => 0,
                }
            }
            _ => 0,
        };

        if bitrate == 0 || sample_rate == 0 {
            break;
        }

        // Calculate frame size
        let frame_size = match layer {
            3 => { // Layer I
                (12 * bitrate / sample_rate + padding) * 4
            }
            2 => { // Layer II
                144 * bitrate / sample_rate + padding
            }
            1 => { // Layer III
                if version == 3 {
                    144 * bitrate / sample_rate + padding
                } else {
                    72 * bitrate / sample_rate + padding
                }
            }
            _ => 0,
        };

        if frame_size == 0 {
            break;
        }

        if offset.checked_add(frame_size).is_none_or(|sum| sum > header_data.len()) {
            reached_end_of_buffer = true;
            break;
        }

        offset += frame_size;
        last_valid_offset = offset;
    }

    if reached_end_of_buffer {
        (None, true)
    } else if last_valid_offset > initial_offset {
        (Some(last_valid_offset as u64), false)
    } else {
        (None, false)
    }
}

fn parse_mp4_size_detail(header_data: &[u8], max_size: u64) -> (Option<u64>, bool) {
    let mut offset = 0;
    let mut reached_end_of_buffer = false;
    while (offset as u64) < max_size {
        if offset == header_data.len() {
            break;
        }
        if offset.checked_add(8).is_none_or(|sum| sum > header_data.len()) {
            reached_end_of_buffer = true;
            break;
        }
        let box_size_raw = BigEndian::read_u32(&header_data[offset..offset + 4]) as u64;
        let box_type = &header_data[offset + 4..offset + 8];

        // Validate box type: must be ASCII alphanumeric or spaces
        for &b in box_type {
            if !(b.is_ascii_alphanumeric() || b == b' ' || b == b'_') {
                if offset > 0 {
                    return (Some(offset as u64), false);
                } else {
                    return (None, false);
                }
            }
        }

        let box_size = if box_size_raw == 1 {
            if offset.checked_add(16).is_none_or(|sum| sum > header_data.len()) {
                reached_end_of_buffer = true;
                break;
            }
            BigEndian::read_u64(&header_data[offset + 8..offset + 16])
        } else if box_size_raw == 0 {
            break;
        } else {
            box_size_raw
        };

        if box_size < 8 {
            break;
        }

        let box_size_usize = match usize::try_from(box_size) {
            Ok(s) => s,
            Err(_) => {
                reached_end_of_buffer = true;
                break;
            }
        };

        if offset.checked_add(box_size_usize).is_none_or(|sum| sum > header_data.len()) {
            reached_end_of_buffer = true;
            break;
        }

        offset += box_size_usize;
    }

    if reached_end_of_buffer {
        (None, true)
    } else if offset > 0 {
        (Some(offset as u64), false)
    } else {
        (None, false)
    }
}

fn parse_7z_size_detail(header_data: &[u8], max_size: u64) -> (Option<u64>, bool) {
    if header_data.len() >= 32 {
        let next_header_offset = LittleEndian::read_u64(&header_data[12..20]);
        let next_header_size = LittleEndian::read_u64(&header_data[20..28]);
        let total_size = 32u64
            .checked_add(next_header_offset)
            .and_then(|s| s.checked_add(next_header_size));
        
        if let Some(total_size) = total_size {
            if total_size > 32 && total_size < max_size {
                (Some(total_size), false)
            } else {
                (None, false)
            }
        } else {
            (None, false)
        }
    } else {
        (None, true)
    }
}

fn parse_ebml_vint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    if offset >= data.len() {
        return None;
    }
    let first_byte = data[offset];
    if first_byte == 0 {
        return None;
    }
    let leading_zeros = first_byte.leading_zeros() as usize;
    let len = leading_zeros + 1;
    if len > 8 || offset + len > data.len() {
        return None;
    }
    let mut val = (first_byte & (0xFF >> len)) as u64;
    for i in 1..len {
        val = (val << 8) | (data[offset + i] as u64);
    }
    Some((val, len))
}

fn parse_mkv_size_detail(header_data: &[u8], max_size: u64) -> (Option<u64>, bool) {
    let limit = std::cmp::min(header_data.len(), 1024);
    if header_data.len() < 4 {
        return (None, true);
    }
    for i in 0..limit - 4 {
        if header_data[i..i + 4] == [0x18, 0x53, 0x80, 0x67] {
            if let Some((vint_val, vint_len)) = parse_ebml_vint(header_data, i + 4) {
                let total_size = (i as u64)
                    .checked_add(4)
                    .and_then(|s| s.checked_add(vint_len as u64))
                    .and_then(|s| s.checked_add(vint_val));
                
                if let Some(total_size) = total_size {
                    if total_size < max_size {
                        return (Some(total_size), false);
                    } else {
                        return (None, false);
                    }
                } else {
                    return (None, false);
                }
            }
            break;
        }
    }
    if header_data.len() < 1024 {
        (None, true)
    } else {
        (None, false)
    }
}

fn parse_elf_size_detail(header_data: &[u8], max_size: u64) -> (Option<u64>, bool) {
    if header_data.len() >= 64 {
        let class = header_data[4];
        let is_little_endian = header_data[5] == 1;

        let read_u16_elf = |offset: usize| -> u16 {
            if is_little_endian {
                LittleEndian::read_u16(&header_data[offset..offset + 2])
            } else {
                BigEndian::read_u16(&header_data[offset..offset + 2])
            }
        };

        let read_u32_elf = |offset: usize| -> u32 {
            if is_little_endian {
                LittleEndian::read_u32(&header_data[offset..offset + 4])
            } else {
                BigEndian::read_u32(&header_data[offset..offset + 4])
            }
        };

        let read_u64_elf = |offset: usize| -> u64 {
            if is_little_endian {
                LittleEndian::read_u64(&header_data[offset..offset + 8])
            } else {
                BigEndian::read_u64(&header_data[offset..offset + 8])
            }
        };

        let mut total_size = 0u64;

        if class == 1 {
            if header_data.len() >= 52 {
                let phoff = read_u32_elf(28) as u64;
                let shoff = read_u32_elf(32) as u64;
                let phentsize = read_u16_elf(42) as u64;
                let phnum = read_u16_elf(44) as u64;
                let shentsize = read_u16_elf(46) as u64;
                let shnum = read_u16_elf(48) as u64;

                let end_ph = phnum.checked_mul(phentsize).and_then(|p| phoff.checked_add(p));
                let end_sh = shnum.checked_mul(shentsize).and_then(|s| shoff.checked_add(s));
                
                if let (Some(ph), Some(sh)) = (end_ph, end_sh) {
                    total_size = std::cmp::max(ph, sh);
                }
            }
        } else if class == 2
            && header_data.len() >= 64 {
                let phoff = read_u64_elf(32);
                let shoff = read_u64_elf(40);
                let phentsize = read_u16_elf(54) as u64;
                let phnum = read_u16_elf(56) as u64;
                let shentsize = read_u16_elf(58) as u64;
                let shnum = read_u16_elf(60) as u64;

                let end_ph = phnum.checked_mul(phentsize).and_then(|p| phoff.checked_add(p));
                let end_sh = shnum.checked_mul(shentsize).and_then(|s| shoff.checked_add(s));
                
                if let (Some(ph), Some(sh)) = (end_ph, end_sh) {
                    total_size = std::cmp::max(ph, sh);
                }
            }

        if total_size > 0 && total_size < max_size {
            (Some(total_size), false)
        } else {
            (None, false)
        }
    } else {
        (None, true)
    }
}

fn parse_jpeg_size_detail(header_data: &[u8], _max_size: u64) -> (Option<u64>, bool) {
    if header_data.len() < 4 {
        return (None, true);
    }
    if header_data[0] != 0xFF || header_data[1] != 0xD8 {
        return (None, false);
    }
    
    let mut off: usize = 2;
    while off.checked_add(2).is_some_and(|sum| sum <= header_data.len()) {
        if header_data[off] != 0xFF {
            return (None, false);
        }
        let marker = header_data[off + 1];
        if marker == 0xFF {
            off += 1;
            continue;
        }
        if marker == 0xD8 {
            off += 2;
            continue;
        }
        if marker == 0xD9 {
            return (Some(off as u64 + 2), false);
        }
        if marker == 0xDA {
            // SOS: Start of Scan. We successfully validated the header!
            // But we don't know the exact size yet because SOS contains entropy-coded data.
            // So we return (None, true) to indicate we need a footer walk.
            return (None, true);
        }
        
        // These markers have no payload size:
        // RST0-RST7 (D0-D7), TEM (01).
        if (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            off += 2;
            continue;
        }
        
        // Other markers have a 2-byte length
        if off.checked_add(4).is_none_or(|sum| sum > header_data.len()) {
            return (None, true);
        }
        let marker_len = BigEndian::read_u16(&header_data[off + 2..off + 4]) as usize;
        if marker_len < 2 {
            return (None, false);
        }
        
        if let Some(next_off) = off.checked_add(2).and_then(|o| o.checked_add(marker_len)) {
            off = next_off;
        } else {
            return (None, false);
        }
    }
    
    if off < header_data.len() {
        (None, false)
    } else {
        (None, true)
    }
}

impl Signature {
    /// Attempts to parse the exact size of the file from its header data, with truncation detection.
    /// Returns `(Some(size), false)` on success, `(None, true)` if the buffer is truncated,
    /// and `(None, false)` if parsing fails due to invalid data format.
    pub fn parse_size_detail(&self, header_data: &[u8]) -> (Option<u64>, bool) {
        let parser_type = match self.size_parser.as_deref() {
            Some(p) => p,
            None => return (None, false),
        };
        match parser_type {
            "riff" => {
                if header_data.len() >= 8 {
                    let size = LittleEndian::read_u32(&header_data[4..8]) as u64;
                    (Some(size + 8), false)
                } else {
                    (None, true)
                }
            }
            "bmp" => {
                if header_data.len() >= 6 {
                    let size = LittleEndian::read_u32(&header_data[2..6]) as u64;
                    if size > 0 && size < self.max_size {
                        (Some(size), false)
                    } else {
                        (None, false)
                    }
                } else {
                    (None, true)
                }
            }
            "png" => {
                let mut offset: usize = 8;
                let mut truncated = false;
                while offset.checked_add(12).is_some_and(|sum| sum <= header_data.len()) {
                    let chunk_len = BigEndian::read_u32(&header_data[offset..offset + 4]) as usize;
                    let chunk_type = &header_data[offset + 4..offset + 8];

                    if chunk_type == b"IEND" {
                        return (Some((offset + 12) as u64), false);
                    }

                    if let Some(next_offset) = offset.checked_add(chunk_len).and_then(|o| o.checked_add(12)) {
                        offset = next_offset;
                    } else {
                        break;
                    }
                    if offset > self.max_size as usize {
                        break;
                    }
                }
                if offset.checked_add(12).is_none_or(|sum| sum > header_data.len()) && offset <= self.max_size as usize {
                    truncated = true;
                }
                (None, truncated)
            }
            "sqlite" => {
                if header_data.len() >= 32 {
                    let mut page_size = BigEndian::read_u16(&header_data[16..18]) as u64;
                    if page_size == 1 {
                        page_size = 65536;
                    }
                    let page_count = BigEndian::read_u32(&header_data[28..32]) as u64;
                    if page_size > 0 && page_count > 0 {
                        let total_size = page_size * page_count;
                        if total_size < self.max_size {
                            return (Some(total_size), false);
                        }
                    }
                    (None, false)
                } else {
                    (None, true)
                }
            }
            "pe" => {
                if header_data.len() >= 0x40 {
                    let pe_offset = LittleEndian::read_u32(&header_data[0x3C..0x40]) as usize;
                    if pe_offset + 248 <= header_data.len() {
                        if &header_data[pe_offset..pe_offset + 4] == b"PE\0\0" {
                            let num_sections = LittleEndian::read_u16(&header_data[pe_offset + 6..pe_offset + 8]) as usize;
                            let size_opt_header = LittleEndian::read_u16(&header_data[pe_offset + 20..pe_offset + 22]) as usize;
                            
                            let mut sections_offset = pe_offset + 24 + size_opt_header;
                            let mut max_file_offset = 0u64;
                            let mut truncated = false;

                            for _ in 0..num_sections {
                                if sections_offset + 40 <= header_data.len() {
                                    let size_raw = LittleEndian::read_u32(&header_data[sections_offset + 16..sections_offset + 20]) as u64;
                                    let ptr_raw = LittleEndian::read_u32(&header_data[sections_offset + 20..sections_offset + 24]) as u64;
                                    let end_offset = ptr_raw + size_raw;
                                    if end_offset > max_file_offset {
                                        max_file_offset = end_offset;
                                    }
                                    sections_offset += 40;
                                } else {
                                    truncated = true;
                                    break;
                                }
                            }
                            if truncated {
                                (None, true)
                            } else if max_file_offset > 0 && max_file_offset < self.max_size {
                                (Some(max_file_offset), false)
                            } else {
                                (None, false)
                            }
                        } else {
                            (None, false)
                        }
                    } else {
                        (None, true)
                    }
                } else {
                    (None, true)
                }
            }
            "mp3" => parse_mp3_size_detail(header_data, self.max_size),
            "mp4" => parse_mp4_size_detail(header_data, self.max_size),
            "7z" => parse_7z_size_detail(header_data, self.max_size),
            "mkv" => parse_mkv_size_detail(header_data, self.max_size),
            "elf" => parse_elf_size_detail(header_data, self.max_size),
            "jpeg" => parse_jpeg_size_detail(header_data, self.max_size),
            _ => (None, false),
        }
    }

    /// Attempts to parse the exact size of the file from its header data.
    /// Returns `None` if the format does not support size parsing or if parsing fails.
    pub fn parse_size(&self, header_data: &[u8]) -> Option<u64> {
        self.parse_size_detail(header_data).0
    }
}

/// Returns the embedded set of standard signatures for 22 file formats.
pub fn get_default_signatures() -> Vec<Signature> {
    vec![
        // Images
        Signature {
            name: "JPEG Image".to_string(),
            extension: "jpg".to_string(),
            headers: vec![vec![0xFF, 0xD8, 0xFF]],
            footers: vec![vec![0xFF, 0xD9]],
            max_size: 20 * 1024 * 1024,
            size_parser: Some("jpeg".to_string()),
        },
        Signature {
            name: "PNG Image".to_string(),
            extension: "png".to_string(),
            headers: vec![vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]],
            footers: vec![vec![0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]],
            max_size: 30 * 1024 * 1024,
            size_parser: Some("png".to_string()),
        },
        Signature {
            name: "GIF Image".to_string(),
            extension: "gif".to_string(),
            headers: vec![
                vec![0x47, 0x49, 0x46, 0x38, 0x37, 0x61],
                vec![0x47, 0x49, 0x46, 0x38, 0x39, 0x61],
            ],
            footers: vec![vec![0x3B]],
            max_size: 10 * 1024 * 1024,
            size_parser: None,
        },
        Signature {
            name: "BMP Image".to_string(),
            extension: "bmp".to_string(),
            headers: vec![vec![0x42, 0x4D]],
            footers: vec![],
            max_size: 20 * 1024 * 1024,
            size_parser: Some("bmp".to_string()),
        },
        Signature {
            name: "WEBP Image".to_string(),
            extension: "webp".to_string(),
            headers: vec![vec![
                0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50,
            ]], // We will mask/ignore bytes 4..8 during matching
            footers: vec![],
            max_size: 50 * 1024 * 1024,
            size_parser: Some("riff".to_string()),
        },
        // Documents
        Signature {
            name: "PDF Document".to_string(),
            extension: "pdf".to_string(),
            headers: vec![vec![0x25, 0x50, 0x44, 0x46]],
            footers: vec![vec![0x25, 0x25, 0x45, 0x4F, 0x46]], // %%EOF
            max_size: 50 * 1024 * 1024,
            size_parser: None,
        },
        Signature {
            name: "ZIP Archive / Office Document".to_string(),
            extension: "zip".to_string(),
            headers: vec![vec![0x50, 0x4B, 0x03, 0x04]],
            footers: vec![vec![0x50, 0x4B, 0x05, 0x06]], // End of central directory marker
            max_size: 50 * 1024 * 1024,
            size_parser: None,
        },
        // Office documents sharing ZIP magic
        Signature {
            name: "DOCX Document".to_string(),
            extension: "docx".to_string(),
            headers: vec![vec![0x50, 0x4B, 0x03, 0x04]],
            footers: vec![vec![0x50, 0x4B, 0x05, 0x06]],
            max_size: 20 * 1024 * 1024,
            size_parser: None,
        },
        Signature {
            name: "XLSX Document".to_string(),
            extension: "xlsx".to_string(),
            headers: vec![vec![0x50, 0x4B, 0x03, 0x04]],
            footers: vec![vec![0x50, 0x4B, 0x05, 0x06]],
            max_size: 20 * 1024 * 1024,
            size_parser: None,
        },
        Signature {
            name: "PPTX Document".to_string(),
            extension: "pptx".to_string(),
            headers: vec![vec![0x50, 0x4B, 0x03, 0x04]],
            footers: vec![vec![0x50, 0x4B, 0x05, 0x06]],
            max_size: 50 * 1024 * 1024,
            size_parser: None,
        },
        // Archives
        Signature {
            name: "RAR Archive".to_string(),
            extension: "rar".to_string(),
            headers: vec![
                vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00],       // RAR v4
                vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00], // RAR v5
            ],
            footers: vec![],
            max_size: 500 * 1024 * 1024,
            size_parser: None,
        },
        Signature {
            name: "7Z Archive".to_string(),
            extension: "7z".to_string(),
            headers: vec![vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]],
            footers: vec![],
            max_size: 1024 * 1024 * 1024, // 1 GB
            size_parser: Some("7z".to_string()),
        },
        // Audio/Video
        Signature {
            name: "MP3 Audio".to_string(),
            extension: "mp3".to_string(),
            headers: vec![
                vec![0x49, 0x44, 0x33], // ID3v2 header
                vec![0xFF, 0xFB],       // Raw MPEG Layer 3 frame header
                vec![0xFF, 0xF3],       // Frame header (MPEG-2.5)
            ],
            footers: vec![],
            max_size: 50 * 1024 * 1024,
            size_parser: Some("mp3".to_string()),
        },
        Signature {
            name: "WAV Audio".to_string(),
            extension: "wav".to_string(),
            headers: vec![vec![
                0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45,
            ]],
            footers: vec![],
            max_size: 200 * 1024 * 1024,
            size_parser: Some("riff".to_string()),
        },
        Signature {
            name: "FLAC Audio".to_string(),
            extension: "flac".to_string(),
            headers: vec![vec![0x66, 0x4C, 0x61, 0x43]], // fLaC
            footers: vec![],
            max_size: 150 * 1024 * 1024,
            size_parser: None,
        },
        Signature {
            name: "MP4 Video".to_string(),
            extension: "mp4".to_string(),
            headers: vec![
                vec![0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70],
                vec![0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70],
            ],
            footers: vec![],
            max_size: 2 * 1024 * 1024 * 1024, // 2 GB
            size_parser: Some("mp4".to_string()),
        },
        Signature {
            name: "MOV Video".to_string(),
            extension: "mov".to_string(),
            headers: vec![vec![0x66, 0x74, 0x79, 0x70, 0x71, 0x74, 0x20, 0x20]],
            footers: vec![],
            max_size: 2 * 1024 * 1024 * 1024,
            size_parser: Some("mp4".to_string()),
        },
        Signature {
            name: "AVI Video".to_string(),
            extension: "avi".to_string(),
            headers: vec![vec![
                0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x41, 0x56, 0x49, 0x20,
            ]],
            footers: vec![],
            max_size: 2 * 1024 * 1024 * 1024,
            size_parser: Some("riff".to_string()),
        },
        Signature {
            name: "MKV Video".to_string(),
            extension: "mkv".to_string(),
            headers: vec![vec![0x1A, 0x45, 0xDF, 0xA3]], // EBML
            footers: vec![],
            max_size: 4 * 1024 * 1024 * 1024, // 4 GB
            size_parser: Some("mkv".to_string()),
        },
        // System/Database
        Signature {
            name: "SQLite Database".to_string(),
            extension: "sqlite".to_string(),
            headers: vec![vec![
                0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20,
                0x33, 0x00,
            ]],
            footers: vec![],
            max_size: 500 * 1024 * 1024,
            size_parser: Some("sqlite".to_string()),
        },
        Signature {
            name: "ELF Executable".to_string(),
            extension: "elf".to_string(),
            headers: vec![vec![0x7F, 0x45, 0x4C, 0x46]],
            footers: vec![],
            max_size: 50 * 1024 * 1024,
            size_parser: Some("elf".to_string()),
        },
        Signature {
            name: "Windows PE Executable".to_string(),
            extension: "exe".to_string(),
            headers: vec![vec![0x4D, 0x5A]], // MZ
            footers: vec![],
            max_size: 150 * 1024 * 1024,
            size_parser: Some("pe".to_string()),
        },
    ]
}

/// Loads signature definitions from a JSON file.
pub fn load_signatures_from_json(path: &str) -> Result<Vec<Signature>> {
    let content = fs::read_to_string(path).map_err(|e| {
        RecoveryError::SignatureError(format!("Failed to read signatures file '{}': {}", path, e))
    })?;

    let sigs: Vec<Signature> = serde_json::from_str(&content).map_err(|e| {
        RecoveryError::SignatureError(format!("Failed to parse custom signatures JSON: {}", e))
    })?;

    debug!("Loaded {} custom signatures from '{}'", sigs.len(), path);
    Ok(sigs)
}

/// Checks if a buffer matches a signature's header.
/// Handles wildcard masking for RIFF structures (bytes 4..8 are skipped).
pub fn matches_header(buffer: &[u8], header: &[u8]) -> bool {
    if buffer.len() < header.len() {
        return false;
    }

    // Special check for RIFF-based formats (bytes 4..8 contain size, which varies)
    if header.len() >= 12 && &header[0..4] == b"RIFF" {
        return &buffer[0..4] == b"RIFF" && buffer[8..header.len()] == header[8..header.len()];
    }

    &buffer[0..header.len()] == header
}
