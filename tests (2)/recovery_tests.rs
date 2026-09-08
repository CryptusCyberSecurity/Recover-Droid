use byteorder::{BigEndian, ByteOrder, LittleEndian};
use recover_droid::recovery::write_file_safe;
use recover_droid::signatures::{get_default_signatures, matches_header};
use recover_droid::utils::{format_duration, format_size, format_speed};
use std::fs;

#[test]
fn test_human_readable_formatting() {
    assert_eq!(format_size(0), "0 B");
    assert_eq!(format_size(1024), "1.00 KB");
    assert_eq!(format_size(2048 * 1024), "2.00 MB");
    assert_eq!(format_size(1024 * 1024 * 1024 * 5), "5.00 GB");

    assert_eq!(format_speed(0.0), "0 B/s");
    assert_eq!(format_speed(1024.0 * 25.5), "25.50 KB/s");

    assert_eq!(format_duration(0), "0s");
    assert_eq!(format_duration(59), "59s");
    assert_eq!(format_duration(120), "02m 00s");
    assert_eq!(format_duration(3600 + 180 + 5), "01h 03m 05s");
}

#[test]
fn test_matches_header_with_wildcards() {
    let raw_webp_header = vec![
        0x52, 0x49, 0x46, 0x46, 0x12, 0x34, 0x56, 0x78, 0x57, 0x45, 0x42, 0x50,
    ];
    let signature_header = vec![
        0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50,
    ];

    assert!(matches_header(&raw_webp_header, &signature_header));
}

#[test]
fn test_size_parsing_bmp() {
    let sigs = get_default_signatures();
    let bmp_sig = sigs.iter().find(|s| s.extension == "bmp").unwrap();

    let mut mock_header = vec![0u8; 100];
    mock_header[0] = 0x42; // 'B'
    mock_header[1] = 0x4D; // 'M'
    LittleEndian::write_u32(&mut mock_header[2..6], 5000); // Size = 5000 bytes

    let size = bmp_sig.parse_size(&mock_header);
    assert_eq!(size, Some(5000));
}

#[test]
fn test_size_parsing_riff() {
    let sigs = get_default_signatures();
    let wav_sig = sigs.iter().find(|s| s.extension == "wav").unwrap();

    let mut mock_header = vec![0u8; 100];
    mock_header[0..4].copy_from_slice(b"RIFF");
    LittleEndian::write_u32(&mut mock_header[4..8], 15000); // Chunk size = 15000
    mock_header[8..12].copy_from_slice(b"WAVE");

    let size = wav_sig.parse_size(&mock_header);
    assert_eq!(size, Some(15008)); // size + 8
}

#[test]
fn test_size_parsing_sqlite() {
    let sigs = get_default_signatures();
    let sqlite_sig = sigs.iter().find(|s| s.extension == "sqlite").unwrap();

    let mut mock_header = vec![0u8; 100];
    mock_header[0..15].copy_from_slice(b"SQLite format 3");
    BigEndian::write_u16(&mut mock_header[16..18], 4096); // Page size = 4096
    BigEndian::write_u32(&mut mock_header[28..32], 10);   // Page count = 10

    let size = sqlite_sig.parse_size(&mock_header);
    assert_eq!(size, Some(40960)); // 4096 * 10
}

#[test]
fn test_size_parsing_png() {
    let sigs = get_default_signatures();
    let png_sig = sigs.iter().find(|s| s.extension == "png").unwrap();

    // Reconstruct PNG mock chunks
    let mut mock_png = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // Header (8 bytes)
    ];

    // Chunk 1: IHDR (size 13)
    let chunk1_offset = mock_png.len();
    mock_png.extend_from_slice(&[0; 4]);
    BigEndian::write_u32(&mut mock_png[chunk1_offset..chunk1_offset + 4], 13);
    mock_png.extend_from_slice(b"IHDR");
    mock_png.extend_from_slice(&[0; 13]); // Dummy IHDR data
    mock_png.extend_from_slice(&[0; 4]);  // Dummy CRC

    // Chunk 2: IEND (size 0)
    let chunk2_offset = mock_png.len();
    mock_png.extend_from_slice(&[0; 4]);
    BigEndian::write_u32(&mut mock_png[chunk2_offset..chunk2_offset + 4], 0);
    mock_png.extend_from_slice(b"IEND");
    mock_png.extend_from_slice(&[0, 0, 0, 0]); // Dummy CRC for IEND

    let size = png_sig.parse_size(&mock_png);
    assert_eq!(size, Some(mock_png.len() as u64));
}

#[test]
fn test_size_parsing_mp3() {
    let sigs = get_default_signatures();
    let mp3_sig = sigs.iter().find(|s| s.extension == "mp3").unwrap();

    // 1. Mock ID3v2 tag (10 bytes header + 20 bytes body)
    let mut mock_mp3 = vec![
        0x49, 0x44, 0x33, // "ID3"
        0x03, 0x00,       // Version 2.3
        0x00,             // No flags
        0x00, 0x00, 0x00, 0x14, // Size = 20 (synchsafe: 20 bytes body)
    ];
    mock_mp3.extend_from_slice(&[0; 20]);

    // 2. Mock 2 MPEG Layer III frames (MPEG-1 Layer III, 128kbps, 44.1kHz, no padding)
    // Formula: 144 * 128000 / 44100 = 417 bytes
    mock_mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    mock_mp3.extend_from_slice(&[0; 413]);

    mock_mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    mock_mp3.extend_from_slice(&[0; 413]);

    let size = mp3_sig.parse_size(&mock_mp3);
    assert_eq!(size, Some(864));
}

#[test]
fn test_size_parsing_mp4() {
    let sigs = get_default_signatures();
    let mp4_sig = sigs.iter().find(|s| s.extension == "mp4").unwrap();

    // Create a mock MP4 box structure
    // Box 1: ftyp (size = 16)
    let mut mock_mp4 = vec![0u8; 16];
    BigEndian::write_u32(&mut mock_mp4[0..4], 16);
    mock_mp4[4..8].copy_from_slice(b"ftyp");
    
    // Box 2: mdat (size = 200)
    let box2_offset = mock_mp4.len();
    mock_mp4.extend_from_slice(&[0; 200]);
    BigEndian::write_u32(&mut mock_mp4[box2_offset..box2_offset + 4], 200);
    mock_mp4[box2_offset + 4..box2_offset + 8].copy_from_slice(b"mdat");

    let size = mp4_sig.parse_size(&mock_mp4);
    assert_eq!(size, Some(216));
}

#[test]
fn test_size_parsing_7z() {
    let sigs = get_default_signatures();
    let seven_z_sig = sigs.iter().find(|s| s.extension == "7z").unwrap();

    let mut mock_7z = vec![0u8; 32];
    mock_7z[0..6].copy_from_slice(b"7z\xBC\xAF\x27\x1C");
    LittleEndian::write_u64(&mut mock_7z[12..20], 1000); // Next header offset = 1000
    LittleEndian::write_u64(&mut mock_7z[20..28], 150);  // Next header size = 150

    let size = seven_z_sig.parse_size(&mock_7z);
    assert_eq!(size, Some(1182)); // 32 + 1000 + 150
}

#[test]
fn test_size_parsing_mkv() {
    let sigs = get_default_signatures();
    let mkv_sig = sigs.iter().find(|s| s.extension == "mkv").unwrap();

    // EBML header + Segment element (ID: 18 53 80 67)
    let mut mock_mkv = vec![
        0x1A, 0x45, 0xDF, 0xA3, // EBML
        0x84, // Length of EBML header (VINT length = 1, size = 4)
        0x00, 0x00, 0x00, 0x00, // Header contents
    ];

    // Segment
    let seg_offset = mock_mkv.len();
    mock_mkv.extend_from_slice(&[0x18, 0x53, 0x80, 0x67]); // Segment ID
    mock_mkv.extend_from_slice(&[0x40, 0xC8]); // VINT size 200 (length = 2, mask clears 0x40 -> size 200)
    mock_mkv.extend_from_slice(&[0; 200]); // Segment contents

    let size = mkv_sig.parse_size(&mock_mkv);
    assert_eq!(size, Some(seg_offset as u64 + 4 + 2 + 200)); // offset + ID(4) + VINT(2) + size(200)
}

#[test]
fn test_size_parsing_elf() {
    let sigs = get_default_signatures();
    let elf_sig = sigs.iter().find(|s| s.extension == "elf").unwrap();

    let mut mock_elf = vec![0u8; 100];
    mock_elf[0..4].copy_from_slice(b"\x7FELF");
    mock_elf[4] = 2; // 64-bit class
    mock_elf[5] = 1; // Little endian

    // e_shoff at 40 (8 bytes) = 500
    LittleEndian::write_u64(&mut mock_elf[40..48], 500);
    // e_shentsize at 58 (2 bytes) = 64
    LittleEndian::write_u16(&mut mock_elf[58..60], 64);
    // e_shnum at 60 (2 bytes) = 10
    LittleEndian::write_u16(&mut mock_elf[60..62], 10);

    let size = elf_sig.parse_size(&mock_elf);
    assert_eq!(size, Some(500 + 64 * 10)); // shoff + shentsize * shnum = 1140
}

#[test]
fn test_safe_path_writing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_path = temp_dir.path().to_str().unwrap();

    let data = b"Test recovery content";
    
    // Normal file
    let res = write_file_safe(output_path, "normal_file.txt", data, None, None);
    assert!(res.is_ok());
    assert!(temp_dir.path().join("normal_file.txt").exists());

    // Path traversal attempt should have directory characters filtered/stripped
    let res_traversal = write_file_safe(output_path, "../../../malicious.txt", data, None, None);
    assert!(res_traversal.is_ok());

    let malicious_resolved = temp_dir.path().join("malicious.txt");
    assert!(malicious_resolved.exists());
    assert_eq!(fs::read(malicious_resolved).unwrap(), data);
}

#[test]
fn test_fat32_lfn_reconstruction() {
    use recover_droid::device::Device;
    use recover_droid::filesystem::fat32::Fat32Parser;
    use recover_droid::filesystem::FilesystemParser;
    use std::io::Write;

    // Create a 1 MB mock disk image
    let temp_dir = tempfile::tempdir().unwrap();
    let img_path = temp_dir.path().join("mock_fat32.img");
    let mut file = std::fs::File::create(&img_path).unwrap();

    let mut disk_data = vec![0u8; 1024 * 1024];

    // 1. Write boot sector
    disk_data[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]); // Jump instruction
    disk_data[3..11].copy_from_slice(b"MSDOS5.0");
    LittleEndian::write_u16(&mut disk_data[11..13], 512); // Bytes per sector
    disk_data[13] = 1; // Sectors per cluster
    LittleEndian::write_u16(&mut disk_data[14..16], 32); // Reserved sectors
    disk_data[16] = 2; // FAT count
    LittleEndian::write_u16(&mut disk_data[19..21], 0);
    LittleEndian::write_u16(&mut disk_data[22..24], 0);
    LittleEndian::write_u32(&mut disk_data[32..36], 2048); // Total sectors
    LittleEndian::write_u32(&mut disk_data[36..40], 32); // Sectors per FAT
    LittleEndian::write_u32(&mut disk_data[44..48], 2); // Root cluster
    disk_data[82..90].copy_from_slice(b"FAT32   ");
    disk_data[510] = 0x55;
    disk_data[511] = 0xAA;

    // Root directory starts at data area: reserved_sectors (32) + fat_count (2) * sectors_per_fat (32) = 96 sectors.
    // Offset in bytes = 96 * 512 = 49152.
    let root_offset = 96 * 512;

    // Helper to write an LFN entry into disk_data
    let write_lfn_entry = |data: &mut [u8], offset: usize, seq: u8, name_part: &str| {
        data[offset] = seq;
        data[offset + 11] = 0x0F; // LFN attribute
        
        let chars: Vec<u16> = name_part.encode_utf16().collect();
        let mut char_idx = 0;
        let char_positions = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        
        for &pos in &char_positions {
            let val = if char_idx < chars.len() {
                chars[char_idx]
            } else if char_idx == chars.len() {
                0x0000 // Null terminator
            } else {
                0xFFFF // Padding
            };
            LittleEndian::write_u16(&mut data[offset + pos..offset + pos + 2], val);
            char_idx += 1;
        }
    };

    // Active LFN: "this_is_a_very_long_filename.txt"
    // Part 1: "this_is_a_ver"
    // Part 2: "y_long_filena"
    // Part 3: "me.txt"
    write_lfn_entry(&mut disk_data, root_offset, 0x43, "me.txt"); // Last entry (3 | 0x40)
    write_lfn_entry(&mut disk_data, root_offset + 32, 0x02, "y_long_filena");
    write_lfn_entry(&mut disk_data, root_offset + 64, 0x01, "this_is_a_ver");

    // SFN for active LFN
    let sfn_offset = root_offset + 96;
    disk_data[sfn_offset..sfn_offset + 11].copy_from_slice(b"THISIS~1TXT");
    disk_data[sfn_offset + 11] = 0x20; // Archive attribute
    LittleEndian::write_u16(&mut disk_data[sfn_offset + 26..sfn_offset + 28], 3); // Start cluster
    LittleEndian::write_u32(&mut disk_data[sfn_offset + 28..sfn_offset + 32], 100); // Size

    // Deleted LFN: "deleted_file.txt"
    // Part 1: "deleted_file"
    // Part 2: ".txt"
    write_lfn_entry(&mut disk_data, root_offset + 128, 0xE5, ".txt");
    write_lfn_entry(&mut disk_data, root_offset + 160, 0xE5, "deleted_file");

    // SFN for deleted LFN
    let deleted_sfn_offset = root_offset + 192;
    disk_data[deleted_sfn_offset] = 0xE5; // Mark deleted
    disk_data[deleted_sfn_offset + 1..deleted_sfn_offset + 11].copy_from_slice(b"LETED~1TXT");
    disk_data[deleted_sfn_offset + 11] = 0x20;
    LittleEndian::write_u16(&mut disk_data[deleted_sfn_offset + 26..deleted_sfn_offset + 28], 4); // Start cluster
    LittleEndian::write_u32(&mut disk_data[deleted_sfn_offset + 28..deleted_sfn_offset + 32], 200); // Size

    // Write all to file
    file.write_all(&disk_data).unwrap();
    file.sync_all().unwrap();

    // Open with Device
    let dev = Device::open(&img_path).unwrap();
    assert!(Fat32Parser::detect(&dev).unwrap());

    let parser = Fat32Parser::new(&dev).unwrap();
    let deleted = parser.scan_deleted(&dev).unwrap();

    // Verify deleted file name reconstruction
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].name, "deleted_file.txt");
    assert_eq!(deleted[0].size, 200);
}

#[test]
fn test_fat16_lfn_reconstruction() {
    use recover_droid::device::Device;
    use recover_droid::filesystem::fat16::Fat16Parser;
    use recover_droid::filesystem::FilesystemParser;
    use std::io::Write;

    // Create a 1 MB mock disk image
    let temp_dir = tempfile::tempdir().unwrap();
    let img_path = temp_dir.path().join("mock_fat16.img");
    let mut file = std::fs::File::create(&img_path).unwrap();

    let mut disk_data = vec![0u8; 1024 * 1024];

    // 1. Write boot sector
    disk_data[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]); // Jump instruction
    disk_data[3..11].copy_from_slice(b"MSDOS5.0");
    LittleEndian::write_u16(&mut disk_data[11..13], 512); // Bytes per sector
    disk_data[13] = 2; // Sectors per cluster
    LittleEndian::write_u16(&mut disk_data[14..16], 4); // Reserved sectors
    disk_data[16] = 2; // FAT count
    LittleEndian::write_u16(&mut disk_data[17..19], 512); // Root entry count
    LittleEndian::write_u16(&mut disk_data[19..21], 2048); // Total sectors
    disk_data[38] = 0x29; // Extended boot signature
    LittleEndian::write_u32(&mut disk_data[39..43], 0x12345678); // Serial number
    disk_data[54..62].copy_from_slice(b"FAT16   ");
    LittleEndian::write_u16(&mut disk_data[22..24], 8); // Sectors per FAT
    disk_data[510] = 0x55;
    disk_data[511] = 0xAA;

    // Root directory starts after FATs: reserved_sectors (4) + fat_count (2) * sectors_per_fat (8) = 20 sectors.
    // Offset in bytes = 20 * 512 = 10240.
    let root_offset = 20 * 512;

    // Helper to write an LFN entry into disk_data
    let write_lfn_entry = |data: &mut [u8], offset: usize, seq: u8, name_part: &str| {
        data[offset] = seq;
        data[offset + 11] = 0x0F; // LFN attribute
        
        let chars: Vec<u16> = name_part.encode_utf16().collect();
        let mut char_idx = 0;
        let char_positions = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        
        for &pos in &char_positions {
            let val = if char_idx < chars.len() {
                chars[char_idx]
            } else if char_idx == chars.len() {
                0x0000 // Null terminator
            } else {
                0xFFFF // Padding
            };
            LittleEndian::write_u16(&mut data[offset + pos..offset + pos + 2], val);
            char_idx += 1;
        }
    };

    // Deleted LFN: "deleted_fat16.txt" (17 chars)
    // Part 1: "deleted_fat1"
    // Part 2: "6.txt"
    write_lfn_entry(&mut disk_data, root_offset, 0xE5, "6.txt");
    write_lfn_entry(&mut disk_data, root_offset + 32, 0xE5, "deleted_fat1");

    // SFN for deleted LFN
    let deleted_sfn_offset = root_offset + 64;
    disk_data[deleted_sfn_offset] = 0xE5; // Mark deleted
    disk_data[deleted_sfn_offset + 1..deleted_sfn_offset + 11].copy_from_slice(b"LETED16TXT");
    disk_data[deleted_sfn_offset + 11] = 0x20;
    LittleEndian::write_u16(&mut disk_data[deleted_sfn_offset + 26..deleted_sfn_offset + 28], 4); // Start cluster
    LittleEndian::write_u32(&mut disk_data[deleted_sfn_offset + 28..deleted_sfn_offset + 32], 200); // Size

    // Write all to file
    file.write_all(&disk_data).unwrap();
    file.sync_all().unwrap();

    // Open with Device
    let dev = Device::open(&img_path).unwrap();
    assert!(Fat16Parser::detect(&dev).unwrap());

    let parser = Fat16Parser::new(&dev).unwrap();
    let deleted = parser.scan_deleted(&dev).unwrap();

    // Verify deleted file name reconstruction
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].name, "deleted_fat16.txt");
    assert_eq!(deleted[0].size, 200);
}

#[test]
fn test_smart_overlap_resolution() {
    use recover_droid::device::Device;
    use recover_droid::scanner::carve_device;
    use recover_droid::signatures::get_default_signatures;
    use std::fs::File;
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let img_path = temp_dir.path().join("mock_overlap.img");
    let mut file = File::create(&img_path).unwrap();

    // Create a 1MB disk image
    let mut disk_data = vec![0u8; 1024 * 1024];

    // File 1: PNG signature at sector 2 (offset 1024). We write no valid chunks, so its size fails to parse
    // and falls back to its footer walk (which also fails and defaults to max_size).
    let png_sig = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    disk_data[1024..1032].copy_from_slice(png_sig);

    // File 2: JPEG signature at sector 10 (offset 5120), with footer at offset 6000
    // Write a valid minimal JPEG header chain to satisfy validation
    let jpeg_header = &[
        0xFF, 0xD8,             // SOI
        0xFF, 0xE0, 0x00, 0x10, // APP0, length 16
        0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00,
        0xFF, 0xDA              // SOS (Start of Scan)
    ];
    disk_data[5120..5120 + jpeg_header.len()].copy_from_slice(jpeg_header);
    // JPEG footer: FF D9
    disk_data[6000..6002].copy_from_slice(&[0xFF, 0xD9]);

    file.write_all(&disk_data).unwrap();
    drop(file);

    let device = Device::open(img_path.to_str().unwrap()).unwrap();
    let sigs = get_default_signatures();

    let findings = carve_device(&device, &sigs, None).unwrap();

    // We expect both files to be recovered:
    // - The PNG starts at 1024. Its size should be truncated to 5120 - 1024 = 4096.
    // - The JPEG starts at 5120, ending at 6002 - 5120 = 882 bytes.
    assert_eq!(findings.len(), 2);
    
    let png_res = &findings[0];
    let jpeg_res = &findings[1];

    assert_eq!(png_res.offset, 1024);
    assert_eq!(png_res.size, 4096);
    assert!(png_res.is_exact);

    assert_eq!(jpeg_res.offset, 5120);
    assert_eq!(jpeg_res.size, 882);
    assert!(jpeg_res.is_exact);
}

#[test]
fn test_truncated_buffer_size_parsing() {
    use byteorder::{BigEndian, ByteOrder};
    use recover_droid::signatures::get_default_signatures;

    let sigs = get_default_signatures();
    let mp3_sig = sigs.iter().find(|s| s.extension == "mp3").unwrap();
    let mp4_sig = sigs.iter().find(|s| s.extension == "mp4").unwrap();

    // 1. MP3 truncated buffer
    let mut mock_mp3 = vec![
        0x49, 0x44, 0x33, // "ID3"
        0x03, 0x00,       // Version 2.3
        0x00,             // No flags
        0x00, 0x00, 0x00, 0x14, // Size = 20
    ];
    mock_mp3.extend_from_slice(&[0; 20]);
    // First frame complete (417 bytes)
    mock_mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    mock_mp3.extend_from_slice(&[0; 413]);
    // Second frame starts but is cut off mid-way
    mock_mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    mock_mp3.extend_from_slice(&[0; 100]); // cut off!

    let size = mp3_sig.parse_size(&mock_mp3);
    assert_eq!(size, None);

    // 2. MP4 truncated buffer
    let mut mock_mp4 = vec![0u8; 16];
    BigEndian::write_u32(&mut mock_mp4[0..4], 16);
    mock_mp4[4..8].copy_from_slice(b"ftyp");
    
    let box2_offset = mock_mp4.len();
    mock_mp4.extend_from_slice(&[0; 50]); // box claims to be 200, only 50 provided
    BigEndian::write_u32(&mut mock_mp4[box2_offset..box2_offset + 4], 200);
    mock_mp4[box2_offset + 4..box2_offset + 8].copy_from_slice(b"mdat");

    let size = mp4_sig.parse_size(&mock_mp4);
    assert_eq!(size, None);
}

#[test]
fn test_carved_filename_preservation() {
    use byteorder::{LittleEndian, ByteOrder};
    use recover_droid::device::Device;
    use recover_droid::scanner::carve_device;
    use recover_droid::signatures::get_default_signatures;
    use recover_droid::recovery::write_carved_files;
    use std::fs::File;
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let img_path = temp_dir.path().join("mock_carved_name.img");
    let mut file = File::create(&img_path).unwrap();

    let mut disk_data = vec![0u8; 1024 * 1024];

    // 1. FAT32 Boot sector
    disk_data[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    disk_data[3..11].copy_from_slice(b"MSDOS5.0");
    LittleEndian::write_u16(&mut disk_data[11..13], 512); // Sector size
    disk_data[13] = 8; // Sectors per cluster
    LittleEndian::write_u16(&mut disk_data[14..16], 32); // Reserved sectors
    disk_data[16] = 2; // FAT count
    LittleEndian::write_u16(&mut disk_data[17..19], 0); // Root entry count for FAT32
    LittleEndian::write_u16(&mut disk_data[19..21], 0);
    LittleEndian::write_u32(&mut disk_data[32..36], 2048); // Total sectors
    LittleEndian::write_u32(&mut disk_data[36..40], 32); // Sectors per FAT
    LittleEndian::write_u32(&mut disk_data[44..48], 2); // Root cluster
    disk_data[66] = 0x29;
    LittleEndian::write_u32(&mut disk_data[67..71], 0x12345678);
    disk_data[82..90].copy_from_slice(b"FAT32   ");
    disk_data[510] = 0x55;
    disk_data[511] = 0xAA;

    // Root directory offset: (32 + 2 * 32) * 512 = 96 * 512 = 49152
    let root_offset = 96 * 512;

    // SFN for deleted LFN
    let deleted_sfn_offset = root_offset;
    disk_data[deleted_sfn_offset] = 0xE5; // Mark deleted
    disk_data[deleted_sfn_offset + 1..deleted_sfn_offset + 11].copy_from_slice(b"ELETED PNG");
    disk_data[deleted_sfn_offset + 11] = 0x20;
    LittleEndian::write_u16(&mut disk_data[deleted_sfn_offset + 26..deleted_sfn_offset + 28], 4); // Start cluster
    LittleEndian::write_u32(&mut disk_data[deleted_sfn_offset + 28..deleted_sfn_offset + 32], 25); // Size

    // Write PNG file at cluster 4 (offset: (96 + (4 - 2) * 8) * 512 = 112 * 512 = 57344)
    let png_offset = 112 * 512;
    disk_data[png_offset..png_offset + 8].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    disk_data[png_offset + 8..png_offset + 21].copy_from_slice(b"hello world!!");
    // PNG footer (IEND)
    disk_data[png_offset + 21..png_offset + 25].copy_from_slice(b"IEND");

    file.write_all(&disk_data).unwrap();
    drop(file);

    let device = Device::open(img_path.to_str().unwrap()).unwrap();
    let sigs = get_default_signatures();

    let findings = carve_device(&device, &sigs, None).unwrap();
    assert!(!findings.is_empty());

    // Recover the files using write_carved_files
    let output_dir = temp_dir.path().join("recovered");
    write_carved_files(&device, &findings, output_dir.to_str().unwrap()).unwrap();

    // Verify the file was written to the output dir in the Images category folder as "_ELETED.PNG" (first letter replaced due to delete marker)
    let expected_path = output_dir.join("Images").join("_ELETED.PNG");
    assert!(expected_path.exists());
}

#[test]
fn test_partition_aware_carved_filename_preservation() {
    use byteorder::{LittleEndian, ByteOrder};
    use recover_droid::device::Device;
    use recover_droid::scanner::carve_device;
    use recover_droid::signatures::get_default_signatures;
    use recover_droid::recovery::write_carved_files;
    use std::fs::File;
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let img_path = temp_dir.path().join("mock_partition_disk.img");
    let mut file = File::create(&img_path).unwrap();

    let mut disk_data = vec![0u8; 2048 * 512 + 1024 * 1024]; // 2048 sectors of MBR/Padding + 1 MB partition

    // Write MBR to sector 0 (disk_data[0..512])
    // Partition table starts at offset 446
    let entry_offset = 446;
    disk_data[entry_offset] = 0x80; // Active/Bootable
    disk_data[entry_offset + 4] = 0x0C; // FAT32 with LBA
    LittleEndian::write_u32(&mut disk_data[entry_offset + 8..entry_offset + 12], 2048); // Start LBA: 2048
    LittleEndian::write_u32(&mut disk_data[entry_offset + 12..entry_offset + 16], 2048); // Sector count: 2048
    disk_data[510] = 0x55;
    disk_data[511] = 0xAA;

    // Partition starts at offset: 2048 * 512 = 1048576
    let part_start = 2048 * 512;

    // FAT32 Boot sector at partition start
    disk_data[part_start..part_start + 3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    disk_data[part_start + 3..part_start + 11].copy_from_slice(b"MSDOS5.0");
    LittleEndian::write_u16(&mut disk_data[part_start + 11..part_start + 13], 512); // Sector size
    disk_data[part_start + 13] = 8; // Sectors per cluster
    LittleEndian::write_u16(&mut disk_data[part_start + 14..part_start + 16], 32); // Reserved sectors
    disk_data[part_start + 16] = 2; // FAT count
    LittleEndian::write_u32(&mut disk_data[part_start + 32..part_start + 36], 2048); // Total sectors
    LittleEndian::write_u32(&mut disk_data[part_start + 36..part_start + 40], 32); // Sectors per FAT
    LittleEndian::write_u32(&mut disk_data[part_start + 44..part_start + 48], 2); // Root cluster
    disk_data[part_start + 66] = 0x29;
    LittleEndian::write_u32(&mut disk_data[part_start + 67..part_start + 71], 0x12345678);
    disk_data[part_start + 82..part_start + 90].copy_from_slice(b"FAT32   ");
    disk_data[part_start + 510] = 0x55;
    disk_data[part_start + 511] = 0xAA;

    // Root directory offset: part_start + (32 + 2 * 32) * 512 = part_start + 96 * 512
    let root_offset = part_start + 96 * 512;

    // SFN for deleted LFN
    let deleted_sfn_offset = root_offset;
    disk_data[deleted_sfn_offset] = 0xE5; // Mark deleted
    disk_data[deleted_sfn_offset + 1..deleted_sfn_offset + 11].copy_from_slice(b"ART    PNG");
    disk_data[deleted_sfn_offset + 11] = 0x20;
    LittleEndian::write_u16(&mut disk_data[deleted_sfn_offset + 26..deleted_sfn_offset + 28], 4); // Start cluster
    LittleEndian::write_u32(&mut disk_data[deleted_sfn_offset + 28..deleted_sfn_offset + 32], 25); // Size

    // Write PNG file at cluster 4 (offset relative to partition: (96 + (4 - 2) * 8) * 512 = 112 * 512 = 57344)
    // Absolute offset: part_start + 57344
    let png_offset = part_start + 112 * 512;
    disk_data[png_offset..png_offset + 8].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    disk_data[png_offset + 8..png_offset + 21].copy_from_slice(b"hello world!!");
    disk_data[png_offset + 21..png_offset + 25].copy_from_slice(b"IEND");

    file.write_all(&disk_data).unwrap();
    drop(file);

    let device = Device::open(img_path.to_str().unwrap()).unwrap();
    let sigs = get_default_signatures();

    let findings = carve_device(&device, &sigs, None).unwrap();
    assert!(!findings.is_empty());

    // Recover the files using write_carved_files
    let output_dir = temp_dir.path().join("recovered");
    write_carved_files(&device, &findings, output_dir.to_str().unwrap()).unwrap();

    // Verify the file was written to the output dir in the Images category folder as "_ART.PNG" (first letter replaced due to delete marker)
    let expected_path = output_dir.join("Images").join("_ART.PNG");
    assert!(expected_path.exists());
}


#[test]
fn test_phase2_size_parser_resolution() {
    use recover_droid::device::Device;
    use recover_droid::scanner::carve_device;
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let img_path = temp_dir.path().join("mock_device.img");
    let mut file = fs::File::create(&img_path).unwrap();

    // 1. Build a mock MP3 file
    let mut mock_mp3 = vec![
        0x49, 0x44, 0x33, // "ID3"
        0x03, 0x00,       // Version 2.3
        0x00,             // No flags
        0x00, 0x00, 0x00, 0x14, // Size = 20
    ];
    mock_mp3.extend_from_slice(&[0; 20]);
    // Frame 1
    mock_mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    mock_mp3.extend_from_slice(&[0; 413]);
    // Frame 2
    mock_mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    mock_mp3.extend_from_slice(&[0; 413]);

    let mp3_len = mock_mp3.len(); // 864 bytes

    // 2. Put this MP3 file on a mock device, followed by random non-MP3 data/zeroes
    let mut device_data = vec![0u8; 1024 * 1024 * 9]; // 9 MB device
    device_data[0..mp3_len].copy_from_slice(&mock_mp3);
    for i in mp3_len..(mp3_len + 100) {
        device_data[i] = 0xAA;
    }

    file.write_all(&device_data).unwrap();
    drop(file);

    let device = Device::open(img_path.to_str().unwrap()).unwrap();
    let sigs = get_default_signatures();

    let findings = carve_device(&device, &sigs, None).unwrap();
    
    let mp3_carved = findings.iter().find(|f| f.signature.extension == "mp3");
    assert!(mp3_carved.is_some());
    let mp3 = mp3_carved.unwrap();
    assert_eq!(mp3.size, mp3_len as u64);
    assert!(mp3.is_exact);
}

#[test]
fn test_parse_size_detail_truncation() {
    use recover_droid::signatures::get_default_signatures;

    let sigs = get_default_signatures();
    let mp3_sig = sigs.iter().find(|s| s.extension == "mp3").unwrap();
    let mp4_sig = sigs.iter().find(|s| s.extension == "mp4").unwrap();

    // 1. MP3 truncated: header is valid, but frame data is cut off
    let mut mock_mp3 = vec![
        0x49, 0x44, 0x33, // "ID3"
        0x03, 0x00,       // Version 2.3
        0x00,             // No flags
        0x00, 0x00, 0x00, 0x14, // Size = 20
    ];
    mock_mp3.extend_from_slice(&[0; 20]);
    // First frame starts but is cut off mid-way
    mock_mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    mock_mp3.extend_from_slice(&[0; 100]); // cut off!

    let (size, truncated) = mp3_sig.parse_size_detail(&mock_mp3);
    assert_eq!(size, None);
    assert!(truncated);

    // 2. MP3 completely invalid (not an MP3 frame or header): should return (None, false)
    let invalid_data = vec![0xAA; 500];
    let (size, truncated) = mp3_sig.parse_size_detail(&invalid_data);
    assert_eq!(size, None);
    assert!(!truncated);

    // 3. MP4 truncated
    let mut mock_mp4 = vec![0u8; 16];
    BigEndian::write_u32(&mut mock_mp4[0..4], 16);
    mock_mp4[4..8].copy_from_slice(b"ftyp");
    let box2_offset = mock_mp4.len();
    mock_mp4.extend_from_slice(&[0; 50]); // box claims to be 200, only 50 provided
    BigEndian::write_u32(&mut mock_mp4[box2_offset..box2_offset + 4], 200);
    mock_mp4[box2_offset + 4..box2_offset + 8].copy_from_slice(b"mdat");

    let (size, truncated) = mp4_sig.parse_size_detail(&mock_mp4);
    assert_eq!(size, None);
    assert!(truncated);

    // 4. MP4 completely invalid (bad boxes): should return (None, false)
    let invalid_mp4 = vec![0x00, 0x00, 0x00, 0x10, 0xFF, 0xFF, 0xFF, 0xFF]; // Box type FFFFFFFF is invalid
    let (size, truncated) = mp4_sig.parse_size_detail(&invalid_mp4);
    assert_eq!(size, None);
    assert!(!truncated);

    // 5. JPEG truncated (valid headers, hits SOS but buffer ends)
    let jpeg_sig = sigs.iter().find(|s| s.extension == "jpg").unwrap();
    let mut mock_jpeg = vec![
        0xFF, 0xD8,             // SOI
        0xFF, 0xE0, 0x00, 0x10, // APP0, length 16
        0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00,
        0xFF, 0xDA              // SOS
    ];
    let (size, truncated) = jpeg_sig.parse_size_detail(&mock_jpeg);
    assert_eq!(size, None);
    assert!(truncated);

    // 6. JPEG completely invalid
    let invalid_jpeg = vec![0xFF, 0xD8, 0xFF, 0x00, 0x00, 0x00];
    let (size, truncated) = jpeg_sig.parse_size_detail(&invalid_jpeg);
    assert_eq!(size, None);
    assert!(!truncated);

    // 7. JPEG complete (has SOI, APP0, EOI)
    mock_jpeg.extend_from_slice(&[0; 100]); // some compressed data
    mock_jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI
    // But wait! parse_jpeg_size_detail stops at SOS and returns (None, true) because it delegates to footer walk
    // So even if it contains EOI, parse_jpeg_size_detail returns (None, true) because it finds SOS (FF DA) first.
    // Let's verify that behavior!
    let (size, truncated) = jpeg_sig.parse_size_detail(&mock_jpeg);
    assert_eq!(size, None);
    assert!(truncated);
}

#[test]
fn test_size_parsing_overflow_protection() {
    let sigs = get_default_signatures();
    let mp4_sig = sigs.iter().find(|s| s.extension == "mp4").unwrap();

    // Box size 1 (implies 64-bit box size), but size is u64::MAX
    let mut mock_mp4 = vec![0u8; 16];
    BigEndian::write_u32(&mut mock_mp4[0..4], 1); // 64-bit size follows
    mock_mp4[4..8].copy_from_slice(b"ftyp");
    BigEndian::write_u64(&mut mock_mp4[8..16], u64::MAX);

    let (size, truncated) = mp4_sig.parse_size_detail(&mock_mp4);
    assert_eq!(size, None);
    assert!(truncated);
}
