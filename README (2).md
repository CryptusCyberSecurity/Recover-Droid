# Recover Droid (`recover-droid`)

`recover-droid` is a professional-grade, high-performance, open-source command-line interface (CLI) data recovery utility written in Rust. It specializes in digital forensics-compliant recovery of deleted files from USB flash drives, SD cards, hard disks (HDDs), and solid-state drives (SSDs).

> [!CAUTION]
> **Safety Warning:** Data recovery operations must always be performed in a **read-only** manner on the source storage media. Writing or modifying data on the same drive you are recovering from can overwrite deleted blocks and destroy recoverable data permanently. The `recover-droid` tool opens target devices strictly in read-only mode and never performs filesystem repairs. Always write recovered files to a separate destination disk.

---

## Features

- **Read-Only Engine**: Guarantees forensic integrity by never writing back to the source media.
- **Filesystem-based Recovery**: Traversing filesystem structures to recover deleted files, directory structures, and file chains.
  - Phase 1: FAT16, FAT32 (Full support, directory parsing, Long Filenames, cluster chains).
  - Phase 2: exFAT (Full support).
- **Signature-based Carving**: Carver module to scan raw disk blocks and reconstruct files using header/footer signatures for 22 different formats (JPEG, PNG, PDF, ZIP, SQLite, EXE, etc.).
- **Parallel Scanning**: Uses multithreading (via `rayon`) to split the drive into chunks and scan them concurrently, maximizing disk read throughput.
- **Real-Time Progress**: Rich feedback bar detailing current sector, percentage, scanning speed, elapsed time, ETA, and recovered counts.
- **Reporting**: Generates structured forensic reports in JSON format.

---

## Supported Filesystems

- **FAT16 & FAT32**:
  - Full BIOS Parameter Block (BPB) parsing.
  - Traverse directories (Short Names + Long Filenames / LFN).
  - Cluster chain validation & reconstruction.
  - Detects partial vs. full overwrites.
- **exFAT**:
  - Traverse directory entries.
  - Recover files and folder trees.

---

## Supported File Carving Formats

The carver supports 22 file formats categorized into:
- **Images**: JPEG, PNG, GIF, BMP, WEBP
- **Documents**: PDF, ZIP, DOCX, XLSX, PPTX
- **Archives**: RAR, 7Z
- **Audio/Video**: MP3, WAV, FLAC, MP4, MOV, AVI, MKV
- **System/Database**: SQLite, ELF, EXE

Users can also load custom signature definitions dynamically via a JSON file.

---

## Installation

### Prerequisites
- [Rust toolchain](https://rustup.rs/) (Stable, Edition 2024)

### Building from Source
Clone the repository and build the binary in release mode:
```bash
cargo build --release
```
The compiled binary will be located at `target/release/recover-droid.exe` (on Windows) or `target/release/recover-droid` (on Unix-like systems).

---

## Command Reference

### 1. List Storage Devices
List all physical storage devices, logical volumes, and SD/USB drives connected to the machine.
```bash
recover-droid list
```

### 2. View Device Information
Show partition layouts, filesystem details, cluster sizing, serials, and geometry.
```bash
recover-droid info <device>
# Example (Windows): recover-droid info \\.\PhysicalDrive1
# Example (Linux):   recover-droid info /dev/sdb
```

### 3. Scan for Deleted Files
Scan the filesystem structures on a partition to detect deleted directories and files.
```bash
recover-droid scan <device>
```

### 4. Recover Specific File
Recover a specific file found during the scan by its ID and save it to an output directory.
```bash
recover-droid recover <device> <id> <output_dir>
```

### 5. Recover All Files
Batch recover all recoverable files found on the partition to the target folder.
```bash
recover-droid recover-all <device> <output_dir>
```

### 6. Perform Signature-based Carving
Search the raw disk sector-by-sector for file headers and footers to extract lost files, even if the filesystem metadata is completely wiped.
```bash
recover-droid carve <device> <output_dir>
```

### 7. Verify Integrity
Validate the integrity of a recovered file (e.g., verifying image headers, parsing container structures).
```bash
recover-droid verify <file>
```

### 8. Generate Forensic Report
Print the metadata and summary of the last recovery operation in JSON format.
```bash
recover-droid report
```
