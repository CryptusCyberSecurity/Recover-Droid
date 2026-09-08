# Recover Droid: Professional Engineering & Feature Improvement Roadmap

As a data recovery and digital forensics utility, **Recover Droid** is highly capable. However, to elevate it to a gold-standard industry tool competing with corporate utilities like FTK Imager, Autopsy, or Cellebrite, several enhancements can be made.

Below is a detailed analysis of areas that can be improved, categorized by **Forensic Integrity**, **Filesystem Coverage**, **Carving Science**, and **Android Capabilities**.

---

## 1. Forensic Integrity & Legal Chain of Custody

### A. Integrated Software Write-Blocking
* **The Problem**: Plugging a target USB drive directly into Windows can alter the evidence. Windows automatically writes hidden system folders (`System Volume Information`, `$RECYCLE.BIN`) or updates access times, which compromises forensic integrity in court.
* **The Improvement**: 
  * Add a `block` command to toggle Windows Registry write-protection policies (`HKLM\System\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect = 1`).
  * Implement checks on startup to verify if the OS has write-protection active for the target physical drive.

### B. Standardized Forensic Formats (E01 / AFF4)
* **The Problem**: Currently, `Recover Droid` scans raw physical drives directly. Forensics standards require making a bit-stream image copy of the disk first, then analyzing the image.
* **The Improvement**:
  * Add support for reading and writing **Expert Witness Format (E01)** or **Advanced Forensic Format (AFF4)** images, including embedded metadata (case number, investigator name, notes) and internal block-level checksum validation.

---

## 2. Expanded Filesystem Support

Currently, the tool supports **FAT16** and **FAT32**, with basic **exFAT** parsing. The majority of modern systems do not use FAT.

| Filesystem | Platform | Status | Improvement Needed |
| :--- | :--- | :--- | :--- |
| **NTFS** | Windows | ❌ Not Supported | Parse Master File Table (`$MFT`), `$LOGFILE` journaling, and Alternate Data Streams (ADS). |
| **APFS / HFS+** | macOS | ❌ Not Supported | Parse Catalog Files, B-Trees, and Extent Overflow Files. |
| **Ext4** | Linux / Android | ❌ Not Supported | Parse Superblocks, Inode Tables, Extent Trees, and Block Group Descriptors. |

---

## 3. "Smart Carving" & Fragmentation Science

### A. Non-Contiguous File Carving (Bifragment / Smart Carving)
* **The Problem**: The current signature carver assumes files are written in one sequential block from header to footer. If a file is fragmented (split across different parts of the drive), the carved file will contain junk data and be corrupt.
* **The Improvement**:
  * Implement **validation-guided carving** (e.g., checking JPEG structure during carving to detect if a cluster belongs to the image or is a fragment gap).
  * Use entropy analysis to detect when file content suddenly changes (indicating a fragment transition).

### B. Custom Signature Builder GUI
* **The Problem**: Adding custom file signatures requires manually writing JSON files with hex codes.
* **The Improvement**:
  * Create a simple interactive CLI wizard or TUI tool where users can paste a sample file, and the program automatically extracts the header/footer magic bytes and formats the JSON structure.

---

## 4. Advanced Android Data Acquisition

### A. Physical Partition Dump (Rooted/Exploit Access)
* **The Problem**: The tool currently performs *Logical Acquisition* (pulling files and app DBs). It cannot recover deleted messages or files because logical filesystems hide deleted database rows.
* **The Improvement**:
  * Add a **Physical Dump** command for rooted Android devices to stream raw block partitions (e.g., `/dev/block/bootdevice/by-name/userdata`) directly to the computer as a raw `.img` file.
  * Integrate exploit pathways (like MTK Bypass or EDL/Emergency Download Mode) to pull raw memory dumps from unbootable phones.

### B. Automated SQLite Deleted Row Parsing
* **The Problem**: When messages are deleted in Android apps, they are removed from the active view but remain in the SQLite database's "freeblocks" until vacuumed.
* **The Improvement**:
  * Add an automated SQLite database parser that scans extracted `.db` files (like SMS, WhatsApp, and call histories) for deleted records hidden in database slack spaces.

---

## 5. UI/UX & Output Enhancements

### A. HTML / PDF Forensic Reports
* **The Problem**: The session reports are currently stored in JSON, which is difficult for non-technical clients, lawyers, or investigators to present.
* **The Improvement**:
  * Add a `report generate --format html` command that compiles recovery stats, files found, verified files, and SHA-256 hashes into a polished, printable HTML dashboard with signature lines for chain of custody.

### B. Real-Time Thumbnail Preview in TUI
* **The Problem**: The TUI hex preview is excellent, but investigators need to visually inspect images.
* **The Improvement**:
  * Use Braille patterns or unicode half-blocks to render low-resolution grayscale thumbnails of carved images directly inside the terminal interface before extraction.
