# Recover Droid User Manual: A Simple Guide to Data Recovery

Welcome to the beginner-friendly user guide for **Recover Droid**! Whether you are a digital forensics investigator or someone who just accidentally deleted an important file from a USB drive, this guide will help you get your data back safely.

---

## 1. How Data Recovery Works (The "Book" Analogy)

To understand how Recover Droid works, imagine your computer's storage drive (like a USB stick or hard drive) is a **large recipe book**:
* **The Table of Contents (Filesystem Index)**: This lists where each recipe (file) is located on which page.
* **The Pages (Raw Sectors)**: This is where the actual recipes (file contents) are written.

When you delete a file on your computer:
1. The computer **does not** erase the actual page contents. 
2. It simply crosses out the file's entry in the **Table of Contents** and marks that page as "free space" that can be written over later.
3. As long as you do not write new files to the drive, **the original page contents are still there and can be rescued!**

Recover Droid uses two ways to find crossed-out files:
* **Filesystem Scan (`scan`)**: Reads the crossed-out entries in the Table of Contents to instantly restore files with their original names and dates intact.
* **Signature Carving (`carve`)**: If the Table of Contents is completely destroyed (e.g., the drive was formatted), the tool scans the pages one-by-one to find files by their unique visual signatures (like the "magic bytes" that define a PNG picture).

---

## 2. Quick-Start Guide (Get Your Files Back in 3 Steps)

Recover Droid runs as a command-line tool. Follow these steps to recover data from a USB flash drive or partition.

> [!IMPORTANT]
> **Run as Administrator**: Bypassing the operating system to read raw drive blocks requires elevated permissions. Under Windows, search for "Command Prompt" or "PowerShell", right-click it, and select **"Run as Administrator"**.

### Step 1: List connected drives
Type the following command and press Enter:
```bash
recover-droid list
```
Look for your target drive path in the list (for example, `\\.\E:` on Windows or `/dev/sdb1` on Linux).

### Step 2: Scan for deleted files
Type the scan command for your drive:
```bash
recover-droid scan \\.\E:
```
This scans the drive's index structures and prints a list of recently deleted files along with a unique **ID** number (e.g., ID `12`).

### Step 3: Recover your file
To save the deleted file to a safe directory (for example, a folder named `C:\Recovered`), type:
```bash
recover-droid recover \\.\E: 12 C:\Recovered
```
*(The tool will automatically calculate a cryptographic hash of the recovered file to verify its integrity).*

---

## 3. Which Recovery Command Do I Need?

Choose the command that matches your situation:

* **"I accidentally deleted a file recently (and haven't formatted the drive)"**
  * **Use**: `recover-droid scan` followed by `recover-droid recover`.
  * **Why**: It is extremely fast and restores the original file names, dates, and folder structures.
* **"My drive partition is corrupted, says 'RAW', or has been formatted"**
  * **Use**: `recover-droid carve`.
  * **Why**: It bypasses the corrupted index and scans raw disk sectors one-by-one for file contents. (Note: filenames are generated automatically).
* **"I prefer a graphical screen instead of typing commands"**
  * **Use**: `recover-droid tui`.
  * **Why**: It opens an interactive terminal application where you can use arrow keys to navigate drives and preview files in hex before recovering.

---

## 4. Command Guide & Reference

Here is a complete list of all 10 commands available in Recover Droid, explained in plain English.

### `list`
* **What it does**: Searches your computer for all active hard drives, USB sticks, and SD cards.
* **Syntax**: `recover-droid list`
* **Output**:
  ```text
  Path          Size        Type
  ====================================
  PhysDrive0    476.94 GB   Physical
  C:            475.90 GB   Logical
  ```

### `info`
* **What it does**: Displays the technical structure of a drive (such as sector sizes and filesystem types like FAT32 or exFAT).
* **Syntax**: `recover-droid info <drive_path>`
* **Example**: `recover-droid info \\.\E:`

### `scan`
* **What it does**: Looks through the drive index to find deleted files.
* **Syntax**: `recover-droid scan <drive_path>`
* **Example**: `recover-droid scan \\.\E:`

### `recover`
* **What it does**: Copies a specific deleted file (found in a previous `scan` step) to a safe directory.
* **Syntax**: `recover-droid recover <drive_path> <file_id> <output_folder>`
* **Example**: `recover-droid recover \\.\E: 12 C:\Recovered`
* **Forensic Hash**: Automatically prints a secure fingerprint (SHA-256 hash) to verify the file was recovered without alteration.

### `recover-all`
* **What it does**: Attempts to recover every deleted file found in the last scan in one go.
* **Syntax**: `recover-droid recover-all <drive_path> <output_folder>`
* **Forensic Hash**: Prints secure fingerprints (SHA-256 hashes) in bulk for all recovered files.

### `carve`
* **What it does**: Performs a deep scan of raw sectors to reconstruct files when the index is missing.
* **Syntax**: `recover-droid carve <drive_path> <output_folder>`
* **Example**: `recover-droid carve \\.\E: C:\Recovered`
* **Forensic Hash**: Automatically calculates and logs the SHA-256 hash for every carved file.

### `verify`
* **What it does**: Double-checks if a recovered file is healthy (not corrupted) by checking its internal structure.
* **Syntax**: `recover-droid verify <file_path>`
* **Example**: `recover-droid verify C:\Recovered\photo.png`

### `report`
* **What it does**: Prints the session log and summary report of your last recovery operation.
* **Syntax**: `recover-droid report`

### `tui`
* **What it does**: Launches the visual Dashboard interface. Use your keyboard's arrow keys to browse, scan, and preview files.
* **Syntax**: `recover-droid tui`

### `acquire-android`
* **What it does**: Copies system logs, media, contacts, text messages, and call logs from a connected Android phone to your computer.
* **Syntax**: `recover-droid acquire-android --output <folder>`
* **Example**: `recover-droid acquire-android --output C:\Backup`
* **Forensic Hash**: Computes and logs security hashes (MD5, SHA-1, SHA-256, SHA-512) for all acquired phone files in a manifest report.

---

## 5. Frequently Asked Questions (FAQ)

### Q: Why does the program fail with "Permission denied"?
**A**: To read raw sectors, Recover Droid needs administrative privileges. Make sure you run your terminal/Command Prompt **as Administrator** (right-click the app icon to find this option).

### Q: Why does my recovered file contain only empty space or zeroes?
**A**: If you are recovering files from a modern **Solid State Drive (SSD)**, a feature called **TRIM** automatically wipes deleted sectors to optimize drive performance. Once TRIM runs, the data is gone forever. Recovery is most successful on USB sticks, SD cards, and traditional mechanical Hard Disk Drives (HDDs).

### Q: Why are the original names missing for carved files?
**A**: In raw signature carving (`carve`), the drive's index (Table of Contents) is gone. Without the index, there is no record of the filename or folders. Recover Droid names them automatically (e.g., `carved_file_1.png`) based on their file format.

---

## 6. How Android Phone Acquisition Works

If you use the `acquire-android` command to extract data from a mobile phone, here is what happens behind the scenes:

```text
  [1] Connect Phone via USB
              │
              ▼
  [2] Dump Device Info
              │
              ▼
  [3] Copy Shared Files (Photos)
              │
              ▼
  [4] Deploy Temp Agent App
              │
              ▼
  [5] Extract SMS, Contacts, Logs
              │
              ▼
  [6] Uninstall App & Sign Hashes
```

### Why do we need a temporary Agent App?
Android phones block computer programs from directly reading sensitive personal databases (like text messages and call logs) to protect user privacy. To get this data, a native Android App must request standard permissions (like `READ_SMS`). Recover Droid temporarily installs a tiny agent app, grants it permission to read the databases, saves the data to a file, copies it back to the computer, and then cleanly uninstalls the agent app.

---

## 7. Why is Recover Droid "Forensic Grade"?

In legal and professional settings, data recovery must follow strict rules to ensure the evidence remains intact and tamper-proof. Recover Droid is designed from the ground up to meet these **forensic-grade standards**:

### A. Strict Read-Only Guarantee (evidence preservation)
Recover Droid opens files, drives, and partitions using direct, low-level OS read commands and **never writes a single byte of data back to the source drive**. This ensures the original drive remains 100% unaltered.

### B. Secure Fingerprints (cryptographic hashing)
Every recovered file and acquired phone database gets a unique **cryptographic hash fingerprint** (like SHA-256 or MD5). This fingerprint acts as a digital seal. If a file is altered even by a single letter, its fingerprint will change completely. Forensic investigators use these hashes to prove in court that the recovered files are exact, untampered copies of the originals.

### C. Fault-Tolerant Scanning (damaged drive protection)
Failing or physically damaged drives often crash standard computers when they hit "bad sectors" (unreadable parts of the drive). Recover Droid has a built-in fallback engine. If a sector is unreadable, the tool automatically switches to a sector-by-sector read, logs the error, fills the unreadable parts with empty space (zeroes), and continues scanning without crashing, extracting the maximum possible data.

### D. Sandbox Path Traversal Protection (investigator safety)
Malicious software or corrupted drives can sometimes contain fake files with directory-climbing paths (e.g., `../../../../Windows/System32/cmd.exe`) designed to overwrite system files on the investigator's computer during extraction. Recover Droid strips out all directory climbing elements from recovered filenames, making sure files are only written safely inside your designated output folder.
