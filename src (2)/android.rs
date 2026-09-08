use crate::errors::{RecoveryError, Result};
use crate::utils::compute_hash;
use log::{info, warn, error};
use std::fs::{self, File};
use std::io::{self, Write, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::SystemTime;

/// Represents a connected Android device.
#[derive(Debug, Clone)]
pub struct AndroidDevice {
    pub serial: String,
    pub state: String,
}

/// Checks if `adb` is available on the system.
fn check_adb_available() -> Result<()> {
    match Command::new("adb").arg("version").output() {
        Ok(output) if output.status.success() => Ok(()),
        _ => Err(RecoveryError::General(
            "ADB (Android Debug Bridge) executable not found in your system PATH.\n\
             Please install ADB to use this feature.\n\n\
             Installation Guide:\n\
             - On Debian/Ubuntu: sudo apt update && sudo apt install -y adb\n\
             - On macOS (Homebrew): brew install android-platform-tools\n\
             - On Windows: Download the SDK Platform-Tools and add its folder to your system PATH."
                .to_string(),
        )),
    }
}

/// Lists all connected Android devices via `adb devices`.
pub fn list_android_devices() -> Result<Vec<AndroidDevice>> {
    check_adb_available()?;

    let output = Command::new("adb")
        .arg("devices")
        .output()
        .map_err(|e| RecoveryError::General(format!("Failed to run adb: {}", e)))?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(RecoveryError::General(format!("adb devices failed: {}", err_msg.trim())));
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();

    for line in stdout_str.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("List of devices attached") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            devices.push(AndroidDevice {
                serial: parts[0].to_string(),
                state: parts[1].to_string(),
            });
        }
    }

    Ok(devices)
}

/// Helper to execute an adb shell command on a specific device and return the trimmed output.
fn adb_shell_getprop(serial: &str, property: &str) -> String {
    let output = Command::new("adb")
        .args(["-s", serial, "shell", "getprop", property])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => "Unknown".to_string(),
    }
}

/// Runs logical data acquisition for a selected device.
pub fn acquire_device(
    target_serial: Option<&str>,
    output_dir: &Path,
    include_backup: bool,
    hash_algorithms: &str,
) -> Result<()> {
    info!("Starting Android Acquisition module...");

    // Validate requested hash algorithms
    let hash_algs: Vec<&str> = hash_algorithms
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if hash_algs.is_empty() {
        return Err(RecoveryError::InvalidArgument("No hash algorithms specified.".to_string()));
    }

    for alg in &hash_algs {
        match alg.to_lowercase().as_str() {
            "md5" | "sha1" | "sha256" | "sha512" => {}
            other => return Err(RecoveryError::InvalidArgument(format!(
                "Unsupported hash algorithm '{}'. Supported: md5, sha1, sha256, sha512",
                other
            ))),
        }
    }

    // 1. Detect and choose device
    let devices = list_android_devices()?;
    if devices.is_empty() {
        return Err(RecoveryError::DeviceNotFound(
            "No connected Android devices found.\n\
             Please connect your device via USB, enable USB Debugging in Developer Options, \n\
             and authorize this computer."
                .to_string(),
        ));
    }

    let selected_device = match target_serial {
        Some(serial) => {
            devices.iter().find(|d| d.serial == serial).ok_or_else(|| {
                RecoveryError::InvalidArgument(format!(
                    "Device with serial '{}' is not connected. Connected devices: {:?}",
                    serial, devices
                ))
            })?
        }
        None => {
            if devices.len() > 1 {
                println!("Multiple Android devices detected:");
                for d in &devices {
                    println!("  - Serial: {} ({})", d.serial, d.state);
                }
                return Err(RecoveryError::InvalidArgument(
                    "Please specify target device serial using the -d/--device option.".to_string(),
                ));
            }
            &devices[0]
        }
    };

    if selected_device.state == "unauthorized" {
        return Err(RecoveryError::PermissionDenied(
            format!("Device '{}' is unauthorized.\n\
                     Please check your device's screen and accept the 'Allow USB debugging' prompt.", 
                     selected_device.serial)
        ));
    }

    println!("[*] Selected Android Device: {} (State: {})", selected_device.serial, selected_device.state);

    // 2. Prepare Directory structure
    let meta_dir = output_dir.join("metadata");
    let shared_dir = output_dir.join("shared_storage");

    fs::create_dir_all(&meta_dir).map_err(|e| {
        RecoveryError::General(format!("Failed to create metadata folder: {}", e))
    })?;
    fs::create_dir_all(&shared_dir).map_err(|e| {
        RecoveryError::General(format!("Failed to create shared storage folder: {}", e))
    })?;

    // 3. Extract Device Properties (Metadata)
    println!("[*] Extracting device properties...");
    let manufacturer = adb_shell_getprop(&selected_device.serial, "ro.product.manufacturer");
    let model = adb_shell_getprop(&selected_device.serial, "ro.product.model");
    let release = adb_shell_getprop(&selected_device.serial, "ro.build.version.release");
    let patch = adb_shell_getprop(&selected_device.serial, "ro.build.version.security_patch");
    let fingerprint = adb_shell_getprop(&selected_device.serial, "ro.build.fingerprint");
    let serialno = adb_shell_getprop(&selected_device.serial, "ro.serialno");

    let device_info_json = serde_json::json!({
        "acquisition_timestamp": SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
        "device_serial": selected_device.serial,
        "device_state": selected_device.state,
        "manufacturer": manufacturer,
        "model": model,
        "android_version": release,
        "security_patch": patch,
        "build_fingerprint": fingerprint,
        "reported_serial": serialno
    });

    let info_path = meta_dir.join("device_info.json");
    let mut info_file = File::create(&info_path)?;
    info_file.write_all(serde_json::to_string_pretty(&device_info_json).unwrap().as_bytes())?;
    println!("  - Wrote device_info.json");

    // 4. Dump Package List
    println!("[*] Extracting list of installed packages...");
    let pkgs_output = Command::new("adb")
        .args(["-s", &selected_device.serial, "shell", "pm", "list", "packages", "-f"])
        .output();
    let pkg_path = meta_dir.join("installed_packages.txt");
    match pkgs_output {
        Ok(out) if out.status.success() => {
            let mut file = File::create(&pkg_path)?;
            file.write_all(&out.stdout)?;
            println!("  - Wrote installed_packages.txt");
        }
        _ => warn!("Could not extract packages list."),
    }

    // 5. Dump Filesystem & Mount points
    println!("[*] Extracting system filesystem layouts...");
    let df_output = Command::new("adb")
        .args(["-s", &selected_device.serial, "shell", "df", "-h"])
        .output();
    let df_path = meta_dir.join("partition_layout.txt");
    if let Ok(out) = df_output {
        let _ = File::create(&df_path).and_then(|mut f| f.write_all(&out.stdout));
        println!("  - Wrote partition_layout.txt");
    }

    let mount_output = Command::new("adb")
        .args(["-s", &selected_device.serial, "shell", "mount"])
        .output();
    let mount_path = meta_dir.join("filesystem_mounts.txt");
    if let Ok(out) = mount_output {
        let _ = File::create(&mount_path).and_then(|mut f| f.write_all(&out.stdout));
        println!("  - Wrote filesystem_mounts.txt");
    }

    // 6. Pull Shared Storage (/sdcard/)
    println!("\n[*] Initiating logical download of shared storage (/sdcard/)...");
    println!("------------------------------------------------------------");
    let mut pull_child = Command::new("adb")
        .args(["-s", &selected_device.serial, "pull", "/sdcard/", shared_dir.to_str().unwrap()])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| RecoveryError::General(format!("Failed to start adb pull: {}", e)))?;

    let pull_status = pull_child.wait()?;
    println!("------------------------------------------------------------");
    if pull_status.success() {
        println!("[+] Shared storage copied successfully.");
    } else {
        warn!("[!] adb pull exited with warnings/errors. Some system files might have been inaccessible, but most user files should be recovered. Inspect target directory.");
    }

    // 6b. Deploy and run Forensic Agent APK to extract SMS, Contacts, and Call Logs
    let _ = acquire_via_agent(&selected_device.serial, output_dir);

    // 7. Optional App Backup
    let mut backup_created = false;
    let backup_path = output_dir.join("backup.ab");
    if include_backup {
        println!("\n[*] INITIATING LOGICAL APPLICATION BACKUP...");
        println!("[!] PLEASE UNLOCK YOUR PHONE NOW AND CONFIRM THE BACKUP REQUEST ON THE SCREEN.");
        println!("------------------------------------------------------------");
        let mut backup_child = Command::new("adb")
            .args([
                "-s",
                &selected_device.serial,
                "backup",
                "-apk",
                "-shared",
                "-all",
                "-f",
                backup_path.to_str().unwrap(),
            ])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| RecoveryError::General(format!("Failed to start adb backup: {}", e)))?;

        let backup_status = backup_child.wait()?;
        println!("------------------------------------------------------------");
        if backup_status.success() {
            println!("[+] Application data backup file created successfully.");
            backup_created = true;
        } else {
            error!("[-] Application data backup failed or was rejected on the screen.");
        }
    }

    // 8. Generate Forensic Manifest File
    println!("\n[*] Calculating integrity checksums and generating forensic manifest...");
    let manifest_path = output_dir.join("acquisition_manifest.txt");
    let mut manifest_file = File::create(&manifest_path)?;

    writeln!(manifest_file, "RECOVER DROID FORENSIC LOGICAL ACQUISITION MANIFEST")?;
    writeln!(manifest_file, "================================================")?;
    writeln!(manifest_file, "Timestamp:        {:?}", SystemTime::now())?;
    writeln!(manifest_file, "Device Serial:    {}", selected_device.serial)?;
    writeln!(manifest_file, "Manufacturer:     {}", manufacturer)?;
    writeln!(manifest_file, "Model:            {}", model)?;
    writeln!(manifest_file, "Android Version:  {}", release)?;
    writeln!(manifest_file, "================================================\n")?;

    writeln!(manifest_file, "FILE INTEGRITY HASHES")?;
    writeln!(manifest_file, "------------------------------------------------")?;

    let agent_sms_path = output_dir.join("metadata/agent_dump/sms_dump.json");
    let agent_contacts_path = output_dir.join("metadata/agent_dump/contacts_dump.json");
    let agent_calllogs_path = output_dir.join("metadata/agent_dump/calllogs_dump.json");

    let files_to_hash = [
        ("metadata/device_info.json", info_path),
        ("metadata/installed_packages.txt", pkg_path),
        ("metadata/partition_layout.txt", df_path),
        ("metadata/filesystem_mounts.txt", mount_path),
        ("metadata/agent_dump/sms_dump.json", agent_sms_path),
        ("metadata/agent_dump/contacts_dump.json", agent_contacts_path),
        ("metadata/agent_dump/calllogs_dump.json", agent_calllogs_path),
    ];

    for (rel, abs) in &files_to_hash {
        if abs.exists() {
            for alg in &hash_algs {
                if let Ok(hash) = compute_hash(abs, alg) {
                    let alg_upper = alg.to_uppercase();
                    writeln!(manifest_file, "{:<8} {}  {}", alg_upper, hash, rel)?;
                    println!("  {}({}) = {}", alg_upper, rel, hash);
                }
            }
        }
    }

    if backup_created && backup_path.exists() {
        for alg in &hash_algs {
            if let Ok(hash) = compute_hash(&backup_path, alg) {
                let alg_upper = alg.to_uppercase();
                writeln!(manifest_file, "{:<8} {}  backup.ab", alg_upper, hash)?;
                println!("  {}(backup.ab) = {}", alg_upper, hash);
            }
        }
    }

    println!("[+] Forensic manifest written to: {}", manifest_path.to_string_lossy());
    println!("\n[+] ACQUISITION COMPLETE. Data stored successfully in: {}", output_dir.to_string_lossy());

    Ok(())
}

/// Helper to install agent APK, grant permissions, launch it to dump SMS/contacts/calllogs,
/// pull the dumped data, and clean up.
fn acquire_via_agent(serial: &str, output_dir: &Path) -> Result<()> {
    println!("\n[*] DEPLOYING FORENSIC AGENT FOR SENSITIVE DATA ACQUISITION...");
    
    // 1. Write the embedded APK bytes to a temporary location
    let apk_bytes = include_bytes!("../agent/bin/RecoverAgent.apk");
    let temp_apk_path = output_dir.join("metadata/RecoverAgent.apk");
    {
        let mut file = File::create(&temp_apk_path)
            .map_err(|e| RecoveryError::General(format!("Failed to write agent APK: {}", e)))?;
        file.write_all(apk_bytes)?;
    }
    
    // 2. Install the APK
    println!("  - Installing forensic agent on device...");
    let install_output = Command::new("adb")
        .args(["-s", serial, "install", "-r", temp_apk_path.to_str().unwrap()])
        .output()
        .map_err(|e| RecoveryError::General(format!("Failed to install agent: {}", e)))?;
        
    if !install_output.status.success() {
        let err = String::from_utf8_lossy(&install_output.stderr);
        warn!("Could not install agent: {}. Skipping agent-based collection.", err.trim());
        let _ = fs::remove_file(temp_apk_path);
        return Ok(());
    }
    
    // 3. Grant Permissions
    println!("  - Granting permissions (READ_SMS, READ_CONTACTS, READ_CALL_LOG)...");
    let permissions = [
        "android.permission.READ_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
    ];
    for perm in &permissions {
        let _ = Command::new("adb")
            .args(["-s", serial, "shell", "pm", "grant", "com.recover.agent", perm])
            .output();
    }
    
    // 4. Start MainActivity
    println!("  - Launching agent MainActivity...");
    let start_output = Command::new("adb")
        .args(["-s", serial, "shell", "am", "start", "-n", "com.recover.agent/.MainActivity"])
        .output();
        
    if let Err(e) = start_output {
        warn!("Failed to start agent MainActivity: {}. Cleaning up.", e);
        let _ = Command::new("adb").args(["-s", serial, "uninstall", "com.recover.agent"]).output();
        let _ = fs::remove_file(temp_apk_path);
        return Ok(());
    }
    
    // 5. Poll for dumped files (timeout after 10 seconds)
    println!("  - Waiting for agent data dump to complete...");
    let mut success = false;
    let agent_files_dir = output_dir.join("metadata/agent_dump");
    let _ = fs::create_dir_all(&agent_files_dir);
    
    for _attempt in 1..=20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        // Check if files exist by running a shell ls command
        let ls_output = Command::new("adb")
            .args(["-s", serial, "shell", "ls", "/sdcard/Android/data/com.recover.agent/files/"])
            .output();
            
        if let Ok(out) = ls_output {
            let files = String::from_utf8_lossy(&out.stdout);
            if files.contains("sms_dump.json") && files.contains("contacts_dump.json") && files.contains("calllogs_dump.json") {
                success = true;
                break;
            }
        }
    }
    
    if success {
        println!("  - Extracting agent dump files...");
        // Pull files
        let pull_output = Command::new("adb")
            .args(["-s", serial, "pull", "/sdcard/Android/data/com.recover.agent/files/sms_dump.json", agent_files_dir.join("sms_dump.json").to_str().unwrap()])
            .output();
        let _ = Command::new("adb")
            .args(["-s", serial, "pull", "/sdcard/Android/data/com.recover.agent/files/contacts_dump.json", agent_files_dir.join("contacts_dump.json").to_str().unwrap()])
            .output();
        let _ = Command::new("adb")
            .args(["-s", serial, "pull", "/sdcard/Android/data/com.recover.agent/files/calllogs_dump.json", agent_files_dir.join("calllogs_dump.json").to_str().unwrap()])
            .output();
            
        match pull_output {
            Ok(out) if out.status.success() => {
                println!("[+] Successfully acquired SMS, Contacts, and Call Logs via agent.");
            }
            Ok(out) => {
                warn!("Failed to pull agent files: {}", String::from_utf8_lossy(&out.stderr).trim());
            }
            Err(e) => {
                warn!("Failed to pull agent files: {}", e);
            }
        }
    } else {
        warn!("[-] Agent data dump timed out. Private databases could not be acquired.");
    }
    
    // 6. Cleanup APK and uninstall agent
    println!("  - Uninstalling forensic agent from device...");
    let _ = Command::new("adb").args(["-s", serial, "uninstall", "com.recover.agent"]).output();
    let _ = fs::remove_file(temp_apk_path);
    
    Ok(())
}
