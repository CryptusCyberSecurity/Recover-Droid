use clap::Parser;
use recover_cli::cli::{Cli, Commands};
use recover_cli::device::{self, Device};
use recover_cli::errors::{RecoveryError, Result};
use recover_cli::filesystem::{detect_filesystem, DeletedFile, RecoveryStatus};
use recover_cli::report::{RecoveryReport, RecoverySession};
use recover_cli::signatures::{get_default_signatures, self};
use recover_cli::utils;
use recover_cli::recovery;
use recover_cli::scanner;
use std::path::Path;
use std::time::Instant;
use log::warn;

fn run_app() -> Result<()> {
    let args = Cli::parse();

    // Print header banner for all commands except Report to keep output clean
    match &args.command {
        Commands::Report { .. } => {}
        _ => {
            let logo = r#"
██████╗ ███████╗ ██████╗  ██████╗ ██╗   ██╗███████╗██████╗ ██████╗ 
██╔══██╗██╔════╝██╔════╝ ██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔══██╗
██████╔╝█████╗  ██║      ██║   ██║██║   ██║█████╗  ██████╔╝██████╔╝
██╔══██╗██╔══╝  ██║      ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══██╗
██║  ██║███████╗╚██████╗ ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝"#;
            println!("\x1b[36m{}\x1b[0m", logo);
            println!("  Recover Droid - Professional Data Recovery & Forensics Tool");
            println!("=================================================================\n");
        }
    }

    match args.command {
        Commands::List => {
            println!("Scanning for connected storage devices...\n");
            let devices = device::list_devices()?;
            if devices.is_empty() {
                println!("No storage devices detected.");
            } else {
                println!(
                    "{:<30} {:<25} {:<15} {:<12} {:<10}",
                    "Device Path", "Description", "Capacity", "Sector Size", "Type"
                );
                println!("{}", "=".repeat(95));
                for dev in devices {
                    println!(
                        "{:<30} {:<25} {:<15} {:<12} {:<10}",
                        dev.path,
                        dev.name,
                        utils::format_size(dev.size),
                        format!("{} B", dev.sector_size),
                        dev.device_type
                    );
                }
            }
        }

        Commands::Info { device } => {
            println!("Reading device geometry and filesystem layout for '{}'...\n", device);
            let dev = Device::open(&device)?;

            println!("Hardware Geometry:");
            println!("------------------");
            println!("Device Path:   {}", dev.path());
            println!("Capacity:      {} ({} bytes)", utils::format_size(dev.size()), dev.size());
            println!("Sector Size:   {} bytes", dev.sector_size());
            println!("Total Sectors: {}\n", dev.total_sectors());

            match detect_filesystem(&dev) {
                Ok(parser) => {
                    let info = parser.get_info();
                    println!("Detected Filesystem Info:");
                    println!("-------------------------");
                    println!("Filesystem:    {}", info.fs_type);
                    println!("OEM Name:      {}", info.oem_name);
                    println!("Serial Number: 0x{:08X}", info.serial_number);
                    println!("Cluster Size:  {} bytes ({} sectors)", info.cluster_size, info.cluster_size / info.sector_size);
                    println!("FAT Count:     {}", info.fat_count);
                    println!("Reserved Sects:{}", info.reserved_sectors);
                    println!("Sects per FAT: {}", info.sectors_per_fat);
                    println!("Root Start Off:0x{:08X}", info.root_dir_start);
                }
                Err(e) => {
                    println!("Filesystem Check:");
                    println!("-----------------");
                    println!("Status:        Raw / Unsupported Filesystem");
                    println!("Details:       {}", e);
                }
            }

        }

        Commands::Scan { device } => {
            let start_time = Instant::now();
            println!("Initializing search for deleted files on '{}'...\n", device);
            let dev = Device::open(&device)?;

            let parser = detect_filesystem(&dev)?;
            let info = parser.get_info();
            println!("Filesystem: {}\n", info.fs_type);

            let deleted = parser.scan_deleted(&dev)?;
            let elapsed = start_time.elapsed().as_secs();

            if deleted.is_empty() {
                println!("Scan completed. No deleted files detected on the filesystem structures.");
            } else {
                println!("Deleted Files Found:");
                println!("{:<6} {:<40} {:<12} {:<15}", "ID", "Name", "Size", "Recovery Status");
                println!("{}", "-".repeat(75));

                let mut recoverable = 0;
                let mut partial = 0;
                let mut overwritten = 0;

                for file in &deleted {
                    match file.status {
                        RecoveryStatus::Recoverable => recoverable += 1,
                        RecoveryStatus::Partial => partial += 1,
                        RecoveryStatus::Overwritten | RecoveryStatus::Corrupted => overwritten += 1,
                    }

                    println!(
                        "{:<6} {:<40} {:<12} {:<15}",
                        file.id,
                        if file.name.len() > 38 {
                            format!("...{}", &file.name[file.name.len() - 35..])
                        } else {
                            file.name.clone()
                        },
                        utils::format_size(file.size),
                        file.status.to_string()
                    );
                }

                println!("{}", "-".repeat(75));
                println!("Scan Summary:");
                println!("  Recoverable: {}", recoverable);
                println!("  Partial:     {}", partial);
                println!("  Overwritten: {}", overwritten);
                println!("  Total Found: {}", deleted.len());
                println!("  Time Taken:  {} seconds\n", elapsed);

                // Cache session details for subsequent commands
                let session = RecoverySession {
                    device: device.clone(),
                    filesystem: info.fs_type.clone(),
                    files: deleted.clone(),
                };
                session.save_to_file("recovery_session.json")?;

                // Generate report
                let report = RecoveryReport {
                    device,
                    filesystem: info.fs_type,
                    deleted_found: deleted.len(),
                    recoverable,
                    partial,
                    overwritten,
                    elapsed_seconds: elapsed,
                };
                report.save_to_file("recovery_report.json")?;
            }
        }

        Commands::Recover { device, id, output } => {
            println!("Loading scan session data...");
            let session = RecoverySession::load_from_file("recovery_session.json").map_err(|_| {
                RecoveryError::InvalidArgument("No active scan session found. Please run 'recover scan' first.".to_string())
            })?;

            if session.device != device {
                warn!(
                    "Session device '{}' does not match requested device '{}'. Continuing anyway...",
                    session.device, device
                );
            }

            let file_meta = session.files.iter().find(|f| f.id == id).ok_or_else(|| {
                RecoveryError::InvalidArgument(format!("File ID {} not found in session cache.", id))
            })?;

            let dev = Device::open(&device)?;
            let parser = detect_filesystem(&dev)?;

            println!("Recovering: {} ({} bytes)...", file_meta.name, file_meta.size);
            let hash = recovery::recover_file(&dev, parser.as_ref(), file_meta, &output)?;
            println!("SHA-256 Checksum: {}", hash);

            // Verify integrity of the recovered file
            let recovered_path = Path::new(&output).join(&file_meta.name);
            match recovery::verify_file_integrity(&recovered_path) {
                Ok(verified) => {
                    if verified {
                        println!("Integrity Status: VERIFIED (Magic structures match)");
                    } else {
                        println!("Integrity Status: UNVERIFIED (Possibility of fragmentation or overwrite)");
                    }
                }
                Err(e) => {
                    warn!("Could not perform integrity check on recovered file: {}", e);
                }
            }
        }

        Commands::RecoverAll { device, output } => {
            println!("Loading scan session data...");
            let session = RecoverySession::load_from_file("recovery_session.json").map_err(|_| {
                RecoveryError::InvalidArgument("No active scan session found. Please run 'recover scan' first.".to_string())
            })?;

            let dev = Device::open(&device)?;
            let parser = detect_filesystem(&dev)?;

            let recoverable_files: Vec<&DeletedFile> = session
                .files
                .iter()
                .filter(|f| f.status == RecoveryStatus::Recoverable || f.status == RecoveryStatus::Partial)
                .collect();

            if recoverable_files.is_empty() {
                println!("No recoverable files found in the current session.");
                return Ok(());
            }

            println!("Recovering {} files to '{}'...", recoverable_files.len(), output);
            let mut success_count = 0;

            for file in recoverable_files {
                match recovery::recover_file(&dev, parser.as_ref(), file, &output) {
                    Ok(hash) => {
                        success_count += 1;
                        println!("  Recovered: {} (SHA-256: {})", file.name, hash);
                    }
                    Err(e) => warn!("Failed to recover file '{}' (ID: {}): {}", file.name, file.id, e),
                }
            }

            println!("\nRecovery complete. Successfully recovered {} / {} files.", success_count, session.files.len());
        }

        Commands::Carve { device, output, signatures, types } => {
            let start_time = Instant::now();
            let mut sigs = if let Some(sig_path) = signatures {
                signatures::load_signatures_from_json(&sig_path)?
            } else {
                get_default_signatures()
            };

            // Filter signatures by user-requested types if provided
            if let Some(types_str) = types {
                let allowed_exts: std::collections::HashSet<String> = types_str
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .collect();
                sigs.retain(|sig| allowed_exts.contains(&sig.extension.to_lowercase()));
                if sigs.is_empty() {
                    return Err(RecoveryError::InvalidArgument(format!(
                        "None of the available signatures matched the requested types: {}",
                        types_str
                    )));
                }
            }

            let dev = Device::open(&device)?;
            println!("Performing raw carving on '{}' using {} file signatures...", device, sigs.len());
            println!("This scans the disk sector-by-sector and may take some time depending on disk size.\n");

            let carved = scanner::carve_device(&dev, &sigs, None)?;
            let elapsed = start_time.elapsed().as_secs();

            if carved.is_empty() {
                println!("Carving complete. No files could be carved from raw signatures.");
            } else {
                println!("\nFound {} files via carving. Writing files to '{}'...", carved.len(), output);
                recovery::write_carved_files(&dev, &carved, &output)?;

                println!("Carving complete in {} seconds.", elapsed);

                // Write report
                let report = RecoveryReport {
                    device,
                    filesystem: "Raw Signature Carving".to_string(),
                    deleted_found: carved.len(),
                    recoverable: carved.len(),
                    partial: 0,
                    overwritten: 0,
                    elapsed_seconds: elapsed,
                };
                report.save_to_file("recovery_report.json")?;
            }
        }

        Commands::Verify { file } => {
            if !Path::new(&file).exists() {
                return Err(RecoveryError::InvalidArgument(format!("Target file '{}' does not exist.", file)));
            }

            println!("Analyzing file integrity for '{}'...", file);
            match recovery::verify_file_integrity(&file)? {
                true => println!("Integrity Check: PASSED. Structure and headers are valid."),
                false => println!("Integrity Check: FAILED. Magic bytes or footer signatures do not match."),
            }
        }

        Commands::Report { path } => {
            let report = RecoveryReport::load_from_file(&path)?;
            println!("Last Session Report (Loaded from {}):", path);
            println!("{}", "=".repeat(45));
            println!("Device:          {}", report.device);
            println!("Filesystem:      {}", report.filesystem);
            println!("Files Found:     {}", report.deleted_found);
            println!("  Recoverable:   {}", report.recoverable);
            println!("  Partial:       {}", report.partial);
            println!("  Overwritten:   {}", report.overwritten);
            println!("Elapsed Time:    {} seconds", report.elapsed_seconds);
            println!("{}", "=".repeat(45));
        }

        Commands::Tui => {
            recover_cli::tui::run_tui()?;
        }

        Commands::AcquireAndroid { output, device, backup, hash } => {
            println!("Initializing Android Device Logical Acquisition...");
            recover_cli::android::acquire_device(
                device.as_deref(),
                Path::new(&output),
                backup,
                &hash,
            )?;
        }
    }

    Ok(())
}

fn run_interactive_mode() -> Result<()> {
    recover_cli::tui::run_tui()
}

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }
    env_logger::init();

    // Friendly interactive mode when run without arguments (e.g., double-clicked)
    if std::env::args().count() == 1 {
        if let Err(e) = run_interactive_mode() {
            eprintln!("\nError in interactive mode: {}", e);
        }
        println!("\nPress Enter to close this window...");
        let mut temp = String::new();
        let _ = std::io::stdin().read_line(&mut temp);
        std::process::exit(0);
    }

    if let Err(e) = run_app() {
        eprintln!("\nError: {}", e);
        std::process::exit(1);
    }
}
