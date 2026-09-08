use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "recover-droid")]
#[command(author = "Antigravity")]
#[command(version = "0.1.0")]
#[command(about = "Recover Droid - Advanced Data Recovery Tool", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Lists connected storage devices.
    List,

    /// Shows detailed filesystem and hardware properties of a storage device.
    Info {
        /// The path to the storage device (e.g., '\\.\PhysicalDrive1' or '/dev/sdb').
        device: String,
    },

    /// Scans a storage device filesystem for deleted files.
    Scan {
        /// The path to the device.
        device: String,
    },

    /// Recovers a specific deleted file by its identifier.
    Recover {
        /// The path to the device.
        device: String,
        /// The ID of the file to recover.
        id: u32,
        /// The output directory to write the recovered file.
        output: String,
    },

    /// Recovers all recoverable files from a device.
    RecoverAll {
        /// The path to the device.
        device: String,
        /// The output directory to write recovered files.
        output: String,
    },

    /// Scans a device and performs raw signature-based file carving.
    Carve {
        /// The path to the device.
        device: String,
        /// The output directory to write carved files.
        output: String,
        /// Path to an optional JSON file containing custom file signatures.
        #[arg(short, long)]
        signatures: Option<String>,
        /// Comma-separated list of file extensions to carve (e.g., 'jpg,png,pdf').
        #[arg(short, long)]
        types: Option<String>,
    },

    /// Verifies the integrity of a recovered file.
    Verify {
        /// The path to the file to verify.
        file: String,
    },

    /// Outputs the JSON report of the last operation.
    Report {
        /// Path to the JSON report file.
        #[arg(short, long, default_value = "recovery_report.json")]
        path: String,
    },

    /// Launches the interactive Terminal User Interface (TUI) dashboard.
    Tui,

    /// Performs logical data acquisition from a connected Android device via ADB.
    AcquireAndroid {
        /// The output directory to store the acquired data.
        #[arg(short, long)]
        output: String,

        /// Optional serial number of the Android device to target (if multiple devices are connected).
        #[arg(short, long)]
        device: Option<String>,

        /// Request a logical application backup (requires authorization on the device screen).
        #[arg(short, long)]
        backup: bool,

        /// Comma-separated hash algorithms to compute for integrity (md5, sha1, sha256, sha512).
        #[arg(short = 'H', long, default_value = "sha256")]
        hash: String,
    },
}
