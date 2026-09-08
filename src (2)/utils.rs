use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use sha2::{Sha256, Sha512, Digest};
use sha1::Sha1;
use md5::Md5;

/// Computes the cryptographic hash of a file dynamically based on the requested algorithm.
pub fn compute_hash(path: &Path, algorithm: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; 1024 * 64]; // 64 KB read buffer
    
    match algorithm.to_lowercase().trim() {
        "md5" => {
            let mut hasher = Md5::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        "sha1" => {
            let mut hasher = Sha1::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported hash algorithm: {}", algorithm)
        ))
    }
}

/// Formats a byte size into a human-readable string (e.g., 4.2 MB, 1.8 GB).
pub fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;

    if bytes >= TIB {
        format!("{:.2} TB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2} GB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Formats speed in bytes per second to a human-readable string (e.g., 45.2 MB/s).
pub fn format_speed(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 0.0 {
        return "0 B/s".to_string();
    }
    let bytes = bytes_per_sec as u64;
    format!("{}/s", format_size(bytes))
}

/// Formats a duration in seconds to a human-readable duration (e.g., 01h 23m 45s).
pub fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{:02}h {:02}m {:02}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{:02}m {:02}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

/// Helper function to check if a year is a leap year.
pub fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Converts MS-DOS date and time fields to a Unix timestamp (seconds since 1970-01-01).
pub fn dos_to_unix_time(dos_date: u16, dos_time: u16) -> Option<u64> {
    if dos_date == 0 && dos_time == 0 {
        return None;
    }
    let day = (dos_date & 0x1F) as u32;
    let month = ((dos_date >> 5) & 0x0F) as u32;
    let year = ((dos_date >> 9) & 0x7F) as u32 + 1980;

    let second = ((dos_time & 0x1F) * 2) as u32;
    let minute = ((dos_time >> 5) & 0x3F) as u32;
    let hour = ((dos_time >> 11) & 0x1F) as u32;

    if day == 0 || month == 0 || month > 12 || day > 31 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let mut days = 0u64;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        if m == 2 && is_leap_year(year) {
            days += 29;
        } else {
            days += month_days[m as usize];
        }
    }
    days += (day - 1) as u64;

    let total_seconds = days * 86400 + (hour as u64 * 3600) + (minute as u64 * 60) + second as u64;
    Some(total_seconds)
}

/// Formats a Unix timestamp (seconds since 1970-01-01) into YYYY-MM-DD HH:MM:SS format.
pub fn format_timestamp(timestamp: u64) -> String {
    let mut seconds = timestamp;
    let sec = seconds % 60;
    seconds /= 60;
    let min = seconds % 60;
    seconds /= 60;
    let hour = seconds % 24;
    let mut days = seconds / 24;

    let mut year = 1970;
    loop {
        let leap = is_leap_year(year);
        let ydays = if leap { 366 } else { 365 };
        if days < ydays {
            break;
        }
        days -= ydays;
        year += 1;
    }

    let mut month = 1;
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    loop {
        let mut mdays = month_days[month as usize] as u64;
        if month == 2 && is_leap_year(year) {
            mdays = 29;
        }
        if days < mdays {
            break;
        }
        days -= mdays;
        month += 1;
    }
    let day = days + 1;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec
    )
}

/// Computes the SHA-256 hash of an in-memory byte slice.
pub fn compute_sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1024 * 1024 * 5 / 2), "2.50 MB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(125), "02m 05s");
        assert_eq!(format_duration(3665), "01h 01m 05s");
    }

    #[test]
    fn test_dos_to_unix_time() {
        // 2026-07-06 15:30:10
        // Year offset from 1980: 46 (0x2E)
        // Month: 7 (0x07)
        // Day: 6 (0x06)
        // DOS Date = (46 << 9) | (7 << 5) | 6 = 23552 + 224 + 6 = 23782
        // Hour: 15 (0x0F)
        // Minute: 30 (0x1E)
        // Second: 10 -> DOS second count = 5 (0x05)
        // DOS Time = (15 << 11) | (30 << 5) | 5 = 30720 + 960 + 5 = 31685
        let dos_date = 23782;
        let dos_time = 31685;
        let ts = dos_to_unix_time(dos_date, dos_time);
        assert!(ts.is_some());
        assert_eq!(format_timestamp(ts.unwrap()), "2026-07-06 15:30:10");
    }
}
