use crate::errors::{RecoveryError, Result};
use crate::filesystem::DeletedFile;
use log::debug;
use serde::{Deserialize, Serialize};
use std::fs;

/// Summary statistics of a recovery session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub device: String,
    pub filesystem: String,
    pub deleted_found: usize,
    pub recoverable: usize,
    pub partial: usize,
    pub overwritten: usize,
    pub elapsed_seconds: u64,
}

/// Represents the persistent session data cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySession {
    pub device: String,
    pub filesystem: String,
    pub files: Vec<DeletedFile>,
}

impl RecoveryReport {
    /// Saves the report to a JSON file.
    pub fn save_to_file(&self, path: &str) -> Result<()> {
        let content = serde_json::to_string_pretty(self).map_err(|e| {
            RecoveryError::General(format!("Failed to serialize report: {}", e))
        })?;
        fs::write(path, content).map_err(RecoveryError::Io)?;
        debug!("Saved recovery report to '{}'", path);
        Ok(())
    }

    /// Loads the report from a JSON file.
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            RecoveryError::General(format!("Failed to read report from '{}': {}", path, e))
        })?;
        let report: Self = serde_json::from_str(&content).map_err(|e| {
            RecoveryError::General(format!("Failed to parse report JSON: {}", e))
        })?;
        Ok(report)
    }
}

impl RecoverySession {
    /// Saves the session files list to a JSON cache file.
    pub fn save_to_file(&self, path: &str) -> Result<()> {
        let content = serde_json::to_string_pretty(self).map_err(|e| {
            RecoveryError::General(format!("Failed to serialize session cache: {}", e))
        })?;
        fs::write(path, content).map_err(RecoveryError::Io)?;
        debug!("Saved session cache ({} files) to '{}'", self.files.len(), path);
        Ok(())
    }

    /// Loads the session files list from a JSON cache file.
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            RecoveryError::General(format!("Failed to read session cache from '{}': {}", path, e))
        })?;
        let session: Self = serde_json::from_str(&content).map_err(|e| {
            RecoveryError::General(format!("Failed to parse session cache JSON: {}", e))
        })?;
        Ok(session)
    }
}
