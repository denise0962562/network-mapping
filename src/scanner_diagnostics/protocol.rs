//! Version 1 wire contract. Kept identical in the independently released scanner.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const VERSION: u16 = 1;
pub const CHUNK_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_JOB_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_FILES: usize = 16;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Capabilities {
    pub supported_versions: Vec<u16>,
    pub can_list_logs: bool,
    pub can_collect_logs: bool,
    pub can_report_errors: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    ListLogs,
    CollectLogs,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Job {
    pub job_id: Uuid,
    #[serde(rename = "type")]
    pub kind: JobKind,
    pub protocol_version: u16,
    pub source_file_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceFile {
    pub source_file_id: String,
    pub name: String,
    pub size_bytes: u64,
    pub modified_at: DateTime<Utc>,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snapshot {
    pub file_id: Uuid,
    pub source: SourceFile,
    pub captured_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub excluded_tail_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Ack {
    pub scanner_id: Uuid,
    pub job_id: Uuid,
    pub status: String,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest {
    pub scanner_id: Uuid,
    pub job_id: Uuid,
    pub sources: Vec<SourceFile>,
    pub files: Vec<Snapshot>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Transfer {
    pub scanner_id: Uuid,
    pub job_id: Uuid,
    pub file_id: Uuid,
    #[serde(default)]
    pub part_index: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Complete {
    pub scanner_id: Uuid,
    pub job_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Events {
    pub scanner_id: Uuid,
    pub events: Vec<serde_json::Value>,
}

pub fn valid_log_name(name: &str) -> bool {
    name.strip_prefix("scanner.log.").is_some_and(|date| {
        date.len() == 10
            && chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")
                .is_ok_and(|parsed| parsed.format("%Y-%m-%d").to_string() == date)
    })
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_daily_log_basenames_are_allowed() {
        assert!(valid_log_name("scanner.log.2026-10-01"));
        for name in [
            "../scanner.log.2026-10-01",
            "scanner.log.2026-02-30",
            "scanner.log.2026-1-01",
            "config.toml",
            "scanner.log.2026-10-01/secret",
        ] {
            assert!(!valid_log_name(name), "{name}");
        }
    }
}
