//! Scanner presence policy; independent of the slow-operation monitor switch.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScannerHealthConfig {
    pub offline_after_seconds: i64,
    pub alert_after_seconds: i64,
    pub check_interval_seconds: u64,
    pub maintenance_grace_seconds: i64,
    pub latency_warning_ms: i64,
    pub latency_critical_ms: i64,
    pub latency_stale_after_seconds: i64,
}

impl Default for ScannerHealthConfig {
    fn default() -> Self {
        Self {
            offline_after_seconds: 90,
            alert_after_seconds: 90,
            check_interval_seconds: 30,
            maintenance_grace_seconds: 90,
            latency_warning_ms: 100,
            latency_critical_ms: 300,
            latency_stale_after_seconds: 90,
        }
    }
}

impl ScannerHealthConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(60..=86_400).contains(&self.offline_after_seconds) {
            return Err("在线判定时间必须为 60～86400 秒，至少覆盖两个默认心跳周期".into());
        }
        if !(self.offline_after_seconds..=604_800).contains(&self.alert_after_seconds) {
            return Err("掉线告警时间必须不小于在线判定时间且不超过 604800 秒".into());
        }
        if !(1..=300).contains(&self.check_interval_seconds)
            || self.check_interval_seconds > self.offline_after_seconds as u64
        {
            return Err("检查间隔必须为 1～300 秒且不超过在线判定时间".into());
        }
        if !(0..=86_400).contains(&self.maintenance_grace_seconds) {
            return Err("维护结束宽限期必须为 0～86400 秒".into());
        }
        if !(1..=86_400_000).contains(&self.latency_warning_ms)
            || !(self.latency_warning_ms..=86_400_000).contains(&self.latency_critical_ms)
        {
            return Err("延迟阈值必须大于 0，严重阈值不能小于警告阈值".into());
        }
        if !(1..=86_400).contains(&self.latency_stale_after_seconds) {
            return Err("延迟样本过期时间必须为 1～86400 秒".into());
        }
        Ok(())
    }
}

/// A scalar subquery makes every SQL reader use the authoritative committed policy,
/// including background generators and other server instances. Only trusted field
/// names from this module enter SQL; values never come from request text.
pub fn seconds_sql() -> String {
    field_sql("offline_after_seconds", 90)
}

pub fn latency_stale_seconds_sql() -> String {
    field_sql("latency_stale_after_seconds", 90)
}

pub fn latency_warning_sql() -> String {
    field_sql("latency_warning_ms", 100)
}
pub fn latency_critical_sql() -> String {
    field_sql("latency_critical_ms", 300)
}

fn field_sql(field: &str, default: i64) -> String {
    format!(
        "COALESCE((SELECT (document->>'{field}')::BIGINT FROM runtime_configuration WHERE namespace = 'scanner_health'), {default})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_presence_alert_and_sampling_relationships() {
        let mut config = ScannerHealthConfig::default();
        assert!(config.validate().is_ok());
        config.alert_after_seconds = 89;
        assert!(config.validate().is_err());
        config.alert_after_seconds = 180;
        config.check_interval_seconds = 91;
        assert!(config.validate().is_err());
        config.check_interval_seconds = 10;
        config.latency_critical_ms = 99;
        assert!(config.validate().is_err());
    }
}
