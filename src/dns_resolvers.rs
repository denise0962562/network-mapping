use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DnsResolverSettings {
    #[serde(default)]
    pub resolvers: Vec<DnsResolverPreset>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsResolverPreset {
    pub id: String,
    pub label: String,
    pub ip: String,
    pub port: u16,
    pub transport: String,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

fn enabled_by_default() -> bool {
    true
}

impl DnsResolverSettings {
    pub fn validate(&self) -> Result<(), String> {
        if self.resolvers.len() > 32 {
            return Err("DNS resolver presets must contain at most 32 entries".into());
        }
        let mut ids = HashSet::new();
        for resolver in &self.resolvers {
            resolver.validate()?;
            if !ids.insert(resolver.id.to_ascii_lowercase()) {
                return Err("DNS resolver presets contain duplicate IDs".into());
            }
        }
        Ok(())
    }
}

impl DnsResolverPreset {
    fn validate(&self) -> Result<(), String> {
        let id = self.id.trim();
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(
                "DNS resolver preset ID must contain 1 to 64 letters, numbers, - or _".into(),
            );
        }
        let label = self.label.trim();
        if label.is_empty() || label.len() > 128 || label.chars().any(char::is_control) {
            return Err("DNS resolver preset name must contain 1 to 128 characters".into());
        }
        self.ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| "DNS resolver preset IP is invalid".to_owned())?;
        if self.port == 0 {
            return Err("DNS resolver preset port must be between 1 and 65535".into());
        }
        if !matches!(
            self.transport.trim().to_ascii_lowercase().as_str(),
            "udp" | "tcp"
        ) {
            return Err("DNS resolver preset transport must be udp or tcp".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_ids_case_insensitively() {
        let preset = DnsResolverPreset {
            id: "dns-a".into(),
            label: "DNS A".into(),
            ip: "1.1.1.1".into(),
            port: 53,
            transport: "udp".into(),
            enabled: true,
        };
        let settings = DnsResolverSettings {
            resolvers: vec![
                preset.clone(),
                DnsResolverPreset {
                    id: "DNS-A".into(),
                    ..preset
                },
            ],
        };
        assert!(settings.validate().is_err());
    }
}
