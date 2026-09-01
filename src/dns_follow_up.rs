use ipnet::IpNet;
use serde::Deserialize;
use std::net::IpAddr;

/// Policy controlling server-side port scan tasks derived from DNS A/AAAA answers.
/// A disabled policy is the safe default for existing installations.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct DnsFollowUpConfig {
    pub enabled: bool,
    pub authorized_cidrs: Vec<String>,
    pub excluded_cidrs: Vec<String>,
    pub max_targets_per_task: u16,
}

impl Default for DnsFollowUpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            authorized_cidrs: Vec::new(),
            excluded_cidrs: Vec::new(),
            max_targets_per_task: 100,
        }
    }
}

impl DnsFollowUpConfig {
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.max_targets_per_task == 0 || self.max_targets_per_task > 500 {
            return Err("dns_follow_up.max_targets_per_task 必须在 1 到 500 之间".into());
        }
        if self.enabled && self.authorized_cidrs.is_empty() {
            return Err("启用 DNS 后续端口任务时必须配置 dns_follow_up.authorized_cidrs".into());
        }
        let authorized = parse_cidrs(&self.authorized_cidrs, "授权")?;
        let excluded = parse_cidrs(&self.excluded_cidrs, "排除")?;
        reject_overlapping_cidrs(&authorized, "授权")?;
        reject_overlapping_cidrs(&excluded, "排除")?;
        Ok(())
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        let authorized = self.authorized_cidrs.iter().any(|value| {
            value
                .parse::<IpNet>()
                .is_ok_and(|network| network.contains(&ip))
        });
        authorized
            && !self.excluded_cidrs.iter().any(|value| {
                value
                    .parse::<IpNet>()
                    .is_ok_and(|network| network.contains(&ip))
            })
    }
}

fn parse_cidrs(values: &[String], kind: &str) -> Result<Vec<IpNet>, Box<dyn std::error::Error>> {
    values
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .map_err(|error| format!("无效的 DNS 后续任务{kind} CIDR {value}: {error}").into())
        })
        .collect()
}

fn reject_overlapping_cidrs(
    networks: &[IpNet],
    kind: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for (index, network) in networks.iter().enumerate() {
        if networks[index + 1..]
            .iter()
            .any(|other| network.contains(&other.network()) || other.contains(&network.network()))
        {
            return Err(format!("DNS 后续任务{kind} CIDR 存在重复或重叠：{network}").into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::DnsFollowUpConfig;

    #[test]
    fn enabled_policy_requires_authorized_cidrs() {
        let config = DnsFollowUpConfig {
            enabled: true,
            ..DnsFollowUpConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn policy_matches_only_authorized_addresses() {
        let config = DnsFollowUpConfig {
            enabled: true,
            authorized_cidrs: vec!["192.0.2.0/24".into(), "2001:db8::/32".into()],
            ..DnsFollowUpConfig::default()
        };
        assert!(config.allows("192.0.2.10".parse().unwrap()));
        assert!(config.allows("2001:db8::10".parse().unwrap()));
        assert!(!config.allows("198.51.100.10".parse().unwrap()));
    }

    #[test]
    fn excluded_cidrs_override_authorized_cidrs() {
        let config = DnsFollowUpConfig {
            enabled: true,
            authorized_cidrs: vec!["192.0.2.0/24".into()],
            excluded_cidrs: vec!["192.0.2.128/25".into()],
            ..DnsFollowUpConfig::default()
        };
        assert!(config.validate().is_ok());
        assert!(config.allows("192.0.2.10".parse().unwrap()));
        assert!(!config.allows("192.0.2.200".parse().unwrap()));
    }

    #[test]
    fn overlapping_exclusions_are_rejected() {
        let config = DnsFollowUpConfig {
            excluded_cidrs: vec!["192.0.2.0/24".into(), "192.0.2.128/25".into()],
            ..DnsFollowUpConfig::default()
        };
        assert!(config.validate().is_err());
    }
}
