use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::net::IpAddr;

use cidr::IpCidr;
use deadpool_postgres::Pool;
use ipnet::{IpNet, Ipv4Net};

use crate::client_ip::normalize_ip;

pub const MAX_LOGIN_ALLOWLIST_ENTRIES: usize = 64;

fn canonical_cidr(network: &IpCidr) -> String {
    format!("{}/{}", network.first_address(), network.network_length())
}

#[derive(Debug, PartialEq, Eq)]
pub struct LoginAllowlistValidationError(String);

impl fmt::Display for LoginAllowlistValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for LoginAllowlistValidationError {}

pub fn normalize_login_allowlist(
    entries: &[String],
) -> Result<Vec<IpCidr>, LoginAllowlistValidationError> {
    let entries = entries
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if entries.len() > MAX_LOGIN_ALLOWLIST_ENTRIES {
        return Err(LoginAllowlistValidationError(format!(
            "登录白名单最多允许 {MAX_LOGIN_ALLOWLIST_ENTRIES} 条地址"
        )));
    }

    let mut normalized = BTreeMap::new();
    for value in entries {
        let network = if let Ok(address) = value.parse::<IpAddr>() {
            IpCidr::from(normalize_ip(address))
        } else {
            let network = value.parse::<IpNet>().map_err(|_| {
                LoginAllowlistValidationError(format!("无效的 IP 地址或 CIDR：{value}"))
            })?;
            let network = match network {
                IpNet::V6(network) if network.prefix_len() >= 96 => network
                    .addr()
                    .to_ipv4_mapped()
                    .and_then(|address| {
                        Ipv4Net::new(address, network.prefix_len() - 96)
                            .ok()
                            .map(IpNet::V4)
                    })
                    .unwrap_or(IpNet::V6(network)),
                network => network,
            };
            network.trunc().to_string().parse::<IpCidr>().map_err(|_| {
                LoginAllowlistValidationError(format!("无效的 IP 地址或 CIDR：{value}"))
            })?
        };
        normalized.insert(canonical_cidr(&network), network);
    }

    Ok(normalized.into_values().collect())
}

pub fn login_ip_is_allowed(allowlist: &[IpCidr], source_ip: Option<IpAddr>) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    let Some(source_ip) = source_ip.map(normalize_ip) else {
        return false;
    };
    allowlist.iter().any(|network| network.contains(&source_ip))
}

pub fn display_login_allowlist(allowlist: &[IpCidr]) -> Vec<String> {
    allowlist.iter().map(canonical_cidr).collect()
}

pub async fn load_login_allowlist(
    pool: &Pool,
    user_id: i32,
) -> Result<Vec<IpCidr>, Box<dyn Error>> {
    let connection = pool.get().await?;
    let row = connection
        .query_opt(
            "SELECT login_ip_allowlist FROM users WHERE id = $1 AND disabled_at IS NULL AND deleted_at IS NULL LIMIT 1;",
            &[&user_id],
        )
        .await?
        .ok_or("用户不存在、已禁用或已删除")?;
    Ok(row.get("login_ip_allowlist"))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{login_ip_is_allowed, normalize_login_allowlist};

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn normalizes_bare_addresses_host_bits_duplicates_and_order() {
        let allowlist = normalize_login_allowlist(&strings(&[
            "2001:db8::1234/64",
            "192.0.2.15",
            "192.0.2.123/24",
            "192.0.2.15/32",
        ]))
        .unwrap();
        let values = super::display_login_allowlist(&allowlist);
        assert_eq!(values, ["192.0.2.0/24", "192.0.2.15/32", "2001:db8::/64"]);
    }

    #[test]
    fn matches_ipv4_ipv6_private_and_loopback_only_when_explicit() {
        let allowlist =
            normalize_login_allowlist(&strings(&["10.0.0.0/8", "127.0.0.1", "2001:db8::/32"]))
                .unwrap();
        for value in ["10.4.5.6", "127.0.0.1", "2001:db8::42"] {
            assert!(login_ip_is_allowed(
                &allowlist,
                Some(value.parse::<IpAddr>().unwrap())
            ));
        }
        for value in ["192.168.1.1", "127.0.0.2", "::1", "2001:db9::1"] {
            assert!(!login_ip_is_allowed(
                &allowlist,
                Some(value.parse::<IpAddr>().unwrap())
            ));
        }
    }

    #[test]
    fn empty_allowlist_allows_unknown_source_but_configured_list_fails_closed() {
        assert!(login_ip_is_allowed(&[], None));
        let allowlist = normalize_login_allowlist(&strings(&["192.0.2.0/24"])).unwrap();
        assert!(!login_ip_is_allowed(&allowlist, None));
    }

    #[test]
    fn normalizes_ipv4_mapped_bare_address() {
        let allowlist =
            normalize_login_allowlist(&strings(&["::ffff:192.0.2.8", "::ffff:192.0.2.1/120"]))
                .unwrap();
        assert_eq!(
            super::display_login_allowlist(&allowlist),
            ["192.0.2.0/24", "192.0.2.8/32"]
        );
        assert!(login_ip_is_allowed(
            &allowlist,
            Some("::ffff:192.0.2.8".parse().unwrap())
        ));
    }

    #[test]
    fn rejects_invalid_entries_and_excessive_input() {
        assert!(normalize_login_allowlist(&strings(&["not-an-address"])).is_err());
        let excessive = (0..65).map(|index| format!("192.0.2.{index}"));
        assert!(normalize_login_allowlist(&excessive.collect::<Vec<_>>()).is_err());
    }

    #[test]
    fn database_schema_adds_bounded_cidr_allowlist() {
        let schema = include_str!("../source/database/init.sql");
        assert!(schema.contains("login_ip_allowlist CIDR[] NOT NULL"));
        assert!(schema.contains("users_login_ip_allowlist_size_check"));
        assert!(schema.contains("cardinality(login_ip_allowlist) <= 64"));
    }
}
