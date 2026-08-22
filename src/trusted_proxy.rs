use actix_web::{HttpRequest, http::header::HeaderMap};
use deadpool_postgres::Pool;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

const SETTING_TYPE: &str = "network";
const SETTING_KEY: &str = "trusted_proxies";
pub const MAX_TRUSTED_PROXY_CIDRS: usize = 32;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientIpHeader {
    #[default]
    XForwardedFor,
    Forwarded,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct TrustedProxySettings {
    pub trusted_proxy_cidrs: Vec<String>,
    pub client_ip_header: ClientIpHeader,
}

pub struct ValidatedTrustedProxySettings {
    pub settings: TrustedProxySettings,
    networks: Vec<IpNet>,
}

#[derive(Clone)]
pub struct TrustedProxyState(Arc<RwLock<TrustedProxyRuntime>>);

struct TrustedProxyRuntime {
    settings: TrustedProxySettings,
    networks: Vec<IpNet>,
}

impl TrustedProxyState {
    pub fn new(settings: TrustedProxySettings) -> Result<Self, String> {
        let validated = validate_settings(settings)?;
        Ok(Self(Arc::new(RwLock::new(TrustedProxyRuntime {
            settings: validated.settings,
            networks: validated.networks,
        }))))
    }

    pub async fn from_database(
        pool: &Pool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let connection = pool.get().await?;
        let row = connection
            .query_opt(
                "SELECT value FROM setting WHERE item_type = $1 AND key = $2 LIMIT 1;",
                &[&SETTING_TYPE, &SETTING_KEY],
            )
            .await?;
        let settings = match row {
            Some(row) => match serde_json::from_str::<TrustedProxySettings>(row.get("value")) {
                Ok(settings) => settings,
                Err(error) => {
                    warn!(
                        event = "TrustedProxySettingsMalformed",
                        reason = %error,
                        "malformed persisted trusted proxy settings were ignored"
                    );
                    TrustedProxySettings::default()
                }
            },
            None => TrustedProxySettings::default(),
        };
        match Self::new(settings) {
            Ok(state) => Ok(state),
            Err(error) => {
                warn!(
                    event = "TrustedProxySettingsInvalid",
                    reason = %error,
                    "invalid persisted trusted proxy settings were ignored"
                );
                Self::new(TrustedProxySettings::default()).map_err(Into::into)
            }
        }
    }

    pub async fn settings(&self) -> TrustedProxySettings {
        self.0.read().await.settings.clone()
    }

    pub async fn replace(&self, validated: ValidatedTrustedProxySettings) {
        *self.0.write().await = TrustedProxyRuntime {
            settings: validated.settings,
            networks: validated.networks,
        };
    }

    pub async fn client_ip(&self, request: &HttpRequest) -> Option<IpAddr> {
        let peer_ip = normalize_ip(request.peer_addr()?.ip());
        let runtime = self.0.read().await;
        if !is_trusted(peer_ip, &runtime.networks) {
            return Some(peer_ip);
        }

        let Some(addresses) =
            forwarded_addresses(request.headers(), runtime.settings.client_ip_header)
        else {
            return Some(peer_ip);
        };
        if addresses.is_empty() {
            return Some(peer_ip);
        }
        addresses
            .iter()
            .rev()
            .copied()
            .find(|address| !is_trusted(*address, &runtime.networks))
            .or(Some(peer_ip))
    }
}

pub fn validate_settings(
    settings: TrustedProxySettings,
) -> Result<ValidatedTrustedProxySettings, String> {
    if settings.trusted_proxy_cidrs.len() > MAX_TRUSTED_PROXY_CIDRS {
        return Err(format!(
            "可信代理 CIDR 不能超过 {MAX_TRUSTED_PROXY_CIDRS} 条"
        ));
    }

    let mut networks = Vec::with_capacity(settings.trusted_proxy_cidrs.len());
    for value in settings.trusted_proxy_cidrs {
        let value = value.trim();
        if value.is_empty() {
            return Err("可信代理 CIDR 不能为空".into());
        }
        if value.len() > 64 {
            return Err("可信代理 CIDR 长度不能超过 64 个字符".into());
        }
        let network = value
            .parse::<IpNet>()
            .map_err(|_| format!("无效的可信代理 CIDR：{value}"))?
            .trunc();
        if network.prefix_len() == 0 {
            return Err("不能把整个 IPv4 或 IPv6 地址空间配置为可信代理".into());
        }
        if !networks.contains(&network) {
            networks.push(network);
        }
    }

    let settings = TrustedProxySettings {
        trusted_proxy_cidrs: networks.iter().map(ToString::to_string).collect(),
        client_ip_header: settings.client_ip_header,
    };
    Ok(ValidatedTrustedProxySettings { settings, networks })
}

pub async fn write_settings_to_database(
    pool: &Pool,
    settings: &TrustedProxySettings,
) -> Result<(), Box<dyn std::error::Error>> {
    let value = serde_json::to_string(settings)?;
    let connection = pool.get().await?;
    connection
        .execute(
            "INSERT INTO setting (item_type, key, value) VALUES ($1, $2, $3) \
             ON CONFLICT (item_type, key) DO UPDATE SET value = EXCLUDED.value, update_at = NOW();",
            &[&SETTING_TYPE, &SETTING_KEY, &value],
        )
        .await?;
    Ok(())
}

fn forwarded_addresses(headers: &HeaderMap, source: ClientIpHeader) -> Option<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    let name = match source {
        ClientIpHeader::XForwardedFor => "x-forwarded-for",
        ClientIpHeader::Forwarded => "forwarded",
    };
    for header_value in headers.get_all(name) {
        let header_value = header_value.to_str().ok()?;
        for element in header_value.split(',') {
            let address = match source {
                ClientIpHeader::XForwardedFor => parse_forwarded_address(element)?,
                ClientIpHeader::Forwarded => element.split(';').find_map(|parameter| {
                    let (name, value) = parameter.split_once('=')?;
                    name.trim()
                        .eq_ignore_ascii_case("for")
                        .then(|| parse_forwarded_address(value))
                        .flatten()
                })?,
            };
            addresses.push(address);
        }
    }
    Some(addresses)
}

fn parse_forwarded_address(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    if value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
        return None;
    }
    if let Some(value) = value.strip_prefix('[') {
        let (address, _) = value.split_once(']')?;
        return address.parse::<IpAddr>().ok().map(normalize_ip);
    }
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|address| address.ip()))
        .map(normalize_ip)
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

fn is_trusted(address: IpAddr, networks: &[IpNet]) -> bool {
    networks.iter().any(|network| network.contains(&address))
}

#[cfg(test)]
mod tests {
    use super::{ClientIpHeader, TrustedProxySettings, TrustedProxyState, validate_settings};
    use actix_web::{http::header, test as actix_test};
    use std::net::{IpAddr, SocketAddr};

    fn settings(cidrs: &[&str], client_ip_header: ClientIpHeader) -> TrustedProxySettings {
        TrustedProxySettings {
            trusted_proxy_cidrs: cidrs.iter().map(|value| (*value).to_owned()).collect(),
            client_ip_header,
        }
    }

    #[test]
    fn settings_are_canonicalized_and_deduplicated() {
        let validated = validate_settings(settings(
            &["10.1.2.3/8", "10.0.0.0/8", "2001:db8::42/64"],
            ClientIpHeader::XForwardedFor,
        ))
        .unwrap();
        assert_eq!(
            validated.settings.trusted_proxy_cidrs,
            ["10.0.0.0/8", "2001:db8::/64"]
        );
        assert!(
            validate_settings(settings(&["0.0.0.0/0"], ClientIpHeader::XForwardedFor)).is_err()
        );
        assert!(validate_settings(settings(&["not-a-cidr"], ClientIpHeader::Forwarded)).is_err());
    }

    #[actix_web::test]
    async fn untrusted_peer_cannot_spoof_forwarded_address() {
        let state =
            TrustedProxyState::new(settings(&["127.0.0.1/32"], ClientIpHeader::XForwardedFor))
                .unwrap();
        let request = actix_test::TestRequest::default()
            .peer_addr("198.51.100.8:443".parse::<SocketAddr>().unwrap())
            .insert_header(("x-forwarded-for", "203.0.113.99"))
            .to_http_request();
        assert_eq!(
            state.client_ip(&request).await,
            Some("198.51.100.8".parse::<IpAddr>().unwrap())
        );
    }

    #[actix_web::test]
    async fn trusted_proxy_chain_is_processed_from_right_to_left() {
        let state = TrustedProxyState::new(settings(
            &["127.0.0.1/32", "10.0.0.0/8"],
            ClientIpHeader::XForwardedFor,
        ))
        .unwrap();
        let request = actix_test::TestRequest::default()
            .peer_addr("127.0.0.1:443".parse::<SocketAddr>().unwrap())
            .insert_header(("x-forwarded-for", "192.0.2.25, 10.2.3.4"))
            .to_http_request();
        assert_eq!(
            state.client_ip(&request).await,
            Some("192.0.2.25".parse::<IpAddr>().unwrap())
        );
    }

    #[actix_web::test]
    async fn all_trusted_forwarded_values_fail_closed_to_peer() {
        let state = TrustedProxyState::new(settings(
            &["127.0.0.1/32", "10.0.0.0/8"],
            ClientIpHeader::XForwardedFor,
        ))
        .unwrap();
        let request = actix_test::TestRequest::default()
            .peer_addr("127.0.0.1:443".parse::<SocketAddr>().unwrap())
            .insert_header(("x-forwarded-for", "10.1.2.3, 10.2.3.4"))
            .to_http_request();
        assert_eq!(
            state.client_ip(&request).await,
            Some("127.0.0.1".parse::<IpAddr>().unwrap())
        );
    }

    #[actix_web::test]
    async fn malformed_forwarded_chain_fails_closed_to_peer() {
        let state = TrustedProxyState::new(settings(
            &["127.0.0.1/32", "10.0.0.0/8"],
            ClientIpHeader::XForwardedFor,
        ))
        .unwrap();
        let request = actix_test::TestRequest::default()
            .peer_addr("127.0.0.1:443".parse::<SocketAddr>().unwrap())
            .insert_header(("x-forwarded-for", "203.0.113.99, invalid, 10.2.3.4"))
            .to_http_request();
        assert_eq!(
            state.client_ip(&request).await,
            Some("127.0.0.1".parse::<IpAddr>().unwrap())
        );
    }

    #[actix_web::test]
    async fn configured_header_is_the_only_header_used() {
        let state =
            TrustedProxyState::new(settings(&["127.0.0.1/32"], ClientIpHeader::Forwarded)).unwrap();
        let request = actix_test::TestRequest::default()
            .peer_addr("127.0.0.1:443".parse::<SocketAddr>().unwrap())
            .insert_header(("x-forwarded-for", "203.0.113.99"))
            .insert_header((
                header::FORWARDED,
                "for=198.51.100.17;proto=https, for=127.0.0.1",
            ))
            .to_http_request();
        assert_eq!(
            state.client_ip(&request).await,
            Some("198.51.100.17".parse::<IpAddr>().unwrap())
        );
    }

    #[actix_web::test]
    async fn forwarded_header_accepts_quoted_ipv6_with_port() {
        let state =
            TrustedProxyState::new(settings(&["::1/128"], ClientIpHeader::Forwarded)).unwrap();
        let request = actix_test::TestRequest::default()
            .peer_addr("[::1]:443".parse::<SocketAddr>().unwrap())
            .insert_header((header::FORWARDED, r#"for="[2001:db8::10]:4711""#))
            .to_http_request();
        assert_eq!(
            state.client_ip(&request).await,
            Some("2001:db8::10".parse::<IpAddr>().unwrap())
        );
    }
}
