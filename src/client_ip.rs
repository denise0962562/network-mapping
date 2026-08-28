use std::net::{IpAddr, SocketAddr};

use actix_web::{HttpMessage, HttpRequest};

/// The client address resolved once at the outer request boundary.
///
/// Keeping the attempted resolution (including `None`) in request extensions prevents
/// downstream consumers from applying a different proxy-header policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedClientIp(pub Option<IpAddr>);

/// Normalize IPv4-mapped IPv6 addresses so one IPv4 client has one canonical identity.
pub fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

/// Parse either a bare IP address or a socket address and return its canonical IP.
pub fn parse_ip(value: &str) -> Option<IpAddr> {
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|address| address.ip()))
        .map(normalize_ip)
}

pub fn display_ip(address: Option<IpAddr>) -> Option<String> {
    address.map(normalize_ip).map(|address| address.to_string())
}

/// Return the centrally resolved client address. Requests created outside the application
/// middleware (for example focused handler tests) safely fall back to the TCP peer and never
/// trust forwarding headers on their own.
pub fn request_ip(request: &HttpRequest) -> Option<IpAddr> {
    request
        .extensions()
        .get::<ResolvedClientIp>()
        .and_then(|resolved| resolved.0)
        .or_else(|| {
            request
                .peer_addr()
                .map(|address| normalize_ip(address.ip()))
        })
}

#[cfg(test)]
mod tests {
    use super::{ResolvedClientIp, display_ip, normalize_ip, parse_ip, request_ip};
    use actix_web::{HttpMessage, test as actix_test};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn normalizes_ipv4_mapped_ipv6_addresses() {
        let mapped = "::ffff:64.81.116.137".parse::<IpAddr>().unwrap();
        assert_eq!(
            normalize_ip(mapped),
            IpAddr::V4(Ipv4Addr::new(64, 81, 116, 137))
        );
        assert_eq!(display_ip(Some(mapped)).as_deref(), Some("64.81.116.137"));
    }

    #[test]
    fn parses_bare_and_socket_addresses_canonically() {
        assert_eq!(
            parse_ip("[::ffff:64.81.116.137]:443"),
            Some(IpAddr::V4(Ipv4Addr::new(64, 81, 116, 137)))
        );
        assert_eq!(
            parse_ip("[2001:db8::1]:443"),
            Some(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
        );
        assert_eq!(parse_ip("unknown"), None);
    }

    #[test]
    fn request_ip_prefers_the_centrally_resolved_address() {
        let request = actix_test::TestRequest::default()
            .peer_addr("127.0.0.1:443".parse().unwrap())
            .insert_header(("x-forwarded-for", "203.0.113.9"))
            .to_http_request();
        request
            .extensions_mut()
            .insert(ResolvedClientIp(Some("203.0.113.9".parse().unwrap())));

        assert_eq!(request_ip(&request), Some("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn request_ip_falls_back_to_peer_without_trusting_headers() {
        let request = actix_test::TestRequest::default()
            .peer_addr("127.0.0.1:443".parse().unwrap())
            .insert_header(("x-forwarded-for", "203.0.113.9"))
            .to_http_request();

        assert_eq!(request_ip(&request), Some("127.0.0.1".parse().unwrap()));
    }
}
