use std::net::{IpAddr, SocketAddr};

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

#[cfg(test)]
mod tests {
    use super::{display_ip, normalize_ip, parse_ip};
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
}
