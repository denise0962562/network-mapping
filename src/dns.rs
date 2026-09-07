use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub const DNS_RECORD_TYPES: [&str; 12] = [
    "A", "AAAA", "CNAME", "NS", "MX", "PTR", "SRV", "TXT", "CAA", "SOA", "SVCB", "HTTPS",
];

/// A DNS response as reported by a scanner.  This is deliberately separate
/// from endpoint observations: DNS has no mandatory IP or port and a single
/// response can contain several resource records.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsObservation {
    pub observed_at: i64,
    pub question: DnsQuestion,
    pub response_code: String,
    #[serde(default)]
    pub authoritative: bool,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub dnssec_authenticated: bool,
    #[serde(default)]
    pub answers: Vec<DnsAnswer>,
    #[serde(default)]
    pub authority: Vec<DnsAnswer>,
    #[serde(default)]
    pub additional: Vec<DnsAnswer>,
    pub resolver_ip: Option<String>,
    #[serde(default)]
    pub resolver_id: Option<String>,
    #[serde(default)]
    pub resolver_label: Option<String>,
    #[serde(default)]
    pub resolver_port: Option<u16>,
    pub resolver_transport: Option<String>,
    pub latency_ms: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsQuestion {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    #[serde(default = "default_dns_class")]
    pub class: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsAnswer {
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub priority: Option<u16>,
    pub weight: Option<u16>,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalDnsRecord {
    pub id: String,
    pub domain: String,
    pub record_type: String,
    pub value: String,
    pub canonical_rdata: String,
    pub ip: Option<String>,
    pub target_domain: Option<String>,
    pub ttl: u32,
    pub priority: Option<u16>,
    pub weight: Option<u16>,
    pub port: Option<u16>,
}

fn default_dns_class() -> String {
    "IN".to_owned()
}

pub fn canonical_domain(value: &str) -> Result<String, String> {
    let value = value.trim();
    let value = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 {
        return Err("DNS domain must contain 1 to 253 octets without the root dot".to_owned());
    }
    let labels = value.split('.').collect::<Vec<_>>();
    let wire_length = 1 + labels.iter().map(|label| 1 + label.len()).sum::<usize>();
    if wire_length > 255
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || label.starts_with('-')
                || label.ends_with('-')
        })
    {
        return Err(format!("invalid DNS domain '{value}'"));
    }
    Ok(value)
}

pub fn canonical_scan_domain(value: &str) -> Result<String, String> {
    let value = canonical_domain(value)?;
    if !value.contains('.') {
        return Err("DNS scan domain must contain at least two labels separated by '.'".to_owned());
    }
    Ok(value)
}

pub fn canonical_record_type(value: &str) -> Result<String, String> {
    let value = value.trim().to_ascii_uppercase();
    if !DNS_RECORD_TYPES.contains(&value.as_str()) {
        return Err(format!("unsupported DNS record type '{value}'"));
    }
    Ok(value)
}

impl DnsObservation {
    pub fn normalize(mut self) -> Result<Self, String> {
        if self.observed_at <= 0 {
            return Err("DNS observation observed_at must be a Unix epoch millisecond".to_owned());
        }
        self.question.name = canonical_domain(&self.question.name)?;
        self.question.record_type = canonical_record_type(&self.question.record_type)?;
        self.question.class = self.question.class.trim().to_ascii_uppercase();
        if self.question.class != "IN" {
            return Err("only IN DNS class is supported".to_owned());
        }
        self.response_code = self.response_code.trim().to_ascii_uppercase();
        if !matches!(
            self.response_code.as_str(),
            "NOERROR" | "NXDOMAIN" | "SERVFAIL" | "REFUSED" | "FORMERR" | "NOTIMP" | "TIMEOUT"
        ) {
            return Err(format!(
                "unsupported DNS response code '{}'",
                self.response_code
            ));
        }
        if let Some(resolver_ip) = self.resolver_ip.as_deref() {
            self.resolver_ip = Some(
                resolver_ip
                    .parse::<IpAddr>()
                    .map_err(|_| "resolver_ip must be an IP address".to_owned())?
                    .to_string(),
            );
        }
        self.resolver_id = self
            .resolver_id
            .as_deref()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty());
        if self.resolver_id.as_deref().is_some_and(|value| {
            value.len() > 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        }) {
            return Err(
                "DNS resolver_id must contain up to 64 letters, numbers, - or _".to_owned(),
            );
        }
        self.resolver_label = self
            .resolver_label
            .as_deref()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if self
            .resolver_label
            .as_deref()
            .is_some_and(|value| value.len() > 128)
        {
            return Err("DNS resolver_label must contain up to 128 characters".to_owned());
        }
        if self.resolver_port == Some(0) {
            return Err("DNS resolver_port must be between 1 and 65535".to_owned());
        }
        self.resolver_transport = self
            .resolver_transport
            .as_deref()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty());
        if self
            .resolver_transport
            .as_deref()
            .is_some_and(|value| !matches!(value, "udp" | "tcp" | "dot" | "doh" | "doq" | "system"))
        {
            return Err("unsupported DNS resolver transport".to_owned());
        }
        for answer in self
            .answers
            .iter_mut()
            .chain(self.authority.iter_mut())
            .chain(self.additional.iter_mut())
        {
            normalize_answer(answer)?;
        }
        Ok(self)
    }

    pub fn answer_records(
        &self,
        tenant_id: &str,
        dns_view_id: &str,
    ) -> Result<Vec<CanonicalDnsRecord>, String> {
        self.answers
            .iter()
            .map(|answer| {
                CanonicalDnsRecord::from_answer(
                    tenant_id,
                    dns_view_id,
                    &self.question.name,
                    &self.question.class,
                    answer,
                )
            })
            .collect()
    }
}

impl CanonicalDnsRecord {
    fn from_answer(
        tenant_id: &str,
        dns_view_id: &str,
        domain: &str,
        class: &str,
        answer: &DnsAnswer,
    ) -> Result<Self, String> {
        let record_type = canonical_record_type(&answer.record_type)?;
        let (value, canonical_rdata, ip, target_domain) = canonical_rdata(&record_type, answer)?;
        let identity = format!(
            "dns-record-v1\0{}\0{}\0{}\0{}\0{}\0{}",
            tenant_id, dns_view_id, domain, class, record_type, canonical_rdata
        );
        let id = openssl::sha::sha256(identity.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(Self {
            id,
            domain: domain.to_owned(),
            record_type,
            value,
            canonical_rdata,
            ip,
            target_domain,
            ttl: answer.ttl,
            priority: answer.priority,
            weight: answer.weight,
            port: answer.port,
        })
    }
}

fn normalize_answer(answer: &mut DnsAnswer) -> Result<(), String> {
    let record_type = canonical_record_type(&answer.record_type)?;
    answer.record_type = record_type.clone();
    let (value, _, _, _) = canonical_rdata(&record_type, answer)?;
    answer.value = value;
    Ok(())
}

fn canonical_rdata(
    record_type: &str,
    answer: &DnsAnswer,
) -> Result<(String, String, Option<String>, Option<String>), String> {
    match record_type {
        "A" | "AAAA" => {
            let ip = answer
                .value
                .trim()
                .parse::<IpAddr>()
                .map_err(|_| format!("{record_type} value must be an IP address"))?;
            if (record_type == "A" && !ip.is_ipv4()) || (record_type == "AAAA" && !ip.is_ipv6()) {
                return Err(format!("{record_type} value has the wrong address family"));
            }
            let value = ip.to_string();
            Ok((value.clone(), value.clone(), Some(value), None))
        }
        "CNAME" | "NS" | "PTR" => {
            let target = canonical_domain(&answer.value)?;
            Ok((target.clone(), target.clone(), None, Some(target)))
        }
        "MX" => {
            let priority = answer
                .priority
                .ok_or_else(|| "MX record requires priority".to_owned())?;
            let target = canonical_domain(&answer.value)?;
            Ok((
                target.clone(),
                format!("priority={priority};target={target}"),
                None,
                Some(target),
            ))
        }
        "SRV" => {
            let priority = answer
                .priority
                .ok_or_else(|| "SRV record requires priority".to_owned())?;
            let weight = answer
                .weight
                .ok_or_else(|| "SRV record requires weight".to_owned())?;
            let port = answer
                .port
                .ok_or_else(|| "SRV record requires port".to_owned())?;
            let target = canonical_domain(&answer.value)?;
            Ok((
                target.clone(),
                format!("priority={priority};weight={weight};port={port};target={target}"),
                None,
                Some(target),
            ))
        }
        // For RDATA that is not modelled into typed fields, preserve the scanner's
        // canonical wire/text representation unchanged except surrounding space.
        _ => {
            let value = answer.value.trim().to_owned();
            if value.is_empty() {
                return Err(format!("{record_type} value must not be empty"));
            }
            Ok((value.clone(), value, None, None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_domains_and_target_records() {
        assert_eq!(
            canonical_domain(" API.Example.COM. ").unwrap(),
            "api.example.com"
        );
        let observation = DnsObservation {
            observed_at: 1,
            question: DnsQuestion {
                name: "api.example.com.".into(),
                record_type: "mx".into(),
                class: "in".into(),
            },
            response_code: "noerror".into(),
            authoritative: false,
            truncated: false,
            dnssec_authenticated: false,
            answers: vec![DnsAnswer {
                record_type: "mx".into(),
                value: "MAIL.example.com.".into(),
                ttl: 300,
                priority: Some(10),
                weight: None,
                port: None,
            }],
            authority: vec![],
            additional: vec![],
            resolver_ip: Some("192.0.2.53".into()),
            resolver_id: Some("resolver-a".into()),
            resolver_label: Some("Resolver A".into()),
            resolver_port: Some(53),
            resolver_transport: Some("UDP".into()),
            latency_ms: Some(23),
        }
        .normalize()
        .unwrap();
        assert_eq!(observation.answers[0].value, "mail.example.com");
        let record = observation
            .answer_records("default", "resolver-a")
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            record.canonical_rdata,
            "priority=10;target=mail.example.com"
        );
        assert_eq!(record.target_domain.as_deref(), Some("mail.example.com"));
    }

    #[test]
    fn scan_domains_require_dot_separation_and_obey_wire_limits() {
        let label_63 = "a".repeat(63);
        let maximum = format!(
            "{label_63}.{}.{}.{}",
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let oversized_name = format!(
            "{label_63}.{}.{}.{}",
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );

        assert!(canonical_scan_domain("a").is_err());
        assert_eq!(canonical_scan_domain("A.Example.").unwrap(), "a.example");
        assert_eq!(maximum.len(), 253);
        assert!(canonical_scan_domain(&maximum).is_ok());
        assert!(canonical_scan_domain(&oversized_name).is_err());
        assert!(canonical_scan_domain(&format!("{}.example", "a".repeat(64))).is_err());
        assert!(canonical_scan_domain("a.example..").is_err());
    }

    #[test]
    fn mx_identity_includes_priority() {
        let question = "mail.example.com";
        let low = DnsAnswer {
            record_type: "MX".into(),
            value: "mx.example.com".into(),
            ttl: 60,
            priority: Some(10),
            weight: None,
            port: None,
        };
        let high = DnsAnswer {
            priority: Some(20),
            ..low.clone()
        };
        assert_ne!(
            CanonicalDnsRecord::from_answer("default", "resolver-a", question, "IN", &low)
                .unwrap()
                .id,
            CanonicalDnsRecord::from_answer("default", "resolver-a", question, "IN", &high)
                .unwrap()
                .id
        );
    }
}
