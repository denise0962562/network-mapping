use std::net::IpAddr;
use std::path::{Path, PathBuf};

use maxminddb::{Reader, geoip2};
use serde::Serialize;
use tracing::{error, warn};

use crate::cli_progress::{NoopProgressReporter, ProgressReporter, ProgressUpdate};

const CITY_DB: &str = "GeoLite2-City.mmdb";
const COUNTRY_DB: &str = "GeoLite2-Country.mmdb";
const ASN_DB: &str = "GeoLite2-ASN.mmdb";
const REFRESH_BATCH_SIZE: i64 = 500;

#[derive(Clone, Debug, Serialize, Default)]
pub struct IpIntel {
    pub asn: Option<String>,
    pub as_org: Option<String>,
    pub isp: Option<String>,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub region_name: Option<String>,
    pub city_name: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub accuracy_radius: Option<u16>,
    pub time_zone: Option<String>,
}

pub struct MaxMindState {
    city: Option<Reader<Vec<u8>>>,
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

#[derive(Debug, Default)]
pub struct RefreshIpIntelReport {
    pub scanned: usize,
    pub updated: usize,
    pub unmatched: usize,
}

impl MaxMindState {
    pub fn from_directory(directory: impl AsRef<Path>) -> Self {
        let directory = directory.as_ref();
        Self {
            city: open_database(directory.join(CITY_DB)),
            country: open_database(directory.join(COUNTRY_DB)),
            asn: open_database(directory.join(ASN_DB)),
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> IpIntel {
        let mut intel = IpIntel::default();

        if let Some(reader) = &self.asn
            && let Some(asn) = lookup_asn(reader, ip)
        {
            intel.asn = asn.autonomous_system_number.map(|n| n.to_string());
            intel.as_org = asn.autonomous_system_organization.map(str::to_string);
        }

        if let Some(reader) = &self.city
            && let Some(city) = lookup_city(reader, ip)
        {
            intel.country_code = city.country.iso_code.map(str::to_string);
            intel.country_name = city.country.names.english.map(str::to_string);
            intel.region_name = city
                .subdivisions
                .first()
                .and_then(|subdivision| subdivision.names.english)
                .map(str::to_string);
            intel.city_name = city.city.names.english.map(str::to_string);
            intel.latitude = city.location.latitude;
            intel.longitude = city.location.longitude;
            intel.accuracy_radius = city.location.accuracy_radius;
            intel.time_zone = city.location.time_zone.map(str::to_string);
        }

        if (intel.country_code.is_none() || intel.country_name.is_none())
            && let Some(reader) = &self.country
            && let Some(country) = lookup_country(reader, ip)
        {
            if intel.country_code.is_none() {
                intel.country_code = country.country.iso_code.map(str::to_string);
            }
            if intel.country_name.is_none() {
                intel.country_name = country.country.names.english.map(str::to_string);
            }
        }

        // GeoLite2-ASN does not include a dedicated ISP field. Until a GeoIP2-ISP
        // database is added, the AS organization is the closest available value.
        intel.isp = intel.as_org.clone();

        intel
    }

    pub async fn refresh_ip_intel(
        &self,
        pool: &deadpool_postgres::Pool,
    ) -> Result<RefreshIpIntelReport, Box<dyn std::error::Error + Send + Sync>> {
        self.refresh_ip_intel_with_progress(pool, &NoopProgressReporter)
            .await
    }

    pub async fn refresh_ip_intel_with_progress(
        &self,
        pool: &deadpool_postgres::Pool,
        reporter: &dyn ProgressReporter,
    ) -> Result<RefreshIpIntelReport, Box<dyn std::error::Error + Send + Sync>> {
        if self.city.is_none() && self.country.is_none() && self.asn.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "没有可用的 MaxMind 数据库",
            )
            .into());
        }

        let mut client = pool.get().await?;
        let expected_total = if reporter.is_enabled() {
            reporter.report(ProgressUpdate::phase("正在统计历史 IP 记录"));
            let total: i64 = client
                .query_one("SELECT COUNT(*)::BIGINT AS total FROM ips;", &[])
                .await?
                .get("total");
            Some(u64::try_from(total)?)
        } else {
            None
        };
        let mut report = RefreshIpIntelReport::default();
        let mut last_ip_id = 0_i32;
        reporter.report(ProgressUpdate::count(
            "刷新 IP 情报",
            0,
            expected_total,
            "条",
            "更新 0 条，无匹配 0 条",
        ));

        loop {
            let rows = client
                .query(
                    "SELECT ip_id, host(ip_address) AS ip FROM ips \
                     WHERE ip_id > $1 ORDER BY ip_id LIMIT $2;",
                    &[&last_ip_id, &REFRESH_BATCH_SIZE],
                )
                .await?;
            if rows.is_empty() {
                break;
            }

            let transaction = client.transaction().await?;
            for row in rows {
                let ip_id: i32 = row.get("ip_id");
                let ip: std::net::IpAddr = row.get::<_, String>("ip").parse()?;
                let intel = self.lookup(ip);
                report.scanned += 1;
                last_ip_id = ip_id;

                if !intel.has_persisted_data() {
                    report.unmatched += 1;
                    continue;
                }

                transaction
                    .execute(
                        "UPDATE ips SET \
                         asn = COALESCE($2, asn), isp = COALESCE($3, isp), \
                         as_org = COALESCE($4, as_org), \
                         country_code = COALESCE($5, country_code), \
                         country_name = COALESCE($6, country_name), \
                         region_name = COALESCE($7, region_name), \
                         city_name = COALESCE($8, city_name), \
                         latitude = COALESCE($9, latitude), \
                         longitude = COALESCE($10, longitude), \
                         update_time = (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT \
                         WHERE ip_id = $1;",
                        &[
                            &ip_id,
                            &intel.asn,
                            &intel.isp,
                            &intel.as_org,
                            &intel.country_code,
                            &intel.country_name,
                            &intel.region_name,
                            &intel.city_name,
                            &intel.latitude,
                            &intel.longitude,
                        ],
                    )
                    .await?;
                report.updated += 1;
            }
            transaction.commit().await?;
            reporter.report(ProgressUpdate::count(
                "刷新 IP 情报",
                report.scanned as u64,
                expected_total,
                "条",
                format!("更新 {} 条，无匹配 {} 条", report.updated, report.unmatched),
            ));
        }

        Ok(report)
    }
}

impl IpIntel {
    fn has_persisted_data(&self) -> bool {
        self.asn.is_some()
            || self.as_org.is_some()
            || self.country_code.is_some()
            || self.country_name.is_some()
            || self.region_name.is_some()
            || self.city_name.is_some()
            || self.latitude.is_some()
            || self.longitude.is_some()
    }
}

fn open_database(path: PathBuf) -> Option<Reader<Vec<u8>>> {
    let path_ref = path.as_path();
    match Reader::open_readfile(path_ref) {
        Ok(reader) => Some(reader),
        Err(e) => {
            warn!(
                event = "MaxMindOpenDatabaseError",
                path = %path_ref.display(),
                message = %e
            );
            None
        }
    }
}

fn lookup_asn(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Option<geoip2::Asn<'_>> {
    let result = reader.lookup(ip).ok()?;
    match result.decode::<geoip2::Asn>() {
        Ok(record) => record,
        Err(e) => {
            error!(event = "MaxMindDecodeAsnError", ip = %ip, message = %e);
            None
        }
    }
}

fn lookup_city(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Option<geoip2::City<'_>> {
    let result = reader.lookup(ip).ok()?;
    match result.decode::<geoip2::City>() {
        Ok(record) => record,
        Err(e) => {
            error!(event = "MaxMindDecodeCityError", ip = %ip, message = %e);
            None
        }
    }
}

fn lookup_country(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Option<geoip2::Country<'_>> {
    let result = reader.lookup(ip).ok()?;
    match result.decode::<geoip2::Country>() {
        Ok(record) => record,
        Err(e) => {
            error!(event = "MaxMindDecodeCountryError", ip = %ip, message = %e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::IpIntel;

    #[test]
    fn persisted_data_detection_ignores_unused_geo_fields() {
        let only_time_zone = IpIntel {
            time_zone: Some("Asia/Shanghai".to_owned()),
            ..IpIntel::default()
        };
        let with_country = IpIntel {
            country_code: Some("CN".to_owned()),
            ..IpIntel::default()
        };
        let with_region = IpIntel {
            region_name: Some("Hubei".to_owned()),
            ..IpIntel::default()
        };
        let with_coordinates = IpIntel {
            latitude: Some(30.5928),
            longitude: Some(114.3055),
            ..IpIntel::default()
        };

        assert!(!only_time_zone.has_persisted_data());
        assert!(with_country.has_persisted_data());
        assert!(with_region.has_persisted_data());
        assert!(with_coordinates.has_persisted_data());
    }
}
