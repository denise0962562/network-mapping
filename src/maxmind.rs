use std::net::IpAddr;
use std::path::Path;

use maxminddb::{Reader, geoip2};
use serde::Serialize;
use tracing::{error, warn};

const DEFAULT_CITY_DB: &str = "source/maxmind/GeoLite2-City.mmdb";
const DEFAULT_COUNTRY_DB: &str = "source/maxmind/GeoLite2-Country.mmdb";
const DEFAULT_ASN_DB: &str = "source/maxmind/GeoLite2-ASN.mmdb";

#[derive(Clone, Debug, Serialize, Default)]
pub struct IpIntel {
    pub asn: Option<String>,
    pub as_org: Option<String>,
    pub isp: Option<String>,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
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

impl MaxMindState {
    pub fn from_default_paths() -> Self {
        Self {
            city: open_database(DEFAULT_CITY_DB),
            country: open_database(DEFAULT_COUNTRY_DB),
            asn: open_database(DEFAULT_ASN_DB),
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> IpIntel {
        let mut intel = IpIntel::default();

        if let Some(reader) = &self.asn {
            if let Some(asn) = lookup_asn(reader, ip) {
                intel.asn = asn.autonomous_system_number.map(|n| n.to_string());
                intel.as_org = asn.autonomous_system_organization.map(str::to_string);
            }
        }

        if let Some(reader) = &self.city {
            if let Some(city) = lookup_city(reader, ip) {
                intel.country_code = city.country.iso_code.map(str::to_string);
                intel.country_name = city.country.names.english.map(str::to_string);
                intel.city_name = city.city.names.english.map(str::to_string);
                intel.latitude = city.location.latitude;
                intel.longitude = city.location.longitude;
                intel.accuracy_radius = city.location.accuracy_radius;
                intel.time_zone = city.location.time_zone.map(str::to_string);
            }
        }

        if intel.country_code.is_none() {
            if let Some(reader) = &self.country {
                if let Some(country) = lookup_country(reader, ip) {
                    intel.country_code = country.country.iso_code.map(str::to_string);
                    intel.country_name = country.country.names.english.map(str::to_string);
                }
            }
        }

        // GeoLite2-ASN does not include a dedicated ISP field. Until a GeoIP2-ISP
        // database is added, the AS organization is the closest available value.
        intel.isp = intel.as_org.clone();

        intel
    }
}

fn open_database(path: impl AsRef<Path>) -> Option<Reader<Vec<u8>>> {
    let path_ref = path.as_ref();
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
