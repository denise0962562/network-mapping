pub mod targetgenerated;

use serde::Serialize;

#[derive(Serialize)]
pub enum port_type {
    Vertor(Vec<u32>),
    Text(String)
}

#[derive(Serialize)]
pub struct ScanTargetGetResponse {
    pub mode: String,
    pub ip: String,
    pub port: port_type,
    pub rate: u32,
}