pub mod targetgenerated;

use serde::Serialize;

// #[derive(Serialize)]
// pub enum port_type {
//     Vertor(Vec<u32>),
//     Text(String)
// }

#[derive(Serialize)]
pub struct ScanTargetGetResponse {
    pub mode: String,
    pub ip: String,
    pub port: String,
    pub rate: u32,
    pub source_port: u16
}