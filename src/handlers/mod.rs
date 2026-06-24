pub mod data_saa; //数据统计与分析
pub mod task;
pub mod user;
pub mod utils;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct ReceiveLoginInfo {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct ResponseLoginStatus {
    pub success: bool,
    pub message: String,
}

#[derive(Deserialize)]
pub struct ScanTargetGet {
    pub scanner_id: String,
    pub test: String,
}

#[derive(Deserialize)]
pub struct ScanTargetDone {
    pub ip: String,
    pub scanner_id: String,
    pub info_count: u32,
    pub survival_ip_count: u32,
}
