use crate::target_generated::ScanTargetGetResponse;
use actix_web::web;
use rand::Rng;

pub fn sequence_generate_target() -> web::Json<ScanTargetGetResponse> {
    let mut rng = rand::rng();
    web::Json(ScanTargetGetResponse {
        mode: "SCAN".to_string(),
        ip: format!(
            "{}.{}.{}.0/24",
            rng.random_range(1..=255),
            rng.random_range(0..=255),
            rng.random_range(0..=255)
        ),
        port: "1-65535".to_string(),
        rate: 1000,
        source_port: 61000,
    })
}

pub fn random_generate_target() -> web::Json<ScanTargetGetResponse> {
    let mut rng = rand::rng();
    web::Json(ScanTargetGetResponse {
        mode: "SCAN".to_string(),
        ip: format!(
            "{}.{}.{}.0/24",
            rng.random_range(1..=255),
            rng.random_range(0..=255),
            rng.random_range(0..=255)
        ),
        port: "1-65535".to_string(),
        rate: 1000,
        source_port: 61000,
    })
}
