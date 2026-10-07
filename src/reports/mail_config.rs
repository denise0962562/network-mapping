use deadpool_postgres::{GenericClient, Pool};
use serde::{Deserialize, Serialize};

pub const NAMESPACE: &str = "report_mail";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReportMailConfig {
    pub public_base_url: String,
    pub remote_images_enabled: bool,
    pub image_lifetime_days: i32,
    pub scanner_row_limit: usize,
}

impl Default for ReportMailConfig {
    fn default() -> Self {
        Self {
            public_base_url: String::new(),
            remote_images_enabled: false,
            image_lifetime_days: 365,
            scanner_row_limit: 20,
        }
    }
}

impl ReportMailConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=3650).contains(&self.image_lifetime_days) {
            return Err("图片有效期必须在 1 至 3650 天之间".into());
        }
        if !(1..=100).contains(&self.scanner_row_limit) {
            return Err("邮件扫描器展示数量必须在 1 至 100 之间".into());
        }
        if self.public_base_url.is_empty() {
            if self.remote_images_enabled {
                return Err("启用远程图片前请设置平台外部 HTTPS 地址".into());
            }
            return Ok(());
        }
        let url = reqwest::Url::parse(&self.public_base_url)
            .map_err(|_| "平台外部地址必须是有效的 HTTPS URL")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || self.public_base_url.trim() != self.public_base_url
        {
            return Err("平台外部地址须使用 HTTPS，且不能包含凭证、查询参数或片段".into());
        }
        // Keep the deployment prefix intact and reject ambiguous path normalization.
        if self.public_base_url.contains(['\\', '\r', '\n'])
            || self
                .public_base_url
                .split('/')
                .any(|s| s == "." || s == "..")
        {
            return Err("平台外部地址包含无效路径".into());
        }
        Ok(())
    }

    pub fn url(&self, path: &str) -> String {
        if self.public_base_url.is_empty() {
            String::new()
        } else {
            format!(
                "{}/{}",
                self.public_base_url.trim_end_matches('/'),
                path.trim_start_matches('/')
            )
        }
    }
}

/// Read the authoritative document for every generation/send, including other instances.
pub async fn load<C: GenericClient + Sync>(client: &C) -> Result<ReportMailConfig, String> {
    let row = client
        .query_opt(
            "SELECT document FROM runtime_configuration WHERE namespace = $1",
            &[&NAMESPACE],
        )
        .await
        .map_err(|e| e.to_string())?;
    let config: ReportMailConfig = match row {
        Some(row) => serde_json::from_value(row.get("document")).map_err(|e| e.to_string())?,
        None => Default::default(),
    };
    config.validate()?;
    Ok(config)
}

pub async fn refresh(
    pool: &Pool,
    runtime: &crate::runtime_config::RuntimeConfig<ReportMailConfig>,
) -> Result<(), String> {
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let row = client
        .query_one(
            "SELECT document, revision FROM runtime_configuration WHERE namespace = $1",
            &[&NAMESPACE],
        )
        .await
        .map_err(|e| e.to_string())?;
    let config: ReportMailConfig =
        serde_json::from_value(row.get("document")).map_err(|e| e.to_string())?;
    config.validate()?;
    runtime.replace(config, row.get("revision")).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_external_url_and_preserves_deployment_prefix() {
        let mut config = ReportMailConfig::default();
        assert!(config.validate().is_ok());
        for url in [
            "http://example.invalid",
            "https://u:p@example.invalid",
            "https://example.invalid/?a=1",
            "https://example.invalid/#x",
            " https://example.invalid",
            "https://example.invalid/../nm",
        ] {
            config.public_base_url = url.into();
            assert!(config.validate().is_err(), "{url}");
        }
        config.public_base_url = "https://example.invalid/nm/".into();
        config.remote_images_enabled = true;
        assert!(config.validate().is_ok());
        assert_eq!(
            config.url("/reports/123"),
            "https://example.invalid/nm/reports/123"
        );
        config.public_base_url.clear();
        assert!(config.validate().is_err());
    }
}
