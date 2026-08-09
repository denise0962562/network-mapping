use std::io;

use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};

use crate::config::TlsConfig;

pub fn build_acceptor(config: &TlsConfig) -> io::Result<SslAcceptorBuilder> {
    let mut tls = SslAcceptor::mozilla_intermediate(SslMethod::tls_server())
        .map_err(|error| io::Error::other(format!("创建 TLS 接收器失败: {error}")))?;

    tls.set_private_key_file(&config.private_key_file, SslFiletype::PEM)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "读取 TLS 私钥文件 {} 失败: {error}",
                    config.private_key_file.display()
                ),
            )
        })?;
    tls.set_certificate_chain_file(&config.certificate_chain_file)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "读取 TLS 证书链文件 {} 失败: {error}",
                    config.certificate_chain_file.display()
                ),
            )
        })?;
    tls.check_private_key().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TLS 证书与私钥不匹配: {error}"),
        )
    })?;

    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::build_acceptor;
    use crate::config::TlsConfig;
    use std::path::PathBuf;

    #[test]
    fn missing_private_key_error_contains_configured_path() {
        let config = TlsConfig {
            certificate_chain_file: PathBuf::from("missing-cert.pem"),
            private_key_file: PathBuf::from("missing-key.pem"),
        };

        let error = match build_acceptor(&config) {
            Ok(_) => panic!("missing TLS files must fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("missing-key.pem"));
    }
}
