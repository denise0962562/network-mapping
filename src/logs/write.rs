use actix_web::{HttpMessage, HttpRequest};
use std::error::Error as StdError;
use tracing::{error, info, warn};
use uuid::Uuid;

// use crate::logs::LogEventType;
use crate::audit::RequestId;
use crate::{get_conn_ip, get_user_agent, logs::LoginLog};

fn request_id(req: &HttpRequest) -> Uuid {
    req.extensions()
        .get::<RequestId>()
        .map(|value| value.0)
        .unwrap_or_else(Uuid::nil)
}

pub fn database_error_diagnostics(error: &tokio_postgres::Error) -> String {
    let Some(database_error) = error.as_db_error() else {
        return format!("{error:?}");
    };
    format!(
        "sqlstate={} severity={} message={} detail={} hint={} schema={} table={} column={} constraint={}",
        database_error.code().code(),
        database_error.severity(),
        database_error.message(),
        database_error.detail().unwrap_or("-"),
        database_error.hint().unwrap_or("-"),
        database_error.schema().unwrap_or("-"),
        database_error.table().unwrap_or("-"),
        database_error.column().unwrap_or("-"),
        database_error.constraint().unwrap_or("-"),
    )
}

pub fn error_chain_diagnostics(error: &(dyn StdError + 'static)) -> String {
    let mut chain = Vec::new();
    let mut current = Some(error);
    while let Some(item) = current {
        if let Some(database_error) = item.downcast_ref::<tokio_postgres::Error>() {
            chain.push(database_error_diagnostics(database_error));
        } else {
            chain.push(item.to_string());
        }
        current = item.source();
    }
    chain.dedup();
    chain.join("; caused_by=")
}

//TODO:需要获取代理状态下用户的原始ip
pub fn info_logs(req: &HttpRequest, event: &str, message: &str) {
    let req_method = req.method();
    let req_path = req.path();
    info!(
        event = event,  //"requests_received"
        client_ip = get_conn_ip(req),
        method = %req_method,
        user_agent = get_user_agent(req),
        path = req_path,
        request_id = %request_id(req),
        message,
    );
}

pub fn warn_logs(req: &HttpRequest, event: &str, message: &str) {
    let req_method = req.method();
    let req_path = req.path();
    warn!(
        event = event,
        client_ip = get_conn_ip(req),
        method = %req_method,
        user_agent = get_user_agent(req),
        path = req_path,
        request_id = %request_id(req),
        message
    );
}

pub fn error_logs(req: &HttpRequest, event: &str, message: &str) {
    let req_method = req.method();
    let req_path = req.path();
    error!(
        event = event,
        client_ip = get_conn_ip(req),
        method = %req_method,
        user_agent = get_user_agent(req),
        path = req_path,
        request_id = %request_id(req),
        message
    );
}

pub fn error_logs_error(
    req: &HttpRequest,
    event: &str,
    operation: &str,
    error_value: &(dyn StdError + 'static),
) {
    error!(
        event,
        operation,
        client_ip = get_conn_ip(req),
        method = %req.method(),
        user_agent = get_user_agent(req),
        path = req.path(),
        request_id = %request_id(req),
        message = %error_chain_diagnostics(error_value),
    );
}

/// 该函数可以把登录日志数据写入数据库，返回一个 bool ,
///
/// 在该函数中无需其调用者处理错误，该函数 **会自动处理错误，然后返回 bool 值**
pub async fn login_logs_to_db(pool: &deadpool_postgres::Pool, log: LoginLog) -> bool {
    let mut client = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!(
                event = "GetConnErrorFromPool",
                path = "fn login_logs_to_db",
                message = %e
            );
            return false;
        }
    };
    let transaction = match client.transaction().await {
        Ok(t) => t,
        Err(e) => {
            error!(
                event = "OpenTransactionError",
                path = "fn login_logs_to_db",
                message = %e
            );
            return false;
        }
    };

    // MARK 过一段时间把数据库规划好之后再来处理这
    let row = match transaction.execute(
        "INSERT INTO login_logs( event_ip, event_usage_id, is_successful ) VALUES ( $1, $2, $3 );",
        &[&log.event_ip, &log.event_useage_userid, &log.is_successful]
    ).await {
        Ok(r) => r,
        Err(e) => {
            error!(
                event = "ExecuteSQLError",
                path = "fn login_logs_to_db",
                message = %e
            );
            return false
        }
    };

    if row > 0 {
        match transaction.commit().await {
            Ok(()) => (),
            Err(e) => {
                error!(
                    event = "TransactionCommitError",
                    path = "fn login_logs_to_db",
                    message = %e
                );
                return false;
            }
        };
        true
    } else {
        error!(
            event = "INSERTDataToDatabaseError",
            path = "fn login_logs_to_db",
            message = "向数据库中插入日志数据失败"
        );
        false
    }
}

#[cfg(test)]
mod tests {
    use super::error_chain_diagnostics;
    use std::error::Error;
    use std::fmt;

    #[derive(Debug)]
    struct WrappedError(std::io::Error);

    impl fmt::Display for WrappedError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("outer operation failed")
        }
    }

    impl Error for WrappedError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn error_chain_diagnostics_includes_all_causes() {
        let error = WrappedError(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "database connection refused",
        ));

        let diagnostics = error_chain_diagnostics(&error);

        assert!(diagnostics.contains("outer operation failed"));
        assert!(diagnostics.contains("database connection refused"));
        assert!(diagnostics.contains("caused_by="));
    }
}
