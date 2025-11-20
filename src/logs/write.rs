
use tracing::{info, warn, error};
use actix_web::{HttpRequest, dev::ConnectionInfo};

// use crate::logs::LogEventType;
use crate::{get_conn_ip, get_user_agent, logs::LoginLog};
//TODO:需要获取代理状态下用户的原始ip
pub fn info_logs(req: &HttpRequest, event: &str, message: &str, proxy: bool)  {

    let req_method = req.method();
    let req_path = req.path();
    let req_query = req.query_string();
    info!(
        event = event,  //"requests_received"
        client_ip = get_conn_ip(req),
        method = %req_method,
        user_agent = get_user_agent(req),
        path = req_path,
        query = req_query,
        message,
    );
}

pub fn warn_logs(req: &HttpRequest, event: &str, message: &str) {
    
    let req_method = req.method();
    let req_path = req.path();
    let req_query = req.query_string();

    warn!(
        event = event,
        client_ip = get_conn_ip(req),
        method = %req_method,
        user_agent = get_user_agent(req),
        path = req_path,
        query = req_query,
        message
    );
}

pub fn error_logs(req: &HttpRequest, event: &str, message: &str) {

    let req_method = req.method();
    let req_path = req.path();
    let req_query = req.query_string();
    error!(
        event = event,
        client_ip = get_conn_ip(req),
        method = %req_method,
        user_agent = get_user_agent(req),
        path = req_path,
        query = req_query,
        message
    );
}

/// 该函数可以把登录日志数据写入数据库，返回一个 bool , 
/// 
/// 在该函数中无需其调用者处理错误，该函数 **会自动处理错误，然后返回 bool 值**
pub async fn login_logs_to_db(
    pool: deadpool_postgres::Pool,
    log: LoginLog
) -> bool {
    let mut client = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!(
                event = "GetConnErrorFromPool",
                path = "",
                message = %e
            );
            return false
        }
    };
    let transaction = match client.transaction().await {
        Ok(t) => t,
        Err(e) => {
            error!(
                event = "OpenTransactionError",
                path = "",
                message = %e
            );
            return false
        }
    };

    // MARK 过一段时间把数据库规划好之后再来处理这
    // BUG暂时不管这里的报错，这是故意留的以提示，还要处理错误 path
    let row = match transaction.execute(
        "INSERT INTO login_logs( event_ip, event_usage_id, is_successful ) VALUES ( &1, &2, &3 );",
        &[&log.event_ip, &log.event_useage_userid, &log.is_successful]
    ).await {
        Ok(r) => r,
        Err(e) => {
            error!(
                event = "ExecuteSQLError",
                path = "",
                message = %e
            );
            return false
        }
    };

    if row > 0 {
        true
    }
    else {
        error!(
            event = "INSERTDataToDatabaseError",
            path = "",
            message = "向数据库中插入日志数据失败"
        );
        false
    }
}
