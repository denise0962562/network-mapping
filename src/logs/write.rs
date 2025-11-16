
use tracing::{info, warn, error};
use actix_web::{HttpRequest, dev::ConnectionInfo};

// use crate::logs::LogEventType;
use crate::{get_conn_ip, get_user_agent};
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