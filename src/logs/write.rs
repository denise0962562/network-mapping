
use tracing::{info, warn, error};
use actix_web::{HttpRequest, dev::ConnectionInfo};

// use crate::logs::LogEventType;

//TODO:需要获取代理状态下用户的原始ip
pub fn info_logs(req: &HttpRequest, conn_info: &ConnectionInfo, event: &str, message: &str, proxy: bool)  {

    let ip = conn_info.realip_remote_addr().unwrap_or("无法获取 IP");
    let req_method = req.method().to_string();
    let req_path = req.path().to_string();
    let req_query = req.query_string().to_string();
    info!(
        event = event,  //"requests_received"
        client_ip = ip,
        method = req_method,
        user_agent = %req.headers().get("User-Agent").unwrap_or(&"".parse().unwrap()).to_str().unwrap_or("unknown"),
        path = req_path,
        query = req_query,
        message,
    );
}

pub fn warn_logs(req: &HttpRequest, conn_info: &ConnectionInfo, event: &str, message: &str) {
    
    let ip = conn_info.realip_remote_addr().unwrap_or("无法获取 IP");
    let req_method = req.method().to_string();
    let req_path = req.path().to_string();
    let req_query = req.query_string().to_string();

    warn!(
        event = event,
        client_ip = ip,
        method = req_method,
        user_agent = %req.headers().get("User-Agent").unwrap_or(&"".parse().unwrap()).to_str().unwrap_or("unknown"),
        path = req_path,
        query = req_query,
        message
    );
}

pub fn error_logs(req: &HttpRequest, conn_info: &ConnectionInfo, event: &str, message: &str) {

    let ip = conn_info.realip_remote_addr().unwrap_or("无法获取 IP");
    let req_method = req.method().to_string();
    let req_path = req.path().to_string();
    let req_query = req.query_string().to_string();
    error!(
        event = event,
        client_ip = ip,
        method = req_method,
        user_agent = %req.headers().get("User-Agent").unwrap_or(&"".parse().unwrap()).to_str().unwrap_or("unknown"),
        path = req_path,
        query = req_query,
        message
    );
}