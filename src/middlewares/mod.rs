use actix_web::dev::ServiceRequest;
use actix_web::{
    Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, dev::Payload,
    error::ErrorInternalServerError, web,
};
use std::future::{Ready, ready};
use tracing::error;

use crate::TEXT_HTML_UTF_8;
use crate::admin::{UserBaseI, UserSession};
use crate::{FrontEndErrorInfo, TemplatesInit, front_end_error_page, logs};

// 该中间件用于检查用户是否拥有访问权
pub mod smiddleware;
// 该中间件用于处理 HTTP 标头
pub mod hmiddleware;
// 该中间件用于处理 CSRF TOKEN
pub mod csrfmiddleware;
// 该中间件用于限制公开入口请求频率
pub mod ratelimit;

/// 该函数用于从 app_data 中获取数据库连接池
///
/// 当从 app_data 中获取到 Some 时会自动从连接池中获取一个连接，然后返回这个连接（也有可能返回的是一个向上传递的错误）
/// 但获取到 None 值时会抛出错误并写入日志
pub fn get_pool_from_app_data<'a>(
    req: &'a ServiceRequest,
) -> Result<&'a deadpool_postgres::Pool, Box<dyn std::error::Error>> {
    match req.app_data::<web::Data<deadpool_postgres::Pool>>() {
        Some(p) => Ok(p.get_ref()),
        None => {
            error!(
                event = "GetDatabasePoolErrorFromAppData", // 从 app_data 中获取数据库连接池失败
                path = "",
                message = "从 app_data 中获取数据库连接池失败，找到 None 值"
            );
            Err("从注入数据中提取失败 ".into())
        }
    }
}

/// 该函数用于生成 403 错误页面
pub fn render_403(req: &HttpRequest, page_template: &TemplatesInit, message: &str) -> HttpResponse {
    logs::write::warn_logs(req, "SessionAuthFailed", message);
    let error_info = FrontEndErrorInfo {
        status_code: 403,
        error_title: "Forbidden",
        error_message: "您已被屏蔽",
    };
    HttpResponse::Forbidden()
        .content_type(TEXT_HTML_UTF_8)
        .body(front_end_error_page(&error_info, page_template))
}

/// 该函数用于生成 500 错误页面
///
pub fn render_500(req: &HttpRequest, page_template: &TemplatesInit, message: &str) -> HttpResponse {
    logs::write::error_logs(req, "SystemError", message);
    let error_info = FrontEndErrorInfo {
        status_code: 500,
        error_title: "Internal Server Error",
        error_message: "服务器内部系统错误，别担心，这不是你的错误",
    };
    HttpResponse::InternalServerError()
        .content_type(TEXT_HTML_UTF_8)
        .body(front_end_error_page(&error_info, &page_template))
}

/// 该函数用于生成一个简单的 500 错误页面，
/// 常用于模板系统无法正常从 app_data 中加载时
pub fn render_500_simple(req: &HttpRequest, message: &str) -> HttpResponse {
    logs::write::error_logs(req, "未能正确获取到模板系统", message);
    HttpResponse::InternalServerError().body("500 Internal Server Error")
}

impl FromRequest for UserBaseI {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(result) = req.extensions().get::<UserBaseI>().cloned() {
            ready(Ok(result))
        } else {
            ready(Err(ErrorInternalServerError("500")))
        }
    }
}

impl FromRequest for UserSession {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(result) = req.extensions().get::<UserSession>().cloned() {
            ready(Ok(result))
        } else {
            ready(Err(ErrorInternalServerError("500")))
        }
    }
}
