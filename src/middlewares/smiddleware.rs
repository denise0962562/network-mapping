
use std::future::{Ready, ready};
use std::sync::Arc;
use actix_web::{
    body::EitherBody,                // 可以参见 https://docs.rs/actix-web/latest/actix_web/body/enum.EitherBody.html
    dev::{
        forward_ready, Service, ServiceRequest, ServiceResponse, Transform
    },
    Error,
    HttpResponse,
    HttpRequest,
    web
};

use futures::future::LocalBoxFuture;

use crate::login::get_session_from_req;
use crate::{TEXT_HTML_UTF_8};
use crate::login::{LoginToken};
use tracing::{error, info};
use crate::{logs, TemplatesInit};

// 导入错误模板
use crate::{front_end_error_page, FrontEndErrorInfo};

/// 用于 session 检查的中间件的 Transform
pub struct AuthMiddleware;

impl<S,B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    // 在此使用 EitherBody<B> 是为了灵活处理中间件提前返回的情况，当一个请求在中间件中提前返回时返回的数据实现了 BoxBody（自己通过 HttpResponse 构造的页面） ,
    // 但是中间件返回原本要实现泛型B(这是请求正常走时返回的)这时候就不符合 Rust 的返回单一类型，
    // 所以利用 Actix-web 提供的权举 EitherBody 实现
    // 下同

    type Response = ServiceResponse<EitherBody<B>>;     
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService { service: Arc::new(service) }))
    }
}

/// 处理请求的 Service
pub struct AuthMiddlewareService<S> {
    service: Arc<S>
}

impl<S,B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {


        // 向量 path_list 定义了需要做权限校验的路径
        let path_list = vec!["/api", "/dashboard"];
        // 白名单
        let white_path = vec!["/api/login"];
        let path = req.path().to_owned();
        let svc = self.service.clone();

        let need_check:bool;
        if white_path.iter().any(|p| p == &path) {
            need_check = false
        }
        else {
            need_check = path_list.iter().any(|p| path.starts_with(p));
        }
        // let need_check = path_list.iter().any(|p| path.starts_with(p));
        let page = req.app_data::<web::Data<TemplatesInit>>().cloned();

        info!(
            event = "received_requests",
            client_ip = &req.connection_info().realip_remote_addr().unwrap_or("Unknown IP"),
            method = &req.method().to_string(),
            user_agent = &req.headers().get("User-Agent").map(|u| u.to_str().unwrap_or("Invalid UTF-8")).unwrap_or("Unknown or None"),
            path = &req.path(),
            query = &req.query_string(),
        );


        Box::pin(async move {
            if !need_check {
                // 当请求不是以 path_list 开头则直接放行
                Ok(
                    svc.call(req).await?.map_into_left_body()
                )
            }
            
            else {
                
                let page_template = match page.as_ref() {
                    Some(p) => p.get_ref(),
                    None => {
                        let resp = render_500_simple(req.request(), "未能正确获取到模板系统");
                        return Ok(
                            req.into_response(resp).map_into_right_body()
                    )}
                };
                let session = {
                    get_session_from_req(req.request(), "session")
                };
                match session {
                    Some(se) => {
                        let g_pool = match get_pool_from_app_data(&req) {
                            Ok(p) => p,
                            Err(e) => {
                                error!(
                                    event = "",
                                    path = "",
                                    message = %e
                                );
                                let resp = render_500(req.request(), page_template, "获取数据库连接池失败");
                                return Ok(
                                    req.into_response(resp).map_into_right_body()
                                )
                            }
                        };
                        let login_t = LoginToken {
                            pool: g_pool.clone()
                        };
                        match login_t.check_token(&se).await {
                            Ok(true) => {
                                Ok(
                                    svc.call(req).await?.map_into_left_body()
                            )},
                            Ok(false) => {
                                let resp = render_403(req.request(), page_template, "数据库中未找到符合条件的 Session");
                                Ok(
                                    req.into_response(resp).map_into_right_body()
                            )},
                            Err(e) => {
                                    error!(
                                        event = "",
                                        path = "",
                                        message = %e
                                    );
                                    let resp = render_500(req.request(), page_template, "校验token出错了");
                                    return Ok(
                                        req.into_response(resp).map_into_right_body()
                                    )
                            }
                        }
                    },
                    None => {
                        let resp = render_403(req.request(), page_template, "没获取到 session");
                        Ok(
                            req.into_response(resp).map_into_right_body()
                        )
                    }
                }
            }
        })
        


    }
}

/// 该函数用于从 app_data 中获取数据库连接池
/// 
/// 当从 app_data 中获取到 Some 时会自动从连接池中获取一个连接，然后返回这个连接（也有可能返回的是一个向上传递的错误）
/// 但获取到 None 值时会抛出错误并写入日志
pub fn get_pool_from_app_data<'a>(req: &'a ServiceRequest) -> Result<&'a deadpool_postgres::Pool, Box<dyn std::error::Error>> {
    match req.app_data::<web::Data<deadpool_postgres::Pool>>() {
        Some(p) => Ok(p.get_ref()),
        None => {
            error!(
                event = "GetDatabasePoolErrorFromAppData",                 // 从 app_data 中获取数据库连接池失败
                path = "",
                message = "从 app_data 中获取数据库连接池失败，找到 None 值"
            );
            Err("从注入数据中提取失败 ".into())
        }
    }
}

/// 该函数用于生成 403 错误页面
pub fn render_403(
    req: &HttpRequest, 
    page_template: &TemplatesInit,
    message: &str
) -> HttpResponse {

    logs::write::warn_logs(req, "SessionAuthFailed", message);
    let error_info = FrontEndErrorInfo { status_code: 403, error_title: "Forbidden", error_message: "您已被屏蔽" };
    HttpResponse::Forbidden()
        .content_type(TEXT_HTML_UTF_8)
        .body(front_end_error_page(&error_info, page_template))

}

/// 该函数用于生成 500 错误页面
/// 
pub fn render_500(
    req: &HttpRequest,
    page_template: &TemplatesInit,
    message: &str
) -> HttpResponse {
    logs::write::error_logs(req, "SystemError", message);
    let error_info = FrontEndErrorInfo { status_code: 500, error_title: "Internal Server Error", error_message: "服务器内部系统错误，别担心，这不是你的错误" };
    HttpResponse::InternalServerError()
        .content_type(TEXT_HTML_UTF_8)
        .body(front_end_error_page(&error_info, &page_template))

}

/// 该函数用于生成一个简单的 500 错误页面，
/// 常用于模板系统无法正常从 app_data 中加载时
pub fn render_500_simple(
    req: &HttpRequest,
    message: &str
) -> HttpResponse {
    logs::write::error_logs(req, "未能正确获取到模板系统", message);
    HttpResponse::InternalServerError()
        .body("500 Internal Server Error")
}
