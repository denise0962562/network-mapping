use std::future::{Ready, ready};
use std::sync::Arc;
use actix_web::HttpResponse;
use actix_web::{
    body::EitherBody,                // 可以参见 https://docs.rs/actix-web/latest/actix_web/body/enum.EitherBody.html
    dev::{
        forward_ready, Service, ServiceRequest, ServiceResponse, Transform
    },
    Error,
    web
};

use futures::future::LocalBoxFuture;

use crate::login::get_session_from_req;
use crate::login::{LoginToken};
use crate::logs::write::info_logs;
use tracing::{error, info};
use crate::{TemplatesInit};

use crate::middlewares::{get_pool_from_app_data, render_500, render_500_simple};

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
                                info_logs(req.request(), "InvalidSession", "数据库中未找到符合条件的 Session", false);
                                let resp = HttpResponse::Unauthorized()
                                    .body("401");
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
                        info_logs(req.request(), "InvalidSession", "未能从请求中获取到 Session", false);
                        let resp = HttpResponse::Unauthorized()
                            .body("401");
                        Ok(
                            req.into_response(resp).map_into_right_body()
                        )
                    }
                }
            }
        })
        


    }
}