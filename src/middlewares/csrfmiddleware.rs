use std::{
    future::{Ready, ready},
    sync::Arc,
};
use tracing::error;

use crate::logs::write::warn_logs;
use crate::{
    TemplatesInit,
    middlewares::{get_pool_from_app_data, render_500, render_500_simple},
};

use actix_web::{
    Error, HttpResponse,
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    web,
};
use futures_util::future::LocalBoxFuture;

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct CsrfMiddleware;

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for CsrfMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = CsrfMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        // 用 Arc 包裹 service，使其可以安全地在 async 块中使用
        ready(Ok(CsrfMiddlewareService {
            service: Arc::new(service),
        }))
    }
}

pub struct CsrfMiddlewareService<S> {
    service: Arc<S>, // Arc 使得 async move 块可以持有其引用
}

impl<S, B> Service<ServiceRequest> for CsrfMiddlewareService<S>
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
        let svc = self.service.clone();
        let no_ckeck_csrft = vec!["/api/scanner/register", "/api/scanner/result"];
        let path = req.path().to_owned();

        let pass = no_ckeck_csrft.iter().any(|p| &path == p);

        Box::pin(async move {
            // 如果路径是扫描器相关直接放行
            if pass {
                return Ok(svc.call(req).await?.map_into_left_body());
            }

            // MARK: 对 GET 请求也校验 csrf token
            // if req.method().as_str() == "GET" {
            //     return Ok(svc.call(req).await?.map_into_left_body())
            // }
            if req.method().as_str() == "POST" && &req.path().to_string() == "/api/login" {
                return Ok(svc.call(req).await?.map_into_left_body());
            }

            let page = match req.app_data::<web::Data<TemplatesInit>>() {
                Some(s) => s.get_ref().clone(),
                None => {
                    let res = render_500_simple(req.request(), "模板加载错误");
                    return Ok(req.into_response(res).map_into_right_body());
                }
            };

            let p = match get_pool_from_app_data(&req) {
                Ok(o) => o,
                Err(e) => {
                    let resp = render_500(req.request(), &page, "获取连接池错误");
                    error!(
                        event = "GetPoolError",
                        path = "csrfmiddleware -> fn call",
                        message = %e
                    );
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };

            let client = match p.get().await {
                Ok(o) => o,
                Err(e) => {
                    let resp = render_500(req.request(), &page, "从连接池中获取连接错误");
                    error!(
                        event = "GetClienFromPooltError",
                        path = "csrfmiddleware -> fn call",
                        message = %e
                    );
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };

            let tmp_csrf_token_base64 = match req.headers().get("X-CSRF-Token") {
                Some(t_base64) => t_base64.to_str().unwrap_or(""),
                None => {
                    warn_logs(req.request(), "CSRFTokenError", "未获取到 CSRF Token");
                    let resp = HttpResponse::Forbidden().body("403");
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };

            let tmp_session = req
                .request()
                .cookie("session")
                .map(|t| t.value().to_string())
                .unwrap_or(format!(""));

            let t = match client.query_opt(
                "SELECT user_id, id FROM session WHERE is_enable = true AND token = $1 AND csrf_token = $2;",
                &[&tmp_session, &tmp_csrf_token_base64]
            ).await {
                Ok(o) => o,
                Err(e) => {
                    error!(
                        event = "DatabaseSELETEError",
                        path = "csrfmiddleware -> fn call",
                        message = %e
                    );
                    let resp = HttpResponse::InternalServerError().body("500 Internal Server Error");
                    return Ok(
                        req.into_response(resp).map_into_right_body()
                    )
                }
            };

            match t {
                Some(_) => Ok(svc.call(req).await?.map_into_left_body()),
                None => {
                    let resp = HttpResponse::Forbidden().body("403");
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            }
        })
    }
}
