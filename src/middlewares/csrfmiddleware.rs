use std::{
    future::{Ready, ready},
    sync::Arc,
};
use tracing::error;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::logs::write::warn_logs;
use crate::{
    frontend::is_frontend_resource_path,
    middlewares::{ExpectedCsrfToken, get_pool_from_app_data, is_scanner_api_request},
};

use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
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
        let path = req.path().to_owned();
        let csrf_protected_get = matches!(
            path.as_str(),
            "/logout" | "/api/totp/bind" | "/api/updaterir"
        );
        let safe_method = matches!(req.method().as_str(), "GET" | "HEAD") && !csrf_protected_get;
        let pass = is_scanner_api_request(req.method(), &path)
            || is_frontend_resource_path(&path)
            || safe_method;

        Box::pin(async move {
            // 扫描器接口、前端资源和无副作用的 GET/HEAD 请求无需 CSRF 校验。
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

            let tmp_csrf_token_base64 = match req.headers().get("X-CSRF-Token") {
                Some(t_base64) => t_base64.to_str().unwrap_or(""),
                None => {
                    let user = req.extensions().get::<UserBaseI>().cloned();
                    let mut audit_event = match user.as_ref() {
                        Some(user) => {
                            AuditEvent::user("authorization", "auth.csrf_rejected", "denied", user)
                        }
                        None => {
                            AuditEvent::anonymous("authorization", "auth.csrf_rejected", "denied")
                        }
                    };
                    audit_event.response_status = Some(403);
                    audit_event.reason_code = Some("missing_csrf_token".to_owned());
                    if let Ok(pool) = get_pool_from_app_data(&req) {
                        write_standalone(
                            pool,
                            &AuditContext::from_request(req.request()),
                            &audit_event,
                        )
                        .await;
                    } else {
                        error!(event = "CsrfAuditError", message = "数据库连接池不可用");
                    }
                    warn_logs(req.request(), "CSRFTokenError", "未获取到 CSRF Token");
                    let resp = HttpResponse::Forbidden().body("403");
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };

            let csrf_valid = req
                .extensions()
                .get::<ExpectedCsrfToken>()
                .is_some_and(|expected| expected.matches(tmp_csrf_token_base64));
            if csrf_valid {
                Ok(svc.call(req).await?.map_into_left_body())
            } else {
                let user = req.extensions().get::<UserBaseI>().cloned();
                let mut audit_event = match user.as_ref() {
                    Some(user) => {
                        AuditEvent::user("authorization", "auth.csrf_rejected", "denied", user)
                    }
                    None => AuditEvent::anonymous("authorization", "auth.csrf_rejected", "denied"),
                };
                audit_event.response_status = Some(403);
                audit_event.reason_code = Some("invalid_csrf_token".to_owned());
                if let Ok(pool) = get_pool_from_app_data(&req) {
                    write_standalone(
                        pool,
                        &AuditContext::from_request(req.request()),
                        &audit_event,
                    )
                    .await;
                } else {
                    error!(event = "CsrfAuditError", message = "数据库连接池不可用");
                }
                let resp = HttpResponse::Forbidden().body("403");
                Ok(req.into_response(resp).map_into_right_body())
            }
        })
    }
}
