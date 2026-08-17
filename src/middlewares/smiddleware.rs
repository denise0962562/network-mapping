use actix_web::{
    Error,
    body::EitherBody, // 可以参见 https://docs.rs/actix-web/latest/actix_web/body/enum.EitherBody.html
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
};
use actix_web::{HttpMessage, HttpResponse, http::header};
use std::future::{Ready, ready};
use std::sync::Arc;

use futures::future::LocalBoxFuture;

use crate::admin::{UserSession, get_user_base_info};
use crate::login::LoginToken;
use crate::login::get_session_from_req;
use tracing::{debug, error};

use crate::audit::{AuditContext, AuditEvent, RequestId, write_standalone};
use crate::frontend::{FrontendAssets, is_protected_frontend_path};
use crate::middlewares::{get_pool_from_app_data, is_scanner_api_path};
use uuid::Uuid;

/// 用于 session 检查的中间件的 Transform
pub struct AuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
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
        ready(Ok(AuthMiddlewareService {
            service: Arc::new(service),
        }))
    }
}

/// 处理请求的 Service
pub struct AuthMiddlewareService<S> {
    service: Arc<S>,
}

fn unauthorized_response(frontend_page: bool) -> HttpResponse {
    if frontend_page {
        HttpResponse::Found()
            .insert_header((header::LOCATION, "/login"))
            .finish()
    } else {
        HttpResponse::Unauthorized().body("401")
    }
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
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
        let request_id = req
            .extensions()
            .get::<RequestId>()
            .map(|value| value.0)
            .unwrap_or_else(Uuid::new_v4);
        req.extensions_mut().insert(RequestId(request_id));
        // 向量 path_list 定义了需要做权限校验的路径
        let path_list = ["/api", "/dashboard", "/logout"];
        let path = req.path().to_owned();
        let svc = self.service.clone();

        let frontend_page =
            matches!(req.method().as_str(), "GET" | "HEAD") && is_protected_frontend_path(&path);
        let frontend_page_available = !frontend_page
            || req
                .app_data::<actix_web::web::Data<FrontendAssets>>()
                .map(|assets| assets.has_page_for_path(&path))
                .unwrap_or(true);
        let need_check = path != "/api/login"
            && !is_scanner_api_path(&path)
            && ((frontend_page && frontend_page_available)
                || path_list.iter().any(|prefix| path.starts_with(prefix)));

        debug!(
            event = "received_requests",
            client_ip = &req
                .connection_info()
                .realip_remote_addr()
                .unwrap_or("Unknown IP"),
            method = &req.method().to_string(),
            user_agent = &req
                .headers()
                .get("User-Agent")
                .map(|u| u.to_str().unwrap_or("Invalid UTF-8"))
                .unwrap_or("Unknown or None"),
            path = &req.path(),
            request_id = %request_id,
        );

        Box::pin(async move {
            if !need_check {
                // 当请求不是以 path_list 开头则直接放行
                return Ok(svc.call(req).await?.map_into_left_body());
            }

            let session = match get_session_from_req(req.request(), "session") {
                Some(se) => se,
                None => {
                    if let Ok(pool) = get_pool_from_app_data(&req) {
                        let mut audit_event = AuditEvent::anonymous(
                            "authentication",
                            "auth.session_rejected",
                            "denied",
                        );
                        audit_event.response_status = Some(401);
                        audit_event.reason_code = Some("missing_session".to_owned());
                        write_standalone(
                            pool,
                            &AuditContext::from_request(req.request()),
                            &audit_event,
                        )
                        .await;
                    }
                    debug!(
                        event = "InvalidSession",
                        reason = "missing_session_cookie",
                        method = %req.method(),
                        path = req.path(),
                        request_id = %request_id,
                        "request rejected because no session cookie was provided",
                    );
                    let resp = unauthorized_response(frontend_page);
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };

            let g_pool = match get_pool_from_app_data(&req) {
                Ok(p) => p,
                Err(e) => {
                    error!(
                        event = "GetPoolError",
                        path = "fn call",
                        message = %e
                    );
                    let resp = HttpResponse::InternalServerError().finish();
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };
            let login_t = LoginToken {
                pool: g_pool.clone(),
            };

            let v_csrf_token = path != "/api/totp/verify" && !is_scanner_api_path(&path);

            match login_t.check_token(&session, v_csrf_token).await {
                Ok((true, uid)) => {
                    let tmp_info = match get_user_base_info(g_pool, uid).await {
                        Ok(o) => o,
                        Err(e) => {
                            error!(
                                event = "GetUserBaseInfoError",
                                path = "fn call",
                                message = e.to_string()
                            );
                            let res = HttpResponse::InternalServerError().finish();
                            return Ok(req.into_response(res).map_into_right_body());
                        }
                    };

                    // 向通过检查的请求注入用户基础数据
                    req.extensions_mut().insert(tmp_info);

                    // 向通过检查的请求注入 session ，这样就不需要在每个 handler 中都读取一个 session 了
                    req.extensions_mut()
                        .insert(UserSession { session: session });

                    Ok(svc.call(req).await?.map_into_left_body())
                }
                Ok((false, _)) => {
                    let mut audit_event =
                        AuditEvent::anonymous("authentication", "auth.session_rejected", "denied");
                    audit_event.response_status = Some(401);
                    audit_event.reason_code = Some("invalid_or_expired_session".to_owned());
                    write_standalone(
                        g_pool,
                        &AuditContext::from_request(req.request()),
                        &audit_event,
                    )
                    .await;
                    debug!(
                        event = "InvalidSession",
                        reason = "invalid_or_expired_session",
                        method = %req.method(),
                        path = req.path(),
                        request_id = %request_id,
                        "request rejected because the session is invalid or expired",
                    );
                    let resp = unauthorized_response(frontend_page);
                    Ok(req.into_response(resp).map_into_right_body())
                }
                Err(e) => {
                    error!(
                        event = "TokenVerifyError",
                        path = "fn call",
                        message = %e
                    );
                    let resp = HttpResponse::InternalServerError().finish();
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            }
        })
    }
}
