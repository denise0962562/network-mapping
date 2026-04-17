use std::{future::{Ready, ready}, sync::Arc};
use tracing::error;
use openssl::base64;

use crate::{TemplatesInit, logs::write::{error_logs, info_logs}, middlewares::{get_pool_from_app_data, render_500, render_500_simple}};
use crate::logs::write::warn_logs;

use actix_web::{
    Error, HttpResponse, body::EitherBody, dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready}, http::{StatusCode, header}, web
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
        ready(Ok(CsrfMiddlewareService { service: Arc::new(service) }))
    }
}

pub struct CsrfMiddlewareService<S> {
    service: Arc<S>,  // Arc 使得 async move 块可以持有其引用
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


        let service = Arc::clone(&self.service);
        

        Box::pin(async move {

            if req.method().as_str() == "GET" {
                return Ok(service.call(req).await?.map_into_left_body())
            }

            let page = match req.app_data::<web::Data<TemplatesInit>>() {
                Some(s) => s.get_ref().clone(),
                None => {
                    let res = render_500_simple(req.request(), "模板加载错误");
                    return Ok(
                        req.into_response(res).map_into_right_body()
                    )
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
                    return Ok(
                        req.into_response(resp).map_into_right_body()
                    )
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
                    return Ok(
                        req.into_response(resp).map_into_right_body()
                    )
                }
            };


            if req.method().as_str() == "POST" && req.path() == "/api/login" {
                let t_req = Arc::clone(&self.service);
                let mut res = service.call(req).await?;
                
                // 拦截响应，根据响应注入 CSRF Token
                let tmp_status = res.response().status().as_u16();
                if tmp_status == 401 {
                    return Ok(
                        res.map_into_left_body()
                    )
                }

                else if tmp_status == 200 {

                    let mut csrf_buffer: [u8; 256] = [0; 256];
                    match openssl::rand::rand_bytes(&mut csrf_buffer) {
                        Ok(_) => (),
                        Err(e) => {
                            error_logs(res.request(), "GenerateCSRFTokenError", &e.to_string());
                            let resp = HttpResponse::InternalServerError().body("500");
                            // res.response_mut().head_mut().status = StatusCode::INTERNAL_SERVER_ERROR;
                            return Ok(
                                res.map_into_left_body()
                            )
                        }
                    };
                    let csrf_base64 = base64::encode_block(&csrf_buffer);

                    match client.execute(
                        "INSERT INTO csrftoken (token) VALUES ($1);",
                        &[&csrf_base64]
                    ).await {
                        Ok(_) => (),
                        Err(e) => {
                            error_logs(req.request(), "InsertCSRFTokenError", &e.to_string());
                            let resp = render_500(req.request(), &page, "InsertCSRFTokenError");
                            return Ok(
                                req.into_response(resp).map_into_right_body()
                            )
                        }
                    };

                    match header::HeaderValue::from_str(&csrf_base64) {
                        Ok(v) => {
                            res.headers_mut().insert(
                                header::HeaderName::from_static("X-CSRF-Token"),
                                v
                            );
                        },
                        Err(e) => {
                            error_logs(req.request(), "InsertCSRFTokenError", &e.to_string());
                            let resp = HttpResponse::InternalServerError().body("500");
                            return Ok(
                                req.into_response(resp).map_into_right_body()
                            )
                        }
                    }

                    return Ok(
                        res.map_into_left_body()
                    )
                }
                else {
                    return Ok(res.map_into_left_body())
                }
            }

            let tmp_csrf_token_base64 = match req.headers().get("X-CSRF-Token") {
                Some(t_bytes) => base64::encode_block(t_bytes.as_bytes()),
                None => {
                    warn_logs(req.request(), "CSRFTokenError", "未获取到 CSRF Token");
                    let resp = HttpResponse::Forbidden().body("403");
                    return Ok(
                        req.into_response(resp).map_into_right_body()
                    )
                }
            };
            

            

            // BUG 需要校验该 csrftoken是否于其session对应
            // let (t_csrftoken_id, t_user_id, t_session_id) = match client.query_opt(
            //         "SELECT id, user_id, session_id FROM csrftoken WHERE token = $1 AND is_enable = true;",
            //         &[&tmp_csrf_token_base64]
            //     ).await? {
            //         Some(r) => {
            //             (r.get::<_, i32>("id"), r.get::<_, i32>("user_id"), r.get::<_, i32>("session_id"))
            //         },
            //         None => {
            //             info_logs(req.request(), "CSRFTokenInvalid", "CSRFToken 无效", false);
            //             let resp = HttpResponse::Forbidden().body("403");
            //             return Ok(
            //                 req.into_response(resp).map_into_right_body()
            //             )
            //         }
            // };

            // BUG 需要校验该 csrftoken是否于其session对应
            // match client.query_opt(
            //         "SELECT id, user_id, session_id FROM csrftoken WHERE token = $1 AND is_enable = true;",
            //         &[&tmp_csrf_token_base64]
            //     ).await? {
            //         Some(r) => {
            //             return Ok(
            //                 self.service.call(req).await?.map_into_left_body()
            //             )
            //         },
            //         None => {
            //             info_logs(req.request(), "CSRFTokenInvalid", "CSRFToken 无效", false);
            //             let resp = HttpResponse::Forbidden().body("403");
            //             return Ok(
            //                 req.into_response(resp).map_into_right_body()
            //             )
            //         }
            // };

            let t = match client.query_opt(
                "SELECT id, user_id, session_id FROM csrftoken WHERE token = $1 AND is_enable = true;",
                &[&tmp_csrf_token_base64]
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
                Some(_) => Ok(self.service.call(req).await?.map_into_left_body()),
                None => {
                    let resp = HttpResponse::Forbidden().body("403");
                    return Ok(
                        req.into_response(resp).map_into_right_body()
                    )
                }
            }

            // if let Some(tmp_row) = match client.query_opt(
            //     "SELECT id, user_id, session_id FROM csrftoken WHERE token = $1 AND is_enable = true;",
            //     &[&tmp_csrf_token_base64]
            // ).await {
            //     Ok(o) => o,
            //     Err(e) => {
            //         error!(
            //             event = "DatabaseSELETEError",
            //             path = "csrfmiddleware -> fn call",
            //             message = %e
            //         );
            //         let resp = HttpResponse::InternalServerError().body("500 Internal Server Error");
            //         return Ok(
            //             req.into_response(resp).map_into_right_body()
            //         )
            //     }
            // } {
            //     return Ok(
            //         self.service.call(req).await?.map_into_left_body()
            //     )
            // }
            // else {
            //     info_logs(req.request(), "CSRFTokenInvalid", "CSRFToken 无效", false);
            //     let resp = HttpResponse::Forbidden().body("403");
            //     return Ok(
            //         req.into_response(resp).map_into_right_body()
            //     )
            // }
            

            // 处理下发
            
        })
    }
}