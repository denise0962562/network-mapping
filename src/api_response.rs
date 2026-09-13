use std::future::{Ready, ready};

use actix_web::{
    Error, HttpMessage, HttpRequest, HttpResponse,
    body::{BoxBody, MessageBody, to_bytes_limited},
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::{StatusCode, header},
    web::Bytes,
};
use futures_util::future::LocalBoxFuture;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::audit::RequestId;

const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const MAX_PUBLIC_MESSAGE_CHARS: usize = 256;

/// Normalizes every API 4xx/5xx response into the public error contract.
///
/// Existing 4xx business fields are retained, but implementation diagnostics are removed.
/// Unexpected 5xx bodies are replaced completely so database/downstream errors cannot leak.
pub struct ApiErrorMiddleware;

impl<S, B> Transform<S, ServiceRequest> for ApiErrorMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = ApiErrorMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ApiErrorMiddlewareService { service }))
    }
}

pub struct ApiErrorMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for ApiErrorMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let future = self.service.call(req);
        Box::pin(async move {
            let response = future.await?;
            let status = response.status();
            let path = response.request().path();
            if !is_api_path(path) || !(status.is_client_error() || status.is_server_error()) {
                return Ok(response.map_into_boxed_body());
            }

            let request_id = response
                .request()
                .extensions()
                .get::<RequestId>()
                .map(|value| value.0)
                .or_else(|| {
                    response
                        .request()
                        .headers()
                        .get("X-Request-ID")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| Uuid::parse_str(value).ok())
                })
                .unwrap_or_else(Uuid::new_v4);

            let (request, response) = response.into_parts();
            let (mut response, body) = response.into_parts();
            let original = match to_bytes_limited(body, MAX_ERROR_BODY_BYTES).await {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(_)) | Err(_) => Bytes::new(),
            };
            let body = normalize_error_body(status, &original, request_id);

            response.headers_mut().remove(header::CONTENT_LENGTH);
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json; charset=utf-8"),
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );

            Ok(ServiceResponse::new(
                request,
                response.set_body(body).map_into_boxed_body(),
            ))
        })
    }
}

pub fn error_response(
    req: &HttpRequest,
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> HttpResponse {
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|value| value.0)
        .unwrap_or_else(Uuid::new_v4);
    HttpResponse::build(status)
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(json!({
            "success": false,
            "code": code,
            "message": message,
            "request_id": request_id,
        }))
}

fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/") || path == "/logout"
}

fn normalize_error_body(status: StatusCode, original: &[u8], request_id: Uuid) -> Bytes {
    let parsed = serde_json::from_slice::<Value>(original).ok();
    let maintenance = status == StatusCode::SERVICE_UNAVAILABLE
        && parsed
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|body| body.get("code"))
            .and_then(Value::as_str)
            == Some("system_maintenance");

    let mut body = if status.is_server_error() && !maintenance {
        Map::new()
    } else {
        match parsed {
            Some(Value::Object(body)) => body,
            _ => Map::new(),
        }
    };

    // These keys are reserved for internal diagnostics and must never cross the API boundary.
    for key in ["detail", "debug", "trace", "stack", "cause", "error"] {
        body.remove(key);
    }

    body.insert("success".to_owned(), Value::Bool(false));
    body.insert(
        "code".to_owned(),
        Value::String(
            body.get("code")
                .and_then(Value::as_str)
                .filter(|_| !status.is_server_error() || maintenance)
                .unwrap_or_else(|| default_code(status))
                .to_owned(),
        ),
    );

    let message = if maintenance {
        "系统维护中，请稍后重试".to_owned()
    } else if status.is_server_error()
        || matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
    {
        default_message(status).to_owned()
    } else {
        body.get("message")
            .and_then(Value::as_str)
            .map(bound_public_message)
            .filter(|message| !message.is_empty())
            .unwrap_or_else(|| default_message(status).to_owned())
    };
    body.insert("message".to_owned(), Value::String(message));
    body.insert(
        "request_id".to_owned(),
        Value::String(request_id.to_string()),
    );

    Bytes::from(
        serde_json::to_vec(&Value::Object(body)).expect("JSON value serialization cannot fail"),
    )
}

fn bound_public_message(message: &str) -> String {
    message
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_PUBLIC_MESSAGE_CHARS)
        .collect()
}

fn default_code(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "authentication_required",
        StatusCode::FORBIDDEN => "access_denied",
        StatusCode::NOT_FOUND => "resource_not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::UNPROCESSABLE_ENTITY => "validation_failed",
        StatusCode::TOO_MANY_REQUESTS => "rate_limit_exceeded",
        StatusCode::SERVICE_UNAVAILABLE => "service_unavailable",
        status if status.is_server_error() => "internal_server_error",
        _ => "request_failed",
    }
}

fn default_message(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "请求参数无效",
        StatusCode::UNAUTHORIZED => "身份验证失败或登录已过期",
        StatusCode::FORBIDDEN => "没有权限执行此操作",
        StatusCode::NOT_FOUND => "请求的资源不存在",
        StatusCode::CONFLICT => "请求与当前资源状态冲突",
        StatusCode::PAYLOAD_TOO_LARGE => "请求内容过大",
        StatusCode::UNPROCESSABLE_ENTITY => "请求内容校验失败",
        StatusCode::TOO_MANY_REQUESTS => "请求过于频繁，请稍后重试",
        StatusCode::SERVICE_UNAVAILABLE => "服务暂时不可用，请稍后重试",
        status if status.is_server_error() => "服务器暂时无法处理请求",
        _ => "请求失败",
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{
        App, HttpResponse, error::ErrorInternalServerError, http::StatusCode, test::TestRequest,
        web,
    };
    use serde_json::{Value, json};
    use uuid::Uuid;

    use super::{ApiErrorMiddleware, normalize_error_body};

    fn normalize(status: StatusCode, value: Value) -> Value {
        serde_json::from_slice(&normalize_error_body(
            status,
            &serde_json::to_vec(&value).unwrap(),
            Uuid::nil(),
        ))
        .unwrap()
    }

    #[test]
    fn legacy_plain_forbidden_becomes_public_contract() {
        let value: Value = serde_json::from_slice(&normalize_error_body(
            StatusCode::FORBIDDEN,
            b"403",
            Uuid::nil(),
        ))
        .unwrap();
        assert_eq!(value["success"], false);
        assert_eq!(value["code"], "access_denied");
        assert_eq!(value["message"], "没有权限执行此操作");
        assert_eq!(value["request_id"], Uuid::nil().to_string());
    }

    #[test]
    fn internal_error_diagnostics_are_discarded() {
        let value = normalize(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"message": "password=secret", "detail": "SQLSTATE 42P01"}),
        );
        assert_eq!(value["code"], "internal_server_error");
        assert_eq!(value["message"], "服务器暂时无法处理请求");
        assert!(value.get("detail").is_none());
        assert!(!value.to_string().contains("secret"));
        assert!(!value.to_string().contains("42P01"));
    }

    #[test]
    fn client_business_fields_are_preserved_but_diagnostics_are_removed() {
        let value = normalize(
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({
                "code": "SEARCH_SYNTAX_ERROR",
                "message": "缺少右括号",
                "position": 12,
                "detail": "parser state"
            }),
        );
        assert_eq!(value["code"], "SEARCH_SYNTAX_ERROR");
        assert_eq!(value["message"], "缺少右括号");
        assert_eq!(value["position"], 12);
        assert!(value.get("detail").is_none());
    }

    #[test]
    fn maintenance_contract_keeps_retry_metadata() {
        let value = normalize(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "success": false,
                "code": "system_maintenance",
                "maintenance": {"retry_after_seconds": 600}
            }),
        );
        assert_eq!(value["code"], "system_maintenance");
        assert_eq!(value["maintenance"]["retry_after_seconds"], 600);
        assert_eq!(value["message"], "系统维护中，请稍后重试");
    }

    #[actix_web::test]
    async fn framework_error_response_is_normalized_without_leaking_details() {
        let app = actix_web::test::init_service(App::new().wrap(ApiErrorMiddleware).route(
            "/api/failure",
            web::get().to(|| async {
                Err::<&'static str, _>(ErrorInternalServerError(
                    "database password=secret connection failed",
                ))
            }),
        ))
        .await;
        let response = actix_web::test::call_service(
            &app,
            TestRequest::get().uri("/api/failure").to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let body = actix_web::test::read_body(response).await;
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], "internal_server_error");
        assert!(!value.to_string().contains("secret"));
        assert!(Uuid::parse_str(value["request_id"].as_str().unwrap()).is_ok());
    }

    #[actix_web::test]
    async fn legacy_plain_forbidden_response_is_normalized_at_the_api_boundary() {
        let app = actix_web::test::init_service(App::new().wrap(ApiErrorMiddleware).route(
            "/api/legacy",
            web::get().to(|| async { HttpResponse::Forbidden().body("403") }),
        ))
        .await;
        let response =
            actix_web::test::call_service(&app, TestRequest::get().uri("/api/legacy").to_request())
                .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json; charset=utf-8"
        );
        let body = actix_web::test::read_body(response).await;
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["success"], false);
        assert_eq!(value["code"], "access_denied");
        assert_eq!(value["message"], "没有权限执行此操作");
    }
}
