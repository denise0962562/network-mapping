use std::{
    future::{Ready, ready},
    rc::Rc,
};

use actix_web::{
    Error, HttpMessage,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    web,
};
use futures_util::future::LocalBoxFuture;

use crate::{client_ip::ResolvedClientIp, trusted_proxy::TrustedProxyState};

/// Resolves the client address once before rate limiting, authentication, and request logging.
#[derive(Clone)]
pub struct ClientIpMiddleware {
    trusted_proxies: web::Data<TrustedProxyState>,
}

impl ClientIpMiddleware {
    pub fn new(trusted_proxies: web::Data<TrustedProxyState>) -> Self {
        Self { trusted_proxies }
    }
}

impl<S, B> Transform<S, ServiceRequest> for ClientIpMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = ClientIpMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ClientIpMiddlewareService {
            service: Rc::new(service),
            trusted_proxies: self.trusted_proxies.clone(),
        }))
    }
}

pub struct ClientIpMiddlewareService<S> {
    service: Rc<S>,
    trusted_proxies: web::Data<TrustedProxyState>,
}

impl<S, B> Service<ServiceRequest> for ClientIpMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let trusted_proxies = self.trusted_proxies.clone();

        Box::pin(async move {
            let address = trusted_proxies.client_ip(req.request()).await;
            req.extensions_mut().insert(ResolvedClientIp(address));
            service.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{App, HttpRequest, HttpResponse, test as actix_test, web};
    use serde_json::json;

    use super::ClientIpMiddleware;
    use crate::{audit::AuditContext, client_ip::request_ip, trusted_proxy::TrustedProxyState};

    fn trusted_proxy_state(cidrs: &[&str]) -> web::Data<TrustedProxyState> {
        let settings = serde_json::from_value(json!({
            "trustedProxyCidrs": cidrs,
            "clientIpHeader": "x-forwarded-for"
        }))
        .unwrap();
        web::Data::new(TrustedProxyState::new(settings).unwrap())
    }

    async fn resolved_address(request: HttpRequest) -> HttpResponse {
        let address = request_ip(&request);
        assert_eq!(AuditContext::from_request(&request).source_ip, address);
        HttpResponse::Ok().body(
            address
                .map(|address| address.to_string())
                .unwrap_or_default(),
        )
    }

    #[actix_web::test]
    async fn trusted_ipv6_loopback_resolves_forwarded_client() {
        let app = actix_test::init_service(
            App::new()
                .wrap(ClientIpMiddleware::new(trusted_proxy_state(&["::1/128"])))
                .default_service(web::to(resolved_address)),
        )
        .await;
        let request = actix_test::TestRequest::get()
            .uri("/")
            .peer_addr("[::1]:443".parse().unwrap())
            .insert_header(("x-forwarded-for", "203.0.113.19"))
            .to_request();

        let body = actix_test::call_and_read_body(&app, request).await;
        assert_eq!(body, "203.0.113.19");
    }

    #[actix_web::test]
    async fn untrusted_peer_cannot_spoof_forwarded_client() {
        let app = actix_test::init_service(
            App::new()
                .wrap(ClientIpMiddleware::new(trusted_proxy_state(&[
                    "127.0.0.1/32",
                ])))
                .default_service(web::to(resolved_address)),
        )
        .await;
        let request = actix_test::TestRequest::get()
            .uri("/")
            .peer_addr("198.51.100.8:443".parse().unwrap())
            .insert_header(("x-forwarded-for", "203.0.113.19"))
            .to_request();

        let body = actix_test::call_and_read_body(&app, request).await;
        assert_eq!(body, "198.51.100.8");
    }
}
