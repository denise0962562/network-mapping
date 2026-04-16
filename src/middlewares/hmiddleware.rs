use std::future::{ready, Ready};

use actix_web::{
    Error, dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready}, http::header
};
use futures_util::future::LocalBoxFuture;

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct SHeaderM;

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for SHeaderM
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SHeaderMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SHeaderMiddleware { service }))
    }
}

pub struct SHeaderMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SHeaderMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {

        let fut = self.service.call(req);

        Box::pin(async move {

            // 可以在此之前拦截请求

            let mut res = fut.await?;
            
            // 在此拦截响应

            res.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                header::HeaderValue::from_static("default-src \'self\'")
            );
            Ok(res)
        })
    }
}