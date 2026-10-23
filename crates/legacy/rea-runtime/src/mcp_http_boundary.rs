//! Tower boundary validation for streamable HTTP requests.

use axum::{
    body::Body,
    http::{Request, Response},
};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::mcp_http_routing::validate_request_target;

/// Reject malformed Web Request inputs before they reach Axum route handlers.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestBoundaryLayer;

impl<S> Layer<S> for RequestBoundaryLayer {
    type Service = RequestBoundaryService<S>;

    fn layer(&self, service: S) -> Self::Service {
        RequestBoundaryService { service }
    }
}

pub struct RequestBoundaryService<S> {
    service: S,
}

impl<S: Clone> Clone for RequestBoundaryService<S> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
        }
    }
}

type BoxFuture<E> = Pin<Box<dyn Future<Output = Result<Response<Body>, E>> + Send>>;

impl<S, B> Service<Request<B>> for RequestBoundaryService<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<S::Error>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(context)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let method = request.method().as_str().to_owned();
        let target = request.uri().to_string();
        let mut service = self.service.clone();

        Box::pin(async move {
            match validate_request_target(&method, &target) {
                Ok(_) => service.call(request).await,
                Err(rejection) => Ok(rejection.response()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::RequestBoundaryLayer;
    use axum::{body::Body, body::to_bytes, http::Request, http::Response, http::StatusCode};
    use std::{
        convert::Infallible,
        future::{Ready, ready},
        task::{Context, Poll},
    };
    use tower::{Layer, Service, ServiceExt};

    #[derive(Clone, Copy, Debug, Default)]
    struct InnerService;

    impl Service<Request<Body>> for InnerService {
        type Response = Response<Body>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request<Body>) -> Self::Future {
            ready(Ok(Response::new(Body::from("inner"))))
        }
    }

    fn service() -> InnerService {
        InnerService
    }

    #[tokio::test]
    async fn rejects_fetch_forbidden_methods_before_the_inner_service() {
        for method in ["TRACE", "CONNECT"] {
            let mut boundary = RequestBoundaryLayer.layer(service());
            let response = boundary
                .ready()
                .await
                .unwrap()
                .call(
                    Request::builder()
                        .method(method)
                        .uri("/mcp")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(
                to_bytes(response.into_body(), usize::MAX).await.unwrap(),
                format!(
                    r#"{{"jsonrpc":"2.0","error":{{"code":-32600,"message":"Unsupported method {method}"}},"id":null}}"#
                )
            );
        }
    }

    #[tokio::test]
    async fn rejects_absolute_and_authority_targets_before_the_inner_service() {
        for target in ["https://example.test/mcp", "example.test:443"] {
            let mut boundary = RequestBoundaryLayer.layer(service());
            let response = boundary
                .ready()
                .await
                .unwrap()
                .call(
                    Request::builder()
                        .method("GET")
                        .uri(target)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                to_bytes(response.into_body(), usize::MAX).await.unwrap(),
                r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Unsupported request target"},"id":null}"#
            );
        }
    }

    #[tokio::test]
    async fn delegates_valid_origin_form_requests() {
        let mut boundary = RequestBoundaryLayer.layer(service());
        let response = boundary
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/mcp?session=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            "inner"
        );
    }
}
