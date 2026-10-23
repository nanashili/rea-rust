//! Bounded admission for the streamable HTTP MCP transport.
//!
//! The gate is deliberately independent of router construction so callers can
//! place it at the transport boundary without changing MCP request handling.

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::{Layer, Service};

/// TypeScript's default maximum number of concurrent HTTP dispatches.
pub const DEFAULT_MAX_CONCURRENT_DISPATCHES: usize = 8;

#[derive(Clone)]
pub struct AdmissionLayer {
    permits: Arc<Semaphore>,
}

impl Default for AdmissionLayer {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONCURRENT_DISPATCHES)
    }
}

impl AdmissionLayer {
    pub fn new(max_concurrent_dispatches: usize) -> Self {
        assert!(
            max_concurrent_dispatches > 0,
            "admission capacity must be positive"
        );
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent_dispatches)),
        }
    }
}

impl<S> Layer<S> for AdmissionLayer {
    type Service = AdmissionService<S>;

    fn layer(&self, service: S) -> Self::Service {
        AdmissionService {
            service,
            permits: Arc::clone(&self.permits),
        }
    }
}

pub struct AdmissionService<S> {
    service: S,
    permits: Arc<Semaphore>,
}

impl<S: Clone> Clone for AdmissionService<S> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            permits: Arc::clone(&self.permits),
        }
    }
}

type BoxFuture<E> = Pin<Box<dyn Future<Output = Result<Response<Body>, E>> + Send>>;

impl<S, B> Service<Request<B>> for AdmissionService<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let permit = match self.permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return Box::pin(async { Ok(admission_overflow_response()) }),
        };
        let mut service = self.service.clone();
        Box::pin(async move { dispatch(service.call(request), permit).await })
    }
}

async fn dispatch<F, E>(future: F, permit: OwnedSemaphorePermit) -> Result<Response<Body>, E>
where
    F: Future<Output = Result<Response<Body>, E>>,
{
    let response = future.await?;
    Ok(hold_permit_until_body_completion(response, permit))
}

struct PermitBody {
    body: Pin<Box<Body>>,
    permit: Option<OwnedSemaphorePermit>,
}

impl HttpBody for PermitBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = self.body.as_mut().poll_frame(context);
        if matches!(result, Poll::Ready(None)) {
            self.permit.take();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

fn hold_permit_until_body_completion(
    response: Response<Body>,
    permit: OwnedSemaphorePermit,
) -> Response<Body> {
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(PermitBody {
            body: Box::pin(body),
            permit: Some(permit),
        }),
    )
}

fn admission_overflow_response() -> Response<Body> {
    crate::mcp_http_errors::json_rpc_error(
        StatusCode::SERVICE_UNAVAILABLE,
        -32000,
        "HTTP request capacity is full; retry after pending dispatches finish",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use std::{convert::Infallible, sync::Arc};

    #[test]
    fn default_capacity_matches_typescript_limit() {
        assert_eq!(DEFAULT_MAX_CONCURRENT_DISPATCHES, 8);
    }

    #[tokio::test]
    async fn rejects_second_dispatch_with_retryable_503() {
        let layer = AdmissionLayer::new(1);
        let release = Arc::new(tokio::sync::Notify::new());
        let service = tower::service_fn({
            let release = Arc::clone(&release);
            move |_request: Request<Body>| {
                let release = Arc::clone(&release);
                async move {
                    release.notified().await;
                    Ok::<_, Infallible>(Response::new(Body::from("ok")))
                }
            }
        });
        let mut admitted = layer.layer(service);
        let first = admitted.call(Request::new(Body::empty()));
        let response = admitted.call(Request::new(Body::empty())).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"HTTP request capacity is full; retry after pending dispatches finish"},"id":null}"#
        );
        release.notify_one();
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn retains_admission_until_the_response_body_is_consumed() {
        let layer = AdmissionLayer::new(1);
        let service = tower::service_fn(|_request: Request<Body>| async {
            Ok::<_, Infallible>(Response::new(Body::from("ok")))
        });
        let mut admitted = layer.layer(service);

        let first = admitted.call(Request::new(Body::empty())).await.unwrap();
        let second = admitted.call(Request::new(Body::empty())).await.unwrap();
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);

        assert_eq!(to_bytes(first.into_body(), usize::MAX).await.unwrap(), "ok");

        let third = admitted.call(Request::new(Body::empty())).await.unwrap();
        assert_eq!(third.status(), StatusCode::OK);
    }
}
