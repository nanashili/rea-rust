//! Single-client session ownership for the streamable HTTP MCP transport.
//!
//! The TypeScript transport replaces an existing session when a new client
//! initializes. RMCP's local manager intentionally supports many sessions, so
//! this wrapper serializes creation and closes the previous session first.

use futures::Stream;
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::{
        common::server_side_http::ServerSseMessage,
        streamable_http_server::{SessionId, SessionManager, session::EventStore},
    },
};
use std::{
    error::Error,
    fmt,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, Notify};

#[derive(Debug)]
pub enum SingleSessionError<E> {
    Closed,
    Draining,
    DrainTimeout { timeout: Duration },
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for SingleSessionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("MCP HTTP session manager is closed"),
            Self::Draining => formatter.write_str("MCP HTTP session is being replaced"),
            Self::DrainTimeout { timeout } => {
                write!(
                    formatter,
                    "MCP HTTP session did not drain within {timeout:?}"
                )
            }
            Self::Inner(error) => error.fmt(formatter),
        }
    }
}

impl<E: Error + 'static> Error for SingleSessionError<E> {}

struct SessionState {
    active: Option<SessionId>,
    closed: bool,
}

/// A session manager that owns at most one active MCP session.
pub struct SingleSessionManager<M> {
    inner: M,
    state: Mutex<SessionState>,
    transition: Mutex<()>,
    in_flight: Arc<AtomicUsize>,
    drain_notify: Arc<Notify>,
    transitioning: AtomicBool,
    drain_timeout: Duration,
}

impl<M: SessionManager> SingleSessionManager<M> {
    pub fn new(inner: M) -> Self {
        Self {
            inner,
            state: Mutex::new(SessionState {
                active: None,
                closed: false,
            }),
            transition: Mutex::new(()),
            in_flight: Arc::new(AtomicUsize::new(0)),
            drain_notify: Arc::new(Notify::new()),
            transitioning: AtomicBool::new(false),
            drain_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_drain_timeout(mut self, drain_timeout: Duration) -> Self {
        self.drain_timeout = drain_timeout;
        self
    }

    async fn begin_request(&self) -> Result<RequestGuard, SingleSessionError<M::Error>> {
        let state = self.state.lock().await;
        if state.closed {
            return Err(SingleSessionError::Closed);
        }
        if self.transitioning.load(Ordering::Acquire) {
            return Err(SingleSessionError::Draining);
        }
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        drop(state);
        Ok(RequestGuard {
            in_flight: Arc::clone(&self.in_flight),
            drain_notify: Arc::clone(&self.drain_notify),
        })
    }

    async fn drain_requests(&self) -> Result<(), SingleSessionError<M::Error>> {
        let deadline = self.drain_timeout;
        if self.in_flight.load(Ordering::Acquire) == 0 {
            return Ok(());
        }
        let wait = async {
            loop {
                let notified = self.drain_notify.notified();
                if self.in_flight.load(Ordering::Acquire) == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(deadline, wait)
            .await
            .map_err(|_| SingleSessionError::DrainTimeout { timeout: deadline })
    }

    fn begin_transition(&self) -> TransitionGuard<'_> {
        self.transitioning.store(true, Ordering::Release);
        TransitionGuard {
            transitioning: &self.transitioning,
        }
    }
}

struct RequestGuard {
    in_flight: Arc<AtomicUsize>,
    drain_notify: Arc<Notify>,
}

struct GuardedStream<S> {
    stream: Pin<Box<S>>,
    guard: Option<RequestGuard>,
}

impl<S> GuardedStream<S> {
    fn new(stream: S, guard: RequestGuard) -> Self {
        Self {
            stream: Box::pin(stream),
            guard: Some(guard),
        }
    }
}

impl<S: Stream> Stream for GuardedStream<S> {
    type Item = S::Item;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<<Self as Stream>::Item>> {
        let this = self.get_mut();
        match this.stream.as_mut().poll_next(context) {
            std::task::Poll::Ready(None) => {
                this.guard.take();
                std::task::Poll::Ready(None)
            }
            other => other,
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if self.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            // Retain one wake-up when the waiter has not been polled yet. This
            // avoids losing the transition's only notification between the
            // count check and registration of the wait future.
            self.drain_notify.notify_one();
        }
    }
}

struct TransitionGuard<'a> {
    transitioning: &'a AtomicBool,
}

impl Drop for TransitionGuard<'_> {
    fn drop(&mut self) {
        self.transitioning.store(false, Ordering::Release);
    }
}

impl<M> SessionManager for SingleSessionManager<M>
where
    M: SessionManager,
{
    type Error = SingleSessionError<M::Error>;
    type Transport = M::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        let _transition = self.transition.lock().await;
        if self.state.lock().await.closed {
            return Err(SingleSessionError::Closed);
        }
        let _transitioning = self.begin_transition();

        let result = async {
            let previous = self.state.lock().await.active.clone();
            if let Some(previous) = previous {
                self.inner
                    .close_session(&previous)
                    .await
                    .map_err(SingleSessionError::Inner)?;
                self.drain_requests().await?;
            }

            let (session_id, transport) = self
                .inner
                .create_session()
                .await
                .map_err(SingleSessionError::Inner)?;
            self.state.lock().await.active = Some(session_id.clone());
            Ok((session_id, transport))
        }
        .await;
        result
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        let _request = self.begin_request().await?;
        self.inner
            .initialize_session(id, message)
            .await
            .map_err(SingleSessionError::Inner)
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        self.inner
            .has_session(id)
            .await
            .map_err(SingleSessionError::Inner)
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        let _transition = self.transition.lock().await;
        let _transitioning = self.begin_transition();
        let result = async {
            self.inner
                .close_session(id)
                .await
                .map_err(SingleSessionError::Inner)?;
            self.drain_requests().await?;

            let mut state = self.state.lock().await;
            if state.active.as_ref() == Some(id) {
                state.active = None;
            }
            Ok(())
        }
        .await;
        result
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl futures::Stream<Item = ServerSseMessage> + Send + 'static, Self::Error> {
        let request = self.begin_request().await?;
        let stream = self
            .inner
            .create_stream(id, message)
            .await
            .map_err(SingleSessionError::Inner)?;
        Ok(GuardedStream::new(stream, request))
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        let _request = self.begin_request().await?;
        self.inner
            .accept_message(id, message)
            .await
            .map_err(SingleSessionError::Inner)
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl futures::Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>
    {
        let request = self.begin_request().await?;
        let stream = self
            .inner
            .create_standalone_stream(id)
            .await
            .map_err(SingleSessionError::Inner)?;
        Ok(GuardedStream::new(stream, request))
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl futures::Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>
    {
        let request = self.begin_request().await?;
        let stream = self
            .inner
            .resume(id, last_event_id)
            .await
            .map_err(SingleSessionError::Inner)?;
        Ok(GuardedStream::new(stream, request))
    }

    fn event_store(&self) -> Option<Arc<dyn EventStore>> {
        self.inner.event_store()
    }
}

impl<M: SessionManager> SingleSessionManager<M> {
    /// Stop accepting replacements and close the owned session.
    pub async fn shutdown(&self) -> Result<(), SingleSessionError<M::Error>> {
        let _transition = self.transition.lock().await;
        self.state.lock().await.closed = true;
        let _transitioning = self.begin_transition();

        let result = async {
            let Some(active) = self.state.lock().await.active.clone() else {
                return Ok(());
            };
            self.inner
                .close_session(&active)
                .await
                .map_err(SingleSessionError::Inner)?;
            self.drain_requests().await?;
            self.state.lock().await.active = None;
            Ok(())
        }
        .await;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::SingleSessionManager;
    use rmcp::transport::streamable_http_server::session::{
        SessionManager, local::LocalSessionManager,
    };
    use std::time::Duration;

    #[tokio::test]
    async fn creating_a_session_closes_the_previous_session() {
        let manager = SingleSessionManager::new(LocalSessionManager::default());

        let (first, _) = manager.create_session().await.unwrap();
        assert!(manager.has_session(&first).await.unwrap());

        let (second, _) = manager.create_session().await.unwrap();
        assert_ne!(first, second);
        assert!(!manager.has_session(&first).await.unwrap());
        assert!(manager.has_session(&second).await.unwrap());
    }

    #[tokio::test]
    async fn shutdown_closes_the_session_and_rejects_replacement() {
        let manager = SingleSessionManager::new(LocalSessionManager::default());
        let (session, _) = manager.create_session().await.unwrap();

        manager.shutdown().await.unwrap();

        assert!(!manager.has_session(&session).await.unwrap());
        assert!(matches!(
            manager.create_session().await,
            Err(super::SingleSessionError::Closed)
        ));
    }

    #[tokio::test]
    async fn shutdown_reports_a_drain_timeout_and_can_be_retried() {
        let manager = SingleSessionManager::new(LocalSessionManager::default())
            .with_drain_timeout(Duration::from_millis(1));
        let (_session, _) = manager.create_session().await.unwrap();
        let request = manager.begin_request().await.unwrap();

        assert!(matches!(
            manager.shutdown().await,
            Err(super::SingleSessionError::DrainTimeout { .. })
        ));

        drop(request);
        manager.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_replacement_does_not_leave_the_manager_stuck_draining() {
        let manager = SingleSessionManager::new(LocalSessionManager::default())
            .with_drain_timeout(Duration::from_secs(1));
        let (_session, _) = manager.create_session().await.unwrap();
        let request = manager.begin_request().await.unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(5), manager.create_session())
                .await
                .is_err()
        );

        drop(request);
        let (replacement, _) = manager.create_session().await.unwrap();
        assert!(manager.has_session(&replacement).await.unwrap());
    }

    #[tokio::test]
    async fn pending_stream_keeps_replacement_drain_owned_until_drop() {
        let manager = SingleSessionManager::new(LocalSessionManager::default())
            .with_drain_timeout(Duration::from_millis(1));
        let request = manager.begin_request().await.unwrap();
        let pending = super::GuardedStream::new(futures::stream::pending::<()>(), request);

        assert!(matches!(
            manager.drain_requests().await,
            Err(super::SingleSessionError::DrainTimeout { .. })
        ));
        drop(pending);
        manager.drain_requests().await.unwrap();
    }

    #[tokio::test]
    async fn zero_drain_timeout_still_completes_when_no_request_is_active() {
        let manager = SingleSessionManager::new(LocalSessionManager::default())
            .with_drain_timeout(Duration::ZERO);

        manager.drain_requests().await.unwrap();
    }
}
