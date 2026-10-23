//! Ordered, retryable shutdown stages for the HTTP transport.

use std::{future::Future, pin::Pin};

pub type ShutdownFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
pub type ShutdownStage = Box<dyn FnMut() -> ShutdownFuture + Send>;

/// Runs cleanup stages once, retaining the first failed stage for a later retry.
pub struct StagedShutdown {
    stages: Vec<ShutdownStage>,
    completed: Vec<bool>,
}

impl StagedShutdown {
    /// Build a shutdown plan whose stages execute in declaration order.
    pub fn new(stages: Vec<ShutdownStage>) -> Self {
        let completed = vec![false; stages.len()];
        Self { stages, completed }
    }

    /// Execute unfinished stages and stop at the first failure.
    pub async fn run(&mut self) -> Result<(), String> {
        for index in 0..self.stages.len() {
            if self.completed[index] {
                continue;
            }

            (self.stages[index])().await?;
            self.completed[index] = true;
        }

        Ok(())
    }

    /// Whether every shutdown stage has completed successfully.
    pub fn is_complete(&self) -> bool {
        self.completed.iter().all(|complete| *complete)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    use super::StagedShutdown;

    fn stage<F, Fut>(operation: F) -> super::ShutdownStage
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let mut operation = operation;
        Box::new(move || Box::pin(operation()))
    }

    #[tokio::test]
    async fn retries_the_failed_stage_without_replaying_completed_work() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let first_attempt = Arc::new(Mutex::new(0_u8));

        let first_calls = Arc::clone(&calls);
        let first_attempts = Arc::clone(&first_attempt);
        let second_calls = Arc::clone(&calls);
        let mut shutdown = StagedShutdown::new(vec![
            stage(move || {
                first_calls.lock().unwrap().push("listener");
                let mut attempts = first_attempts.lock().unwrap();
                *attempts += 1;
                let result = if *attempts == 1 {
                    Err("listener still closing".to_owned())
                } else {
                    Ok(())
                };
                async move { result }
            }),
            stage(move || {
                second_calls.lock().unwrap().push("session");
                async { Ok(()) }
            }),
        ]);

        assert_eq!(shutdown.run().await, Err("listener still closing".into()));
        assert!(!shutdown.is_complete());
        assert_eq!(*calls.lock().unwrap(), vec!["listener"]);

        assert_eq!(shutdown.run().await, Ok(()));
        assert!(shutdown.is_complete());
        assert_eq!(
            *calls.lock().unwrap(),
            vec!["listener", "listener", "session"]
        );

        assert_eq!(shutdown.run().await, Ok(()));
        assert_eq!(
            *calls.lock().unwrap(),
            vec!["listener", "listener", "session"]
        );
    }

    #[tokio::test]
    async fn an_empty_plan_is_already_complete() {
        let mut shutdown = StagedShutdown::new(Vec::new());

        assert!(shutdown.is_complete());
        assert_eq!(shutdown.run().await, Ok(()));
    }
}
