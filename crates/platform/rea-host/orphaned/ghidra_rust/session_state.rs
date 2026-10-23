//! Explicit lifecycle state for one Rust Ghidra worker session.
//!
//! The process owner and transport remain responsible for I/O.  This module
//! owns the state transitions that make a session safe to reuse: a worker is
//! opened once, its inventory identity is frozen, and close is terminal.

use crate::ghidra_rust::protocol::{WorkerInfo, WorkerProtocolError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    Created,
    Opened,
    Checkpointed,
    Closed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GhidraRustSessionState {
    phase: SessionPhase,
    target_sha256: Option<String>,
    inventory_sha256: Option<String>,
    worker_identity: Option<WorkerInfo>,
    info: Option<WorkerInfo>,
}

impl GhidraRustSessionState {
    pub fn new() -> Self {
        Self {
            phase: SessionPhase::Created,
            target_sha256: None,
            inventory_sha256: None,
            worker_identity: None,
            info: None,
        }
    }

    pub fn phase(&self) -> &SessionPhase {
        &self.phase
    }

    pub fn info(&self) -> Option<&WorkerInfo> {
        self.info.as_ref()
    }

    pub fn worker_identity(&self) -> Option<&WorkerInfo> {
        self.worker_identity.as_ref()
    }

    pub fn target_sha256(&self) -> Option<&str> {
        self.target_sha256.as_deref()
    }

    pub fn inventory_sha256(&self) -> Option<&str> {
        self.inventory_sha256.as_deref()
    }

    pub fn config_identity(&self) -> Option<&str> {
        self.info.as_ref().map(|info| info.config_identity.as_str())
    }

    /// Record the unprepared worker identity returned before `open`.
    ///
    /// The TypeScript session validates this reply before opening the target,
    /// then requires the prepared reply to retain the same worker profile and
    /// configuration.  Keeping that identity separately from prepared `info`
    /// preserves the distinction between worker readiness and target state.
    pub fn accept_worker_identity(
        &mut self,
        info: WorkerInfo,
    ) -> Result<(), WorkerProtocolError> {
        self.require_phase(SessionPhase::Created, "record worker identity")?;
        if self.worker_identity.is_some() {
            return Err(WorkerProtocolError::Malformed(
                "worker identity was already recorded for this session".into(),
            ));
        }
        if info.inventory_frozen {
            return Err(WorkerProtocolError::Malformed(
                "initial worker identity unexpectedly froze the inventory".into(),
            ));
        }

        self.worker_identity = Some(info);
        Ok(())
    }

    /// Record the reply to `open` after validating that its identity is
    /// complete and that the inventory is frozen for this target.
    pub fn accept_open(
        &mut self,
        info: WorkerInfo,
        target_sha256: &str,
    ) -> Result<(), WorkerProtocolError> {
        self.require_phase(SessionPhase::Created, "open")?;
        if let Some(expected) = self.worker_identity.as_ref() {
            Self::require_static_identity(&info, expected)?;
        }
        info.require_target(target_sha256)?;
        if !info.inventory_frozen {
            return Err(WorkerProtocolError::Malformed(
                "worker open reply did not freeze the inventory".into(),
            ));
        }
        Self::require_complete_inventory(&info)?;
        let inventory_sha256 = info.inventory_sha256.clone().ok_or_else(|| {
            WorkerProtocolError::Malformed(
                "worker open reply omitted the frozen inventory identity".into(),
            )
        })?;

        self.phase = SessionPhase::Opened;
        self.target_sha256 = Some(target_sha256.to_owned());
        self.inventory_sha256 = Some(inventory_sha256);
        self.info = Some(info);
        Ok(())
    }

    pub fn accept_observation(&self, info: &WorkerInfo) -> Result<(), WorkerProtocolError> {
        self.require_open_phase("observe")?;
        self.require_matching_identity(info)
    }

    pub fn accept_checkpoint(&mut self, info: &WorkerInfo) -> Result<(), WorkerProtocolError> {
        self.require_open_phase("checkpoint")?;
        self.require_matching_identity(info)?;
        self.phase = SessionPhase::Checkpointed;
        self.info = Some(info.clone());
        Ok(())
    }

    pub fn accept_close(&mut self, info: Option<&WorkerInfo>) -> Result<(), WorkerProtocolError> {
        match self.phase {
            // Closing an unprepared session is valid: the TypeScript owner
            // releases an absent worker channel after startup/open failure.
            SessionPhase::Created | SessionPhase::Opened | SessionPhase::Checkpointed => {}
            _ => return Err(self.invalid_transition("close")),
        }
        if let Some(info) = info {
            self.require_matching_identity(info)?;
            self.info = Some(info.clone());
        }
        self.phase = SessionPhase::Closed;
        Ok(())
    }

    fn require_matching_identity(&self, info: &WorkerInfo) -> Result<(), WorkerProtocolError> {
        let target = self.target_sha256.as_deref().ok_or_else(|| {
            WorkerProtocolError::Malformed("session has no opened target identity".into())
        })?;
        let inventory = self.inventory_sha256.as_deref().ok_or_else(|| {
            WorkerProtocolError::Malformed("session has no frozen inventory identity".into())
        })?;
        Self::require_frozen_inventory(info)?;
        info.require_target(target)?;
        info.require_inventory(inventory)?;

        let expected = self.info.as_ref().ok_or_else(|| {
            WorkerProtocolError::Malformed("session has no opened worker identity".into())
        })?;
        Self::require_profile_identity(info, expected)?;
        Ok(())
    }

    fn require_profile_identity(
        observed: &WorkerInfo,
        expected: &WorkerInfo,
    ) -> Result<(), WorkerProtocolError> {
        Self::require_static_identity(observed, expected)?;

        if observed.total != expected.total {
            return Err(WorkerProtocolError::Malformed(
                "worker inventory count changed during the session".into(),
            ));
        }
        Ok(())
    }

    fn require_static_identity(
        observed: &WorkerInfo,
        expected: &WorkerInfo,
    ) -> Result<(), WorkerProtocolError> {
        if observed.engine != expected.engine
            || observed.provider != expected.provider
            || observed.worker_protocol_version != expected.worker_protocol_version
            || observed.worker_protocol_name != expected.worker_protocol_name
            || observed.cache_id != expected.cache_id
            || observed.snapshot_schema != expected.snapshot_schema
            || observed.worker_sha256 != expected.worker_sha256
            || observed.config_identity != expected.config_identity
            || observed.memory_limit_mib != expected.memory_limit_mib
            || observed.timeout_ms != expected.timeout_ms
            || observed.capabilities != expected.capabilities
        {
            return Err(WorkerProtocolError::Malformed(
                "worker profile identity changed during the session".into(),
            ));
        }
        Ok(())
    }

    fn require_frozen_inventory(info: &WorkerInfo) -> Result<(), WorkerProtocolError> {
        if !info.inventory_frozen {
            return Err(WorkerProtocolError::Malformed(
                "worker observation did not preserve the frozen inventory".into(),
            ));
        }
        Self::require_complete_inventory(info)
    }

    fn require_complete_inventory(info: &WorkerInfo) -> Result<(), WorkerProtocolError> {
        let indexed_functions = info.indexed_functions.ok_or_else(|| {
            WorkerProtocolError::Malformed(
                "worker open reply omitted the indexed function count".into(),
            )
        })?;
        let total = info.total.ok_or_else(|| {
            WorkerProtocolError::Malformed("worker open reply omitted the function count".into())
        })?;
        if indexed_functions != total {
            return Err(WorkerProtocolError::Malformed(
                "worker open reply reported an incomplete function inventory".into(),
            ));
        }
        if info.preparation.is_none() {
            return Err(WorkerProtocolError::Malformed(
                "worker open reply omitted the preparation identity".into(),
            ));
        }
        Ok(())
    }

    fn require_phase(
        &self,
        expected: SessionPhase,
        operation: &str,
    ) -> Result<(), WorkerProtocolError> {
        if self.phase == expected {
            return Ok(());
        }
        Err(self.invalid_transition(operation))
    }

    fn require_open_phase(&self, operation: &str) -> Result<(), WorkerProtocolError> {
        match self.phase {
            SessionPhase::Opened | SessionPhase::Checkpointed => Ok(()),
            _ => Err(self.invalid_transition(operation)),
        }
    }

    fn invalid_transition(&self, operation: &str) -> WorkerProtocolError {
        WorkerProtocolError::Malformed(format!(
            "cannot {operation} Rust Ghidra session in {:?} phase",
            self.phase
        ))
    }
}

impl Default for GhidraRustSessionState {
    fn default() -> Self {
        Self::new()
    }
}
