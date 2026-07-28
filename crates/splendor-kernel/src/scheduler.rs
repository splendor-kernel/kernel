//! # Scheduler
//!
//! A cooperative scheduler that executes agent loop engines in a fair queue and
//! enforces a per-tick time budget. Each scheduler cycle resets tenant quota
//! ledgers so limits apply across all agents in the tenant.

use crate::loop_engine::{LoopEngine, LoopError, TickOutcome, TICK_RECONCILIATION_REQUIRED};
use crate::tenancy::TenantRegistry;
use crate::{StateCommit, StateHandoffExportRequest, StateHandoffScope};
use splendor_store::StateMetadata;
use splendor_types::{
    ActionId, AgentId, RunId, StateHandoff, TenantId, TraceEvent, TraceEventKind,
    WorkOrderEnvelope, WorkOrderKeyring,
};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use time::OffsetDateTime;

/// Exact scheduler address for one admitted runtime context.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeTarget {
    run_id: RunId,
    tenant_id: TenantId,
    agent_id: AgentId,
}

impl RuntimeTarget {
    /// Creates an exact run/tenant/agent scheduler target.
    pub fn new(run_id: RunId, tenant_id: TenantId, agent_id: AgentId) -> Self {
        Self {
            run_id,
            tenant_id,
            agent_id,
        }
    }

    /// Run identity of the admitted runtime.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Tenant identity of the admitted runtime.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Agent identity of the admitted runtime.
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }
}

impl std::fmt::Debug for RuntimeTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeTarget")
            .finish_non_exhaustive()
    }
}

/// Scheduler configuration options.
#[derive(Clone, Debug, Default)]
pub struct SchedulerConfig {
    /// Optional per-tick time budget.
    pub tick_budget: Option<Duration>,
    /// Optional tick interval to enforce predictable boundaries.
    pub tick_interval: Option<Duration>,
}

/// Result of running a scheduler step.
#[derive(Clone, Debug)]
pub struct SchedulerStep {
    /// Tick identifier assigned by the scheduler.
    pub tick_id: u64,
    /// Exact run identifier that was executed.
    pub run_id: RunId,
    /// Exact tenant identifier that was executed.
    pub tenant_id: TenantId,
    /// Agent identifier that was executed.
    pub agent_id: AgentId,
    /// Outcome produced by the loop engine.
    pub outcome: TickOutcome,
    /// Wall-clock duration for the tick.
    pub elapsed: Duration,
}

/// Scheduler errors.
#[derive(thiserror::Error)]
pub enum SchedulerError {
    /// No agents are registered with the scheduler.
    #[error("no agents registered")]
    NoAgents,
    /// No tenant context was found for the agent.
    #[error("scheduler_tenant_unavailable")]
    MissingTenant(TenantId),
    /// No agent was found in the scheduler queue.
    #[error("scheduler_agent_unavailable")]
    MissingAgent(AgentId),
    /// Agent-only lookup had zero or multiple matches, or an exact target was absent.
    #[error("scheduler_runtime_target_unavailable")]
    RuntimeTargetUnavailable,
    /// A loop engine returned an error.
    #[error("loop engine failed: {0}")]
    Loop(#[from] LoopError),
    /// The exact run/tenant/agent identity is already admitted.
    #[error("scheduler_runtime_identity_conflict")]
    DuplicateRuntimeIdentity {
        run_id: RunId,
        tenant_id: TenantId,
        agent_id: AgentId,
    },
    /// Tick budget exceeded for the executed step.
    #[error("tick budget exceeded ({elapsed:?} > {budget:?})")]
    TickBudgetExceeded {
        /// Step that exceeded the budget.
        step: Box<SchedulerStep>,
        /// Budget configured for the scheduler.
        budget: Duration,
        /// Observed elapsed duration.
        elapsed: Duration,
    },
}

impl std::fmt::Debug for SchedulerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

/// Cooperative scheduler for agent loop engines.
pub struct Scheduler {
    config: SchedulerConfig,
    tenants: TenantRegistry,
    queue: VecDeque<LoopEngine>,
    reconciliation_queue: Vec<LoopEngine>,
    tick_id: u64,
    cycle_remaining: usize,
}

impl Scheduler {
    /// Creates a new scheduler with the provided config.
    pub fn new(config: SchedulerConfig) -> Self {
        Self::with_registry(config, TenantRegistry::new())
    }

    /// Creates a scheduler backed by an explicit tenant registry.
    pub fn with_registry(config: SchedulerConfig, registry: TenantRegistry) -> Self {
        Self {
            config,
            tenants: registry,
            queue: VecDeque::new(),
            reconciliation_queue: Vec::new(),
            tick_id: 0,
            cycle_remaining: 0,
        }
    }

    /// Returns a clone of the tenant registry.
    pub fn tenant_registry(&self) -> TenantRegistry {
        self.tenants.clone()
    }

    /// Registers a tenant context with the scheduler.
    pub fn register_tenant(&mut self, tenant: crate::TenantContext) {
        self.tenants.insert(tenant);
    }

    /// Returns tick usage for a tenant if available.
    pub fn tenant_usage(&self, tenant_id: &TenantId) -> Option<crate::QuotaUsage> {
        self.tenants
            .with_tenant(tenant_id, |tenant| tenant.tick_usage())
    }

    /// Adds a loop engine to the scheduling queue. Duplicate exact identities
    /// are rejected without admission; callers that need the typed conflict
    /// should use `try_add_agent`.
    pub fn add_agent(&mut self, engine: LoopEngine) {
        let _ = self.try_add_agent(engine);
    }

    /// Adds a loop engine unless its exact run/tenant/agent identity is already live.
    pub fn try_add_agent(&mut self, engine: LoopEngine) -> Result<(), SchedulerError> {
        let run_id = engine.run_id().clone();
        let tenant_id = engine.tenant_id().clone();
        let agent_id = engine.agent_id().clone();
        if self
            .queue
            .iter()
            .chain(self.reconciliation_queue.iter())
            .any(|admitted| admitted.has_runtime_identity(&run_id, &tenant_id, &agent_id))
        {
            return Err(SchedulerError::DuplicateRuntimeIdentity {
                run_id,
                tenant_id,
                agent_id,
            });
        }
        if let Some(last_tick_id) = engine.last_tick_id() {
            self.tick_id = self.tick_id.max(last_tick_id);
        }
        self.queue.push_back(engine);
        Ok(())
    }

    /// Records a non-tick runtime event through the target agent's trace runtime.
    pub fn record_event_for_agent(
        &self,
        agent_id: &AgentId,
        kind: TraceEventKind,
    ) -> Result<TraceEvent, SchedulerError> {
        let target = self.unique_target_for_agent(agent_id)?;
        self.record_event_for_target(&target, kind)
    }

    /// Records a non-tick runtime event through one exact runtime target.
    pub fn record_event_for_target(
        &self,
        target: &RuntimeTarget,
        kind: TraceEventKind,
    ) -> Result<TraceEvent, SchedulerError> {
        let engine = self.engine_for_target(target)?;
        engine
            .record_runtime_event(kind)
            .map_err(SchedulerError::Loop)
    }

    /// Records a non-tick action event with complete run/tenant/agent/action
    /// identity through the target agent's shared trace cursor.
    pub fn record_action_event_for_agent(
        &self,
        agent_id: &AgentId,
        action_id: &ActionId,
        kind: TraceEventKind,
    ) -> Result<TraceEvent, SchedulerError> {
        let target = self.unique_target_for_agent(agent_id)?;
        self.record_action_event_for_target(&target, action_id, kind)
    }

    /// Records an action event through one exact runtime target.
    pub fn record_action_event_for_target(
        &self,
        target: &RuntimeTarget,
        action_id: &ActionId,
        kind: TraceEventKind,
    ) -> Result<TraceEvent, SchedulerError> {
        let engine = self.engine_for_target(target)?;
        engine
            .record_runtime_action_event(action_id, kind)
            .map_err(SchedulerError::Loop)
    }

    /// Exports the target agent's current state through its owning loop engine.
    pub fn export_state_handoff_for_agent(
        &self,
        agent_id: &AgentId,
        request: StateHandoffExportRequest,
    ) -> Result<(StateHandoff, TraceEvent), SchedulerError> {
        let target = self.unique_target_for_agent(agent_id)?;
        self.export_state_handoff_for_target(&target, request)
    }

    /// Exports current state through one exact runtime target.
    pub fn export_state_handoff_for_target(
        &self,
        target: &RuntimeTarget,
        request: StateHandoffExportRequest,
    ) -> Result<(StateHandoff, TraceEvent), SchedulerError> {
        let engine = self.engine_for_target(target)?;
        engine
            .export_state_handoff(request)
            .map_err(SchedulerError::Loop)
    }

    /// Imports a handoff through the target agent's owning loop engine.
    #[allow(clippy::too_many_arguments)]
    pub fn import_state_handoff_for_agent(
        &mut self,
        agent_id: &AgentId,
        handoff: &StateHandoff,
        work_order: &WorkOrderEnvelope,
        keyring: &WorkOrderKeyring,
        scope: &StateHandoffScope,
        now: OffsetDateTime,
        metadata: StateMetadata,
    ) -> Result<(StateCommit, TraceEvent), SchedulerError> {
        let target = self.unique_target_for_agent(agent_id)?;
        self.import_state_handoff_for_target(
            &target, handoff, work_order, keyring, scope, now, metadata,
        )
    }

    /// Imports a handoff through one exact runtime target.
    #[allow(clippy::too_many_arguments)]
    pub fn import_state_handoff_for_target(
        &mut self,
        target: &RuntimeTarget,
        handoff: &StateHandoff,
        work_order: &WorkOrderEnvelope,
        keyring: &WorkOrderKeyring,
        scope: &StateHandoffScope,
        now: OffsetDateTime,
        metadata: StateMetadata,
    ) -> Result<(StateCommit, TraceEvent), SchedulerError> {
        let engine = self.engine_for_target_mut(target)?;
        engine
            .import_state_handoff(handoff, work_order, keyring, scope, now, metadata)
            .map_err(SchedulerError::Loop)
    }

    /// Runs a single agent tick.
    pub fn run_once(&mut self) -> Result<SchedulerStep, SchedulerError> {
        if self.queue.is_empty() {
            return Err(self.empty_queue_error());
        }
        self.ensure_cycle();

        let mut engine = self.queue.pop_front().expect("queue not empty");
        let tenant_id = engine.tenant_id().clone();
        if self.tenants.with_tenant(&tenant_id, |_| ()).is_none() {
            self.queue.push_back(engine);
            self.cycle_remaining = self.cycle_remaining.saturating_sub(1);
            return Err(SchedulerError::MissingTenant(tenant_id));
        }

        let start = Instant::now();
        let outcome = match engine.tick(self.tick_id) {
            Ok(outcome) => outcome,
            Err(error) => {
                if engine.requires_reconciliation() {
                    self.reconciliation_queue.push(engine);
                } else {
                    self.queue.push_back(engine);
                }
                self.cycle_remaining = self.cycle_remaining.saturating_sub(1);
                return Err(SchedulerError::Loop(error));
            }
        };
        let elapsed = start.elapsed();

        let step = SchedulerStep {
            tick_id: self.tick_id,
            run_id: engine.run_id().clone(),
            tenant_id: engine.tenant_id().clone(),
            agent_id: engine.agent_id().clone(),
            outcome,
            elapsed,
        };

        if engine.requires_reconciliation() {
            self.reconciliation_queue.push(engine);
        } else {
            self.queue.push_back(engine);
        }
        self.cycle_remaining = self.cycle_remaining.saturating_sub(1);

        if let Some(budget) = self.config.tick_budget {
            if elapsed > budget {
                return Err(SchedulerError::TickBudgetExceeded {
                    step: Box::new(step),
                    budget,
                    elapsed,
                });
            }
        }

        Ok(step)
    }

    /// Runs a full scheduler cycle (each agent once).
    pub fn run_cycle(&mut self) -> Result<Vec<SchedulerStep>, SchedulerError> {
        if self.queue.is_empty() {
            return Err(self.empty_queue_error());
        }
        let cycle_start = Instant::now();
        let remaining = self.queue.len();
        let mut steps = Vec::with_capacity(remaining);
        for _ in 0..remaining {
            steps.push(self.run_once()?);
        }
        self.enforce_tick_interval(cycle_start);
        Ok(steps)
    }

    /// Runs the scheduler for a fixed number of cycles.
    pub fn run_cycles(&mut self, cycles: u64) -> Result<Vec<SchedulerStep>, SchedulerError> {
        let mut steps = Vec::new();
        for _ in 0..cycles {
            let cycle = self.run_cycle()?;
            steps.extend(cycle);
            if !self.reconciliation_queue.is_empty() {
                return Err(SchedulerError::Loop(LoopError::Policy(
                    TICK_RECONCILIATION_REQUIRED.to_string(),
                )));
            }
        }
        Ok(steps)
    }

    /// Runs the scheduler continuously until an error occurs.
    pub fn run_forever(&mut self) -> Result<(), SchedulerError> {
        loop {
            self.run_cycle()?;
            if !self.reconciliation_queue.is_empty() {
                return Err(SchedulerError::Loop(LoopError::Policy(
                    TICK_RECONCILIATION_REQUIRED.to_string(),
                )));
            }
        }
    }

    fn ensure_cycle(&mut self) {
        if self.cycle_remaining > 0 {
            return;
        }
        self.tick_id = self.tick_id.saturating_add(1);
        let now = OffsetDateTime::now_utc();
        self.tenants.begin_tick(self.tick_id, now);
        self.cycle_remaining = self.queue.len();
    }

    fn enforce_tick_interval(&self, cycle_start: Instant) {
        if let Some(interval) = self.config.tick_interval {
            let elapsed = cycle_start.elapsed();
            if elapsed < interval {
                std::thread::sleep(interval - elapsed);
            }
        }
    }

    fn unique_target_for_agent(&self, agent_id: &AgentId) -> Result<RuntimeTarget, SchedulerError> {
        let mut matches = self
            .queue
            .iter()
            .chain(self.reconciliation_queue.iter())
            .filter(|engine| engine.agent_id() == agent_id);
        let engine = matches
            .next()
            .ok_or(SchedulerError::RuntimeTargetUnavailable)?;
        if matches.next().is_some() {
            return Err(SchedulerError::RuntimeTargetUnavailable);
        }
        Ok(RuntimeTarget::new(
            engine.run_id().clone(),
            engine.tenant_id().clone(),
            engine.agent_id().clone(),
        ))
    }

    fn engine_for_target(&self, target: &RuntimeTarget) -> Result<&LoopEngine, SchedulerError> {
        self.queue
            .iter()
            .chain(self.reconciliation_queue.iter())
            .find(|engine| {
                engine.has_runtime_identity(target.run_id(), target.tenant_id(), target.agent_id())
            })
            .ok_or(SchedulerError::RuntimeTargetUnavailable)
    }

    fn engine_for_target_mut(
        &mut self,
        target: &RuntimeTarget,
    ) -> Result<&mut LoopEngine, SchedulerError> {
        self.queue
            .iter_mut()
            .chain(self.reconciliation_queue.iter_mut())
            .find(|engine| {
                engine.has_runtime_identity(target.run_id(), target.tenant_id(), target.agent_id())
            })
            .ok_or(SchedulerError::RuntimeTargetUnavailable)
    }

    fn empty_queue_error(&self) -> SchedulerError {
        if self.reconciliation_queue.is_empty() {
            SchedulerError::NoAgents
        } else {
            SchedulerError::Loop(LoopError::Policy(TICK_RECONCILIATION_REQUIRED.to_string()))
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/scheduler_tests.rs"]
mod tests;
