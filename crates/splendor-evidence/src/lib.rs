//! Compatibility owner for stable trace validation, recovery selection, and
//! redacted inspection.
//!
//! This crate is intentionally a narrow RFC 0015 compatibility slice. Storage
//! engines remain in `splendor-store`; this crate owns the stable event-profile
//! semantics used by the kernel, daemon, CLI, and inspect-only replay paths.

mod trace_compat;

pub use trace_compat::{
    acquire_current_trace_writer, append_stable_trace_event, inspect_durable_action_history,
    inspect_trace, open_trace_reader, project_trace, project_trace_range, resume_trace,
    DurableActionHistoryDisposition, DurableActionHistorySource, InspectTraceResult,
    ResumeTraceResult, TraceCompatibilityError, TraceProjection,
};

#[cfg(test)]
#[path = "../tests/unit/trace_compat_tests.rs"]
mod tests;
