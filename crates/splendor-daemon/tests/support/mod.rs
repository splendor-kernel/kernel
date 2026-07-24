#![allow(dead_code)]

use splendor_daemon::{ConfiguredActionAdapters, DaemonConfig, DaemonState};
use splendor_gateway::{ActionAdapter, ActionRequest, AdapterError, AdapterResult};
use splendor_store::TraceStore;
use std::sync::Arc;

struct ReceiptTestAdapter {
    adapter_id: String,
}

impl ActionAdapter for ReceiptTestAdapter {
    fn execute(&self, action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        if action.action.name == "failing_action" {
            return Err(AdapterError::Failed("fixture_adapter_failure".to_string()));
        }
        Ok(AdapterResult {
            output: serde_json::json!({
                "schema_version": "splendor.test.provider_receipt.v1",
                "provider_receipt_id": format!("test-provider:{}", action.action_id),
                "adapter_id": self.adapter_id,
                "action_id": action.action_id,
                "action_name": action.action.name,
                "accepted": true,
            }),
            satisfied_postconditions: action.action.postconditions.clone(),
        })
    }
}

pub fn action_adapters(adapter_ids: &[&str]) -> ConfiguredActionAdapters {
    let mut adapters = ConfiguredActionAdapters::new();
    for adapter_id in adapter_ids {
        adapters
            .insert(
                *adapter_id,
                Arc::new(ReceiptTestAdapter {
                    adapter_id: (*adapter_id).to_string(),
                }),
            )
            .expect("unique test action adapter identity");
    }
    adapters
}

pub fn local_state(adapter_ids: &[&str]) -> DaemonState {
    state(DaemonConfig::local_dev(), adapter_ids)
}

pub fn state(config: DaemonConfig, adapter_ids: &[&str]) -> DaemonState {
    DaemonState::with_action_adapters(config, action_adapters(adapter_ids))
}

pub fn state_with_trace_store(
    config: DaemonConfig,
    trace_store: Arc<dyn TraceStore>,
    adapter_ids: &[&str],
) -> DaemonState {
    DaemonState::with_trace_store_and_action_adapters(
        config,
        trace_store,
        action_adapters(adapter_ids),
    )
}
