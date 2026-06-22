use super::*;
use serde_json::json;
use std::collections::BTreeMap;

fn extension_map(
    entries: impl IntoIterator<Item = (&'static str, serde_json::Value)>,
) -> BTreeMap<String, serde_json::Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
}

#[test]
fn extension_key_normalization_is_canonical_across_common_variants() {
    for key in [
        "approval_token",
        "approvalToken",
        "approval-token",
        "approval token",
        "approval.token",
        "ApprovalToken",
    ] {
        assert_eq!(normalize_extension_key(key), "approval_token");
        assert!(is_reserved_extension_key(key));
    }

    assert_eq!(normalize_extension_key("api-key"), "api_key");
    assert_eq!(normalize_extension_key("APIKey"), "api_key");
    assert_eq!(normalize_extension_key("workOrder"), "work_order");
    assert_eq!(
        normalize_extension_key("driver.selection"),
        "driver_selection"
    );
    assert!(is_reserved_extension_key("api-key"));
    assert!(is_reserved_extension_key("apikey"));
    assert!(is_reserved_extension_key("workOrder"));
    assert!(is_reserved_extension_key("gateway"));
}

#[test]
fn allowed_non_authorizing_extension_metadata_validates() {
    let values = extension_map([
        (
            "x_review_hint",
            json!({
                "display": "CFO review requested",
                "diagnostics": [
                    {"label": "finance"},
                    {"external_ref": {"provider": "harmony", "reference_id": "ref_123"}}
                ]
            }),
        ),
        ("workspace_ref", json!("finance-weekly-dashboard")),
    ]);

    validate_extension_map(&values, "extensions").expect("safe metadata accepted");
}

#[test]
fn reserved_authority_key_variants_are_rejected_with_path_and_reason() {
    let cases = [
        ("approval_token", "approval_token"),
        ("approvalToken", "approval_token"),
        ("api-key", "api_key"),
        ("apikey", "apikey"),
        ("workOrder", "work_order"),
        ("driver", "driver"),
        ("gateway", "gateway"),
        ("secret", "secret"),
    ];

    for (key, normalized) in cases {
        let values = extension_map([(key, json!("must not authorize"))]);
        let error =
            validate_extension_map(&values, "extensions").expect_err("reserved keys fail closed");

        assert_eq!(error.path, format!("extensions.{key}"));
        assert_eq!(error.key, key);
        assert_eq!(error.normalized_key, normalized);
        assert_eq!(
            error.reason,
            ExtensionValidationReason::ReservedAuthorityKey
        );
    }
}

#[test]
fn nested_objects_and_arrays_are_rejected_at_the_exact_reserved_path() {
    let values = extension_map([(
        "x_future",
        json!({
            "notes": [
                {"display": "safe"},
                {"metadata": {"gateway": "bypass"}}
            ]
        }),
    )]);

    let error =
        validate_extension_map(&values, "extensions").expect_err("nested gateway key fails closed");
    assert_eq!(error.path, "extensions.x_future.notes[1].metadata.gateway");
    assert_eq!(error.key, "gateway");
    assert_eq!(
        error.reason,
        ExtensionValidationReason::ReservedAuthorityKey
    );

    let value = json!([{"label": "safe"}, {"metadata": {"secret": "no"}}]);
    let error =
        validate_extension_value(&value, "metadata").expect_err("nested array secret fails closed");
    assert_eq!(error.path, "metadata[1].metadata.secret");
    assert_eq!(error.normalized_key, "secret");
}

#[test]
fn blank_and_trimmed_extension_keys_are_rejected_recursively() {
    let blank = extension_map([(" ", json!("blank"))]);
    let error = validate_extension_map(&blank, "extensions").expect_err("blank key rejected");
    assert_eq!(error.reason, ExtensionValidationReason::BlankKey);
    assert_eq!(error.key, " ");

    let trimmed = extension_map([(" driver ", json!("padded"))]);
    let error = validate_extension_map(&trimmed, "extensions").expect_err("trimmed key rejected");
    assert_eq!(error.reason, ExtensionValidationReason::TrimmedKey);
    assert_eq!(error.normalized_key, "driver");

    let nested = json!({"items": [{" display ": "padded"}]});
    let error =
        validate_extension_value(&nested, "extensions.x").expect_err("nested trimmed key rejected");
    assert_eq!(error.path, "extensions.x.items[0]. display ");
    assert_eq!(error.reason, ExtensionValidationReason::TrimmedKey);
}

#[test]
fn context_specific_reserved_keys_can_extend_the_canonical_policy() {
    let values = extension_map([("status", json!("display-only"))]);
    validate_extension_map(&values, "extensions").expect("status is not globally reserved");

    let error = validate_extension_map_with_reserved_keys(&values, "extensions", &["status"])
        .expect_err("context-specific reserved key rejected");
    assert_eq!(error.path, "extensions.status");
    assert_eq!(
        error.reason,
        ExtensionValidationReason::ReservedAuthorityKey
    );
}
