use super::*;

#[test]
fn deterministic_id_factory_reproduces_values_from_seed() {
    let first = DeterministicIdFactory::from_seed("fnd-008-fixture").expect("factory");
    let second = DeterministicIdFactory::from_seed("fnd-008-fixture").expect("factory");
    let tenant_a = first.tenant_id("tenant-a").expect("tenant");

    assert_eq!(tenant_a.to_string(), "46ec58e4-a218-590c-b187-2c7789acb305");
    assert_eq!(tenant_a, second.tenant_id("tenant-a").expect("tenant"));
    assert_eq!(
        first.run_id("run-a").expect("run"),
        second.run_id("run-a").expect("run")
    );
    assert_ne!(
        first.run_id("run-a").expect("run"),
        first.run_id("run-b").expect("run")
    );

    let work_order = first.work_order_id("weekly-report").expect("work order");
    let other_seed = DeterministicIdFactory::from_seed("fnd-008-other").expect("factory");
    assert_eq!(
        work_order,
        second.work_order_id("weekly-report").expect("work order")
    );
    assert_ne!(
        work_order,
        other_seed
            .work_order_id("weekly-report")
            .expect("work order")
    );
    assert!(work_order.as_str().starts_with("wo_"));
}

#[test]
fn deterministic_id_factory_keeps_typed_id_domains_separate() {
    let factory = DeterministicIdFactory::from_seed("typed-separation").expect("factory");

    let tenant = factory.tenant_id("same-label").expect("tenant");
    let agent = factory.agent_id("same-label").expect("agent");
    let run = factory.run_id("same-label").expect("run");
    let trace_event = factory.trace_event_id("same-label").expect("trace");

    assert_ne!(tenant.as_uuid(), agent.as_uuid());
    assert_ne!(tenant.as_uuid(), run.as_uuid());
    assert_ne!(run.as_uuid(), trace_event.as_uuid());
    assert!(!tenant.is_nil());
    assert!(!agent.is_nil());
    assert!(!run.is_nil());
    assert!(!trace_event.is_nil());
}

#[test]
fn deterministic_id_factory_length_prefixes_components_to_avoid_delimiter_ambiguity() {
    let namespace = Uuid::parse_str("aaaaaaaa-aaaa-5aaa-aaaa-aaaaaaaaaaaa").expect("namespace");
    let domain_with_separator =
        DeterministicIdFactory::with_domain(namespace, "a:b").expect("factory");
    let type_with_separator = DeterministicIdFactory::with_domain(namespace, "a").expect("factory");

    assert_ne!(
        domain_with_separator.uuid_for("c", "d").expect("uuid"),
        type_with_separator.uuid_for("b:c", "d").expect("uuid")
    );
}

#[test]
fn deterministic_id_factory_rejects_nil_namespace_and_empty_inputs() {
    assert_eq!(
        DeterministicIdFactory::new(Uuid::nil()),
        Err(DeterminismError::NilNamespace)
    );
    assert_eq!(
        DeterministicIdFactory::from_seed("  "),
        Err(DeterminismError::Empty { field: "seed" })
    );

    let factory = DeterministicIdFactory::from_seed("invalid-inputs").expect("factory");
    assert_eq!(
        factory.uuid_for(" ", "label"),
        Err(DeterminismError::Empty { field: "id_type" })
    );
    assert_eq!(
        factory.tenant_id(" "),
        Err(DeterminismError::Empty { field: "label" })
    );
    assert_eq!(
        factory.work_order_id(" "),
        Err(DeterminismError::Empty { field: "label" })
    );
}

#[test]
fn fixed_clock_returns_the_same_timestamp() {
    let timestamp = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("timestamp");
    let clock = FixedClock::new(timestamp);

    assert_eq!(clock.now(), timestamp);
    assert_eq!(clock.now(), timestamp);
}

#[test]
fn step_clock_advances_by_the_configured_duration() {
    let start = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("timestamp");
    let mut clock = StepClock::new(start, Duration::seconds(5)).expect("clock");

    assert_eq!(clock.peek(), start);
    assert_eq!(clock.step(), Duration::seconds(5));
    assert_eq!(clock.now().expect("first tick"), start);
    assert_eq!(
        clock.now().expect("second tick"),
        start + Duration::seconds(5)
    );
    assert_eq!(clock.peek(), start + Duration::seconds(10));
}

#[test]
fn step_clock_rejects_negative_steps_and_reports_overflow() {
    let start = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("timestamp");
    assert_eq!(
        StepClock::new(start, Duration::seconds(-1)),
        Err(DeterminismError::NegativeClockStep)
    );

    let mut clock = StepClock::new(start, Duration::seconds(i64::MAX)).expect("clock");
    assert_eq!(clock.now(), Err(DeterminismError::ClockOverflow));
    assert_eq!(clock.peek(), start);
}
