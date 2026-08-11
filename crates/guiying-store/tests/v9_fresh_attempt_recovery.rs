use guiying_store::{
    compute_capability_profile_hash, CapabilityProfileInput, FreshAttemptRecoveryQuery,
    FreshAttemptRecoverySelection, MountSessionKey, NamespaceProfileInput, NamespaceProfileKey,
    NewBoundScanRun, NewScopedScanJob, RootObjectSignature, RootScopeKey, RunEvidenceGuard,
    ScanAttemptStrategy, StablePathKey, Store, StoreError, VolumeInput,
};
use rusqlite::{params, Connection, TransactionBehavior};
use serde_json::json;
use std::path::Path;
use tempfile::TempDir;

const APPLICATION_ID: i32 = 0x4755_5949;

const PRE_V9_MIGRATIONS: [(&str, &str); 8] = [
    (
        "initial_data_model",
        include_str!("../src/migrations/0001_init.sql"),
    ),
    (
        "store_runtime",
        include_str!("../src/migrations/0002_store_runtime.sql"),
    ),
    (
        "store_hardening",
        include_str!("../src/migrations/0003_store_hardening.sql"),
    ),
    (
        "evidence_binding",
        include_str!("../src/migrations/0004_evidence_binding.sql"),
    ),
    (
        "session_bound_evidence",
        include_str!("../src/migrations/0005_session_bound_evidence.sql"),
    ),
    (
        "runtime_stream_evidence",
        include_str!("../src/migrations/0006_runtime_stream_evidence.sql"),
    ),
    (
        "capture_time_evidence",
        include_str!("../src/migrations/0007_capture_time_evidence.sql"),
    ),
    (
        "runtime_control",
        include_str!("../src/migrations/0008_runtime_control.sql"),
    ),
];

#[derive(Debug, Clone, Copy)]
struct StableScope {
    volume_id: i64,
    namespace_profile_id: i64,
    capability_profile_id: i64,
    mount_session_key: MountSessionKey,
    stable_root_path_key: StablePathKey,
    root_scope_key: RootScopeKey,
}

#[derive(Debug, Clone, Copy)]
struct RunningAttempt {
    job_id: i64,
    run_id: i64,
    guard: RunEvidenceGuard,
}

#[test]
fn unknown_unicode_is_fresh_only_and_cross_store_profile_registration_is_idempotent(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("unknown-unicode-policy.sqlite3");
    let mut store = Store::open_or_create(&database)?;

    let (volume_id, unknown_namespace_id, known_namespace_id) =
        store.write_transaction(|repository| {
            let volume_id = repository.upsert_volume(&strong_volume("policy", 100))?;
            let unknown = namespace_input(
                volume_id,
                NamespaceProfileKey::from_volume_adapter([11; 32]),
                "sensitive",
                "unknown",
                100,
            );
            let unknown_namespace_id = repository.register_namespace_profile(&unknown)?;
            let known_namespace_id = repository.register_namespace_profile(&namespace_input(
                volume_id,
                NamespaceProfileKey::from_volume_adapter([12; 32]),
                "sensitive",
                "exact",
                101,
            ))?;
            Ok((volume_id, unknown_namespace_id, known_namespace_id))
        })?;
    store.close()?;

    let mut reopened = Store::open_existing(&database)?;
    let reused_namespace_id = reopened.write_transaction(|repository| {
        assert_eq!(
            repository.upsert_volume(&strong_volume("policy", 1_000))?,
            volume_id
        );
        repository.register_namespace_profile(&namespace_input(
            volume_id,
            NamespaceProfileKey::from_volume_adapter([11; 32]),
            "sensitive",
            "unknown",
            999,
        ))
    })?;
    assert_eq!(reused_namespace_id, unknown_namespace_id);

    let weak_error = reopened
        .write_transaction(|repository| {
            let weak_volume_id = repository.upsert_volume(&weak_volume("weak-policy", 1_001))?;
            repository.register_namespace_profile(&namespace_input(
                weak_volume_id,
                NamespaceProfileKey::from_volume_adapter([21; 32]),
                "sensitive",
                "unknown",
                1_001,
            ))
        })
        .expect_err("weak identity acquired a cross-session policy");
    assert!(matches!(
        weak_error,
        StoreError::InvalidInput {
            field: "reuse_scope",
            ..
        }
    ));

    let unknown_case_error = reopened
        .write_transaction(|repository| {
            repository.register_namespace_profile(&namespace_input(
                volume_id,
                NamespaceProfileKey::from_volume_adapter([22; 32]),
                "unknown",
                "unknown",
                1_002,
            ))
        })
        .expect_err("unknown case behavior acquired cross-session lineage");
    assert!(matches!(
        unknown_case_error,
        StoreError::InvalidInput {
            field: "reuse_scope",
            ..
        }
    ));
    reopened.close()?;

    let connection = Connection::open(&database)?;
    let unknown_policy: (String, i64) = connection.query_row(
        "SELECT policy, created_at_ms FROM namespace_reuse_policies \
         WHERE namespace_profile_id = ?1",
        [unknown_namespace_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let known_policy: String = connection.query_row(
        "SELECT policy FROM namespace_reuse_policies WHERE namespace_profile_id = ?1",
        [known_namespace_id],
        |row| row.get(0),
    )?;
    assert_eq!(unknown_policy, ("fresh_attempt_only".into(), 100));
    assert_eq!(known_policy, "evidence_reuse_eligible");
    Ok(())
}

#[test]
fn exact_recovery_selection_creates_one_fresh_child_and_rejects_stale_or_mismatched_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("fresh-attempt-selection.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let scope = create_stable_scope(&mut store, "selection", "unknown", 31)?;
    let initial = create_running_initial_attempt(&mut store, scope, "selection", 120)?;
    store.close()?;

    let mut reopened = Store::open_existing(&database)?;
    let canonical_query = recovery_query(scope, json!({"a": 1, "b": 2}));
    let selected = select(&mut reopened, &canonical_query)?;
    let target = match selected {
        FreshAttemptRecoverySelection::Unique(target) => target,
        other => return Err(format!("expected one recovery target, observed {other:?}").into()),
    };
    assert_eq!(target.job_id, initial.job_id);
    assert_eq!(target.parent_scan_run_id, initial.run_id);
    assert!(target.job_state_version >= 2);

    let mut mismatches = Vec::new();
    let mut wrong_raw = canonical_query.clone();
    wrong_raw.mount_relative_root_raw = b"Pictures".to_vec();
    mismatches.push(wrong_raw);
    let mut wrong_encoding = canonical_query.clone();
    wrong_encoding.path_encoding = "unix_bytes".into();
    mismatches.push(wrong_encoding);
    let mut wrong_stable_key = canonical_query.clone();
    wrong_stable_key.stable_root_path_key = StablePathKey::from_volume_adapter([91; 32]);
    mismatches.push(wrong_stable_key);
    let mut wrong_root_scope = canonical_query.clone();
    wrong_root_scope.root_scope_key = RootScopeKey::from_volume_adapter([92; 32]);
    mismatches.push(wrong_root_scope);
    let mut wrong_config = canonical_query.clone();
    wrong_config.config = Some(json!({"a": 1, "b": 3}));
    mismatches.push(wrong_config);
    let mut wrong_namespace = canonical_query.clone();
    wrong_namespace.namespace_profile_id += 10_000;
    mismatches.push(wrong_namespace);
    let mut wrong_volume = canonical_query.clone();
    wrong_volume.volume_id += 10_000;
    mismatches.push(wrong_volume);
    for mismatch in mismatches {
        assert_eq!(
            select(&mut reopened, &mismatch)?,
            FreshAttemptRecoverySelection::None
        );
    }

    let child_mount = MountSessionKey::from_runtime_evidence([32; 32]);
    let (child_run_id, atomic_target) = reopened.write_transaction(|repository| {
        let capability_profile_id = repository.set_current_capability_profile(&capability(
            scope.volume_id,
            child_mount,
            500,
        ))?;
        let selection = repository.select_fresh_attempt_recovery(&canonical_query)?;
        let atomic_target = match selection {
            FreshAttemptRecoverySelection::Unique(target) => target,
            other => panic!("fixture expected one atomic recovery target, observed {other:?}"),
        };
        let child_run_id = repository.create_bound_scan_run(&NewBoundScanRun {
            run_key: "selection-fresh-child".into(),
            scan_job_id: atomic_target.job_id,
            volume_id: scope.volume_id,
            capability_profile_id,
            parent_scan_run_id: Some(atomic_target.parent_scan_run_id),
            mount_session_key: child_mount,
            mount_relative_root_raw: b"DCIM".to_vec(),
            path_encoding: "utf8".into(),
            stable_root_path_key: scope.stable_root_path_key,
            root_scope_key: scope.root_scope_key,
            root_object_signature: RootObjectSignature::from_volume_adapter([33; 32]),
            scan_mode: "full".into(),
            attempt_strategy: ScanAttemptStrategy::FreshFullChildV1,
            config: Some(json!({"b": 2, "a": 1})),
            created_at_ms: 510,
        })?;
        Ok((child_run_id, atomic_target))
    })?;
    assert_eq!(atomic_target, target);
    assert_eq!(
        select(&mut reopened, &canonical_query)?,
        FreshAttemptRecoverySelection::None
    );

    let stale_error =
        reopened
            .write_transaction(|repository| {
                let capability_profile_id = repository.set_current_capability_profile(
                    &capability(scope.volume_id, child_mount, 500),
                )?;
                repository.create_bound_scan_run(&NewBoundScanRun {
                    run_key: "selection-stale-child".into(),
                    scan_job_id: target.job_id,
                    volume_id: scope.volume_id,
                    capability_profile_id,
                    parent_scan_run_id: Some(target.parent_scan_run_id),
                    mount_session_key: child_mount,
                    mount_relative_root_raw: b"DCIM".to_vec(),
                    path_encoding: "utf8".into(),
                    stable_root_path_key: scope.stable_root_path_key,
                    root_scope_key: scope.root_scope_key,
                    root_object_signature: RootObjectSignature::from_volume_adapter([34; 32]),
                    scan_mode: "full".into(),
                    attempt_strategy: ScanAttemptStrategy::FreshFullChildV1,
                    config: Some(json!({"a": 1, "b": 2})),
                    created_at_ms: 520,
                })
            })
            .expect_err("stale parent selection created a second child");
    assert!(matches!(
        stale_error,
        StoreError::IdempotencyConflict {
            entity: "bound_scan_run_parent_lineage",
            ..
        }
    ));

    reopened.close()?;
    let connection = Connection::open(&database)?;
    let child: (String, Option<i64>, String, i64, i64) = connection.query_row(
        "SELECT attempt_strategy, parent_scan_run_id, scan_mode, \
                (SELECT count(*) FROM media_observation_snapshots \
                 WHERE scan_run_id = scan_runs.id), \
                (SELECT count(*) FROM observation_fingerprints \
                 WHERE scan_run_id = scan_runs.id) \
         FROM scan_runs WHERE id = ?1",
        [child_run_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    assert_eq!(
        child,
        (
            "fresh_full_child_v1".into(),
            Some(initial.run_id),
            "full".into(),
            0,
            0,
        )
    );
    Ok(())
}

#[test]
fn every_exact_matching_failed_job_is_ambiguous_even_when_recency_differs(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("ambiguous.sqlite3"))?;
    let scope = create_stable_scope(&mut store, "ambiguous", "unknown", 41)?;
    let first = create_running_initial_attempt(&mut store, scope, "ambiguous-a", 120)?;
    let second = create_running_initial_attempt(&mut store, scope, "ambiguous-b", 220)?;
    interrupt(&mut store, first, 300)?;
    interrupt(&mut store, second, 900)?;

    assert_eq!(
        select(&mut store, &recovery_query(scope, json!({"b": 2, "a": 1})))?,
        FreshAttemptRecoverySelection::Ambiguous { candidate_count: 2 }
    );
    Ok(())
}

#[test]
fn migrated_v8_attempt_stays_legacy_and_offline_promotion_fails_reopen(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("v8-legacy-epoch.sqlite3");
    create_v8_legacy_bound_run(&database)?;

    Store::open_existing(&database)?.close()?;
    let connection = Connection::open(&database)?;
    let (run_id, strategy, cutoff): (i64, String, i64) = connection.query_row(
        "SELECT run.id, run.attempt_strategy, epoch.legacy_scan_run_id_cutoff \
         FROM scan_runs AS run CROSS JOIN scan_attempt_strategy_epochs AS epoch \
         WHERE run.run_key = 'v8-legacy-run' AND epoch.id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(strategy, "legacy");
    assert!(run_id <= cutoff);

    let immutable_trigger = scan_attempt_immutable_trigger(&connection)?;
    connection.execute_batch("DROP TRIGGER trg_scan_runs_attempt_lineage_no_update_v9;")?;
    connection.execute(
        "UPDATE scan_runs SET attempt_strategy = 'initial_full_v1' WHERE id = ?1",
        [run_id],
    )?;
    connection.execute_batch(&immutable_trigger)?;
    connection.close().map_err(|(_, error)| error)?;

    let error = Store::open_existing(&database)
        .err()
        .ok_or("an offline legacy-to-initial promotion crossed the v9 epoch")?;
    assert!(matches!(error, StoreError::MigrationHistoryMismatch(_)));
    Ok(())
}

#[test]
fn repository_insert_uses_post_epoch_id_and_offline_demotion_fails_reopen(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("v9-explicit-epoch.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let scope = create_stable_scope(&mut store, "epoch", "unknown", 51)?;
    let attempt = create_running_initial_attempt(&mut store, scope, "epoch", 120)?;
    store.close()?;

    let connection = Connection::open(&database)?;
    let (strategy, cutoff): (String, i64) = connection.query_row(
        "SELECT run.attempt_strategy, epoch.legacy_scan_run_id_cutoff \
         FROM scan_runs AS run CROSS JOIN scan_attempt_strategy_epochs AS epoch \
         WHERE run.id = ?1 AND epoch.id = 1",
        [attempt.run_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(strategy, "initial_full_v1");
    assert!(attempt.run_id > cutoff);

    let id_error = connection
        .execute(
            "UPDATE scan_runs SET id = id + 1000 WHERE id = ?1",
            [attempt.run_id],
        )
        .expect_err("scan run id crossed the immutable strategy epoch");
    assert!(id_error
        .to_string()
        .contains("parent lineage are immutable"));

    let immutable_trigger = scan_attempt_immutable_trigger(&connection)?;
    connection.execute_batch("DROP TRIGGER trg_scan_runs_attempt_lineage_no_update_v9;")?;
    connection.execute(
        "UPDATE scan_runs SET attempt_strategy = 'legacy' WHERE id = ?1",
        [attempt.run_id],
    )?;
    connection.execute_batch(&immutable_trigger)?;
    connection.close().map_err(|(_, error)| error)?;

    let error = Store::open_existing(&database)
        .err()
        .ok_or("an offline explicit-to-legacy demotion crossed the v9 epoch")?;
    assert!(matches!(error, StoreError::MigrationHistoryMismatch(_)));
    Ok(())
}

fn create_stable_scope(
    store: &mut Store,
    prefix: &str,
    unicode_behavior: &str,
    session_byte: u8,
) -> Result<StableScope, StoreError> {
    let mount_session_key = MountSessionKey::from_runtime_evidence([session_byte; 32]);
    store.write_transaction(|repository| {
        let volume_id = repository.upsert_volume(&strong_volume(prefix, 100))?;
        let capability_profile_id = repository.set_current_capability_profile(&capability(
            volume_id,
            mount_session_key,
            100,
        ))?;
        let namespace_profile_id = repository.register_namespace_profile(&namespace_input(
            volume_id,
            NamespaceProfileKey::from_volume_adapter([11; 32]),
            "sensitive",
            unicode_behavior,
            100,
        ))?;
        Ok(StableScope {
            volume_id,
            namespace_profile_id,
            capability_profile_id,
            mount_session_key,
            stable_root_path_key: StablePathKey::from_volume_adapter([12; 32]),
            root_scope_key: RootScopeKey::from_volume_adapter([13; 32]),
        })
    })
}

fn create_running_initial_attempt(
    store: &mut Store,
    scope: StableScope,
    prefix: &str,
    created_at_ms: i64,
) -> Result<RunningAttempt, StoreError> {
    store.write_transaction(|repository| {
        let job_id = repository.create_scoped_scan_job(&NewScopedScanJob {
            job_key: format!("{prefix}-job"),
            volume_id: scope.volume_id,
            namespace_profile_id: scope.namespace_profile_id,
            root_display: "DCIM".into(),
            mount_relative_root_raw: b"DCIM".to_vec(),
            path_encoding: "utf8".into(),
            stable_root_path_key: scope.stable_root_path_key,
            root_scope_key: scope.root_scope_key,
            config: Some(json!({"b": 2, "a": 1})),
            created_at_ms,
        })?;
        let run_id = repository.create_bound_scan_run(&NewBoundScanRun {
            run_key: format!("{prefix}-run"),
            scan_job_id: job_id,
            volume_id: scope.volume_id,
            capability_profile_id: scope.capability_profile_id,
            parent_scan_run_id: None,
            mount_session_key: scope.mount_session_key,
            mount_relative_root_raw: b"DCIM".to_vec(),
            path_encoding: "utf8".into(),
            stable_root_path_key: scope.stable_root_path_key,
            root_scope_key: scope.root_scope_key,
            root_object_signature: RootObjectSignature::from_volume_adapter([14; 32]),
            scan_mode: "full".into(),
            attempt_strategy: ScanAttemptStrategy::InitialFullV1,
            config: Some(json!({"a": 1, "b": 2})),
            created_at_ms: created_at_ms + 10,
        })?;
        let guard = RunEvidenceGuard {
            scan_run_id: run_id,
            capability_profile_id: scope.capability_profile_id,
            mount_session_key: scope.mount_session_key,
        };
        repository.transition_bound_scan_job_and_run(
            &guard,
            job_id,
            "queued",
            0,
            "queued",
            0,
            "running",
            "running",
            created_at_ms + 20,
            None,
        )?;
        Ok(RunningAttempt {
            job_id,
            run_id,
            guard,
        })
    })
}

fn interrupt(
    store: &mut Store,
    attempt: RunningAttempt,
    interrupted_at_ms: i64,
) -> Result<(), StoreError> {
    store.write_transaction(|repository| {
        repository.transition_bound_scan_job_and_run(
            &attempt.guard,
            attempt.job_id,
            "running",
            1,
            "running",
            1,
            "failed",
            "interrupted",
            interrupted_at_ms,
            Some(("TEST_INTERRUPTED", "fresh-attempt fixture interruption")),
        )?;
        Ok(())
    })
}

fn select(
    store: &mut Store,
    query: &FreshAttemptRecoveryQuery,
) -> Result<FreshAttemptRecoverySelection, StoreError> {
    store.write_transaction(|repository| repository.select_fresh_attempt_recovery(query))
}

fn recovery_query(scope: StableScope, config: serde_json::Value) -> FreshAttemptRecoveryQuery {
    FreshAttemptRecoveryQuery {
        volume_id: scope.volume_id,
        namespace_profile_id: scope.namespace_profile_id,
        mount_relative_root_raw: b"DCIM".to_vec(),
        path_encoding: "utf8".into(),
        stable_root_path_key: scope.stable_root_path_key,
        root_scope_key: scope.root_scope_key,
        config: Some(config),
    }
}

fn namespace_input(
    volume_id: i64,
    profile_key: NamespaceProfileKey,
    case_behavior: &str,
    unicode_behavior: &str,
    created_at_ms: i64,
) -> NamespaceProfileInput {
    NamespaceProfileInput {
        volume_id,
        profile_key,
        profile_version: 1,
        native_path_encoding: "unix_bytes".into(),
        case_behavior: case_behavior.into(),
        unicode_behavior: unicode_behavior.into(),
        key_strategy: "exact_native_v1".into(),
        key_algorithm_version: 2,
        reuse_scope: "cross_session".into(),
        bound_mount_session_key: None,
        created_at_ms,
    }
}

fn strong_volume(prefix: &str, now_ms: i64) -> VolumeInput {
    VolumeInput {
        identity_key: format!("{prefix}-volume"),
        identity_strength: "strong".into(),
        marker_uuid: Some(format!("{prefix}-marker")),
        native_uuid: Some(format!("{prefix}-native")),
        filesystem_type: "apfs".into(),
        display_name: Some("Fixture".into()),
        mount_source: Some("fixture".into()),
        last_mount_path: Some("/Volumes/Fixture".into()),
        transport: Some("virtual".into()),
        is_network: false,
        is_read_only: true,
        now_ms,
    }
}

fn weak_volume(prefix: &str, now_ms: i64) -> VolumeInput {
    VolumeInput {
        identity_key: format!("{prefix}-volume"),
        identity_strength: "weak".into(),
        marker_uuid: None,
        native_uuid: None,
        filesystem_type: "unknown".into(),
        display_name: Some("Weak fixture".into()),
        mount_source: None,
        last_mount_path: Some("/Volumes/Weak".into()),
        transport: None,
        is_network: false,
        is_read_only: true,
        now_ms,
    }
}

fn capability(
    volume_id: i64,
    mount_session_key: MountSessionKey,
    observed_at_ms: i64,
) -> CapabilityProfileInput {
    CapabilityProfileInput {
        volume_id,
        probe_mode: "passive".into(),
        probe_status: "complete".into(),
        observed_at_ms,
        os_build: "fixture".into(),
        mount_session_key: Some(mount_session_key.to_storage_hex()),
        probe_protocol_version: Some(1),
        driver_name: None,
        driver_version: None,
        mount_flags: Some(0),
        case_behavior: Some("sensitive".into()),
        unicode_behavior: None,
        path_encoding_family: Some("unix".into()),
        path_semantics_version: 2,
        can_read: Some(true),
        can_write: Some(false),
        can_rename_same_volume: None,
        can_rename_exclusive: None,
        can_no_replace: None,
        can_sync_directory: None,
        can_append_durable: None,
        single_writer: Some(true),
        can_set_birth_time: None,
        can_set_modified_time: None,
        can_use_xattrs: None,
        can_use_hard_links: None,
        can_use_clones: None,
        has_persistent_file_ids: Some(true),
        timestamp_granularity_ns: Some(1),
        maximum_name_bytes: Some(255),
        maximum_file_bytes: None,
        raw_capabilities: None,
    }
}

fn scan_attempt_immutable_trigger(connection: &Connection) -> Result<String, rusqlite::Error> {
    connection.query_row(
        "SELECT sql FROM sqlite_schema \
         WHERE type = 'trigger' \
           AND name = 'trg_scan_runs_attempt_lineage_no_update_v9'",
        [],
        |row| row.get(0),
    )
}

fn create_v8_legacy_bound_run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    create_empty_managed_version(path, 8)?;
    let mount_session_key = MountSessionKey::from_runtime_evidence([61; 32]);
    let capability = capability(1, mount_session_key, 1);
    let capability_hash = compute_capability_profile_hash(&capability)?;
    let mount_session_hex = mount_session_key.to_storage_hex();

    let connection = Connection::open(path)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.execute_batch(
        "INSERT INTO volumes ( \
             id, identity_key, identity_strength, marker_uuid, native_uuid, filesystem_type, \
             display_name, mount_source, last_mount_path, transport, is_network, is_read_only, \
             first_seen_at_ms, last_seen_at_ms, created_at_ms, updated_at_ms \
         ) VALUES ( \
             1, 'v8-legacy-volume', 'strong', 'v8-legacy-marker', 'v8-legacy-native', \
             'apfs', 'Fixture', 'fixture', '/Volumes/Fixture', 'virtual', 0, 1, \
             1, 1, 1, 1 \
         );",
    )?;
    connection.execute(
        "INSERT INTO capability_profiles ( \
             id, volume_id, profile_hash, profile_hash_version, probe_mode, probe_status, \
             observed_at_ms, os_build, mount_session_key, probe_protocol_version, \
             driver_name, driver_version, mount_flags, case_behavior, unicode_behavior, \
             path_encoding_family, path_semantics_version, can_read, can_write, \
             can_rename_same_volume, can_rename_exclusive, can_no_replace, \
             can_sync_directory, can_append_durable, single_writer, can_set_birth_time, \
             can_set_modified_time, can_use_xattrs, can_use_hard_links, can_use_clones, \
             has_persistent_file_ids, timestamp_granularity_ns, maximum_name_bytes, \
             maximum_file_bytes, raw_capabilities_json, is_current, created_at_ms \
         ) VALUES ( \
             1, 1, ?1, 2, 'passive', 'complete', 1, 'fixture', ?2, 1, \
             NULL, NULL, 0, 'sensitive', NULL, 'unix', 2, 1, 0, \
             NULL, NULL, NULL, NULL, NULL, 1, NULL, NULL, NULL, NULL, NULL, \
             1, 1, 255, NULL, NULL, 1, 1 \
         )",
        params![capability_hash.as_slice(), mount_session_hex],
    )?;
    connection.execute_batch(&format!(
        "INSERT INTO namespace_profiles ( \
             id, volume_id, profile_key, profile_version, origin, native_path_encoding, \
             case_behavior, unicode_behavior, key_strategy, key_algorithm_version, \
             reuse_scope, bound_mount_session_key, created_at_ms \
         ) VALUES ( \
             1, 1, x'1111111111111111111111111111111111111111111111111111111111111111', \
             1, 'observed_v5', 'unix_bytes', 'sensitive', 'exact', 'exact_native_v1', 2, \
             'current_session_only', '{mount_session_hex}', 2 \
         ); \
         INSERT INTO scan_jobs ( \
             id, job_key, volume_id, root_relative_path, root_path_key, state, \
             created_at_ms, updated_at_ms \
         ) VALUES ( \
             1, 'v8-legacy-job', 1, 'DCIM', \
             x'1212121212121212121212121212121212121212121212121212121212121212', \
             'queued', 10, 10 \
         ); \
         INSERT INTO scan_job_roots ( \
             scan_job_id, volume_id, capability_profile_id, path_semantics_version, \
             relative_path_raw, path_encoding, semantic_path_key, created_at_ms \
         ) VALUES ( \
             1, 1, NULL, 1, CAST('DCIM' AS BLOB), 'utf8', \
             x'1212121212121212121212121212121212121212121212121212121212121212', 10 \
         ); \
         INSERT INTO scan_job_scopes ( \
             scan_job_id, volume_id, namespace_profile_id, origin, root_display, \
             mount_relative_root_raw, path_encoding, stable_root_path_key, root_scope_key, \
             recoverable, created_at_ms \
         ) VALUES ( \
             1, 1, 1, 'observed_v5', 'DCIM', CAST('DCIM' AS BLOB), 'utf8', \
             x'1212121212121212121212121212121212121212121212121212121212121212', \
             x'1313131313131313131313131313131313131313131313131313131313131313', \
             0, 10 \
         ); \
         INSERT INTO scan_runs ( \
             id, run_key, volume_id, capability_profile_id, parent_scan_run_id, \
             root_relative_path, root_path_key, scan_mode, state, created_at_ms, updated_at_ms \
         ) VALUES ( \
             1, 'v8-legacy-run', 1, 1, NULL, 'DCIM', \
             x'1212121212121212121212121212121212121212121212121212121212121212', \
             'full', 'queued', 11, 11 \
         ); \
         INSERT INTO scan_run_roots ( \
             scan_run_id, volume_id, capability_profile_id, path_semantics_version, \
             relative_path_raw, path_encoding, semantic_path_key, created_at_ms \
         ) VALUES ( \
             1, 1, 1, 2, CAST('DCIM' AS BLOB), 'utf8', \
             x'1212121212121212121212121212121212121212121212121212121212121212', 11 \
         ); \
         INSERT INTO scan_job_runs ( \
             scan_job_id, scan_run_id, volume_id, attempt_number, created_at_ms \
         ) VALUES (1, 1, 1, 1, 11); \
         UPDATE scan_jobs SET active_scan_run_id = 1 WHERE id = 1; \
         INSERT INTO scan_run_sessions ( \
             scan_run_id, scan_job_id, volume_id, capability_profile_id, \
             namespace_profile_id, mount_session_key, mount_relative_root_raw, \
             path_encoding, stable_root_path_key, root_scope_key, \
             root_object_signature, created_at_ms \
         ) VALUES ( \
             1, 1, 1, 1, 1, '{mount_session_hex}', CAST('DCIM' AS BLOB), 'utf8', \
             x'1212121212121212121212121212121212121212121212121212121212121212', \
             x'1313131313131313131313131313131313131313131313131313131313131313', \
             x'1414141414141414141414141414141414141414141414141414141414141414', 11 \
         );"
    ))?;
    connection.close().map_err(|(_, error)| error)?;
    Ok(())
}

fn create_empty_managed_version(
    path: &Path,
    target_version: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = Connection::open(path)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    for (index, (name, sql)) in PRE_V9_MIGRATIONS.iter().enumerate() {
        let version = i64::try_from(index)? + 1;
        if version > target_version {
            break;
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if version == 1 {
            transaction.execute_batch(
                r#"CREATE TABLE guiying_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    checksum BLOB NOT NULL CHECK (length(checksum) = 32),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
) STRICT;"#,
            )?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        }
        let body = if version == 1 {
            strip_initial_transaction(sql)?
        } else {
            sql
        };
        transaction.execute_batch(body)?;
        let checksum = blake3::hash(sql.as_bytes());
        transaction.execute(
            "INSERT INTO guiying_schema_migrations (version, name, checksum, applied_at_ms) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                version,
                name,
                checksum.as_bytes().as_slice(),
                1_000 + version,
            ],
        )?;
        transaction.pragma_update(None, "user_version", version)?;
        transaction.commit()?;
    }
    connection.close().map_err(|(_, error)| error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn strip_initial_transaction(sql: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let begin = sql
        .find("BEGIN IMMEDIATE;\n")
        .ok_or("initial migration is missing BEGIN IMMEDIATE")?
        + "BEGIN IMMEDIATE;\n".len();
    let commit = sql
        .rfind("COMMIT;")
        .ok_or("initial migration is missing COMMIT")?;
    Ok(&sql[begin..commit])
}
