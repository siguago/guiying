use std::fs;

use guiying_store::{
    compute_capability_profile_hash, BeginExactGroupInput, BuildKey, CapabilityProfileInput,
    FileObjectKey, FileTimestampParts, FingerprintReadOrigin, FreshFingerprintInput,
    FreshFingerprintKind, IntegrityCheckKind, ManifestDigest, MediaFileInput, MountSessionKey,
    NamespaceProfileInput, NamespaceProfileKey, NewBoundScanRun, NewScanIssue, NewScanJob,
    NewScanReport, NewScanRun, NewScopedScanJob, ObservationInput, ParametersHash, PathKey,
    RootObjectSignature, RootScopeKey, RunEvidenceGuard, ScanCheckpointInput, ScanStage,
    SourceSignature, StablePathKey, Store, StoreError, VolumeInput, MAX_PAGE_SIZE,
    MAX_SCAN_REPORT_JSON_BYTES,
};
use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;

#[test]
fn open_enforces_settings_migrations_and_integrity() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("guiying.sqlite3");
    let store = Store::open_or_create(&database)?;

    assert_eq!(store.schema_version()?, 6);
    assert!(store.settings().foreign_keys);
    assert_eq!(store.settings().busy_timeout_ms, 5_000);
    assert_eq!(store.settings().synchronous, "FULL");
    assert_eq!(store.settings().journal_mode, "wal");
    assert!(!store.settings().trusted_schema);
    assert_eq!(store.settings().wal_autocheckpoint_pages, 1_000);
    assert!(store.settings().defensive);
    assert!(!store.settings().dqs_ddl);
    assert!(!store.settings().dqs_dml);
    assert!(store
        .integrity_check(IntegrityCheckKind::Full)?
        .is_healthy());
    store.close()?;

    let connection = Connection::open(&database)?;
    let migration_count: i64 = connection.query_row(
        "SELECT count(*) FROM guiying_schema_migrations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(migration_count, 6);
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    assert_eq!(application_id, 0x4755_5949);
    connection.close().map_err(|(_, error)| error)?;

    let reopened = Store::open_existing(&database)?;
    assert_eq!(reopened.schema_version()?, 6);
    Ok(())
}

#[test]
fn parent_creation_requires_explicit_api() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("nested/app/guiying.sqlite3");

    let error = match Store::open_or_create(&database) {
        Ok(_) => return Err("open unexpectedly created parent directories".into()),
        Err(error) => error,
    };
    assert!(matches!(error, StoreError::ParentDirectoryMissing(_)));
    assert!(!database.exists());

    let store = Store::open_or_create_with_parent_creation(&database)?;
    assert!(database.is_file());
    store.close()?;
    Ok(())
}

#[test]
fn rejects_unmanaged_or_tampered_schema() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let unmanaged_path = temporary.path().join("unmanaged.sqlite3");
    let unmanaged = Connection::open(&unmanaged_path)?;
    unmanaged.execute_batch("CREATE TABLE unrelated (id INTEGER PRIMARY KEY) STRICT;")?;
    unmanaged.close().map_err(|(_, error)| error)?;
    make_private(&unmanaged_path)?;
    let error = match Store::open_existing(&unmanaged_path) {
        Ok(_) => return Err("unmanaged schema was unexpectedly adopted".into()),
        Err(error) => error,
    };
    assert!(matches!(error, StoreError::UnmanagedSchema));

    let managed_path = temporary.path().join("managed.sqlite3");
    Store::open_or_create(&managed_path)?.close()?;
    let managed = Connection::open(&managed_path)?;
    managed.execute(
        "UPDATE guiying_schema_migrations SET checksum = zeroblob(32) WHERE version = 2",
        [],
    )?;
    managed.close().map_err(|(_, error)| error)?;
    let error = match Store::open_existing(&managed_path) {
        Ok(_) => return Err("tampered migration history was unexpectedly accepted".into()),
        Err(error) => error,
    };
    assert!(matches!(error, StoreError::MigrationHistoryMismatch(_)));

    let schema_path = temporary.path().join("schema-tamper.sqlite3");
    Store::open_or_create(&schema_path)?.close()?;
    let schema = Connection::open(&schema_path)?;
    schema.execute_batch(
        "CREATE TRIGGER unexpected_volume_trigger AFTER INSERT ON volumes BEGIN SELECT 1; END;",
    )?;
    schema.close().map_err(|(_, error)| error)?;
    let error = match Store::open_existing(&schema_path) {
        Ok(_) => return Err("tampered safety schema was unexpectedly accepted".into()),
        Err(error) => error,
    };
    assert!(matches!(error, StoreError::SchemaManifestMismatch { .. }));
    Ok(())
}

#[test]
fn read_only_preflight_rejects_before_enabling_wal() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("foreign.sqlite3");
    let connection = Connection::open(&database)?;
    connection
        .execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE foreign_data(id INTEGER);")?;
    connection.close().map_err(|(_, error)| error)?;
    make_private(&database)?;

    let error = Store::open_existing(&database)
        .err()
        .ok_or("foreign database was unexpectedly adopted")?;
    assert!(matches!(error, StoreError::UnmanagedSchema));
    assert!(!database.with_extension("sqlite3-wal").exists());
    let connection =
        Connection::open_with_flags(&database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    assert_eq!(journal_mode, "delete");
    Ok(())
}

#[cfg(unix)]
#[test]
fn existing_database_requires_private_file_permissions() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    let database = temporary.path().join("permissions.sqlite3");
    Store::open_or_create(&database)?.close()?;
    fs::set_permissions(&database, fs::Permissions::from_mode(0o644))?;
    let error = Store::open_existing(&database)
        .err()
        .ok_or("group/world-readable database was unexpectedly opened")?;
    assert!(matches!(
        error,
        StoreError::UnsafeDatabasePermissions { .. }
    ));

    fs::set_permissions(&database, fs::Permissions::from_mode(0o600))?;
    let alias = temporary.path().join("database-hard-link.sqlite3");
    fs::hard_link(&database, alias)?;
    let error = Store::open_existing(&database)
        .err()
        .ok_or("hard-linked database was unexpectedly opened")?;
    assert!(matches!(
        error,
        StoreError::UnsafeDatabasePermissions { .. }
    ));
    Ok(())
}

#[test]
fn strong_volume_identity_conflicts_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("volume-identity.sqlite3"))?;
    store.write_transaction(|repository| {
        repository.upsert_volume(&volume_input("volume-a"))?;
        Ok(())
    })?;

    let mut changed = volume_input("volume-a");
    changed.native_uuid = Some("different-native-uuid".into());
    let error = store
        .write_transaction(|repository| {
            repository.upsert_volume(&changed)?;
            Ok(())
        })
        .err()
        .ok_or("changed strong identifier was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::VolumeIdentityConflict { .. }));

    let mut alias = volume_input("volume-b");
    alias.native_uuid = Some("native-volume-a".into());
    let error = store
        .write_transaction(|repository| {
            repository.upsert_volume(&alias)?;
            Ok(())
        })
        .err()
        .ok_or("strong identifier alias was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::VolumeIdentityConflict { .. }));
    Ok(())
}

#[test]
fn volume_upgrade_and_capability_evidence_are_immutable() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let database = temporary.path().join("immutable-evidence.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let mut weak = volume_input("upgrade-volume");
    weak.identity_strength = "weak".into();
    weak.marker_uuid = None;
    weak.native_uuid = None;
    let volume = store.write_transaction(|repository| repository.upsert_volume(&weak))?;

    let mut strong = weak.clone();
    strong.identity_strength = "strong".into();
    strong.marker_uuid = Some("marker-upgraded".into());
    strong.now_ms = 1_100;
    assert_eq!(
        store.write_transaction(|repository| repository.upsert_volume(&strong))?,
        volume
    );

    let capability = store.write_transaction(|repository| {
        repository.set_current_capability_profile(&capability_input(
            volume,
            MountSessionKey::from_runtime_evidence([7; 32]),
            "unix",
        ))
    })?;
    let mut late_identifier = strong.clone();
    late_identifier.native_uuid = Some("late-native-id".into());
    late_identifier.now_ms = 1_200;
    let error = store
        .write_transaction(|repository| repository.upsert_volume(&late_identifier))
        .err()
        .ok_or("strong identity accepted a late identifier")?;
    assert!(matches!(error, StoreError::VolumeIdentityConflict { .. }));
    store.close()?;

    let connection = Connection::open(&database)?;
    assert!(connection
        .execute(
            "UPDATE volumes SET marker_uuid = 'rewritten' WHERE id = ?1",
            [volume],
        )
        .is_err());
    assert!(connection
        .execute("DELETE FROM volumes WHERE id = ?1", [volume])
        .is_err());
    assert!(connection
        .execute(
            "UPDATE capability_profiles SET driver_version = 'rewritten' WHERE id = ?1",
            [capability],
        )
        .is_err());
    assert!(connection
        .execute(
            "DELETE FROM capability_profiles WHERE id = ?1",
            [capability]
        )
        .is_err());
    assert_eq!(
        connection.execute(
            "UPDATE capability_profiles SET is_current = 0 WHERE id = ?1",
            [capability],
        )?,
        1
    );
    Ok(())
}

#[test]
fn capability_hash_is_internal_and_collision_checked() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("capability-hash.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let volume = store.write_transaction(|repository| {
        repository.upsert_volume(&volume_input("capability-volume"))
    })?;
    let original = capability_input(
        volume,
        MountSessionKey::from_runtime_evidence([7; 32]),
        "unix",
    );
    store.write_transaction(|repository| {
        let first = repository.set_current_capability_profile(&original)?;
        assert_eq!(repository.set_current_capability_profile(&original)?, first);
        Ok(())
    })?;
    store.close()?;

    let mut different = original.clone();
    different.driver_version = Some("collision-target".into());
    let collision_hash = compute_capability_profile_hash(&different)?;
    let connection = Connection::open(&database)?;
    assert!(connection
        .execute(
            "UPDATE capability_profiles SET profile_hash = ?1 WHERE volume_id = ?2",
            rusqlite::params![collision_hash.as_slice(), volume],
        )
        .is_err());
    connection.close().map_err(|(_, error)| error)?;

    let mut store = Store::open_existing(&database)?;
    let second = store
        .write_transaction(|repository| repository.set_current_capability_profile(&different))?;
    assert_ne!(second, 0);
    Ok(())
}

#[test]
fn capability_hash_covers_semantics_and_is_json_canonical() -> Result<(), Box<dyn std::error::Error>>
{
    let original = capability_input(7, MountSessionKey::from_runtime_evidence([7; 32]), "unix");
    let original_hash = compute_capability_profile_hash(&original)?;

    let mut variations = Vec::new();
    let mut changed = original.clone();
    changed.mount_session_key = Some("other-session".into());
    variations.push(changed);
    let mut changed = original.clone();
    changed.probe_protocol_version = Some(2);
    variations.push(changed);
    let mut changed = original.clone();
    changed.case_behavior = Some("insensitive_preserving".into());
    variations.push(changed);
    let mut changed = original.clone();
    changed.unicode_behavior = Some("nfd".into());
    variations.push(changed);
    let mut changed = original.clone();
    changed.path_encoding_family = Some("windows".into());
    variations.push(changed);
    let mut changed = original.clone();
    changed.path_semantics_version = 3;
    variations.push(changed);
    let mut changed = original.clone();
    changed.can_sync_directory = Some(true);
    variations.push(changed);
    let mut changed = original.clone();
    changed.can_no_replace = Some(true);
    variations.push(changed);
    let mut changed = original.clone();
    changed.can_append_durable = Some(true);
    variations.push(changed);
    let mut changed = original.clone();
    changed.single_writer = Some(false);
    variations.push(changed);
    let mut changed = original.clone();
    changed.can_use_hard_links = Some(true);
    variations.push(changed);
    let mut changed = original.clone();
    changed.maximum_file_bytes = Some(9_999);
    variations.push(changed);

    for changed in variations {
        assert_ne!(compute_capability_profile_hash(&changed)?, original_hash);
    }

    let mut first = original.clone();
    first.raw_capabilities = Some(json!({
        "alpha": 1,
        "nested": {"left": [1, {"a": true, "z": false}], "right": 2},
        "beta": 2
    }));
    let mut second = original;
    second.raw_capabilities = Some(json!({
        "beta": 2,
        "nested": {"right": 2, "left": [1, {"z": false, "a": true}]},
        "alpha": 1
    }));
    assert_eq!(
        compute_capability_profile_hash(&first)?,
        compute_capability_profile_hash(&second)?
    );
    Ok(())
}

#[test]
fn v5_coordinated_transitions_reject_aba_and_roll_back_both_halves(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("state-cas.sqlite3"))?;
    let scan = create_queued_scan(&mut store, "cas", 8)?;

    assert_eq!(
        store.write_transaction(|repository| repository.transition_bound_scan_job_and_run(
            &scan.guard,
            scan.job_id,
            "queued",
            0,
            "queued",
            0,
            "running",
            "running",
            200,
            None,
        ))?,
        (1, 1)
    );
    assert_eq!(
        store.write_transaction(|repository| repository.transition_bound_scan_job_and_run(
            &scan.guard,
            scan.job_id,
            "running",
            1,
            "running",
            1,
            "paused",
            "paused",
            300,
            None,
        ))?,
        (2, 2)
    );

    let caught = store.write_transaction(|repository| {
        let error = repository
            .transition_bound_scan_job_and_run(
                &scan.guard,
                scan.job_id,
                "paused",
                2,
                "paused",
                1,
                "running",
                "running",
                400,
                None,
            )
            .expect_err("stale run CAS unexpectedly succeeded");
        assert!(matches!(error, StoreError::ConcurrencyConflict { .. }));
        Ok(())
    });
    assert!(matches!(caught, Err(StoreError::WriteTransactionPoisoned)));
    assert_eq!(
        store
            .get_scan_job("cas-job")?
            .ok_or("scan job missing")?
            .state_version,
        2
    );
    assert_eq!(
        store
            .get_scan_run("cas-run")?
            .ok_or("scan run missing")?
            .state_version,
        2
    );

    for (from_version, target, now_ms) in [(2, "running", 400), (3, "paused", 500)] {
        let from = if target == "running" {
            "paused"
        } else {
            "running"
        };
        assert_eq!(
            store.write_transaction(|repository| repository.transition_bound_scan_job_and_run(
                &scan.guard,
                scan.job_id,
                from,
                from_version,
                from,
                from_version,
                target,
                target,
                now_ms,
                None,
            ))?,
            (from_version + 1, from_version + 1)
        );
    }

    let aba = store
        .write_transaction(|repository| {
            repository.transition_bound_scan_job_and_run(
                &scan.guard,
                scan.job_id,
                "paused",
                2,
                "paused",
                2,
                "cancelled",
                "cancelled",
                600,
                None,
            )
        })
        .expect_err("ABA transition unexpectedly succeeded");
    assert!(matches!(aba, StoreError::ConcurrencyConflict { .. }));

    let missing_error_evidence = store
        .write_transaction(|repository| {
            repository.transition_bound_scan_job_and_run(
                &scan.guard,
                scan.job_id,
                "paused",
                4,
                "paused",
                4,
                "failed",
                "failed",
                700,
                None,
            )
        })
        .expect_err("failed transition without error evidence unexpectedly succeeded");
    assert!(matches!(
        missing_error_evidence,
        StoreError::InvalidInput { .. }
    ));
    assert_eq!(
        store.write_transaction(|repository| repository.transition_bound_scan_job_and_run(
            &scan.guard,
            scan.job_id,
            "paused",
            4,
            "paused",
            4,
            "failed",
            "failed",
            800,
            Some(("io_error", "fixture failure")),
        ))?,
        (5, 5)
    );
    Ok(())
}

#[test]
fn v5_repository_round_trip_is_idempotent_and_queryable() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("repository.sqlite3"))?;
    let scan = create_running_scan(&mut store, "roundtrip", 9)?;
    let observation = observation_input(1, 4_096);
    let (observation_id, issue_id) = store.write_transaction(|repository| {
        let observation_id = repository
            .record_observation_batch(&scan.guard, std::slice::from_ref(&observation))?[0];
        repository.update_bound_scan_progress(&scan.guard, 1, 0, 1, 4_096, 250)?;
        assert_eq!(
            repository.save_bound_scan_checkpoint(
                &scan.guard,
                &ScanCheckpointInput {
                    scan_run_id: scan.run_id,
                    volume_id: scan.volume_id,
                    expected_previous_version: None,
                    cursor_version: 1,
                    cursor: json!({"last_observation_id": observation_id}),
                    discovered_count: 1,
                    fingerprinted_count: 0,
                    error_count: 1,
                    logical_bytes_seen: 4_096,
                    saved_at_ms: 260,
                },
            )?,
            1
        );
        let issue = NewScanIssue {
            issue_key: "roundtrip-issue".into(),
            volume_id: scan.volume_id,
            scan_run_id: scan.run_id,
            media_file_id: None,
            severity: "warning".into(),
            stage: "metadata".into(),
            code: "missing_offset".into(),
            message: "Capture time has no UTC offset".into(),
            details: Some(json!({"fallback": "wall_time_only"})),
            occurred_at_ms: 270,
        };
        let issue_id = repository.record_bound_scan_issue(&scan.guard, &issue)?;
        assert_eq!(
            repository.record_bound_scan_issue(&scan.guard, &issue)?,
            issue_id
        );
        Ok((observation_id, issue_id))
    })?;

    let observations = store.list_observations_page(scan.run_id, None, 8)?;
    assert_eq!(observations.items.len(), 1);
    assert_eq!(observations.items[0].id, observation_id);
    let issues = store.list_issues_page(scan.run_id, None, 8)?;
    assert_eq!(issues.items.len(), 1);
    assert_eq!(issues.items[0].id, issue_id);
    assert_eq!(
        store
            .get_scan_checkpoint(scan.run_id)?
            .ok_or("checkpoint missing")?
            .checkpoint_version,
        1
    );
    store.write_transaction(|repository| {
        repository.seal_scan_stage(&scan.guard, ScanStage::Enumeration, 1, 4_096, 281)?;
        repository.seal_scan_stage(&scan.guard, ScanStage::Sampling, 0, 0, 282)?;
        repository.seal_scan_stage(&scan.guard, ScanStage::FullHash, 0, 0, 283)?;
        repository.seal_scan_stage(&scan.guard, ScanStage::ExactVerification, 0, 0, 284)?;
        Ok(())
    })?;
    assert_eq!(
        store.write_transaction(|repository| repository.transition_bound_scan_job_and_run(
            &scan.guard,
            scan.job_id,
            "running",
            1,
            "running",
            1,
            "completed",
            "completed",
            300,
            None,
        ))?,
        (2, 2)
    );
    let run = store
        .get_scan_run("roundtrip-run")?
        .ok_or("completed run missing")?;
    assert_eq!(run.state, "completed");
    assert_eq!(run.discovered_count, 1);
    assert_eq!(run.logical_bytes_seen, 4_096);
    Ok(())
}

#[test]
fn transaction_error_rolls_back_all_writes() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("rollback.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let result: Result<(), StoreError> = store.write_transaction(|repository| {
        repository.upsert_volume(&volume_input("rollback-volume"))?;
        Err(StoreError::InvalidInput {
            field: "test",
            reason: "force rollback".into(),
        })
    });
    assert!(result.is_err());
    store.close()?;

    let connection = Connection::open(&database)?;
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM volumes WHERE identity_key = 'rollback-volume'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn retired_create_scan_job_is_zero_write_and_poisons_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("legacy-job.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let result = store.write_transaction(|repository| {
        repository.upsert_volume(&volume_input("legacy-job-sentinel"))?;
        let error = repository
            .create_scan_job(&legacy_job_input())
            .expect_err("retired create_scan_job unexpectedly accepted evidence");
        assert!(matches!(
            error,
            StoreError::LegacyEvidenceApiDisabled {
                api: "create_scan_job"
            }
        ));
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::WriteTransactionPoisoned)));
    store.close()?;
    assert_legacy_transaction_left_no_rows(&database)?;
    Ok(())
}

#[test]
fn retired_create_scan_run_is_zero_write_and_poisons_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("legacy-run.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let result = store.write_transaction(|repository| {
        repository.upsert_volume(&volume_input("legacy-run-sentinel"))?;
        let error = repository
            .create_scan_run(&legacy_run_input())
            .expect_err("retired create_scan_run unexpectedly accepted evidence");
        assert!(matches!(
            error,
            StoreError::LegacyEvidenceApiDisabled {
                api: "create_scan_run"
            }
        ));
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::WriteTransactionPoisoned)));
    store.close()?;
    assert_legacy_transaction_left_no_rows(&database)?;
    Ok(())
}

#[test]
fn retired_upsert_media_file_is_zero_write_and_poisons_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("legacy-media.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let result = store.write_transaction(|repository| {
        repository.upsert_volume(&volume_input("legacy-media-sentinel"))?;
        let error = repository
            .upsert_media_file(&legacy_media_input())
            .expect_err("retired upsert_media_file unexpectedly accepted evidence");
        assert!(matches!(
            error,
            StoreError::LegacyEvidenceApiDisabled {
                api: "upsert_media_file"
            }
        ));
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::WriteTransactionPoisoned)));
    store.close()?;
    assert_legacy_transaction_left_no_rows(&database)?;
    Ok(())
}

#[test]
fn retired_record_scan_issue_is_zero_write_and_poisons_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("legacy-issue.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let result = store.write_transaction(|repository| {
        repository.upsert_volume(&volume_input("legacy-issue-sentinel"))?;
        let error = repository
            .record_scan_issue(&NewScanIssue {
                issue_key: "legacy-issue".into(),
                volume_id: 1,
                scan_run_id: 1,
                media_file_id: None,
                severity: "warning".into(),
                stage: "scan".into(),
                code: "legacy".into(),
                message: "legacy".into(),
                details: None,
                occurred_at_ms: 1,
            })
            .expect_err("retired record_scan_issue unexpectedly accepted evidence");
        assert!(matches!(
            error,
            StoreError::LegacyEvidenceApiDisabled {
                api: "record_scan_issue"
            }
        ));
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::WriteTransactionPoisoned)));
    store.close()?;
    assert_legacy_transaction_left_no_rows(&database)?;
    Ok(())
}

#[test]
fn retired_write_scan_report_is_zero_write_and_poisons_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("legacy-report.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let result = store.write_transaction(|repository| {
        repository.upsert_volume(&volume_input("legacy-report-sentinel"))?;
        let error = repository
            .write_scan_report(&NewScanReport {
                report_key: "legacy-report".into(),
                volume_id: 1,
                scan_run_id: 1,
                report_version: 1,
                report: json!({"legacy": true}),
                generated_at_ms: 1,
            })
            .expect_err("retired write_scan_report unexpectedly accepted evidence");
        assert!(matches!(
            error,
            StoreError::LegacyEvidenceApiDisabled {
                api: "write_scan_report"
            }
        ));
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::WriteTransactionPoisoned)));
    store.close()?;
    assert_legacy_transaction_left_no_rows(&database)?;
    Ok(())
}

#[test]
fn retired_update_scan_progress_is_zero_write_and_poisons_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("legacy-progress.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let result = store.write_transaction(|repository| {
        repository.upsert_volume(&volume_input("legacy-progress-sentinel"))?;
        let error = repository
            .update_scan_progress(1, 1, 0, 0, 1, 1)
            .expect_err("retired update_scan_progress unexpectedly accepted evidence");
        assert!(matches!(
            error,
            StoreError::LegacyEvidenceApiDisabled {
                api: "update_scan_progress"
            }
        ));
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::WriteTransactionPoisoned)));
    store.close()?;
    assert_legacy_transaction_left_no_rows(&database)?;
    Ok(())
}

#[test]
fn retired_save_scan_checkpoint_is_zero_write_and_poisons_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("legacy-checkpoint.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let result = store.write_transaction(|repository| {
        repository.upsert_volume(&volume_input("legacy-checkpoint-sentinel"))?;
        let error = repository
            .save_scan_checkpoint(&ScanCheckpointInput {
                scan_run_id: 1,
                volume_id: 1,
                expected_previous_version: None,
                cursor_version: 1,
                cursor: json!({"legacy": true}),
                discovered_count: 0,
                fingerprinted_count: 0,
                error_count: 0,
                logical_bytes_seen: 0,
                saved_at_ms: 1,
            })
            .expect_err("retired save_scan_checkpoint unexpectedly accepted evidence");
        assert!(matches!(
            error,
            StoreError::LegacyEvidenceApiDisabled {
                api: "save_scan_checkpoint"
            }
        ));
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::WriteTransactionPoisoned)));
    store.close()?;
    assert_legacy_transaction_left_no_rows(&database)?;
    Ok(())
}

#[test]
fn retired_transition_scan_pair_is_zero_write_and_poisons_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("legacy-transition.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let result = store.write_transaction(|repository| {
        repository.upsert_volume(&volume_input("legacy-transition-sentinel"))?;
        let error = repository
            .transition_scan_job_and_run(
                1,
                1,
                1,
                "0000000000000000000000000000000000000000000000000000000000000000",
                "queued",
                0,
                "queued",
                0,
                "running",
                "running",
                1,
                None,
            )
            .expect_err("retired transition_scan_job_and_run unexpectedly accepted evidence");
        assert!(matches!(
            error,
            StoreError::LegacyEvidenceApiDisabled {
                api: "transition_scan_job_and_run"
            }
        ));
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::WriteTransactionPoisoned)));
    store.close()?;
    assert_legacy_transaction_left_no_rows(&database)?;
    Ok(())
}

#[test]
fn v5_observations_require_running_current_session() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("observation-state.sqlite3"))?;
    let scan = create_running_scan(&mut store, "observation-state", 10)?;
    store.write_transaction(|repository| {
        repository.transition_bound_scan_job_and_run(
            &scan.guard,
            scan.job_id,
            "running",
            1,
            "running",
            1,
            "paused",
            "paused",
            250,
            None,
        )
    })?;

    let paused = store
        .write_transaction(|repository| {
            repository.record_observation_batch(&scan.guard, &[observation_input(1, 10)])
        })
        .expect_err("paused run accepted observation evidence");
    assert!(matches!(paused, StoreError::ConcurrencyConflict { .. }));

    store.write_transaction(|repository| {
        repository.transition_bound_scan_job_and_run(
            &scan.guard,
            scan.job_id,
            "paused",
            2,
            "paused",
            2,
            "running",
            "running",
            300,
            None,
        )
    })?;
    assert_eq!(
        store
            .write_transaction(|repository| repository
                .record_observation_batch(&scan.guard, &[observation_input(1, 10)],))?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn v5_paths_are_lossless_and_reject_traversal_or_encoding_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("v5-paths.sqlite3"))?;
    let scan = create_running_scan(&mut store, "paths", 11)?;

    let mut non_utf8 = observation_input(1, 20);
    non_utf8.path_encoding = "unix_bytes".into();
    non_utf8.mount_relative_path_raw = b"DCIM/IMG_\xff.JPG".to_vec();
    non_utf8.root_relative_path_raw = b"IMG_\xff.JPG".to_vec();
    non_utf8.display_path = "IMG_invalid-byte.JPG".into();
    let observation_id = store.write_transaction(|repository| {
        Ok(repository.record_observation_batch(&scan.guard, std::slice::from_ref(&non_utf8))?[0])
    })?;
    let page = store.list_observations_page(scan.run_id, None, 8)?;
    let record = page
        .items
        .iter()
        .find(|record| record.id == observation_id)
        .ok_or("non-UTF-8 observation missing")?;
    assert_eq!(record.mount_relative_path_raw, b"DCIM/IMG_\xff.JPG");
    assert_eq!(record.root_relative_path_raw, b"IMG_\xff.JPG");
    assert_eq!(record.path_encoding, "unix_bytes");
    assert_eq!(record.display_path, "IMG_invalid-byte.JPG");

    let mut traversal = observation_input(2, 20);
    traversal.path_encoding = "unix_bytes".into();
    traversal.root_relative_path_raw = b"../escape.JPG".to_vec();
    let error = store
        .write_transaction(|repository| {
            repository.record_observation_batch(&scan.guard, std::slice::from_ref(&traversal))
        })
        .expect_err("raw traversal path unexpectedly succeeded");
    assert!(matches!(error, StoreError::InvalidInput { .. }));

    let mut mismatch = observation_input(3, 20);
    mismatch.root_relative_path_raw = b"OTHER.JPG".to_vec();
    let error = store
        .write_transaction(|repository| {
            repository.record_observation_batch(&scan.guard, std::slice::from_ref(&mismatch))
        })
        .expect_err("UTF-8 raw/display mismatch unexpectedly succeeded");
    assert!(matches!(error, StoreError::InvalidInput { .. }));
    assert_eq!(
        store
            .list_observations_page(scan.run_id, None, 8)?
            .items
            .len(),
        1
    );
    assert!(matches!(
        PathKey::from_filesystem_adapter(vec![0; PathKey::MAX_BYTES + 1]),
        Err(StoreError::InvalidInput { .. })
    ));
    Ok(())
}

#[test]
fn v5_windows_namespaces_reject_ambiguous_paths_and_foreign_encoding(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("windows-paths.sqlite3"))?;
    let root_raw = windows_raw("DCIM\\photo.jpg");
    let scan = create_running_scan_with_root(
        &mut store,
        "windows",
        12,
        "DCIM/photo.jpg",
        root_raw,
        "windows_utf16_le",
    )?;

    let mut unsafe_paths = vec![
        "DCIM\\..\\escape".to_string(),
        "DCIM\\photo.jpg:stream".to_string(),
        "DCIM\\CON.txt".to_string(),
        "DCIM\\CLOCK$".to_string(),
        "DCIM\\COM0.txt".to_string(),
        "DCIM\\COM¹.txt".to_string(),
        "DCIM\\bad?.jpg".to_string(),
        "DCIM\\bad\u{1}.jpg".to_string(),
        "DCIM\\trailing.".to_string(),
        "C:\\DCIM\\photo.jpg".to_string(),
    ];
    unsafe_paths.push(format!("DCIM\\{}", "a".repeat(8_193)));
    for (index, unsafe_path) in unsafe_paths.iter().enumerate() {
        let byte = 40_u8
            .checked_add(u8::try_from(index).expect("small fixture index"))
            .expect("fixture byte does not overflow");
        let error = store
            .write_transaction(|repository| {
                repository.create_scoped_scan_job(&NewScopedScanJob {
                    job_key: format!("windows-unsafe-{index}"),
                    volume_id: scan.volume_id,
                    namespace_profile_id: scan.namespace_profile_id,
                    root_display: format!("DCIM/safe-{index}"),
                    mount_relative_root_raw: windows_raw(unsafe_path),
                    path_encoding: "windows_utf16_le".into(),
                    stable_root_path_key: StablePathKey::from_volume_adapter([byte; 32]),
                    root_scope_key: RootScopeKey::from_volume_adapter([byte + 20; 32]),
                    config: None,
                    created_at_ms: 400 + i64::try_from(index).expect("small fixture index"),
                })
            })
            .expect_err("ambiguous Windows path unexpectedly succeeded");
        assert!(matches!(error, StoreError::InvalidInput { .. }));
    }

    let foreign_encoding = store
        .write_transaction(|repository| {
            repository.record_observation_batch(&scan.guard, &[observation_input(1, 10)])
        })
        .expect_err("Windows namespace accepted Unix/UTF-8 observation evidence");
    assert!(matches!(foreign_encoding, StoreError::InvalidInput { .. }));
    Ok(())
}

#[test]
fn scan_start_rechecks_current_mount_session() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("mount-session.sqlite3"))?;
    let scan = create_queued_scan(&mut store, "session", 13)?;
    let replacement_guard = RunEvidenceGuard {
        scan_run_id: scan.run_id,
        capability_profile_id: scan.capability_profile_id,
        mount_session_key: MountSessionKey::from_runtime_evidence([14; 32]),
    };
    let stale = store
        .write_transaction(|repository| {
            repository.transition_bound_scan_job_and_run(
                &replacement_guard,
                scan.job_id,
                "queued",
                0,
                "queued",
                0,
                "running",
                "running",
                300,
                None,
            )
        })
        .expect_err("stale mount session unexpectedly started a scan");
    assert!(matches!(stale, StoreError::ConcurrencyConflict { .. }));

    assert_eq!(
        store.write_transaction(|repository| repository.transition_bound_scan_job_and_run(
            &scan.guard,
            scan.job_id,
            "queued",
            0,
            "queued",
            0,
            "running",
            "running",
            400,
            None,
        ))?,
        (1, 1)
    );
    Ok(())
}

#[test]
fn reopen_reconciles_stale_sessions_abandons_drafts_and_allows_fresh_strong_attempt(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("stale-session-recovery.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let queued = create_queued_scan(&mut store, "reconcile-queued", 22)?;
    let running = create_running_scan(&mut store, "reconcile-running", 23)?;
    let paused = create_running_scan(&mut store, "reconcile-paused", 24)?;
    store.write_transaction(|repository| {
        repository.transition_bound_scan_job_and_run(
            &paused.guard,
            paused.job_id,
            "running",
            1,
            "running",
            1,
            "paused",
            "paused",
            250,
            None,
        )?;
        Ok(())
    })?;

    let observation = observation_input(1, 10);
    let draft_id = store.write_transaction(|repository| {
        let observation_id = repository
            .record_observation_batch(&running.guard, std::slice::from_ref(&observation))?[0];
        repository.seal_scan_stage(&running.guard, ScanStage::Enumeration, 1, 10, 230)?;
        repository.seal_scan_stage(&running.guard, ScanStage::Sampling, 0, 0, 231)?;
        let parameters_hash = ParametersHash::from_runtime_evidence([61; 32]);
        let fingerprint_id = repository.record_fingerprint_fresh_batch(
            &running.guard,
            &[FreshFingerprintInput {
                observation_id,
                fingerprint_kind: FreshFingerprintKind::ExactBytes,
                algorithm: "blake3".into(),
                algorithm_version: 1,
                parameters_hash,
                read_origin: FingerprintReadOrigin::FullHashRead,
                source_signature_before: observation.source_signature,
                source_signature_after: observation.source_signature,
                digest: vec![62; 32],
                observed_size_bytes: observation.size_bytes,
                bytes_read: observation.size_bytes,
                reached_expected_eof: true,
                completed_at_ms: 232,
                created_at_ms: 232,
            }],
        )?[0];
        repository.seal_scan_stage(&running.guard, ScanStage::FullHash, 1, 10, 233)?;
        repository.begin_exact_group(
            &running.guard,
            &BeginExactGroupInput {
                build_key: BuildKey::from_runtime_evidence([63; 32]),
                representative_observation_id: observation_id,
                representative_fingerprint_id: fingerprint_id,
                expected_member_count: 2,
                expected_manifest_digest: ManifestDigest::from_runtime_evidence([64; 32]),
                created_at_ms: 234,
            },
        )
    })?;
    store.close()?;

    let mut reopened = Store::open_existing(&database)?;
    for (run_key, job_key, expected_version) in [
        ("reconcile-queued-run", "reconcile-queued-job", 1),
        ("reconcile-running-run", "reconcile-running-job", 2),
        ("reconcile-paused-run", "reconcile-paused-job", 3),
    ] {
        let run = reopened
            .get_scan_run(run_key)?
            .ok_or("reconciled run missing")?;
        let job = reopened
            .get_scan_job(job_key)?
            .ok_or("reconciled job missing")?;
        assert_eq!(run.state, "interrupted");
        assert_eq!(job.state, "failed");
        assert_eq!(run.state_version, expected_version);
        assert_eq!(job.state_version, expected_version);
    }

    for stale in [queued.guard, running.guard, paused.guard] {
        let error = reopened
            .write_transaction(|repository| {
                repository.update_bound_scan_progress(&stale, 1, 0, 0, 1, 300)
            })
            .expect_err("stale process-local guard unexpectedly remained usable");
        assert!(matches!(error, StoreError::ConcurrencyConflict { .. }));
    }

    let inspection =
        Connection::open_with_flags(&database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let (draft_state, abandon_reason, interrupted_code): (String, Option<String>, Option<String>) =
        inspection.query_row(
            "SELECT build.state, build.abandon_reason_code, run.last_error_code \
             FROM exact_group_builds AS build \
             JOIN scan_runs AS run ON run.id = build.scan_run_id \
             WHERE build.id = ?1",
            [draft_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    assert_eq!(draft_state, "abandoned");
    assert_eq!(abandon_reason.as_deref(), Some("PROCESS_RESTARTED"));
    assert_eq!(
        interrupted_code.as_deref(),
        Some("PROCESS_RESTARTED_WITH_STALE_SESSION")
    );
    inspection.close().map_err(|(_, error)| error)?;

    let next_mount = MountSessionKey::from_runtime_evidence([25; 32]);
    let next_created_at_ms = 9_000_000_000_000_i64;
    let next_run_id = reopened.write_transaction(|repository| {
        let next_capability = repository.set_current_capability_profile(&capability_input(
            running.volume_id,
            next_mount,
            "unix",
        ))?;
        let next_run_id = repository.create_bound_scan_run(&NewBoundScanRun {
            run_key: "reconcile-running-run-fresh".into(),
            scan_job_id: running.job_id,
            volume_id: running.volume_id,
            capability_profile_id: next_capability,
            parent_scan_run_id: Some(running.run_id),
            mount_session_key: next_mount,
            mount_relative_root_raw: b"DCIM".to_vec(),
            path_encoding: "utf8".into(),
            stable_root_path_key: StablePathKey::from_volume_adapter([12; 32]),
            root_scope_key: RootScopeKey::from_volume_adapter([13; 32]),
            root_object_signature: RootObjectSignature::from_volume_adapter([15; 32]),
            scan_mode: "resume".into(),
            config: Some(json!({"exact": true})),
            created_at_ms: next_created_at_ms,
        })?;
        let next_guard = RunEvidenceGuard {
            scan_run_id: next_run_id,
            capability_profile_id: next_capability,
            mount_session_key: next_mount,
        };
        assert_eq!(
            repository.transition_bound_scan_job_and_run(
                &next_guard,
                running.job_id,
                "failed",
                2,
                "queued",
                0,
                "running",
                "running",
                next_created_at_ms + 1,
                None,
            )?,
            (3, 1)
        );
        Ok(next_run_id)
    })?;
    let fresh = reopened
        .get_scan_run("reconcile-running-run-fresh")?
        .ok_or("fresh recovery attempt missing")?;
    assert_eq!(fresh.id, next_run_id);
    assert_eq!(fresh.parent_scan_run_id, Some(running.run_id));
    assert_eq!(fresh.state, "running");
    Ok(())
}

#[test]
fn reopen_fails_orphan_scope_and_clears_process_local_capabilities(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("orphan-scope-recovery.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let old_mount = MountSessionKey::from_runtime_evidence([81; 32]);
    let (volume_id, job_id) = store.write_transaction(|repository| {
        let volume_id = repository.upsert_volume(&volume_input("orphan-scope-volume"))?;
        repository
            .set_current_capability_profile(&capability_input(volume_id, old_mount, "unix"))?;
        let namespace_profile_id =
            repository.register_namespace_profile(&NamespaceProfileInput {
                volume_id,
                profile_key: NamespaceProfileKey::from_volume_adapter([82; 32]),
                profile_version: 1,
                native_path_encoding: "unix_bytes".into(),
                case_behavior: "sensitive".into(),
                unicode_behavior: "exact".into(),
                key_strategy: "exact_native_v1".into(),
                key_algorithm_version: 2,
                reuse_scope: "cross_session".into(),
                bound_mount_session_key: None,
                created_at_ms: 100,
            })?;
        let job_id = repository.create_scoped_scan_job(&NewScopedScanJob {
            job_key: "orphan-scope-job".into(),
            volume_id,
            namespace_profile_id,
            root_display: "DCIM".into(),
            mount_relative_root_raw: b"DCIM".to_vec(),
            path_encoding: "utf8".into(),
            stable_root_path_key: StablePathKey::from_volume_adapter([83; 32]),
            root_scope_key: RootScopeKey::from_volume_adapter([84; 32]),
            config: None,
            created_at_ms: 110,
        })?;
        Ok((volume_id, job_id))
    })?;
    store.close()?;

    let mut reopened = Store::open_existing(&database)?;
    let orphan = reopened
        .get_scan_job("orphan-scope-job")?
        .ok_or("orphan scoped job missing after reopen")?;
    assert_eq!(orphan.state, "failed");
    assert_eq!(orphan.state_version, 1);
    assert_eq!(orphan.active_scan_run_id, None);

    let inspection =
        Connection::open_with_flags(&database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    assert_eq!(
        inspection.query_row(
            "SELECT count(*) FROM capability_profiles WHERE is_current = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0
    );
    inspection.close().map_err(|(_, error)| error)?;

    let new_mount = MountSessionKey::from_runtime_evidence([85; 32]);
    reopened.write_transaction(|repository| {
        let capability_profile_id = repository
            .set_current_capability_profile(&capability_input(volume_id, new_mount, "unix"))?;
        let run_id = repository.create_bound_scan_run(&NewBoundScanRun {
            run_key: "orphan-scope-fresh-run".into(),
            scan_job_id: job_id,
            volume_id,
            capability_profile_id,
            parent_scan_run_id: None,
            mount_session_key: new_mount,
            mount_relative_root_raw: b"DCIM".to_vec(),
            path_encoding: "utf8".into(),
            stable_root_path_key: StablePathKey::from_volume_adapter([83; 32]),
            root_scope_key: RootScopeKey::from_volume_adapter([84; 32]),
            root_object_signature: RootObjectSignature::from_volume_adapter([86; 32]),
            scan_mode: "full".into(),
            config: None,
            created_at_ms: 9_000_000_000_000,
        })?;
        let guard = RunEvidenceGuard {
            scan_run_id: run_id,
            capability_profile_id,
            mount_session_key: new_mount,
        };
        assert_eq!(
            repository.transition_bound_scan_job_and_run(
                &guard,
                job_id,
                "failed",
                1,
                "queued",
                0,
                "running",
                "running",
                9_000_000_000_001,
                None,
            )?,
            (2, 1)
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn v5_root_binding_is_checked_before_run_insert() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("root-binding.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let scan = create_queued_scan(&mut store, "root-binding", 15)?;
    let error = store
        .write_transaction(|repository| {
            repository.create_bound_scan_run(&NewBoundScanRun {
                run_key: "mismatched-root-run".into(),
                scan_job_id: scan.job_id,
                volume_id: scan.volume_id,
                capability_profile_id: scan.capability_profile_id,
                parent_scan_run_id: None,
                mount_session_key: scan.guard.mount_session_key,
                mount_relative_root_raw: b"Pictures".to_vec(),
                path_encoding: "utf8".into(),
                stable_root_path_key: StablePathKey::from_volume_adapter([99; 32]),
                root_scope_key: RootScopeKey::from_volume_adapter([98; 32]),
                root_object_signature: RootObjectSignature::from_volume_adapter([97; 32]),
                scan_mode: "full".into(),
                config: None,
                created_at_ms: 300,
            })
        })
        .expect_err("mismatched job/run root unexpectedly succeeded");
    assert!(matches!(error, StoreError::IdempotencyConflict { .. }));
    store.close()?;

    let connection = Connection::open(&database)?;
    let run_count: i64 =
        connection.query_row("SELECT count(*) FROM scan_runs", [], |row| row.get(0))?;
    assert_eq!(run_count, 1);
    Ok(())
}

#[test]
fn v5_repository_rejects_oversized_text_blob_and_json_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("input-bounds.sqlite3"))?;
    let scan = create_running_scan(&mut store, "bounds", 16)?;

    let mut oversized_volume = volume_input(&"v".repeat(1_025));
    oversized_volume.marker_uuid = Some("marker-oversized".into());
    assert!(matches!(
        store.write_transaction(|repository| repository.upsert_volume(&oversized_volume)),
        Err(StoreError::InvalidInput { .. })
    ));

    let mut oversized_capability =
        capability_input(scan.volume_id, scan.guard.mount_session_key, "unix");
    oversized_capability.raw_capabilities = Some(json!({"probe": "x".repeat(1_048_576)}));
    assert!(matches!(
        store.write_transaction(
            |repository| repository.set_current_capability_profile(&oversized_capability)
        ),
        Err(StoreError::InvalidInput { .. })
    ));

    let mut oversized_observation = observation_input(1, 10);
    oversized_observation.native_file_id = Some(vec![0; 1_048_577]);
    assert!(matches!(
        store.write_transaction(|repository| repository
            .record_observation_batch(&scan.guard, std::slice::from_ref(&oversized_observation),)),
        Err(StoreError::InvalidInput { .. })
    ));

    let oversized_issue = NewScanIssue {
        issue_key: "oversized-issue".into(),
        volume_id: scan.volume_id,
        scan_run_id: scan.run_id,
        media_file_id: None,
        severity: "warning".into(),
        stage: "metadata".into(),
        code: "oversized".into(),
        message: "x".repeat(65_537),
        details: None,
        occurred_at_ms: 300,
    };
    assert!(matches!(
        store.write_transaction(
            |repository| repository.record_bound_scan_issue(&scan.guard, &oversized_issue)
        ),
        Err(StoreError::InvalidInput { .. })
    ));
    Ok(())
}

#[test]
fn v5_active_job_pages_are_bounded_and_resumable() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("pages.sqlite3"))?;
    create_queued_scan(&mut store, "page-a", 17)?;
    create_queued_scan(&mut store, "page-b", 18)?;

    let first = store.list_active_scan_jobs_page(None, 1)?;
    assert_eq!(first.items.len(), 1);
    let cursor = first.next_cursor.ok_or("first page had no cursor")?;
    let second = store.list_active_scan_jobs_page(Some(cursor), 1)?;
    assert_eq!(second.items.len(), 1);
    assert!(second.next_cursor.is_none());
    assert!(matches!(
        store.list_active_scan_jobs_page(None, MAX_PAGE_SIZE + 1),
        Err(StoreError::InvalidInput { .. })
    ));
    assert!(matches!(
        store.list_active_scan_jobs_page(Some(-1), 1),
        Err(StoreError::InvalidInput { .. })
    ));
    Ok(())
}

#[test]
fn read_apis_reject_oversized_rows_before_materializing_payloads(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("read-bounds.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let scan = create_running_scan(&mut store, "read-bounds", 19)?;

    let connection = Connection::open(&database)?;
    let oversized_message = "x".repeat(16 * 1024 * 1024 + 1);
    connection.execute(
        "INSERT INTO scan_issues ( \
             issue_key, volume_id, scan_run_id, severity, stage, code, message, occurred_at_ms \
         ) VALUES ('oversized-direct', ?1, ?2, 'warning', 'scan', 'oversized', ?3, 2_000)",
        rusqlite::params![scan.volume_id, scan.run_id, oversized_message],
    )?;
    let oversized_cursor = format!("{{\"payload\":\"{}\"}}", "x".repeat(1024 * 1024));
    connection.execute(
        "INSERT INTO scan_checkpoints ( \
             scan_run_id, volume_id, checkpoint_version, cursor_version, cursor_json, \
             discovered_count, fingerprinted_count, error_count, logical_bytes_seen, saved_at_ms \
         ) VALUES (?1, ?2, 1, 1, ?3, 0, 0, 0, 0, 2_000)",
        rusqlite::params![scan.run_id, scan.volume_id, oversized_cursor],
    )?;
    let oversized_report = format!(
        "{{\"payload\":\"{}\"}}",
        "x".repeat(MAX_SCAN_REPORT_JSON_BYTES)
    );
    connection.execute(
        "INSERT INTO scan_reports ( \
             report_key, volume_id, scan_run_id, report_version, report_json, generated_at_ms \
         ) VALUES ('oversized-direct', ?1, ?2, 2, ?3, 2_000)",
        rusqlite::params![scan.volume_id, scan.run_id, oversized_report],
    )?;
    connection.close().map_err(|(_, error)| error)?;

    assert!(matches!(
        store.list_issues_page(scan.run_id, None, 256),
        Err(StoreError::ReadResultLimit { .. })
    ));
    assert!(matches!(
        store.get_scan_checkpoint(scan.run_id),
        Err(StoreError::ReadResultLimit { .. })
    ));
    assert!(matches!(
        store.get_scan_report("oversized-direct"),
        Err(StoreError::ReadResultLimit { .. })
    ));
    Ok(())
}

#[test]
fn v5_job_run_and_session_bindings_cannot_be_rewritten() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("immutable-bindings.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let scan = create_running_scan(&mut store, "bindings", 20)?;
    store.close()?;

    let connection = Connection::open(&database)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    assert!(connection
        .execute(
            "UPDATE scan_job_runs SET attempt_number = 2 \
             WHERE scan_job_id = ?1 AND scan_run_id = ?2",
            [scan.job_id, scan.run_id],
        )
        .is_err());
    assert!(connection
        .execute(
            "DELETE FROM scan_job_runs WHERE scan_job_id = ?1 AND scan_run_id = ?2",
            [scan.job_id, scan.run_id],
        )
        .is_err());
    assert!(connection
        .execute(
            "UPDATE scan_jobs SET active_scan_run_id = NULL WHERE id = ?1",
            [scan.job_id],
        )
        .is_err());
    assert!(connection
        .execute(
            "UPDATE scan_run_sessions SET mount_session_key = lower(hex(randomblob(32))) \
             WHERE scan_run_id = ?1",
            [scan.run_id],
        )
        .is_err());
    assert!(connection
        .execute(
            "DELETE FROM scan_run_sessions WHERE scan_run_id = ?1",
            [scan.run_id],
        )
        .is_err());
    let active_run: Option<i64> = connection.query_row(
        "SELECT active_scan_run_id FROM scan_jobs WHERE id = ?1",
        [scan.job_id],
        |row| row.get(0),
    )?;
    let session_count: i64 = connection.query_row(
        "SELECT count(*) FROM scan_run_sessions WHERE scan_run_id = ?1",
        [scan.run_id],
        |row| row.get(0),
    )?;
    assert_eq!(active_run, Some(scan.run_id));
    assert_eq!(session_count, 1);
    Ok(())
}

#[test]
fn backup_is_verified_atomic_and_no_clobber() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("source.sqlite3");
    let backup = temporary.path().join("backups/snapshot.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let scan = create_running_scan(&mut store, "backup", 21)?;
    let observation_id = store.write_transaction(|repository| {
        Ok(repository.record_observation_batch(&scan.guard, &[observation_input(1, 10)])?[0])
    })?;

    let source_error = store
        .backup_to(&database)
        .err()
        .ok_or("source database was unexpectedly accepted as its own backup")?;
    assert!(matches!(
        source_error,
        StoreError::BackupDestinationIsSource(_)
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let unsafe_parent = temporary.path().join("unsafe-backup-parent");
        fs::create_dir(&unsafe_parent)?;
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))?;
        let error = store
            .backup_to(unsafe_parent.join("snapshot.sqlite3"))
            .err()
            .ok_or("world-writable backup parent was unexpectedly accepted")?;
        assert!(matches!(error, StoreError::UnsafeBackupParent(_)));
    }

    let result = store.backup_to(&backup);
    assert!(matches!(result, Err(StoreError::ParentDirectoryMissing(_))));
    let published = store.backup_to_with_parent_creation(&backup)?;
    assert_eq!(
        published,
        fs::canonicalize(backup.parent().ok_or("backup parent missing")?)?.join("snapshot.sqlite3")
    );
    assert!(backup.is_file());
    assert!(matches!(
        store.backup_to(&backup),
        Err(StoreError::BackupDestinationExists(_))
    ));
    store.close()?;

    let backup_store = Store::open_existing(&backup)?;
    assert!(backup_store
        .integrity_check(IntegrityCheckKind::Full)?
        .is_healthy());
    assert_eq!(
        backup_store
            .list_observations_page(scan.run_id, None, 8)?
            .items
            .first()
            .ok_or("observation missing from backup")?
            .id,
        observation_id
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ScanFixture {
    volume_id: i64,
    capability_profile_id: i64,
    namespace_profile_id: i64,
    job_id: i64,
    run_id: i64,
    guard: RunEvidenceGuard,
}

fn create_queued_scan(
    store: &mut Store,
    prefix: &str,
    session_byte: u8,
) -> Result<ScanFixture, StoreError> {
    create_queued_scan_with_root(
        store,
        prefix,
        session_byte,
        "DCIM",
        b"DCIM".to_vec(),
        "utf8",
    )
}

fn create_running_scan(
    store: &mut Store,
    prefix: &str,
    session_byte: u8,
) -> Result<ScanFixture, StoreError> {
    create_running_scan_with_root(
        store,
        prefix,
        session_byte,
        "DCIM",
        b"DCIM".to_vec(),
        "utf8",
    )
}

fn create_running_scan_with_root(
    store: &mut Store,
    prefix: &str,
    session_byte: u8,
    root_display: &str,
    root_raw: Vec<u8>,
    path_encoding: &str,
) -> Result<ScanFixture, StoreError> {
    let scan = create_queued_scan_with_root(
        store,
        prefix,
        session_byte,
        root_display,
        root_raw,
        path_encoding,
    )?;
    store.write_transaction(|repository| {
        repository.transition_bound_scan_job_and_run(
            &scan.guard,
            scan.job_id,
            "queued",
            0,
            "queued",
            0,
            "running",
            "running",
            200,
            None,
        )
    })?;
    Ok(scan)
}

fn create_queued_scan_with_root(
    store: &mut Store,
    prefix: &str,
    session_byte: u8,
    root_display: &str,
    root_raw: Vec<u8>,
    path_encoding: &str,
) -> Result<ScanFixture, StoreError> {
    let mount_session_key = MountSessionKey::from_runtime_evidence([session_byte; 32]);
    let path_family = if path_encoding == "windows_utf16_le" {
        "windows"
    } else {
        "unix"
    };
    let native_path_encoding = if path_family == "windows" {
        "windows_utf16_le"
    } else {
        "unix_bytes"
    };
    store.write_transaction(|repository| {
        let volume_id = repository.upsert_volume(&volume_input(&format!("{prefix}-volume")))?;
        let capability_profile_id = repository.set_current_capability_profile(
            &capability_input(volume_id, mount_session_key, path_family),
        )?;
        let namespace_profile_id =
            repository.register_namespace_profile(&NamespaceProfileInput {
                volume_id,
                profile_key: NamespaceProfileKey::from_volume_adapter([11; 32]),
                profile_version: 1,
                native_path_encoding: native_path_encoding.into(),
                case_behavior: if path_family == "windows" {
                    "insensitive_preserving".into()
                } else {
                    "sensitive".into()
                },
                unicode_behavior: "exact".into(),
                key_strategy: "exact_native_v1".into(),
                key_algorithm_version: 2,
                reuse_scope: "cross_session".into(),
                bound_mount_session_key: None,
                created_at_ms: 100,
            })?;
        let stable_root_path_key = StablePathKey::from_volume_adapter([12; 32]);
        let root_scope_key = RootScopeKey::from_volume_adapter([13; 32]);
        let job_id = repository.create_scoped_scan_job(&NewScopedScanJob {
            job_key: format!("{prefix}-job"),
            volume_id,
            namespace_profile_id,
            root_display: root_display.into(),
            mount_relative_root_raw: root_raw.clone(),
            path_encoding: path_encoding.into(),
            stable_root_path_key,
            root_scope_key,
            config: Some(json!({"exact": true})),
            created_at_ms: 110,
        })?;
        let run_id = repository.create_bound_scan_run(&NewBoundScanRun {
            run_key: format!("{prefix}-run"),
            scan_job_id: job_id,
            volume_id,
            capability_profile_id,
            parent_scan_run_id: None,
            mount_session_key,
            mount_relative_root_raw: root_raw,
            path_encoding: path_encoding.into(),
            stable_root_path_key,
            root_scope_key,
            root_object_signature: RootObjectSignature::from_volume_adapter([14; 32]),
            scan_mode: "full".into(),
            config: Some(json!({"exact": true})),
            created_at_ms: 120,
        })?;
        Ok(ScanFixture {
            volume_id,
            capability_profile_id,
            namespace_profile_id,
            job_id,
            run_id,
            guard: RunEvidenceGuard {
                scan_run_id: run_id,
                capability_profile_id,
                mount_session_key,
            },
        })
    })
}

fn observation_input(index: u8, size_bytes: i64) -> ObservationInput {
    let filename = format!("photo-{index}.jpg");
    ObservationInput {
        stable_path_key: StablePathKey::from_volume_adapter([20_u8.wrapping_add(index); 32]),
        mount_relative_path_raw: format!("DCIM/{filename}").into_bytes(),
        root_relative_path_raw: filename.as_bytes().to_vec(),
        path_encoding: "utf8".into(),
        display_path: filename,
        entry_type: "regular".into(),
        media_kind: "photo".into(),
        mime_type: Some("image/jpeg".into()),
        file_extension: Some("jpg".into()),
        source_signature: SourceSignature::from_runtime_evidence([30_u8.wrapping_add(index); 32]),
        stat_signature_version: 2,
        file_object_key: Some(FileObjectKey::from_runtime_evidence(
            [40_u8.wrapping_add(index); 32],
        )),
        native_file_id: Some(vec![index; 8]),
        native_file_generation: Some(1),
        file_mode: 0o100_644,
        size_bytes,
        allocated_bytes: Some(size_bytes),
        link_count: Some(1),
        is_sparse: Some(false),
        may_share_content: Some(false),
        birth_time: Some(FileTimestampParts {
            seconds: 1_000,
            nanoseconds: 0,
        }),
        modified_time: FileTimestampParts {
            seconds: 2_000,
            nanoseconds: 0,
        },
        changed_time: FileTimestampParts {
            seconds: 3_000,
            nanoseconds: 0,
        },
        accessed_time: None,
        timestamp_granularity_ns: Some(1),
        observed_at_ms: 220 + i64::from(index),
    }
}

fn assert_legacy_transaction_left_no_rows(
    database: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open(database)?;
    let counts: (i64, i64, i64, i64, i64, i64, i64) = connection.query_row(
        "SELECT \
             (SELECT count(*) FROM volumes), \
             (SELECT count(*) FROM scan_jobs), \
             (SELECT count(*) FROM scan_runs), \
             (SELECT count(*) FROM media_files), \
             (SELECT count(*) FROM scan_checkpoints), \
             (SELECT count(*) FROM scan_issues), \
             (SELECT count(*) FROM scan_reports)",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        },
    )?;
    assert_eq!(counts, (0, 0, 0, 0, 0, 0, 0));
    Ok(())
}

fn legacy_job_input() -> NewScanJob {
    NewScanJob {
        job_key: "legacy-job".into(),
        volume_id: 1,
        capability_profile_id: 1,
        root_relative_path: "DCIM".into(),
        root_relative_path_raw: b"DCIM".to_vec(),
        root_path_encoding: "utf8".into(),
        root_path_key: path_key(b"dcim"),
        path_semantics_version: 1,
        config: None,
        created_at_ms: 1,
    }
}

fn legacy_run_input() -> NewScanRun {
    NewScanRun {
        run_key: "legacy-run".into(),
        scan_job_id: 1,
        volume_id: 1,
        capability_profile_id: 1,
        parent_scan_run_id: None,
        root_relative_path: "DCIM".into(),
        root_relative_path_raw: b"DCIM".to_vec(),
        root_path_encoding: "utf8".into(),
        root_path_key: path_key(b"dcim"),
        path_semantics_version: 1,
        scan_mode: "full".into(),
        config: None,
        created_at_ms: 1,
    }
}

fn legacy_media_input() -> MediaFileInput {
    MediaFileInput {
        volume_id: 1,
        scan_run_id: 1,
        capability_profile_id: 1,
        path_semantics_version: 1,
        relative_path: "DCIM/legacy.jpg".into(),
        relative_path_raw: b"DCIM/legacy.jpg".to_vec(),
        path_encoding: "utf8".into(),
        path_key: path_key(b"dcim/legacy.jpg"),
        entry_type: "regular".into(),
        media_kind: "photo".into(),
        mime_type: Some("image/jpeg".into()),
        file_extension: Some("jpg".into()),
        lifecycle_state: "present".into(),
        size_bytes: Some(1),
        allocated_bytes: Some(1),
        native_file_id: None,
        native_file_generation: None,
        link_count: Some(1),
        is_sparse: Some(false),
        may_share_content: Some(false),
        birth_time_ns: None,
        modified_time_ns: Some(1),
        changed_time_ns: Some(1),
        accessed_time_ns: None,
        timestamp_granularity_ns: Some(1),
        stat_signature: Some(vec![1; 32]),
        metadata: None,
        observed_at_ms: 1,
    }
}

fn path_key(bytes: &[u8]) -> PathKey {
    PathKey::from_filesystem_adapter(bytes.to_vec()).expect("fixture path key is valid")
}

fn windows_raw(path: &str) -> Vec<u8> {
    path.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[cfg(unix)]
fn make_private(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn make_private(_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn volume_input(identity_key: &str) -> VolumeInput {
    VolumeInput {
        identity_key: identity_key.into(),
        identity_strength: "strong".into(),
        marker_uuid: Some(format!("marker-{identity_key}")),
        native_uuid: Some(format!("native-{identity_key}")),
        filesystem_type: "apfs".into(),
        display_name: Some("Fixture Volume".into()),
        mount_source: Some("fixture".into()),
        last_mount_path: Some("/Volumes/Fixture".into()),
        transport: Some("virtual".into()),
        is_network: false,
        is_read_only: true,
        now_ms: 100,
    }
}

fn capability_input(
    volume_id: i64,
    mount_session_key: MountSessionKey,
    path_encoding_family: &str,
) -> CapabilityProfileInput {
    CapabilityProfileInput {
        volume_id,
        probe_mode: "passive".into(),
        probe_status: "complete".into(),
        observed_at_ms: 100,
        os_build: "test-os".into(),
        mount_session_key: Some(mount_session_key.to_storage_hex()),
        probe_protocol_version: Some(1),
        driver_name: Some("fixture-driver".into()),
        driver_version: Some("1".into()),
        mount_flags: Some(0),
        case_behavior: Some(if path_encoding_family == "windows" {
            "insensitive_preserving".into()
        } else {
            "sensitive".into()
        }),
        unicode_behavior: Some("exact".into()),
        path_encoding_family: Some(path_encoding_family.into()),
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
