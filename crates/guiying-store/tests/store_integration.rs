use std::fs;

use guiying_store::{
    compute_capability_profile_hash, CapabilityProfileInput, IntegrityCheckKind, MediaFileInput,
    NewScanIssue, NewScanJob, NewScanReport, NewScanRun, PathKey, RepositoryTx,
    ScanCheckpointInput, Store, StoreError, VolumeInput, MAX_PAGE_SIZE, MAX_SCAN_REPORT_JSON_BYTES,
};
use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;

#[test]
fn open_enforces_settings_migrations_and_integrity() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("guiying.sqlite3");
    let store = Store::open_or_create(&database)?;

    assert_eq!(store.schema_version()?, 4);
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
    assert_eq!(migration_count, 4);
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    assert_eq!(application_id, 0x4755_5949);
    connection.close().map_err(|(_, error)| error)?;

    let reopened = Store::open_existing(&database)?;
    assert_eq!(reopened.schema_version()?, 4);
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
        repository.set_current_capability_profile(&capability_input(volume))
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
    let original = capability_input(volume);
    store.write_transaction(|repository| {
        let first = repository.set_current_capability_profile(&original)?;
        assert_eq!(repository.set_current_capability_profile(&original)?, first);
        Ok(())
    })?;
    store.close()?;

    let mut different = capability_input(volume);
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
    let original = capability_input(7);
    let original_hash = compute_capability_profile_hash(&original)?;

    let mut variations = Vec::new();
    let mut changed = original.clone();
    changed.mount_session_key = Some("other-session".into());
    variations.push(changed);
    let mut changed = original.clone();
    changed.probe_protocol_version = Some(2);
    variations.push(changed);
    let mut changed = original.clone();
    changed.case_behavior = Some("sensitive".into());
    variations.push(changed);
    let mut changed = original.clone();
    changed.unicode_behavior = Some("nfd".into());
    variations.push(changed);
    let mut changed = original.clone();
    changed.path_encoding_family = Some("windows".into());
    variations.push(changed);
    let mut changed = original.clone();
    changed.path_semantics_version = 2;
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
fn coordinated_transitions_reject_aba_and_roll_back_both_halves(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("state-cas.sqlite3"))?;
    let ids = seed_queued_scan(&mut store)?;

    for (job_from, run_from, job_to, run_to, expected_version, now_ms) in [
        ("queued", "queued", "running", "running", 0, 1_500),
        ("running", "running", "paused", "paused", 1, 1_600),
    ] {
        assert_eq!(
            store.write_transaction(|repository| repository.transition_scan_job_and_run(
                ids.job,
                ids.run,
                ids.capability,
                "fixture-mount-session",
                job_from,
                expected_version,
                run_from,
                expected_version,
                job_to,
                run_to,
                now_ms,
                None,
            ))?,
            (expected_version + 1, expected_version + 1)
        );
    }

    let poisoned = store.write_transaction(|repository| {
        let error = repository
            .transition_scan_job_and_run(
                ids.job,
                ids.run,
                ids.capability,
                "fixture-mount-session",
                "paused",
                2,
                "paused",
                1,
                "running",
                "running",
                1_700,
                None,
            )
            .expect_err("stale run CAS succeeded");
        assert!(matches!(error, StoreError::ConcurrencyConflict { .. }));
        Ok(())
    });
    assert!(matches!(
        poisoned,
        Err(StoreError::WriteTransactionPoisoned)
    ));
    assert_eq!(
        store
            .get_scan_job("job-1")?
            .ok_or("job missing")?
            .state_version,
        2
    );
    assert_eq!(
        store
            .get_scan_run("run-1")?
            .ok_or("run missing")?
            .state_version,
        2
    );

    assert_eq!(
        store.write_transaction(|repository| repository.transition_scan_job_and_run(
            ids.job,
            ids.run,
            ids.capability,
            "fixture-mount-session",
            "paused",
            2,
            "paused",
            2,
            "running",
            "running",
            1_700,
            None,
        ))?,
        (3, 3)
    );
    assert_eq!(
        store.write_transaction(|repository| repository.transition_scan_job_and_run(
            ids.job,
            ids.run,
            ids.capability,
            "fixture-mount-session",
            "running",
            3,
            "running",
            3,
            "paused",
            "paused",
            1_800,
            None,
        ))?,
        (4, 4)
    );
    let error = store
        .write_transaction(|repository| {
            repository.transition_scan_job_and_run(
                ids.job,
                ids.run,
                ids.capability,
                "fixture-mount-session",
                "paused",
                2,
                "paused",
                2,
                "cancelled",
                "cancelled",
                1_900,
                None,
            )
        })
        .err()
        .ok_or("ABA transition was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::ConcurrencyConflict { .. }));

    let error = store
        .write_transaction(|repository| {
            repository.transition_scan_job_and_run(
                ids.job,
                ids.run,
                ids.capability,
                "fixture-mount-session",
                "paused",
                4,
                "paused",
                4,
                "failed",
                "failed",
                1_900,
                None,
            )
        })
        .err()
        .ok_or("failed transition without error evidence was accepted")?;
    assert!(matches!(error, StoreError::InvalidInput { .. }));
    assert_eq!(
        store.write_transaction(|repository| repository.transition_scan_job_and_run(
            ids.job,
            ids.run,
            ids.capability,
            "fixture-mount-session",
            "paused",
            4,
            "paused",
            4,
            "failed",
            "failed",
            2_000,
            Some(("io_error", "fixture failure")),
        ))?,
        (5, 5)
    );
    Ok(())
}

#[test]
fn repository_round_trip_is_idempotent_and_queryable() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("repository.sqlite3");
    let mut store = Store::open_or_create(database)?;
    let ids = seed_repository(&mut store)?;

    let job = store
        .get_scan_job("job-1")?
        .ok_or("scan job was not stored")?;
    assert_eq!(job.id, ids.job);
    assert_eq!(job.active_scan_run_id, Some(ids.run));
    let run = store
        .get_scan_run("run-1")?
        .ok_or("scan run was not stored")?;
    assert_eq!(run.id, ids.run);
    let files = store.list_files_page(ids.run, None, 32)?;
    assert_eq!(files.items.len(), 1);
    assert_eq!(files.items[0].id, ids.media);
    let issues = store.list_issues_page(ids.run, None, 32)?;
    assert_eq!(issues.items.len(), 1);
    assert_eq!(issues.items[0].id, ids.issue);
    let report = store
        .get_scan_report("report-1")?
        .ok_or("scan report was not stored")?;
    assert_eq!(report.id, ids.report);
    assert_eq!(report.report, json!({"duplicates": 1, "safe": true}));

    store.write_transaction(|repository| {
        repository.update_scan_progress(ids.run, 10, 4, 1, 4_096, 2_000)?;
        assert_eq!(
            repository.save_scan_checkpoint(&ScanCheckpointInput {
                scan_run_id: ids.run,
                volume_id: ids.volume,
                expected_previous_version: None,
                cursor_version: 1,
                cursor: json!({"last_id": ids.media}),
                discovered_count: 10,
                fingerprinted_count: 4,
                error_count: 1,
                logical_bytes_seen: 4_096,
                saved_at_ms: 2_050,
            })?,
            1
        );
        assert_eq!(
            repository.transition_scan_job_and_run(
                ids.job,
                ids.run,
                ids.capability,
                "fixture-mount-session",
                "running",
                1,
                "running",
                1,
                "completed",
                "completed",
                2_200,
                None,
            )?,
            (2, 2)
        );
        Ok(())
    })?;
    let updated_job = store
        .get_scan_job("job-1")?
        .ok_or("updated scan job was not stored")?;
    assert_eq!(updated_job.state, "completed");
    assert_eq!(updated_job.state_version, 2);
    let updated_run = store
        .get_scan_run("run-1")?
        .ok_or("updated scan run was not stored")?;
    assert_eq!(updated_run.state, "completed");
    assert_eq!(updated_run.discovered_count, 10);
    assert_eq!(updated_run.logical_bytes_seen, 4_096);
    store.write_transaction(|repository| {
        assert_eq!(
            repository.create_scan_run(&NewScanRun {
                run_key: "run-1".into(),
                scan_job_id: ids.job,
                volume_id: ids.volume,
                capability_profile_id: ids.capability,
                parent_scan_run_id: None,
                root_relative_path: "DCIM".into(),
                root_relative_path_raw: b"DCIM".to_vec(),
                root_path_encoding: "utf8".into(),
                root_path_key: path_key(b"dcim")?,
                path_semantics_version: 1,
                scan_mode: "full".into(),
                config: Some(json!({"exact": true})),
                created_at_ms: 1_100,
            })?,
            ids.run
        );
        Ok(())
    })?;
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
fn caught_mutator_error_poison_rolls_back_partial_writes() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("poison.sqlite3"))?;
    let ids = seed_repository(&mut store)?;

    let result = store.write_transaction(|repository| {
        let mut changed = media_input(ids.volume, ids.run, ids.capability);
        changed.size_bytes = Some(20);
        changed.observed_at_ms = 1_300;
        let error = repository
            .upsert_media_file(&changed)
            .expect_err("conflicting observation unexpectedly succeeded");
        assert!(matches!(error, StoreError::IdempotencyConflict { .. }));

        let follow_up = repository
            .record_scan_issue(&NewScanIssue {
                issue_key: "must-not-commit".into(),
                volume_id: ids.volume,
                scan_run_id: ids.run,
                media_file_id: Some(ids.media),
                severity: "warning".into(),
                stage: "scan".into(),
                code: "poisoned".into(),
                message: "poisoned transaction".into(),
                details: None,
                occurred_at_ms: 1_301,
            })
            .expect_err("a poisoned repository accepted another mutator");
        assert!(matches!(follow_up, StoreError::WriteTransactionPoisoned));
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::WriteTransactionPoisoned)));

    let files = store.list_files_page(ids.run, None, 32)?;
    let media = files
        .items
        .iter()
        .find(|media| media.id == ids.media)
        .ok_or("seed media missing")?;
    assert_eq!(media.size_bytes, Some(4_096));
    assert!(store
        .list_issues_page(ids.run, None, 32)?
        .items
        .iter()
        .all(|issue| issue.issue_key != "must-not-commit"));
    Ok(())
}

#[test]
fn media_observations_require_a_running_current_profile() -> Result<(), Box<dyn std::error::Error>>
{
    for state in [
        "queued",
        "running",
        "paused",
        "completed",
        "failed",
        "cancelled",
        "interrupted",
    ] {
        let temporary = TempDir::new()?;
        let mut store = Store::open_or_create(
            temporary
                .path()
                .join(format!("observation-{state}.sqlite3")),
        )?;
        let ids = seed_queued_scan(&mut store)?;
        if state != "queued" {
            store.write_transaction(|repository| {
                repository.transition_scan_job_and_run(
                    ids.job,
                    ids.run,
                    ids.capability,
                    "fixture-mount-session",
                    "queued",
                    0,
                    "queued",
                    0,
                    "running",
                    "running",
                    1_150,
                    None,
                )?;
                Ok(())
            })?;
        }
        if !matches!(state, "queued" | "running") {
            let (job_state, run_state, last_error) = match state {
                "interrupted" => (
                    "failed",
                    "interrupted",
                    Some(("interrupted", "fixture interruption")),
                ),
                "failed" => ("failed", "failed", Some(("failed", "fixture failure"))),
                state => (state, state, None),
            };
            store.write_transaction(|repository| {
                repository.transition_scan_job_and_run(
                    ids.job,
                    ids.run,
                    ids.capability,
                    "fixture-mount-session",
                    "running",
                    1,
                    "running",
                    1,
                    job_state,
                    run_state,
                    1_300,
                    last_error,
                )?;
                Ok(())
            })?;
        }

        let mut media = media_input(ids.volume, ids.run, ids.capability);
        media.relative_path = "DCIM/STATE.JPG".into();
        media.relative_path_raw = b"DCIM/STATE.JPG".to_vec();
        media.path_key = path_key(b"dcim/state.jpg")?;
        media.observed_at_ms = 1_400;
        let result = store.write_transaction(|repository| repository.upsert_media_file(&media));
        if state == "running" {
            assert!(
                result.is_ok(),
                "running observation was rejected: {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(StoreError::IdempotencyConflict { .. })),
                "{state} observation was not rejected: {result:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn observation_trigger_rejects_non_running_direct_writes() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let database = temporary.path().join("observation-trigger.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let ids = seed_queued_scan(&mut store)?;
    store.close()?;

    let connection = Connection::open(&database)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.execute(
        "INSERT INTO media_files ( \
             volume_id, first_seen_scan_run_id, last_seen_scan_run_id, relative_path, path_key, \
             entry_type, media_kind, lifecycle_state, created_at_ms, updated_at_ms \
         ) VALUES (?1, ?2, ?2, 'DCIM/DIRECT.JPG', x'01', \
                   'regular', 'photo', 'present', 1_200, 1_200)",
        rusqlite::params![ids.volume, ids.run],
    )?;
    let media = connection.last_insert_rowid();
    connection.execute(
        "INSERT INTO media_path_keys ( \
             volume_id, media_file_id, capability_profile_id, path_semantics_version, \
             semantic_path_key, created_at_ms \
         ) VALUES (?1, ?2, ?3, 1, x'02', 1_200)",
        rusqlite::params![ids.volume, media, ids.capability],
    )?;
    let error = connection
        .execute(
            "INSERT INTO media_file_observations ( \
                 volume_id, media_file_id, scan_run_id, capability_profile_id, \
                 path_semantics_version, relative_path, relative_path_raw, path_encoding, \
                 semantic_path_key, observed_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, 1, 'DCIM/DIRECT.JPG', \
                       CAST('DCIM/DIRECT.JPG' AS BLOB), 'utf8', x'02', 1_200)",
            rusqlite::params![ids.volume, media, ids.run, ids.capability],
        )
        .expect_err("queued run bypassed the observation trigger");
    assert!(matches!(error, rusqlite::Error::SqliteFailure(_, _)));
    Ok(())
}

#[test]
fn scan_start_rechecks_current_mount_session() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("start-session.sqlite3"))?;
    let ids = seed_queued_scan(&mut store)?;

    let wrong_session = store.write_transaction(|repository| {
        repository.transition_scan_job_and_run(
            ids.job,
            ids.run,
            ids.capability,
            "stale-session",
            "queued",
            0,
            "queued",
            0,
            "running",
            "running",
            1_150,
            None,
        )
    });
    assert!(matches!(
        wrong_session,
        Err(StoreError::ConcurrencyConflict { .. })
    ));

    let mut reprobe = capability_input(ids.volume);
    reprobe.mount_session_key = Some("replacement-session".into());
    reprobe.driver_version = Some("replacement".into());
    let replacement = store
        .write_transaction(|repository| repository.set_current_capability_profile(&reprobe))?;
    assert_ne!(replacement, ids.capability);

    let stale_profile = store.write_transaction(|repository| {
        repository.transition_scan_job_and_run(
            ids.job,
            ids.run,
            ids.capability,
            "fixture-mount-session",
            "queued",
            0,
            "queued",
            0,
            "running",
            "running",
            1_200,
            None,
        )
    });
    assert!(matches!(
        stale_profile,
        Err(StoreError::ConcurrencyConflict { .. })
    ));
    assert_eq!(
        store.get_scan_run("run-1")?.ok_or("run missing")?.state,
        "queued"
    );
    Ok(())
}

#[test]
fn repository_rejects_oversized_text_blob_and_json_inputs() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("input-bounds.sqlite3"))?;
    let ids = seed_repository(&mut store)?;

    let mut oversized_volume = volume_input(&"v".repeat(1_025));
    oversized_volume.marker_uuid = Some("marker-oversized".into());
    let error = store
        .write_transaction(|repository| repository.upsert_volume(&oversized_volume))
        .expect_err("oversized identifier was accepted");
    assert!(matches!(error, StoreError::InvalidInput { .. }));

    let mut oversized_capability = capability_input(ids.volume);
    oversized_capability.raw_capabilities = Some(json!({"probe": "x".repeat(1_048_576)}));
    let error = store
        .write_transaction(|repository| {
            repository.set_current_capability_profile(&oversized_capability)
        })
        .expect_err("oversized capability JSON was accepted");
    assert!(matches!(error, StoreError::InvalidInput { .. }));

    let mut oversized_media = media_input(ids.volume, ids.run, ids.capability);
    oversized_media.native_file_id = Some(vec![0; 1_048_577]);
    let error = store
        .write_transaction(|repository| repository.upsert_media_file(&oversized_media))
        .expect_err("oversized opaque blob was accepted");
    assert!(matches!(error, StoreError::InvalidInput { .. }));

    let oversized_issue = NewScanIssue {
        issue_key: "oversized-issue".into(),
        volume_id: ids.volume,
        scan_run_id: ids.run,
        media_file_id: Some(ids.media),
        severity: "warning".into(),
        stage: "metadata".into(),
        code: "oversized".into(),
        message: "x".repeat(65_537),
        details: None,
        occurred_at_ms: 2_000,
    };
    let error = store
        .write_transaction(|repository| repository.record_scan_issue(&oversized_issue))
        .expect_err("oversized text was accepted");
    assert!(matches!(error, StoreError::InvalidInput { .. }));

    let oversized_report = NewScanReport {
        report_key: "oversized-report".into(),
        volume_id: ids.volume,
        scan_run_id: ids.run,
        report_version: 1,
        report: json!({"payload": "x".repeat(16 * 1024 * 1024)}),
        generated_at_ms: 2_000,
    };
    let error = store
        .write_transaction(|repository| repository.write_scan_report(&oversized_report))
        .expect_err("oversized report JSON was accepted");
    assert!(matches!(error, StoreError::InvalidInput { .. }));
    Ok(())
}

#[test]
fn repository_rejects_parent_path_components() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("paths.sqlite3");
    let mut store = Store::open_or_create(database)?;
    let error = store
        .write_transaction(|repository| {
            let volume = repository.upsert_volume(&volume_input("path-volume"))?;
            let capability =
                repository.set_current_capability_profile(&capability_input(volume))?;
            repository.create_scan_job(&NewScanJob {
                job_key: "escape-job".into(),
                volume_id: volume,
                capability_profile_id: capability,
                root_relative_path: "photos/../private".into(),
                root_relative_path_raw: b"photos/../private".to_vec(),
                root_path_encoding: "utf8".into(),
                root_path_key: path_key(&[1])?,
                path_semantics_version: 1,
                config: None,
                created_at_ms: 1_000,
            })?;
            Ok(())
        })
        .err()
        .ok_or("parent path was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::InvalidInput { .. }));
    Ok(())
}

#[test]
fn windows_profiles_require_unambiguous_windows_paths() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("windows-paths.sqlite3"))?;
    let (volume, capability) = store.write_transaction(|repository| {
        let volume = repository.upsert_volume(&volume_input("windows-path-volume"))?;
        let mut profile = capability_input(volume);
        profile.path_encoding_family = Some("windows".into());
        profile.case_behavior = Some("insensitive_preserving".into());
        let capability = repository.set_current_capability_profile(&profile)?;
        Ok((volume, capability))
    })?;

    let utf8_error = store
        .write_transaction(|repository| {
            repository.create_scan_job(&NewScanJob {
                job_key: "windows-utf8".into(),
                volume_id: volume,
                capability_profile_id: capability,
                root_relative_path: "DCIM/photo.jpg".into(),
                root_relative_path_raw: b"DCIM/photo.jpg".to_vec(),
                root_path_encoding: "utf8".into(),
                root_path_key: path_key(b"windows/utf8")?,
                path_semantics_version: 1,
                config: None,
                created_at_ms: 1_100,
            })
        })
        .expect_err("Windows profile accepted UTF-8/Unix path evidence");
    assert!(matches!(utf8_error, StoreError::IdempotencyConflict { .. }));

    for (index, unsafe_path) in [
        "DCIM\\..\\escape",
        "DCIM\\photo.jpg:stream",
        "DCIM\\CON.txt",
        "DCIM\\trailing.",
        "C:\\DCIM\\photo.jpg",
    ]
    .into_iter()
    .enumerate()
    {
        let raw = unsafe_path
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let error = store
            .write_transaction(|repository| {
                repository.create_scan_job(&NewScanJob {
                    job_key: format!("windows-unsafe-{index}"),
                    volume_id: volume,
                    capability_profile_id: capability,
                    root_relative_path: format!("DCIM/safe-{index}"),
                    root_relative_path_raw: raw.clone(),
                    root_path_encoding: "windows_utf16_le".into(),
                    root_path_key: path_key(format!("windows/unsafe/{index}").as_bytes())?,
                    path_semantics_version: 1,
                    config: None,
                    created_at_ms: 1_200 + i64::try_from(index).expect("fixture index fits in i64"),
                })
            })
            .expect_err("ambiguous Windows path was accepted");
        assert!(matches!(error, StoreError::InvalidInput { .. }));
    }

    let safe_raw = "DCIM\\photo.jpg"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    store.write_transaction(|repository| {
        repository.create_scan_job(&NewScanJob {
            job_key: "windows-safe".into(),
            volume_id: volume,
            capability_profile_id: capability,
            root_relative_path: "DCIM/photo.jpg".into(),
            root_relative_path_raw: safe_raw,
            root_path_encoding: "windows_utf16_le".into(),
            root_path_key: path_key(b"windows/safe")?,
            path_semantics_version: 1,
            config: None,
            created_at_ms: 1_300,
        })
    })?;
    Ok(())
}

#[test]
fn job_run_root_state_progress_and_checkpoint_invariants_are_enforced(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("scan-invariants.sqlite3"))?;
    let ids = seed_queued_scan(&mut store)?;

    let error = store
        .write_transaction(|repository| repository.update_scan_progress(ids.run, 1, 0, 0, 0, 1_500))
        .err()
        .ok_or("queued run progress was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::ConcurrencyConflict { .. }));

    let error = store
        .write_transaction(|repository| {
            repository.save_scan_checkpoint(&ScanCheckpointInput {
                scan_run_id: ids.run,
                volume_id: ids.volume,
                expected_previous_version: None,
                cursor_version: 1,
                cursor: json!({"entry": 1}),
                discovered_count: 1,
                fingerprinted_count: 0,
                error_count: 0,
                logical_bytes_seen: 0,
                saved_at_ms: 1_500,
            })?;
            Ok(())
        })
        .err()
        .ok_or("queued run checkpoint was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::ConcurrencyConflict { .. }));

    let error = store
        .write_transaction(|repository| {
            repository.transition_scan_job_and_run(
                ids.job,
                ids.run,
                ids.capability,
                "fixture-mount-session",
                "queued",
                1,
                "queued",
                0,
                "running",
                "running",
                1_500,
                None,
            )
        })
        .err()
        .ok_or("stale coordinated transition was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::ConcurrencyConflict { .. }));

    store.write_transaction(|repository| {
        assert_eq!(
            repository.transition_scan_job_and_run(
                ids.job,
                ids.run,
                ids.capability,
                "fixture-mount-session",
                "queued",
                0,
                "queued",
                0,
                "running",
                "running",
                1_600,
                None,
            )?,
            (1, 1)
        );
        Ok(())
    })?;

    let error = store
        .write_transaction(|repository| repository.update_scan_progress(ids.run, 1, 2, 0, 0, 1_700))
        .err()
        .ok_or("fingerprinted count exceeded discovered count")?;
    assert!(matches!(error, StoreError::InvalidInput { .. }));

    store.write_transaction(|repository| {
        repository.update_scan_progress(ids.run, 1, 1, 0, 100, 1_700)?;
        assert_eq!(
            repository.save_scan_checkpoint(&ScanCheckpointInput {
                scan_run_id: ids.run,
                volume_id: ids.volume,
                expected_previous_version: None,
                cursor_version: 1,
                cursor: json!({"entry": 1}),
                discovered_count: 1,
                fingerprinted_count: 1,
                error_count: 0,
                logical_bytes_seen: 100,
                saved_at_ms: 1_701,
            })?,
            1
        );
        Ok(())
    })?;
    let error = store
        .write_transaction(|repository| {
            repository.save_scan_checkpoint(&ScanCheckpointInput {
                scan_run_id: ids.run,
                volume_id: ids.volume,
                expected_previous_version: None,
                cursor_version: 1,
                cursor: json!({"entry": 2}),
                discovered_count: 2,
                fingerprinted_count: 1,
                error_count: 0,
                logical_bytes_seen: 200,
                saved_at_ms: 1_800,
            })?;
            Ok(())
        })
        .err()
        .ok_or("stale checkpoint writer was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::ConcurrencyConflict { .. }));
    assert_eq!(
        store
            .get_scan_checkpoint(ids.run)?
            .ok_or("checkpoint missing")?
            .checkpoint_version,
        1
    );
    Ok(())
}

#[test]
fn job_run_bindings_and_active_history_cannot_be_rewritten(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("immutable-bindings.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let ids = seed_repository(&mut store)?;
    store.close()?;

    let connection = Connection::open(&database)?;
    connection.pragma_update(None, "foreign_keys", true)?;

    assert!(connection
        .execute(
            "UPDATE scan_job_runs SET attempt_number = 2 \
             WHERE scan_job_id = ?1 AND scan_run_id = ?2",
            [ids.job, ids.run],
        )
        .is_err());
    assert!(connection
        .execute(
            "DELETE FROM scan_job_runs WHERE scan_job_id = ?1 AND scan_run_id = ?2",
            [ids.job, ids.run],
        )
        .is_err());
    assert!(connection
        .execute(
            "UPDATE scan_jobs SET active_scan_run_id = NULL WHERE id = ?1",
            [ids.job],
        )
        .is_err());

    connection.execute(
        "INSERT INTO scan_runs ( \
             run_key, volume_id, capability_profile_id, root_relative_path, root_path_key, \
             scan_mode, created_at_ms, updated_at_ms \
         ) SELECT 'direct-second-run', volume_id, capability_profile_id, root_relative_path, \
                  root_path_key, 'full', 2_000, 2_000 \
           FROM scan_runs WHERE id = ?1",
        [ids.run],
    )?;
    let second_run: i64 = connection.query_row(
        "SELECT id FROM scan_runs WHERE run_key = 'direct-second-run'",
        [],
        |row| row.get(0),
    )?;
    connection.execute(
        "INSERT INTO scan_run_roots ( \
             scan_run_id, volume_id, capability_profile_id, path_semantics_version, \
             relative_path_raw, path_encoding, semantic_path_key, created_at_ms \
         ) SELECT ?2, volume_id, capability_profile_id, path_semantics_version, \
                  relative_path_raw, path_encoding, semantic_path_key, 2_000 \
           FROM scan_run_roots WHERE scan_run_id = ?1",
        rusqlite::params![ids.run, second_run],
    )?;
    connection.execute(
        "INSERT INTO scan_job_runs (scan_job_id, scan_run_id, volume_id, attempt_number, created_at_ms) \
         VALUES (?1, ?2, ?3, 2, 2_000)",
        rusqlite::params![ids.job, second_run, ids.volume],
    )?;
    assert!(connection
        .execute(
            "UPDATE scan_jobs SET active_scan_run_id = ?2 WHERE id = ?1",
            rusqlite::params![ids.job, second_run],
        )
        .is_err());

    let active_run: Option<i64> = connection.query_row(
        "SELECT active_scan_run_id FROM scan_jobs WHERE id = ?1",
        [ids.job],
        |row| row.get(0),
    )?;
    let original_binding_count: i64 = connection.query_row(
        "SELECT count(*) FROM scan_job_runs WHERE scan_job_id = ?1 AND scan_run_id = ?2",
        rusqlite::params![ids.job, ids.run],
        |row| row.get(0),
    )?;
    assert_eq!(active_run, Some(ids.run));
    assert_eq!(original_binding_count, 1);
    Ok(())
}

#[test]
fn mismatched_job_run_root_is_rejected_before_insert() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("root-binding.sqlite3"))?;
    let error = store
        .write_transaction(|repository| {
            let volume = repository.upsert_volume(&volume_input("root-volume"))?;
            let capability =
                repository.set_current_capability_profile(&capability_input(volume))?;
            let job = repository.create_scan_job(&NewScanJob {
                job_key: "root-job".into(),
                volume_id: volume,
                capability_profile_id: capability,
                root_relative_path: "DCIM".into(),
                root_relative_path_raw: b"DCIM".to_vec(),
                root_path_encoding: "utf8".into(),
                root_path_key: path_key(b"dcim")?,
                path_semantics_version: 1,
                config: None,
                created_at_ms: 1_000,
            })?;
            repository.create_scan_run(&NewScanRun {
                run_key: "root-run".into(),
                scan_job_id: job,
                volume_id: volume,
                capability_profile_id: capability,
                parent_scan_run_id: None,
                root_relative_path: "Pictures".into(),
                root_relative_path_raw: b"Pictures".to_vec(),
                root_path_encoding: "utf8".into(),
                root_path_key: path_key(b"pictures")?,
                path_semantics_version: 1,
                scan_mode: "full".into(),
                config: None,
                created_at_ms: 1_100,
            })?;
            Ok(())
        })
        .err()
        .ok_or("mismatched job/run root was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::IdempotencyConflict { .. }));
    Ok(())
}

#[test]
fn keyset_pages_are_bounded_and_resumable() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("pages.sqlite3"))?;
    let ids = seed_repository(&mut store)?;
    store.write_transaction(|repository| {
        repository.create_scan_job(&NewScanJob {
            job_key: "job-2".into(),
            volume_id: ids.volume,
            capability_profile_id: ids.capability,
            root_relative_path: "DCIM".into(),
            root_relative_path_raw: b"DCIM".to_vec(),
            root_path_encoding: "utf8".into(),
            root_path_key: path_key(b"dcim")?,
            path_semantics_version: 1,
            config: None,
            created_at_ms: 2_000,
        })?;
        Ok(())
    })?;

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
        store.list_files_page(ids.run, Some(-1), 1),
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
    let ids = seed_repository(&mut store)?;

    let connection = Connection::open(&database)?;
    let oversized_message = "x".repeat(16 * 1024 * 1024 + 1);
    connection.execute(
        "INSERT INTO scan_issues ( \
             issue_key, volume_id, scan_run_id, severity, stage, code, message, occurred_at_ms \
         ) VALUES ('oversized-direct', ?1, ?2, 'warning', 'scan', 'oversized', ?3, 2_000)",
        rusqlite::params![ids.volume, ids.run, oversized_message],
    )?;
    let oversized_cursor = format!("{{\"payload\":\"{}\"}}", "x".repeat(1024 * 1024));
    connection.execute(
        "INSERT INTO scan_checkpoints ( \
             scan_run_id, volume_id, checkpoint_version, cursor_version, cursor_json, \
             discovered_count, fingerprinted_count, error_count, logical_bytes_seen, saved_at_ms \
         ) VALUES (?1, ?2, 1, 1, ?3, 0, 0, 0, 0, 2_000)",
        rusqlite::params![ids.run, ids.volume, oversized_cursor],
    )?;
    let oversized_report = format!(
        "{{\"payload\":\"{}\"}}",
        "x".repeat(MAX_SCAN_REPORT_JSON_BYTES)
    );
    connection.execute(
        "INSERT INTO scan_reports ( \
             report_key, volume_id, scan_run_id, report_version, report_json, generated_at_ms \
         ) VALUES ('oversized-direct', ?1, ?2, 2, ?3, 2_000)",
        rusqlite::params![ids.volume, ids.run, oversized_report],
    )?;
    connection.close().map_err(|(_, error)| error)?;

    assert!(matches!(
        store.list_issues_page(ids.run, None, 256),
        Err(StoreError::ReadResultLimit { .. })
    ));
    assert!(matches!(
        store.get_scan_checkpoint(ids.run),
        Err(StoreError::ReadResultLimit { .. })
    ));
    assert!(matches!(
        store.get_scan_report("oversized-direct"),
        Err(StoreError::ReadResultLimit { .. })
    ));
    Ok(())
}

#[test]
fn raw_paths_are_lossless_and_stale_observations_do_not_regress(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("raw-paths.sqlite3");
    let mut store = Store::open_or_create(database)?;
    let ids = seed_repository(&mut store)?;

    let mut stale = media_input(ids.volume, ids.run, ids.capability);
    stale.relative_path = "DCIM/STALE.JPG".into();
    stale.relative_path_raw = b"DCIM/STALE.JPG".to_vec();
    stale.observed_at_ms = 1_100;
    let error = store
        .write_transaction(|repository| {
            repository.upsert_media_file(&stale)?;
            Ok(())
        })
        .err()
        .ok_or("conflicting stale observation was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::IdempotencyConflict { .. }));
    let after_stale = store.list_files_page(ids.run, None, 32)?;
    assert_eq!(after_stale.items[0].relative_path, "DCIM/IMG_0001.JPG");

    let mut non_utf8 = media_input(ids.volume, ids.run, ids.capability);
    non_utf8.relative_path = "DCIM/IMG_invalid-byte.JPG".into();
    non_utf8.relative_path_raw = b"DCIM/IMG_\xff.JPG".to_vec();
    non_utf8.path_encoding = "unix_bytes".into();
    non_utf8.path_key = path_key(b"dcim/img_invalid-byte.jpg")?;
    non_utf8.observed_at_ms = 1_500;
    let non_utf8_id =
        store.write_transaction(|repository| repository.upsert_media_file(&non_utf8))?;
    let files = store.list_files_page(ids.run, None, 32)?;
    let non_utf8_record = files
        .items
        .iter()
        .find(|record| record.id == non_utf8_id)
        .ok_or("non-UTF-8 media record missing")?;
    assert_eq!(non_utf8_record.relative_path, "DCIM/IMG_invalid-byte.JPG");
    assert_eq!(
        non_utf8_record.relative_path_raw.as_deref(),
        Some(b"DCIM/IMG_\xff.JPG".as_slice())
    );
    assert_eq!(non_utf8_record.path_encoding.as_deref(), Some("unix_bytes"));
    Ok(())
}

#[test]
fn raw_paths_reject_traversal_independently_of_display_text(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("raw-path-traversal.sqlite3");
    let mut store = Store::open_or_create(database)?;
    let ids = seed_repository(&mut store)?;
    let mut unsafe_path = media_input(ids.volume, ids.run, ids.capability);
    unsafe_path.relative_path = "DCIM/safe-display.JPG".into();
    unsafe_path.relative_path_raw = b"DCIM/../escape.JPG".to_vec();
    unsafe_path.observed_at_ms = 1_500;
    let error = store
        .write_transaction(|repository| {
            repository.upsert_media_file(&unsafe_path)?;
            Ok(())
        })
        .err()
        .ok_or("raw traversal path was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::InvalidInput { .. }));
    Ok(())
}

#[test]
fn raw_path_encoding_and_utf8_display_must_be_canonical() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("path-canonical.sqlite3"))?;
    let ids = seed_repository(&mut store)?;
    let mut mismatch = media_input(ids.volume, ids.run, ids.capability);
    mismatch.relative_path_raw = b"DCIM/OTHER.JPG".to_vec();
    mismatch.observed_at_ms = 1_500;
    let error = store
        .write_transaction(|repository| {
            repository.upsert_media_file(&mismatch)?;
            Ok(())
        })
        .err()
        .ok_or("UTF-8 raw/display mismatch was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::InvalidInput { .. }));

    let mut legacy = media_input(ids.volume, ids.run, ids.capability);
    legacy.path_encoding = "windows_wtf16le".into();
    legacy.observed_at_ms = 1_500;
    let error = store
        .write_transaction(|repository| {
            repository.upsert_media_file(&legacy)?;
            Ok(())
        })
        .err()
        .ok_or("legacy Windows encoding label was unexpectedly accepted")?;
    assert!(matches!(error, StoreError::InvalidInput { .. }));

    assert!(matches!(
        PathKey::from_filesystem_adapter(vec![0; PathKey::MAX_BYTES + 1]),
        Err(StoreError::InvalidInput { .. })
    ));
    Ok(())
}

#[test]
fn root_evidence_is_lossless_and_windows_traversal_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("root-raw.sqlite3"))?;
    let (job, run, volume, capability) = store.write_transaction(|repository| {
        let volume = repository.upsert_volume(&volume_input("root-raw-volume"))?;
        let capability = repository.set_current_capability_profile(&capability_input(volume))?;
        let job = repository.create_scan_job(&NewScanJob {
            job_key: "raw-root-job".into(),
            volume_id: volume,
            capability_profile_id: capability,
            root_relative_path: "DCIM/lossy-name".into(),
            root_relative_path_raw: b"DCIM/name-\xff".to_vec(),
            root_path_encoding: "unix_bytes".into(),
            root_path_key: path_key(b"dcim/name-raw")?,
            path_semantics_version: 1,
            config: None,
            created_at_ms: 1_000,
        })?;
        let run = repository.create_scan_run(&NewScanRun {
            run_key: "raw-root-run".into(),
            scan_job_id: job,
            volume_id: volume,
            capability_profile_id: capability,
            parent_scan_run_id: None,
            root_relative_path: "DCIM/lossy-name".into(),
            root_relative_path_raw: b"DCIM/name-\xff".to_vec(),
            root_path_encoding: "unix_bytes".into(),
            root_path_key: path_key(b"dcim/name-raw")?,
            path_semantics_version: 1,
            scan_mode: "full".into(),
            config: None,
            created_at_ms: 1_100,
        })?;

        Ok((job, run, volume, capability))
    })?;

    let unsafe_raw = "DCIM\\..\\escape"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let error = store
        .write_transaction(|repository| {
            repository.create_scan_job(&NewScanJob {
                job_key: "windows-escape-job".into(),
                volume_id: volume,
                capability_profile_id: capability,
                root_relative_path: "DCIM/safe-display".into(),
                root_relative_path_raw: unsafe_raw,
                root_path_encoding: "windows_utf16_le".into(),
                root_path_key: path_key(b"windows-safe-key")?,
                path_semantics_version: 1,
                config: None,
                created_at_ms: 1_200,
            })
        })
        .expect_err("Windows raw traversal root was accepted");
    assert!(matches!(error, StoreError::InvalidInput { .. }));

    let job_record = store
        .get_scan_job("raw-root-job")?
        .ok_or("raw root job missing")?;
    assert_eq!(job_record.id, job);
    assert_eq!(job_record.root_relative_path_raw, b"DCIM/name-\xff");
    assert_eq!(job_record.root_path_encoding, "unix_bytes");
    assert_eq!(job_record.path_semantics_version, 1);
    let run_record = store
        .get_scan_run("raw-root-run")?
        .ok_or("raw root run missing")?;
    assert_eq!(run_record.id, run);
    assert_eq!(run_record.root_relative_path_raw, b"DCIM/name-\xff");
    assert_eq!(run_record.root_path_encoding, "unix_bytes");
    assert_eq!(run_record.root_path_key, b"dcim/name-raw");
    Ok(())
}

#[test]
fn media_path_keys_do_not_cross_capability_profiles() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("profile-path-isolation.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let ids = seed_repository(&mut store)?;

    let second_media = store.write_transaction(|repository| {
        let mut second_profile = capability_input(ids.volume);
        second_profile.mount_session_key = Some("second-mount-session".into());
        second_profile.driver_version = Some("2".into());
        let capability = repository.set_current_capability_profile(&second_profile)?;
        let job = repository.create_scan_job(&NewScanJob {
            job_key: "job-profile-2".into(),
            volume_id: ids.volume,
            capability_profile_id: capability,
            root_relative_path: "DCIM".into(),
            root_relative_path_raw: b"DCIM".to_vec(),
            root_path_encoding: "utf8".into(),
            root_path_key: path_key(b"dcim")?,
            path_semantics_version: 1,
            config: None,
            created_at_ms: 2_000,
        })?;
        let run = repository.create_scan_run(&NewScanRun {
            run_key: "run-profile-2".into(),
            scan_job_id: job,
            volume_id: ids.volume,
            capability_profile_id: capability,
            parent_scan_run_id: None,
            root_relative_path: "DCIM".into(),
            root_relative_path_raw: b"DCIM".to_vec(),
            root_path_encoding: "utf8".into(),
            root_path_key: path_key(b"dcim")?,
            path_semantics_version: 1,
            scan_mode: "full".into(),
            config: None,
            created_at_ms: 2_100,
        })?;
        repository.transition_scan_job_and_run(
            job,
            run,
            capability,
            "second-mount-session",
            "queued",
            0,
            "queued",
            0,
            "running",
            "running",
            2_150,
            None,
        )?;
        let mut media = media_input(ids.volume, run, capability);
        media.observed_at_ms = 2_200;
        repository.upsert_media_file(&media)
    })?;
    assert_ne!(second_media, ids.media);
    store.close()?;

    let connection = Connection::open(&database)?;
    let (binding_count, media_count, storage_key_count): (i64, i64, i64) = connection.query_row(
        "SELECT \
             (SELECT count(*) FROM media_path_keys WHERE semantic_path_key = ?1), \
             (SELECT count(*) FROM media_files), \
             (SELECT count(DISTINCT path_key) FROM media_files)",
        [b"dcim/img_0001.jpg".as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!((binding_count, media_count, storage_key_count), (2, 2, 2));
    Ok(())
}

#[test]
fn backup_is_verified_atomic_and_no_clobber() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("source.sqlite3");
    let backup = temporary.path().join("backups/snapshot.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let ids = seed_repository(&mut store)?;

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

    let no_clobber = store.backup_to(&backup);
    assert!(matches!(
        no_clobber,
        Err(StoreError::BackupDestinationExists(_))
    ));
    store.close()?;

    let backup_store = Store::open_existing(&backup)?;
    assert!(backup_store
        .integrity_check(IntegrityCheckKind::Full)?
        .is_healthy());
    assert_eq!(
        backup_store
            .get_scan_report("report-1")?
            .ok_or("report missing from backup")?
            .id,
        ids.report
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ScanIds {
    volume: i64,
    capability: i64,
    job: i64,
    run: i64,
}

#[derive(Debug, Clone, Copy)]
struct SeedIds {
    volume: i64,
    capability: i64,
    job: i64,
    run: i64,
    media: i64,
    issue: i64,
    report: i64,
}

fn seed_queued_scan(store: &mut Store) -> Result<ScanIds, StoreError> {
    store.write_transaction(create_queued_scan)
}

fn create_queued_scan(repository: &mut RepositoryTx<'_>) -> Result<ScanIds, StoreError> {
    let volume = repository.upsert_volume(&volume_input("volume-1"))?;
    let capability = repository.set_current_capability_profile(&capability_input(volume))?;
    let job_input = NewScanJob {
        job_key: "job-1".into(),
        volume_id: volume,
        capability_profile_id: capability,
        root_relative_path: "DCIM".into(),
        root_relative_path_raw: b"DCIM".to_vec(),
        root_path_encoding: "utf8".into(),
        root_path_key: path_key(b"dcim")?,
        path_semantics_version: 1,
        config: Some(json!({"exact": true})),
        created_at_ms: 1_000,
    };
    let job = repository.create_scan_job(&job_input)?;
    assert_eq!(repository.create_scan_job(&job_input)?, job);
    let run_input = NewScanRun {
        run_key: "run-1".into(),
        scan_job_id: job,
        volume_id: volume,
        capability_profile_id: capability,
        parent_scan_run_id: None,
        root_relative_path: "DCIM".into(),
        root_relative_path_raw: b"DCIM".to_vec(),
        root_path_encoding: "utf8".into(),
        root_path_key: path_key(b"dcim")?,
        path_semantics_version: 1,
        scan_mode: "full".into(),
        config: Some(json!({"exact": true})),
        created_at_ms: 1_100,
    };
    let run = repository.create_scan_run(&run_input)?;
    assert_eq!(repository.create_scan_run(&run_input)?, run);
    Ok(ScanIds {
        volume,
        capability,
        job,
        run,
    })
}

fn seed_repository(store: &mut Store) -> Result<SeedIds, StoreError> {
    store.write_transaction(|repository| {
        let ids = create_queued_scan(repository)?;
        repository.transition_scan_job_and_run(
            ids.job,
            ids.run,
            ids.capability,
            "fixture-mount-session",
            "queued",
            0,
            "queued",
            0,
            "running",
            "running",
            1_150,
            None,
        )?;
        let media =
            repository.upsert_media_file(&media_input(ids.volume, ids.run, ids.capability))?;
        let issue_input = NewScanIssue {
            issue_key: "issue-1".into(),
            volume_id: ids.volume,
            scan_run_id: ids.run,
            media_file_id: Some(media),
            severity: "warning".into(),
            stage: "metadata".into(),
            code: "missing_offset".into(),
            message: "Capture time has no UTC offset".into(),
            details: Some(json!({"fallback": "wall_time_only"})),
            occurred_at_ms: 1_300,
        };
        let issue = repository.record_scan_issue(&issue_input)?;
        assert_eq!(repository.record_scan_issue(&issue_input)?, issue);
        let report_input = NewScanReport {
            report_key: "report-1".into(),
            volume_id: ids.volume,
            scan_run_id: ids.run,
            report_version: 1,
            report: json!({"duplicates": 1, "safe": true}),
            generated_at_ms: 1_400,
        };
        let report = repository.write_scan_report(&report_input)?;
        assert_eq!(repository.write_scan_report(&report_input)?, report);
        Ok(SeedIds {
            volume: ids.volume,
            capability: ids.capability,
            job: ids.job,
            run: ids.run,
            media,
            issue,
            report,
        })
    })
}

fn media_input(volume_id: i64, scan_run_id: i64, capability_profile_id: i64) -> MediaFileInput {
    MediaFileInput {
        volume_id,
        scan_run_id,
        capability_profile_id,
        path_semantics_version: 1,
        relative_path: "DCIM/IMG_0001.JPG".into(),
        relative_path_raw: b"DCIM/IMG_0001.JPG".to_vec(),
        path_encoding: "utf8".into(),
        path_key: path_key(b"dcim/img_0001.jpg").expect("fixture path key is valid"),
        entry_type: "regular".into(),
        media_kind: "photo".into(),
        mime_type: Some("image/jpeg".into()),
        file_extension: Some("JPG".into()),
        lifecycle_state: "present".into(),
        size_bytes: Some(4_096),
        allocated_bytes: Some(4_096),
        native_file_id: Some(vec![3, 4]),
        native_file_generation: None,
        link_count: Some(1),
        is_sparse: Some(false),
        may_share_content: Some(false),
        birth_time_ns: Some(1_000_000_000),
        modified_time_ns: Some(1_000_000_000),
        changed_time_ns: Some(1_000_000_000),
        accessed_time_ns: Some(1_000_000_000),
        timestamp_granularity_ns: Some(1_000_000_000),
        stat_signature: Some(vec![9; 32]),
        metadata: Some(json!({"camera": "fixture"})),
        observed_at_ms: 1_200,
    }
}

fn path_key(bytes: &[u8]) -> Result<PathKey, StoreError> {
    PathKey::from_filesystem_adapter(bytes.to_vec())
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
        now_ms: 1_000,
    }
}

fn capability_input(volume_id: i64) -> CapabilityProfileInput {
    CapabilityProfileInput {
        volume_id,
        probe_mode: "passive".into(),
        probe_status: "complete".into(),
        observed_at_ms: 1_000,
        os_build: "test-os".into(),
        mount_session_key: Some("fixture-mount-session".into()),
        probe_protocol_version: Some(1),
        driver_name: Some("test-driver".into()),
        driver_version: Some("1".into()),
        mount_flags: Some(0),
        case_behavior: Some("insensitive_preserving".into()),
        unicode_behavior: Some("nfc".into()),
        path_encoding_family: Some("unix".into()),
        path_semantics_version: 1,
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
        has_persistent_file_ids: None,
        timestamp_granularity_ns: Some(1_000_000_000),
        maximum_name_bytes: Some(255),
        maximum_file_bytes: None,
        raw_capabilities: Some(json!({"fixture": true})),
    }
}
