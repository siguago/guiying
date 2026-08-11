use guiying_store::{
    AcquireRuntimeLeaseInput, CapabilityProfileInput, CoreDirectoryObservationInput, CoreSessionId,
    CoreSessionInput, DirectoryObjectSignature, LeasedScanTerminalOutcome, MountSessionKey,
    NamespaceProfileInput, NamespaceProfileKey, NewBoundScanRun, NewScopedScanJob,
    PauseCheckpointCursor, PauseCheckpointInput, PauseCheckpointWriteKey, RootObjectSignature,
    RootScopeKey, RunEvidenceGuard, RuntimeLeaseGuard, RuntimeLeaseKey, ScanControlDisposition,
    ScanControlKind, ScanControlRequestInput, ScanControlRequestKey, SourceSignature,
    StablePathKey, Store, StoreError, TicketSortKey, VolumeInput,
};
use rusqlite::Connection;
use std::path::Path;
use tempfile::TempDir;

#[derive(Clone, Copy)]
struct RunningRuntime {
    guard: RunEvidenceGuard,
    job_id: i64,
    core_session_id: CoreSessionId,
    lease: RuntimeLeaseGuard,
}

#[test]
fn pause_resume_generation_write_idempotency_and_cancel_dominance(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("runtime.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let runtime = create_running_runtime(&mut store, "runtime", 31)?;

    let stale_version_error = store
        .write_transaction(|repository| {
            repository.request_scan_control(
                &runtime.lease,
                &ScanControlRequestInput::new(
                    ScanControlRequestKey::from_runtime_evidence([40; 32]),
                    ScanControlKind::Pause,
                    0,
                    0,
                    None,
                    165,
                )?,
            )
        })
        .expect_err("a control request accepted stale run/job state versions");
    assert!(matches!(
        stale_version_error,
        StoreError::ConcurrencyConflict { .. }
    ));

    let pause_key_1 = ScanControlRequestKey::from_runtime_evidence([41; 32]);
    let pause_1 = store.write_transaction(|repository| {
        repository.request_scan_control(
            &runtime.lease,
            &ScanControlRequestInput::new(pause_key_1, ScanControlKind::Pause, 1, 1, None, 170)?,
        )
    })?;
    let write_key_1 = PauseCheckpointWriteKey::from_runtime_evidence([42; 32]);
    let checkpoint_1 = pause_input(pause_1.id, pause_key_1, None, write_key_1, 1, 1, 175)?;
    assert_eq!(
        store.write_transaction(|repository| {
            repository.acknowledge_pause(&runtime.lease, &checkpoint_1, 180)
        })?,
        (2, 2, 1)
    );
    assert_eq!(
        store.write_transaction(|repository| {
            repository.acknowledge_pause(&runtime.lease, &checkpoint_1, 180)
        })?,
        (2, 2, 1)
    );

    let resume_key = ScanControlRequestKey::from_runtime_evidence([43; 32]);
    let resume = store.write_transaction(|repository| {
        repository.request_scan_control(
            &runtime.lease,
            &ScanControlRequestInput::new(resume_key, ScanControlKind::Resume, 2, 2, Some(1), 190)?,
        )
    })?;
    assert_eq!(
        store.write_transaction(|repository| {
            repository.acknowledge_resume(&runtime.lease, resume.id, &resume_key, 200)
        })?,
        (3, 3)
    );

    let pause_key_2 = ScanControlRequestKey::from_runtime_evidence([44; 32]);
    let pause_2 = store.write_transaction(|repository| {
        repository.request_scan_control(
            &runtime.lease,
            &ScanControlRequestInput::new(pause_key_2, ScanControlKind::Pause, 3, 3, None, 210)?,
        )
    })?;
    let write_key_2 = PauseCheckpointWriteKey::from_runtime_evidence([45; 32]);
    let checkpoint_2 = pause_input(pause_2.id, pause_key_2, Some(1), write_key_2, 3, 3, 215)?;
    assert_eq!(
        store.write_transaction(|repository| {
            repository.acknowledge_pause(&runtime.lease, &checkpoint_2, 220)
        })?,
        (4, 4, 2)
    );
    assert_eq!(
        store.write_transaction(|repository| {
            repository.acknowledge_pause(&runtime.lease, &checkpoint_1, 180)
        })?,
        (2, 2, 1),
        "an old exact write-key retry must survive later checkpoint generations"
    );
    let reused = pause_input(pause_2.id, pause_key_2, Some(1), write_key_1, 3, 3, 215)?;
    let reuse_error = store
        .write_transaction(|repository| repository.acknowledge_pause(&runtime.lease, &reused, 220))
        .expect_err("A/B/A checkpoint write-key reuse was accepted");
    assert!(matches!(
        reuse_error,
        StoreError::IdempotencyConflict { .. }
    ));
    let stale_resume_key = ScanControlRequestKey::from_runtime_evidence([47; 32]);
    let stale_resume = store
        .write_transaction(|repository| {
            repository.request_scan_control(
                &runtime.lease,
                &ScanControlRequestInput::new(
                    stale_resume_key,
                    ScanControlKind::Resume,
                    4,
                    4,
                    Some(1),
                    225,
                )?,
            )
        })
        .expect_err("resume accepted an older checkpoint after generation two was durable");
    assert!(matches!(stale_resume, StoreError::Sqlite(_)));

    let dominated_resume_key = ScanControlRequestKey::from_runtime_evidence([48; 32]);
    let dominated_resume_input = ScanControlRequestInput::new(
        dominated_resume_key,
        ScanControlKind::Resume,
        4,
        4,
        Some(2),
        1_000,
    )?;
    store.write_transaction(|repository| {
        repository.request_scan_control(&runtime.lease, &dominated_resume_input)
    })?;

    let cancel_key = ScanControlRequestKey::from_runtime_evidence([46; 32]);
    let cancel_input =
        ScanControlRequestInput::new(cancel_key, ScanControlKind::Cancel, 4, 4, None, 230)?;
    let cancel = store.write_transaction(|repository| {
        repository.request_scan_control(&runtime.lease, &cancel_input)
    })?;
    assert_eq!(
        store.write_transaction(|repository| {
            repository.acknowledge_cancel(&runtime.lease, cancel.id, &cancel_key, 240)
        })?,
        (5, 5)
    );
    let retry = store.write_transaction(|repository| {
        repository.request_scan_control(&runtime.lease, &cancel_input)
    })?;
    assert_eq!(retry.disposition, ScanControlDisposition::Acknowledged);
    let dominated_retry = store.write_transaction(|repository| {
        repository.request_scan_control(&runtime.lease, &dominated_resume_input)
    })?;
    assert_eq!(
        dominated_retry.disposition,
        ScanControlDisposition::Superseded
    );
    store.close()?;
    let connection = Connection::open(&database)?;
    let duplicate_cursor_tamper = connection
        .execute(
            "UPDATE scan_pause_checkpoints SET cursor_json = \
             '{\"stage\":\"enumeration\",\"next_directory_ordinal\":0,\
               \"next_directory_ordinal\":1}' WHERE scan_run_id = ?1 AND generation = 1",
            [runtime.guard.scan_run_id],
        )
        .expect_err("an append-only checkpoint accepted a duplicate-key cursor rewrite");
    assert!(duplicate_cursor_tamper.to_string().contains("append-only"));
    let generations: (i64, i64, i64) = connection.query_row(
        "SELECT count(*), min(generation), max(generation) \
         FROM scan_pause_checkpoints WHERE scan_run_id = ?1",
        [runtime.guard.scan_run_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(generations, (2, 1, 2));
    drop(connection);
    Store::open_existing(&database)?.close()?;
    Ok(())
}

#[test]
fn reopen_invalidates_live_guard_and_honours_pending_cancel(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("reopen.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let runtime = create_running_runtime(&mut store, "reopen", 51)?;
    let cancel_key = ScanControlRequestKey::from_runtime_evidence([52; 32]);
    store.write_transaction(|repository| {
        repository.request_scan_control(
            &runtime.lease,
            &ScanControlRequestInput::new(cancel_key, ScanControlKind::Cancel, 1, 1, None, 170)?,
        )?;
        Ok(())
    })?;
    store.close()?;

    let mut reopened = Store::open_existing(&database)?;
    let stale_guard_error = reopened
        .write_transaction(|repository| repository.heartbeat_runtime_lease(&runtime.lease, 200))
        .expect_err("a previous Store instance's lease guard remained live");
    assert!(matches!(
        stale_guard_error,
        StoreError::ConcurrencyConflict { .. }
    ));
    reopened.close()?;

    let connection = Connection::open(&database)?;
    let states: (String, String, String, String) = connection.query_row(
        "SELECT run.state, job.state, lease.state, request.disposition \
         FROM scan_runs AS run \
         JOIN scan_jobs AS job ON job.id = ?1 \
         JOIN scan_runtime_leases AS lease ON lease.scan_run_id = run.id \
         JOIN scan_control_requests AS request ON request.scan_run_id = run.id \
         WHERE run.id = ?2 AND request.kind = 'cancel'",
        [runtime.job_id, runtime.guard.scan_run_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(
        states,
        (
            "cancelled".into(),
            "cancelled".into(),
            "released".into(),
            "acknowledged".into()
        )
    );
    Ok(())
}

#[test]
fn reopen_interrupts_pending_pause_and_resume_requests() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    for (name, pending_kind, session_byte) in [
        ("pending-pause", ScanControlKind::Pause, 53_u8),
        ("pending-resume", ScanControlKind::Resume, 57_u8),
    ] {
        let database = temporary.path().join(format!("{name}.sqlite3"));
        let mut store = Store::open_or_create(&database)?;
        let runtime = create_running_runtime(&mut store, name, session_byte)?;
        if pending_kind == ScanControlKind::Resume {
            let pause_key =
                ScanControlRequestKey::from_runtime_evidence([session_byte.wrapping_add(3); 32]);
            let pause = store.write_transaction(|repository| {
                repository.request_scan_control(
                    &runtime.lease,
                    &ScanControlRequestInput::new(
                        pause_key,
                        ScanControlKind::Pause,
                        1,
                        1,
                        None,
                        170,
                    )?,
                )
            })?;
            let checkpoint = pause_input(
                pause.id,
                pause_key,
                None,
                PauseCheckpointWriteKey::from_runtime_evidence([session_byte.wrapping_add(4); 32]),
                1,
                1,
                175,
            )?;
            store.write_transaction(|repository| {
                repository.acknowledge_pause(&runtime.lease, &checkpoint, 180)
            })?;
        }
        let (expected_job_version, expected_run_version, expected_generation) =
            if pending_kind == ScanControlKind::Resume {
                (2, 2, Some(1))
            } else {
                (1, 1, None)
            };
        let request_key =
            ScanControlRequestKey::from_runtime_evidence([session_byte.wrapping_add(5); 32]);
        store.write_transaction(|repository| {
            repository.request_scan_control(
                &runtime.lease,
                &ScanControlRequestInput::new(
                    request_key,
                    pending_kind,
                    expected_job_version,
                    expected_run_version,
                    expected_generation,
                    190,
                )?,
            )?;
            Ok(())
        })?;
        store.close()?;
        Store::open_existing(&database)?.close()?;

        let connection = Connection::open(&database)?;
        let states: (String, String, String, String, String) = connection.query_row(
            "SELECT run.state, job.state, lease.state, request.disposition, \
                    request.ack_reason_code \
             FROM scan_runs AS run \
             JOIN scan_jobs AS job ON job.id = ?1 \
             JOIN scan_runtime_leases AS lease ON lease.scan_run_id = run.id \
             JOIN scan_control_requests AS request ON request.scan_run_id = run.id \
             WHERE run.id = ?2 ORDER BY request.sequence DESC LIMIT 1",
            [runtime.job_id, runtime.guard.scan_run_id],
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
            states,
            (
                "interrupted".into(),
                "failed".into(),
                "released".into(),
                "interrupted".into(),
                "PROCESS_RESTART".into(),
            )
        );
    }
    Ok(())
}

#[test]
fn leased_terminal_is_atomic_and_v8_schema_tamper_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("terminal.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let runtime = create_running_runtime(&mut store, "terminal", 61)?;
    assert_eq!(
        store.write_transaction(|repository| {
            repository.transition_leased_scan_job_and_run(
                &runtime.lease,
                "running",
                1,
                "running",
                1,
                LeasedScanTerminalOutcome::Interrupted,
                180,
                Some(("TEST_INTERRUPTED", "fixture interruption")),
            )
        })?,
        (2, 2)
    );
    store.close()?;
    let connection = Connection::open(&database)?;
    connection.execute_batch("DROP TRIGGER trg_scan_control_requests_no_delete_v8;")?;
    drop(connection);
    assert!(Store::open_existing(&database).is_err());
    Ok(())
}

#[test]
fn reopen_rejects_an_impossible_releasing_terminal_half() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let database = temporary.path().join("releasing-half.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let runtime = create_running_runtime(&mut store, "releasing-half", 67)?;
    store.close()?;
    let connection = Connection::open(&database)?;
    let plan_tamper = connection
        .execute(
            "UPDATE scan_runtime_leases SET work_plan_digest = zeroblob(32) \
             WHERE scan_run_id = ?1",
            [runtime.guard.scan_run_id],
        )
        .expect_err("the immutable runtime binding digest was rewritten");
    assert!(plan_tamper.to_string().contains("lifecycle is invalid"));
    connection.execute(
        "UPDATE scan_runtime_leases \
         SET state = 'releasing', release_reason = 'failed', release_started_at_ms = 180 \
         WHERE scan_run_id = ?1 AND state = 'active'",
        [runtime.guard.scan_run_id],
    )?;
    connection.execute(
        "UPDATE scan_runs \
         SET state = 'failed', state_version = state_version + 1, \
             started_at_ms = COALESCE(started_at_ms, created_at_ms), \
             finished_at_ms = 180, updated_at_ms = 180, \
             last_error_code = 'HALF_FAILED', last_error_message = 'fixture half transition' \
         WHERE id = ?1 AND state = 'running'",
        [runtime.guard.scan_run_id],
    )?;
    drop(connection);
    assert!(Store::open_existing(&database).is_err());
    Ok(())
}

#[test]
fn bound_core_cannot_write_or_finish_before_runtime_lease_acquisition(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("lease-required.sqlite3"))?;
    let (guard, job_id, core_session_id) =
        create_running_bound_core(&mut store, "lease-required", 74)?;
    let observation = directory_ticket("before-lease", 75, vec![4, 3, 2, 1]);
    let evidence_error = store
        .write_transaction(|repository| {
            repository.record_core_directory_batch(&guard, &core_session_id, &[observation.clone()])
        })
        .expect_err("core evidence was accepted before acquiring a runtime lease");
    assert!(matches!(
        evidence_error,
        StoreError::ConcurrencyConflict { .. }
    ));
    let terminal_error = store
        .write_transaction(|repository| {
            repository.transition_bound_scan_job_and_run(
                &guard,
                job_id,
                "running",
                1,
                "running",
                1,
                "failed",
                "failed",
                170,
                Some(("BEFORE_LEASE", "terminal transition must be lease-bound")),
            )
        })
        .expect_err("a core-bound run reached terminal state without a runtime lease");
    assert!(matches!(
        terminal_error,
        StoreError::ConcurrencyConflict { .. }
    ));
    let wrong_core_error = store
        .write_transaction(|repository| {
            repository.acquire_runtime_lease(
                &guard,
                &AcquireRuntimeLeaseInput::new(
                    RuntimeLeaseKey::from_runtime_evidence([75; 32]),
                    CoreSessionId::from_runtime_evidence([77; 32]),
                    175,
                )?,
            )
        })
        .expect_err("an unbound core session acquired a runtime lease");
    assert!(matches!(
        wrong_core_error,
        StoreError::ConcurrencyConflict { .. }
    ));
    let lease = store.write_transaction(|repository| {
        repository.acquire_runtime_lease(
            &guard,
            &AcquireRuntimeLeaseInput::new(
                RuntimeLeaseKey::from_runtime_evidence([76; 32]),
                core_session_id,
                180,
            )?,
        )
    })?;
    let ids = store.write_transaction(|repository| {
        repository.record_core_directory_batch(&guard, &core_session_id, &[observation])
    })?;
    assert_eq!(ids.len(), 1);
    store.write_transaction(|repository| repository.heartbeat_runtime_lease(&lease, 190))?;
    Ok(())
}

#[test]
fn first_core_batch_can_bind_acquire_and_record_atomically(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("first-batch.sqlite3"))?;
    let (guard, _, core_session_id) = create_running_run(&mut store, "first-batch", 77)?;
    let observation = directory_ticket("atomic-first", 78, vec![1, 4, 9]);
    let (lease, ids) = store.write_transaction(|repository| {
        repository.bind_core_session(
            &guard,
            &CoreSessionInput {
                core_session_id,
                root_object_signature: RootObjectSignature::from_volume_adapter([14; 32]),
                root_source_signature: SourceSignature::from_runtime_evidence([15; 32]),
                bound_at_ms: 151,
            },
        )?;
        let lease = repository.acquire_runtime_lease(
            &guard,
            &AcquireRuntimeLeaseInput::new(
                RuntimeLeaseKey::from_runtime_evidence([79; 32]),
                core_session_id,
                160,
            )?,
        )?;
        let ids =
            repository.record_core_directory_batch(&guard, &core_session_id, &[observation])?;
        Ok((lease, ids))
    })?;
    assert_eq!(ids.len(), 1);
    store.write_transaction(|repository| repository.heartbeat_runtime_lease(&lease, 300))?;
    Ok(())
}

#[test]
fn evidence_accumulator_is_idempotent_and_checkpoint_audit_row_is_immutable(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("accumulator.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let runtime = create_running_runtime(&mut store, "accumulator", 81)?;
    let first_blob = vec![1, 3, 5, 7, 9];
    let first = directory_ticket("first", 82, first_blob.clone());
    let first_ids = store.write_transaction(|repository| {
        repository.record_core_directory_batch(
            &runtime.guard,
            &runtime.core_session_id,
            &[first.clone()],
        )
    })?;
    let repeated_ids = store.write_transaction(|repository| {
        repository.record_core_directory_batch(
            &runtime.guard,
            &runtime.core_session_id,
            &[first.clone()],
        )
    })?;
    assert_eq!(first_ids, repeated_ids);
    let mut wrong_key = directory_ticket("wrong-key", 87, vec![9, 8, 7]);
    wrong_key.ticket_sort_key = TicketSortKey::from_core_evidence([0; 32]);
    let wrong_key_error = store
        .write_transaction(|repository| {
            repository.record_core_directory_batch(
                &runtime.guard,
                &runtime.core_session_id,
                &[wrong_key],
            )
        })
        .expect_err("a leased ticket key not derived from its opaque blob was accepted");
    assert!(matches!(wrong_key_error, StoreError::InvalidInput { .. }));

    let pause_key = ScanControlRequestKey::from_runtime_evidence([83; 32]);
    let pause = store.write_transaction(|repository| {
        repository.request_scan_control(
            &runtime.lease,
            &ScanControlRequestInput::new(pause_key, ScanControlKind::Pause, 1, 1, None, 180)?,
        )
    })?;
    let checkpoint = PauseCheckpointInput::new(
        pause.id,
        pause_key,
        None,
        PauseCheckpointWriteKey::from_runtime_evidence([84; 32]),
        PauseCheckpointCursor::Enumeration {
            next_directory_ordinal: 1,
            next_file_ordinal: 0,
        },
        1,
        1,
        0,
        0,
        0,
        0,
        185,
    )?;
    store.write_transaction(|repository| {
        repository.acknowledge_pause(&runtime.lease, &checkpoint, 190)?;
        Ok(())
    })?;
    let generation_one_before = checkpoint_row_snapshot(&database, runtime.guard.scan_run_id, 1)?;
    let resume_key = ScanControlRequestKey::from_runtime_evidence([85; 32]);
    let resume = store.write_transaction(|repository| {
        repository.request_scan_control(
            &runtime.lease,
            &ScanControlRequestInput::new(resume_key, ScanControlKind::Resume, 2, 2, Some(1), 200)?,
        )
    })?;
    store.write_transaction(|repository| {
        repository.acknowledge_resume(&runtime.lease, resume.id, &resume_key, 210)?;
        Ok(())
    })?;
    let second = directory_ticket("second", 86, vec![2, 4, 6, 8]);
    store.write_transaction(|repository| {
        repository.record_core_directory_batch(
            &runtime.guard,
            &runtime.core_session_id,
            &[second],
        )?;
        Ok(())
    })?;
    let pause_key_2 = ScanControlRequestKey::from_runtime_evidence([88; 32]);
    let pause_2 = store.write_transaction(|repository| {
        repository.request_scan_control(
            &runtime.lease,
            &ScanControlRequestInput::new(pause_key_2, ScanControlKind::Pause, 3, 3, None, 300)?,
        )
    })?;
    let checkpoint_2 = PauseCheckpointInput::new(
        pause_2.id,
        pause_key_2,
        Some(1),
        PauseCheckpointWriteKey::from_runtime_evidence([89; 32]),
        PauseCheckpointCursor::Enumeration {
            next_directory_ordinal: 2,
            next_file_ordinal: 0,
        },
        3,
        3,
        0,
        0,
        0,
        0,
        305,
    )?;
    let rewound_checkpoint = PauseCheckpointInput::new(
        pause_2.id,
        pause_key_2,
        Some(1),
        PauseCheckpointWriteKey::from_runtime_evidence([90; 32]),
        PauseCheckpointCursor::Enumeration {
            next_directory_ordinal: 0,
            next_file_ordinal: 0,
        },
        3,
        3,
        0,
        0,
        0,
        0,
        305,
    )?;
    let rewind_error = store
        .write_transaction(|repository| {
            repository.acknowledge_pause(&runtime.lease, &rewound_checkpoint, 310)
        })
        .expect_err("a later pause checkpoint rewound its accepted evidence cursor");
    assert!(matches!(
        rewind_error,
        StoreError::ConcurrencyConflict { .. }
    ));
    assert_eq!(
        store.write_transaction(|repository| {
            repository.acknowledge_pause(&runtime.lease, &checkpoint_2, 310)
        })?,
        (4, 4, 2)
    );
    let generation_one_after = checkpoint_row_snapshot(&database, runtime.guard.scan_run_id, 1)?;
    assert_eq!(generation_one_before, generation_one_after);
    store.close()?;
    Store::open_existing(&database)?.close()?;
    let connection = Connection::open(&database)?;
    let states: (String, String, String) = connection.query_row(
        "SELECT run.state, job.state, lease.state \
         FROM scan_runs AS run \
         JOIN scan_jobs AS job ON job.id = ?1 \
         JOIN scan_runtime_leases AS lease ON lease.scan_run_id = run.id \
         WHERE run.id = ?2",
        [runtime.job_id, runtime.guard.scan_run_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(
        states,
        ("interrupted".into(), "failed".into(), "released".into())
    );
    Ok(())
}

#[test]
fn version_seven_database_migrates_to_runtime_control_schema(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("v7.sqlite3");
    Store::open_or_create(&database)?.close()?;
    let connection = Connection::open(&database)?;
    connection.execute_batch(
        "PRAGMA foreign_keys = OFF; \
         DROP TRIGGER trg_scan_jobs_runtime_control_gate_v8; \
         DROP TRIGGER trg_scan_runs_runtime_control_gate_v8; \
         DROP TRIGGER trg_scan_pause_checkpoints_no_delete_v8; \
         DROP TRIGGER trg_scan_pause_checkpoints_update_guard_v8; \
         DROP TRIGGER trg_scan_pause_checkpoints_insert_guard_v8; \
         DROP TRIGGER trg_scan_control_requests_no_delete_v8; \
         DROP TRIGGER trg_scan_control_requests_update_guard_v8; \
         DROP TRIGGER trg_scan_control_requests_insert_guard_v8; \
         DROP TRIGGER trg_scan_runtime_leases_no_delete_v8; \
         DROP TRIGGER trg_scan_runtime_leases_update_guard_v8; \
         DROP TRIGGER trg_scan_runtime_leases_insert_guard_v8; \
         DROP TABLE scan_pause_checkpoints; \
         DROP TABLE scan_control_requests; \
         DROP TABLE scan_runtime_leases; \
         DROP INDEX ux_scan_run_sessions_mount_binding_v8; \
         DELETE FROM guiying_schema_migrations WHERE version = 8; \
         PRAGMA user_version = 7;",
    )?;
    drop(connection);
    let store = Store::open_existing(&database)?;
    assert_eq!(store.schema_version()?, 8);
    store.close()?;
    Ok(())
}

#[test]
fn cursor_rejects_values_outside_sqlite_integer_domain() -> Result<(), StoreError> {
    let key = ScanControlRequestKey::from_runtime_evidence([71; 32]);
    let max = PauseCheckpointInput::new(
        1,
        key,
        None,
        PauseCheckpointWriteKey::from_runtime_evidence([72; 32]),
        PauseCheckpointCursor::Enumeration {
            next_directory_ordinal: i64::MAX as u64,
            next_file_ordinal: i64::MAX as u64,
        },
        1,
        1,
        0,
        0,
        0,
        0,
        1,
    );
    assert!(max.is_ok());
    let too_large = PauseCheckpointInput::new(
        1,
        key,
        None,
        PauseCheckpointWriteKey::from_runtime_evidence([73; 32]),
        PauseCheckpointCursor::Enumeration {
            next_directory_ordinal: i64::MAX as u64 + 1,
            next_file_ordinal: 0,
        },
        1,
        1,
        0,
        0,
        0,
        0,
        1,
    );
    assert!(too_large.is_err());
    Ok(())
}

fn checkpoint_row_snapshot(
    database: &Path,
    scan_run_id: i64,
    generation: i64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let connection = Connection::open(database)?;
    let values = connection.query_row(
        "SELECT quote(scan_run_id), quote(volume_id), quote(runtime_lease_key), \
                quote(core_session_id), quote(mount_session_key), quote(pause_request_id), \
                quote(pause_request_key), quote(generation), quote(write_key), \
                quote(payload_digest), quote(cursor_contract_version), quote(stage), \
                quote(cursor_json), quote(work_plan_digest), \
                quote(evidence_manifest_digest), quote(job_state_version), \
                quote(run_state_version), quote(discovered_count), \
                quote(fingerprinted_count), quote(error_count), \
                quote(logical_bytes_seen), quote(saved_at_ms) \
         FROM scan_pause_checkpoints WHERE scan_run_id = ?1 AND generation = ?2",
        [scan_run_id, generation],
        |row| {
            (0..22)
                .map(|index| row.get::<_, String>(index))
                .collect::<rusqlite::Result<Vec<_>>>()
        },
    )?;
    Ok(values)
}

fn pause_input(
    request_id: i64,
    request_key: ScanControlRequestKey,
    expected_generation: Option<i64>,
    write_key: PauseCheckpointWriteKey,
    expected_job_state_version: i64,
    expected_run_state_version: i64,
    saved_at_ms: i64,
) -> Result<PauseCheckpointInput, StoreError> {
    PauseCheckpointInput::new(
        request_id,
        request_key,
        expected_generation,
        write_key,
        PauseCheckpointCursor::Enumeration {
            next_directory_ordinal: 0,
            next_file_ordinal: 0,
        },
        expected_job_state_version,
        expected_run_state_version,
        0,
        0,
        0,
        0,
        saved_at_ms,
    )
}

fn create_running_runtime(
    store: &mut Store,
    prefix: &str,
    session_byte: u8,
) -> Result<RunningRuntime, StoreError> {
    let (guard, job_id, core_session_id) = create_running_run(store, prefix, session_byte)?;
    let lease = store.write_transaction(|repository| {
        repository.bind_core_session(
            &guard,
            &CoreSessionInput {
                core_session_id,
                root_object_signature: RootObjectSignature::from_volume_adapter([14; 32]),
                root_source_signature: SourceSignature::from_runtime_evidence([15; 32]),
                bound_at_ms: 151,
            },
        )?;
        repository.acquire_runtime_lease(
            &guard,
            &AcquireRuntimeLeaseInput::new(
                RuntimeLeaseKey::from_runtime_evidence([session_byte.wrapping_add(2); 32]),
                core_session_id,
                160,
            )?,
        )
    })?;
    Ok(RunningRuntime {
        guard,
        job_id,
        core_session_id,
        lease,
    })
}

fn create_running_bound_core(
    store: &mut Store,
    prefix: &str,
    session_byte: u8,
) -> Result<(RunEvidenceGuard, i64, CoreSessionId), StoreError> {
    let (guard, job_id, core_session_id) = create_running_run(store, prefix, session_byte)?;
    store.write_transaction(|repository| {
        repository.bind_core_session(
            &guard,
            &CoreSessionInput {
                core_session_id,
                root_object_signature: RootObjectSignature::from_volume_adapter([14; 32]),
                root_source_signature: SourceSignature::from_runtime_evidence([15; 32]),
                bound_at_ms: 151,
            },
        )
    })?;
    Ok((guard, job_id, core_session_id))
}

fn create_running_run(
    store: &mut Store,
    prefix: &str,
    session_byte: u8,
) -> Result<(RunEvidenceGuard, i64, CoreSessionId), StoreError> {
    let mount_session_key = MountSessionKey::from_runtime_evidence([session_byte; 32]);
    let (guard, job_id) = store.write_transaction(|repository| {
        let volume_id = repository.upsert_volume(&VolumeInput {
            identity_key: format!("{prefix}-volume"),
            identity_strength: "strong".into(),
            marker_uuid: Some(format!("{prefix}-marker")),
            native_uuid: Some(format!("{prefix}-native")),
            filesystem_type: "apfs".into(),
            display_name: None,
            mount_source: None,
            last_mount_path: None,
            transport: None,
            is_network: false,
            is_read_only: true,
            now_ms: 100,
        })?;
        let capability_profile_id =
            repository.set_current_capability_profile(&capability(volume_id, mount_session_key))?;
        let namespace_profile_id =
            repository.register_namespace_profile(&NamespaceProfileInput {
                volume_id,
                profile_key: NamespaceProfileKey::from_volume_adapter([11; 32]),
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
            job_key: format!("{prefix}-job"),
            volume_id,
            namespace_profile_id,
            root_display: "DCIM".into(),
            mount_relative_root_raw: b"DCIM".to_vec(),
            path_encoding: "utf8".into(),
            stable_root_path_key: StablePathKey::from_volume_adapter([12; 32]),
            root_scope_key: RootScopeKey::from_volume_adapter([13; 32]),
            config: None,
            created_at_ms: 110,
        })?;
        let run_id = repository.create_bound_scan_run(&NewBoundScanRun {
            run_key: format!("{prefix}-run"),
            scan_job_id: job_id,
            volume_id,
            capability_profile_id,
            parent_scan_run_id: None,
            mount_session_key,
            mount_relative_root_raw: b"DCIM".to_vec(),
            path_encoding: "utf8".into(),
            stable_root_path_key: StablePathKey::from_volume_adapter([12; 32]),
            root_scope_key: RootScopeKey::from_volume_adapter([13; 32]),
            root_object_signature: RootObjectSignature::from_volume_adapter([14; 32]),
            scan_mode: "full".into(),
            config: None,
            created_at_ms: 120,
        })?;
        let guard = RunEvidenceGuard {
            scan_run_id: run_id,
            capability_profile_id,
            mount_session_key,
        };
        repository.transition_bound_scan_job_and_run(
            &guard, job_id, "queued", 0, "queued", 0, "running", "running", 150, None,
        )?;
        Ok((guard, job_id))
    })?;
    let core_session_id = CoreSessionId::from_runtime_evidence([session_byte.wrapping_add(1); 32]);
    Ok((guard, job_id, core_session_id))
}

fn capability(volume_id: i64, mount_session_key: MountSessionKey) -> CapabilityProfileInput {
    CapabilityProfileInput {
        volume_id,
        probe_mode: "passive".into(),
        probe_status: "complete".into(),
        observed_at_ms: 100,
        os_build: "fixture".into(),
        mount_session_key: Some(mount_session_key.to_storage_hex()),
        probe_protocol_version: Some(1),
        driver_name: None,
        driver_version: None,
        mount_flags: Some(0),
        case_behavior: Some("sensitive".into()),
        unicode_behavior: Some("exact".into()),
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

fn directory_ticket(
    display_path: &str,
    signature_byte: u8,
    ticket_blob: Vec<u8>,
) -> CoreDirectoryObservationInput {
    let mut ticket_hasher = blake3::Hasher::new();
    ticket_hasher.update(b"guiying.core-ticket-id.v1\0");
    ticket_hasher.update(&ticket_blob);
    CoreDirectoryObservationInput {
        root_relative_path_raw: display_path.as_bytes().to_vec(),
        path_encoding: "utf8".into(),
        display_path: display_path.into(),
        source_signature: SourceSignature::from_runtime_evidence([signature_byte; 32]),
        directory_object_signature: DirectoryObjectSignature::from_runtime_evidence(
            [signature_byte.wrapping_add(1); 32],
        ),
        ticket_blob,
        ticket_sort_key: TicketSortKey::from_core_evidence(*ticket_hasher.finalize().as_bytes()),
        observed_at_ms: 170 + i64::from(signature_byte),
    }
}
