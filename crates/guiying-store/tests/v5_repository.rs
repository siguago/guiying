use guiying_store::{
    compute_exact_group_manifest, compute_exact_group_member_leaf, BeginExactGroupInput, BuildKey,
    CapabilityProfileInput, ExactGroupManifestMember, ExactGroupMemberInput,
    ExactVerificationEdgeInput, FileObjectKey, FileTimestampParts, FingerprintReadOrigin,
    FreshFingerprintInput, FreshFingerprintKind, ManifestDigest, MountSessionKey,
    NamespaceProfileInput, NamespaceProfileKey, NewBoundScanRun, NewScanIssue, NewScanJob,
    NewScanReport, NewScopedScanJob, ObservationInput, ParametersHash, PathKey, RepositoryTx,
    RootObjectSignature, RootScopeKey, RunEvidenceGuard, ScanCheckpointInput, ScanStage,
    SourceSignature, StablePathKey, Store, StoreError, VolumeInput,
};
use rusqlite::{params, Connection};
use std::path::Path;
use tempfile::TempDir;

const ALGORITHM: &str = "blake3";

#[derive(Debug, Clone, Copy)]
struct RunningRun {
    volume_id: i64,
    capability_profile_id: i64,
    job_id: i64,
    run_id: i64,
    guard: RunEvidenceGuard,
}

#[test]
fn v5_write_pipeline_is_idempotent_and_finalizes_only_database_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database_path = temporary.path().join("write-pipeline.sqlite3");
    let mut store = Store::open_or_create(&database_path)?;
    let run = create_running_run(&mut store, "pipeline", 7)?;
    let observations = vec![observation(0, 10), observation(1, 10)];
    let observation_ids = store.write_transaction(|repository| {
        let first = repository.record_observation_batch(&run.guard, &observations)?;
        let repeated = repository.record_observation_batch(&run.guard, &observations)?;
        assert_eq!(first, repeated);
        repository.seal_scan_stage(&run.guard, ScanStage::Enumeration, 2, 20, 200)?;
        repository.seal_scan_stage(&run.guard, ScanStage::Sampling, 0, 0, 210)?;
        Ok(first)
    })?;
    assert_eq!(
        store.write_transaction(|repository| {
            repository.record_observation_batch(&run.guard, &observations)
        })?,
        observation_ids
    );
    let mut conflicting_observation = observations[0].clone();
    conflicting_observation.size_bytes = 11;
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.record_observation_batch(&run.guard, &[conflicting_observation])
        }),
        Err(StoreError::IdempotencyConflict { .. })
    ));

    let parameters_hash = ParametersHash::from_runtime_evidence([41; 32]);
    let fingerprints = observation_ids
        .iter()
        .enumerate()
        .map(|(index, observation_id)| {
            exact_fingerprint(
                *observation_id,
                observations[index].source_signature,
                observations[index].size_bytes,
                parameters_hash,
                300 + i64::try_from(index).expect("small fixture index"),
            )
        })
        .collect::<Vec<_>>();
    let fingerprint_ids = store.write_transaction(|repository| {
        let first = repository.record_fingerprint_fresh_batch(&run.guard, &fingerprints)?;
        let repeated = repository.record_fingerprint_fresh_batch(&run.guard, &fingerprints)?;
        assert_eq!(first, repeated);
        repository.seal_scan_stage(&run.guard, ScanStage::FullHash, 2, 20, 400)?;
        Ok(first)
    })?;
    assert_eq!(
        store.write_transaction(|repository| {
            repository.record_fingerprint_fresh_batch(&run.guard, &fingerprints)
        })?,
        fingerprint_ids
    );
    let mut conflicting_fingerprint = fingerprints[0].clone();
    conflicting_fingerprint.digest = vec![99; 32];
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.record_fingerprint_fresh_batch(&run.guard, &[conflicting_fingerprint])
        }),
        Err(StoreError::IdempotencyConflict { .. })
    ));

    let manifest_members = manifest_members(
        &observations,
        &observation_ids,
        &fingerprint_ids,
        parameters_hash,
    )?;
    let leaves = manifest_members
        .iter()
        .map(compute_exact_group_member_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = compute_exact_group_manifest(&leaves)?;
    let verified = store.write_transaction(|repository| {
        let build_id = repository.begin_exact_group(
            &run.guard,
            &BeginExactGroupInput {
                build_key: BuildKey::from_runtime_evidence([51; 32]),
                representative_observation_id: observation_ids[0],
                representative_fingerprint_id: fingerprint_ids[0],
                expected_member_count: 2,
                expected_manifest_digest: manifest,
                created_at_ms: 500,
            },
        )?;
        let repeated_build_id = repository.begin_exact_group(
            &run.guard,
            &BeginExactGroupInput {
                build_key: BuildKey::from_runtime_evidence([51; 32]),
                representative_observation_id: observation_ids[0],
                representative_fingerprint_id: fingerprint_ids[0],
                expected_member_count: 2,
                expected_manifest_digest: manifest,
                created_at_ms: 500,
            },
        )?;
        assert_eq!(build_id, repeated_build_id);
        let members = [
            ExactGroupMemberInput {
                ordinal: 0,
                observation_id: observation_ids[0],
                fingerprint_id: fingerprint_ids[0],
                sort_rank: 0,
            },
            ExactGroupMemberInput {
                ordinal: 1,
                observation_id: observation_ids[1],
                fingerprint_id: fingerprint_ids[1],
                sort_rank: 1,
            },
        ];
        repository.append_exact_group_members(&run.guard, build_id, &members)?;
        repository.append_exact_group_members(&run.guard, build_id, &members)?;
        let edges = [ExactVerificationEdgeInput {
            member_observation_id: observation_ids[1],
            member_fingerprint_id: fingerprint_ids[1],
            representative_source_signature: observations[0].source_signature,
            member_source_signature: observations[1].source_signature,
            compared_bytes: 10,
            verified_at_ms: 600,
        }];
        repository.append_exact_verification_edges(&run.guard, build_id, &edges)?;
        repository.append_exact_verification_edges(&run.guard, build_id, &edges)?;
        let verified = repository.finalize_exact_group(&run.guard, build_id, 700)?;
        assert_eq!(
            verified,
            repository.finalize_exact_group(&run.guard, build_id, 700)?
        );
        repository.seal_scan_stage(&run.guard, ScanStage::ExactVerification, 1, 10, 710)?;
        Ok(verified)
    })?;

    assert_eq!(verified.member_count, 2);
    assert_eq!(verified.edge_count, 1);
    assert_eq!(verified.independent_file_count, 2);
    assert_eq!(verified.logical_reclaimable_bytes, 10);
    assert_eq!(verified.manifest_digest, manifest);

    let (next_run, next_guard) = store.write_transaction(|repository| {
        repository.transition_bound_scan_job_and_run(
            &run.guard,
            run.job_id,
            "running",
            1,
            "running",
            1,
            "completed",
            "completed",
            800,
            None,
        )?;
        let next_mount = MountSessionKey::from_runtime_evidence([9; 32]);
        let next_capability =
            repository.set_current_capability_profile(&capability(run.volume_id, next_mount))?;
        let next_input = NewBoundScanRun {
            run_key: "pipeline-run-rescan".into(),
            scan_job_id: run.job_id,
            volume_id: run.volume_id,
            capability_profile_id: next_capability,
            parent_scan_run_id: Some(run.run_id),
            mount_session_key: next_mount,
            mount_relative_root_raw: b"DCIM".to_vec(),
            path_encoding: "utf8".into(),
            stable_root_path_key: StablePathKey::from_volume_adapter([12; 32]),
            root_scope_key: RootScopeKey::from_volume_adapter([13; 32]),
            root_object_signature: RootObjectSignature::from_volume_adapter([15; 32]),
            scan_mode: "full".into(),
            config: None,
            created_at_ms: 900,
        };
        let next_run = repository.create_bound_scan_run(&next_input)?;
        assert_eq!(repository.create_bound_scan_run(&next_input)?, next_run);
        let next_guard = RunEvidenceGuard {
            scan_run_id: next_run,
            capability_profile_id: next_capability,
            mount_session_key: next_mount,
        };
        repository.transition_bound_scan_job_and_run(
            &next_guard,
            run.job_id,
            "completed",
            2,
            "queued",
            0,
            "running",
            "running",
            950,
            None,
        )?;
        assert_eq!(repository.create_bound_scan_run(&next_input)?, next_run);
        Ok((next_run, next_guard))
    })?;
    store.write_transaction(|repository| {
        repository.transition_bound_scan_job_and_run(
            &next_guard,
            run.job_id,
            "running",
            3,
            "running",
            1,
            "failed",
            "interrupted",
            1_000,
            Some(("TEST_RESTART", "prepare a third attempt")),
        )?;
        Ok(())
    })?;
    let third_mount = MountSessionKey::from_runtime_evidence([10; 32]);
    let third_capability = store.write_transaction(|repository| {
        repository.set_current_capability_profile(&capability(run.volume_id, third_mount))
    })?;
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.create_bound_scan_run(&NewBoundScanRun {
                run_key: "pipeline-run-stale-parent".into(),
                scan_job_id: run.job_id,
                volume_id: run.volume_id,
                capability_profile_id: third_capability,
                parent_scan_run_id: Some(run.run_id),
                mount_session_key: third_mount,
                mount_relative_root_raw: b"DCIM".to_vec(),
                path_encoding: "utf8".into(),
                stable_root_path_key: StablePathKey::from_volume_adapter([12; 32]),
                root_scope_key: RootScopeKey::from_volume_adapter([13; 32]),
                root_object_signature: RootObjectSignature::from_volume_adapter([16; 32]),
                scan_mode: "resume".into(),
                config: None,
                created_at_ms: 1_100,
            })
        }),
        Err(StoreError::IdempotencyConflict {
            entity: "bound_scan_run_parent_lineage",
            ..
        })
    ));
    assert_eq!(
        store
            .get_scan_run("pipeline-run-rescan")?
            .expect("second attempt")
            .id,
        next_run
    );
    let verified_build_id = verified.build_id;
    drop(store);
    assert_verified_group_tampering_is_rejected(&database_path, verified_build_id)?;
    Ok(())
}

#[test]
fn terminal_v5_attempt_cannot_lose_its_session_provenance() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let database_path = temporary.path().join("terminal-session.sqlite3");
    let mut store = Store::open_or_create(&database_path)?;
    let run = create_running_run(&mut store, "terminal-session", 17)?;
    store.write_transaction(|repository| {
        repository.seal_scan_stage(&run.guard, ScanStage::Enumeration, 0, 0, 200)?;
        repository.seal_scan_stage(&run.guard, ScanStage::Sampling, 0, 0, 210)?;
        repository.seal_scan_stage(&run.guard, ScanStage::FullHash, 0, 0, 220)?;
        repository.seal_scan_stage(&run.guard, ScanStage::ExactVerification, 0, 0, 230)?;
        repository.transition_bound_scan_job_and_run(
            &run.guard,
            run.job_id,
            "running",
            1,
            "running",
            1,
            "completed",
            "completed",
            240,
            None,
        )?;
        Ok(())
    })?;
    drop(store);

    rewrite_with_trigger_disabled(
        &database_path,
        "trg_scan_run_sessions_no_delete_v5",
        |connection| {
            let deleted = connection.execute(
                "DELETE FROM scan_run_sessions WHERE scan_run_id = ?1",
                [run.run_id],
            )?;
            assert_eq!(deleted, 1);
            Ok(())
        },
    )?;
    assert_corrupt_store_rejected(&database_path);
    Ok(())
}

#[test]
fn v5_guards_batches_and_caught_mutation_errors_poison_the_transaction(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("guards.sqlite3"))?;
    let run = create_running_run(&mut store, "guards", 8)?;
    let oversized = (0_u8..=128)
        .map(|index| observation(index, 1))
        .collect::<Vec<_>>();
    let result = store.write_transaction(|repository| {
        assert!(matches!(
            repository.record_observation_batch(&run.guard, &oversized),
            Err(StoreError::InvalidInput { .. })
        ));
        repository.record_bound_scan_issue(
            &run.guard,
            &NewScanIssue {
                issue_key: "must-roll-back".into(),
                volume_id: run.volume_id,
                scan_run_id: run.run_id,
                media_file_id: None,
                severity: "warning".into(),
                stage: "enumeration".into(),
                code: "CAUGHT_ERROR".into(),
                message: "this write must not commit".into(),
                details: None,
                occurred_at_ms: 300,
            },
        )?;
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::WriteTransactionPoisoned)));
    assert!(store
        .list_issues_page(run.run_id, None, 10)?
        .items
        .is_empty());

    let wrong_guard = RunEvidenceGuard {
        scan_run_id: run.run_id,
        capability_profile_id: run.capability_profile_id,
        mount_session_key: MountSessionKey::from_runtime_evidence([99; 32]),
    };
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.record_observation_batch(&wrong_guard, &[observation(1, 1)])
        }),
        Err(StoreError::ConcurrencyConflict { .. })
    ));
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.record_bound_scan_issue(
                &wrong_guard,
                &NewScanIssue {
                    issue_key: "stale-worker-issue".into(),
                    volume_id: run.volume_id,
                    scan_run_id: run.run_id,
                    media_file_id: None,
                    severity: "warning".into(),
                    stage: "enumeration".into(),
                    code: "STALE_WORKER".into(),
                    message: "must not persist".into(),
                    details: None,
                    occurred_at_ms: 180,
                },
            )
        }),
        Err(StoreError::ConcurrencyConflict { .. })
    ));
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.update_bound_scan_progress(&wrong_guard, 1, 0, 0, 1, 180)
        }),
        Err(StoreError::ConcurrencyConflict { .. })
    ));
    let checkpoint = ScanCheckpointInput {
        scan_run_id: run.run_id,
        volume_id: run.volume_id,
        expected_previous_version: None,
        cursor_version: 1,
        cursor: serde_json::json!({"after": 0}),
        discovered_count: 0,
        fingerprinted_count: 0,
        error_count: 0,
        logical_bytes_seen: 0,
        saved_at_ms: 180,
    };
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.save_bound_scan_checkpoint(&wrong_guard, &checkpoint)
        }),
        Err(StoreError::ConcurrencyConflict { .. })
    ));
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.transition_bound_scan_job_and_run(
                &wrong_guard,
                run.job_id,
                "running",
                1,
                "running",
                1,
                "failed",
                "interrupted",
                181,
                Some(("STALE_WORKER", "wrong mount session")),
            )
        }),
        Err(StoreError::ConcurrencyConflict { .. })
    ));
    let unchanged = store.get_scan_run("guards-run")?.expect("fixture run");
    assert_eq!(unchanged.state, "running");
    assert_eq!(unchanged.state_version, 1);
    assert_eq!(unchanged.discovered_count, 0);
    assert_eq!(unchanged.logical_bytes_seen, 0);
    assert!(store.get_scan_checkpoint(run.run_id)?.is_none());
    assert!(store
        .list_issues_page(run.run_id, None, 10)?
        .items
        .is_empty());

    let mut mismatched_path = observation(2, 1);
    mismatched_path.mount_relative_path_raw = b"DCIM2/photo-2.jpg".to_vec();
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.record_observation_batch(&run.guard, &[mismatched_path])
        }),
        Err(StoreError::InvalidInput {
            field: "mount_relative_path_raw",
            ..
        })
    ));
    Ok(())
}

#[test]
fn current_session_namespace_cannot_cross_mount_generations(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("session-namespace.sqlite3"))?;
    let mount_a = MountSessionKey::from_runtime_evidence([61; 32]);
    let mount_b = MountSessionKey::from_runtime_evidence([62; 32]);
    let (volume_id, job_id, run_id, capability_a, guard_a) =
        store.write_transaction(|repository| {
            let volume_id = repository.upsert_volume(&VolumeInput {
                identity_key: "session-namespace-volume".into(),
                identity_strength: "weak".into(),
                marker_uuid: None,
                native_uuid: None,
                filesystem_type: "unknown".into(),
                display_name: None,
                mount_source: None,
                last_mount_path: None,
                transport: None,
                is_network: false,
                is_read_only: true,
                now_ms: 100,
            })?;
            let capability_a =
                repository.set_current_capability_profile(&capability(volume_id, mount_a))?;
            let namespace_a = NamespaceProfileInput {
                volume_id,
                profile_key: NamespaceProfileKey::from_volume_adapter([63; 32]),
                profile_version: 1,
                native_path_encoding: "unix_bytes".into(),
                case_behavior: "unknown".into(),
                unicode_behavior: "unknown".into(),
                key_strategy: "exact_native_v1".into(),
                key_algorithm_version: 2,
                reuse_scope: "current_session_only".into(),
                bound_mount_session_key: Some(mount_a),
                created_at_ms: 100,
            };
            let namespace_a_id = repository.register_namespace_profile(&namespace_a)?;
            assert_eq!(
                repository.register_namespace_profile(&namespace_a)?,
                namespace_a_id
            );
            let namespace_b_id = repository.register_namespace_profile(&NamespaceProfileInput {
                bound_mount_session_key: Some(mount_b),
                ..namespace_a.clone()
            })?;
            assert_ne!(namespace_a_id, namespace_b_id);
            let job_id = repository.create_scoped_scan_job(&NewScopedScanJob {
                job_key: "session-namespace-job".into(),
                volume_id,
                namespace_profile_id: namespace_a_id,
                root_display: "DCIM".into(),
                mount_relative_root_raw: b"DCIM".to_vec(),
                path_encoding: "utf8".into(),
                stable_root_path_key: StablePathKey::from_volume_adapter([64; 32]),
                root_scope_key: RootScopeKey::from_volume_adapter([65; 32]),
                config: None,
                created_at_ms: 110,
            })?;
            let run_id = repository.create_bound_scan_run(&NewBoundScanRun {
                run_key: "session-namespace-run-a".into(),
                scan_job_id: job_id,
                volume_id,
                capability_profile_id: capability_a,
                parent_scan_run_id: None,
                mount_session_key: mount_a,
                mount_relative_root_raw: b"DCIM".to_vec(),
                path_encoding: "utf8".into(),
                stable_root_path_key: StablePathKey::from_volume_adapter([64; 32]),
                root_scope_key: RootScopeKey::from_volume_adapter([65; 32]),
                root_object_signature: RootObjectSignature::from_volume_adapter([66; 32]),
                scan_mode: "full".into(),
                config: None,
                created_at_ms: 120,
            })?;
            let guard_a = RunEvidenceGuard {
                scan_run_id: run_id,
                capability_profile_id: capability_a,
                mount_session_key: mount_a,
            };
            repository.transition_bound_scan_job_and_run(
                &guard_a, job_id, "queued", 0, "queued", 0, "running", "running", 150, None,
            )?;
            Ok((volume_id, job_id, run_id, capability_a, guard_a))
        })?;

    store.write_transaction(|repository| {
        repository.transition_bound_scan_job_and_run(
            &guard_a,
            job_id,
            "running",
            1,
            "running",
            1,
            "failed",
            "interrupted",
            180,
            Some(("MOUNT_ENDED", "fixture mount generation ended")),
        )?;
        Ok(())
    })?;
    let capability_b = store.write_transaction(|repository| {
        repository.set_current_capability_profile(&capability(volume_id, mount_b))
    })?;
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.record_observation_batch(&guard_a, &[observation(0, 1)])
        }),
        Err(StoreError::ConcurrencyConflict { .. })
    ));
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.create_bound_scan_run(&NewBoundScanRun {
                run_key: "session-namespace-run-b".into(),
                scan_job_id: job_id,
                volume_id,
                capability_profile_id: capability_b,
                parent_scan_run_id: Some(run_id),
                mount_session_key: mount_b,
                mount_relative_root_raw: b"DCIM".to_vec(),
                path_encoding: "utf8".into(),
                stable_root_path_key: StablePathKey::from_volume_adapter([64; 32]),
                root_scope_key: RootScopeKey::from_volume_adapter([65; 32]),
                root_object_signature: RootObjectSignature::from_volume_adapter([67; 32]),
                scan_mode: "resume".into(),
                config: None,
                created_at_ms: 200,
            })
        }),
        Err(StoreError::ConcurrencyConflict {
            entity: "bound_run_namespace_mount_session",
            ..
        })
    ));
    let stale = store
        .get_scan_run("session-namespace-run-a")?
        .expect("fixture run");
    assert_eq!(stale.capability_profile_id, capability_a);
    assert_eq!(stale.state, "interrupted");
    assert_eq!(stale.state_version, 2);
    Ok(())
}

#[test]
fn exact_group_overlap_and_failed_draft_abandonment_are_fail_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("exact-overlap.sqlite3"))?;
    let run = create_running_run(&mut store, "overlap", 21)?;
    let mut observations = (0_u8..5)
        .map(|index| observation(index, 10))
        .collect::<Vec<_>>();
    observations[3].file_object_key = observations[1].file_object_key;
    let observation_ids = store.write_transaction(|repository| {
        let ids = repository.record_observation_batch(&run.guard, &observations)?;
        repository.seal_scan_stage(&run.guard, ScanStage::Enumeration, 5, 50, 200)?;
        repository.seal_scan_stage(&run.guard, ScanStage::Sampling, 0, 0, 210)?;
        Ok(ids)
    })?;
    let parameters_hash = ParametersHash::from_runtime_evidence([81; 32]);
    let fingerprints = observation_ids
        .iter()
        .enumerate()
        .map(|(index, observation_id)| {
            exact_fingerprint(
                *observation_id,
                observations[index].source_signature,
                10,
                parameters_hash,
                300 + i64::try_from(index).expect("small fixture index"),
            )
        })
        .collect::<Vec<_>>();
    let fingerprint_ids = store.write_transaction(|repository| {
        let ids = repository.record_fingerprint_fresh_batch(&run.guard, &fingerprints)?;
        repository.seal_scan_stage(&run.guard, ScanStage::FullHash, 5, 50, 400)?;
        Ok(ids)
    })?;

    let verified_build = store.write_transaction(|repository| {
        prepare_two_member_group(
            repository,
            &run.guard,
            82,
            [0, 1],
            &observations,
            &observation_ids,
            &fingerprint_ids,
            parameters_hash,
            500,
        )
    })?;
    store.write_transaction(|repository| {
        repository.finalize_exact_group(&run.guard, verified_build, 520)?;
        Ok(())
    })?;

    let observation_overlap = store.write_transaction(|repository| {
        prepare_two_member_group(
            repository,
            &run.guard,
            83,
            [0, 2],
            &observations,
            &observation_ids,
            &fingerprint_ids,
            parameters_hash,
            530,
        )
    })?;
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.finalize_exact_group(&run.guard, observation_overlap, 550)
        }),
        Err(StoreError::IdempotencyConflict {
            entity: "verified_exact_group_observation_overlap",
            ..
        })
    ));
    store.write_transaction(|repository| {
        repository.abandon_exact_group_draft(
            &run.guard,
            observation_overlap,
            560,
            "OVERLAPPING_OBSERVATION",
            Some("member already belongs to a verified group"),
        )?;
        repository.abandon_exact_group_draft(
            &run.guard,
            observation_overlap,
            560,
            "OVERLAPPING_OBSERVATION",
            Some("member already belongs to a verified group"),
        )
    })?;

    let file_object_overlap = store.write_transaction(|repository| {
        prepare_two_member_group(
            repository,
            &run.guard,
            84,
            [3, 4],
            &observations,
            &observation_ids,
            &fingerprint_ids,
            parameters_hash,
            570,
        )
    })?;
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.finalize_exact_group(&run.guard, file_object_overlap, 590)
        }),
        Err(StoreError::IdempotencyConflict {
            entity: "verified_exact_group_file_object_overlap",
            ..
        })
    ));
    store.write_transaction(|repository| {
        repository.abandon_exact_group_draft(
            &run.guard,
            file_object_overlap,
            600,
            "OVERLAPPING_FILE_OBJECT",
            None,
        )
    })?;

    let short_read_draft = store.write_transaction(|repository| {
        repository.begin_exact_group(
            &run.guard,
            &BeginExactGroupInput {
                build_key: BuildKey::from_runtime_evidence([85; 32]),
                representative_observation_id: observation_ids[2],
                representative_fingerprint_id: fingerprint_ids[2],
                expected_member_count: 2,
                expected_manifest_digest: ManifestDigest::from_runtime_evidence([86; 32]),
                created_at_ms: 610,
            },
        )
    })?;
    store.write_transaction(|repository| {
        repository.abandon_exact_group_draft(
            &run.guard,
            short_read_draft,
            620,
            "SHORT_READ",
            Some("source changed before the exact comparison reached EOF"),
        )
    })?;

    let remaining_build = store.write_transaction(|repository| {
        prepare_two_member_group(
            repository,
            &run.guard,
            87,
            [2, 4],
            &observations,
            &observation_ids,
            &fingerprint_ids,
            parameters_hash,
            630,
        )
    })?;
    store.write_transaction(|repository| {
        repository.finalize_exact_group(&run.guard, remaining_build, 650)?;
        repository.seal_scan_stage(&run.guard, ScanStage::ExactVerification, 4, 40, 660)?;
        repository.transition_bound_scan_job_and_run(
            &run.guard,
            run.job_id,
            "running",
            1,
            "running",
            1,
            "completed",
            "completed",
            670,
            None,
        )?;
        Ok(())
    })?;
    let completed = store.get_scan_run("overlap-run")?.expect("fixture run");
    assert_eq!(completed.state, "completed");
    Ok(())
}

#[test]
fn legacy_scan_evidence_api_is_explicitly_retired_and_poisoned(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("legacy-disabled.sqlite3"))?;
    let result = store.write_transaction(|repository| {
        let error = repository
            .create_scan_job(&NewScanJob {
                job_key: "legacy-job".into(),
                volume_id: 1,
                capability_profile_id: 1,
                root_relative_path: "DCIM".into(),
                root_relative_path_raw: b"DCIM".to_vec(),
                root_path_encoding: "utf8".into(),
                root_path_key: PathKey::from_filesystem_adapter(vec![1; 32])?,
                path_semantics_version: 1,
                config: None,
                created_at_ms: 1,
            })
            .expect_err("legacy API unexpectedly accepted new evidence");
        assert!(matches!(
            error,
            StoreError::LegacyEvidenceApiDisabled {
                api: "create_scan_job"
            }
        ));
        repository.upsert_volume(&VolumeInput {
            identity_key: "must-not-commit".into(),
            identity_strength: "weak".into(),
            marker_uuid: None,
            native_uuid: None,
            filesystem_type: "unknown".into(),
            display_name: None,
            mount_source: None,
            last_mount_path: None,
            transport: None,
            is_network: false,
            is_read_only: true,
            now_ms: 1,
        })?;
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::WriteTransactionPoisoned)));

    let report_result = store.write_transaction(|repository| {
        let error = repository
            .write_scan_report(&NewScanReport {
                report_key: "legacy-report".into(),
                volume_id: 1,
                scan_run_id: 1,
                report_version: 1,
                report: serde_json::json!({"untrusted": true}),
                generated_at_ms: 1,
            })
            .expect_err("legacy report API unexpectedly accepted a report");
        assert!(matches!(
            error,
            StoreError::LegacyEvidenceApiDisabled {
                api: "write_scan_report"
            }
        ));
        repository.upsert_volume(&VolumeInput {
            identity_key: "report-must-not-commit".into(),
            identity_strength: "weak".into(),
            marker_uuid: None,
            native_uuid: None,
            filesystem_type: "unknown".into(),
            display_name: None,
            mount_source: None,
            last_mount_path: None,
            transport: None,
            is_network: false,
            is_read_only: true,
            now_ms: 1,
        })?;
        Ok(())
    });
    assert!(matches!(
        report_result,
        Err(StoreError::WriteTransactionPoisoned)
    ));
    assert!(store.get_scan_report("legacy-report")?.is_none());
    Ok(())
}

#[test]
fn manifest_encoding_has_a_stable_golden_digest() -> Result<(), StoreError> {
    let member = ExactGroupManifestMember {
        ordinal: 0,
        observation_id: 1,
        fingerprint_id: 2,
        sort_rank: 3,
        stable_path_key: StablePathKey::from_volume_adapter([4; 32]),
        source_signature: SourceSignature::from_runtime_evidence([5; 32]),
        size_bytes: 6,
        algorithm: "blake3".into(),
        algorithm_version: 1,
        parameters_hash: ParametersHash::from_runtime_evidence([7; 32]),
        digest: vec![8; 32],
        file_object_key: Some(FileObjectKey::from_runtime_evidence([9; 32])),
    };
    let leaf = compute_exact_group_member_leaf(&member)?;
    let manifest = compute_exact_group_manifest(&[leaf, leaf])?;
    assert_eq!(
        hex(leaf),
        "9cc2d8f3c0a26ad6dc50bd6ff4059224717a047fd2750932b364823400b8736a"
    );
    assert_eq!(
        hex(manifest),
        "9f4c9d3529629d6a954db5137357a15aa2e0b9c0f01f911f276748ffc0353d56"
    );
    Ok(())
}

fn create_running_run(
    store: &mut Store,
    prefix: &str,
    session_byte: u8,
) -> Result<RunningRun, StoreError> {
    let mount_session_key = MountSessionKey::from_runtime_evidence([session_byte; 32]);
    store.write_transaction(|repository| {
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
        let run_input = NewBoundScanRun {
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
        };
        let run_id = repository.create_bound_scan_run(&run_input)?;
        assert_eq!(repository.create_bound_scan_run(&run_input)?, run_id);
        let guard = RunEvidenceGuard {
            scan_run_id: run_id,
            capability_profile_id,
            mount_session_key,
        };
        repository.transition_bound_scan_job_and_run(
            &guard, job_id, "queued", 0, "queued", 0, "running", "running", 150, None,
        )?;
        Ok(RunningRun {
            volume_id,
            capability_profile_id,
            job_id,
            run_id,
            guard,
        })
    })
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

fn observation(index: u8, size_bytes: i64) -> ObservationInput {
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
        birth_time: None,
        modified_time: FileTimestampParts {
            seconds: 2_000,
            nanoseconds: 0,
        },
        changed_time: FileTimestampParts {
            seconds: 3_000,
            nanoseconds: 0,
        },
        accessed_time: None,
        timestamp_granularity_ns: 1,
        observed_at_ms: 160 + i64::from(index),
    }
}

fn exact_fingerprint(
    observation_id: i64,
    source_signature: SourceSignature,
    size_bytes: i64,
    parameters_hash: ParametersHash,
    timestamp: i64,
) -> FreshFingerprintInput {
    FreshFingerprintInput {
        observation_id,
        fingerprint_kind: FreshFingerprintKind::ExactBytes,
        algorithm: ALGORITHM.into(),
        algorithm_version: 1,
        parameters_hash,
        read_origin: FingerprintReadOrigin::FullHashRead,
        source_signature_before: source_signature,
        source_signature_after: source_signature,
        digest: vec![71; 32],
        observed_size_bytes: size_bytes,
        bytes_read: size_bytes,
        reached_expected_eof: true,
        completed_at_ms: timestamp,
        created_at_ms: timestamp,
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_two_member_group(
    repository: &mut RepositoryTx<'_>,
    guard: &RunEvidenceGuard,
    build_key_byte: u8,
    indices: [usize; 2],
    observations: &[ObservationInput],
    observation_ids: &[i64],
    fingerprint_ids: &[i64],
    parameters_hash: ParametersHash,
    created_at_ms: i64,
) -> Result<i64, StoreError> {
    let selected_observations = indices
        .iter()
        .map(|index| observations[*index].clone())
        .collect::<Vec<_>>();
    let selected_observation_ids = indices
        .iter()
        .map(|index| observation_ids[*index])
        .collect::<Vec<_>>();
    let selected_fingerprint_ids = indices
        .iter()
        .map(|index| fingerprint_ids[*index])
        .collect::<Vec<_>>();
    let material = manifest_members(
        &selected_observations,
        &selected_observation_ids,
        &selected_fingerprint_ids,
        parameters_hash,
    )?;
    let leaves = material
        .iter()
        .map(compute_exact_group_member_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = compute_exact_group_manifest(&leaves)?;
    let build_id = repository.begin_exact_group(
        guard,
        &BeginExactGroupInput {
            build_key: BuildKey::from_runtime_evidence([build_key_byte; 32]),
            representative_observation_id: selected_observation_ids[0],
            representative_fingerprint_id: selected_fingerprint_ids[0],
            expected_member_count: 2,
            expected_manifest_digest: manifest,
            created_at_ms,
        },
    )?;
    repository.append_exact_group_members(
        guard,
        build_id,
        &[
            ExactGroupMemberInput {
                ordinal: 0,
                observation_id: selected_observation_ids[0],
                fingerprint_id: selected_fingerprint_ids[0],
                sort_rank: 0,
            },
            ExactGroupMemberInput {
                ordinal: 1,
                observation_id: selected_observation_ids[1],
                fingerprint_id: selected_fingerprint_ids[1],
                sort_rank: 1,
            },
        ],
    )?;
    let verified_at_ms = created_at_ms
        .checked_add(10)
        .ok_or_else(|| StoreError::InvalidInput {
            field: "verified_at_ms",
            reason: "fixture time overflow".into(),
        })?;
    repository.append_exact_verification_edges(
        guard,
        build_id,
        &[ExactVerificationEdgeInput {
            member_observation_id: selected_observation_ids[1],
            member_fingerprint_id: selected_fingerprint_ids[1],
            representative_source_signature: selected_observations[0].source_signature,
            member_source_signature: selected_observations[1].source_signature,
            compared_bytes: selected_observations[0].size_bytes,
            verified_at_ms,
        }],
    )?;
    Ok(build_id)
}

fn assert_verified_group_tampering_is_rejected(
    database_path: &Path,
    build_id: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open(database_path)?;
    let original_leaf: Vec<u8> = connection.query_row(
        "SELECT manifest_leaf FROM exact_group_build_members \
         WHERE exact_group_build_id = ?1 AND ordinal = 0",
        [build_id],
        |row| row.get(0),
    )?;
    let (original_group_key, original_reclaim): (Vec<u8>, i64) = connection.query_row(
        "SELECT group_key, logical_reclaimable_bytes FROM exact_group_builds WHERE id = ?1",
        [build_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    drop(connection);

    rewrite_with_trigger_disabled(
        database_path,
        "trg_exact_group_build_members_no_update_v5",
        |connection| {
            connection.execute(
                "UPDATE exact_group_build_members SET manifest_leaf = ?2 \
                 WHERE exact_group_build_id = ?1 AND ordinal = 0",
                params![build_id, vec![0_u8; 32]],
            )?;
            Ok(())
        },
    )?;
    assert_corrupt_store_rejected(database_path);
    rewrite_with_trigger_disabled(
        database_path,
        "trg_exact_group_build_members_no_update_v5",
        |connection| {
            connection.execute(
                "UPDATE exact_group_build_members SET manifest_leaf = ?2 \
                 WHERE exact_group_build_id = ?1 AND ordinal = 0",
                params![build_id, original_leaf],
            )?;
            Ok(())
        },
    )?;
    drop(Store::open_existing(database_path)?);

    let tampered_reclaim =
        original_reclaim
            .checked_add(1)
            .ok_or_else(|| StoreError::InvalidInput {
                field: "logical_reclaimable_bytes",
                reason: "fixture reclaim overflow".into(),
            })?;
    rewrite_with_trigger_disabled(
        database_path,
        "trg_exact_group_builds_update_guard_v5",
        |connection| {
            connection.execute(
                "UPDATE exact_group_builds SET logical_reclaimable_bytes = ?2 WHERE id = ?1",
                params![build_id, tampered_reclaim],
            )?;
            Ok(())
        },
    )?;
    assert_corrupt_store_rejected(database_path);
    rewrite_with_trigger_disabled(
        database_path,
        "trg_exact_group_builds_update_guard_v5",
        |connection| {
            connection.execute(
                "UPDATE exact_group_builds SET logical_reclaimable_bytes = ?2 WHERE id = ?1",
                params![build_id, original_reclaim],
            )?;
            Ok(())
        },
    )?;
    drop(Store::open_existing(database_path)?);

    rewrite_with_trigger_disabled(
        database_path,
        "trg_exact_group_builds_update_guard_v5",
        |connection| {
            connection.execute(
                "UPDATE exact_group_builds SET group_key = ?2 WHERE id = ?1",
                params![build_id, vec![0_u8; 32]],
            )?;
            Ok(())
        },
    )?;
    assert_corrupt_store_rejected(database_path);
    rewrite_with_trigger_disabled(
        database_path,
        "trg_exact_group_builds_update_guard_v5",
        |connection| {
            connection.execute(
                "UPDATE exact_group_builds SET group_key = ?2 WHERE id = ?1",
                params![build_id, original_group_key],
            )?;
            Ok(())
        },
    )?;
    drop(Store::open_existing(database_path)?);

    let (scan_run_id, enumeration_count): (i64, i64) = {
        let connection = Connection::open(database_path)?;
        connection.query_row(
            "SELECT build.scan_run_id, seal.item_count \
             FROM exact_group_builds AS build \
             JOIN scan_stage_seals AS seal \
               ON seal.scan_run_id = build.scan_run_id \
              AND seal.stage = 'enumeration' \
             WHERE build.id = ?1",
            [build_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?
    };
    let tampered_enumeration_count =
        enumeration_count
            .checked_add(1)
            .ok_or(StoreError::InvalidInput {
                field: "enumeration_count",
                reason: "fixture count overflow".into(),
            })?;
    rewrite_with_trigger_disabled(
        database_path,
        "trg_scan_stage_seals_no_update_v5",
        |connection| {
            connection.execute(
                "UPDATE scan_stage_seals SET item_count = ?2 \
                 WHERE scan_run_id = ?1 AND stage = 'enumeration'",
                params![scan_run_id, tampered_enumeration_count],
            )?;
            Ok(())
        },
    )?;
    assert_corrupt_store_rejected(database_path);
    rewrite_with_trigger_disabled(
        database_path,
        "trg_scan_stage_seals_no_update_v5",
        |connection| {
            connection.execute(
                "UPDATE scan_stage_seals SET item_count = ?2 \
                 WHERE scan_run_id = ?1 AND stage = 'enumeration'",
                params![scan_run_id, enumeration_count],
            )?;
            Ok(())
        },
    )?;
    drop(Store::open_existing(database_path)?);

    let (namespace_path_id, original_display, original_mount_path): (i64, String, Vec<u8>) = {
        let connection = Connection::open(database_path)?;
        connection.query_row(
            "SELECT path.id, path.display_path, path.mount_relative_path_raw \
             FROM exact_group_build_members AS member \
             JOIN media_observation_snapshots AS observation \
               ON observation.id = member.media_observation_snapshot_id \
              AND observation.scan_run_id = member.scan_run_id \
             JOIN media_namespace_paths AS path \
               ON path.id = observation.media_namespace_path_id \
              AND path.volume_id = observation.volume_id \
             WHERE member.exact_group_build_id = ?1 AND member.ordinal = 0",
            [build_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?
    };
    rewrite_with_trigger_disabled(
        database_path,
        "trg_media_namespace_paths_no_update_v5",
        |connection| {
            connection.execute(
                "UPDATE media_namespace_paths \
                 SET display_path = 'OTHER/photo-0.jpg', \
                     mount_relative_path_raw = CAST('OTHER/photo-0.jpg' AS BLOB) \
                 WHERE id = ?1",
                [namespace_path_id],
            )?;
            Ok(())
        },
    )?;
    assert_corrupt_store_rejected(database_path);
    rewrite_with_trigger_disabled(
        database_path,
        "trg_media_namespace_paths_no_update_v5",
        |connection| {
            connection.execute(
                "UPDATE media_namespace_paths \
                 SET display_path = ?2, mount_relative_path_raw = ?3 WHERE id = ?1",
                params![namespace_path_id, original_display, original_mount_path],
            )?;
            Ok(())
        },
    )?;
    drop(Store::open_existing(database_path)?);
    Ok(())
}

fn rewrite_with_trigger_disabled(
    database_path: &Path,
    trigger_name: &str,
    mutation: impl FnOnce(&Connection) -> rusqlite::Result<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open(database_path)?;
    let trigger_sql: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
        [trigger_name],
        |row| row.get(0),
    )?;
    let drop_sql = match trigger_name {
        "trg_exact_group_build_members_no_update_v5" => {
            "DROP TRIGGER trg_exact_group_build_members_no_update_v5"
        }
        "trg_exact_group_builds_update_guard_v5" => {
            "DROP TRIGGER trg_exact_group_builds_update_guard_v5"
        }
        "trg_scan_stage_seals_no_update_v5" => "DROP TRIGGER trg_scan_stage_seals_no_update_v5",
        "trg_media_namespace_paths_no_update_v5" => {
            "DROP TRIGGER trg_media_namespace_paths_no_update_v5"
        }
        "trg_scan_run_sessions_no_delete_v5" => "DROP TRIGGER trg_scan_run_sessions_no_delete_v5",
        _ => return Err("unexpected fixture trigger".into()),
    };
    connection.execute_batch(drop_sql)?;
    mutation(&connection)?;
    connection.execute_batch(&trigger_sql)?;
    Ok(())
}

fn assert_corrupt_store_rejected(database_path: &Path) {
    let error = match Store::open_existing(database_path) {
        Ok(store) => {
            drop(store);
            panic!("tampered verified exact group was accepted")
        }
        Err(error) => error,
    };
    assert!(matches!(error, StoreError::MigrationHistoryMismatch(_)));
}

fn manifest_members(
    observations: &[ObservationInput],
    observation_ids: &[i64],
    fingerprint_ids: &[i64],
    parameters_hash: ParametersHash,
) -> Result<Vec<ExactGroupManifestMember>, StoreError> {
    (0..2)
        .map(|index| {
            Ok(ExactGroupManifestMember {
                ordinal: u64::try_from(index).map_err(|_| StoreError::InvalidInput {
                    field: "ordinal",
                    reason: "fixture ordinal overflow".into(),
                })?,
                observation_id: u64::try_from(observation_ids[index]).map_err(|_| {
                    StoreError::InvalidInput {
                        field: "observation_id",
                        reason: "fixture id overflow".into(),
                    }
                })?,
                fingerprint_id: u64::try_from(fingerprint_ids[index]).map_err(|_| {
                    StoreError::InvalidInput {
                        field: "fingerprint_id",
                        reason: "fixture id overflow".into(),
                    }
                })?,
                sort_rank: u64::try_from(index).map_err(|_| StoreError::InvalidInput {
                    field: "sort_rank",
                    reason: "fixture rank overflow".into(),
                })?,
                stable_path_key: observations[index].stable_path_key,
                source_signature: observations[index].source_signature,
                size_bytes: u64::try_from(observations[index].size_bytes).map_err(|_| {
                    StoreError::InvalidInput {
                        field: "size_bytes",
                        reason: "fixture size overflow".into(),
                    }
                })?,
                algorithm: ALGORITHM.into(),
                algorithm_version: 1,
                parameters_hash,
                digest: vec![71; 32],
                file_object_key: observations[index].file_object_key,
            })
        })
        .collect()
}

fn hex(digest: ManifestDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest.into_bytes() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
