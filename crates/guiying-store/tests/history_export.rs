use guiying_store::{
    compute_exact_group_manifest, compute_exact_group_member_leaf, AcquireRuntimeLeaseInput,
    BeginExactGroupInput, BuildKey, CapabilityProfileInput, CoreCoverageSealDigest,
    CoreDirectoryManifest, CoreDirectoryObservationInput, CoreFileObservationInput, CoreSessionId,
    CoreSessionInput, CoverageOutcomeInput, CoverageStatus, DirectoryObjectSignature,
    EvidenceReader, ExactGroupManifestMember, ExactGroupMemberInput, ExactVerificationEdgeInput,
    FileObjectKey, FileTimestampParts, FingerprintReadOrigin, FreshFingerprintInput,
    FreshFingerprintKind, HistoryExportDecimal, HistoryExportProjectedText,
    HistoryExportProjection, HistoryExportRecord, HistoryExportRequest, HistoryExportScope,
    LeasedScanTerminalOutcome, MountSessionKey, NamespaceProfileInput, NamespaceProfileKey,
    NewBoundScanRun, NewScanIssue, NewScopedScanJob, ObservationInput, ParametersHash,
    RootObjectSignature, RootScopeKey, RunEvidenceGuard, RuntimeLeaseKey, ScanStage,
    SourceSignature, StablePathKey, Store, StoreError, TicketSortKey, VolumeCoverageManifest,
    VolumeInput, MAX_HISTORY_EXPORT_BATCH_SIZE,
};
use tempfile::TempDir;

#[test]
fn export_request_enforces_the_batch_contract() {
    let request = HistoryExportRequest::new(
        HistoryExportScope::CompleteEvidence,
        HistoryExportProjection::Redacted,
        MAX_HISTORY_EXPORT_BATCH_SIZE,
    )
    .expect("maximum batch size is valid");
    assert_eq!(request.batch_size(), MAX_HISTORY_EXPORT_BATCH_SIZE);

    assert!(matches!(
        HistoryExportRequest::new(
            HistoryExportScope::Summary,
            HistoryExportProjection::Display,
            0,
        ),
        Err(StoreError::InvalidInput {
            field: "history_export_batch_size",
            ..
        })
    ));
    assert!(HistoryExportRequest::new(
        HistoryExportScope::Summary,
        HistoryExportProjection::Display,
        MAX_HISTORY_EXPORT_BATCH_SIZE + 1,
    )
    .is_err());
}

#[test]
fn database_integers_serialize_as_canonical_decimal_strings() {
    assert_eq!(
        serde_json::to_string(&HistoryExportDecimal::from_i64(i64::MIN))
            .expect("decimal serializes"),
        format!("\"{}\"", i64::MIN)
    );
    assert_eq!(HistoryExportDecimal::from_i64(0).as_str(), "0");
}

#[test]
fn redacted_text_serialization_has_no_value_field() {
    let value = serde_json::to_value(HistoryExportProjectedText::Redacted)
        .expect("redacted projection serializes");
    assert_eq!(value, serde_json::json!({ "projection": "redacted" }));
}

#[test]
fn real_snapshot_is_ordered_bounded_fully_consumed_and_safely_projected(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("history-export.sqlite3");
    let mut store = Store::open_or_create(&database)?;
    let run_id = seed_history_export_fixture(&mut store)?;
    store.close()?;

    let reader = EvidenceReader::open_existing_read_only(&database)?;
    let context = reader
        .resolve_scan_history_entry(run_id)?
        .expect("sealed completed fixture is visible to history");
    let incomplete = reader.with_scan_history_export_snapshot(
        &context,
        HistoryExportRequest::new(
            HistoryExportScope::CompleteEvidence,
            HistoryExportProjection::Redacted,
            1,
        )?,
        |snapshot| {
            let _ = snapshot.next_batch(|| Ok(()))?;
            Ok(())
        },
    );
    assert!(matches!(
        incomplete,
        Err(StoreError::InvalidInput {
            field: "history_export_callback",
            ..
        })
    ));

    let mut deadline_checks = 0_u32;
    let redacted = reader.with_scan_history_export_snapshot(
        &context,
        HistoryExportRequest::new(
            HistoryExportScope::CompleteEvidence,
            HistoryExportProjection::Redacted,
            1,
        )?,
        |snapshot| {
            assert_eq!(snapshot.expected_record_count(), 5);
            assert!(snapshot.logical_bytes_upper_bound() > 0);
            let mut records = Vec::new();
            let mut expected_cumulative = 0_u32;
            while let Some(batch) = snapshot.next_batch(|| {
                deadline_checks += 1;
                Ok(())
            })? {
                assert_eq!(batch.records.len(), 1, "batch_size=1 was not enforced");
                expected_cumulative += 1;
                assert_eq!(batch.cumulative_record_count, expected_cumulative);
                assert!(
                    batch.cumulative_logical_bytes_upper_bound
                        <= snapshot.logical_bytes_upper_bound()
                );
                records.extend(batch.records);
            }
            assert!(snapshot.is_complete());
            Ok(records)
        },
    )?;
    assert!(deadline_checks >= 6);
    assert_export_order(&redacted);
    for record in &redacted {
        match record {
            HistoryExportRecord::Summary(record) => {
                assert_eq!(
                    record.root_display_path,
                    HistoryExportProjectedText::Redacted
                );
            }
            HistoryExportRecord::DuplicateMember(record) => {
                assert_eq!(record.display_path, HistoryExportProjectedText::Redacted);
            }
            HistoryExportRecord::ScanIssue(record) => {
                assert_eq!(record.stage, HistoryExportProjectedText::Redacted);
                assert_eq!(record.code, HistoryExportProjectedText::Redacted);
                assert_eq!(record.message, HistoryExportProjectedText::Redacted);
            }
            HistoryExportRecord::DuplicateGroup(_) => {}
        }
    }
    let redacted_json = serde_json::to_string(&redacted)?;
    for sensitive in [
        "DCIM_PRIVATE_ROOT",
        "private-a.jpg",
        "private-b.jpg",
        "PRIVATE_STAGE",
        "PRIVATE_CODE",
        "PRIVATE_MESSAGE",
    ] {
        assert!(!redacted_json.contains(sensitive));
    }

    let display = reader.with_scan_history_export_snapshot(
        &context,
        HistoryExportRequest::new(
            HistoryExportScope::CompleteEvidence,
            HistoryExportProjection::Display,
            2,
        )?,
        |snapshot| {
            let mut records = Vec::new();
            let mut saw_two_record_batch = false;
            while let Some(batch) = snapshot.next_batch(|| Ok(()))? {
                assert!(batch.records.len() <= 2);
                saw_two_record_batch |= batch.records.len() == 2;
                records.extend(batch.records);
            }
            assert!(
                saw_two_record_batch,
                "member section did not exercise batch_size=2"
            );
            Ok(records)
        },
    )?;
    assert_export_order(&display);
    let display_json = serde_json::to_string(&display)?;
    for visible in [
        "DCIM_PRIVATE_ROOT",
        "private-a.jpg",
        "private-b.jpg",
        "PRIVATE_STAGE",
        "PRIVATE_CODE",
        "PRIVATE_MESSAGE",
    ] {
        assert!(display_json.contains(visible));
    }
    let lowercase = display_json.to_ascii_lowercase();
    for forbidden in [
        "native_file",
        "_raw",
        "path_key",
        "signature",
        "digest",
        "file_object",
        "ticket_blob",
    ] {
        assert!(
            !lowercase.contains(forbidden),
            "unsafe export field {forbidden}"
        );
    }
    reader.close()?;
    Ok(())
}

fn assert_export_order(records: &[HistoryExportRecord]) {
    assert_eq!(records.len(), 5);
    assert!(matches!(&records[0], HistoryExportRecord::Summary(_)));
    assert!(matches!(
        &records[1],
        HistoryExportRecord::DuplicateGroup(_)
    ));
    assert!(matches!(
        &records[2],
        HistoryExportRecord::DuplicateMember(_)
    ));
    assert!(matches!(
        &records[3],
        HistoryExportRecord::DuplicateMember(_)
    ));
    assert!(matches!(&records[4], HistoryExportRecord::ScanIssue(_)));
}

fn seed_history_export_fixture(store: &mut Store) -> Result<i64, Box<dyn std::error::Error>> {
    let mount_session_key = MountSessionKey::from_runtime_evidence([7; 32]);
    let (volume_id, guard) = store.write_transaction(|repository| {
        let volume_id = repository.upsert_volume(&VolumeInput {
            identity_key: "history-export-volume".into(),
            identity_strength: "strong".into(),
            marker_uuid: Some("history-export-marker".into()),
            native_uuid: Some("history-export-native".into()),
            filesystem_type: "apfs".into(),
            display_name: None,
            mount_source: None,
            last_mount_path: None,
            transport: None,
            is_network: false,
            is_read_only: true,
            now_ms: 100,
        })?;
        let capability_profile_id = repository
            .set_current_capability_profile(&history_capability(volume_id, mount_session_key))?;
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
            job_key: "history-export-job".into(),
            volume_id,
            namespace_profile_id,
            root_display: "DCIM_PRIVATE_ROOT".into(),
            mount_relative_root_raw: b"DCIM_PRIVATE_ROOT".to_vec(),
            path_encoding: "utf8".into(),
            stable_root_path_key: StablePathKey::from_volume_adapter([12; 32]),
            root_scope_key: RootScopeKey::from_volume_adapter([13; 32]),
            config: None,
            created_at_ms: 110,
        })?;
        let run_id = repository.create_bound_scan_run(&NewBoundScanRun {
            run_key: "history-export-run".into(),
            scan_job_id: job_id,
            volume_id,
            capability_profile_id,
            parent_scan_run_id: None,
            mount_session_key,
            mount_relative_root_raw: b"DCIM_PRIVATE_ROOT".to_vec(),
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
        Ok((volume_id, guard))
    })?;

    let core_session_id = CoreSessionId::from_runtime_evidence([20; 32]);
    let observations = [history_observation(0), history_observation(1)];
    let files = observations
        .iter()
        .enumerate()
        .map(|(index, observation)| {
            let ticket_blob = vec![30 + u8::try_from(index)?; 12];
            Ok(CoreFileObservationInput {
                observation: observation.clone(),
                ticket_sort_key: history_ticket_sort_key(&ticket_blob),
                ticket_blob,
                ticket_created_at_ms: 180 + i64::try_from(index)?,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let directory_blob = vec![40; 12];
    let directory = CoreDirectoryObservationInput {
        root_relative_path_raw: b"PRIVATE_DIRECTORY_TEXT".to_vec(),
        path_encoding: "utf8".into(),
        display_path: "PRIVATE_DIRECTORY_TEXT".into(),
        source_signature: SourceSignature::from_runtime_evidence([41; 32]),
        directory_object_signature: DirectoryObjectSignature::from_runtime_evidence([42; 32]),
        ticket_sort_key: history_ticket_sort_key(&directory_blob),
        ticket_blob: directory_blob,
        observed_at_ms: 175,
    };
    let (lease, observation_ids) = store.write_transaction(|repository| {
        repository.bind_core_session(
            &guard,
            &CoreSessionInput {
                core_session_id,
                root_object_signature: RootObjectSignature::from_volume_adapter([14; 32]),
                root_source_signature: SourceSignature::from_runtime_evidence([21; 32]),
                bound_at_ms: 151,
            },
        )?;
        let lease = repository.acquire_runtime_lease(
            &guard,
            &AcquireRuntimeLeaseInput::new(
                RuntimeLeaseKey::from_runtime_evidence([22; 32]),
                core_session_id,
                160,
            )?,
        )?;
        let observation_ids =
            repository.record_core_observation_batch(&guard, &core_session_id, &files)?;
        repository.record_core_directory_batch(&guard, &core_session_id, &[directory])?;
        repository.seal_scan_stage(&guard, ScanStage::Enumeration, 2, 20, 200)?;
        repository.seal_scan_stage(&guard, ScanStage::Sampling, 0, 0, 210)?;
        Ok((lease, observation_ids))
    })?;

    let parameters_hash = ParametersHash::from_runtime_evidence([50; 32]);
    let fingerprints = observation_ids
        .iter()
        .enumerate()
        .map(|(index, observation_id)| FreshFingerprintInput {
            observation_id: *observation_id,
            fingerprint_kind: FreshFingerprintKind::ExactBytes,
            algorithm: "blake3".into(),
            algorithm_version: 1,
            parameters_hash,
            read_origin: FingerprintReadOrigin::FullHashRead,
            source_signature_before: observations[index].source_signature,
            source_signature_after: observations[index].source_signature,
            digest: vec![51; 32],
            observed_size_bytes: 10,
            bytes_read: 10,
            reached_expected_eof: true,
            completed_at_ms: 300 + i64::try_from(index).expect("fixture index"),
            created_at_ms: 300 + i64::try_from(index).expect("fixture index"),
        })
        .collect::<Vec<_>>();
    let fingerprint_ids = store.write_transaction(|repository| {
        let ids = repository.record_fingerprint_fresh_batch(&guard, &fingerprints)?;
        repository.seal_scan_stage(&guard, ScanStage::FullHash, 2, 20, 400)?;
        Ok(ids)
    })?;
    let manifest_members = (0..2)
        .map(|index| ExactGroupManifestMember {
            ordinal: index as u64,
            observation_id: observation_ids[index] as u64,
            fingerprint_id: fingerprint_ids[index] as u64,
            sort_rank: index as u64,
            stable_path_key: observations[index].stable_path_key,
            source_signature: observations[index].source_signature,
            size_bytes: 10,
            algorithm: "blake3".into(),
            algorithm_version: 1,
            parameters_hash,
            digest: vec![51; 32],
            file_object_key: observations[index].file_object_key,
        })
        .collect::<Vec<_>>();
    let leaves = manifest_members
        .iter()
        .map(compute_exact_group_member_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = compute_exact_group_manifest(&leaves)?;
    store.write_transaction(|repository| {
        let build_id = repository.begin_exact_group(
            &guard,
            &BeginExactGroupInput {
                build_key: BuildKey::from_runtime_evidence([60; 32]),
                representative_observation_id: observation_ids[0],
                representative_fingerprint_id: fingerprint_ids[0],
                expected_member_count: 2,
                expected_manifest_digest: manifest,
                created_at_ms: 500,
            },
        )?;
        repository.append_exact_group_members(
            &guard,
            build_id,
            &[
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
            ],
        )?;
        repository.append_exact_verification_edges(
            &guard,
            build_id,
            &[ExactVerificationEdgeInput {
                member_observation_id: observation_ids[1],
                member_fingerprint_id: fingerprint_ids[1],
                representative_source_signature: observations[0].source_signature,
                member_source_signature: observations[1].source_signature,
                compared_bytes: 10,
                verified_at_ms: 600,
            }],
        )?;
        repository.finalize_exact_group(&guard, build_id, 700)?;
        repository.record_bound_scan_issue(
            &guard,
            &NewScanIssue {
                issue_key: "history-export-private-issue".into(),
                volume_id,
                scan_run_id: guard.scan_run_id,
                media_file_id: None,
                severity: "warning".into(),
                stage: "PRIVATE_STAGE".into(),
                code: "PRIVATE_CODE".into(),
                message: "PRIVATE_MESSAGE".into(),
                details: Some(serde_json::json!({ "private": "details" })),
                occurred_at_ms: 705,
            },
        )?;
        repository.record_core_coverage(
            &guard,
            &core_session_id,
            &CoverageOutcomeInput {
                status: CoverageStatus::Complete,
                directory_count: 1,
                replayed_count: 1,
                stable_count: 1,
                failed_count: 0,
                core_manifest_digest: Some(CoreDirectoryManifest::from_core_evidence([61; 32])),
                core_seal_digest: Some(CoreCoverageSealDigest::from_core_evidence([62; 32])),
                volume_verification_manifest: Some(VolumeCoverageManifest::from_volume_adapter(
                    [63; 32],
                )),
                finalized_at_ms: 710,
            },
        )?;
        repository.seal_scan_stage(&guard, ScanStage::ExactVerification, 1, 10, 720)?;
        repository.transition_leased_scan_job_and_run(
            &lease,
            "running",
            1,
            "running",
            1,
            LeasedScanTerminalOutcome::Completed,
            800,
            None,
        )?;
        Ok(())
    })?;
    Ok(guard.scan_run_id)
}

fn history_ticket_sort_key(ticket_blob: &[u8]) -> TicketSortKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.core-ticket-id.v1\0");
    hasher.update(ticket_blob);
    TicketSortKey::from_core_evidence(*hasher.finalize().as_bytes())
}

fn history_observation(index: u8) -> ObservationInput {
    let display_path = if index == 0 {
        "private-a.jpg"
    } else {
        "private-b.jpg"
    };
    ObservationInput {
        stable_path_key: StablePathKey::from_volume_adapter([70 + index; 32]),
        mount_relative_path_raw: format!("DCIM_PRIVATE_ROOT/{display_path}").into_bytes(),
        root_relative_path_raw: display_path.as_bytes().to_vec(),
        path_encoding: "utf8".into(),
        display_path: display_path.into(),
        entry_type: "regular".into(),
        media_kind: "photo".into(),
        mime_type: Some("image/jpeg".into()),
        file_extension: Some("jpg".into()),
        source_signature: SourceSignature::from_runtime_evidence([80 + index; 32]),
        stat_signature_version: 2,
        file_object_key: Some(FileObjectKey::from_runtime_evidence([90 + index; 32])),
        native_file_id: Some(vec![100 + index; 8]),
        native_file_generation: Some(1),
        file_mode: 0o100_644,
        size_bytes: 10,
        allocated_bytes: Some(10),
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
        observed_at_ms: 170 + i64::from(index),
    }
}

fn history_capability(
    volume_id: i64,
    mount_session_key: MountSessionKey,
) -> CapabilityProfileInput {
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
