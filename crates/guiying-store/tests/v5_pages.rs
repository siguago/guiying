use guiying_store::{
    compute_exact_group_manifest, compute_exact_group_member_leaf, BeginExactGroupInput, BuildKey,
    CapabilityProfileInput, ExactGroupManifestMember, ExactGroupMemberInput,
    ExactVerificationEdgeInput, FileObjectKey, FileTimestampParts, FingerprintReadOrigin,
    FreshFingerprintInput, FreshFingerprintKind, MountSessionKey, NamespaceProfileInput,
    NamespaceProfileKey, NewBoundScanRun, NewScanIssue, NewScopedScanJob, ObservationInput,
    ParametersHash, RootObjectSignature, RootScopeKey, RunEvidenceGuard, ScanStage,
    SourceSignature, StablePathKey, Store, StoreError, VolumeInput, MAX_PAGE_SIZE,
};
use tempfile::TempDir;

const ALGORITHM: &str = "blake3";

#[derive(Debug, Clone, Copy)]
struct RunningRun {
    volume_id: i64,
    job_id: i64,
    run_id: i64,
    guard: RunEvidenceGuard,
}

#[derive(Debug, Clone)]
struct SeededObservation {
    input: ObservationInput,
    id: i64,
}

#[test]
fn v5_candidate_pages_are_sealed_bounded_and_context_bound(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("v5-pages.sqlite3"))?;
    let run = create_running_run(&mut store, "pages", 7, None)?;

    assert_invalid(store.list_size_candidate_buckets_page(run.run_id, None, 1));

    let inputs = (0_u8..6)
        .map(|index| observation_input(index, 10 * (i64::from(index / 2) + 1)))
        .collect::<Vec<_>>();
    let observation_ids = store
        .write_transaction(|repository| repository.record_observation_batch(&run.guard, &inputs))?;
    let observations = inputs
        .into_iter()
        .zip(observation_ids)
        .map(|(input, id)| SeededObservation { input, id })
        .collect::<Vec<_>>();

    assert_invalid(store.list_size_candidate_buckets_page(run.run_id, None, 1));
    store.write_transaction(|repository| {
        repository.seal_scan_stage(&run.guard, ScanStage::Enumeration, 6, 120, 200)
    })?;

    let observation_page = store.list_observations_page(run.run_id, None, 2)?;
    assert_eq!(observation_page.items.len(), 2);
    let mut wrong_observation_cursor = observation_page
        .next_cursor
        .clone()
        .ok_or("observation page did not return a cursor")?;
    wrong_observation_cursor.scan_run_id += 1;
    assert_invalid(store.list_observations_page(run.run_id, Some(&wrong_observation_cursor), 2));
    let mut wrong_version_cursor = observation_page
        .next_cursor
        .ok_or("observation page did not return a cursor")?;
    wrong_version_cursor.cursor_version += 1;
    assert_invalid(store.list_observations_page(run.run_id, Some(&wrong_version_cursor), 2));
    let observed_ids = collect_observation_ids(&store, run.run_id, 2)?;
    assert_eq!(
        observed_ids,
        observations.iter().map(|item| item.id).collect::<Vec<_>>()
    );

    let size_buckets = collect_size_buckets(&store, run.run_id, 1)?;
    assert_eq!(size_buckets, vec![(10, 2), (20, 2), (30, 2)]);
    let first_size_page = store.list_size_candidate_buckets_page(run.run_id, None, 1)?;
    let mut wrong_size_cursor = first_size_page
        .next_cursor
        .ok_or("size page did not return a cursor")?;
    wrong_size_cursor.scan_run_id += 1;
    assert_invalid(store.list_size_candidate_buckets_page(run.run_id, Some(&wrong_size_cursor), 1));

    let first_members = store.list_observations_for_size_page(run.run_id, 10, None, 1)?;
    let mut wrong_member_cursor = first_members
        .next_cursor
        .ok_or("size-member page did not return a cursor")?;
    wrong_member_cursor.size_bytes = 20;
    assert_invalid(store.list_observations_for_size_page(
        run.run_id,
        10,
        Some(&wrong_member_cursor),
        1,
    ));

    let parameters_hash = ParametersHash::from_runtime_evidence([91; 32]);
    let samples = observations
        .iter()
        .enumerate()
        .map(|(index, observation)| sample_fingerprint(index, observation, parameters_hash))
        .collect::<Vec<_>>();
    store.write_transaction(|repository| {
        repository.record_fingerprint_fresh_batch(&run.guard, &samples)?;
        Ok(())
    })?;
    assert_invalid(store.list_sample_candidate_buckets_page(
        run.run_id,
        ALGORITHM,
        1,
        &parameters_hash,
        None,
        1,
    ));
    store.write_transaction(|repository| {
        repository.seal_scan_stage(&run.guard, ScanStage::Sampling, 6, 24, 300)
    })?;

    let exact = observations
        .iter()
        .enumerate()
        .map(|(index, observation)| exact_fingerprint(index, observation, parameters_hash))
        .collect::<Vec<_>>();
    let exact_ids = store.write_transaction(|repository| {
        repository.record_fingerprint_fresh_batch(&run.guard, &exact)
    })?;
    assert_invalid(store.list_exact_digest_buckets_page(
        run.run_id,
        ALGORITHM,
        1,
        &parameters_hash,
        None,
        1,
    ));

    let sample_buckets = collect_sample_buckets(&store, run.run_id, parameters_hash, 1)?;
    assert_eq!(
        sample_buckets,
        vec![(10, vec![40], 2), (20, vec![41], 2), (30, vec![42], 2)]
    );
    let first_sample = store.list_sample_candidate_buckets_page(
        run.run_id,
        ALGORITHM,
        1,
        &parameters_hash,
        None,
        1,
    )?;
    let mut wrong_sample_cursor = first_sample
        .next_cursor
        .clone()
        .ok_or("sample page did not return a cursor")?;
    wrong_sample_cursor.algorithm_version = 2;
    assert_invalid(store.list_sample_candidate_buckets_page(
        run.run_id,
        ALGORITHM,
        1,
        &parameters_hash,
        Some(&wrong_sample_cursor),
        1,
    ));
    let mut wrong_kind_cursor = first_sample
        .next_cursor
        .ok_or("sample page did not return a cursor")?;
    wrong_kind_cursor.fingerprint_kind = FreshFingerprintKind::ExactBytes;
    assert_invalid(store.list_sample_candidate_buckets_page(
        run.run_id,
        ALGORITHM,
        1,
        &parameters_hash,
        Some(&wrong_kind_cursor),
        1,
    ));

    store.write_transaction(|repository| {
        repository.seal_scan_stage(&run.guard, ScanStage::FullHash, 6, 120, 400)
    })?;
    let exact_buckets = collect_exact_buckets(&store, run.run_id, parameters_hash, 1)?;
    assert_eq!(
        exact_buckets,
        vec![(10, vec![50], 2), (20, vec![51], 2), (30, vec![52], 2)]
    );

    let mut verified_build_ids = Vec::new();
    for pair_index in 0..3 {
        verified_build_ids.push(create_verified_group(
            &mut store,
            &run,
            &observations,
            &exact_ids,
            parameters_hash,
            pair_index,
        )?);
    }
    assert_invalid(store.list_duplicate_groups_page(run.run_id, None, 1));
    assert_invalid(store.list_duplicate_group_members_page(
        run.run_id,
        verified_build_ids[0],
        None,
        1,
    ));
    store.write_transaction(|repository| {
        repository.seal_scan_stage(&run.guard, ScanStage::ExactVerification, 3, 60, 1_000)
    })?;
    let mut group_cursor = None;
    let mut group_ids = Vec::new();
    loop {
        let page = store.list_duplicate_groups_page(run.run_id, group_cursor.as_ref(), 1)?;
        group_ids.extend(page.items.into_iter().map(|group| group.build_id));
        group_cursor = page.next_cursor;
        if group_cursor.is_none() {
            break;
        }
    }
    assert_eq!(group_ids.len(), 3);
    assert_eq!(
        group_ids,
        verified_build_ids.into_iter().rev().collect::<Vec<_>>()
    );

    let first_group_page = store.list_duplicate_groups_page(run.run_id, None, 1)?;
    let first_group = first_group_page.items[0].build_id;
    let mut wrong_group_cursor = first_group_page
        .next_cursor
        .ok_or("group page did not return a cursor")?;
    wrong_group_cursor.scan_run_id += 1;
    assert_invalid(store.list_duplicate_groups_page(run.run_id, Some(&wrong_group_cursor), 1));

    let first_member_page =
        store.list_duplicate_group_members_page(run.run_id, first_group, None, 1)?;
    assert_eq!(
        first_member_page.items[0].birth_time,
        Some(FileTimestampParts {
            seconds: 1_000,
            nanoseconds: 0,
        })
    );
    assert_eq!(
        first_member_page.items[0].modified_time,
        FileTimestampParts {
            seconds: 2_000,
            nanoseconds: 0,
        }
    );
    assert_eq!(first_member_page.items[0].timestamp_granularity_ns, Some(1));
    let mut wrong_group_member_cursor = first_member_page
        .next_cursor
        .ok_or("group-member page did not return a cursor")?;
    wrong_group_member_cursor.group_build_id = first_group + 1_000_000;
    assert_invalid(store.list_duplicate_group_members_page(
        run.run_id,
        first_group,
        Some(&wrong_group_member_cursor),
        1,
    ));
    let mut member_cursor = None;
    let mut member_ordinals = Vec::new();
    loop {
        let page = store.list_duplicate_group_members_page(
            run.run_id,
            first_group,
            member_cursor.as_ref(),
            1,
        )?;
        member_ordinals.extend(page.items.into_iter().map(|member| member.ordinal));
        member_cursor = page.next_cursor;
        if member_cursor.is_none() {
            break;
        }
    }
    assert_eq!(member_ordinals, vec![0, 1]);

    assert_invalid(store.list_observations_page(run.run_id, None, 0));
    assert_invalid(store.list_observations_page(run.run_id, None, MAX_PAGE_SIZE + 1));
    Ok(())
}

#[test]
fn v5_issue_page_rejects_payload_above_the_materialization_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("v5-budget.sqlite3"))?;
    let run = create_running_run(&mut store, "budget", 8, None)?;
    let message = "x".repeat(65_500);
    store.write_transaction(|repository| {
        for index in 0..=MAX_PAGE_SIZE {
            repository.record_bound_scan_issue(
                &run.guard,
                &NewScanIssue {
                    issue_key: format!("budget-issue-{index}"),
                    volume_id: run.volume_id,
                    scan_run_id: run.run_id,
                    media_file_id: None,
                    severity: "warning".into(),
                    stage: "enumeration".into(),
                    code: "PAGE_BUDGET".into(),
                    message: message.clone(),
                    details: None,
                    occurred_at_ms: 1_000 + i64::from(index),
                },
            )?;
        }
        Ok(())
    })?;

    assert!(matches!(
        store.list_scan_issues_page(run.run_id, None, MAX_PAGE_SIZE),
        Err(StoreError::ReadResultLimit { .. })
    ));
    assert!(matches!(
        store.list_issues_page(run.run_id, None, MAX_PAGE_SIZE),
        Err(StoreError::ReadResultLimit { .. })
    ));
    Ok(())
}

#[test]
fn exact_bucket_pages_ignore_late_exact_comparison_reads() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("v5-exact-origin.sqlite3"))?;
    let run = create_running_run(&mut store, "exact-origin", 10, None)?;
    let inputs = [observation_input(0, 10), observation_input(1, 10)];
    let ids = store
        .write_transaction(|repository| repository.record_observation_batch(&run.guard, &inputs))?;
    store.write_transaction(|repository| {
        repository.seal_scan_stage(&run.guard, ScanStage::Enumeration, 2, 20, 600)?;
        repository.seal_scan_stage(&run.guard, ScanStage::Sampling, 0, 0, 610)?;
        repository.seal_scan_stage(&run.guard, ScanStage::FullHash, 0, 0, 620)?;
        let parameters_hash = ParametersHash::from_runtime_evidence([93; 32]);
        let fingerprints = inputs
            .iter()
            .zip(ids.iter())
            .map(|(observation, observation_id)| FreshFingerprintInput {
                observation_id: *observation_id,
                fingerprint_kind: FreshFingerprintKind::ExactBytes,
                algorithm: ALGORITHM.into(),
                algorithm_version: 1,
                parameters_hash,
                read_origin: FingerprintReadOrigin::ExactCompareRead,
                source_signature_before: observation.source_signature,
                source_signature_after: observation.source_signature,
                digest: vec![77],
                observed_size_bytes: observation.size_bytes,
                bytes_read: observation.size_bytes,
                reached_expected_eof: true,
                completed_at_ms: 700,
                created_at_ms: 700,
            })
            .collect::<Vec<_>>();
        repository.record_fingerprint_fresh_batch(&run.guard, &fingerprints)?;
        Ok(())
    })?;

    let page = store.list_exact_digest_buckets_page(
        run.run_id,
        ALGORITHM,
        1,
        &ParametersHash::from_runtime_evidence([93; 32]),
        None,
        10,
    )?;
    assert!(page.items.is_empty());
    Ok(())
}

#[test]
fn fingerprint_hint_is_historical_v5_only_and_falls_back_on_missing_stat_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let mut store = Store::open_or_create(temporary.path().join("v5-hint.sqlite3"))?;
    let first = create_running_run(&mut store, "hint", 9, None)?;
    let parameters_hash = ParametersHash::from_runtime_evidence([92; 32]);
    let old_inputs = (0_u8..7)
        .map(|index| observation_input(index, 10))
        .collect::<Vec<_>>();
    let old_ids = store.write_transaction(|repository| {
        repository.record_observation_batch(&first.guard, &old_inputs)
    })?;
    let old_observations = old_inputs
        .into_iter()
        .zip(old_ids)
        .map(|(input, id)| SeededObservation { input, id })
        .collect::<Vec<_>>();
    store.write_transaction(|repository| {
        repository.seal_scan_stage(&first.guard, ScanStage::Enumeration, 7, 70, 200)?;
        repository.seal_scan_stage(&first.guard, ScanStage::Sampling, 0, 0, 210)?;
        let fingerprints = old_observations
            .iter()
            .enumerate()
            .map(|(index, observation)| exact_fingerprint(index, observation, parameters_hash))
            .collect::<Vec<_>>();
        repository.record_fingerprint_fresh_batch(&first.guard, &fingerprints)?;
        repository.transition_bound_scan_job_and_run(
            &first.guard,
            first.job_id,
            "running",
            1,
            "running",
            1,
            "failed",
            "interrupted",
            300,
            Some(("TEST_RESTART", "fixture restart")),
        )?;
        Ok(())
    })?;

    let resumed = create_running_run(&mut store, "hint", 10, Some(first.run_id))?;
    let mut matching = observation_input(0, 10);
    let mut missing_generation = observation_input(1, 10);
    missing_generation.native_file_generation = None;
    let mut changed_mtime = observation_input(2, 10);
    changed_mtime.modified_time.seconds += 1;
    let mut changed_ctime = observation_input(3, 10);
    changed_ctime.changed_time.nanoseconds += 1;
    let mut changed_size = observation_input(4, 11);
    let mut changed_native_id = observation_input(5, 10);
    changed_native_id.native_file_id = Some(vec![99; 8]);
    let mut changed_granularity = observation_input(6, 10);
    changed_granularity.timestamp_granularity_ns = Some(2);
    for (index, input) in [
        &mut matching,
        &mut missing_generation,
        &mut changed_mtime,
        &mut changed_ctime,
        &mut changed_size,
        &mut changed_native_id,
        &mut changed_granularity,
    ]
    .into_iter()
    .enumerate()
    {
        input.observed_at_ms = 500 + i64::try_from(index).expect("small fixture index");
    }
    let current_ids = store.write_transaction(|repository| {
        repository.record_observation_batch(
            &resumed.guard,
            &[
                matching,
                missing_generation,
                changed_mtime,
                changed_ctime,
                changed_size,
                changed_native_id,
                changed_granularity,
            ],
        )
    })?;

    let hint = store
        .find_fingerprint_hint(
            resumed.run_id,
            current_ids[0],
            ALGORITHM,
            1,
            &parameters_hash,
        )?
        .ok_or("eligible historical v5 fingerprint was not returned as a hint")?;
    assert_eq!(hint.scan_run_id, first.run_id);
    assert_eq!(hint.observation_id, old_observations[0].id);
    assert_eq!(hint.digest, vec![50]);

    for observation_id in &current_ids[1..] {
        assert!(store
            .find_fingerprint_hint(
                resumed.run_id,
                *observation_id,
                ALGORITHM,
                1,
                &parameters_hash,
            )?
            .is_none());
    }
    assert!(store
        .find_fingerprint_hint(
            resumed.run_id,
            current_ids[0],
            "different-algorithm",
            1,
            &parameters_hash,
        )?
        .is_none());
    Ok(())
}

fn create_running_run(
    store: &mut Store,
    prefix: &str,
    session_byte: u8,
    parent_scan_run_id: Option<i64>,
) -> Result<RunningRun, StoreError> {
    let mount_session_key = MountSessionKey::from_runtime_evidence([session_byte; 32]);
    let run_created_at_ms = if parent_scan_run_id.is_some() {
        400 + i64::from(session_byte)
    } else {
        120 + i64::from(session_byte)
    };
    let run_started_at_ms = if parent_scan_run_id.is_some() {
        450 + i64::from(session_byte)
    } else {
        150 + i64::from(session_byte)
    };
    store.write_transaction(|repository| {
        let volume_id = repository.upsert_volume(&volume_input(prefix))?;
        let capability_profile_id = repository
            .set_current_capability_profile(&capability_input(volume_id, mount_session_key))?;
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
            run_key: format!("{prefix}-run-{session_byte}"),
            scan_job_id: job_id,
            volume_id,
            capability_profile_id,
            parent_scan_run_id,
            mount_session_key,
            mount_relative_root_raw: b"DCIM".to_vec(),
            path_encoding: "utf8".into(),
            stable_root_path_key: StablePathKey::from_volume_adapter([12; 32]),
            root_scope_key: RootScopeKey::from_volume_adapter([13; 32]),
            root_object_signature: RootObjectSignature::from_volume_adapter([session_byte; 32]),
            scan_mode: if parent_scan_run_id.is_some() {
                "resume".into()
            } else {
                "full".into()
            },
            config: None,
            created_at_ms: run_created_at_ms,
        })?;
        let guard = RunEvidenceGuard {
            scan_run_id: run_id,
            capability_profile_id,
            mount_session_key,
        };
        repository.transition_bound_scan_job_and_run(
            &guard,
            job_id,
            if parent_scan_run_id.is_some() {
                "failed"
            } else {
                "queued"
            },
            if parent_scan_run_id.is_some() { 2 } else { 0 },
            "queued",
            0,
            "running",
            "running",
            run_started_at_ms,
            None,
        )?;
        Ok(RunningRun {
            volume_id,
            job_id,
            run_id,
            guard,
        })
    })
}

fn volume_input(prefix: &str) -> VolumeInput {
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
        now_ms: 100,
    }
}

fn capability_input(volume_id: i64, mount_session_key: MountSessionKey) -> CapabilityProfileInput {
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

fn observation_input(index: u8, size_bytes: i64) -> ObservationInput {
    let filename = format!("photo-{index}.jpg");
    ObservationInput {
        stable_path_key: StablePathKey::from_volume_adapter([20 + index; 32]),
        mount_relative_path_raw: format!("DCIM/{filename}").into_bytes(),
        root_relative_path_raw: filename.as_bytes().to_vec(),
        path_encoding: "utf8".into(),
        display_path: filename,
        entry_type: "regular".into(),
        media_kind: "photo".into(),
        mime_type: Some("image/jpeg".into()),
        file_extension: Some("jpg".into()),
        source_signature: SourceSignature::from_runtime_evidence([30 + index; 32]),
        stat_signature_version: 2,
        file_object_key: Some(FileObjectKey::from_runtime_evidence([60 + index; 32])),
        native_file_id: Some(vec![index + 1; 8]),
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
        observed_at_ms: 160 + i64::from(index),
    }
}

fn sample_fingerprint(
    index: usize,
    observation: &SeededObservation,
    parameters_hash: ParametersHash,
) -> FreshFingerprintInput {
    FreshFingerprintInput {
        observation_id: observation.id,
        fingerprint_kind: FreshFingerprintKind::Sample,
        algorithm: ALGORITHM.into(),
        algorithm_version: 1,
        parameters_hash,
        read_origin: FingerprintReadOrigin::SampleRead,
        source_signature_before: observation.input.source_signature,
        source_signature_after: observation.input.source_signature,
        digest: vec![40 + u8::try_from(index / 2).expect("small fixture index")],
        observed_size_bytes: observation.input.size_bytes,
        bytes_read: 4,
        reached_expected_eof: false,
        completed_at_ms: 250 + i64::try_from(index).expect("small fixture index"),
        created_at_ms: 250 + i64::try_from(index).expect("small fixture index"),
    }
}

fn exact_fingerprint(
    index: usize,
    observation: &SeededObservation,
    parameters_hash: ParametersHash,
) -> FreshFingerprintInput {
    FreshFingerprintInput {
        observation_id: observation.id,
        fingerprint_kind: FreshFingerprintKind::ExactBytes,
        algorithm: ALGORITHM.into(),
        algorithm_version: 1,
        parameters_hash,
        read_origin: FingerprintReadOrigin::FullHashRead,
        source_signature_before: observation.input.source_signature,
        source_signature_after: observation.input.source_signature,
        digest: vec![50 + u8::try_from(index / 2).expect("small fixture index")],
        observed_size_bytes: observation.input.size_bytes,
        bytes_read: observation.input.size_bytes,
        reached_expected_eof: true,
        completed_at_ms: 220 + i64::try_from(index).expect("small fixture index"),
        created_at_ms: 220 + i64::try_from(index).expect("small fixture index"),
    }
}

fn create_verified_group(
    store: &mut Store,
    run: &RunningRun,
    observations: &[SeededObservation],
    exact_ids: &[i64],
    parameters_hash: ParametersHash,
    pair_index: usize,
) -> Result<i64, StoreError> {
    let first = pair_index * 2;
    let members = exact_manifest_members(observations, exact_ids, parameters_hash, first)?;
    let leaves = members
        .iter()
        .map(compute_exact_group_member_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = compute_exact_group_manifest(&leaves)?;
    store.write_transaction(|repository| {
        let build_id = repository.begin_exact_group(
            &run.guard,
            &BeginExactGroupInput {
                build_key: BuildKey::from_runtime_evidence(
                    [100 + u8::try_from(pair_index).expect("small pair index"); 32],
                ),
                representative_observation_id: observations[first].id,
                representative_fingerprint_id: exact_ids[first],
                expected_member_count: 2,
                expected_manifest_digest: manifest,
                created_at_ms: 800 + i64::try_from(pair_index).expect("small pair index"),
            },
        )?;
        repository.append_exact_group_members(
            &run.guard,
            build_id,
            &[
                ExactGroupMemberInput {
                    ordinal: 0,
                    observation_id: observations[first].id,
                    fingerprint_id: exact_ids[first],
                    sort_rank: 0,
                },
                ExactGroupMemberInput {
                    ordinal: 1,
                    observation_id: observations[first + 1].id,
                    fingerprint_id: exact_ids[first + 1],
                    sort_rank: 1,
                },
            ],
        )?;
        repository.append_exact_verification_edges(
            &run.guard,
            build_id,
            &[ExactVerificationEdgeInput {
                member_observation_id: observations[first + 1].id,
                member_fingerprint_id: exact_ids[first + 1],
                representative_source_signature: observations[first].input.source_signature,
                member_source_signature: observations[first + 1].input.source_signature,
                compared_bytes: observations[first].input.size_bytes,
                verified_at_ms: 850 + i64::try_from(pair_index).expect("small pair index"),
            }],
        )?;
        Ok(repository
            .finalize_exact_group(
                &run.guard,
                build_id,
                900 + i64::try_from(pair_index).expect("small pair index"),
            )?
            .build_id)
    })
}

fn exact_manifest_members(
    observations: &[SeededObservation],
    exact_ids: &[i64],
    parameters_hash: ParametersHash,
    first: usize,
) -> Result<Vec<ExactGroupManifestMember>, StoreError> {
    (0..2)
        .map(|offset| {
            let index = first + offset;
            Ok(ExactGroupManifestMember {
                ordinal: u64::try_from(offset).map_err(|_| StoreError::InvalidInput {
                    field: "ordinal",
                    reason: "fixture ordinal overflow".into(),
                })?,
                observation_id: u64::try_from(observations[index].id).map_err(|_| {
                    StoreError::InvalidInput {
                        field: "observation_id",
                        reason: "fixture id overflow".into(),
                    }
                })?,
                fingerprint_id: u64::try_from(exact_ids[index]).map_err(|_| {
                    StoreError::InvalidInput {
                        field: "fingerprint_id",
                        reason: "fixture id overflow".into(),
                    }
                })?,
                sort_rank: u64::try_from(offset).map_err(|_| StoreError::InvalidInput {
                    field: "sort_rank",
                    reason: "fixture sort rank overflow".into(),
                })?,
                stable_path_key: observations[index].input.stable_path_key,
                source_signature: observations[index].input.source_signature,
                size_bytes: u64::try_from(observations[index].input.size_bytes).map_err(|_| {
                    StoreError::InvalidInput {
                        field: "size_bytes",
                        reason: "fixture size overflow".into(),
                    }
                })?,
                algorithm: ALGORITHM.into(),
                algorithm_version: 1,
                parameters_hash,
                digest: vec![50 + u8::try_from(first / 2).expect("small pair index")],
                file_object_key: observations[index].input.file_object_key,
            })
        })
        .collect()
}

fn collect_observation_ids(store: &Store, run_id: i64, limit: u32) -> Result<Vec<i64>, StoreError> {
    let mut cursor = None;
    let mut ids = Vec::new();
    loop {
        let page = store.list_observations_page(run_id, cursor.as_ref(), limit)?;
        ids.extend(page.items.into_iter().map(|record| record.id));
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(ids);
        }
    }
}

fn collect_size_buckets(
    store: &Store,
    run_id: i64,
    limit: u32,
) -> Result<Vec<(i64, i64)>, StoreError> {
    let mut cursor = None;
    let mut buckets = Vec::new();
    loop {
        let page = store.list_size_candidate_buckets_page(run_id, cursor.as_ref(), limit)?;
        buckets.extend(
            page.items
                .into_iter()
                .map(|record| (record.observed_size_bytes, record.member_count)),
        );
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(buckets);
        }
    }
}

fn collect_sample_buckets(
    store: &Store,
    run_id: i64,
    parameters_hash: ParametersHash,
    limit: u32,
) -> Result<Vec<(i64, Vec<u8>, i64)>, StoreError> {
    let mut cursor = None;
    let mut buckets = Vec::new();
    loop {
        let page = store.list_sample_candidate_buckets_page(
            run_id,
            ALGORITHM,
            1,
            &parameters_hash,
            cursor.as_ref(),
            limit,
        )?;
        buckets.extend(page.items.into_iter().map(|record| {
            (
                record.observed_size_bytes,
                record.digest,
                record.member_count,
            )
        }));
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(buckets);
        }
    }
}

fn collect_exact_buckets(
    store: &Store,
    run_id: i64,
    parameters_hash: ParametersHash,
    limit: u32,
) -> Result<Vec<(i64, Vec<u8>, i64)>, StoreError> {
    let mut cursor = None;
    let mut buckets = Vec::new();
    loop {
        let page = store.list_exact_digest_buckets_page(
            run_id,
            ALGORITHM,
            1,
            &parameters_hash,
            cursor.as_ref(),
            limit,
        )?;
        buckets.extend(page.items.into_iter().map(|record| {
            (
                record.observed_size_bytes,
                record.digest,
                record.member_count,
            )
        }));
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(buckets);
        }
    }
}

fn assert_invalid<T>(result: Result<T, StoreError>) {
    assert!(matches!(result, Err(StoreError::InvalidInput { .. })));
}
