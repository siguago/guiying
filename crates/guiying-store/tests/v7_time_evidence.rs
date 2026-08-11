use guiying_store::{
    compute_capture_time_analysis_manifest, compute_exact_group_manifest,
    compute_exact_group_member_leaf, compute_metadata_report_manifest, compute_time_lineage_key,
    compute_time_policy_context_digest, compute_time_source_key, BeginExactGroupInput,
    BeginTimeSessionInput, BuildKey, CapabilityProfileInput, CaptureTimeAnalysisManifestPlan,
    CaptureTimeAnalysisSourceInput, CaptureTimeCandidateInput, CaptureTimeConfidence,
    CaptureTimeDecision, CaptureTimeEvidenceGate, CaptureTimeEvidenceKind,
    CaptureTimeMemberAssessmentInput, CaptureTimeObservationInput,
    CaptureTimeObservationInterpretationInput, CaptureTimeRecommendationInput, CaptureWallTime,
    CoreCoverageSealDigest, CoreDirectoryManifest, CoreDirectoryObservationInput,
    CoreFileObservationInput, CoreSessionId, CoreSessionInput, CoverageOutcomeInput,
    CoverageStatus, DirectoryObjectSignature, EvidenceParserIdentity, ExactGroupManifestMember,
    ExactGroupMemberInput, ExactVerificationEdgeInput, FileObjectKey, FileTimeRelation,
    FileTimestampParts, FingerprintReadOrigin, FreshFingerprintInput, FreshFingerprintKind,
    ManifestDigest, MetadataDetectedFormat, MetadataExtractionLimitsInput,
    MetadataExtractionStatus, MetadataExtractionUsageInput, MetadataFieldInput,
    MetadataLocatorInput, MetadataReportDigest, MetadataReportManifestPlan,
    MetadataSourceRevalidationInput, MountSessionKey, NamespaceProfileInput, NamespaceProfileKey,
    NewBoundScanRun, NewScopedScanJob, NormalizedCaptureTime, ObservationInput, ParametersHash,
    RootObjectSignature, RootScopeKey, RunEvidenceGuard, ScanStage, SourceSignature, StablePathKey,
    Store, StoreError, StoredMetadataEncoding, StoredMetadataFieldKind, StoredTiffByteOrder,
    TicketSortKey, TimeDonorEligibility, TimeEvidenceManifestDigest, TimeExactFingerprintMaterial,
    TimeSessionBudget, TimeSessionKey, TimeSessionOutcome, TimeSourceKeyMaterial,
    VolumeCoverageManifest, VolumeInput,
};
use rusqlite::config::DbConfig;
use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;

const ALGORITHM: &str = "blake3";

#[derive(Debug, Clone, Copy)]
struct RunningRun {
    job_id: i64,
    run_id: i64,
    guard: RunEvidenceGuard,
}

#[test]
fn v7_full_time_evidence_pipeline_is_guarded_sealed_and_historical_only(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database_path = temporary.path().join("v7-time-evidence.sqlite3");
    let mut store = Store::open_or_create(&database_path)?;
    let run = create_running_run(&mut store, "time", 7)?;
    let core_session_id = CoreSessionId::from_runtime_evidence([70; 32]);
    let observations = [observation(0), observation(1)];
    let files = observations
        .iter()
        .enumerate()
        .map(|(index, observation)| {
            let index_u8 = u8::try_from(index).expect("two-item fixture index fits in u8");
            let index_i64 = i64::try_from(index).expect("two-item fixture index fits in i64");
            CoreFileObservationInput {
                observation: observation.clone(),
                ticket_blob: vec![80 + index_u8; 48],
                ticket_sort_key: TicketSortKey::from_core_evidence([90 + index_u8; 32]),
                ticket_created_at_ms: 180 + index_i64,
            }
        })
        .collect::<Vec<_>>();
    let directory = CoreDirectoryObservationInput {
        root_relative_path_raw: Vec::new(),
        path_encoding: "utf8".into(),
        display_path: String::new(),
        source_signature: SourceSignature::from_runtime_evidence([73; 32]),
        directory_object_signature: DirectoryObjectSignature::from_runtime_evidence([74; 32]),
        ticket_blob: vec![75; 48],
        ticket_sort_key: TicketSortKey::from_core_evidence([76; 32]),
        observed_at_ms: 182,
    };
    let observation_ids = store.write_transaction(|repository| {
        repository.bind_core_session(
            &run.guard,
            &CoreSessionInput {
                core_session_id,
                root_object_signature: RootObjectSignature::from_volume_adapter([14; 32]),
                root_source_signature: SourceSignature::from_runtime_evidence([72; 32]),
                bound_at_ms: 151,
            },
        )?;
        let ids = repository.record_core_observation_batch(&run.guard, &core_session_id, &files)?;
        repository.record_core_directory_batch(&run.guard, &core_session_id, &[directory])?;
        repository.seal_scan_stage(&run.guard, ScanStage::Enumeration, 2, 256, 200)?;
        repository.seal_scan_stage(&run.guard, ScanStage::Sampling, 0, 0, 210)?;
        Ok(ids)
    })?;
    let parameters_hash = ParametersHash::from_runtime_evidence([41; 32]);
    let fingerprints = observation_ids
        .iter()
        .enumerate()
        .map(|(index, observation_id)| {
            let index_i64 = i64::try_from(index).expect("two-item fixture index fits in i64");
            FreshFingerprintInput {
                observation_id: *observation_id,
                fingerprint_kind: FreshFingerprintKind::ExactBytes,
                algorithm: ALGORITHM.into(),
                algorithm_version: 1,
                parameters_hash,
                read_origin: FingerprintReadOrigin::FullHashRead,
                source_signature_before: observations[index].source_signature,
                source_signature_after: observations[index].source_signature,
                digest: vec![71; 32],
                observed_size_bytes: 128,
                bytes_read: 128,
                reached_expected_eof: true,
                completed_at_ms: 300 + index_i64,
                created_at_ms: 300 + index_i64,
            }
        })
        .collect::<Vec<_>>();
    let fingerprint_ids = store.write_transaction(|repository| {
        let ids = repository.record_fingerprint_fresh_batch(&run.guard, &fingerprints)?;
        repository.seal_scan_stage(&run.guard, ScanStage::FullHash, 2, 256, 400)?;
        Ok(ids)
    })?;
    let manifest_members = (0..2)
        .map(|index| {
            Ok(ExactGroupManifestMember {
                ordinal: u64::try_from(index)?,
                observation_id: u64::try_from(observation_ids[index])?,
                fingerprint_id: u64::try_from(fingerprint_ids[index])?,
                sort_rank: u64::try_from(index)?,
                stable_path_key: observations[index].stable_path_key,
                source_signature: observations[index].source_signature,
                size_bytes: 128,
                algorithm: ALGORITHM.into(),
                algorithm_version: 1,
                parameters_hash,
                digest: vec![71; 32],
                file_object_key: observations[index].file_object_key,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let leaves = manifest_members
        .iter()
        .map(compute_exact_group_member_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let exact_manifest = compute_exact_group_manifest(&leaves)?;
    let group = store.write_transaction(|repository| {
        let build_id = repository.begin_exact_group(
            &run.guard,
            &BeginExactGroupInput {
                build_key: BuildKey::from_runtime_evidence([51; 32]),
                representative_observation_id: observation_ids[0],
                representative_fingerprint_id: fingerprint_ids[0],
                expected_member_count: 2,
                expected_manifest_digest: exact_manifest,
                created_at_ms: 500,
            },
        )?;
        repository.append_exact_group_members(
            &run.guard,
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
            &run.guard,
            build_id,
            &[ExactVerificationEdgeInput {
                member_observation_id: observation_ids[1],
                member_fingerprint_id: fingerprint_ids[1],
                representative_source_signature: observations[0].source_signature,
                member_source_signature: observations[1].source_signature,
                compared_bytes: 128,
                verified_at_ms: 600,
            }],
        )?;
        let group = repository.finalize_exact_group(&run.guard, build_id, 700)?;
        repository.record_core_coverage(
            &run.guard,
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
                finalized_at_ms: 705,
            },
        )?;
        repository.seal_scan_stage(&run.guard, ScanStage::ExactVerification, 1, 128, 710)?;
        Ok(group)
    })?;

    let preterminal_summary = store.verified_time_scope_summary(&run.guard, &core_session_id)?;
    assert_eq!(preterminal_summary.expected_group_count, 1);
    assert!(matches!(
        store.time_evidence_guard(run.guard, core_session_id),
        Err(StoreError::ConcurrencyConflict { .. })
    ));
    store.write_transaction(|repository| {
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
        Ok(())
    })?;
    let time_guard = store.time_evidence_guard(run.guard, core_session_id)?;
    assert_eq!(
        store.verified_time_scope_summary_for_time(&time_guard)?,
        preterminal_summary
    );
    let probe_page = store.list_verified_time_probe_scopes_page(&time_guard, None, 1)?;
    assert_eq!(probe_page.items.len(), 1);
    assert_eq!(probe_page.items[0].probes.len(), 2);
    assert_eq!(probe_page.items[0].group, group);
    assert!(matches!(
        store.list_verified_time_probe_scopes_page(&time_guard, None, 257),
        Err(StoreError::InvalidInput { .. })
    ));

    let budget = TimeSessionBudget::new(1_024, 2, 128, 16, 128, 8, 8)?;
    let begin_session = BeginTimeSessionInput::new(
        TimeSessionKey::from_runtime_evidence([100; 32]),
        preterminal_summary.expected_group_count,
        budget,
        preterminal_summary.expected_manifest_digest,
        900,
    )?;
    let wrong_session = BeginTimeSessionInput::new(
        TimeSessionKey::from_runtime_evidence([100; 32]),
        1,
        budget,
        TimeEvidenceManifestDigest::from_runtime_evidence([255; 32]),
        900,
    )?;
    let poison = store.write_transaction(|repository| {
        assert!(matches!(
            repository.begin_time_session(&time_guard, &wrong_session),
            Err(StoreError::InvalidInput { .. })
        ));
        repository.begin_time_session(&time_guard, &begin_session)?;
        Ok(())
    });
    assert!(matches!(poison, Err(StoreError::WriteTransactionPoisoned)));
    let time_session_id = store.write_transaction(|repository| {
        let id = repository.begin_time_session(&time_guard, &begin_session)?;
        assert_eq!(
            repository.begin_time_session(&time_guard, &begin_session)?,
            id
        );
        Ok(id)
    })?;

    let probe = &probe_page.items[0].probes[0];
    let exact_material =
        TimeExactFingerprintMaterial::new(ALGORITHM, 1, parameters_hash, 128, vec![71; 32])?;
    let source_material = TimeSourceKeyMaterial::new(
        1,
        run.run_id,
        core_session_id,
        run.guard.mount_session_key,
        RootScopeKey::from_volume_adapter([13; 32]),
        StablePathKey::from_volume_adapter([12; 32]),
        RootObjectSignature::from_volume_adapter([14; 32]),
        probe.ticket.stable_path_key,
        probe.ticket.source_signature,
        probe.ticket.observation_id,
        probe.fingerprint_id,
        group.group_key,
        group.manifest_digest,
        exact_material.clone(),
    )?;
    let source_key = compute_time_source_key(&source_material);
    let lineage_key = compute_time_lineage_key(&exact_material);
    let retained_report_digest = MetadataReportDigest::from_runtime_evidence([110; 32]);
    let revalidation = MetadataSourceRevalidationInput::reextracted_pinned_exact(
        source_key,
        lineage_key,
        probe.ticket.source_signature,
        probe.ticket.source_signature,
        retained_report_digest,
        retained_report_digest,
        920,
    )?;
    let premature_revalidation = MetadataSourceRevalidationInput::reextracted_pinned_exact(
        source_key,
        lineage_key,
        probe.ticket.source_signature,
        probe.ticket.source_signature,
        retained_report_digest,
        retained_report_digest,
        910,
    )?;
    let raw_field = b"2020:01:02 03:04:05".to_vec();
    let raw_offset = b"+00:00".to_vec();
    let raw_subsecond = b"123".to_vec();
    let field = MetadataFieldInput::new(
        0,
        EvidenceParserIdentity::new("guiying-metadata", "1")?,
        StoredMetadataFieldKind::ExifDateTimeOriginal,
        StoredMetadataEncoding::DeclaredAscii,
        MetadataLocatorInput::jpeg_exif(
            0,
            i64::try_from(raw_field.len())?,
            0,
            0,
            0,
            0x9003,
            StoredTiffByteOrder::LittleEndian,
        )?,
        raw_field.clone(),
        MetadataReportDigest::from_runtime_evidence(*blake3::hash(&raw_field).as_bytes()),
        911,
    )?;
    let offset_field = MetadataFieldInput::new(
        1,
        EvidenceParserIdentity::new("guiying-metadata", "1")?,
        StoredMetadataFieldKind::ExifOffsetTimeOriginal,
        StoredMetadataEncoding::DeclaredAscii,
        MetadataLocatorInput::jpeg_exif(
            32,
            i64::try_from(raw_offset.len())?,
            0,
            0,
            0,
            0x9011,
            StoredTiffByteOrder::LittleEndian,
        )?,
        raw_offset.clone(),
        MetadataReportDigest::from_runtime_evidence(*blake3::hash(&raw_offset).as_bytes()),
        911,
    )?;
    let subsecond_field = MetadataFieldInput::new(
        2,
        EvidenceParserIdentity::new("guiying-metadata", "1")?,
        StoredMetadataFieldKind::ExifSubSecTimeOriginal,
        StoredMetadataEncoding::DeclaredAscii,
        MetadataLocatorInput::jpeg_exif(
            40,
            i64::try_from(raw_subsecond.len())?,
            0,
            0,
            0,
            0x9291,
            StoredTiffByteOrder::LittleEndian,
        )?,
        raw_subsecond.clone(),
        MetadataReportDigest::from_runtime_evidence(*blake3::hash(&raw_subsecond).as_bytes()),
        911,
    )?;
    let create_date_field = MetadataFieldInput::new(
        3,
        EvidenceParserIdentity::new("guiying-metadata", "1")?,
        StoredMetadataFieldKind::ExifCreateDate,
        StoredMetadataEncoding::DeclaredAscii,
        MetadataLocatorInput::jpeg_exif(
            48,
            i64::try_from(raw_field.len())?,
            0,
            0,
            0,
            0x9004,
            StoredTiffByteOrder::LittleEndian,
        )?,
        raw_field.clone(),
        MetadataReportDigest::from_runtime_evidence(*blake3::hash(&raw_field).as_bytes()),
        911,
    )?;
    let other_ifd_offset_field = MetadataFieldInput::new(
        4,
        EvidenceParserIdentity::new("guiying-metadata", "1")?,
        StoredMetadataFieldKind::ExifOffsetTimeOriginal,
        StoredMetadataEncoding::DeclaredAscii,
        MetadataLocatorInput::jpeg_exif(
            80,
            i64::try_from(raw_offset.len())?,
            0,
            0,
            64,
            0x9011,
            StoredTiffByteOrder::LittleEndian,
        )?,
        raw_offset.clone(),
        MetadataReportDigest::from_runtime_evidence(*blake3::hash(&raw_offset).as_bytes()),
        911,
    )?;
    let report_fields = [
        field.clone(),
        offset_field.clone(),
        subsecond_field.clone(),
        create_date_field.clone(),
        other_ifd_offset_field.clone(),
    ];
    let retained_field_bytes =
        i64::try_from(raw_field.len() * 2 + raw_offset.len() * 2 + raw_subsecond.len())?;
    let report_plan = MetadataReportManifestPlan::new(
        &time_guard,
        time_session_id,
        group.build_id,
        probe.ticket.observation_id,
        probe.fingerprint_id,
        0,
        128,
        EvidenceParserIdentity::new("guiying-metadata", "1")?,
        Some(MetadataDetectedFormat::Jpeg),
        MetadataExtractionStatus::ExtractedUnvalidated,
        MetadataExtractionLimitsInput::new(128, 16, 128, 64, 8, 8, 8, 4, 8, 4)?,
        MetadataExtractionUsageInput::new(128, 2, retained_field_bytes, 5, 1, 5, 0, 1)?,
        5,
        0,
        retained_field_bytes,
        retained_report_digest,
        910,
    )?;
    let report_manifest =
        compute_metadata_report_manifest(&report_plan, &report_fields, &[], &revalidation)?;
    let begin_report = report_plan.into_begin_input(report_manifest);
    let (report_id, field_ids) = store.write_transaction(|repository| {
        let report_id = repository.begin_metadata_report(&time_guard, &begin_report)?;
        assert_eq!(
            repository.begin_metadata_report(&time_guard, &begin_report)?,
            report_id
        );
        let field_ids =
            repository.append_metadata_fields_batch(&time_guard, report_id, &report_fields)?;
        assert_eq!(
            repository.append_metadata_fields_batch(&time_guard, report_id, &report_fields)?,
            field_ids
        );
        Ok((report_id, field_ids))
    })?;
    let conflicting_begin_report = MetadataReportManifestPlan::new(
        &time_guard,
        time_session_id,
        group.build_id,
        probe.ticket.observation_id,
        probe.fingerprint_id,
        0,
        128,
        EvidenceParserIdentity::new("guiying-metadata", "different-version")?,
        Some(MetadataDetectedFormat::Jpeg),
        MetadataExtractionStatus::ExtractedUnvalidated,
        MetadataExtractionLimitsInput::new(128, 16, 128, 64, 8, 8, 8, 4, 8, 4)?,
        MetadataExtractionUsageInput::new(128, 2, retained_field_bytes, 5, 1, 5, 0, 1)?,
        5,
        0,
        retained_field_bytes,
        retained_report_digest,
        910,
    )?
    .into_begin_input(report_manifest);
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.begin_metadata_report(&time_guard, &conflicting_begin_report)?;
            Ok(())
        }),
        Err(StoreError::IdempotencyConflict { .. })
    ));
    let direct_report_connection = Connection::open(&database_path)?;
    assert!(direct_report_connection
        .execute(
            "UPDATE metadata_extraction_reports \
             SET state = 'abandoned', abandon_reason_code = 'premature', \
                 finalized_at_ms = 910 WHERE id = ?1",
            [report_id],
        )
        .is_err());
    direct_report_connection
        .close()
        .map_err(|(_, error)| error)?;
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.seal_metadata_report(
                &time_guard,
                report_id,
                &premature_revalidation,
                930,
            )?;
            Ok(())
        }),
        Err(StoreError::InvalidInput { .. })
    ));
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.seal_metadata_report(&time_guard, report_id, &revalidation, 919)?;
            Ok(())
        }),
        Err(StoreError::InvalidInput { .. })
    ));
    store.write_transaction(|repository| {
        assert_eq!(
            repository.seal_metadata_report(&time_guard, report_id, &revalidation, 930)?,
            report_manifest
        );
        assert_eq!(
            repository.seal_metadata_report(&time_guard, report_id, &revalidation, 930)?,
            report_manifest
        );
        Ok(())
    })?;

    let source = CaptureTimeAnalysisSourceInput::reextracted_pinned_source(
        0,
        report_id,
        source_key,
        lineage_key,
        941,
    )?;
    let source_wall = CaptureWallTime::new(2020, 1, 2, 3, 4, 5, 0)?;
    let candidate_wall = CaptureWallTime::new(2020, 1, 2, 3, 4, 5, 123_000_000)?;
    let observations =
        [
            CaptureTimeObservationInput::new(
                0,
                0,
                field_ids[0],
                CaptureTimeObservationInterpretationInput::Timestamp(
                    NormalizedCaptureTime::floating(source_wall, 1_000_000_000)?,
                ),
                942,
            )?,
            CaptureTimeObservationInput::new(
                1,
                0,
                field_ids[1],
                CaptureTimeObservationInterpretationInput::offset(0)?,
                942,
            )?,
            CaptureTimeObservationInput::new(
                2,
                0,
                field_ids[2],
                CaptureTimeObservationInterpretationInput::subsecond(123_000_000, 3, 1_000_000)?,
                942,
            )?,
            CaptureTimeObservationInput::new(
                3,
                0,
                field_ids[3],
                CaptureTimeObservationInterpretationInput::Timestamp(
                    NormalizedCaptureTime::floating(source_wall, 1_000_000_000)?,
                ),
                942,
            )?,
            CaptureTimeObservationInput::new(
                4,
                0,
                field_ids[4],
                CaptureTimeObservationInterpretationInput::offset(0)?,
                942,
            )?,
        ];
    let candidate = CaptureTimeCandidateInput::new(
        0,
        NormalizedCaptureTime::explicit_utc(
            candidate_wall,
            0,
            "1577934245",
            123_000_000,
            1_000_000,
        )?,
        CaptureTimeConfidence::High,
        CaptureTimeEvidenceGate::eligible(),
        vec![CaptureTimeEvidenceKind::ExifDateTimeOriginal],
        vec![source_key],
        vec![lineage_key],
        vec![0, 1, 2],
        Vec::new(),
        943,
    )?;
    let borrowed_create_date_candidate = CaptureTimeCandidateInput::new(
        0,
        NormalizedCaptureTime::explicit_utc(
            candidate_wall,
            0,
            "1577934245",
            123_000_000,
            1_000_000,
        )?,
        CaptureTimeConfidence::High,
        CaptureTimeEvidenceGate::eligible(),
        vec![
            CaptureTimeEvidenceKind::ExifDateTimeOriginal,
            CaptureTimeEvidenceKind::ExifCreateDate,
        ],
        vec![source_key],
        vec![lineage_key],
        vec![0, 1, 2, 3],
        Vec::new(),
        943,
    )?;
    let wrong_ifd_companion_candidate = CaptureTimeCandidateInput::new(
        0,
        NormalizedCaptureTime::explicit_utc(
            candidate_wall,
            0,
            "1577934245",
            123_000_000,
            1_000_000,
        )?,
        CaptureTimeConfidence::High,
        CaptureTimeEvidenceGate::eligible(),
        vec![CaptureTimeEvidenceKind::ExifDateTimeOriginal],
        vec![source_key],
        vec![lineage_key],
        vec![0, 2, 4],
        Vec::new(),
        943,
    )?;
    assert!(matches!(
        CaptureTimeCandidateInput::new(
            0,
            NormalizedCaptureTime::explicit_utc(source_wall, 0, "1577934245", 0, 1_000_000_000,)?,
            CaptureTimeConfidence::High,
            CaptureTimeEvidenceGate::eligible(),
            vec![CaptureTimeEvidenceKind::ExifCreateDate],
            vec![source_key],
            vec![lineage_key],
            vec![3],
            Vec::new(),
            943,
        ),
        Err(StoreError::InvalidInput { .. })
    ));
    assert!(matches!(
        CaptureTimeCandidateInput::new(
            0,
            NormalizedCaptureTime::quicktime_epoch_assumed_utc(
                source_wall,
                "1577934245",
                0,
                1_000_000_000,
            )?,
            CaptureTimeConfidence::High,
            CaptureTimeEvidenceGate::eligible(),
            vec![CaptureTimeEvidenceKind::QuickTimeMetadataCreationDate],
            vec![source_key],
            vec![lineage_key],
            vec![3],
            Vec::new(),
            943,
        ),
        Err(StoreError::InvalidInput { .. })
    ));
    let unsupported_future_candidate = CaptureTimeCandidateInput::new(
        0,
        NormalizedCaptureTime::explicit_utc(
            CaptureWallTime::new(2035, 1, 2, 3, 4, 5, 0)?,
            0,
            "2051319845",
            0,
            1_000_000_000,
        )?,
        CaptureTimeConfidence::High,
        CaptureTimeEvidenceGate::eligible(),
        vec![CaptureTimeEvidenceKind::ExifDateTimeOriginal],
        vec![source_key],
        vec![lineage_key],
        vec![0, 1, 2],
        Vec::new(),
        943,
    )?;
    let members = observation_ids
        .iter()
        .enumerate()
        .map(|(ordinal, observation_id)| {
            CaptureTimeMemberAssessmentInput::new(
                i64::try_from(ordinal)?,
                *observation_id,
                Some(0),
                FileTimeRelation::Unavailable,
                FileTimeRelation::Differs,
                TimeDonorEligibility::Ineligible,
                "embedded_time_differs_fs",
                944,
            )
            .map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let false_matches = observation_ids
        .iter()
        .enumerate()
        .map(|(ordinal, observation_id)| {
            CaptureTimeMemberAssessmentInput::new(
                i64::try_from(ordinal)?,
                *observation_id,
                Some(0),
                FileTimeRelation::Unavailable,
                FileTimeRelation::Matches,
                TimeDonorEligibility::Ineligible,
                "embedded_time_matches_fs",
                944,
            )
            .map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let recommendation =
        CaptureTimeRecommendationInput::without_keeper_policy("keeper_policy_unavailable", 945)?;
    let policy_context = json!({"sentinel_rules": [], "timezone": "explicit_only"});
    let policy_digest = compute_time_policy_context_digest(&policy_context)?;
    let analysis_plan = CaptureTimeAnalysisManifestPlan::new(
        &time_guard,
        time_session_id,
        group.build_id,
        "capture-time-v1",
        "1",
        policy_context,
        policy_digest,
        1,
        5,
        1,
        0,
        2,
        1,
        940,
    )?;
    let analysis_manifest = compute_capture_time_analysis_manifest(
        &analysis_plan,
        std::slice::from_ref(&source),
        &observations,
        std::slice::from_ref(&candidate),
        &[],
        &members,
        &recommendation,
    )?;
    let begin_analysis = analysis_plan.into_begin_input(analysis_manifest);
    let analysis_id = store.write_transaction(|repository| {
        let analysis_id = repository.begin_capture_time_analysis(&time_guard, &begin_analysis)?;
        assert_eq!(
            repository.begin_capture_time_analysis(&time_guard, &begin_analysis)?,
            analysis_id
        );
        repository.append_capture_time_sources_batch(
            &time_guard,
            analysis_id,
            std::slice::from_ref(&source),
        )?;
        repository.append_capture_time_sources_batch(
            &time_guard,
            analysis_id,
            std::slice::from_ref(&source),
        )?;
        let observation_ids = repository.append_capture_time_observations_batch(
            &time_guard,
            analysis_id,
            &observations,
        )?;
        assert_eq!(
            repository.append_capture_time_observations_batch(
                &time_guard,
                analysis_id,
                &observations,
            )?,
            observation_ids
        );
        Ok(analysis_id)
    })?;
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.append_capture_time_candidates_batch(
                &time_guard,
                analysis_id,
                std::slice::from_ref(&unsupported_future_candidate),
            )?;
            Ok(())
        }),
        Err(StoreError::InvalidInput { .. })
    ));
    for unsupported in [
        borrowed_create_date_candidate,
        wrong_ifd_companion_candidate,
    ] {
        assert!(matches!(
            store.write_transaction(|repository| {
                repository.append_capture_time_candidates_batch(
                    &time_guard,
                    analysis_id,
                    std::slice::from_ref(&unsupported),
                )?;
                Ok(())
            }),
            Err(StoreError::InvalidInput { .. })
        ));
    }
    let direct_candidate_connection = Connection::open(&database_path)?;
    let source_keys_json = serde_json::to_string(&[hex32(source_key.into_bytes())])?;
    let lineage_keys_json = serde_json::to_string(&[hex32(lineage_key.into_bytes())])?;
    for (evidence_kinds_json, observation_ordinals_json) in [
        (r#"["exif_date_time_original"]"#, "[0,2,4]"),
        (r#"["exif_create_date"]"#, "[1,2,3]"),
    ] {
        let direct_insert = direct_candidate_connection.execute(
            "INSERT INTO capture_time_candidates ( \
                 analysis_build_id, ordinal, wall_year, wall_month, wall_day, wall_hour, \
                 wall_minute, wall_second, wall_nanosecond, semantic_kind, offset_kind, \
                 utc_offset_minutes, utc_seconds_decimal, utc_nanoseconds, precision_ns, \
                 confidence, evidence_gate, evidence_kinds_json, source_keys_json, \
                 lineage_keys_json, observation_ordinals_json, anomalies_json, blockers_json, \
                 created_at_ms \
             ) VALUES ( \
                 ?1, 0, 2020, 1, 2, 3, 4, 5, 123000000, 'utc', 'explicit', \
                 0, '1577934245', 123000000, 1000000, 'high', 'eligible', \
                 ?2, ?3, ?4, ?5, '[]', '[]', 943 \
             )",
            rusqlite::params![
                analysis_id,
                evidence_kinds_json,
                source_keys_json,
                lineage_keys_json,
                observation_ordinals_json,
            ],
        );
        assert!(
            direct_insert.is_err(),
            "direct SQL accepted a cross-scope or non-original eligible candidate"
        );
    }
    direct_candidate_connection
        .close()
        .map_err(|(_, error)| error)?;
    store.write_transaction(|repository| {
        let candidate_id = repository.append_capture_time_candidates_batch(
            &time_guard,
            analysis_id,
            std::slice::from_ref(&candidate),
        )?[0];
        assert_eq!(
            repository.append_capture_time_candidates_batch(
                &time_guard,
                analysis_id,
                std::slice::from_ref(&candidate),
            )?[0],
            candidate_id
        );
        Ok(())
    })?;
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.append_capture_time_members_batch(
                &time_guard,
                analysis_id,
                &false_matches,
            )?;
            Ok(())
        }),
        Err(StoreError::InvalidInput { .. })
    ));
    store.write_transaction(|repository| {
        repository.append_capture_time_members_batch(&time_guard, analysis_id, &members)?;
        repository.append_capture_time_members_batch(&time_guard, analysis_id, &members)?;
        repository.append_capture_time_recommendation(&time_guard, analysis_id, &recommendation)?;
        repository.append_capture_time_recommendation(&time_guard, analysis_id, &recommendation)?;
        Ok(())
    })?;
    let direct_analysis_connection = Connection::open(&database_path)?;
    assert!(direct_analysis_connection
        .execute(
            "UPDATE capture_time_analysis_builds \
             SET state = 'abandoned', abandon_reason_code = 'premature', \
                 finalized_at_ms = 944 WHERE id = ?1",
            [analysis_id],
        )
        .is_err());
    direct_analysis_connection
        .close()
        .map_err(|(_, error)| error)?;
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.abandon_capture_time_analysis(
                &time_guard,
                analysis_id,
                944,
                "premature_abandonment",
                None,
            )?;
            Ok(())
        }),
        Err(StoreError::InvalidInput { .. })
    ));
    store.write_transaction(|repository| {
        assert_eq!(
            repository.seal_capture_time_analysis(
                &time_guard,
                analysis_id,
                CaptureTimeDecision::EvidenceEligible,
                Some(0),
                951,
            )?,
            analysis_manifest
        );
        assert_eq!(
            repository.seal_capture_time_analysis(
                &time_guard,
                analysis_id,
                CaptureTimeDecision::EvidenceEligible,
                Some(0),
                951,
            )?,
            analysis_manifest
        );
        Ok(())
    })?;
    let direct_session_connection = Connection::open(&database_path)?;
    assert!(direct_session_connection
        .execute(
            "UPDATE scan_time_sessions \
             SET state = 'abandoned', abandon_reason_code = 'premature', \
                 finalized_at_ms = 950 WHERE id = ?1",
            [time_session_id],
        )
        .is_err());
    direct_session_connection
        .close()
        .map_err(|(_, error)| error)?;
    assert!(matches!(
        store.write_transaction(|repository| {
            repository.finalize_time_session(
                &time_guard,
                time_session_id,
                TimeSessionOutcome::Complete,
                950,
            )?;
            Ok(())
        }),
        Err(StoreError::InvalidInput { .. })
    ));
    assert!(store
        .get_capture_time_group_summary(run.run_id, group.build_id)?
        .is_none());
    let outcome_manifest = store.write_transaction(|repository| {
        let digest = repository.finalize_time_session(
            &time_guard,
            time_session_id,
            TimeSessionOutcome::Complete,
            960,
        )?;
        assert_eq!(
            repository.finalize_time_session(
                &time_guard,
                time_session_id,
                TimeSessionOutcome::Complete,
                960,
            )?,
            digest
        );
        Ok(digest)
    })?;
    assert_ne!(
        outcome_manifest,
        preterminal_summary.expected_manifest_digest
    );

    let summaries = store.list_capture_time_group_summaries_page(run.run_id, None, 10)?;
    assert_eq!(summaries.items.len(), 1);
    assert_eq!(summaries.items[0].analysis_build_id, analysis_id);
    assert!(!summaries.items[0].write_authorized);
    assert!(summaries.items[0].evidence_only);
    assert!(summaries.items[0].keeper_observation_id.is_none());
    let point_summary = store
        .get_capture_time_group_summary(run.run_id, group.build_id)?
        .expect("sealed terminal summary");
    assert_eq!(point_summary.analysis_build_id, analysis_id);
    assert_eq!(point_summary.exact_group_build_id, group.build_id);
    assert!(!point_summary.write_authorized);
    assert!(point_summary.evidence_only);
    assert!(store
        .get_capture_time_group_summary(run.run_id + 1_000, group.build_id)?
        .is_none());
    assert!(store
        .get_capture_time_group_summary(run.run_id, group.build_id + 1_000)?
        .is_none());
    assert_eq!(
        store
            .list_capture_time_candidates_page(run.run_id, group.build_id, analysis_id, None, 10)?
            .items
            .len(),
        1
    );
    let first_member =
        store.list_capture_time_members_page(run.run_id, group.build_id, analysis_id, None, 1)?;
    assert_eq!(first_member.items.len(), 1);
    let second_member = store.list_capture_time_members_page(
        run.run_id,
        group.build_id,
        analysis_id,
        first_member.next_cursor.as_ref(),
        1,
    )?;
    assert_eq!(second_member.items.len(), 1);
    assert!(store
        .list_capture_time_issues_page(run.run_id, group.build_id, analysis_id, None, 10)?
        .items
        .is_empty());

    let old_guard = time_guard;
    store.close()?;
    let reopened = Store::open_existing(&database_path)?;
    assert!(matches!(
        reopened.list_verified_time_probe_scopes_page(&old_guard, None, 1),
        Err(StoreError::ConcurrencyConflict { .. })
    ));
    assert!(matches!(
        reopened.time_evidence_guard(run.guard, core_session_id),
        Err(StoreError::ConcurrencyConflict { .. })
    ));
    assert_eq!(
        reopened
            .list_capture_time_group_summaries_page(run.run_id, None, 10)?
            .items
            .len(),
        1
    );
    assert!(reopened
        .get_capture_time_group_summary(run.run_id, group.build_id)?
        .is_some());
    reopened.close()?;

    let decision_tamper_path = temporary.path().join("v7-decision-tamper.sqlite3");
    std::fs::copy(&database_path, &decision_tamper_path)?;
    let decision_connection = Connection::open(&decision_tamper_path)?;
    decision_connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    decision_connection.execute(
        "UPDATE capture_time_analysis_builds \
         SET decision = 'no_usable_evidence', selected_candidate_ordinal = NULL \
         WHERE id = ?1",
        [analysis_id],
    )?;
    decision_connection.close().map_err(|(_, error)| error)?;
    assert!(matches!(
        Store::open_existing(&decision_tamper_path),
        Err(StoreError::MigrationHistoryMismatch(_))
    ));

    let candidate_support_tamper_path =
        temporary.path().join("v7-candidate-support-tamper.sqlite3");
    std::fs::copy(&database_path, &candidate_support_tamper_path)?;
    let candidate_support_connection = Connection::open(&candidate_support_tamper_path)?;
    candidate_support_connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    candidate_support_connection.execute(
        "UPDATE capture_time_candidates \
         SET observation_ordinals_json = '[0,2,4]' \
         WHERE analysis_build_id = ?1 AND ordinal = 0",
        [analysis_id],
    )?;
    candidate_support_connection
        .close()
        .map_err(|(_, error)| error)?;
    assert!(matches!(
        Store::open_existing(&candidate_support_tamper_path),
        Err(StoreError::MigrationHistoryMismatch(_))
    ));

    let filesystem_tamper_path = temporary.path().join("v7-filesystem-time-tamper.sqlite3");
    std::fs::copy(&database_path, &filesystem_tamper_path)?;
    let filesystem_connection = Connection::open(&filesystem_tamper_path)?;
    filesystem_connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    filesystem_connection.execute(
        "UPDATE media_observation_snapshots \
         SET modified_time_seconds = modified_time_seconds + 1 WHERE id = ?1",
        [observation_ids[0]],
    )?;
    filesystem_connection.close().map_err(|(_, error)| error)?;
    assert!(matches!(
        Store::open_existing(&filesystem_tamper_path),
        Err(StoreError::MigrationHistoryMismatch(_))
    ));

    let session_state_tamper_path = temporary.path().join("v7-session-state-tamper.sqlite3");
    std::fs::copy(&database_path, &session_state_tamper_path)?;
    let session_state_connection = Connection::open(&session_state_tamper_path)?;
    session_state_connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    session_state_connection.execute(
        "UPDATE scan_time_sessions SET state = 'partial' WHERE id = ?1",
        [time_session_id],
    )?;
    session_state_connection
        .close()
        .map_err(|(_, error)| error)?;
    assert!(matches!(
        Store::open_existing(&session_state_tamper_path),
        Err(StoreError::MigrationHistoryMismatch(_))
    ));

    let session_time_tamper_path = temporary.path().join("v7-session-time-tamper.sqlite3");
    std::fs::copy(&database_path, &session_time_tamper_path)?;
    let session_time_connection = Connection::open(&session_time_tamper_path)?;
    session_time_connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    session_time_connection.execute(
        "UPDATE scan_time_sessions SET finalized_at_ms = finalized_at_ms + 1 WHERE id = ?1",
        [time_session_id],
    )?;
    session_time_connection
        .close()
        .map_err(|(_, error)| error)?;
    assert!(matches!(
        Store::open_existing(&session_time_tamper_path),
        Err(StoreError::MigrationHistoryMismatch(_))
    ));

    let outcome_time_tamper_path = temporary.path().join("v7-outcome-time-tamper.sqlite3");
    std::fs::copy(&database_path, &outcome_time_tamper_path)?;
    let outcome_time_connection = Connection::open(&outcome_time_tamper_path)?;
    outcome_time_connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    outcome_time_connection.execute(
        "UPDATE capture_time_group_outcomes SET created_at_ms = 950 \
         WHERE time_session_id = ?1 AND analysis_build_id = ?2",
        rusqlite::params![time_session_id, analysis_id],
    )?;
    outcome_time_connection
        .close()
        .map_err(|(_, error)| error)?;
    assert!(matches!(
        Store::open_existing(&outcome_time_tamper_path),
        Err(StoreError::MigrationHistoryMismatch(_))
    ));

    let session_start_tamper_path = temporary.path().join("v7-session-start-tamper.sqlite3");
    std::fs::copy(&database_path, &session_start_tamper_path)?;
    let session_start_connection = Connection::open(&session_start_tamper_path)?;
    session_start_connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    session_start_connection.execute(
        "UPDATE scan_time_sessions SET created_at_ms = 0 WHERE id = ?1",
        [time_session_id],
    )?;
    session_start_connection
        .close()
        .map_err(|(_, error)| error)?;
    assert!(matches!(
        Store::open_existing(&session_start_tamper_path),
        Err(StoreError::MigrationHistoryMismatch(_))
    ));

    let connection = Connection::open(&database_path)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    connection.execute(
        "UPDATE metadata_extraction_reports SET finalized_at_ms = 910 WHERE id = ?1",
        [report_id],
    )?;
    connection.close().map_err(|(_, error)| error)?;
    let tampered_reopen = Store::open_existing(&database_path);
    assert!(
        matches!(
            &tampered_reopen,
            Err(StoreError::MigrationHistoryMismatch(_))
        ),
        "unexpected tamper result: {:?}",
        tampered_reopen.as_ref().err()
    );
    Ok(())
}

#[test]
fn v7_source_v2_and_lineage_v1_domains_are_stable_and_separated(
) -> Result<(), Box<dyn std::error::Error>> {
    let exact = TimeExactFingerprintMaterial::new(
        "blake3",
        1,
        ParametersHash::from_runtime_evidence([1; 32]),
        123,
        vec![2; 32],
    )?;
    let first = TimeSourceKeyMaterial::new(
        1,
        7,
        CoreSessionId::from_runtime_evidence([3; 32]),
        MountSessionKey::from_runtime_evidence([4; 32]),
        RootScopeKey::from_volume_adapter([5; 32]),
        StablePathKey::from_volume_adapter([6; 32]),
        RootObjectSignature::from_volume_adapter([7; 32]),
        StablePathKey::from_volume_adapter([8; 32]),
        SourceSignature::from_runtime_evidence([9; 32]),
        10,
        11,
        guiying_store::ExactGroupKey::from_runtime_evidence([12; 32]),
        ManifestDigest::from_runtime_evidence([13; 32]),
        exact.clone(),
    )?;
    let second = TimeSourceKeyMaterial::new(
        1,
        8,
        CoreSessionId::from_runtime_evidence([14; 32]),
        MountSessionKey::from_runtime_evidence([15; 32]),
        RootScopeKey::from_volume_adapter([16; 32]),
        StablePathKey::from_volume_adapter([17; 32]),
        RootObjectSignature::from_volume_adapter([18; 32]),
        StablePathKey::from_volume_adapter([19; 32]),
        SourceSignature::from_runtime_evidence([20; 32]),
        21,
        22,
        guiying_store::ExactGroupKey::from_runtime_evidence([23; 32]),
        ManifestDigest::from_runtime_evidence([24; 32]),
        exact.clone(),
    )?;
    assert_ne!(
        compute_time_source_key(&first),
        compute_time_source_key(&second)
    );
    assert_eq!(
        compute_time_lineage_key(&exact),
        compute_time_lineage_key(&exact)
    );
    let changed = TimeExactFingerprintMaterial::new(
        "blake3",
        1,
        ParametersHash::from_runtime_evidence([1; 32]),
        123,
        vec![3; 32],
    )?;
    assert_ne!(
        compute_time_lineage_key(&exact),
        compute_time_lineage_key(&changed)
    );
    assert_eq!(
        hex32(compute_time_source_key(&first).into_bytes()),
        "486b082d392f69e061965d9469c24cc4c228c09a0c5579d558bbebf6e71b5b67"
    );
    assert_eq!(
        hex32(compute_time_lineage_key(&exact).into_bytes()),
        "32c5d1db049d194900e9403d6635b65f56b8d76c0cff235653f3eb42a37a6b28"
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
        Ok(RunningRun {
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

fn observation(index: u8) -> ObservationInput {
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
        file_object_key: Some(FileObjectKey::from_runtime_evidence([40 + index; 32])),
        native_file_id: Some(vec![index; 8]),
        native_file_generation: Some(1),
        file_mode: 0o100_644,
        size_bytes: 128,
        allocated_bytes: Some(128),
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
        timestamp_granularity_ns: Some(1),
        observed_at_ms: 160 + i64::from(index),
    }
}

fn hex32(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
