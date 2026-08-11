use guiying_store::{
    MetadataFieldCursor, MetadataFieldRawLocator, MetadataReportCursor, Store, StoreError,
};
use rusqlite::config::DbConfig;
use rusqlite::{named_params, params, Connection, Transaction};
use serde_json::json;
use tempfile::TempDir;

const SCAN_RUN_ID: i64 = 10;
const GROUP_ID: i64 = 20;
const ANALYSIS_ID: i64 = 100;
const SESSION_ID: i64 = 30;
const REPORT_ID: i64 = 200;
const DRAFT_REPORT_ID: i64 = 201;
const NON_EVIDENCE_SCAN_RUN_ID: i64 = 11;
const NON_EVIDENCE_GROUP_ID: i64 = 21;
const NON_EVIDENCE_ANALYSIS_ID: i64 = 101;
const NON_EVIDENCE_SESSION_ID: i64 = 31;
const NON_EVIDENCE_REPORT_ID: i64 = 202;
const SMALL_FIELD_ID: i64 = 300;
const LARGE_FIELD_ID: i64 = 301;
const BMFF_FIELD_ID: i64 = 302;

#[test]
fn sealed_metadata_review_is_scoped_bounded_and_lossless() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let database_path = temporary.path().join("v7-metadata-read.sqlite3");
    let store = Store::open_or_create(&database_path)?;
    seed_read_fixture(&database_path)?;

    assert_eq!(
        store.schema_version()?,
        9,
        "capture-time read APIs must remain available on the latest schema"
    );

    let reports = store.list_capture_time_metadata_reports_page(
        SCAN_RUN_ID,
        GROUP_ID,
        ANALYSIS_ID,
        None,
        32,
    )?;
    assert_eq!(reports.items.len(), 1);
    let report = &reports.items[0];
    assert_eq!(report.report_id, REPORT_ID);
    assert_eq!(report.source_ordinal, 0);
    assert!(report.double_extraction_consistent);
    assert!(report.descriptor_revalidated);
    assert!(report.path_revalidated);
    assert!(report.session_revalidated);
    assert!(report.evidence_only);
    assert!(!report.write_authorized);
    let report_json = serde_json::to_value(report)?;
    let report_object = report_json
        .as_object()
        .expect("report serializes as an object");
    for forbidden in [
        "raw_bytes",
        "root_relative_path_raw",
        "bmff_box_path",
        "box_path_raw",
    ] {
        assert!(
            !report_object.contains_key(forbidden),
            "report page exposed forbidden key {forbidden}"
        );
    }
    assert!(matches!(
        store
            .list_capture_time_metadata_reports_page(SCAN_RUN_ID, GROUP_ID, ANALYSIS_ID, None, 33,),
        Err(StoreError::InvalidInput { .. })
    ));

    let fields = store.list_capture_time_metadata_fields_page(
        SCAN_RUN_ID,
        GROUP_ID,
        ANALYSIS_ID,
        0,
        REPORT_ID,
        None,
        128,
    )?;
    assert_eq!(fields.items.len(), 3);
    let fields_json = serde_json::to_value(&fields.items)?;
    let serialized_fields = serde_json::to_string(&fields_json)?;
    for forbidden in [
        "raw_bytes",
        "root_relative_path_raw",
        "bmff_box_path",
        "box_path_raw",
    ] {
        assert!(
            !serialized_fields.contains(forbidden),
            "field page exposed forbidden key {forbidden}"
        );
    }
    assert!(fields.items.iter().all(|field| field.raw_available));
    assert!(matches!(
        store.list_capture_time_metadata_fields_page(
            SCAN_RUN_ID,
            GROUP_ID,
            ANALYSIS_ID,
            0,
            REPORT_ID,
            None,
            129,
        ),
        Err(StoreError::InvalidInput { .. })
    ));

    let binary = store
        .get_capture_time_metadata_field_raw_detail(
            SCAN_RUN_ID,
            GROUP_ID,
            ANALYSIS_ID,
            0,
            REPORT_ID,
            0,
            SMALL_FIELD_ID,
        )?
        .expect("small raw detail");
    assert_eq!(binary.raw_bytes, vec![0x00, 0xff, 0xc3, 0x28]);
    assert_eq!(binary.root_relative_path_raw, b"source-\xff.jpg");
    assert!(matches!(
        binary.locator,
        MetadataFieldRawLocator::JpegExif {
            app1_offset: 0,
            header_offset: 8,
            ifd_offset: 16,
            tag: 0x9003,
            ..
        }
    ));

    let one_mib = store
        .get_capture_time_metadata_field_raw_detail(
            SCAN_RUN_ID,
            GROUP_ID,
            ANALYSIS_ID,
            0,
            REPORT_ID,
            1,
            LARGE_FIELD_ID,
        )?
        .expect("1 MiB boundary detail");
    assert_eq!(one_mib.raw_bytes.len(), 1024 * 1024);
    assert!(one_mib.raw_bytes.iter().all(|byte| *byte == 0xa5));

    let bmff = store
        .get_capture_time_metadata_field_raw_detail(
            SCAN_RUN_ID,
            GROUP_ID,
            ANALYSIS_ID,
            0,
            REPORT_ID,
            2,
            BMFF_FIELD_ID,
        )?
        .expect("BMFF detail");
    assert!(matches!(
        bmff.locator,
        MetadataFieldRawLocator::IsoBmff {
            box_offset: 64,
            ref box_path_raw,
        } if box_path_raw == b"moovmeta"
    ));

    assert!(store
        .get_capture_time_metadata_field_raw_detail(
            SCAN_RUN_ID,
            GROUP_ID,
            ANALYSIS_ID,
            0,
            REPORT_ID,
            1,
            SMALL_FIELD_ID,
        )?
        .is_none());
    assert!(matches!(
        store.list_capture_time_metadata_fields_page(
            SCAN_RUN_ID,
            GROUP_ID,
            ANALYSIS_ID,
            1,
            REPORT_ID,
            None,
            10,
        ),
        Err(StoreError::ConcurrencyConflict { .. })
    ));

    assert!(matches!(
        store.list_capture_time_metadata_fields_page(
            SCAN_RUN_ID,
            GROUP_ID,
            ANALYSIS_ID,
            1,
            DRAFT_REPORT_ID,
            None,
            10,
        ),
        Err(StoreError::ConcurrencyConflict { .. })
    ));
    assert!(store
        .list_capture_time_metadata_reports_page(
            NON_EVIDENCE_SCAN_RUN_ID,
            NON_EVIDENCE_GROUP_ID,
            NON_EVIDENCE_ANALYSIS_ID,
            None,
            10,
        )?
        .items
        .is_empty());
    assert!(matches!(
        store.list_capture_time_metadata_fields_page(
            NON_EVIDENCE_SCAN_RUN_ID,
            NON_EVIDENCE_GROUP_ID,
            NON_EVIDENCE_ANALYSIS_ID,
            0,
            NON_EVIDENCE_REPORT_ID,
            None,
            10,
        ),
        Err(StoreError::ConcurrencyConflict { .. })
    ));

    let wrong_report_cursor: MetadataReportCursor = serde_json::from_value(json!({
        "cursor_version": 1,
        "scan_run_id": SCAN_RUN_ID,
        "exact_group_build_id": GROUP_ID + 1,
        "analysis_build_id": ANALYSIS_ID,
        "last_source_ordinal": 0,
        "last_report_id": REPORT_ID,
    }))?;
    assert!(matches!(
        store.list_capture_time_metadata_reports_page(
            SCAN_RUN_ID,
            GROUP_ID,
            ANALYSIS_ID,
            Some(&wrong_report_cursor),
            10,
        ),
        Err(StoreError::InvalidInput { .. })
    ));
    let wrong_field_cursor: MetadataFieldCursor = serde_json::from_value(json!({
        "cursor_version": 1,
        "scan_run_id": SCAN_RUN_ID,
        "exact_group_build_id": GROUP_ID,
        "analysis_build_id": ANALYSIS_ID,
        "source_ordinal": 0,
        "report_id": REPORT_ID + 1,
        "last_field_ordinal": 0,
        "last_field_id": SMALL_FIELD_ID,
    }))?;
    assert!(matches!(
        store.list_capture_time_metadata_fields_page(
            SCAN_RUN_ID,
            GROUP_ID,
            ANALYSIS_ID,
            0,
            REPORT_ID,
            Some(&wrong_field_cursor),
            10,
        ),
        Err(StoreError::InvalidInput { .. })
    ));
    assert!(serde_json::from_value::<MetadataReportCursor>(json!({
        "cursor_version": 1,
        "scan_run_id": SCAN_RUN_ID,
        "exact_group_build_id": GROUP_ID,
        "analysis_build_id": ANALYSIS_ID,
        "last_source_ordinal": 0,
        "last_report_id": REPORT_ID,
        "unexpected": true,
    }))
    .is_err());
    assert!(serde_json::from_value::<MetadataFieldCursor>(json!({
        "cursor_version": 1,
        "scan_run_id": SCAN_RUN_ID,
        "exact_group_build_id": GROUP_ID,
        "analysis_build_id": ANALYSIS_ID,
        "source_ordinal": 0,
        "report_id": REPORT_ID,
        "last_field_ordinal": 0,
        "last_field_id": SMALL_FIELD_ID,
        "unexpected": true,
    }))
    .is_err());

    let tamper = Connection::open(&database_path)?;
    tamper.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    assert_eq!(
        tamper.execute(
            "UPDATE metadata_extraction_fields \
             SET jpeg_app1_offset = ?1 WHERE id = ?2",
            params![i64::MAX, SMALL_FIELD_ID],
        )?,
        1
    );
    tamper.close().map_err(|(_, error)| error)?;
    assert!(matches!(
        store.get_capture_time_metadata_field_raw_detail(
            SCAN_RUN_ID,
            GROUP_ID,
            ANALYSIS_ID,
            0,
            REPORT_ID,
            0,
            SMALL_FIELD_ID,
        ),
        Err(StoreError::InvalidInput { .. })
    ));

    store.close()?;
    Ok(())
}

fn seed_read_fixture(database_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = Connection::open(database_path)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    connection.execute_batch("PRAGMA foreign_keys = OFF;")?;
    let transaction = connection.transaction()?;

    insert_observation(&transaction, 1, SCAN_RUN_ID, [10; 32])?;
    insert_observation(&transaction, 2, NON_EVIDENCE_SCAN_RUN_ID, [11; 32])?;
    insert_session(&transaction, SESSION_ID, SCAN_RUN_ID, 1, 0, [40; 32])?;
    insert_session(
        &transaction,
        NON_EVIDENCE_SESSION_ID,
        NON_EVIDENCE_SCAN_RUN_ID,
        0,
        1,
        [41; 32],
    )?;
    insert_analysis(
        &transaction,
        ANALYSIS_ID,
        SESSION_ID,
        SCAN_RUN_ID,
        GROUP_ID,
        2,
        [50; 32],
    )?;
    insert_analysis(
        &transaction,
        NON_EVIDENCE_ANALYSIS_ID,
        NON_EVIDENCE_SESSION_ID,
        NON_EVIDENCE_SCAN_RUN_ID,
        NON_EVIDENCE_GROUP_ID,
        1,
        [51; 32],
    )?;
    transaction.execute(
        "INSERT INTO capture_time_group_outcomes (time_session_id, exact_group_build_id, \
             volume_id, scan_run_id, outcome, analysis_build_id, reason_code, created_at_ms) \
         VALUES (?1, ?2, 1, ?3, 'evidence', ?4, 'sealed_evidence', 40)",
        params![SESSION_ID, GROUP_ID, SCAN_RUN_ID, ANALYSIS_ID],
    )?;
    transaction.execute(
        "INSERT INTO capture_time_group_outcomes (time_session_id, exact_group_build_id, \
             volume_id, scan_run_id, outcome, analysis_build_id, reason_code, created_at_ms) \
         VALUES (?1, ?2, 1, ?3, 'unavailable', NULL, 'no_metadata', 40)",
        params![
            NON_EVIDENCE_SESSION_ID,
            NON_EVIDENCE_GROUP_ID,
            NON_EVIDENCE_SCAN_RUN_ID,
        ],
    )?;
    insert_recommendation(&transaction, ANALYSIS_ID, SCAN_RUN_ID, GROUP_ID)?;
    insert_recommendation(
        &transaction,
        NON_EVIDENCE_ANALYSIS_ID,
        NON_EVIDENCE_SCAN_RUN_ID,
        NON_EVIDENCE_GROUP_ID,
    )?;

    let small_raw = vec![0x00, 0xff, 0xc3, 0x28];
    let large_raw = vec![0xa5; 1024 * 1024];
    let bmff_raw = b"data".to_vec();
    let retained_bytes = i64::try_from(small_raw.len() + large_raw.len() + bmff_raw.len())?;
    insert_report(
        &transaction,
        REPORT_ID,
        SESSION_ID,
        SCAN_RUN_ID,
        GROUP_ID,
        1,
        "sealed",
        3,
        retained_bytes,
        [60; 32],
        [61; 32],
    )?;
    insert_report(
        &transaction,
        DRAFT_REPORT_ID,
        SESSION_ID,
        SCAN_RUN_ID,
        GROUP_ID,
        1,
        "draft",
        0,
        0,
        [62; 32],
        [63; 32],
    )?;
    insert_report(
        &transaction,
        NON_EVIDENCE_REPORT_ID,
        NON_EVIDENCE_SESSION_ID,
        NON_EVIDENCE_SCAN_RUN_ID,
        NON_EVIDENCE_GROUP_ID,
        2,
        "sealed",
        0,
        0,
        [64; 32],
        [65; 32],
    )?;
    insert_revalidation(
        &transaction,
        REPORT_ID,
        SESSION_ID,
        SCAN_RUN_ID,
        GROUP_ID,
        1,
        [70; 32],
        [71; 32],
        [10; 32],
        [60; 32],
    )?;
    insert_revalidation(
        &transaction,
        NON_EVIDENCE_REPORT_ID,
        NON_EVIDENCE_SESSION_ID,
        NON_EVIDENCE_SCAN_RUN_ID,
        NON_EVIDENCE_GROUP_ID,
        2,
        [72; 32],
        [73; 32],
        [11; 32],
        [64; 32],
    )?;
    insert_analysis_source(&transaction, ANALYSIS_ID, 0, REPORT_ID, [70; 32], [71; 32])?;
    insert_analysis_source(
        &transaction,
        ANALYSIS_ID,
        1,
        DRAFT_REPORT_ID,
        [74; 32],
        [75; 32],
    )?;
    insert_analysis_source(
        &transaction,
        NON_EVIDENCE_ANALYSIS_ID,
        0,
        NON_EVIDENCE_REPORT_ID,
        [72; 32],
        [73; 32],
    )?;

    insert_jpeg_field(
        &transaction,
        SMALL_FIELD_ID,
        REPORT_ID,
        0,
        0,
        0x9003,
        &small_raw,
    )?;
    insert_jpeg_field(
        &transaction,
        LARGE_FIELD_ID,
        REPORT_ID,
        1,
        128,
        0x9004,
        &large_raw,
    )?;
    insert_bmff_field(
        &transaction,
        BMFF_FIELD_ID,
        REPORT_ID,
        2,
        1_100_000,
        &bmff_raw,
    )?;

    transaction.commit()?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, true)?;
    connection.close().map_err(|(_, error)| error)?;
    Ok(())
}

fn insert_observation(
    transaction: &Transaction<'_>,
    id: i64,
    scan_run_id: i64,
    source_signature: [u8; 32],
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO media_observation_snapshots ( \
             id, volume_id, scan_run_id, media_namespace_path_id, media_file_id, \
             namespace_profile_id, capability_profile_id, root_relative_path_raw, \
             path_encoding, display_path, source_signature, stat_signature_version, \
             file_mode, entry_type, size_bytes, modified_time_seconds, \
             modified_time_nanoseconds, changed_time_seconds, changed_time_nanoseconds, \
             timestamp_storage_unit_ns, timestamp_granularity_ns, observed_at_ms \
         ) VALUES ( \
             ?1, 1, ?2, ?1, ?1, 1, 1, ?3, 'unix_bytes', '/review/source.jpg', ?4, 1, \
             33188, 'regular', 2097152, 1, 0, 1, 0, 1, 1, 1 \
         )",
        params![
            id,
            scan_run_id,
            b"source-\xff.jpg".as_slice(),
            source_signature
        ],
    )?;
    Ok(())
}

fn insert_session(
    transaction: &Transaction<'_>,
    id: i64,
    scan_run_id: i64,
    evidence_count: i64,
    unavailable_count: i64,
    manifest: [u8; 32],
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO scan_time_sessions ( \
             id, time_session_key, volume_id, scan_run_id, core_session_id, \
             schema_contract_version, scope_manifest_version, outcome_manifest_version, state, \
             expected_group_count, evidence_group_count, unavailable_group_count, \
             failed_group_count, max_total_read_bytes, max_probe_count_per_group, \
             max_report_total_bytes_read, max_report_read_operations, \
             max_report_retained_field_bytes, max_report_fields, max_report_issues, \
             expected_manifest_digest, sealed_manifest_digest, sealed_outcome_manifest_digest, \
             created_at_ms, finalized_at_ms \
         ) VALUES ( \
             ?1, ?2, 1, ?3, ?4, 1, 1, 2, 'complete', 1, ?5, ?6, 0, \
             4294967296, 4, 8388608, 32768, 262144, 128, 128, ?7, ?7, ?8, 1, 50 \
         )",
        params![
            id,
            [u8::try_from(id).unwrap_or(1); 32],
            scan_run_id,
            [20_u8; 32],
            evidence_count,
            unavailable_count,
            manifest,
            [21_u8; 32],
        ],
    )?;
    Ok(())
}

fn insert_analysis(
    transaction: &Transaction<'_>,
    id: i64,
    session_id: i64,
    scan_run_id: i64,
    group_id: i64,
    source_count: i64,
    manifest: [u8; 32],
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO capture_time_analysis_builds ( \
             id, time_session_id, volume_id, scan_run_id, exact_group_build_id, \
             policy_name, policy_version, policy_context_json, policy_context_digest, \
             state, decision, selected_candidate_ordinal, expected_source_count, \
             expected_observation_count, expected_candidate_count, expected_issue_count, \
             expected_member_count, expected_recommendation_count, manifest_version, \
             expected_manifest_digest, sealed_manifest_digest, created_at_ms, finalized_at_ms \
         ) VALUES ( \
             ?1, ?2, 1, ?3, ?4, 'review', '1', '{}', ?5, 'sealed', \
             'no_usable_evidence', NULL, ?6, 0, 0, 0, 2, 1, 1, ?7, ?7, 20, 45 \
         )",
        params![
            id,
            session_id,
            scan_run_id,
            group_id,
            [30_u8; 32],
            source_count,
            manifest
        ],
    )?;
    Ok(())
}

fn insert_recommendation(
    transaction: &Transaction<'_>,
    analysis_id: i64,
    scan_run_id: i64,
    group_id: i64,
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO capture_time_recommendations ( \
             analysis_build_id, volume_id, scan_run_id, exact_group_build_id, \
             evidence_only, write_authorized, reason_code, created_at_ms \
         ) VALUES (?1, 1, ?2, ?3, 1, 0, 'historical_only', 30)",
        params![analysis_id, scan_run_id, group_id],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_report(
    transaction: &Transaction<'_>,
    id: i64,
    session_id: i64,
    scan_run_id: i64,
    group_id: i64,
    observation_id: i64,
    state: &str,
    field_count: i64,
    retained_bytes: i64,
    retained_digest: [u8; 32],
    manifest: [u8; 32],
) -> rusqlite::Result<()> {
    let sealed_manifest = (state == "sealed").then_some(manifest);
    let finalized_at_ms = (state == "sealed").then_some(35_i64);
    let probe_ordinal = if state == "draft" { 1_i64 } else { 0_i64 };
    transaction.execute(
        "INSERT INTO metadata_extraction_reports ( \
             id, time_session_id, volume_id, scan_run_id, core_session_id, \
             exact_group_build_id, metadata_probe_observation_id, \
             metadata_probe_fingerprint_id, probe_ordinal, source_size_bytes, \
             report_parser_name, report_parser_version, detected_format, extraction_status, \
             effective_max_total_bytes_read, effective_max_read_operations, \
             effective_max_retained_field_bytes, effective_max_field_bytes, \
             effective_max_fields, effective_max_jpeg_segments, effective_max_ifd_entries, \
             effective_max_ifd_depth, effective_max_bmff_boxes, effective_max_bmff_depth, \
             usage_bytes_read, usage_read_operations, usage_retained_field_bytes, \
             usage_fields_emitted, usage_jpeg_segments_visited, usage_ifd_entries_visited, \
             usage_bmff_boxes_visited, usage_max_depth_observed, expected_field_count, \
             expected_issue_count, expected_retained_field_bytes, retained_report_digest, \
             expected_manifest_digest, state, sealed_manifest_digest, created_at_ms, \
             finalized_at_ms \
         ) VALUES ( \
             :id, :session_id, 1, :scan_run_id, :core_session_id, :group_id, \
             :observation_id, :fingerprint_id, :probe_ordinal, 2097152, 'guiying-metadata', '1', \
             'jpeg', 'extracted_unvalidated', 2097152, 128, 2097152, 1048576, \
             128, 128, 128, 8, 128, 8, 2097152, 3, :retained_bytes, :field_count, \
             2, 2, 1, 2, :field_count, 0, :retained_bytes, :retained_digest, \
             :manifest, :state, :sealed_manifest, 10, :finalized_at_ms \
         )",
        named_params! {
            ":id": id,
            ":session_id": session_id,
            ":scan_run_id": scan_run_id,
            ":core_session_id": [20_u8; 32],
            ":group_id": group_id,
            ":observation_id": observation_id,
            ":fingerprint_id": id + 1_000,
            ":probe_ordinal": probe_ordinal,
            ":retained_bytes": retained_bytes,
            ":field_count": field_count,
            ":retained_digest": retained_digest,
            ":manifest": manifest,
            ":state": state,
            ":sealed_manifest": sealed_manifest,
            ":finalized_at_ms": finalized_at_ms,
        },
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_revalidation(
    transaction: &Transaction<'_>,
    report_id: i64,
    session_id: i64,
    scan_run_id: i64,
    group_id: i64,
    observation_id: i64,
    source_key: [u8; 32],
    lineage_key: [u8; 32],
    source_signature: [u8; 32],
    report_digest: [u8; 32],
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO metadata_source_revalidations ( \
             report_id, time_session_id, volume_id, scan_run_id, core_session_id, \
             exact_group_build_id, metadata_probe_observation_id, source_key, \
             source_key_version, lineage_key, lineage_key_version, source_signature_before, \
             source_signature_after, first_report_digest, second_report_digest, outcome, \
             descriptor_revalidated, path_revalidated, session_revalidated, trust_scope, \
             revalidated_at_ms \
         ) VALUES ( \
             ?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, 2, ?8, 1, ?9, ?9, ?10, ?10, \
             'reextracted_pinned_exact', 1, 1, 1, 'historical_proof_only', 30 \
         )",
        params![
            report_id,
            session_id,
            scan_run_id,
            [20_u8; 32],
            group_id,
            observation_id,
            source_key,
            lineage_key,
            source_signature,
            report_digest,
        ],
    )?;
    Ok(())
}

fn insert_analysis_source(
    transaction: &Transaction<'_>,
    analysis_id: i64,
    ordinal: i64,
    report_id: i64,
    source_key: [u8; 32],
    lineage_key: [u8; 32],
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO capture_time_analysis_sources ( \
             analysis_build_id, ordinal, report_id, source_key, lineage_key, \
             binding_status, created_at_ms \
         ) VALUES (?1, ?2, ?3, ?4, ?5, 'reextracted_pinned_source', 32)",
        params![analysis_id, ordinal, report_id, source_key, lineage_key],
    )?;
    Ok(())
}

fn insert_jpeg_field(
    transaction: &Transaction<'_>,
    id: i64,
    report_id: i64,
    ordinal: i64,
    absolute_offset: i64,
    tag: i64,
    raw_bytes: &[u8],
) -> rusqlite::Result<()> {
    let digest = *blake3::hash(raw_bytes).as_bytes();
    transaction.execute(
        "INSERT INTO metadata_extraction_fields ( \
             id, report_id, ordinal, parser_name, parser_version, field_kind, encoding, \
             absolute_offset, byte_len, raw_bytes, raw_digest, container_kind, \
             tiff_header_offset, tiff_ifd_offset, tiff_tag, tiff_byte_order, \
             jpeg_app1_offset, created_at_ms \
         ) VALUES ( \
             ?1, ?2, ?3, 'guiying-metadata', '1', 'exif_date_time_original', \
             'declared_ascii', ?4, ?5, ?6, ?7, 'jpeg_exif', 8, 16, ?8, \
             'little_endian', 0, 20 \
         )",
        params![
            id,
            report_id,
            ordinal,
            absolute_offset,
            i64::try_from(raw_bytes.len()).unwrap_or(i64::MAX),
            raw_bytes,
            digest,
            tag,
        ],
    )?;
    Ok(())
}

fn insert_bmff_field(
    transaction: &Transaction<'_>,
    id: i64,
    report_id: i64,
    ordinal: i64,
    absolute_offset: i64,
    raw_bytes: &[u8],
) -> rusqlite::Result<()> {
    let digest = *blake3::hash(raw_bytes).as_bytes();
    transaction.execute(
        "INSERT INTO metadata_extraction_fields ( \
             id, report_id, ordinal, parser_name, parser_version, field_kind, encoding, \
             absolute_offset, byte_len, raw_bytes, raw_digest, container_kind, \
             bmff_box_offset, bmff_box_path, created_at_ms \
         ) VALUES ( \
             ?1, ?2, ?3, 'guiying-metadata', '1', \
             'quicktime_metadata_creation_date', 'validated_utf8', ?4, ?5, ?6, ?7, \
             'iso_bmff', 64, ?8, 20 \
         )",
        params![
            id,
            report_id,
            ordinal,
            absolute_offset,
            i64::try_from(raw_bytes.len()).unwrap_or(i64::MAX),
            raw_bytes,
            digest,
            b"moovmeta".as_slice(),
        ],
    )?;
    Ok(())
}
