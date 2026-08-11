use guiying_store::{Store, StoreError};
use rusqlite::{params, Connection, TransactionBehavior};
use tempfile::TempDir;

const APPLICATION_ID: i32 = 0x4755_5949;

const MIGRATIONS: [(&str, &str); 6] = [
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
];

#[test]
fn empty_v6_database_upgrades_transactionally_to_latest_without_legacy_copy(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("v6-to-latest.sqlite3");
    create_empty_managed_v6(&database)?;

    let store = Store::open_existing(&database)?;
    assert_eq!(store.schema_version()?, 8);
    store.close()?;

    let connection = Connection::open(&database)?;
    let registered: i64 = connection.query_row(
        "SELECT count(*) FROM guiying_schema_migrations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(registered, 8);
    let v7_tables: i64 = connection.query_row(
        "SELECT count(*) FROM pragma_table_list \
         WHERE name IN ( \
             'scan_time_sessions', 'capture_time_group_outcomes', \
             'metadata_extraction_reports', 'metadata_extraction_fields', \
             'metadata_extraction_issues', 'metadata_source_revalidations', \
             'capture_time_analysis_builds', 'capture_time_analysis_sources', \
             'capture_time_observations', 'capture_time_candidates', \
             'capture_time_policy_issues', 'capture_time_member_assessments', \
             'capture_time_recommendations' \
         ) AND strict = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(v7_tables, 13);
    let legacy_rows: i64 =
        connection.query_row("SELECT count(*) FROM time_candidates", [], |row| row.get(0))?;
    let v7_rows: i64 = connection.query_row(
        "SELECT count(*) FROM metadata_extraction_reports",
        [],
        |row| row.get(0),
    )?;
    assert_eq!((legacy_rows, v7_rows), (0, 0));
    let session_guard: String = connection.query_row(
        "SELECT sql FROM sqlite_schema \
         WHERE type = 'trigger' AND name = 'trg_scan_time_sessions_insert_guard_v7'",
        [],
        |row| row.get(0),
    )?;
    assert!(session_guard.contains("run.state = 'completed'"));
    assert!(session_guard.contains("job.state = 'completed'"));
    assert!(session_guard.contains("job.active_scan_run_id = run.id"));
    let candidate_guard: String = connection.query_row(
        "SELECT sql FROM sqlite_schema \
         WHERE type = 'trigger' AND name = 'trg_capture_time_candidates_insert_guard_v7'",
        [],
        |row| row.get(0),
    )?;
    for required_scope_term in [
        "timestamp_field.field_kind = 'exif_date_time_original'",
        "offset_observation.report_id = timestamp_observation.report_id",
        "offset_field.tiff_header_offset = timestamp_field.tiff_header_offset",
        "offset_field.tiff_ifd_offset = timestamp_field.tiff_ifd_offset",
        "offset_field.jpeg_app1_offset IS timestamp_field.jpeg_app1_offset",
    ] {
        assert!(
            candidate_guard.contains(required_scope_term),
            "migrated candidate gate omitted {required_scope_term}"
        );
    }
    let candidate_table: String = connection.query_row(
        "SELECT sql FROM sqlite_schema \
         WHERE type = 'table' AND name = 'capture_time_candidates'",
        [],
        |row| row.get(0),
    )?;
    assert!(candidate_table.contains("offset_kind = 'explicit'"));
    Ok(())
}

#[test]
fn fresh_latest_manifest_detects_a_removed_v7_evidence_only_gate(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("manifest.sqlite3");
    Store::open_or_create(&database)?.close()?;

    let connection = Connection::open(&database)?;
    connection.execute_batch("DROP TRIGGER trg_capture_time_recommendations_no_update_v7;")?;
    connection.close().map_err(|(_, error)| error)?;

    let error = Store::open_existing(&database)
        .err()
        .ok_or("store accepted the latest schema with a v7 evidence trigger removed")?;
    assert!(matches!(error, StoreError::SchemaManifestMismatch { .. }));
    Ok(())
}

#[test]
fn direct_sql_enforces_time_safety_write_denial_and_source_v2_lineage_v1(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("direct-sql-gates.sqlite3");
    Store::open_or_create(&database)?.close()?;

    let connection = Connection::open(&database)?;
    connection.pragma_update(None, "foreign_keys", false)?;
    connection.execute_batch(
        "DROP TRIGGER trg_capture_time_candidates_insert_guard_v7; \
         DROP TRIGGER trg_capture_time_recommendations_insert_guard_v7; \
         DROP TRIGGER trg_metadata_revalidations_insert_guard_v7;",
    )?;

    let leap_second = connection
        .execute(
            "INSERT INTO capture_time_candidates ( \
                 id, analysis_build_id, ordinal, wall_year, wall_month, wall_day, \
                 wall_hour, wall_minute, wall_second, wall_nanosecond, semantic_kind, \
                 offset_kind, precision_ns, confidence, evidence_gate, evidence_kinds_json, \
                 source_keys_json, lineage_keys_json, observation_ordinals_json, \
                 anomalies_json, blockers_json, created_at_ms \
             ) VALUES ( \
                 1, 1, 0, 2024, 1, 1, 0, 0, 60, 0, 'floating', 'missing', \
                 1000000000, 'low', 'blocked', '[\"exif_date_time_original\"]', \
                 '[\"source\"]', '[\"lineage\"]', '[0]', '[]', \
                 '[\"confidence_below_high\"]', 1 \
             )",
            [],
        )
        .expect_err("wall second 60 bypassed the strict time model");
    assert!(leap_second.to_string().contains("CHECK constraint failed"));

    let noncanonical_decimal = connection
        .execute(
            "INSERT INTO capture_time_candidates ( \
                 id, analysis_build_id, ordinal, wall_year, wall_month, wall_day, \
                 wall_hour, wall_minute, wall_second, wall_nanosecond, semantic_kind, \
                 offset_kind, utc_offset_minutes, utc_seconds_decimal, utc_nanoseconds, \
                 precision_ns, confidence, evidence_gate, evidence_kinds_json, \
                 source_keys_json, lineage_keys_json, observation_ordinals_json, \
                 anomalies_json, blockers_json, created_at_ms \
             ) VALUES ( \
                 2, 1, 0, 2024, 1, 1, 0, 0, 0, 0, 'utc', 'explicit', 0, '01', 0, \
                 1000000000, 'low', 'blocked', '[\"exif_date_time_original\"]', \
                 '[\"source\"]', '[\"lineage\"]', '[0]', '[]', \
                 '[\"confidence_below_high\"]', 1 \
             )",
            [],
        )
        .expect_err("non-canonical signed decimal was accepted");
    assert!(noncanonical_decimal
        .to_string()
        .contains("CHECK constraint failed"));

    let write_authority = connection
        .execute(
            "INSERT INTO capture_time_recommendations ( \
                 analysis_build_id, volume_id, scan_run_id, exact_group_build_id, \
                 evidence_only, write_authorized, reason_code, created_at_ms \
             ) VALUES (1, 1, 1, 1, 1, 1, 'must-remain-evidence-only', 1)",
            [],
        )
        .expect_err("capture-time evidence granted filesystem write authority");
    assert!(write_authority
        .to_string()
        .contains("CHECK constraint failed"));

    let source_v1 = connection
        .execute(
            "INSERT INTO metadata_source_revalidations ( \
                 id, report_id, time_session_id, volume_id, scan_run_id, core_session_id, \
                 exact_group_build_id, metadata_probe_observation_id, source_key, \
                 source_key_version, lineage_key, lineage_key_version, \
                 source_signature_before, source_signature_after, first_report_digest, \
                 second_report_digest, outcome, descriptor_revalidated, path_revalidated, \
                 session_revalidated, trust_scope, revalidated_at_ms \
             ) VALUES ( \
                 1, 1, 1, 1, 1, zeroblob(32), 1, 1, zeroblob(32), 1, \
                 zeroblob(32), 1, zeroblob(32), zeroblob(32), zeroblob(32), \
                 zeroblob(32), 'reextracted_pinned_exact', 1, 1, 1, \
                 'historical_proof_only', 1 \
             )",
            [],
        )
        .expect_err("timestamp-source.v1 was accepted under the v2 source-key contract");
    assert!(source_v1.to_string().contains("CHECK constraint failed"));

    connection.execute(
        "INSERT INTO metadata_source_revalidations ( \
             id, report_id, time_session_id, volume_id, scan_run_id, core_session_id, \
             exact_group_build_id, metadata_probe_observation_id, source_key, \
             source_key_version, lineage_key, lineage_key_version, \
             source_signature_before, source_signature_after, first_report_digest, \
             second_report_digest, outcome, descriptor_revalidated, path_revalidated, \
             session_revalidated, trust_scope, revalidated_at_ms \
         ) VALUES ( \
             2, 2, 1, 1, 1, zeroblob(32), 1, 1, zeroblob(32), 2, \
             zeroblob(32), 1, zeroblob(32), zeroblob(32), zeroblob(32), \
             zeroblob(32), 'reextracted_pinned_exact', 1, 1, 1, \
             'historical_proof_only', 1 \
         )",
        [],
    )?;
    let versions: (i64, i64) = connection.query_row(
        "SELECT source_key_version, lineage_key_version \
         FROM metadata_source_revalidations WHERE id = 2",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(versions, (2, 1));
    Ok(())
}

#[test]
fn restored_schema_still_rejects_a_check_bypassed_zero_limit_on_reopen(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("reopen-typed-limit.sqlite3");
    Store::open_or_create(&database)?.close()?;

    let connection = Connection::open(&database)?;
    connection.pragma_update(None, "foreign_keys", false)?;
    connection.pragma_update(None, "ignore_check_constraints", true)?;
    let trigger_sql: String = connection.query_row(
        "SELECT sql FROM sqlite_schema \
         WHERE type = 'trigger' AND name = 'trg_metadata_reports_insert_guard_v7'",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch("DROP TRIGGER trg_metadata_reports_insert_guard_v7;")?;
    connection.execute(
        "INSERT INTO metadata_extraction_reports ( \
             id, time_session_id, volume_id, scan_run_id, core_session_id, \
             exact_group_build_id, metadata_probe_observation_id, \
             metadata_probe_fingerprint_id, probe_ordinal, source_size_bytes, \
             report_parser_name, report_parser_version, extraction_status, \
             effective_max_total_bytes_read, effective_max_read_operations, \
             effective_max_retained_field_bytes, effective_max_field_bytes, \
             effective_max_fields, effective_max_jpeg_segments, effective_max_ifd_entries, \
             effective_max_ifd_depth, effective_max_bmff_boxes, effective_max_bmff_depth, \
             usage_bytes_read, usage_read_operations, usage_retained_field_bytes, \
             usage_fields_emitted, usage_jpeg_segments_visited, usage_ifd_entries_visited, \
             usage_bmff_boxes_visited, usage_max_depth_observed, expected_field_count, \
             expected_issue_count, expected_retained_field_bytes, retained_report_digest, \
             expected_manifest_digest, state, abandon_reason_code, created_at_ms, finalized_at_ms \
         ) VALUES ( \
             1, 1, 1, 1, zeroblob(32), 1, 1, 1, 0, 0, 'parser', '1', 'failed', \
             0, 1, 1, 1, 1, 1, 1, 1, 1, 1, \
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, zeroblob(32), zeroblob(32), \
             'abandoned', 'TEST_TAMPER', 1, 1 \
         )",
        [],
    )?;
    connection.execute_batch(&trigger_sql)?;
    connection.close().map_err(|(_, error)| error)?;

    let error = Store::open_existing(&database)
        .err()
        .ok_or("reopen accepted a zero effective extraction limit")?;
    assert!(
        !matches!(error, StoreError::SchemaManifestMismatch { .. }),
        "the restored trigger must match the canonical schema: {error}"
    );
    Ok(())
}

fn create_empty_managed_v6(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = Connection::open(path)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    for (index, (name, sql)) in MIGRATIONS.iter().enumerate() {
        let version = i64::try_from(index)? + 1;
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
                1_000 + version
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
