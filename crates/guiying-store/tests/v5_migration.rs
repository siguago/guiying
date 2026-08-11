use guiying_store::{Store, StoreError};
use rusqlite::Connection;
use tempfile::TempDir;

#[test]
fn fresh_store_has_v6_runtime_companion_schema_and_manifest_guards(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("guiying-v5.sqlite3");
    let store = Store::open_or_create(&database)?;
    assert_eq!(store.schema_version()?, 6);
    store.close()?;

    let connection = Connection::open(&database)?;
    let strict_tables: i64 = connection.query_row(
        "SELECT count(*) FROM pragma_table_list \
         WHERE name IN ( \
             'namespace_profiles', 'scan_job_scopes', 'scan_run_sessions', \
             'scan_stage_seals', 'media_namespace_paths', \
             'media_observation_snapshots', 'observation_fingerprints', \
             'exact_group_builds', 'exact_group_build_members', \
             'exact_verification_edges', 'scan_core_sessions', \
             'scan_file_tickets', 'scan_directory_observations', \
             'scan_coverage_outcomes' \
         ) AND strict = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(strict_tables, 14);
    let migration_count: i64 = connection.query_row(
        "SELECT count(*) FROM guiying_schema_migrations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(migration_count, 6);
    connection.execute_batch("DROP TRIGGER trg_scan_runs_enter_running_session_gate_v5;")?;
    connection.close().map_err(|(_, error)| error)?;

    let error = Store::open_existing(&database)
        .err()
        .ok_or("store accepted a v5 schema with its running-session gate removed")?;
    assert!(matches!(error, StoreError::SchemaManifestMismatch { .. }));
    Ok(())
}

#[test]
fn direct_sql_cannot_enter_running_without_a_bound_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let database = temporary.path().join("running-gate.sqlite3");
    Store::open_or_create(&database)?.close()?;
    let connection = Connection::open(&database)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.execute_batch(
        "INSERT INTO volumes ( \
             id, identity_key, identity_strength, marker_uuid, filesystem_type, \
             is_network, is_read_only, first_seen_at_ms, last_seen_at_ms, \
             created_at_ms, updated_at_ms \
         ) VALUES (1, 'volume', 'strong', 'marker', 'apfs', 0, 1, 1, 1, 1, 1); \
         INSERT INTO capability_profiles ( \
             id, volume_id, profile_hash, profile_hash_version, probe_mode, probe_status, \
             observed_at_ms, os_build, mount_session_key, probe_protocol_version, \
             case_behavior, unicode_behavior, path_encoding_family, path_semantics_version, \
             can_read, is_current, created_at_ms \
         ) VALUES ( \
             1, 1, zeroblob(32), 2, 'passive', 'complete', 1, 'test', \
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
             1, 'sensitive', 'exact', 'unix', 1, 1, 1, 1 \
         ); \
         INSERT INTO namespace_profiles ( \
             id, volume_id, profile_key, profile_version, origin, native_path_encoding, \
             case_behavior, unicode_behavior, key_strategy, key_algorithm_version, \
             reuse_scope, bound_mount_session_key, created_at_ms \
         ) VALUES ( \
             1, 1, zeroblob(32), 1, 'observed_v5', 'unix_bytes', 'sensitive', \
             'exact', 'exact_native_v1', 1, 'current_session_only', \
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1 \
         ); \
         INSERT INTO scan_jobs ( \
             id, job_key, volume_id, root_relative_path, root_path_key, state, \
             created_at_ms, updated_at_ms \
         ) VALUES (1, 'job', 1, 'DCIM', zeroblob(32), 'queued', 1, 1); \
         INSERT INTO scan_job_roots ( \
             scan_job_id, volume_id, capability_profile_id, path_semantics_version, \
             relative_path_raw, path_encoding, semantic_path_key, created_at_ms \
         ) VALUES (1, 1, NULL, 1, CAST('DCIM' AS BLOB), 'utf8', zeroblob(32), 1); \
         INSERT INTO scan_job_scopes ( \
             scan_job_id, volume_id, namespace_profile_id, origin, root_display, \
             mount_relative_root_raw, path_encoding, stable_root_path_key, root_scope_key, \
             recoverable, created_at_ms \
         ) VALUES ( \
             1, 1, 1, 'observed_v5', 'DCIM', CAST('DCIM' AS BLOB), 'utf8', \
             zeroblob(32), x'0101010101010101010101010101010101010101010101010101010101010101', \
             0, 1 \
         ); \
         INSERT INTO scan_runs ( \
             id, run_key, volume_id, capability_profile_id, root_relative_path, \
             root_path_key, scan_mode, state, created_at_ms, updated_at_ms \
         ) VALUES (1, 'run', 1, 1, 'DCIM', zeroblob(32), 'full', 'queued', 1, 1); \
         INSERT INTO scan_run_roots ( \
             scan_run_id, volume_id, capability_profile_id, path_semantics_version, \
             relative_path_raw, path_encoding, semantic_path_key, created_at_ms \
         ) VALUES (1, 1, 1, 1, CAST('DCIM' AS BLOB), 'utf8', zeroblob(32), 1); \
         INSERT INTO scan_job_runs ( \
             scan_job_id, scan_run_id, volume_id, attempt_number, created_at_ms \
         ) VALUES (1, 1, 1, 1, 1); \
         UPDATE scan_jobs SET active_scan_run_id = 1 WHERE id = 1; \
         UPDATE scan_jobs \
            SET state = 'running', state_version = state_version + 1 \
          WHERE id = 1;",
    )?;

    let error = connection
        .execute(
            "UPDATE scan_runs \
                SET state = 'running', state_version = state_version + 1, started_at_ms = 2 \
              WHERE id = 1",
            [],
        )
        .expect_err("run entered running without a scan_run_sessions row");
    assert!(error.to_string().contains("current bound session"));

    connection.execute_batch(
        "INSERT INTO scan_run_sessions ( \
             scan_run_id, scan_job_id, volume_id, capability_profile_id, \
             namespace_profile_id, mount_session_key, mount_relative_root_raw, \
             path_encoding, stable_root_path_key, root_scope_key, \
             root_object_signature, created_at_ms \
         ) VALUES ( \
             1, 1, 1, 1, 1, \
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
             CAST('DCIM' AS BLOB), 'utf8', zeroblob(32), \
             x'0101010101010101010101010101010101010101010101010101010101010101', \
             x'0202020202020202020202020202020202020202020202020202020202020202', 1 \
         ); \
         UPDATE scan_runs \
            SET state = 'running', state_version = state_version + 1, started_at_ms = 2 \
          WHERE id = 1; \
         INSERT INTO media_files ( \
             id, volume_id, first_seen_scan_run_id, last_seen_scan_run_id, \
             relative_path, path_key, entry_type, media_kind, lifecycle_state, \
             size_bytes, created_at_ms, updated_at_ms \
         ) VALUES ( \
             1, 1, 1, 1, 'DCIM/photo.jpg', \
             x'0303030303030303030303030303030303030303030303030303030303030303', \
             'regular', 'photo', 'present', 10, 2, 2 \
         ); \
         INSERT INTO media_file_paths ( \
             volume_id, media_file_id, relative_path_raw, path_encoding, \
             created_at_ms, updated_at_ms \
         ) VALUES (1, 1, CAST('DCIM/photo.jpg' AS BLOB), 'utf8', 2, 2); \
         INSERT INTO media_path_keys ( \
             volume_id, media_file_id, capability_profile_id, path_semantics_version, \
             semantic_path_key, created_at_ms \
         ) VALUES ( \
             1, 1, 1, 1, \
             x'0303030303030303030303030303030303030303030303030303030303030303', 2 \
         ); \
         INSERT INTO media_namespace_paths ( \
             id, volume_id, media_file_id, namespace_profile_id, stable_path_key, \
             mount_relative_path_raw, path_encoding, display_path, created_at_ms \
         ) VALUES ( \
             1, 1, 1, 1, \
             x'0303030303030303030303030303030303030303030303030303030303030303', \
             CAST('DCIM/photo.jpg' AS BLOB), 'utf8', 'DCIM/photo.jpg', 2 \
         ); \
         INSERT INTO media_observation_snapshots ( \
             id, volume_id, scan_run_id, media_namespace_path_id, media_file_id, \
             namespace_profile_id, capability_profile_id, root_relative_path_raw, \
             path_encoding, display_path, source_signature, stat_signature_version, \
             file_object_key, native_file_id, native_file_generation, file_mode, \
             entry_type, size_bytes, allocated_bytes, link_count, is_sparse, \
             may_share_content, modified_time_seconds, modified_time_nanoseconds, \
             changed_time_seconds, changed_time_nanoseconds, \
             timestamp_storage_unit_ns, timestamp_granularity_ns, observed_at_ms \
         ) VALUES ( \
             1, 1, 1, 1, 1, 1, 1, CAST('photo.jpg' AS BLOB), 'utf8', 'photo.jpg', \
             x'1111111111111111111111111111111111111111111111111111111111111111', \
             1, \
             x'1212121212121212121212121212121212121212121212121212121212121212', \
             x'01', 1, 33188, 'regular', 10, 10, 1, 0, 0, 1, 0, 1, 0, 1, 1, 2 \
         ); \
         INSERT INTO scan_stage_seals ( \
             scan_run_id, volume_id, stage, item_count, logical_bytes, sealed_at_ms \
         ) VALUES (1, 1, 'enumeration', 1, 10, 3); \
         INSERT INTO scan_stage_seals ( \
             scan_run_id, volume_id, stage, item_count, logical_bytes, sealed_at_ms \
         ) VALUES (1, 1, 'sampling', 0, 0, 4); \
         INSERT INTO observation_fingerprints ( \
             id, volume_id, scan_run_id, media_observation_snapshot_id, \
             fingerprint_kind, algorithm, algorithm_version, parameters_hash, \
             read_origin, source_signature_before, source_signature_after, digest, \
             observed_size_bytes, bytes_read, reached_expected_eof, \
             completed_at_ms, created_at_ms \
         ) VALUES ( \
             1, 1, 1, 1, 'exact_bytes', 'blake3', 1, zeroblob(32), \
             'full_hash_read', \
             x'1111111111111111111111111111111111111111111111111111111111111111', \
             x'1111111111111111111111111111111111111111111111111111111111111111', \
             x'aa', 10, 10, 1, 4, 4 \
         ); \
         INSERT INTO scan_stage_seals ( \
             scan_run_id, volume_id, stage, item_count, logical_bytes, sealed_at_ms \
         ) VALUES (1, 1, 'full_hash', 1, 10, 5);",
    )?;

    let preverified_error = connection
        .execute(
            "INSERT INTO exact_group_builds ( \
                 build_key, volume_id, scan_run_id, representative_observation_id, \
                 representative_fingerprint_id, expected_member_count, expected_edge_count, \
                 expected_manifest_digest, state, group_key, independent_file_count, \
                 logical_reclaimable_bytes, created_at_ms, finalized_at_ms \
             ) VALUES ( \
                 zeroblob(32), 1, 1, 1, 1, 2, 1, zeroblob(32), 'verified', \
                 x'5151515151515151515151515151515151515151515151515151515151515151', \
                 1, 0, 5, 5 \
             )",
            [],
        )
        .expect_err("verified exact group was inserted without a draft manifest or edges");
    assert!(preverified_error
        .to_string()
        .contains("current exact representative evidence"));

    let duplicate_error = connection
        .execute(
            "INSERT INTO observation_fingerprints ( \
                 volume_id, scan_run_id, media_observation_snapshot_id, fingerprint_kind, \
                 algorithm, algorithm_version, parameters_hash, read_origin, \
                 source_signature_before, source_signature_after, digest, \
                 observed_size_bytes, bytes_read, reached_expected_eof, \
                 completed_at_ms, created_at_ms \
             ) VALUES ( \
                 1, 1, 1, 'exact_bytes', 'blake3', 1, zeroblob(32), \
                 'exact_compare_read', \
                 x'1111111111111111111111111111111111111111111111111111111111111111', \
                 x'1111111111111111111111111111111111111111111111111111111111111111', \
                 x'bb', 10, 10, 1, 5, 5 \
             )",
            [],
        )
        .expect_err("same logical fingerprint was accepted with a second read origin");
    assert!(duplicate_error
        .to_string()
        .contains("UNIQUE constraint failed"));
    Ok(())
}
