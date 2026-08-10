use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::error::{Result, StoreError};

pub(crate) const APPLICATION_ID: i32 = 0x4755_5949; // ASCII "GUYI"
pub(crate) const LATEST_SCHEMA_VERSION: i64 = 4;

const INITIAL_MIGRATION: &str = include_str!("migrations/0001_init.sql");

const STORE_MIGRATION: &str = include_str!("migrations/0002_store_runtime.sql");
const STORE_HARDENING_MIGRATION: &str = include_str!("migrations/0003_store_hardening.sql");
const EVIDENCE_BINDING_MIGRATION: &str = include_str!("migrations/0004_evidence_binding.sql");

const REGISTRY_SQL: &str = r#"
CREATE TABLE guiying_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    checksum BLOB NOT NULL CHECK (length(checksum) = 32),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
) STRICT;
"#;

const MAX_SCHEMA_OBJECTS: usize = 512;
const MAX_SCHEMA_SQL_BYTES: i64 = 1024 * 1024;
const MAX_SCHEMA_TOTAL_SQL_BYTES: i64 = 16 * 1024 * 1024;
const MAX_SCHEMA_NAME_BYTES: i64 = 1_024;

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
    strips_embedded_transaction: bool,
}

const MIGRATIONS: [Migration; 4] = [
    Migration {
        version: 1,
        name: "initial_data_model",
        sql: INITIAL_MIGRATION,
        strips_embedded_transaction: true,
    },
    Migration {
        version: 2,
        name: "store_runtime",
        sql: STORE_MIGRATION,
        strips_embedded_transaction: false,
    },
    Migration {
        version: 3,
        name: "store_hardening",
        sql: STORE_HARDENING_MIGRATION,
        strips_embedded_transaction: false,
    },
    Migration {
        version: 4,
        name: "evidence_binding",
        sql: EVIDENCE_BINDING_MIGRATION,
        strips_embedded_transaction: false,
    },
];

pub(crate) fn migrate(connection: &mut Connection, now_ms: i64) -> Result<()> {
    if now_ms < 0 {
        return Err(StoreError::invalid_input(
            "now_ms",
            "migration timestamp must be non-negative",
        ));
    }

    let registry_exists = object_exists(connection, "table", "guiying_schema_migrations")?;
    if !registry_exists {
        if has_user_schema_objects(connection)? {
            return Err(StoreError::UnmanagedSchema);
        }
        apply_migration(connection, &MIGRATIONS[0], now_ms, true)?;
    }

    validate_application_id(connection)?;
    let applied = read_registry(connection)?;
    validate_registry(&applied)?;

    let current_version = read_user_version(connection)?;
    let registry_version = applied.keys().next_back().copied().unwrap_or(0);
    if current_version != registry_version {
        return Err(StoreError::MigrationHistoryMismatch(format!(
            "PRAGMA user_version is {current_version}, registry ends at {registry_version}"
        )));
    }
    if current_version > LATEST_SCHEMA_VERSION {
        return Err(StoreError::DatabaseTooNew {
            observed: current_version,
            supported: LATEST_SCHEMA_VERSION,
        });
    }

    validate_runtime_invariants(connection, current_version)?;
    crate::repository::validate_capability_profile_hashes(connection, current_version)?;

    for migration in MIGRATIONS
        .iter()
        .filter(|item| item.version > current_version)
    {
        apply_migration(connection, migration, now_ms, false)?;
    }

    let final_version = read_user_version(connection)?;
    if final_version != LATEST_SCHEMA_VERSION {
        return Err(StoreError::MigrationHistoryMismatch(format!(
            "migration stopped at version {final_version}; expected {LATEST_SCHEMA_VERSION}"
        )));
    }
    validate_registry(&read_registry(connection)?)?;
    validate_runtime_invariants(connection, final_version)?;
    crate::repository::validate_capability_profile_hashes(connection, final_version)
}

/// Validates ownership markers, migration history, and the actual safety
/// schema without executing a write-capable PRAGMA or migration.
pub(crate) fn preflight_existing(connection: &Connection) -> Result<i64> {
    if !object_exists(connection, "table", "guiying_schema_migrations")? {
        return Err(StoreError::UnmanagedSchema);
    }
    validate_application_id(connection)?;
    let applied = read_registry(connection)?;
    validate_registry(&applied)?;
    let current_version = read_user_version(connection)?;
    let registry_version = applied.keys().next_back().copied().unwrap_or(0);
    if current_version != registry_version {
        return Err(StoreError::MigrationHistoryMismatch(format!(
            "PRAGMA user_version is {current_version}, registry ends at {registry_version}"
        )));
    }
    if current_version == 0 {
        return Err(StoreError::MigrationHistoryMismatch(
            "managed database has no applied migration".into(),
        ));
    }
    if current_version > LATEST_SCHEMA_VERSION {
        return Err(StoreError::DatabaseTooNew {
            observed: current_version,
            supported: LATEST_SCHEMA_VERSION,
        });
    }
    validate_schema_manifest(connection, current_version)?;
    validate_runtime_invariants(connection, current_version)?;
    crate::repository::validate_capability_profile_hashes(connection, current_version)?;
    Ok(current_version)
}

pub(crate) fn validate_current_schema(connection: &Connection) -> Result<()> {
    validate_application_id(connection)?;
    let version = read_user_version(connection)?;
    if version > LATEST_SCHEMA_VERSION {
        return Err(StoreError::DatabaseTooNew {
            observed: version,
            supported: LATEST_SCHEMA_VERSION,
        });
    }
    if version != LATEST_SCHEMA_VERSION {
        return Err(StoreError::MigrationHistoryMismatch(format!(
            "schema version is {version}; expected {LATEST_SCHEMA_VERSION}"
        )));
    }
    validate_registry(&read_registry(connection)?)?;
    validate_schema_manifest(connection, version)?;
    validate_runtime_invariants(connection, version)?;
    crate::repository::validate_capability_profile_hashes(connection, version)
}

fn validate_runtime_invariants(connection: &Connection, version: i64) -> Result<()> {
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM volumes \
             WHERE (identity_strength = 'strong' AND ( \
                       (marker_uuid IS NULL OR length(CAST(marker_uuid AS BLOB)) = 0) \
                       AND (native_uuid IS NULL OR length(CAST(native_uuid AS BLOB)) = 0) \
                   )) \
                OR (marker_uuid IS NOT NULL AND length(CAST(marker_uuid AS BLOB)) = 0) \
                OR (native_uuid IS NOT NULL AND length(CAST(native_uuid AS BLOB)) = 0) \
         )",
        "volume has invalid strong-identity evidence",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM volumes AS left_volume \
             JOIN volumes AS right_volume \
               ON right_volume.id > left_volume.id \
              AND right_volume.identity_key <> left_volume.identity_key \
              AND ((left_volume.marker_uuid IS NOT NULL \
                    AND right_volume.marker_uuid = left_volume.marker_uuid) \
                OR (left_volume.native_uuid IS NOT NULL \
                    AND right_volume.native_uuid = left_volume.native_uuid)) \
         )",
        "strong volume identifier aliases more than one identity key",
    )?;
    validate_stored_value_bounds(connection, version)?;
    validate_operation_item_paths(connection)?;
    if version < 2 {
        return Ok(());
    }

    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_job_runs AS binding \
             JOIN scan_jobs AS job \
               ON job.id = binding.scan_job_id AND job.volume_id = binding.volume_id \
             JOIN scan_runs AS run \
               ON run.id = binding.scan_run_id AND run.volume_id = binding.volume_id \
             WHERE job.root_relative_path <> run.root_relative_path \
                OR job.root_path_key <> run.root_path_key \
         )",
        "scan job/run binding has mismatched root evidence",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_job_runs AS binding \
             JOIN scan_runs AS run ON run.id = binding.scan_run_id \
             GROUP BY binding.scan_job_id \
             HAVING MIN(run.capability_profile_id) <> MAX(run.capability_profile_id) \
         )",
        "scan job history mixes capability profiles",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_jobs AS job \
             WHERE job.active_scan_run_id IS NOT NULL \
               AND NOT EXISTS ( \
                   SELECT 1 FROM scan_job_runs AS binding \
                   WHERE binding.scan_job_id = job.id \
                     AND binding.scan_run_id = job.active_scan_run_id \
                     AND binding.volume_id = job.volume_id \
               ) \
         )",
        "active scan run is not bound to its job",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_jobs AS job \
             LEFT JOIN scan_runs AS run \
               ON run.id = job.active_scan_run_id AND run.volume_id = job.volume_id \
             WHERE NOT ( \
                 (job.state = 'queued' AND (run.id IS NULL OR run.state = 'queued')) \
                 OR (job.state = 'running' AND run.state = 'running') \
                 OR (job.state = 'paused' AND run.state = 'paused') \
                 OR (job.state = 'completed' AND run.state = 'completed') \
                 OR (job.state = 'failed' AND run.state IN ('failed', 'interrupted', 'queued')) \
                 OR (job.state = 'cancelled' AND (run.id IS NULL OR run.state = 'cancelled')) \
             ) \
         )",
        "scan job and active run states are inconsistent",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_runs \
             WHERE (state IN ('failed', 'interrupted') AND ( \
                       last_error_code IS NULL OR last_error_message IS NULL \
                       OR length(CAST(last_error_code AS BLOB)) NOT BETWEEN 1 AND 1024 \
                       OR length(CAST(last_error_message AS BLOB)) NOT BETWEEN 1 AND 65536 \
                   )) \
                OR (state NOT IN ('failed', 'interrupted') AND ( \
                       last_error_code IS NOT NULL OR last_error_message IS NOT NULL \
                   )) \
         )",
        "scan run last-error evidence is inconsistent with its state",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_runs \
             WHERE fingerprinted_count > discovered_count \
         )",
        "scan progress has more fingerprints than discovered files",
    )?;

    if version >= 4 {
        reject_if_exists(
            connection,
            "SELECT EXISTS( \
                 SELECT 1 FROM scan_jobs AS job \
                 LEFT JOIN scan_job_roots AS root ON root.scan_job_id = job.id \
                 WHERE root.scan_job_id IS NULL \
                    OR root.volume_id <> job.volume_id \
                    OR root.semantic_path_key <> job.root_path_key \
                    OR (root.path_encoding = 'utf8' \
                        AND root.relative_path_raw <> CAST(job.root_relative_path AS BLOB)) \
             )",
            "scan job is missing bound raw root evidence",
        )?;
        reject_if_exists(
            connection,
            "SELECT EXISTS( \
                 SELECT 1 FROM scan_runs AS run \
                 LEFT JOIN scan_run_roots AS root ON root.scan_run_id = run.id \
                 WHERE root.scan_run_id IS NULL \
                    OR root.volume_id <> run.volume_id \
                    OR root.capability_profile_id <> run.capability_profile_id \
                    OR root.semantic_path_key <> run.root_path_key \
                    OR (root.path_encoding = 'utf8' \
                        AND root.relative_path_raw <> CAST(run.root_relative_path AS BLOB)) \
             )",
            "scan run is missing bound raw root evidence",
        )?;
        reject_if_exists(
            connection,
            "SELECT EXISTS( \
                 SELECT 1 \
                 FROM scan_job_runs AS binding \
                 JOIN scan_job_roots AS job_root \
                   ON job_root.scan_job_id = binding.scan_job_id \
                  AND job_root.volume_id = binding.volume_id \
                 JOIN scan_run_roots AS run_root \
                   ON run_root.scan_run_id = binding.scan_run_id \
                  AND run_root.volume_id = binding.volume_id \
                 WHERE job_root.capability_profile_id IS NULL \
                    OR job_root.capability_profile_id <> run_root.capability_profile_id \
                    OR job_root.path_semantics_version <> run_root.path_semantics_version \
                    OR job_root.relative_path_raw <> run_root.relative_path_raw \
                    OR job_root.path_encoding <> run_root.path_encoding \
                    OR job_root.semantic_path_key <> run_root.semantic_path_key \
             )",
            "scan job/run binding has mismatched raw path-semantics evidence",
        )?;
        reject_if_exists(
            connection,
            "SELECT EXISTS( \
                 SELECT 1 FROM media_files AS media \
                 LEFT JOIN media_path_keys AS path \
                   ON path.volume_id = media.volume_id AND path.media_file_id = media.id \
                 WHERE path.media_file_id IS NULL \
             )",
            "media file is missing a path-semantics binding",
        )?;
    }
    validate_stored_path_evidence(connection, version)?;
    Ok(())
}

fn validate_stored_value_bounds(connection: &Connection, version: i64) -> Result<()> {
    let identifier = crate::model::MAX_IDENTIFIER_BYTES;
    let text = crate::model::MAX_TEXT_BYTES;
    let path = crate::model::MAX_PATH_BYTES;
    let json = crate::model::MAX_JSON_BYTES;
    let report = crate::model::MAX_SCAN_REPORT_JSON_BYTES;
    let opaque = crate::model::MAX_OPAQUE_BLOB_BYTES;
    let path_key = crate::model::PathKey::MAX_BYTES;

    let checks = [
        (
            "volumes",
            format!(
                "length(CAST(identity_key AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                 OR length(CAST(filesystem_type AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                 OR (display_name IS NOT NULL AND length(CAST(display_name AS BLOB)) NOT BETWEEN 1 AND {text}) \
                 OR (marker_uuid IS NOT NULL AND length(CAST(marker_uuid AS BLOB)) NOT BETWEEN 1 AND {identifier}) \
                 OR (native_uuid IS NOT NULL AND length(CAST(native_uuid AS BLOB)) NOT BETWEEN 1 AND {identifier}) \
                 OR (mount_source IS NOT NULL AND length(CAST(mount_source AS BLOB)) NOT BETWEEN 1 AND {path}) \
                 OR (last_mount_path IS NOT NULL AND length(CAST(last_mount_path AS BLOB)) NOT BETWEEN 1 AND {path}) \
                 OR (transport IS NOT NULL AND length(CAST(transport AS BLOB)) NOT BETWEEN 1 AND {identifier})"
            ),
        ),
        (
            "capability_profiles",
            format!(
                "length(CAST(os_build AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                 OR (driver_name IS NOT NULL AND length(CAST(driver_name AS BLOB)) NOT BETWEEN 1 AND {identifier}) \
                 OR (driver_version IS NOT NULL AND length(CAST(driver_version AS BLOB)) NOT BETWEEN 1 AND {identifier}) \
                 OR (raw_capabilities_json IS NOT NULL AND length(CAST(raw_capabilities_json AS BLOB)) > {json})"
            ),
        ),
        (
            "scan_runs",
            format!(
                "length(CAST(run_key AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                 OR length(CAST(root_relative_path AS BLOB)) > {path} \
                 OR length(root_path_key) NOT BETWEEN 1 AND {path_key} \
                 OR (config_json IS NOT NULL AND length(CAST(config_json AS BLOB)) > {json}) \
                 OR (last_error_code IS NOT NULL AND length(CAST(last_error_code AS BLOB)) > {identifier}) \
                 OR (last_error_message IS NOT NULL AND length(CAST(last_error_message AS BLOB)) > {text})"
            ),
        ),
        (
            "media_files",
            format!(
                "length(CAST(relative_path AS BLOB)) NOT BETWEEN 1 AND {path} \
                 OR length(path_key) NOT BETWEEN 1 AND {path_key} \
                 OR length(CAST(entry_type AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                 OR length(CAST(media_kind AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                 OR length(CAST(lifecycle_state AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                 OR (mime_type IS NOT NULL AND length(CAST(mime_type AS BLOB)) NOT BETWEEN 1 AND {identifier}) \
                 OR (file_extension IS NOT NULL AND length(CAST(file_extension AS BLOB)) NOT BETWEEN 1 AND {identifier}) \
                 OR (native_file_id IS NOT NULL AND length(native_file_id) > {opaque}) \
                 OR (metadata_json IS NOT NULL AND length(CAST(metadata_json AS BLOB)) > {json})"
            ),
        ),
        (
            "operation_items",
            format!(
                "length(CAST(item_key AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                 OR length(CAST(source_relative_path_snapshot AS BLOB)) NOT BETWEEN 1 AND {path} \
                 OR length(source_relative_path_raw) NOT BETWEEN 1 AND {path} \
                 OR (destination_relative_path IS NOT NULL AND length(CAST(destination_relative_path AS BLOB)) NOT BETWEEN 1 AND {path}) \
                 OR (destination_relative_path_raw IS NOT NULL AND length(destination_relative_path_raw) NOT BETWEEN 1 AND {path})"
            ),
        ),
    ];
    for (table, predicate) in checks {
        reject_if_exists(
            connection,
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {predicate})"),
            "stored row exceeds a repository value bound",
        )?;
    }

    if version >= 2 {
        for (table, predicate) in [
            (
                "scan_jobs",
                format!(
                    "length(CAST(job_key AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                     OR length(CAST(root_relative_path AS BLOB)) > {path} \
                     OR length(root_path_key) NOT BETWEEN 1 AND {path_key} \
                     OR (config_json IS NOT NULL AND length(CAST(config_json AS BLOB)) > {json})"
                ),
            ),
            (
                "media_file_paths",
                format!("length(relative_path_raw) NOT BETWEEN 1 AND {path}"),
            ),
            (
                "scan_issues",
                format!(
                    "length(CAST(issue_key AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                     OR length(CAST(stage AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                     OR length(CAST(code AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                     OR length(CAST(message AS BLOB)) NOT BETWEEN 1 AND {text} \
                     OR (details_json IS NOT NULL AND length(CAST(details_json AS BLOB)) > {json})"
                ),
            ),
            (
                "scan_reports",
                format!(
                    "length(CAST(report_key AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                     OR length(CAST(report_json AS BLOB)) > {report}"
                ),
            ),
        ] {
            reject_if_exists(
                connection,
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {predicate})"),
                "stored runtime row exceeds a repository value bound",
            )?;
        }
    }
    if version >= 3 {
        reject_if_exists(
            connection,
            &format!(
                "SELECT EXISTS(SELECT 1 FROM scan_checkpoints \
                 WHERE length(CAST(cursor_json AS BLOB)) > {json})"
            ),
            "stored checkpoint exceeds the cursor bound",
        )?;
    }
    if version >= 4 {
        reject_if_exists(
            connection,
            &format!(
                "SELECT EXISTS(SELECT 1 FROM capability_profiles \
                 WHERE mount_session_key IS NOT NULL \
                   AND length(CAST(mount_session_key AS BLOB)) NOT BETWEEN 1 AND {identifier})"
            ),
            "stored capability session key exceeds a repository value bound",
        )?;
        for table in ["scan_job_roots", "scan_run_roots"] {
            reject_if_exists(
                connection,
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM {table} \
                     WHERE length(relative_path_raw) > {path} \
                        OR length(semantic_path_key) NOT BETWEEN 1 AND {path_key})"
                ),
                "stored root evidence exceeds a repository value bound",
            )?;
        }
        reject_if_exists(
            connection,
            &format!(
                "SELECT EXISTS(SELECT 1 FROM media_file_observations \
                 WHERE length(CAST(relative_path AS BLOB)) NOT BETWEEN 1 AND {path} \
                    OR length(relative_path_raw) NOT BETWEEN 1 AND {path} \
                    OR length(semantic_path_key) NOT BETWEEN 1 AND {path_key})"
            ),
            "stored media observation exceeds a repository value bound",
        )?;
    }
    Ok(())
}

fn validate_stored_path_evidence(connection: &Connection, version: i64) -> Result<()> {
    if version < 4 {
        for table in ["scan_jobs", "scan_runs"] {
            let sql = format!("SELECT id, root_relative_path FROM {table} ORDER BY id");
            let mut statement = connection.prepare(&sql)?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let id = row.get::<_, i64>(0)?;
                let display = row.get::<_, String>(1)?;
                validate_path_row(table, id, &display, display.as_bytes(), "utf8", true)?;
                crate::repository::validate_legacy_portable_utf8_path(&display, true).map_err(
                    |error| {
                        StoreError::MigrationHistoryMismatch(format!(
                            "{table} id {id} has platform-ambiguous legacy root evidence: {error}"
                        ))
                    },
                )?;
            }
        }

        let mut statement = connection.prepare(
            "SELECT media.id, media.relative_path, path.relative_path_raw, path.path_encoding \
             FROM media_file_paths AS path \
             JOIN media_files AS media \
               ON media.id = path.media_file_id AND media.volume_id = path.volume_id \
             ORDER BY media.id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id = row.get::<_, i64>(0)?;
            let display = row.get::<_, String>(1)?;
            let raw = row.get::<_, Vec<u8>>(2)?;
            let stored_encoding = row.get::<_, String>(3)?;
            let encoding = if version == 2 && stored_encoding == "windows_wtf16le" {
                "windows_utf16_le"
            } else {
                stored_encoding.as_str()
            };
            validate_path_row("media_file_paths", id, &display, &raw, encoding, false)?;
            if encoding == "utf8" {
                crate::repository::validate_legacy_portable_utf8_path(&display, false).map_err(
                    |error| {
                        StoreError::MigrationHistoryMismatch(format!(
                            "media_file_paths id {id} has platform-ambiguous legacy path evidence: {error}"
                        ))
                    },
                )?;
            }
        }
        return Ok(());
    }

    for (table, owner_table, owner_id, allow_empty) in [
        ("scan_job_roots", "scan_jobs", "scan_job_id", true),
        ("scan_run_roots", "scan_runs", "scan_run_id", true),
    ] {
        let sql = format!(
            "SELECT owner.id, owner.root_relative_path, root.relative_path_raw, root.path_encoding \
             FROM {table} AS root \
             JOIN {owner_table} AS owner ON owner.id = root.{owner_id} \
             ORDER BY owner.id"
        );
        let mut statement = connection.prepare(&sql)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            validate_path_row(
                table,
                row.get(0)?,
                &row.get::<_, String>(1)?,
                &row.get::<_, Vec<u8>>(2)?,
                &row.get::<_, String>(3)?,
                allow_empty,
            )?;
        }
    }

    let mut statement = connection.prepare(
        "SELECT id, relative_path, relative_path_raw, path_encoding \
         FROM media_file_observations ORDER BY id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        validate_path_row(
            "media_file_observations",
            row.get(0)?,
            &row.get::<_, String>(1)?,
            &row.get::<_, Vec<u8>>(2)?,
            &row.get::<_, String>(3)?,
            false,
        )?;
    }

    let mut statement = connection.prepare(
        "SELECT media.id, media.relative_path, path.relative_path_raw, path.path_encoding \
         FROM media_file_paths AS path \
         JOIN media_files AS media \
           ON media.id = path.media_file_id AND media.volume_id = path.volume_id \
         ORDER BY media.id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        validate_path_row(
            "media_file_paths",
            row.get(0)?,
            &row.get::<_, String>(1)?,
            &row.get::<_, Vec<u8>>(2)?,
            &row.get::<_, String>(3)?,
            false,
        )?;
    }
    Ok(())
}

fn validate_operation_item_paths(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT id, source_relative_path_snapshot, source_relative_path_raw, \
                source_path_encoding, destination_relative_path, \
                destination_relative_path_raw, destination_path_encoding \
         FROM operation_items ORDER BY id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let id = row.get::<_, i64>(0)?;
        let source_encoding = row.get::<_, String>(3)?;
        if source_encoding == "windows_utf16le" {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "operation_items id {id} uses Windows path evidence, which is unsupported until the executor binds a Windows namespace profile"
            )));
        }
        validate_path_row(
            "operation_items.source",
            id,
            &row.get::<_, String>(1)?,
            &row.get::<_, Vec<u8>>(2)?,
            &source_encoding,
            false,
        )?;

        let destination_display = row.get::<_, Option<String>>(4)?;
        let destination_raw = row.get::<_, Option<Vec<u8>>>(5)?;
        let destination_encoding = row.get::<_, Option<String>>(6)?;
        match (destination_display, destination_raw, destination_encoding) {
            (None, None, None) => {}
            (Some(display), Some(raw), Some(encoding)) => {
                if encoding == "windows_utf16le" {
                    return Err(StoreError::MigrationHistoryMismatch(format!(
                        "operation_items id {id} uses an unsupported Windows destination path"
                    )));
                }
                validate_path_row(
                    "operation_items.destination",
                    id,
                    &display,
                    &raw,
                    &encoding,
                    false,
                )?;
            }
            _ => {
                return Err(StoreError::MigrationHistoryMismatch(format!(
                    "operation_items id {id} has a partial destination path envelope"
                )));
            }
        }
    }
    Ok(())
}

fn validate_path_row(
    entity: &str,
    id: i64,
    display: &str,
    raw: &[u8],
    encoding: &str,
    allow_empty: bool,
) -> Result<()> {
    crate::repository::validate_persisted_path_evidence(display, raw, encoding, allow_empty)
        .map_err(|error| {
            StoreError::MigrationHistoryMismatch(format!(
                "{entity} id {id} has unsafe or non-canonical path evidence: {error}"
            ))
        })
}

fn reject_if_exists(connection: &Connection, sql: &str, reason: &'static str) -> Result<()> {
    let exists = connection.query_row(sql, [], |row| row.get::<_, bool>(0))?;
    if exists {
        return Err(StoreError::MigrationHistoryMismatch(reason.into()));
    }
    Ok(())
}

fn apply_migration(
    connection: &mut Connection,
    migration: &Migration,
    now_ms: i64,
    create_registry: bool,
) -> Result<()> {
    let body = if migration.strips_embedded_transaction {
        strip_transaction(migration.sql)?
    } else {
        migration.sql
    };
    let checksum = migration_checksum(migration.sql);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if create_registry {
        transaction.execute_batch(REGISTRY_SQL)?;
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    }
    if migration.version == 4 {
        crate::repository::upgrade_capability_profile_hashes_to_v2(&transaction)?;
    }
    transaction.execute_batch(body)?;
    transaction.execute(
        "INSERT INTO guiying_schema_migrations (version, name, checksum, applied_at_ms)\
         VALUES (?1, ?2, ?3, ?4)",
        params![
            migration.version,
            migration.name,
            checksum.as_slice(),
            now_ms
        ],
    )?;
    transaction.pragma_update(None, "user_version", migration.version)?;
    transaction.commit()?;
    Ok(())
}

fn strip_transaction(sql: &'static str) -> Result<&'static str> {
    let (_, after_begin) =
        sql.split_once("\nBEGIN IMMEDIATE;\n")
            .ok_or(StoreError::MalformedMigration(
                "initial migration must contain one BEGIN IMMEDIATE boundary",
            ))?;
    let (body, trailing) =
        after_begin
            .rsplit_once("\nCOMMIT;")
            .ok_or(StoreError::MalformedMigration(
                "initial migration must end with COMMIT",
            ))?;
    if !trailing.trim().is_empty() {
        return Err(StoreError::MalformedMigration(
            "unexpected content follows initial migration COMMIT",
        ));
    }
    Ok(body)
}

fn migration_checksum(sql: &str) -> [u8; 32] {
    *blake3::hash(sql.as_bytes()).as_bytes()
}

fn read_registry(connection: &Connection) -> Result<BTreeMap<i64, (String, Vec<u8>)>> {
    let mut statement = connection.prepare(
        "SELECT version, length(CAST(name AS BLOB)), length(checksum), name, checksum \
         FROM guiying_schema_migrations ORDER BY version LIMIT ?1",
    )?;
    let read_limit = LATEST_SCHEMA_VERSION + 2;
    let mut rows = statement.query([read_limit])?;
    let mut result = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let version = row.get::<_, i64>(0)?;
        let name_bytes = row.get::<_, i64>(1)?;
        let checksum_bytes = row.get::<_, i64>(2)?;
        if !(1..=128).contains(&name_bytes) || checksum_bytes != 32 {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "migration {version} has an invalid name or checksum size"
            )));
        }
        let name = row.get::<_, String>(3)?;
        let checksum = row.get::<_, Vec<u8>>(4)?;
        result.insert(version, (name, checksum));
        if result.len() > MIGRATIONS.len() {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "migration registry contains more than {} supported entries",
                MIGRATIONS.len()
            )));
        }
    }
    Ok(result)
}

fn validate_registry(applied: &BTreeMap<i64, (String, Vec<u8>)>) -> Result<()> {
    if let Some(version) = applied.keys().next_back().copied() {
        if version > LATEST_SCHEMA_VERSION {
            return Err(StoreError::DatabaseTooNew {
                observed: version,
                supported: LATEST_SCHEMA_VERSION,
            });
        }
    }

    for version in applied.keys() {
        if !MIGRATIONS
            .iter()
            .any(|migration| migration.version == *version)
        {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "migration registry contains unknown version {version}"
            )));
        }
    }

    for (index, migration) in MIGRATIONS.iter().enumerate() {
        let expected_version = i64::try_from(index)
            .map_err(|_| StoreError::MigrationHistoryMismatch("migration index overflow".into()))?
            + 1;
        if migration.version != expected_version {
            return Err(StoreError::MigrationHistoryMismatch(
                "compiled migrations are not contiguous".into(),
            ));
        }

        let Some((name, checksum)) = applied.get(&migration.version) else {
            if applied.keys().any(|version| *version > migration.version) {
                return Err(StoreError::MigrationHistoryMismatch(format!(
                    "migration {} is missing from history",
                    migration.version
                )));
            }
            continue;
        };
        let expected_checksum = migration_checksum(migration.sql);
        if name != migration.name || checksum.as_slice() != expected_checksum {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "migration {} name or checksum differs from the compiled migration",
                migration.version
            )));
        }
    }
    Ok(())
}

fn validate_application_id(connection: &Connection) -> Result<()> {
    let observed: i32 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if observed != APPLICATION_ID {
        return Err(StoreError::ApplicationIdMismatch {
            expected: APPLICATION_ID,
            observed,
        });
    }
    Ok(())
}

fn read_user_version(connection: &Connection) -> Result<i64> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(StoreError::from)
}

fn object_exists(connection: &Connection, kind: &str, name: &str) -> Result<bool> {
    connection
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![kind, name],
            |_| Ok(true),
        )
        .optional()
        .map(|value| value.unwrap_or(false))
        .map_err(StoreError::from)
}

fn has_user_schema_objects(connection: &Connection) -> Result<bool> {
    connection
        .query_row(
            "SELECT 1 FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' \
             LIMIT 1",
            [],
            |_| Ok(true),
        )
        .optional()
        .map(|value| value.unwrap_or(false))
        .map_err(StoreError::from)
}

fn validate_schema_manifest(connection: &Connection, version: i64) -> Result<()> {
    let expected_connection = Connection::open_in_memory()?;
    expected_connection.execute_batch(REGISTRY_SQL)?;
    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version <= version)
    {
        let body = if migration.strips_embedded_transaction {
            strip_transaction(migration.sql)?
        } else {
            migration.sql
        };
        expected_connection.execute_batch(body)?;
    }

    let expected = schema_manifest(&expected_connection)?;
    let observed = schema_manifest(connection)?;
    if expected == observed {
        return Ok(());
    }

    let missing = expected
        .keys()
        .filter(|key| !observed.contains_key(*key))
        .map(schema_key)
        .collect::<Vec<_>>();
    let unexpected = observed
        .keys()
        .filter(|key| !expected.contains_key(*key))
        .map(schema_key)
        .collect::<Vec<_>>();
    let changed = expected
        .iter()
        .filter_map(|(key, expected_hash)| {
            observed
                .get(key)
                .filter(|observed_hash| *observed_hash != expected_hash)
                .map(|_| schema_key(key))
        })
        .collect::<Vec<_>>();
    Err(StoreError::SchemaManifestMismatch {
        missing,
        unexpected,
        changed,
    })
}

fn schema_manifest(connection: &Connection) -> Result<BTreeMap<(String, String), [u8; 32]>> {
    let mut statement = connection.prepare(
        "SELECT length(CAST(type AS BLOB)), length(CAST(name AS BLOB)), \
                length(CAST(sql AS BLOB)), type, name, sql FROM sqlite_schema \
         WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' \
         ORDER BY type, name",
    )?;
    let mut manifest = BTreeMap::new();
    let mut total_sql_bytes = 0_i64;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        if manifest.len() >= MAX_SCHEMA_OBJECTS {
            return Err(StoreError::SchemaManifestLimit {
                reason: format!("more than {MAX_SCHEMA_OBJECTS} explicit schema objects"),
            });
        }
        let kind_bytes = row.get::<_, i64>(0)?;
        let name_bytes = row.get::<_, i64>(1)?;
        let sql_bytes = row.get::<_, i64>(2)?;
        if !(1..=MAX_SCHEMA_NAME_BYTES).contains(&kind_bytes)
            || !(1..=MAX_SCHEMA_NAME_BYTES).contains(&name_bytes)
        {
            return Err(StoreError::SchemaManifestLimit {
                reason: "schema object type or name exceeds its bound".into(),
            });
        }
        if !(0..=MAX_SCHEMA_SQL_BYTES).contains(&sql_bytes) {
            return Err(StoreError::SchemaManifestLimit {
                reason: format!("schema object has {sql_bytes} SQL bytes"),
            });
        }
        total_sql_bytes = total_sql_bytes.checked_add(sql_bytes).ok_or_else(|| {
            StoreError::SchemaManifestLimit {
                reason: "schema SQL byte total overflowed".into(),
            }
        })?;
        if total_sql_bytes > MAX_SCHEMA_TOTAL_SQL_BYTES {
            return Err(StoreError::SchemaManifestLimit {
                reason: format!(
                    "schema SQL exceeds the {MAX_SCHEMA_TOTAL_SQL_BYTES}-byte total bound"
                ),
            });
        }
        let kind = row.get::<_, String>(3)?;
        let name = row.get::<_, String>(4)?;
        let sql = row.get::<_, String>(5)?;
        let key = (kind, name);
        if manifest
            .insert(key.clone(), migration_checksum(&sql))
            .is_some()
        {
            return Err(StoreError::SchemaManifestMismatch {
                missing: Vec::new(),
                unexpected: Vec::new(),
                changed: vec![schema_key(&key)],
            });
        }
    }
    Ok(manifest)
}

fn schema_key((kind, name): &(String, String)) -> String {
    format!("{kind}:{name}")
}

#[cfg(test)]
mod tests {
    use super::{
        apply_migration, migrate, preflight_existing, validate_current_schema, MIGRATIONS,
    };
    use crate::model::{CapabilityProfileInput, NewScanJob, PathKey};
    use crate::repository::{
        compute_legacy_capability_profile_hash, validate_capability_profile_hashes, RepositoryTx,
    };
    use rusqlite::{params, Connection};

    #[test]
    fn version_two_windows_label_is_migrated_losslessly() -> crate::Result<()> {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        apply_migration(&mut connection, &MIGRATIONS[0], 1_000, true)?;
        apply_migration(&mut connection, &MIGRATIONS[1], 1_001, false)?;
        connection.execute_batch(
            "INSERT INTO volumes ( \
                 id, identity_key, identity_strength, marker_uuid, filesystem_type, is_network, is_read_only, \
                 first_seen_at_ms, last_seen_at_ms, created_at_ms, updated_at_ms \
             ) VALUES (1, 'volume', 'strong', 'marker-volume', 'ntfs', 0, 1, 1, 1, 1, 1);",
        )?;
        insert_legacy_capability(&connection)?;
        connection.execute_batch(
            "INSERT INTO scan_runs ( \
                 id, run_key, volume_id, capability_profile_id, root_relative_path, root_path_key, \
                 scan_mode, created_at_ms, updated_at_ms \
             ) VALUES (1, 'run', 1, 1, '', x'01', 'full', 1, 1); \
             INSERT INTO media_files ( \
                 id, volume_id, first_seen_scan_run_id, last_seen_scan_run_id, relative_path, \
                 path_key, entry_type, media_kind, lifecycle_state, created_at_ms, updated_at_ms \
             ) VALUES (1, 1, 1, 1, 'photo.jpg', x'01', 'regular', 'photo', 'present', 1, 1); \
             INSERT INTO media_file_paths ( \
                 volume_id, media_file_id, relative_path_raw, path_encoding, created_at_ms, updated_at_ms \
             ) VALUES (1, 1, x'700068006F0074006F002E006A0070006700', 'windows_wtf16le', 1, 1);",
        )?;

        assert_eq!(preflight_existing(&connection)?, 2);
        apply_migration(&mut connection, &MIGRATIONS[2], 1_002, false)?;
        apply_migration(&mut connection, &MIGRATIONS[3], 1_003, false)?;
        validate_current_schema(&connection)?;
        let (encoding, raw): (String, Vec<u8>) = connection.query_row(
            "SELECT path_encoding, relative_path_raw FROM media_file_paths WHERE media_file_id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(encoding, "windows_utf16_le");
        assert_eq!(raw, hex_bytes("700068006F0074006F002E006A0070006700"));
        Ok(())
    }

    #[test]
    fn dirty_version_two_state_is_rejected_and_upgrade_rolls_back() -> crate::Result<()> {
        let corruptions = [
            "UPDATE scan_runs SET fingerprinted_count = 2, discovered_count = 1 WHERE id = 1;",
            "UPDATE scan_runs SET root_relative_path = 'different-root' WHERE id = 1;",
            "UPDATE scan_jobs SET state = 'completed' WHERE id = 1;",
            "UPDATE scan_jobs SET state = 'running', active_scan_run_id = NULL WHERE id = 1;",
        ];

        for corruption in corruptions {
            let mut connection = seeded_version_two_connection()?;
            connection.execute_batch(corruption)?;

            assert!(apply_migration(&mut connection, &MIGRATIONS[2], 1_002, false).is_err());
            let user_version: i64 =
                connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
            let registered: i64 = connection.query_row(
                "SELECT count(*) FROM guiying_schema_migrations",
                [],
                |row| row.get(0),
            )?;
            let v3_objects: i64 = connection.query_row(
                "SELECT count(*) FROM sqlite_schema \
                 WHERE name IN ('scan_checkpoints', 'trg_scan_jobs_state_binding')",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(user_version, 2);
            assert_eq!(registered, 2);
            assert_eq!(v3_objects, 0);
        }
        Ok(())
    }

    #[test]
    fn dirty_version_three_state_or_hash_is_rejected_before_v4_writes() -> crate::Result<()> {
        let corruptions = [
            "UPDATE scan_jobs SET state = 'running', state_version = 1 WHERE id = 1;",
            "UPDATE scan_runs SET last_error_code = 'unexpected' WHERE id = 1;",
            "UPDATE capability_profiles SET profile_hash = zeroblob(32) WHERE id = 1;",
        ];

        for corruption in corruptions {
            let mut connection = seeded_version_two_connection()?;
            apply_migration(&mut connection, &MIGRATIONS[2], 1_002, false)?;
            connection.execute_batch(corruption)?;

            assert!(migrate(&mut connection, 1_003).is_err());
            let user_version: i64 =
                connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
            let registered: i64 = connection.query_row(
                "SELECT count(*) FROM guiying_schema_migrations",
                [],
                |row| row.get(0),
            )?;
            let v4_objects: i64 = connection.query_row(
                "SELECT count(*) FROM sqlite_schema \
                 WHERE name IN ('scan_job_roots', 'media_file_observations')",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(user_version, 3);
            assert_eq!(registered, 3);
            assert_eq!(v4_objects, 0);
        }
        Ok(())
    }

    #[test]
    fn canonical_capability_hash_detects_v4_evidence_tampering() -> crate::Result<()> {
        let mut connection = seeded_version_two_connection()?;
        apply_migration(&mut connection, &MIGRATIONS[2], 1_002, false)?;
        apply_migration(&mut connection, &MIGRATIONS[3], 1_003, false)?;
        validate_capability_profile_hashes(&connection, 4)?;

        connection.execute_batch(
            "DROP TRIGGER trg_capability_profiles_evidence_immutable_v4; \
             UPDATE capability_profiles SET mount_session_key = 'tampered' WHERE id = 1;",
        )?;
        let error = validate_capability_profile_hashes(&connection, 4)
            .expect_err("tampered capability evidence was unexpectedly accepted");
        assert!(matches!(
            error,
            crate::StoreError::MigrationHistoryMismatch(_)
        ));
        Ok(())
    }

    #[test]
    fn mixed_historical_capability_profiles_are_rejected_before_v4() -> crate::Result<()> {
        let mut connection = seeded_version_two_connection()?;
        apply_migration(&mut connection, &MIGRATIONS[2], 1_002, false)?;

        let mut second_input = legacy_capability_input();
        second_input.driver_version = Some("second".into());
        let second_hash = compute_legacy_capability_profile_hash(&second_input)?;
        connection.execute(
            "INSERT INTO capability_profiles ( \
                 id, volume_id, profile_hash, probe_mode, probe_status, observed_at_ms, os_build, \
                 driver_version, is_current, created_at_ms \
             ) VALUES (2, 1, ?1, 'passive', 'partial', 2, 'test', 'second', 0, 2)",
            params![second_hash.as_slice()],
        )?;
        connection.execute_batch(
            "INSERT INTO scan_runs ( \
                 id, run_key, volume_id, capability_profile_id, root_relative_path, root_path_key, \
                 scan_mode, created_at_ms, updated_at_ms \
             ) VALUES (2, 'run-2', 1, 2, '', x'01', 'full', 2, 2); \
             INSERT INTO scan_job_runs ( \
                 scan_job_id, scan_run_id, volume_id, attempt_number, created_at_ms \
             ) VALUES (1, 2, 1, 2, 2);",
        )?;

        let error = migrate(&mut connection, 1_003)
            .expect_err("mixed historical capability profiles were migrated");
        assert!(matches!(
            error,
            crate::StoreError::MigrationHistoryMismatch(_)
        ));
        assert_eq!(read_test_user_version(&connection)?, 3);
        Ok(())
    }

    #[test]
    fn legacy_utf8_mismatch_and_ambiguous_roots_are_rejected() -> crate::Result<()> {
        let corruptions = [
            "INSERT INTO media_files ( \
                 id, volume_id, first_seen_scan_run_id, last_seen_scan_run_id, relative_path, \
                 path_key, entry_type, media_kind, lifecycle_state, created_at_ms, updated_at_ms \
             ) VALUES (1, 1, 1, 1, 'photo.jpg', x'02', 'regular', 'photo', 'present', 1, 1); \
             INSERT INTO media_file_paths ( \
                 volume_id, media_file_id, relative_path_raw, path_encoding, created_at_ms, updated_at_ms \
             ) VALUES (1, 1, CAST('evil.jpg' AS BLOB), 'utf8', 1, 1);",
            "UPDATE scan_jobs SET root_relative_path = '../escape' WHERE id = 1; \
             UPDATE scan_runs SET root_relative_path = '../escape' WHERE id = 1;",
            "UPDATE scan_jobs SET root_relative_path = 'DCIM\\..\\escape' WHERE id = 1; \
             UPDATE scan_runs SET root_relative_path = 'DCIM\\..\\escape' WHERE id = 1;",
            "UPDATE scan_jobs SET root_relative_path = 'CON' WHERE id = 1; \
             UPDATE scan_runs SET root_relative_path = 'CON' WHERE id = 1;",
        ];

        for corruption in corruptions {
            let mut connection = seeded_version_two_connection()?;
            connection.execute_batch(corruption)?;
            let error = migrate(&mut connection, 1_003)
                .expect_err("unsafe legacy path evidence was migrated");
            assert!(matches!(
                error,
                crate::StoreError::MigrationHistoryMismatch(_)
            ));
            assert_eq!(read_test_user_version(&connection)?, 2);
        }
        Ok(())
    }

    #[test]
    fn legacy_unauthenticated_capabilities_are_downgraded_to_unknown() -> crate::Result<()> {
        let mut connection = seeded_version_two_connection()?;
        apply_migration(&mut connection, &MIGRATIONS[2], 1_002, false)?;
        connection.execute_batch(
            "UPDATE capability_profiles SET \
                 mount_flags = 123, can_use_hard_links = 1, can_use_clones = 1, \
                 maximum_name_bytes = 999, maximum_file_bytes = 999999 \
             WHERE id = 1;",
        )?;

        migrate(&mut connection, 1_003)?;
        let all_unknown = connection.query_row(
            "SELECT mount_flags, can_use_hard_links, can_use_clones, \
                    maximum_name_bytes, maximum_file_bytes \
             FROM capability_profiles WHERE id = 1",
            [],
            |row| {
                Ok(row.get::<_, Option<i64>>(0)?.is_none()
                    && row.get::<_, Option<i64>>(1)?.is_none()
                    && row.get::<_, Option<i64>>(2)?.is_none()
                    && row.get::<_, Option<i64>>(3)?.is_none()
                    && row.get::<_, Option<i64>>(4)?.is_none())
            },
        )?;
        assert!(all_unknown);
        validate_capability_profile_hashes(&connection, 4)?;
        Ok(())
    }

    #[test]
    fn invalid_or_aliased_legacy_volume_identity_is_rejected() -> crate::Result<()> {
        let corruptions = [
            "UPDATE volumes SET marker_uuid = NULL, native_uuid = NULL WHERE id = 1;",
            "UPDATE volumes SET native_uuid = 'duplicate-native' WHERE id = 1; \
             INSERT INTO volumes ( \
                 id, identity_key, identity_strength, marker_uuid, native_uuid, filesystem_type, \
                 is_network, is_read_only, first_seen_at_ms, last_seen_at_ms, created_at_ms, updated_at_ms \
             ) VALUES (2, 'alias', 'strong', 'marker-alias', 'duplicate-native', 'apfs', \
                       0, 0, 1, 1, 1, 1);",
        ];
        for corruption in corruptions {
            let mut connection = seeded_version_two_connection()?;
            connection.execute_batch(corruption)?;
            let error = migrate(&mut connection, 1_003)
                .expect_err("invalid legacy volume identity was migrated");
            assert!(matches!(
                error,
                crate::StoreError::MigrationHistoryMismatch(_)
            ));
            assert_eq!(read_test_user_version(&connection)?, 2);
        }
        Ok(())
    }

    #[test]
    fn migrated_legacy_profile_cannot_start_or_accept_new_roots() -> crate::Result<()> {
        let mut connection = seeded_version_two_connection()?;
        apply_migration(&mut connection, &MIGRATIONS[2], 1_002, false)?;
        migrate(&mut connection, 1_003)?;

        {
            let transaction = connection.transaction()?;
            let mut repository = RepositoryTx::new(&transaction);
            let start_error = repository
                .transition_scan_job_and_run(
                    1,
                    1,
                    1,
                    "invented-session",
                    "queued",
                    0,
                    "queued",
                    0,
                    "running",
                    "running",
                    2_000,
                    None,
                )
                .expect_err("legacy profile started a scan");
            assert!(matches!(
                start_error,
                crate::StoreError::ConcurrencyConflict { .. }
            ));
        }

        let transaction = connection.transaction()?;
        let mut repository = RepositoryTx::new(&transaction);
        let root_error = repository
            .create_scan_job(&NewScanJob {
                job_key: "new-job".into(),
                volume_id: 1,
                capability_profile_id: 1,
                root_relative_path: "DCIM".into(),
                root_relative_path_raw: b"DCIM".to_vec(),
                root_path_encoding: "utf8".into(),
                root_path_key: PathKey::from_filesystem_adapter(b"dcim".to_vec())?,
                path_semantics_version: 1,
                config: None,
                created_at_ms: 2_000,
            })
            .expect_err("legacy profile accepted a new root");
        assert!(matches!(
            root_error,
            crate::StoreError::IdempotencyConflict { .. }
        ));
        Ok(())
    }

    #[test]
    fn oversized_legacy_checkpoint_is_rejected_before_v4() -> crate::Result<()> {
        let mut connection = seeded_version_two_connection()?;
        apply_migration(&mut connection, &MIGRATIONS[2], 1_002, false)?;
        let cursor = format!("{{\"payload\":\"{}\"}}", "x".repeat(1024 * 1024));
        connection.execute(
            "INSERT INTO scan_checkpoints ( \
                 scan_run_id, volume_id, checkpoint_version, cursor_version, cursor_json, \
                 discovered_count, fingerprinted_count, error_count, logical_bytes_seen, saved_at_ms \
             ) VALUES (1, 1, 1, 1, ?1, 0, 0, 0, 0, 2)",
            [cursor],
        )?;
        let error =
            migrate(&mut connection, 1_003).expect_err("oversized legacy checkpoint was migrated");
        assert!(matches!(
            error,
            crate::StoreError::MigrationHistoryMismatch(_)
        ));
        assert_eq!(read_test_user_version(&connection)?, 3);
        Ok(())
    }

    fn seeded_version_two_connection() -> crate::Result<Connection> {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        apply_migration(&mut connection, &MIGRATIONS[0], 1_000, true)?;
        apply_migration(&mut connection, &MIGRATIONS[1], 1_001, false)?;
        connection.execute_batch(
            "INSERT INTO volumes ( \
                 id, identity_key, identity_strength, marker_uuid, filesystem_type, is_network, is_read_only, \
                 first_seen_at_ms, last_seen_at_ms, created_at_ms, updated_at_ms \
             ) VALUES (1, 'volume', 'strong', 'marker-volume', 'apfs', 0, 0, 1, 1, 1, 1);",
        )?;
        insert_legacy_capability(&connection)?;
        connection.execute_batch(
            "INSERT INTO scan_runs ( \
                 id, run_key, volume_id, capability_profile_id, root_relative_path, root_path_key, \
                 scan_mode, created_at_ms, updated_at_ms \
             ) VALUES (1, 'run', 1, 1, '', x'01', 'full', 1, 1); \
             INSERT INTO scan_jobs ( \
                 id, job_key, volume_id, root_relative_path, root_path_key, created_at_ms, updated_at_ms \
             ) VALUES (1, 'job', 1, '', x'01', 1, 1); \
             INSERT INTO scan_job_runs ( \
                 scan_job_id, scan_run_id, volume_id, attempt_number, created_at_ms \
             ) VALUES (1, 1, 1, 1, 1); \
             UPDATE scan_jobs SET active_scan_run_id = 1 WHERE id = 1;",
        )?;
        Ok(connection)
    }

    fn read_test_user_version(connection: &Connection) -> crate::Result<i64> {
        connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(crate::StoreError::from)
    }

    fn insert_legacy_capability(connection: &Connection) -> crate::Result<()> {
        let input = legacy_capability_input();
        let hash = compute_legacy_capability_profile_hash(&input)?;
        connection.execute(
            "INSERT INTO capability_profiles ( \
                 id, volume_id, profile_hash, probe_mode, probe_status, observed_at_ms, os_build, \
                 is_current, created_at_ms \
             ) VALUES (1, 1, ?1, 'passive', 'partial', 1, 'test', 1, 1)",
            params![hash.as_slice()],
        )?;
        Ok(())
    }

    fn legacy_capability_input() -> CapabilityProfileInput {
        CapabilityProfileInput {
            volume_id: 1,
            probe_mode: "passive".into(),
            probe_status: "partial".into(),
            observed_at_ms: 1,
            os_build: "test".into(),
            mount_session_key: None,
            probe_protocol_version: None,
            driver_name: None,
            driver_version: None,
            mount_flags: None,
            case_behavior: None,
            unicode_behavior: None,
            path_encoding_family: None,
            path_semantics_version: 1,
            can_read: None,
            can_write: None,
            can_rename_same_volume: None,
            can_rename_exclusive: None,
            can_no_replace: None,
            can_sync_directory: None,
            can_append_durable: None,
            single_writer: None,
            can_set_birth_time: None,
            can_set_modified_time: None,
            can_use_xattrs: None,
            can_use_hard_links: None,
            can_use_clones: None,
            has_persistent_file_ids: None,
            timestamp_granularity_ns: None,
            maximum_name_bytes: None,
            maximum_file_bytes: None,
            raw_capabilities: None,
        }
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("fixture hex is ASCII");
                u8::from_str_radix(text, 16).expect("fixture hex is valid")
            })
            .collect()
    }
}
