use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::error::{Result, StoreError};

pub(crate) const APPLICATION_ID: i32 = 0x4755_5949; // ASCII "GUYI"
pub(crate) const LATEST_SCHEMA_VERSION: i64 = 9;

const INITIAL_MIGRATION: &str = include_str!("migrations/0001_init.sql");

const STORE_MIGRATION: &str = include_str!("migrations/0002_store_runtime.sql");
const STORE_HARDENING_MIGRATION: &str = include_str!("migrations/0003_store_hardening.sql");
const EVIDENCE_BINDING_MIGRATION: &str = include_str!("migrations/0004_evidence_binding.sql");
const SESSION_BOUND_EVIDENCE_MIGRATION: &str =
    include_str!("migrations/0005_session_bound_evidence.sql");
const RUNTIME_STREAM_EVIDENCE_MIGRATION: &str =
    include_str!("migrations/0006_runtime_stream_evidence.sql");
const CAPTURE_TIME_EVIDENCE_MIGRATION: &str =
    include_str!("migrations/0007_capture_time_evidence.sql");
const RUNTIME_CONTROL_MIGRATION: &str = include_str!("migrations/0008_runtime_control.sql");
const FRESH_ATTEMPT_RECOVERY_MIGRATION: &str =
    include_str!("migrations/0009_fresh_attempt_recovery.sql");

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

const MIGRATIONS: [Migration; 9] = [
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
    Migration {
        version: 5,
        name: "session_bound_evidence",
        sql: SESSION_BOUND_EVIDENCE_MIGRATION,
        strips_embedded_transaction: false,
    },
    Migration {
        version: 6,
        name: "runtime_stream_evidence",
        sql: RUNTIME_STREAM_EVIDENCE_MIGRATION,
        strips_embedded_transaction: false,
    },
    Migration {
        version: 7,
        name: "capture_time_evidence",
        sql: CAPTURE_TIME_EVIDENCE_MIGRATION,
        strips_embedded_transaction: false,
    },
    Migration {
        version: 8,
        name: "runtime_control",
        sql: RUNTIME_CONTROL_MIGRATION,
        strips_embedded_transaction: false,
    },
    Migration {
        version: 9,
        name: "fresh_attempt_recovery",
        sql: FRESH_ATTEMPT_RECOVERY_MIGRATION,
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

/// Invalidates process-local scan sessions whenever an existing database is
/// opened by a new `Store`. File descriptors and mount bindings never survive
/// a process/connection lifetime, so persisted non-terminal state is evidence
/// to recover from, not authority to resume in place.
pub(crate) fn reconcile_stale_scan_sessions(
    connection: &mut Connection,
    now_ms: i64,
) -> Result<u64> {
    if now_ms < 0 {
        return Err(StoreError::invalid_input(
            "now_ms",
            "recovery timestamp must be non-negative",
        ));
    }
    if read_user_version(connection)? < 5 {
        return Ok(0);
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let schema_version = read_user_version(&transaction)?;
    let runtime_control_interrupted = if schema_version >= 8 {
        reconcile_runtime_control_sessions(&transaction, now_ms)?
    } else {
        0
    };
    let legacy_reconcile_sql = if schema_version >= 8 {
        "UPDATE scan_runs \
         SET state = 'interrupted', \
             state_version = state_version + 1, \
             started_at_ms = COALESCE(started_at_ms, created_at_ms), \
             finished_at_ms = MAX(created_at_ms, updated_at_ms, ?1), \
             updated_at_ms = MAX(updated_at_ms, ?1), \
             last_error_code = 'PROCESS_RESTARTED_WITH_STALE_SESSION', \
             last_error_message = \
                 'The process-local volume binding ended; start a fresh bound attempt.' \
         WHERE state IN ('queued', 'running', 'paused') \
           AND EXISTS ( \
               SELECT 1 FROM scan_run_sessions AS session \
               WHERE session.scan_run_id = scan_runs.id \
                 AND session.volume_id = scan_runs.volume_id \
           ) \
           AND NOT EXISTS ( \
               SELECT 1 FROM scan_runtime_leases AS lease \
               WHERE lease.scan_run_id = scan_runs.id \
           )"
    } else {
        "UPDATE scan_runs \
         SET state = 'interrupted', \
             state_version = state_version + 1, \
             started_at_ms = COALESCE(started_at_ms, created_at_ms), \
             finished_at_ms = MAX(created_at_ms, updated_at_ms, ?1), \
             updated_at_ms = MAX(updated_at_ms, ?1), \
             last_error_code = 'PROCESS_RESTARTED_WITH_STALE_SESSION', \
             last_error_message = \
                 'The process-local volume binding ended; start a fresh bound attempt.' \
         WHERE state IN ('queued', 'running', 'paused') \
           AND EXISTS ( \
               SELECT 1 FROM scan_run_sessions AS session \
               WHERE session.scan_run_id = scan_runs.id \
                 AND session.volume_id = scan_runs.volume_id \
           )"
    };
    let legacy_interrupted = transaction.execute(legacy_reconcile_sql, [now_ms])?;
    transaction.execute(
        "UPDATE exact_group_builds \
         SET state = 'abandoned', \
             finalized_at_ms = MAX(created_at_ms, ?1), \
             abandon_reason_code = 'PROCESS_RESTARTED', \
             abandon_reason_message = \
                 'Draft evidence cannot cross a process-local volume session.' \
         WHERE state = 'draft' \
           AND EXISTS ( \
               SELECT 1 FROM scan_runs AS run \
               JOIN scan_run_sessions AS session \
                 ON session.scan_run_id = run.id \
                AND session.volume_id = run.volume_id \
               WHERE run.id = exact_group_builds.scan_run_id \
                 AND run.volume_id = exact_group_builds.volume_id \
                 AND run.state = 'interrupted' \
                 AND run.last_error_code IN ( \
                     'PROCESS_RESTARTED_WITH_STALE_SESSION', \
                     'PROCESS_RESTARTED_WITH_RUNTIME_LEASE' \
                 ) \
           )",
        [now_ms],
    )?;
    if read_user_version(&transaction)? >= 7 {
        transaction.execute(
            "UPDATE capture_time_analysis_builds \
             SET state = 'abandoned', \
                 abandon_reason_code = 'PROCESS_RESTARTED', \
                 abandon_reason_message = \
                     'Draft time analysis cannot cross a process-local source session.', \
                 finalized_at_ms = MAX( \
                     created_at_ms, ?1, \
                     COALESCE((SELECT max(source.created_at_ms) \
                               FROM capture_time_analysis_sources AS source \
                               WHERE source.analysis_build_id = \
                                   capture_time_analysis_builds.id), created_at_ms), \
                     COALESCE((SELECT max(observation.created_at_ms) \
                               FROM capture_time_observations AS observation \
                               WHERE observation.analysis_build_id = \
                                   capture_time_analysis_builds.id), created_at_ms), \
                     COALESCE((SELECT max(candidate.created_at_ms) \
                               FROM capture_time_candidates AS candidate \
                               WHERE candidate.analysis_build_id = \
                                   capture_time_analysis_builds.id), created_at_ms), \
                     COALESCE((SELECT max(issue.created_at_ms) \
                               FROM capture_time_policy_issues AS issue \
                               WHERE issue.analysis_build_id = \
                                   capture_time_analysis_builds.id), created_at_ms), \
                     COALESCE((SELECT max(member.created_at_ms) \
                               FROM capture_time_member_assessments AS member \
                               WHERE member.analysis_build_id = \
                                   capture_time_analysis_builds.id), created_at_ms), \
                     COALESCE((SELECT max(recommendation.created_at_ms) \
                               FROM capture_time_recommendations AS recommendation \
                               WHERE recommendation.analysis_build_id = \
                                   capture_time_analysis_builds.id), created_at_ms) \
                 ) \
             WHERE state = 'draft'",
            [now_ms],
        )?;
        transaction.execute(
            "UPDATE metadata_extraction_reports \
             SET state = 'abandoned', \
                 abandon_reason_code = 'PROCESS_RESTARTED', \
                 abandon_reason_message = \
                     'Draft metadata evidence cannot cross a process-local source session.', \
                 finalized_at_ms = MAX( \
                     created_at_ms, ?1, \
                     COALESCE((SELECT max(field.created_at_ms) \
                               FROM metadata_extraction_fields AS field \
                               WHERE field.report_id = \
                                   metadata_extraction_reports.id), created_at_ms), \
                     COALESCE((SELECT max(issue.created_at_ms) \
                               FROM metadata_extraction_issues AS issue \
                               WHERE issue.report_id = \
                                   metadata_extraction_reports.id), created_at_ms), \
                     COALESCE((SELECT max(revalidation.revalidated_at_ms) \
                               FROM metadata_source_revalidations AS revalidation \
                               WHERE revalidation.report_id = \
                                   metadata_extraction_reports.id), created_at_ms) \
                 ) \
             WHERE state = 'draft'",
            [now_ms],
        )?;
        transaction.execute(
            "UPDATE scan_time_sessions \
             SET state = 'abandoned', \
                 abandon_reason_code = 'PROCESS_RESTARTED', \
                 abandon_reason_message = \
                     'The process-local core and volume bindings ended; start a fresh time stage.', \
                 finalized_at_ms = MAX( \
                     created_at_ms, ?1, \
                     COALESCE((SELECT max(report.finalized_at_ms) \
                               FROM metadata_extraction_reports AS report \
                               WHERE report.time_session_id = scan_time_sessions.id), \
                              created_at_ms), \
                     COALESCE((SELECT max(build.finalized_at_ms) \
                               FROM capture_time_analysis_builds AS build \
                               WHERE build.time_session_id = scan_time_sessions.id), \
                              created_at_ms), \
                     COALESCE((SELECT max(outcome.created_at_ms) \
                               FROM capture_time_group_outcomes AS outcome \
                               WHERE outcome.time_session_id = scan_time_sessions.id), \
                              created_at_ms) \
                 ) \
             WHERE state = 'draft'",
            [now_ms],
        )?;
    }
    transaction.execute(
        "UPDATE scan_jobs \
         SET state = 'failed', \
             state_version = state_version + 1, \
             updated_at_ms = MAX(updated_at_ms, ?1) \
         WHERE state IN ('queued', 'running', 'paused') \
           AND EXISTS ( \
               SELECT 1 FROM scan_runs AS run \
               JOIN scan_run_sessions AS session \
                 ON session.scan_run_id = run.id \
                AND session.volume_id = run.volume_id \
               WHERE run.id = scan_jobs.active_scan_run_id \
                 AND run.volume_id = scan_jobs.volume_id \
                 AND run.state = 'interrupted' \
                 AND run.last_error_code = 'PROCESS_RESTARTED_WITH_STALE_SESSION' \
           )",
        [now_ms],
    )?;
    transaction.execute(
        "UPDATE scan_jobs \
         SET state = 'failed', \
             state_version = state_version + 1, \
             updated_at_ms = MAX(updated_at_ms, ?1) \
         WHERE state = 'queued' \
           AND active_scan_run_id IS NULL \
           AND EXISTS ( \
               SELECT 1 FROM scan_job_scopes AS scope \
               WHERE scope.scan_job_id = scan_jobs.id \
                 AND scope.volume_id = scan_jobs.volume_id \
                 AND scope.origin = 'observed_v5' \
           )",
        [now_ms],
    )?;
    transaction.execute(
        "UPDATE capability_profiles \
         SET is_current = 0 \
         WHERE is_current = 1 \
           AND profile_hash_version = 2 \
           AND mount_session_key IS NOT NULL",
        [],
    )?;
    transaction.commit()?;
    let interrupted = runtime_control_interrupted
        .checked_add(u64::try_from(legacy_interrupted).map_err(|_| {
            StoreError::invalid_input("interrupted_scan_count", "row count overflow")
        })?)
        .ok_or_else(|| StoreError::invalid_input("interrupted_scan_count", "row count overflow"))?;
    Ok(interrupted)
}

/// Reconciles v8 process-local leases before the legacy stale-session pass.
/// Every unfinished lease first enters restart release, then pending
/// pause/resume intent is made terminal before the run/job state gates fire.
/// A durable pending cancel is the sole intent honoured across reopen.
/// Repository terminal transitions are one SQLite transaction, so a persisted
/// one-sided terminal pair is impossible and preflight rejects it as tampering.
fn reconcile_runtime_control_sessions(
    transaction: &rusqlite::Transaction<'_>,
    now_ms: i64,
) -> Result<u64> {
    transaction.execute(
        "UPDATE scan_runtime_leases \
         SET state = 'releasing', release_reason = 'process_restart', \
             release_started_at_ms = MAX(last_heartbeat_at_ms, ?1) \
         WHERE state = 'active' \
           AND EXISTS ( \
               SELECT 1 FROM scan_runs AS run \
               JOIN scan_jobs AS job ON job.id = scan_runtime_leases.scan_job_id \
               WHERE run.id = scan_runtime_leases.scan_run_id \
                 AND run.state IN ('running', 'paused') \
                 AND job.state IN ('running', 'paused') \
           )",
        [now_ms],
    )?;
    transaction.execute(
        "UPDATE scan_control_requests \
         SET disposition = 'interrupted', \
             acknowledged_at_ms = MAX(requested_at_ms, ?1), \
             ack_reason_code = 'PROCESS_RESTART' \
         WHERE disposition = 'pending' AND kind IN ('pause', 'resume') \
           AND EXISTS ( \
               SELECT 1 FROM scan_runtime_leases AS lease \
               WHERE lease.scan_run_id = scan_control_requests.scan_run_id \
                 AND lease.runtime_lease_key = scan_control_requests.runtime_lease_key \
                 AND lease.state = 'releasing' \
                 AND lease.release_reason = 'process_restart' \
           )",
        [now_ms],
    )?;

    transaction.execute(
        "UPDATE scan_runs \
         SET state = 'cancelled', state_version = state_version + 1, \
             started_at_ms = COALESCE(started_at_ms, created_at_ms), \
             finished_at_ms = MAX(created_at_ms, updated_at_ms, ?1), \
             updated_at_ms = MAX(updated_at_ms, ?1), \
             last_error_code = NULL, last_error_message = NULL \
         WHERE state IN ('running', 'paused') \
           AND EXISTS ( \
               SELECT 1 FROM scan_runtime_leases AS lease \
               JOIN scan_control_requests AS request \
                 ON request.scan_run_id = lease.scan_run_id \
                AND request.runtime_lease_key = lease.runtime_lease_key \
               WHERE lease.scan_run_id = scan_runs.id \
                 AND lease.state = 'releasing' \
                 AND lease.release_reason = 'process_restart' \
                 AND request.kind = 'cancel' \
                 AND request.disposition = 'pending' \
           )",
        [now_ms],
    )?;
    transaction.execute(
        "UPDATE scan_jobs \
         SET state = 'cancelled', state_version = state_version + 1, \
             updated_at_ms = MAX(updated_at_ms, ?1) \
         WHERE state IN ('running', 'paused') \
           AND EXISTS ( \
               SELECT 1 FROM scan_runtime_leases AS lease \
               JOIN scan_runs AS run ON run.id = lease.scan_run_id \
               JOIN scan_control_requests AS request \
                 ON request.scan_run_id = lease.scan_run_id \
                AND request.runtime_lease_key = lease.runtime_lease_key \
               WHERE lease.scan_job_id = scan_jobs.id \
                 AND lease.state = 'releasing' \
                 AND lease.release_reason = 'process_restart' \
                 AND run.state = 'cancelled' \
                 AND request.kind = 'cancel' \
                 AND request.disposition = 'pending' \
           )",
        [now_ms],
    )?;
    transaction.execute(
        "UPDATE scan_control_requests \
         SET disposition = 'acknowledged', \
             acknowledged_at_ms = MAX(requested_at_ms, ?1), \
             ack_job_state_version = ( \
                 SELECT job.state_version FROM scan_runtime_leases AS lease \
                 JOIN scan_jobs AS job ON job.id = lease.scan_job_id \
                 WHERE lease.scan_run_id = scan_control_requests.scan_run_id \
             ), \
             ack_run_state_version = ( \
                 SELECT run.state_version FROM scan_runs AS run \
                 WHERE run.id = scan_control_requests.scan_run_id \
             ), \
             ack_checkpoint_generation = ( \
                 SELECT max(checkpoint.generation) FROM scan_pause_checkpoints AS checkpoint \
                 WHERE checkpoint.scan_run_id = scan_control_requests.scan_run_id \
             ), \
             ack_reason_code = 'PROCESS_RESTART_CANCEL_ACK' \
         WHERE disposition = 'pending' AND kind = 'cancel' \
           AND EXISTS ( \
               SELECT 1 FROM scan_runtime_leases AS lease \
               JOIN scan_runs AS run ON run.id = lease.scan_run_id \
               JOIN scan_jobs AS job ON job.id = lease.scan_job_id \
               WHERE lease.scan_run_id = scan_control_requests.scan_run_id \
                 AND lease.runtime_lease_key = scan_control_requests.runtime_lease_key \
                 AND lease.state = 'releasing' \
                 AND lease.release_reason = 'process_restart' \
                 AND run.state = 'cancelled' AND job.state = 'cancelled' \
           )",
        [now_ms],
    )?;

    let interrupted = transaction.execute(
        "UPDATE scan_runs \
         SET state = 'interrupted', state_version = state_version + 1, \
             started_at_ms = COALESCE(started_at_ms, created_at_ms), \
             finished_at_ms = MAX(created_at_ms, updated_at_ms, ?1), \
             updated_at_ms = MAX(updated_at_ms, ?1), \
             last_error_code = 'PROCESS_RESTARTED_WITH_RUNTIME_LEASE', \
             last_error_message = \
                 'The process-local runtime lease ended; start a fresh bound attempt.' \
         WHERE state IN ('running', 'paused') \
           AND EXISTS ( \
               SELECT 1 FROM scan_runtime_leases AS lease \
               WHERE lease.scan_run_id = scan_runs.id \
                 AND lease.state = 'releasing' \
                 AND lease.release_reason = 'process_restart' \
           )",
        [now_ms],
    )?;
    transaction.execute(
        "UPDATE scan_jobs \
         SET state = 'failed', state_version = state_version + 1, \
             updated_at_ms = MAX(updated_at_ms, ?1) \
         WHERE state IN ('running', 'paused') \
           AND EXISTS ( \
               SELECT 1 FROM scan_runtime_leases AS lease \
               JOIN scan_runs AS run ON run.id = lease.scan_run_id \
               WHERE lease.scan_job_id = scan_jobs.id \
                 AND lease.state = 'releasing' \
                 AND lease.release_reason = 'process_restart' \
                 AND run.state = 'interrupted' \
           )",
        [now_ms],
    )?;
    transaction.execute(
        "UPDATE scan_runtime_leases \
         SET state = 'released', \
             released_at_ms = MAX(release_started_at_ms, ?1) \
         WHERE state = 'releasing' AND release_reason = 'process_restart' \
           AND EXISTS ( \
               SELECT 1 FROM scan_runs AS run \
               JOIN scan_jobs AS job ON job.id = scan_runtime_leases.scan_job_id \
               WHERE run.id = scan_runtime_leases.scan_run_id \
                 AND ((run.state = 'interrupted' AND job.state = 'failed') \
                   OR (run.state = 'cancelled' AND job.state = 'cancelled')) \
           )",
        [now_ms],
    )?;
    u64::try_from(interrupted)
        .map_err(|_| StoreError::invalid_input("interrupted_scan_count", "row count overflow"))
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
    if version < 5 {
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
    }
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
    let terminal_retry_adjacency = if version >= 5 {
        "OR (job.state = 'completed' AND run.state IN ('completed', 'queued')) \
         OR (job.state = 'cancelled' AND (run.id IS NULL OR run.state IN ( \
             'cancelled', 'failed', 'interrupted', 'queued' \
         )))"
    } else {
        "OR (job.state = 'completed' AND run.state = 'completed') \
         OR (job.state = 'cancelled' AND (run.id IS NULL OR run.state = 'cancelled'))"
    };
    let failed_adjacency = if version >= 5 {
        "(job.state = 'failed' AND (run.id IS NULL OR run.state IN ( \
             'failed', 'interrupted', 'queued' \
         )))"
    } else {
        "(job.state = 'failed' AND run.state IN ('failed', 'interrupted', 'queued'))"
    };
    reject_if_exists(
        connection,
        &format!(
            "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_jobs AS job \
             LEFT JOIN scan_runs AS run \
               ON run.id = job.active_scan_run_id AND run.volume_id = job.volume_id \
             WHERE NOT ( \
                 (job.state = 'queued' AND (run.id IS NULL OR run.state = 'queued')) \
                 OR (job.state = 'running' AND run.state = 'running') \
                 OR (job.state = 'paused' AND run.state = 'paused') \
                 OR {failed_adjacency} \
                 {terminal_retry_adjacency} \
             ) \
         )"
        ),
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
        if version == 4 {
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
        }
        if version == 4 {
            reject_if_exists(
                connection,
                "SELECT EXISTS( \
                     SELECT 1 FROM media_files AS media \
                     LEFT JOIN media_path_keys AS path \
                       ON path.volume_id = media.volume_id AND path.media_file_id = media.id \
                     WHERE path.media_file_id IS NULL \
                 )",
                "media file is missing a v4 path-semantics binding",
            )?;
        } else {
            reject_if_exists(
                connection,
                "SELECT EXISTS( \
                     SELECT 1 FROM media_files AS media \
                     WHERE NOT EXISTS ( \
                         SELECT 1 FROM media_path_keys AS legacy_path \
                         WHERE legacy_path.volume_id = media.volume_id \
                           AND legacy_path.media_file_id = media.id \
                     ) \
                       AND NOT EXISTS ( \
                         SELECT 1 \
                         FROM media_namespace_paths AS namespace_path \
                         JOIN namespace_profiles AS namespace \
                           ON namespace.id = namespace_path.namespace_profile_id \
                          AND namespace.volume_id = namespace_path.volume_id \
                         WHERE namespace_path.volume_id = media.volume_id \
                           AND namespace_path.media_file_id = media.id \
                           AND namespace.origin = 'observed_v5' \
                           AND namespace.reuse_scope <> 'history_only' \
                     ) \
                 )",
                "media file is missing a trusted v4 or v5 path binding",
            )?;
        }
    }
    if version >= 5 {
        validate_session_bound_evidence(connection, version)?;
    }
    if version >= 6 {
        validate_runtime_stream_evidence(connection)?;
    }
    if version >= 7 {
        validate_capture_time_evidence(connection)?;
    }
    if version >= 8 {
        validate_runtime_control_evidence(connection)?;
    }
    if version >= 9 {
        validate_fresh_attempt_recovery_evidence(connection)?;
    }
    validate_stored_path_evidence(connection, version)?;
    Ok(())
}

fn validate_runtime_control_evidence(connection: &Connection) -> Result<()> {
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_runtime_leases AS lease \
             LEFT JOIN scan_runs AS run \
               ON run.id = lease.scan_run_id AND run.volume_id = lease.volume_id \
             LEFT JOIN scan_jobs AS job \
               ON job.id = lease.scan_job_id AND job.volume_id = lease.volume_id \
             LEFT JOIN scan_job_runs AS binding \
               ON binding.scan_job_id = lease.scan_job_id \
              AND binding.scan_run_id = lease.scan_run_id \
              AND binding.volume_id = lease.volume_id \
             LEFT JOIN scan_run_sessions AS session \
               ON session.scan_run_id = lease.scan_run_id \
              AND session.volume_id = lease.volume_id \
              AND session.capability_profile_id = lease.capability_profile_id \
              AND session.namespace_profile_id = lease.namespace_profile_id \
              AND session.mount_session_key = lease.mount_session_key \
             LEFT JOIN scan_core_sessions AS core \
               ON core.scan_run_id = lease.scan_run_id \
              AND core.volume_id = lease.volume_id \
              AND core.capability_profile_id = lease.capability_profile_id \
              AND core.namespace_profile_id = lease.namespace_profile_id \
              AND core.core_session_id = lease.core_session_id \
             WHERE run.id IS NULL OR job.id IS NULL OR binding.scan_run_id IS NULL \
                OR session.scan_run_id IS NULL OR core.scan_run_id IS NULL \
                OR session.scan_job_id <> lease.scan_job_id \
                OR run.capability_profile_id <> lease.capability_profile_id \
                OR lease.acquired_at_ms < core.bound_at_ms \
                OR lease.last_heartbeat_at_ms < lease.acquired_at_ms \
                OR NOT ( \
                    (lease.state = 'active' \
                     AND lease.release_reason IS NULL \
                     AND lease.release_started_at_ms IS NULL \
                     AND lease.released_at_ms IS NULL \
                     AND job.active_scan_run_id = lease.scan_run_id \
                     AND ((run.state = 'running' AND job.state = 'running') \
                       OR (run.state = 'paused' AND job.state = 'paused'))) \
                 OR (lease.state = 'released' \
                     AND lease.release_reason IS NOT NULL \
                     AND lease.release_started_at_ms >= lease.last_heartbeat_at_ms \
                     AND lease.released_at_ms >= lease.release_started_at_ms \
                     AND ( \
                         (lease.release_reason = 'completed' \
                          AND run.state = 'completed') \
                      OR (lease.release_reason = 'failed' \
                          AND run.state = 'failed') \
                      OR (lease.release_reason = 'cancelled' \
                          AND run.state = 'cancelled') \
                      OR (lease.release_reason IN ('interrupted', 'process_restart') \
                          AND run.state IN ('interrupted', 'cancelled')) \
                     )) \
                ) \
         )",
        "runtime lease is not fully bound or has an invalid lifecycle/state relation",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_control_requests AS request \
             LEFT JOIN scan_runtime_leases AS lease \
               ON lease.scan_run_id = request.scan_run_id \
              AND lease.volume_id = request.volume_id \
              AND lease.runtime_lease_key = request.runtime_lease_key \
             LEFT JOIN scan_runs AS run ON run.id = request.scan_run_id \
             LEFT JOIN scan_jobs AS job ON job.id = lease.scan_job_id \
             WHERE lease.scan_run_id IS NULL \
                OR request.requested_at_ms < lease.acquired_at_ms \
                OR length(request.request_key) <> 32 \
                OR length(request.runtime_lease_key) <> 32 \
                OR (request.kind = 'resume') \
                   <> (request.expected_checkpoint_generation IS NOT NULL) \
                OR (request.disposition = 'pending' AND ( \
                       request.acknowledged_at_ms IS NOT NULL \
                       OR request.ack_job_state_version IS NOT NULL \
                       OR request.ack_run_state_version IS NOT NULL \
                       OR request.ack_checkpoint_generation IS NOT NULL \
                       OR request.ack_reason_code IS NOT NULL \
                       OR request.pause_checkpoint_write_key IS NOT NULL \
                       OR request.pause_checkpoint_payload_digest IS NOT NULL \
                       OR request.superseded_by_request_id IS NOT NULL \
                   )) \
                OR (request.disposition = 'acknowledged' AND ( \
                       request.acknowledged_at_ms < request.requested_at_ms \
                       OR request.ack_job_state_version <> \
                          request.expected_job_state_version + 1 \
                       OR request.ack_run_state_version <> \
                          request.expected_run_state_version + 1 \
                       OR request.ack_reason_code IS NULL \
                       OR length(CAST(request.ack_reason_code AS BLOB)) NOT BETWEEN 1 AND 256 \
                       OR request.superseded_by_request_id IS NOT NULL \
                       OR (request.kind IN ('pause', 'resume') \
                           AND request.ack_checkpoint_generation IS NULL) \
                       OR (request.kind = 'pause' AND ( \
                           length(request.pause_checkpoint_write_key) <> 32 \
                           OR length(request.pause_checkpoint_payload_digest) <> 32 \
                       )) \
                       OR (request.kind IN ('resume', 'cancel') AND ( \
                           request.pause_checkpoint_write_key IS NOT NULL \
                           OR request.pause_checkpoint_payload_digest IS NOT NULL \
                       )) \
                       OR (request.kind = 'resume' \
                           AND request.ack_checkpoint_generation \
                               <> request.expected_checkpoint_generation) \
                       OR (request.kind = 'pause' AND NOT EXISTS ( \
                           SELECT 1 FROM scan_pause_checkpoints AS checkpoint \
                           WHERE checkpoint.pause_request_id = request.id \
                             AND checkpoint.scan_run_id = request.scan_run_id \
                             AND checkpoint.pause_request_key = request.request_key \
                             AND checkpoint.generation = \
                                 request.ack_checkpoint_generation \
                             AND checkpoint.write_key = \
                                 request.pause_checkpoint_write_key \
                             AND checkpoint.payload_digest = \
                                 request.pause_checkpoint_payload_digest \
                             AND checkpoint.job_state_version = \
                                 request.ack_job_state_version \
                             AND checkpoint.run_state_version = \
                                 request.ack_run_state_version \
                       )) \
                   )) \
                OR (request.kind <> 'pause' AND EXISTS ( \
                       SELECT 1 FROM scan_pause_checkpoints AS checkpoint \
                       WHERE checkpoint.pause_request_id = request.id \
                   )) \
                OR (request.disposition <> 'acknowledged' AND EXISTS ( \
                       SELECT 1 FROM scan_pause_checkpoints AS checkpoint \
                       WHERE checkpoint.pause_request_id = request.id \
                   )) \
                OR (request.disposition = 'superseded' AND ( \
                       request.acknowledged_at_ms < request.requested_at_ms \
                       OR request.ack_job_state_version IS NOT NULL \
                       OR request.ack_run_state_version IS NOT NULL \
                       OR request.ack_checkpoint_generation IS NOT NULL \
                       OR request.pause_checkpoint_write_key IS NOT NULL \
                       OR request.pause_checkpoint_payload_digest IS NOT NULL \
                       OR request.ack_reason_code <> 'CANCEL_DOMINATED' \
                       OR NOT EXISTS ( \
                           SELECT 1 FROM scan_control_requests AS superseder \
                           WHERE superseder.id = request.superseded_by_request_id \
                             AND superseder.scan_run_id = request.scan_run_id \
                             AND superseder.kind = 'cancel' \
                             AND superseder.sequence > request.sequence \
                       ) \
                   )) \
                OR (request.disposition = 'interrupted' AND ( \
                       request.kind NOT IN ('pause', 'resume') \
                       OR request.ack_reason_code <> 'PROCESS_RESTART' \
                       OR lease.state NOT IN ('releasing', 'released') \
                       OR lease.release_reason <> 'process_restart' \
                       OR \
                       request.acknowledged_at_ms < request.requested_at_ms \
                       OR request.ack_job_state_version IS NOT NULL \
                       OR request.ack_run_state_version IS NOT NULL \
                       OR request.ack_checkpoint_generation IS NOT NULL \
                       OR request.pause_checkpoint_write_key IS NOT NULL \
                       OR request.pause_checkpoint_payload_digest IS NOT NULL \
                       OR request.ack_reason_code IS NULL \
                       OR length(CAST(request.ack_reason_code AS BLOB)) NOT BETWEEN 1 AND 256 \
                       OR request.superseded_by_request_id IS NOT NULL \
                   )) \
                OR (request.disposition = 'pending' AND lease.state = 'active' AND ( \
                       request.expected_job_state_version <> job.state_version \
                       OR request.expected_run_state_version <> run.state_version \
                       OR (request.kind = 'pause' \
                           AND (job.state <> 'running' OR run.state <> 'running')) \
                       OR (request.kind = 'resume' \
                           AND (job.state <> 'paused' OR run.state <> 'paused' \
                                OR NOT EXISTS ( \
                                    SELECT 1 FROM scan_pause_checkpoints AS checkpoint \
                                    WHERE checkpoint.scan_run_id = request.scan_run_id \
                                      AND checkpoint.generation = \
                                          request.expected_checkpoint_generation \
                                      AND checkpoint.runtime_lease_key = \
                                          request.runtime_lease_key \
                                ))) \
                       OR (request.kind = 'cancel' \
                           AND (job.state NOT IN ('running', 'paused') \
                                OR run.state NOT IN ('running', 'paused'))) \
                   )) \
         )",
        "runtime control request is not lease-bound or has invalid terminal evidence",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_control_requests \
             GROUP BY scan_run_id \
             HAVING min(sequence) <> 1 OR max(sequence) <> count(*) \
                 OR sum(disposition = 'pending') > 1 \
         )",
        "runtime control sequence is non-contiguous or has multiple pending requests",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_control_requests \
             GROUP BY scan_run_id \
             HAVING (min(CASE WHEN kind = 'cancel' THEN sequence END) IS NOT NULL \
                     AND max(sequence) > \
                         min(CASE WHEN kind = 'cancel' THEN sequence END)) \
                 OR (sum(disposition = 'pending' AND kind <> 'cancel') > 0 \
                     AND sum(kind = 'cancel') > 0) \
         )",
        "runtime control request violates durable cancel dominance",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_pause_checkpoints AS checkpoint \
             LEFT JOIN scan_runtime_leases AS lease \
               ON lease.scan_run_id = checkpoint.scan_run_id \
              AND lease.volume_id = checkpoint.volume_id \
              AND lease.runtime_lease_key = checkpoint.runtime_lease_key \
              AND lease.core_session_id = checkpoint.core_session_id \
              AND lease.mount_session_key = checkpoint.mount_session_key \
             LEFT JOIN scan_control_requests AS request \
               ON request.id = checkpoint.pause_request_id \
              AND request.request_key = checkpoint.pause_request_key \
              AND request.scan_run_id = checkpoint.scan_run_id \
              AND request.volume_id = checkpoint.volume_id \
              AND request.runtime_lease_key = checkpoint.runtime_lease_key \
             LEFT JOIN scan_runs AS run ON run.id = checkpoint.scan_run_id \
             WHERE lease.scan_run_id IS NULL OR request.id IS NULL OR run.id IS NULL \
                OR request.kind <> 'pause' OR request.disposition <> 'acknowledged' \
                OR request.pause_checkpoint_write_key <> checkpoint.write_key \
                OR request.pause_checkpoint_payload_digest <> checkpoint.payload_digest \
                OR request.ack_checkpoint_generation <> checkpoint.generation \
                OR request.ack_job_state_version <> checkpoint.job_state_version \
                OR request.ack_run_state_version <> checkpoint.run_state_version \
                OR request.expected_job_state_version + 1 \
                   <> checkpoint.job_state_version \
                OR request.expected_run_state_version + 1 \
                   <> checkpoint.run_state_version \
                OR checkpoint.job_state_version > ( \
                    SELECT job.state_version FROM scan_jobs AS job \
                    WHERE job.id = lease.scan_job_id \
                ) \
                OR checkpoint.run_state_version > run.state_version \
                OR checkpoint.discovered_count > run.discovered_count \
                OR checkpoint.fingerprinted_count > run.fingerprinted_count \
                OR checkpoint.error_count > run.error_count \
                OR checkpoint.logical_bytes_seen > run.logical_bytes_seen \
                OR checkpoint.saved_at_ms < request.requested_at_ms \
                OR length(checkpoint.write_key) <> 32 \
                OR length(checkpoint.payload_digest) <> 32 \
                OR length(checkpoint.work_plan_digest) <> 32 \
                OR length(checkpoint.evidence_manifest_digest) <> 32 \
                OR length(CAST(checkpoint.cursor_json AS BLOB)) NOT BETWEEN 2 AND 16384 \
                OR CASE WHEN json_valid(checkpoint.cursor_json) THEN ( \
                       json_type(checkpoint.cursor_json) <> 'object' \
                       OR checkpoint.cursor_json <> json(checkpoint.cursor_json) \
                       OR (SELECT count(*) FROM json_each(checkpoint.cursor_json)) <> 3 \
                       OR (SELECT count(*) FROM json_each(checkpoint.cursor_json) \
                           WHERE key = 'stage' AND type = 'text' \
                             AND value = 'enumeration') <> 1 \
                       OR (SELECT count(*) FROM json_each(checkpoint.cursor_json) \
                           WHERE key = 'next_directory_ordinal' AND type = 'integer' \
                             AND atom BETWEEN 0 AND 9223372036854775807) <> 1 \
                       OR (SELECT count(*) FROM json_each(checkpoint.cursor_json) \
                           WHERE key = 'next_file_ordinal' AND type = 'integer' \
                             AND atom BETWEEN 0 AND 9223372036854775807) <> 1 \
                       OR json_extract(checkpoint.cursor_json, \
                                       '$.next_directory_ordinal') > ( \
                           lease.directory_evidence_count \
                       ) \
                       OR json_extract(checkpoint.cursor_json, \
                                       '$.next_file_ordinal') > ( \
                           lease.file_evidence_count \
                       ) \
                   ) ELSE 1 END \
         )",
        "pause checkpoint is not a closed typed projection of lease-bound evidence",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_runtime_leases AS lease \
             JOIN scan_runs AS run ON run.id = lease.scan_run_id \
             JOIN scan_jobs AS job ON job.id = lease.scan_job_id \
             WHERE (lease.state IN ('releasing', 'released') AND EXISTS ( \
                       SELECT 1 FROM scan_control_requests AS request \
                       WHERE request.scan_run_id = lease.scan_run_id \
                         AND request.disposition = 'pending' \
                   )) \
                OR (lease.state = 'active' AND run.state = 'paused' AND ( \
                       NOT EXISTS ( \
                           SELECT 1 FROM scan_pause_checkpoints AS checkpoint \
                           WHERE checkpoint.scan_run_id = lease.scan_run_id \
                             AND checkpoint.generation = ( \
                                 SELECT max(latest.generation) \
                                 FROM scan_pause_checkpoints AS latest \
                                 WHERE latest.scan_run_id = lease.scan_run_id \
                             ) \
                             AND checkpoint.pause_request_id = ( \
                                 SELECT latest_request.id \
                                 FROM scan_control_requests AS latest_request \
                                 WHERE latest_request.scan_run_id = lease.scan_run_id \
                                   AND latest_request.disposition = 'acknowledged' \
                                 ORDER BY latest_request.sequence DESC LIMIT 1 \
                             ) \
                             AND checkpoint.work_plan_digest = lease.work_plan_digest \
                             AND checkpoint.evidence_manifest_digest = \
                                 lease.evidence_chain_digest \
                             AND json_extract(checkpoint.cursor_json, \
                                              '$.next_directory_ordinal') = \
                                 lease.directory_evidence_count \
                             AND json_extract(checkpoint.cursor_json, \
                                              '$.next_file_ordinal') = \
                                 lease.file_evidence_count \
                       ) \
                       OR COALESCE(( \
                           SELECT request.kind FROM scan_control_requests AS request \
                           WHERE request.scan_run_id = lease.scan_run_id \
                             AND request.disposition = 'acknowledged' \
                           ORDER BY request.sequence DESC LIMIT 1 \
                       ), '') <> 'pause' \
                   )) \
                OR (lease.state = 'active' AND run.state = 'running' \
                    AND EXISTS ( \
                        SELECT 1 FROM scan_control_requests AS acknowledged \
                        WHERE acknowledged.scan_run_id = lease.scan_run_id \
                          AND acknowledged.disposition = 'acknowledged' \
                    ) \
                    AND COALESCE(( \
                        SELECT request.kind FROM scan_control_requests AS request \
                        WHERE request.scan_run_id = lease.scan_run_id \
                          AND request.disposition = 'acknowledged' \
                        ORDER BY request.sequence DESC LIMIT 1 \
                    ), '') <> 'resume') \
         )",
        "runtime lease current state is inconsistent with control/checkpoint evidence",
    )?;
    let mut statement = connection.prepare(
        "SELECT scan_run_id, runtime_lease_key, core_session_id, work_plan_digest, \
                directory_evidence_count, file_evidence_count \
         FROM scan_runtime_leases ORDER BY scan_run_id",
    )?;
    let mut rows = statement.query([])?;
    let mut leases = Vec::new();
    while let Some(row) = rows.next()? {
        leases.push((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
        ));
    }
    drop(rows);
    drop(statement);
    for lease in leases {
        let lease_key: [u8; 32] = lease.1.try_into().map_err(|_| {
            StoreError::MigrationHistoryMismatch("runtime lease key length is invalid".into())
        })?;
        let core_session_id: [u8; 32] = lease.2.try_into().map_err(|_| {
            StoreError::MigrationHistoryMismatch("runtime core session id length is invalid".into())
        })?;
        let work_plan_digest = crate::repository::compute_runtime_work_plan_digest(
            connection,
            lease.0,
            &lease_key,
            &core_session_id,
        )?;
        crate::repository::validate_runtime_checkpoint_payload_history(
            connection,
            lease.0,
            &work_plan_digest,
            lease.4,
            lease.5,
        )?;
        if lease.3.as_slice() != work_plan_digest {
            return Err(StoreError::MigrationHistoryMismatch(
                "runtime lease work plan does not match its immutable session binding".into(),
            ));
        }
    }

    Ok(())
}

fn validate_session_bound_evidence(connection: &Connection, version: i64) -> Result<()> {
    let unicode_cross_session_rejection = if version >= 9 {
        ""
    } else {
        "OR namespace.unicode_behavior = 'unknown'"
    };
    reject_if_exists(
        connection,
        &format!(
            "SELECT EXISTS( \
             SELECT 1 \
             FROM namespace_profiles AS namespace \
             JOIN volumes AS volume ON volume.id = namespace.volume_id \
             WHERE (namespace.origin = 'legacy_session_v4' AND ( \
                       namespace.profile_key IS NOT NULL \
                       OR namespace.reuse_scope <> 'history_only' \
                       OR namespace.bound_mount_session_key IS NOT NULL \
                   )) \
                OR (namespace.origin = 'observed_v5' AND ( \
                       namespace.profile_key IS NULL \
                       OR namespace.native_path_encoding IS NULL \
                       OR namespace.case_behavior IS NULL \
                       OR namespace.unicode_behavior IS NULL \
                       OR namespace.key_strategy <> 'exact_native_v1' \
                       OR namespace.key_algorithm_version IS NULL \
                       OR namespace.reuse_scope = 'history_only' \
                       OR namespace.legacy_capability_profile_id IS NOT NULL \
                       OR (namespace.reuse_scope = 'cross_session' \
                           AND namespace.bound_mount_session_key IS NOT NULL) \
                       OR (namespace.reuse_scope = 'current_session_only' AND ( \
                           namespace.bound_mount_session_key IS NULL \
                           OR length(namespace.bound_mount_session_key) <> 64 \
                           OR namespace.bound_mount_session_key \
                               <> lower(namespace.bound_mount_session_key) \
                           OR namespace.bound_mount_session_key GLOB '*[^0-9a-f]*' \
                       )) \
                   )) \
                OR (namespace.reuse_scope = 'cross_session' AND ( \
                       volume.identity_strength <> 'strong' \
                       OR namespace.case_behavior = 'unknown' \
                       {unicode_cross_session_rejection} \
                   )) \
         )"
        ),
        "namespace profile has incomplete or over-privileged reuse evidence",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_jobs AS job \
             LEFT JOIN scan_job_scopes AS scope ON scope.scan_job_id = job.id \
             LEFT JOIN namespace_profiles AS namespace \
               ON namespace.id = scope.namespace_profile_id \
              AND namespace.volume_id = scope.volume_id \
             LEFT JOIN volumes AS volume ON volume.id = scope.volume_id \
             WHERE scope.scan_job_id IS NULL \
                OR scope.volume_id <> job.volume_id \
                OR scope.root_display <> job.root_relative_path \
                OR namespace.id IS NULL \
                OR scope.origin <> namespace.origin \
                OR (scope.origin = 'legacy_session_v4' AND ( \
                       scope.recoverable <> 0 \
                       OR scope.stable_root_path_key IS NOT NULL \
                       OR scope.root_scope_key IS NOT NULL \
                       OR scope.legacy_semantic_path_key <> job.root_path_key \
                   )) \
                OR (scope.origin = 'observed_v5' AND ( \
                       scope.stable_root_path_key <> job.root_path_key \
                       OR scope.root_scope_key IS NULL \
                       OR scope.legacy_semantic_path_key IS NOT NULL \
                       OR (scope.recoverable = 1 AND ( \
                           namespace.reuse_scope <> 'cross_session' \
                           OR volume.identity_strength <> 'strong' \
                       )) \
                   )) \
         )",
        "scan job scope does not match its stable namespace evidence",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_job_runs AS binding \
             JOIN scan_job_scopes AS scope \
               ON scope.scan_job_id = binding.scan_job_id \
              AND scope.volume_id = binding.volume_id \
             LEFT JOIN scan_run_sessions AS session \
               ON session.scan_run_id = binding.scan_run_id \
              AND session.scan_job_id = binding.scan_job_id \
              AND session.volume_id = binding.volume_id \
             WHERE scope.origin = 'observed_v5' \
               AND session.scan_run_id IS NULL \
         )",
        "v5 scan attempt is missing its immutable session provenance",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_run_sessions AS session \
             JOIN scan_runs AS run \
               ON run.id = session.scan_run_id \
              AND run.volume_id = session.volume_id \
             JOIN scan_job_runs AS binding \
               ON binding.scan_job_id = session.scan_job_id \
              AND binding.scan_run_id = session.scan_run_id \
              AND binding.volume_id = session.volume_id \
             JOIN scan_job_scopes AS scope \
               ON scope.scan_job_id = session.scan_job_id \
              AND scope.volume_id = session.volume_id \
             JOIN namespace_profiles AS namespace \
               ON namespace.id = session.namespace_profile_id \
              AND namespace.volume_id = session.volume_id \
             JOIN capability_profiles AS profile \
               ON profile.id = session.capability_profile_id \
              AND profile.volume_id = session.volume_id \
             JOIN volumes AS volume ON volume.id = session.volume_id \
             WHERE run.capability_profile_id <> session.capability_profile_id \
                OR scope.origin <> 'observed_v5' \
                OR namespace.origin <> 'observed_v5' \
                OR (namespace.reuse_scope = 'cross_session' \
                    AND namespace.bound_mount_session_key IS NOT NULL) \
                OR (namespace.reuse_scope = 'current_session_only' \
                    AND namespace.bound_mount_session_key \
                        <> session.mount_session_key COLLATE BINARY) \
                OR scope.namespace_profile_id <> session.namespace_profile_id \
                OR scope.mount_relative_root_raw <> session.mount_relative_root_raw \
                OR scope.path_encoding <> session.path_encoding \
                OR scope.stable_root_path_key <> session.stable_root_path_key \
                OR scope.root_scope_key <> session.root_scope_key \
                OR profile.profile_hash_version <> 2 \
                OR profile.probe_status <> 'complete' \
                OR profile.can_read <> 1 \
                OR profile.mount_session_key <> session.mount_session_key COLLATE BINARY \
                OR length(session.mount_session_key) <> 64 \
                OR session.mount_session_key GLOB '*[^0-9a-f]*' \
                OR (binding.attempt_number > 1 AND ( \
                     scope.recoverable <> 1 \
                     OR namespace.reuse_scope <> 'cross_session' \
                     OR volume.identity_strength <> 'strong' \
                )) \
         )",
        "scan run session is not bound to its stable scope and capability",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_job_runs AS binding \
             JOIN scan_runs AS run \
               ON run.id = binding.scan_run_id \
              AND run.volume_id = binding.volume_id \
             JOIN scan_run_sessions AS session \
               ON session.scan_run_id = binding.scan_run_id \
              AND session.scan_job_id = binding.scan_job_id \
              AND session.volume_id = binding.volume_id \
             LEFT JOIN scan_job_runs AS previous_binding \
               ON previous_binding.scan_job_id = binding.scan_job_id \
              AND previous_binding.attempt_number = binding.attempt_number - 1 \
             WHERE (binding.attempt_number = 1 \
                    AND run.parent_scan_run_id IS NOT NULL) \
                OR (binding.attempt_number > 1 AND ( \
                    previous_binding.scan_run_id IS NULL \
                    OR run.parent_scan_run_id <> previous_binding.scan_run_id \
                )) \
         )",
        "scan attempt lineage does not point to the immediately preceding run",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_runs AS run \
             LEFT JOIN scan_run_sessions AS session \
               ON session.scan_run_id = run.id \
              AND session.volume_id = run.volume_id \
             LEFT JOIN capability_profiles AS profile \
               ON profile.id = session.capability_profile_id \
              AND profile.volume_id = session.volume_id \
             WHERE run.state IN ('queued', 'running', 'paused') \
               AND (session.scan_run_id IS NULL \
                    OR profile.is_current <> 1 \
                    OR profile.mount_session_key <> session.mount_session_key COLLATE BINARY) \
         )",
        "non-terminal scan lacks its current mount session",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_runs AS run \
             JOIN scan_run_sessions AS session \
               ON session.scan_run_id = run.id \
              AND session.volume_id = run.volume_id \
             WHERE run.state = 'completed' \
               AND NOT EXISTS ( \
                   SELECT 1 FROM scan_stage_seals AS seal \
                   WHERE seal.scan_run_id = run.id \
                     AND seal.volume_id = run.volume_id \
                     AND seal.stage = 'exact_verification' \
               ) \
         )",
        "completed v5 scan is missing its exact-verification seal",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_stage_seals AS seal \
             WHERE (seal.stage = 'enumeration' AND ( \
                       seal.item_count <> ( \
                           SELECT count(*) \
                           FROM media_observation_snapshots AS observation \
                           WHERE observation.scan_run_id = seal.scan_run_id \
                       ) \
                       OR seal.logical_bytes <> COALESCE(( \
                           SELECT sum(observation.size_bytes) \
                           FROM media_observation_snapshots AS observation \
                           WHERE observation.scan_run_id = seal.scan_run_id \
                       ), 0) \
                   )) \
                OR (seal.stage = 'sampling' AND ( \
                       NOT EXISTS ( \
                           SELECT 1 FROM scan_stage_seals AS prerequisite \
                           WHERE prerequisite.scan_run_id = seal.scan_run_id \
                             AND prerequisite.stage = 'enumeration' \
                             AND prerequisite.sealed_at_ms <= seal.sealed_at_ms \
                       ) \
                       OR seal.item_count <> ( \
                           SELECT count(*) FROM observation_fingerprints AS fingerprint \
                           WHERE fingerprint.scan_run_id = seal.scan_run_id \
                             AND fingerprint.fingerprint_kind = 'sample' \
                       ) \
                       OR seal.logical_bytes <> COALESCE(( \
                           SELECT sum(fingerprint.bytes_read) \
                           FROM observation_fingerprints AS fingerprint \
                           WHERE fingerprint.scan_run_id = seal.scan_run_id \
                             AND fingerprint.fingerprint_kind = 'sample' \
                       ), 0) \
                   )) \
                OR (seal.stage = 'full_hash' AND ( \
                       NOT EXISTS ( \
                           SELECT 1 FROM scan_stage_seals AS prerequisite \
                           WHERE prerequisite.scan_run_id = seal.scan_run_id \
                             AND prerequisite.stage = 'sampling' \
                             AND prerequisite.sealed_at_ms <= seal.sealed_at_ms \
                       ) \
                       OR seal.item_count <> ( \
                           SELECT count(*) FROM observation_fingerprints AS fingerprint \
                           WHERE fingerprint.scan_run_id = seal.scan_run_id \
                             AND fingerprint.fingerprint_kind = 'exact_bytes' \
                             AND fingerprint.read_origin = 'full_hash_read' \
                       ) \
                       OR seal.logical_bytes <> COALESCE(( \
                           SELECT sum(fingerprint.bytes_read) \
                           FROM observation_fingerprints AS fingerprint \
                           WHERE fingerprint.scan_run_id = seal.scan_run_id \
                             AND fingerprint.fingerprint_kind = 'exact_bytes' \
                             AND fingerprint.read_origin = 'full_hash_read' \
                       ), 0) \
                   )) \
                OR (seal.stage = 'exact_verification' AND ( \
                       NOT EXISTS ( \
                           SELECT 1 FROM scan_stage_seals AS prerequisite \
                           WHERE prerequisite.scan_run_id = seal.scan_run_id \
                             AND prerequisite.stage = 'full_hash' \
                             AND prerequisite.sealed_at_ms <= seal.sealed_at_ms \
                       ) \
                       OR EXISTS ( \
                           SELECT 1 FROM exact_group_builds AS draft \
                           WHERE draft.scan_run_id = seal.scan_run_id \
                             AND draft.state = 'draft' \
                       ) \
                       OR seal.item_count <> ( \
                           SELECT count(*) FROM exact_verification_edges AS edge \
                           WHERE edge.scan_run_id = seal.scan_run_id \
                       ) \
                       OR seal.logical_bytes <> COALESCE(( \
                           SELECT sum(edge.compared_bytes) \
                           FROM exact_verification_edges AS edge \
                           WHERE edge.scan_run_id = seal.scan_run_id \
                       ), 0) \
                   )) \
         )",
        "scan stage seal is out of order or has stale totals",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM observation_fingerprints AS fingerprint \
             JOIN media_observation_snapshots AS observation \
               ON observation.id = fingerprint.media_observation_snapshot_id \
              AND observation.scan_run_id = fingerprint.scan_run_id \
              AND observation.volume_id = fingerprint.volume_id \
             WHERE fingerprint.source_signature_before <> observation.source_signature \
                OR fingerprint.source_signature_after <> observation.source_signature \
                OR fingerprint.observed_size_bytes <> observation.size_bytes \
                OR (fingerprint.fingerprint_kind = 'exact_bytes' AND ( \
                     fingerprint.bytes_read <> observation.size_bytes \
                     OR fingerprint.reached_expected_eof <> 1 \
                )) \
         )",
        "fingerprint does not match its immutable observation",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM exact_group_builds AS build \
             WHERE build.state = 'verified' \
               AND ( \
                   (SELECT count(*) FROM exact_group_build_members AS member \
                    WHERE member.exact_group_build_id = build.id) \
                       <> build.expected_member_count \
                   OR (SELECT count(*) FROM exact_verification_edges AS edge \
                       WHERE edge.exact_group_build_id = build.id) \
                       <> build.expected_edge_count \
                   OR NOT EXISTS ( \
                       SELECT 1 FROM exact_group_build_members AS representative \
                       WHERE representative.exact_group_build_id = build.id \
                         AND representative.ordinal = 0 \
                         AND representative.media_observation_snapshot_id = \
                             build.representative_observation_id \
                         AND representative.observation_fingerprint_id = \
                             build.representative_fingerprint_id \
                   ) \
                   OR EXISTS ( \
                       SELECT 1 FROM exact_group_build_members AS member \
                       WHERE member.exact_group_build_id = build.id \
                         AND member.media_observation_snapshot_id <> \
                             build.representative_observation_id \
                         AND NOT EXISTS ( \
                             SELECT 1 FROM exact_verification_edges AS edge \
                             WHERE edge.exact_group_build_id = build.id \
                               AND edge.member_observation_id = \
                                   member.media_observation_snapshot_id \
                         ) \
                   ) \
               ) \
         )",
        "verified exact group is missing members or verification edges",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM exact_group_builds AS build \
             JOIN exact_group_build_members AS member \
               ON member.exact_group_build_id = build.id \
              AND member.scan_run_id = build.scan_run_id \
             WHERE build.state = 'verified' \
             GROUP BY member.scan_run_id, member.media_observation_snapshot_id \
             HAVING count(DISTINCT build.id) > 1 \
         )",
        "verified exact groups overlap by observation identity",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM exact_group_builds AS build \
             JOIN exact_group_build_members AS member \
               ON member.exact_group_build_id = build.id \
              AND member.scan_run_id = build.scan_run_id \
             JOIN media_observation_snapshots AS observation \
               ON observation.id = member.media_observation_snapshot_id \
              AND observation.scan_run_id = member.scan_run_id \
              AND observation.volume_id = member.volume_id \
             WHERE build.state = 'verified' \
               AND observation.file_object_key IS NOT NULL \
             GROUP BY member.scan_run_id, observation.file_object_key \
             HAVING count(DISTINCT build.id) > 1 \
         )",
        "verified exact groups overlap by physical file identity",
    )?;
    crate::repository::verify_all_verified_exact_groups(connection)?;
    Ok(())
}

fn validate_fresh_attempt_recovery_evidence(connection: &Connection) -> Result<()> {
    reject_if_exists(
        connection,
        "SELECT (SELECT count(*) FROM scan_attempt_strategy_epochs) <> 1 \
             OR EXISTS( \
                 SELECT 1 \
                 FROM scan_runs AS run \
                 CROSS JOIN scan_attempt_strategy_epochs AS epoch \
                 WHERE epoch.id <> 1 \
                    OR (run.id <= epoch.legacy_scan_run_id_cutoff \
                        AND run.attempt_strategy <> 'legacy') \
                    OR (run.id > epoch.legacy_scan_run_id_cutoff \
                        AND run.attempt_strategy = 'legacy') \
             )",
        "scan attempt strategy violates the immutable v8-to-v9 epoch",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM namespace_reuse_policies AS policy \
             LEFT JOIN namespace_profiles AS namespace \
               ON namespace.id = policy.namespace_profile_id \
              AND namespace.volume_id = policy.volume_id \
             LEFT JOIN volumes AS volume ON volume.id = policy.volume_id \
             WHERE namespace.id IS NULL OR volume.id IS NULL \
                OR namespace.origin <> 'observed_v5' \
                OR namespace.reuse_scope <> 'cross_session' \
                OR namespace.bound_mount_session_key IS NOT NULL \
                OR namespace.key_strategy <> 'exact_native_v1' \
                OR namespace.case_behavior = 'unknown' \
                OR volume.identity_strength <> 'strong' \
                OR policy.policy_version <> 1 \
                OR policy.created_at_ms < namespace.created_at_ms \
                OR (policy.policy = 'evidence_reuse_eligible' \
                    AND namespace.unicode_behavior = 'unknown') \
         )",
        "namespace reuse policy exceeds immutable namespace evidence",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_job_scopes AS scope \
             LEFT JOIN namespace_reuse_policies AS policy \
               ON policy.namespace_profile_id = scope.namespace_profile_id \
              AND policy.volume_id = scope.volume_id \
             WHERE scope.recoverable = 1 \
               AND (policy.namespace_profile_id IS NULL \
                    OR policy.policy NOT IN ( \
                        'fresh_attempt_only', 'evidence_reuse_eligible' \
                    )) \
         )",
        "recoverable scan scope lacks an explicit fresh-attempt policy",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_job_runs AS binding \
             JOIN scan_runs AS run \
               ON run.id = binding.scan_run_id AND run.volume_id = binding.volume_id \
             JOIN scan_job_scopes AS scope \
               ON scope.scan_job_id = binding.scan_job_id \
              AND scope.volume_id = binding.volume_id \
             LEFT JOIN scan_runs AS parent ON parent.id = run.parent_scan_run_id \
             LEFT JOIN namespace_reuse_policies AS policy \
               ON policy.namespace_profile_id = scope.namespace_profile_id \
              AND policy.volume_id = scope.volume_id \
             WHERE (run.attempt_strategy = 'initial_full_v1' AND ( \
                       binding.attempt_number <> 1 \
                       OR run.parent_scan_run_id IS NOT NULL \
                       OR run.scan_mode <> 'full' \
                   )) \
                OR (run.attempt_strategy = 'fresh_full_child_v1' AND ( \
                       binding.attempt_number <= 1 \
                       OR run.parent_scan_run_id IS NULL \
                       OR run.scan_mode <> 'full' \
                       OR parent.attempt_strategy NOT IN ( \
                           'initial_full_v1', 'fresh_full_child_v1' \
                       ) \
                       OR parent.state <> 'interrupted' \
                       OR scope.recoverable <> 1 \
                       OR policy.policy NOT IN ( \
                           'fresh_attempt_only', 'evidence_reuse_eligible' \
                       ) \
                   )) \
                OR (run.attempt_strategy <> 'legacy' \
                    AND run.attempt_strategy NOT IN ( \
                        'initial_full_v1', 'fresh_full_child_v1' \
                    )) \
                OR (run.attempt_strategy <> 'legacy' \
                    AND binding.attempt_number = 1 \
                    AND run.attempt_strategy <> 'initial_full_v1') \
                OR (run.attempt_strategy <> 'legacy' \
                    AND binding.attempt_number > 1 \
                    AND run.attempt_strategy <> 'fresh_full_child_v1') \
         )",
        "explicit scan attempt strategy is inconsistent with lineage policy",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_runs AS run \
             LEFT JOIN scan_job_runs AS binding \
               ON binding.scan_run_id = run.id AND binding.volume_id = run.volume_id \
             WHERE run.attempt_strategy <> 'legacy' \
               AND binding.scan_run_id IS NULL \
         )",
        "explicit v9 scan attempt is missing its job binding",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_runs AS run \
             JOIN scan_job_runs AS binding \
               ON binding.scan_run_id = run.id AND binding.volume_id = run.volume_id \
             JOIN scan_jobs AS job \
               ON job.id = binding.scan_job_id AND job.volume_id = binding.volume_id \
             LEFT JOIN scan_runs AS parent ON parent.id = run.parent_scan_run_id \
             WHERE run.state = 'queued' \
               AND run.attempt_strategy <> 'legacy' \
               AND (job.active_scan_run_id IS NOT run.id \
                    OR (run.attempt_strategy = 'initial_full_v1' AND ( \
                        binding.attempt_number <> 1 \
                        OR job.state <> 'queued' \
                        OR run.parent_scan_run_id IS NOT NULL \
                    )) \
                    OR (run.attempt_strategy = 'fresh_full_child_v1' AND ( \
                        binding.attempt_number <= 1 \
                        OR job.state <> 'failed' \
                        OR parent.state <> 'interrupted' \
                    ))) \
         )",
        "queued v9 scan attempt is not in its atomic creation state",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_runs AS child \
             JOIN scan_runs AS parent ON parent.id = child.parent_scan_run_id \
             WHERE child.attempt_strategy = 'fresh_full_child_v1' \
               AND parent.attempt_strategy = 'legacy' \
         )",
        "legacy scan run was promoted into a v9 fresh-attempt lineage",
    )?;
    Ok(())
}

fn validate_runtime_stream_evidence(connection: &Connection) -> Result<()> {
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM media_observation_snapshots AS observation \
             WHERE observation.timestamp_storage_unit_ns <> 1 \
                OR (observation.timestamp_granularity_ns IS NOT NULL \
                    AND observation.timestamp_granularity_ns <= 0) \
         )",
        "media observation has invalid timestamp precision evidence",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_core_sessions AS core \
             LEFT JOIN scan_run_sessions AS session \
               ON session.scan_run_id = core.scan_run_id \
              AND session.volume_id = core.volume_id \
              AND session.capability_profile_id = core.capability_profile_id \
              AND session.namespace_profile_id = core.namespace_profile_id \
             LEFT JOIN scan_runs AS run \
               ON run.id = core.scan_run_id \
              AND run.volume_id = core.volume_id \
             WHERE session.scan_run_id IS NULL \
                OR run.id IS NULL \
                OR core.trust_scope <> 'current_core_session_only' \
                OR core.engine_contract_version <> 1 \
                OR core.root_index <> 0 \
                OR core.root_kind <> 'directory' \
                OR core.root_object_signature <> session.root_object_signature \
                OR core.bound_at_ms < session.created_at_ms \
         )",
        "core scan session is detached from its immutable volume session",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_file_tickets AS ticket \
             LEFT JOIN scan_core_sessions AS core \
               ON core.scan_run_id = ticket.scan_run_id \
              AND core.volume_id = ticket.volume_id \
              AND core.core_session_id = ticket.core_session_id \
             LEFT JOIN media_observation_snapshots AS observation \
               ON observation.id = ticket.media_observation_snapshot_id \
              AND observation.scan_run_id = ticket.scan_run_id \
              AND observation.volume_id = ticket.volume_id \
             WHERE core.scan_run_id IS NULL \
                OR observation.id IS NULL \
                OR ticket.source_signature <> observation.source_signature \
                OR ticket.created_at_ms < observation.observed_at_ms \
                OR ticket.created_at_ms < core.bound_at_ms \
         )",
        "file ticket is detached from its core session or observation",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_directory_observations AS directory \
             LEFT JOIN scan_core_sessions AS core \
               ON core.scan_run_id = directory.scan_run_id \
              AND core.volume_id = directory.volume_id \
              AND core.core_session_id = directory.core_session_id \
             LEFT JOIN scan_run_sessions AS session \
               ON session.scan_run_id = directory.scan_run_id \
              AND session.volume_id = directory.volume_id \
             WHERE core.scan_run_id IS NULL \
                OR session.scan_run_id IS NULL \
                OR directory.root_index <> core.root_index \
                OR directory.path_encoding <> session.path_encoding \
                OR directory.observed_at_ms < core.bound_at_ms \
         )",
        "directory ticket is detached from its core and volume session",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_coverage_outcomes AS coverage \
             LEFT JOIN scan_core_sessions AS core \
               ON core.scan_run_id = coverage.scan_run_id \
              AND core.volume_id = coverage.volume_id \
              AND core.core_session_id = coverage.core_session_id \
             WHERE core.scan_run_id IS NULL \
                OR coverage.directory_count <> ( \
                    SELECT count(*) FROM scan_directory_observations AS directory \
                    WHERE directory.scan_run_id = coverage.scan_run_id \
                ) \
                OR NOT EXISTS ( \
                    SELECT 1 FROM scan_stage_seals AS full_hash \
                    WHERE full_hash.scan_run_id = coverage.scan_run_id \
                      AND full_hash.stage = 'full_hash' \
                      AND full_hash.sealed_at_ms <= coverage.finalized_at_ms \
                ) \
                OR (coverage.status = 'complete' AND ( \
                    coverage.replayed_count <> coverage.directory_count \
                    OR coverage.stable_count <> coverage.directory_count \
                    OR coverage.failed_count <> 0 \
                    OR (SELECT count(*) FROM scan_file_tickets AS ticket \
                        WHERE ticket.scan_run_id = coverage.scan_run_id) <> \
                       (SELECT count(*) FROM media_observation_snapshots AS observation \
                        WHERE observation.scan_run_id = coverage.scan_run_id) \
                    OR coverage.finalized_at_ms < COALESCE(( \
                        SELECT max(directory.observed_at_ms) \
                        FROM scan_directory_observations AS directory \
                        WHERE directory.scan_run_id = coverage.scan_run_id \
                    ), core.bound_at_ms) \
                )) \
         )",
        "coverage outcome is detached, incomplete, or predates its evidence",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_core_sessions AS core \
             JOIN scan_stage_seals AS seal \
               ON seal.scan_run_id = core.scan_run_id \
              AND seal.volume_id = core.volume_id \
             WHERE (seal.stage = 'enumeration' AND ( \
                       (SELECT count(*) FROM scan_file_tickets AS ticket \
                        WHERE ticket.scan_run_id = core.scan_run_id) <> \
                       (SELECT count(*) FROM media_observation_snapshots AS observation \
                        WHERE observation.scan_run_id = core.scan_run_id) \
                       OR EXISTS ( \
                           SELECT 1 FROM media_observation_snapshots AS observation \
                           WHERE observation.scan_run_id = core.scan_run_id \
                             AND NOT EXISTS ( \
                                 SELECT 1 FROM scan_file_tickets AS ticket \
                                 WHERE ticket.scan_run_id = observation.scan_run_id \
                                   AND ticket.media_observation_snapshot_id = observation.id \
                                   AND ticket.source_signature = observation.source_signature \
                             ) \
                       ) \
                   )) \
                OR (seal.stage = 'exact_verification' AND NOT EXISTS ( \
                       SELECT 1 FROM scan_coverage_outcomes AS coverage \
                       WHERE coverage.scan_run_id = core.scan_run_id \
                         AND coverage.volume_id = core.volume_id \
                         AND coverage.status = 'complete' \
                         AND coverage.finalized_at_ms <= seal.sealed_at_ms \
                   )) \
         )",
        "streaming scan seal lacks complete authenticated ticket coverage",
    )?;
    validate_v6_evidence_chronology(connection)?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_issues AS issue \
             JOIN scan_run_sessions AS session \
               ON session.scan_run_id = issue.scan_run_id \
              AND session.volume_id = issue.volume_id \
             WHERE issue.media_file_id IS NOT NULL \
               AND NOT EXISTS ( \
                   SELECT 1 FROM media_observation_snapshots AS observation \
                   WHERE observation.scan_run_id = issue.scan_run_id \
                     AND observation.volume_id = issue.volume_id \
                     AND observation.media_file_id = issue.media_file_id \
               ) \
         )",
        "scan issue references media that was not observed by its run",
    )?;
    Ok(())
}

fn validate_capture_time_declared_bounds(connection: &Connection) -> Result<()> {
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_time_sessions \
             WHERE length(time_session_key) <> 32 \
                OR length(core_session_id) <> 32 \
                OR schema_contract_version <> 1 \
                OR scope_manifest_version <> 1 \
                OR outcome_manifest_version <> 2 \
                OR state NOT IN ('draft', 'complete', 'partial', 'abandoned') \
                OR expected_group_count < 0 \
                OR max_total_read_bytes NOT BETWEEN 1 AND 4294967296 \
                OR max_probe_count_per_group NOT BETWEEN 1 AND 4 \
                OR max_report_total_bytes_read NOT BETWEEN 1 AND 8388608 \
                OR max_report_read_operations NOT BETWEEN 1 AND 32768 \
                OR max_report_retained_field_bytes NOT BETWEEN 1 AND 262144 \
                OR max_report_fields NOT BETWEEN 1 AND 128 \
                OR max_report_issues NOT BETWEEN 1 AND 128 \
                OR length(expected_manifest_digest) <> 32 \
                OR (sealed_manifest_digest IS NOT NULL \
                    AND length(sealed_manifest_digest) <> 32) \
                OR (sealed_outcome_manifest_digest IS NOT NULL \
                    AND length(sealed_outcome_manifest_digest) <> 32) \
                OR created_at_ms < 0 \
                OR (finalized_at_ms IS NOT NULL AND finalized_at_ms < created_at_ms) \
                OR (state = 'draft' AND ( \
                    evidence_group_count IS NOT NULL \
                    OR unavailable_group_count IS NOT NULL \
                    OR failed_group_count IS NOT NULL \
                    OR sealed_manifest_digest IS NOT NULL \
                    OR sealed_outcome_manifest_digest IS NOT NULL \
                    OR abandon_reason_code IS NOT NULL \
                    OR abandon_reason_message IS NOT NULL \
                    OR finalized_at_ms IS NOT NULL \
                )) \
                OR (state IN ('complete', 'partial') AND ( \
                    evidence_group_count IS NULL OR evidence_group_count < 0 \
                    OR unavailable_group_count IS NULL OR unavailable_group_count < 0 \
                    OR failed_group_count IS NULL OR failed_group_count < 0 \
                    OR sealed_manifest_digest <> expected_manifest_digest \
                    OR sealed_outcome_manifest_digest IS NULL \
                    OR abandon_reason_code IS NOT NULL \
                    OR abandon_reason_message IS NOT NULL \
                    OR finalized_at_ms IS NULL \
                    OR (state = 'complete' AND ( \
                        SELECT count(*) FROM capture_time_group_outcomes AS outcome \
                        WHERE outcome.time_session_id = scan_time_sessions.id \
                    ) <> expected_group_count) \
                    OR (state = 'partial' AND ( \
                        SELECT count(*) FROM capture_time_group_outcomes AS outcome \
                        WHERE outcome.time_session_id = scan_time_sessions.id \
                    ) > expected_group_count) \
                )) \
                OR (state = 'abandoned' AND ( \
                    evidence_group_count IS NOT NULL \
                    OR unavailable_group_count IS NOT NULL \
                    OR failed_group_count IS NOT NULL \
                    OR sealed_manifest_digest IS NOT NULL \
                    OR sealed_outcome_manifest_digest IS NOT NULL \
                    OR abandon_reason_code IS NULL \
                    OR finalized_at_ms IS NULL \
                )) \
                OR (abandon_reason_code IS NOT NULL AND \
                    length(CAST(abandon_reason_code AS BLOB)) NOT BETWEEN 1 AND 256) \
                OR (abandon_reason_message IS NOT NULL AND \
                    length(CAST(abandon_reason_message AS BLOB)) NOT BETWEEN 1 AND 65536) \
         )",
        "capture-time session violates its typed state, manifest, or budget bounds",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM metadata_extraction_reports AS report \
             WHERE report.probe_ordinal NOT BETWEEN 0 AND 3 \
                OR report.source_size_bytes < 0 \
                OR length(CAST(report.report_parser_name AS BLOB)) NOT BETWEEN 1 AND 128 \
                OR length(CAST(report.report_parser_version AS BLOB)) NOT BETWEEN 1 AND 128 \
                OR (report.detected_format IS NOT NULL \
                    AND report.detected_format NOT IN ('jpeg', 'tiff', 'iso_bmff')) \
                OR report.extraction_status NOT IN ( \
                    'extracted_unvalidated', 'no_metadata', 'partial', 'failed', 'unsupported' \
                ) \
                OR report.effective_max_total_bytes_read NOT BETWEEN 1 AND 67108864 \
                OR report.effective_max_read_operations NOT BETWEEN 1 AND 262144 \
                OR report.effective_max_retained_field_bytes NOT BETWEEN 1 AND 16777216 \
                OR report.effective_max_field_bytes NOT BETWEEN 1 AND 1048576 \
                OR report.effective_max_fields NOT BETWEEN 1 AND 4096 \
                OR report.effective_max_jpeg_segments NOT BETWEEN 1 AND 65536 \
                OR report.effective_max_ifd_entries NOT BETWEEN 1 AND 65536 \
                OR report.effective_max_ifd_depth NOT BETWEEN 1 AND 64 \
                OR report.effective_max_bmff_boxes NOT BETWEEN 1 AND 65536 \
                OR report.effective_max_bmff_depth NOT BETWEEN 1 AND 64 \
                OR report.usage_bytes_read NOT BETWEEN 0 AND report.effective_max_total_bytes_read \
                OR report.usage_read_operations NOT BETWEEN 0 \
                    AND report.effective_max_read_operations \
                OR report.usage_retained_field_bytes NOT BETWEEN 0 \
                    AND report.effective_max_retained_field_bytes \
                OR report.usage_fields_emitted NOT BETWEEN 0 \
                    AND report.effective_max_fields \
                OR report.usage_jpeg_segments_visited NOT BETWEEN 0 \
                    AND report.effective_max_jpeg_segments \
                OR report.usage_ifd_entries_visited NOT BETWEEN 0 \
                    AND report.effective_max_ifd_entries \
                OR report.usage_bmff_boxes_visited NOT BETWEEN 0 \
                    AND report.effective_max_bmff_boxes \
                OR report.usage_max_depth_observed NOT BETWEEN 0 \
                    AND MAX(report.effective_max_ifd_depth, report.effective_max_bmff_depth) \
                OR report.effective_max_field_bytes > \
                    report.effective_max_retained_field_bytes \
                OR report.expected_field_count NOT BETWEEN 0 AND 4096 \
                OR report.expected_issue_count NOT BETWEEN 0 AND 4096 \
                OR report.expected_retained_field_bytes NOT BETWEEN 0 AND 16777216 \
                OR report.expected_field_count <> report.usage_fields_emitted \
                OR report.expected_retained_field_bytes <> report.usage_retained_field_bytes \
                OR report.manifest_version <> 1 \
                OR length(report.retained_report_digest) <> 32 \
                OR length(report.expected_manifest_digest) <> 32 \
                OR (report.sealed_manifest_digest IS NOT NULL \
                    AND length(report.sealed_manifest_digest) <> 32) \
                OR report.state NOT IN ('draft', 'sealed', 'abandoned') \
                OR report.created_at_ms < 0 \
                OR (report.finalized_at_ms IS NOT NULL \
                    AND report.finalized_at_ms < report.created_at_ms) \
                OR (report.state = 'draft' AND ( \
                    report.sealed_manifest_digest IS NOT NULL \
                    OR report.abandon_reason_code IS NOT NULL \
                    OR report.abandon_reason_message IS NOT NULL \
                    OR report.finalized_at_ms IS NOT NULL \
                )) \
                OR (report.state = 'sealed' AND ( \
                    report.sealed_manifest_digest <> report.expected_manifest_digest \
                    OR report.abandon_reason_code IS NOT NULL \
                    OR report.abandon_reason_message IS NOT NULL \
                    OR report.finalized_at_ms IS NULL \
                )) \
                OR (report.state = 'abandoned' AND ( \
                    report.sealed_manifest_digest IS NOT NULL \
                    OR report.abandon_reason_code IS NULL \
                    OR report.finalized_at_ms IS NULL \
                )) \
                OR (report.abandon_reason_code IS NOT NULL AND \
                    length(CAST(report.abandon_reason_code AS BLOB)) NOT BETWEEN 1 AND 256) \
                OR (report.abandon_reason_message IS NOT NULL AND \
                    length(CAST(report.abandon_reason_message AS BLOB)) NOT BETWEEN 1 AND 65536) \
         )",
        "metadata extraction report violates typed limits, usage, or state bounds",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM metadata_extraction_fields AS field \
             JOIN metadata_extraction_reports AS report ON report.id = field.report_id \
             WHERE field.ordinal NOT BETWEEN 0 AND 4095 \
                OR field.ordinal >= report.expected_field_count \
                OR length(CAST(field.parser_name AS BLOB)) NOT BETWEEN 1 AND 128 \
                OR length(CAST(field.parser_version AS BLOB)) NOT BETWEEN 1 AND 128 \
                OR field.field_kind NOT IN ( \
                    'exif_date_time_original', 'exif_create_date', 'exif_modify_date', \
                    'exif_offset_time_original', 'exif_subsec_time_original', \
                    'quicktime_movie_header_creation_time', \
                    'quicktime_metadata_creation_date' \
                ) \
                OR field.encoding NOT IN ( \
                    'declared_ascii', 'validated_utf8', 'unsigned_big_endian' \
                ) \
                OR field.absolute_offset < 0 \
                OR field.byte_len NOT BETWEEN 1 AND 1048576 \
                OR length(field.raw_bytes) NOT BETWEEN 1 AND 1048576 \
                OR field.byte_len <> length(field.raw_bytes) \
                OR length(field.raw_digest) <> 32 \
                OR field.container_kind NOT IN ('tiff', 'jpeg_exif', 'iso_bmff') \
                OR (field.bmff_box_path IS NOT NULL AND ( \
                    length(field.bmff_box_path) NOT BETWEEN 4 AND 256 \
                    OR length(field.bmff_box_path) % 4 <> 0 \
                )) \
                OR field.created_at_ms < 0 \
                OR (field.container_kind = 'tiff' AND NOT ( \
                    field.tiff_header_offset IS NOT NULL \
                    AND field.tiff_header_offset >= 0 \
                    AND field.tiff_ifd_offset IS NOT NULL \
                    AND field.tiff_ifd_offset >= 0 \
                    AND field.tiff_tag IS NOT NULL \
                    AND field.tiff_tag BETWEEN 0 AND 65535 \
                    AND field.tiff_byte_order IS NOT NULL \
                    AND field.tiff_byte_order IN ('little_endian', 'big_endian') \
                    AND field.jpeg_app1_offset IS NULL \
                    AND field.bmff_box_offset IS NULL \
                    AND field.bmff_box_path IS NULL \
                )) \
                OR (field.container_kind = 'jpeg_exif' AND NOT ( \
                    field.tiff_header_offset IS NOT NULL \
                    AND field.tiff_header_offset >= 0 \
                    AND field.tiff_ifd_offset IS NOT NULL \
                    AND field.tiff_ifd_offset >= 0 \
                    AND field.tiff_tag IS NOT NULL \
                    AND field.tiff_tag BETWEEN 0 AND 65535 \
                    AND field.tiff_byte_order IS NOT NULL \
                    AND field.tiff_byte_order IN ('little_endian', 'big_endian') \
                    AND field.jpeg_app1_offset IS NOT NULL \
                    AND field.jpeg_app1_offset >= 0 \
                    AND field.bmff_box_offset IS NULL \
                    AND field.bmff_box_path IS NULL \
                )) \
                OR (field.container_kind = 'iso_bmff' AND NOT ( \
                    field.tiff_header_offset IS NULL \
                    AND field.tiff_ifd_offset IS NULL \
                    AND field.tiff_tag IS NULL \
                    AND field.tiff_byte_order IS NULL \
                    AND field.jpeg_app1_offset IS NULL \
                    AND field.bmff_box_offset IS NOT NULL \
                    AND field.bmff_box_offset >= 0 \
                    AND field.bmff_box_path IS NOT NULL \
                )) \
         )",
        "metadata extraction field violates typed locator or payload bounds",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM metadata_extraction_issues AS issue \
             JOIN metadata_extraction_reports AS report ON report.id = issue.report_id \
             WHERE issue.ordinal NOT BETWEEN 0 AND 4095 \
                OR issue.ordinal >= report.expected_issue_count \
                OR length(CAST(issue.parser_name AS BLOB)) NOT BETWEEN 1 AND 128 \
                OR length(CAST(issue.parser_version AS BLOB)) NOT BETWEEN 1 AND 128 \
                OR issue.issue_code NOT IN ( \
                    'io', 'unexpected_eof', 'arithmetic_overflow', 'out_of_bounds', \
                    'invalid_structure', 'cycle_detected', 'limit_exceeded', \
                    'unsupported_version', 'invalid_source' \
                ) \
                OR (issue.source_offset IS NOT NULL AND ( \
                    issue.source_offset < 0 OR issue.source_offset > report.source_size_bytes \
                )) \
                OR length(CAST(issue.context AS BLOB)) NOT BETWEEN 1 AND 4096 \
                OR issue.created_at_ms < 0 \
         )",
        "metadata extraction issue violates typed ordinal, locator, or text bounds",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM metadata_source_revalidations AS revalidation \
             LEFT JOIN metadata_extraction_reports AS report \
               ON report.id = revalidation.report_id \
             LEFT JOIN media_observation_snapshots AS observation \
               ON observation.id = revalidation.metadata_probe_observation_id \
              AND observation.scan_run_id = revalidation.scan_run_id \
              AND observation.volume_id = revalidation.volume_id \
             WHERE report.id IS NULL \
                OR observation.id IS NULL \
                OR revalidation.time_session_id <> report.time_session_id \
                OR revalidation.volume_id <> report.volume_id \
                OR revalidation.scan_run_id <> report.scan_run_id \
                OR revalidation.core_session_id <> report.core_session_id \
                OR revalidation.exact_group_build_id <> report.exact_group_build_id \
                OR revalidation.metadata_probe_observation_id <> \
                    report.metadata_probe_observation_id \
                OR length(revalidation.core_session_id) <> 32 \
                OR length(revalidation.source_key) <> 32 \
                OR revalidation.source_key_version <> 2 \
                OR length(revalidation.lineage_key) <> 32 \
                OR revalidation.lineage_key_version <> 1 \
                OR length(revalidation.source_signature_before) <> 32 \
                OR length(revalidation.source_signature_after) <> 32 \
                OR revalidation.source_signature_before <> observation.source_signature \
                OR revalidation.source_signature_after <> observation.source_signature \
                OR revalidation.source_signature_before <> \
                    revalidation.source_signature_after \
                OR length(revalidation.first_report_digest) <> 32 \
                OR length(revalidation.second_report_digest) <> 32 \
                OR revalidation.first_report_digest <> report.retained_report_digest \
                OR revalidation.second_report_digest <> report.retained_report_digest \
                OR revalidation.first_report_digest <> revalidation.second_report_digest \
                OR revalidation.outcome <> 'reextracted_pinned_exact' \
                OR revalidation.descriptor_revalidated <> 1 \
                OR revalidation.path_revalidated <> 1 \
                OR revalidation.session_revalidated <> 1 \
                OR revalidation.trust_scope <> 'historical_proof_only' \
                OR revalidation.revalidated_at_ms < report.created_at_ms \
                OR revalidation.revalidated_at_ms < COALESCE(( \
                    SELECT max(field.created_at_ms) \
                    FROM metadata_extraction_fields AS field \
                    WHERE field.report_id = report.id \
                ), report.created_at_ms) \
                OR revalidation.revalidated_at_ms < COALESCE(( \
                    SELECT max(issue.created_at_ms) \
                    FROM metadata_extraction_issues AS issue \
                    WHERE issue.report_id = report.id \
                ), report.created_at_ms) \
                OR (report.finalized_at_ms IS NOT NULL \
                    AND revalidation.revalidated_at_ms > report.finalized_at_ms) \
         )",
        "metadata source revalidation violates its pinned report or source bounds",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM capture_time_analysis_builds AS build \
             WHERE length(CAST(build.policy_name AS BLOB)) NOT BETWEEN 1 AND 128 \
                OR length(CAST(build.policy_version AS BLOB)) NOT BETWEEN 1 AND 128 \
                OR length(CAST(build.policy_context_json AS BLOB)) NOT BETWEEN 2 AND 1048576 \
                OR length(build.policy_context_digest) <> 32 \
                OR build.state NOT IN ('draft', 'sealed', 'abandoned') \
                OR (build.decision IS NOT NULL AND build.decision NOT IN ( \
                    'no_usable_evidence', 'review_required', 'evidence_eligible', 'conflict' \
                )) \
                OR (build.selected_candidate_ordinal IS NOT NULL \
                    AND build.selected_candidate_ordinal < 0) \
                OR build.expected_source_count NOT BETWEEN 1 AND 4096 \
                OR build.expected_observation_count NOT BETWEEN 0 AND 8192 \
                OR build.expected_candidate_count NOT BETWEEN 0 AND 8192 \
                OR build.expected_issue_count NOT BETWEEN 0 AND 8192 \
                OR build.expected_member_count NOT BETWEEN 2 AND 8192 \
                OR build.expected_recommendation_count <> 1 \
                OR build.manifest_version <> 1 \
                OR length(build.expected_manifest_digest) <> 32 \
                OR (build.sealed_manifest_digest IS NOT NULL \
                    AND length(build.sealed_manifest_digest) <> 32) \
                OR build.created_at_ms < 0 \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND build.finalized_at_ms < build.created_at_ms) \
                OR (build.state = 'draft' AND ( \
                    build.decision IS NOT NULL \
                    OR build.selected_candidate_ordinal IS NOT NULL \
                    OR build.sealed_manifest_digest IS NOT NULL \
                    OR build.abandon_reason_code IS NOT NULL \
                    OR build.abandon_reason_message IS NOT NULL \
                    OR build.finalized_at_ms IS NOT NULL \
                )) \
                OR (build.state = 'sealed' AND ( \
                    build.decision IS NULL \
                    OR (build.decision IN ('review_required', 'evidence_eligible') \
                        AND build.selected_candidate_ordinal IS NULL) \
                    OR (build.decision IN ('no_usable_evidence', 'conflict') \
                        AND build.selected_candidate_ordinal IS NOT NULL) \
                    OR build.sealed_manifest_digest <> build.expected_manifest_digest \
                    OR build.abandon_reason_code IS NOT NULL \
                    OR build.abandon_reason_message IS NOT NULL \
                    OR build.finalized_at_ms IS NULL \
                )) \
                OR (build.state = 'abandoned' AND ( \
                    build.decision IS NOT NULL \
                    OR build.selected_candidate_ordinal IS NOT NULL \
                    OR build.sealed_manifest_digest IS NOT NULL \
                    OR build.abandon_reason_code IS NULL \
                    OR build.finalized_at_ms IS NULL \
                )) \
                OR (build.abandon_reason_code IS NOT NULL AND \
                    length(CAST(build.abandon_reason_code AS BLOB)) NOT BETWEEN 1 AND 256) \
                OR (build.abandon_reason_message IS NOT NULL AND \
                    length(CAST(build.abandon_reason_message AS BLOB)) NOT BETWEEN 1 AND 65536) \
         )",
        "capture-time analysis violates typed counts, policy, manifest, or state bounds",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM capture_time_analysis_sources AS source \
             LEFT JOIN capture_time_analysis_builds AS build \
               ON build.id = source.analysis_build_id \
             LEFT JOIN metadata_extraction_reports AS report ON report.id = source.report_id \
             LEFT JOIN metadata_source_revalidations AS revalidation \
               ON revalidation.report_id = source.report_id \
              AND revalidation.source_key = source.source_key \
              AND revalidation.lineage_key = source.lineage_key \
             WHERE build.id IS NULL \
                OR report.id IS NULL \
                OR revalidation.id IS NULL \
                OR source.ordinal NOT BETWEEN 0 AND 4095 \
                OR source.ordinal >= build.expected_source_count \
                OR length(source.source_key) <> 32 \
                OR length(source.lineage_key) <> 32 \
                OR source.binding_status <> 'reextracted_pinned_source' \
                OR source.created_at_ms < MAX(build.created_at_ms, report.finalized_at_ms) \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND source.created_at_ms > build.finalized_at_ms) \
                OR report.state <> 'sealed' \
                OR report.time_session_id <> build.time_session_id \
                OR report.exact_group_build_id <> build.exact_group_build_id \
         )",
        "capture-time analysis source violates its sealed revalidated report binding",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM capture_time_observations AS observation \
             JOIN capture_time_analysis_builds AS build \
               ON build.id = observation.analysis_build_id \
             WHERE observation.ordinal NOT BETWEEN 0 AND 8191 \
                OR observation.ordinal >= build.expected_observation_count \
                OR observation.source_ordinal NOT BETWEEN 0 AND 4095 \
                OR observation.interpretation_kind NOT IN ( \
                    'timestamp', 'offset', 'subsecond', 'rejected' \
                ) \
                OR observation.created_at_ms < build.created_at_ms \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND observation.created_at_ms > build.finalized_at_ms) \
                OR (observation.interpretation_kind = 'timestamp' AND NOT ( \
                    observation.wall_year IS NOT NULL \
                    AND observation.wall_month IS NOT NULL \
                    AND observation.wall_day IS NOT NULL \
                    AND observation.wall_hour IS NOT NULL \
                    AND observation.wall_minute IS NOT NULL \
                    AND observation.wall_second IS NOT NULL \
                    AND observation.wall_nanosecond IS NOT NULL \
                    AND observation.semantic_kind IS NOT NULL \
                    AND observation.offset_kind IS NOT NULL \
                    AND observation.normalized_precision_ns IS NOT NULL \
                    AND observation.parsed_offset_minutes IS NULL \
                    AND observation.subsecond_nanosecond IS NULL \
                    AND observation.subsecond_digits IS NULL \
                    AND observation.subsecond_precision_ns IS NULL \
                    AND observation.rejection_code IS NULL \
                )) \
                OR (observation.interpretation_kind = 'offset' AND NOT ( \
                    observation.wall_year IS NULL \
                    AND observation.wall_month IS NULL \
                    AND observation.wall_day IS NULL \
                    AND observation.wall_hour IS NULL \
                    AND observation.wall_minute IS NULL \
                    AND observation.wall_second IS NULL \
                    AND observation.wall_nanosecond IS NULL \
                    AND observation.semantic_kind IS NULL \
                    AND observation.offset_kind IS NULL \
                    AND observation.utc_offset_minutes IS NULL \
                    AND observation.utc_seconds_decimal IS NULL \
                    AND observation.utc_nanoseconds IS NULL \
                    AND observation.normalized_precision_ns IS NULL \
                    AND observation.parsed_offset_minutes IS NOT NULL \
                    AND observation.parsed_offset_minutes BETWEEN -840 AND 840 \
                    AND observation.subsecond_nanosecond IS NULL \
                    AND observation.subsecond_digits IS NULL \
                    AND observation.subsecond_precision_ns IS NULL \
                    AND observation.rejection_code IS NULL \
                )) \
                OR (observation.interpretation_kind = 'subsecond' AND NOT ( \
                    observation.wall_year IS NULL \
                    AND observation.wall_month IS NULL \
                    AND observation.wall_day IS NULL \
                    AND observation.wall_hour IS NULL \
                    AND observation.wall_minute IS NULL \
                    AND observation.wall_second IS NULL \
                    AND observation.wall_nanosecond IS NULL \
                    AND observation.semantic_kind IS NULL \
                    AND observation.offset_kind IS NULL \
                    AND observation.utc_offset_minutes IS NULL \
                    AND observation.utc_seconds_decimal IS NULL \
                    AND observation.utc_nanoseconds IS NULL \
                    AND observation.normalized_precision_ns IS NULL \
                    AND observation.parsed_offset_minutes IS NULL \
                    AND observation.subsecond_nanosecond IS NOT NULL \
                    AND observation.subsecond_nanosecond BETWEEN 0 AND 999999999 \
                    AND observation.subsecond_digits IS NOT NULL \
                    AND observation.subsecond_digits BETWEEN 1 AND 9 \
                    AND observation.subsecond_precision_ns IS NOT NULL \
                    AND observation.subsecond_precision_ns BETWEEN 1 AND 1000000000 \
                    AND observation.rejection_code IS NULL \
                )) \
                OR (observation.interpretation_kind = 'rejected' AND NOT ( \
                    observation.wall_year IS NULL \
                    AND observation.wall_month IS NULL \
                    AND observation.wall_day IS NULL \
                    AND observation.wall_hour IS NULL \
                    AND observation.wall_minute IS NULL \
                    AND observation.wall_second IS NULL \
                    AND observation.wall_nanosecond IS NULL \
                    AND observation.semantic_kind IS NULL \
                    AND observation.offset_kind IS NULL \
                    AND observation.utc_offset_minutes IS NULL \
                    AND observation.utc_seconds_decimal IS NULL \
                    AND observation.utc_nanoseconds IS NULL \
                    AND observation.normalized_precision_ns IS NULL \
                    AND observation.parsed_offset_minutes IS NULL \
                    AND observation.subsecond_nanosecond IS NULL \
                    AND observation.subsecond_digits IS NULL \
                    AND observation.subsecond_precision_ns IS NULL \
                    AND observation.rejection_code IS NOT NULL \
                    AND observation.rejection_code IN ( \
                        'empty', 'invalid_encoding', 'invalid_syntax', \
                        'year_out_of_range', 'month_out_of_range', 'day_out_of_range', \
                        'hour_out_of_range', 'minute_out_of_range', \
                        'second_out_of_range', 'nanosecond_out_of_range', \
                        'subsecond_out_of_range', 'offset_out_of_range', \
                        'unknown_negative_zero_offset', 'precision_out_of_range', \
                        'unsupported_binary_length', 'arithmetic_overflow' \
                    ) \
                )) \
         )",
        "capture-time observation violates typed ordinal or interpretation bounds",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM capture_time_candidates AS candidate \
             JOIN capture_time_analysis_builds AS build \
               ON build.id = candidate.analysis_build_id \
             WHERE candidate.ordinal NOT BETWEEN 0 AND 8191 \
                OR candidate.ordinal >= build.expected_candidate_count \
                OR candidate.confidence NOT IN ('conflict', 'low', 'medium', 'high') \
                OR candidate.evidence_gate NOT IN ('eligible', 'blocked') \
                OR candidate.created_at_ms < build.created_at_ms \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND candidate.created_at_ms > build.finalized_at_ms) \
                OR length(CAST(candidate.evidence_kinds_json AS BLOB)) \
                    NOT BETWEEN 2 AND 1048576 \
                OR length(CAST(candidate.source_keys_json AS BLOB)) \
                    NOT BETWEEN 2 AND 1048576 \
                OR length(CAST(candidate.lineage_keys_json AS BLOB)) \
                    NOT BETWEEN 2 AND 1048576 \
                OR length(CAST(candidate.observation_ordinals_json AS BLOB)) \
                    NOT BETWEEN 2 AND 1048576 \
                OR length(CAST(candidate.anomalies_json AS BLOB)) \
                    NOT BETWEEN 2 AND 1048576 \
                OR length(CAST(candidate.blockers_json AS BLOB)) \
                    NOT BETWEEN 2 AND 1048576 \
                OR NOT json_valid(candidate.evidence_kinds_json) \
                OR NOT json_valid(candidate.source_keys_json) \
                OR NOT json_valid(candidate.lineage_keys_json) \
                OR NOT json_valid(candidate.observation_ordinals_json) \
                OR NOT json_valid(candidate.anomalies_json) \
                OR NOT json_valid(candidate.blockers_json) \
         )",
        "capture-time candidate violates typed ordinal, chronology, or JSON byte bounds",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM capture_time_policy_issues AS issue \
             JOIN capture_time_analysis_builds AS build \
               ON build.id = issue.analysis_build_id \
             WHERE issue.ordinal NOT BETWEEN 0 AND 8191 \
                OR issue.ordinal >= build.expected_issue_count \
                OR length(CAST(issue.context AS BLOB)) NOT BETWEEN 1 AND 4096 \
                OR issue.created_at_ms < build.created_at_ms \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND issue.created_at_ms > build.finalized_at_ms) \
                OR length(CAST(issue.observation_ordinals_json AS BLOB)) \
                    NOT BETWEEN 2 AND 1048576 \
                OR length(CAST(issue.source_keys_json AS BLOB)) \
                    NOT BETWEEN 2 AND 1048576 \
                OR length(CAST(issue.lineage_keys_json AS BLOB)) \
                    NOT BETWEEN 2 AND 1048576 \
                OR NOT json_valid(issue.observation_ordinals_json) \
                OR NOT json_valid(issue.source_keys_json) \
                OR NOT json_valid(issue.lineage_keys_json) \
         )",
        "capture-time policy issue violates typed ordinal, chronology, or JSON byte bounds",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM capture_time_group_outcomes AS outcome \
             JOIN scan_time_sessions AS time_session \
               ON time_session.id = outcome.time_session_id \
             WHERE outcome.outcome NOT IN ('evidence', 'unavailable', 'failed') \
                OR (outcome.outcome = 'evidence' AND outcome.analysis_build_id IS NULL) \
                OR (outcome.outcome IN ('unavailable', 'failed') \
                    AND outcome.analysis_build_id IS NOT NULL) \
                OR length(CAST(outcome.reason_code AS BLOB)) NOT BETWEEN 1 AND 256 \
                OR outcome.created_at_ms < time_session.created_at_ms \
                OR (time_session.finalized_at_ms IS NOT NULL \
                    AND outcome.created_at_ms > time_session.finalized_at_ms) \
         )",
        "capture-time group outcome violates its typed state or chronology bounds",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM capture_time_member_assessments AS member \
             JOIN capture_time_analysis_builds AS build \
               ON build.id = member.analysis_build_id \
             JOIN media_observation_snapshots AS observation \
               ON observation.id = member.media_observation_snapshot_id \
              AND observation.scan_run_id = member.scan_run_id \
              AND observation.volume_id = member.volume_id \
             LEFT JOIN capture_time_candidates AS candidate \
               ON candidate.analysis_build_id = member.analysis_build_id \
              AND candidate.id = member.candidate_id \
             WHERE member.member_ordinal < 0 \
                OR member.member_ordinal >= build.expected_member_count \
                OR member.volume_id <> build.volume_id \
                OR member.scan_run_id <> build.scan_run_id \
                OR member.exact_group_build_id <> build.exact_group_build_id \
                OR member.birth_time_relation NOT IN ( \
                    'unavailable', 'not_compared', 'matches', 'differs', \
                    'review_fs_precision_unknown' \
                ) \
                OR member.modified_time_relation NOT IN ( \
                    'not_compared', 'matches', 'differs', 'review_fs_precision_unknown' \
                ) \
                OR member.donor_eligibility <> 'ineligible' \
                OR length(CAST(member.reason_code AS BLOB)) NOT BETWEEN 1 AND 256 \
                OR member.created_at_ms < build.created_at_ms \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND member.created_at_ms > build.finalized_at_ms) \
                OR (member.birth_time_relation = 'unavailable') <> \
                    (observation.birth_time_seconds IS NULL) \
                OR (member.candidate_id IS NULL AND ( \
                    member.birth_time_relation NOT IN ('unavailable', 'not_compared') \
                    OR member.modified_time_relation <> 'not_compared' \
                    OR member.reason_code <> 'no_strong_embedded_candidate' \
                )) \
                OR (member.candidate_id IS NOT NULL AND ( \
                    candidate.id IS NULL \
                    OR candidate.evidence_gate <> 'eligible' \
                    OR candidate.semantic_kind <> 'utc' \
                    OR (observation.timestamp_granularity_ns IS NULL AND ( \
                        member.birth_time_relation <> CASE \
                            WHEN observation.birth_time_seconds IS NULL \
                            THEN 'unavailable' \
                            ELSE 'review_fs_precision_unknown' \
                        END \
                        OR member.modified_time_relation <> \
                            'review_fs_precision_unknown' \
                        OR member.reason_code <> 'fs_precision_unknown' \
                    )) \
                    OR (observation.timestamp_granularity_ns IS NOT NULL AND ( \
                        member.birth_time_relation NOT IN ( \
                            'unavailable', 'matches', 'differs' \
                        ) \
                        OR member.modified_time_relation NOT IN ('matches', 'differs') \
                        OR member.reason_code <> CASE \
                            WHEN member.birth_time_relation = 'matches' \
                              OR member.modified_time_relation = 'matches' \
                            THEN 'embedded_time_matches_fs' \
                            ELSE 'embedded_time_differs_fs' \
                        END \
                    )) \
                )) \
         )",
        "capture-time member assessment violates exact-member or donor eligibility bounds",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM capture_time_recommendations AS recommendation \
             JOIN capture_time_analysis_builds AS build \
               ON build.id = recommendation.analysis_build_id \
             WHERE recommendation.volume_id <> build.volume_id \
                OR recommendation.scan_run_id <> build.scan_run_id \
                OR recommendation.exact_group_build_id <> build.exact_group_build_id \
                OR recommendation.evidence_only <> 1 \
                OR recommendation.write_authorized <> 0 \
                OR length(CAST(recommendation.reason_code AS BLOB)) NOT BETWEEN 1 AND 256 \
                OR recommendation.created_at_ms < build.created_at_ms \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND recommendation.created_at_ms > build.finalized_at_ms) \
                OR (recommendation.keeper_policy_name IS NOT NULL AND \
                    length(CAST(recommendation.keeper_policy_name AS BLOB)) \
                        NOT BETWEEN 1 AND 128) \
                OR (recommendation.keeper_policy_version IS NOT NULL AND \
                    length(CAST(recommendation.keeper_policy_version AS BLOB)) \
                        NOT BETWEEN 1 AND 128) \
                OR (recommendation.time_donor_policy_name IS NOT NULL AND \
                    length(CAST(recommendation.time_donor_policy_name AS BLOB)) \
                        NOT BETWEEN 1 AND 128) \
                OR (recommendation.time_donor_policy_version IS NOT NULL AND \
                    length(CAST(recommendation.time_donor_policy_version AS BLOB)) \
                        NOT BETWEEN 1 AND 128) \
                OR (recommendation.keeper_observation_id IS NULL AND ( \
                    recommendation.keeper_policy_name IS NOT NULL \
                    OR recommendation.keeper_policy_version IS NOT NULL \
                    OR recommendation.time_donor_observation_id IS NOT NULL \
                    OR recommendation.candidate_id IS NOT NULL \
                    OR recommendation.time_donor_policy_name IS NOT NULL \
                    OR recommendation.time_donor_policy_version IS NOT NULL \
                )) \
                OR (recommendation.keeper_observation_id IS NOT NULL AND ( \
                    recommendation.keeper_policy_name IS NULL \
                    OR recommendation.keeper_policy_version IS NULL \
                    OR ((recommendation.time_donor_observation_id IS NULL) <> \
                        (recommendation.candidate_id IS NULL)) \
                    OR ((recommendation.time_donor_observation_id IS NULL) <> \
                        (recommendation.time_donor_policy_name IS NULL)) \
                    OR ((recommendation.time_donor_observation_id IS NULL) <> \
                        (recommendation.time_donor_policy_version IS NULL)) \
                )) \
         )",
        "capture-time recommendation violates evidence-only identity or policy bounds",
    )?;
    Ok(())
}

fn validate_capture_time_evidence(connection: &Connection) -> Result<()> {
    validate_capture_time_declared_bounds(connection)?;
    crate::repository::validate_capture_time_member_relations(connection)?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_time_sessions AS time_session \
             LEFT JOIN scan_core_sessions AS core \
               ON core.scan_run_id = time_session.scan_run_id \
              AND core.volume_id = time_session.volume_id \
              AND core.core_session_id = time_session.core_session_id \
             LEFT JOIN scan_run_sessions AS run_session \
               ON run_session.scan_run_id = core.scan_run_id \
              AND run_session.volume_id = core.volume_id \
              AND run_session.capability_profile_id = core.capability_profile_id \
              AND run_session.namespace_profile_id = core.namespace_profile_id \
             LEFT JOIN scan_runs AS run \
               ON run.id = run_session.scan_run_id \
              AND run.volume_id = run_session.volume_id \
             LEFT JOIN scan_jobs AS job \
               ON job.id = run_session.scan_job_id \
              AND job.volume_id = run_session.volume_id \
              AND job.active_scan_run_id = run.id \
             LEFT JOIN capability_profiles AS profile \
               ON profile.id = run_session.capability_profile_id \
              AND profile.volume_id = run_session.volume_id \
             LEFT JOIN scan_stage_seals AS exact_seal \
               ON exact_seal.scan_run_id = time_session.scan_run_id \
              AND exact_seal.volume_id = time_session.volume_id \
              AND exact_seal.stage = 'exact_verification' \
             WHERE core.scan_run_id IS NULL \
                OR run_session.scan_run_id IS NULL \
                OR run.id IS NULL \
                OR job.id IS NULL \
                OR profile.id IS NULL \
                OR exact_seal.scan_run_id IS NULL \
                OR run.state <> 'completed' \
                OR job.state <> 'completed' \
                OR time_session.created_at_ms < core.bound_at_ms \
                OR time_session.created_at_ms < exact_seal.sealed_at_ms \
                OR (time_session.state = 'draft' AND ( \
                    profile.profile_hash_version <> 2 \
                    OR profile.probe_status <> 'complete' \
                    OR profile.can_read <> 1 \
                    OR profile.is_current <> 1 \
                    OR profile.mount_session_key <> \
                        run_session.mount_session_key COLLATE BINARY \
                )) \
                OR time_session.expected_group_count <> ( \
                    SELECT count(*) FROM exact_group_builds AS exact_build \
                    WHERE exact_build.scan_run_id = time_session.scan_run_id \
                      AND exact_build.volume_id = time_session.volume_id \
                      AND exact_build.state = 'verified' \
                ) \
                OR (time_session.state <> 'draft' AND ( \
                    EXISTS ( \
                        SELECT 1 FROM metadata_extraction_reports AS report \
                        WHERE report.time_session_id = time_session.id \
                          AND report.state = 'draft' \
                    ) \
                    OR EXISTS ( \
                        SELECT 1 FROM capture_time_analysis_builds AS build \
                        WHERE build.time_session_id = time_session.id \
                          AND build.state = 'draft' \
                    ) \
                    OR time_session.finalized_at_ms < COALESCE(( \
                        SELECT max(report.finalized_at_ms) \
                        FROM metadata_extraction_reports AS report \
                        WHERE report.time_session_id = time_session.id \
                    ), time_session.created_at_ms) \
                    OR time_session.finalized_at_ms < COALESCE(( \
                        SELECT max(build.finalized_at_ms) \
                        FROM capture_time_analysis_builds AS build \
                        WHERE build.time_session_id = time_session.id \
                    ), time_session.created_at_ms) \
                    OR time_session.finalized_at_ms < COALESCE(( \
                        SELECT max(outcome.created_at_ms) \
                        FROM capture_time_group_outcomes AS outcome \
                        WHERE outcome.time_session_id = time_session.id \
                    ), time_session.created_at_ms) \
                )) \
                OR (time_session.state IN ('complete', 'partial') AND ( \
                    EXISTS ( \
                        SELECT 1 FROM metadata_extraction_reports AS report \
                        WHERE report.time_session_id = time_session.id \
                          AND report.state = 'draft' \
                    ) \
                    OR EXISTS ( \
                        SELECT 1 FROM capture_time_analysis_builds AS build \
                        WHERE build.time_session_id = time_session.id \
                          AND build.state = 'draft' \
                    ) \
                    OR time_session.evidence_group_count <> ( \
                        SELECT count(*) FROM capture_time_group_outcomes AS outcome \
                        WHERE outcome.time_session_id = time_session.id \
                          AND outcome.outcome = 'evidence' \
                    ) \
                    OR time_session.unavailable_group_count <> ( \
                        SELECT count(*) FROM capture_time_group_outcomes AS outcome \
                        WHERE outcome.time_session_id = time_session.id \
                          AND outcome.outcome = 'unavailable' \
                    ) \
                    OR time_session.failed_group_count <> ( \
                        SELECT count(*) FROM capture_time_group_outcomes AS outcome \
                        WHERE outcome.time_session_id = time_session.id \
                          AND outcome.outcome = 'failed' \
                    ) \
                )) \
         )",
        "capture-time session is detached from core or has stale terminal coverage",
    )?;
    let mut session_manifest_statement = connection.prepare(
        "SELECT id, scan_run_id, expected_group_count, expected_manifest_digest, state, \
                sealed_manifest_digest, sealed_outcome_manifest_digest \
         FROM scan_time_sessions ORDER BY id",
    )?;
    let mut session_manifest_rows = session_manifest_statement.query([])?;
    while let Some(row) = session_manifest_rows.next()? {
        let id = row.get::<_, i64>(0)?;
        let scan_run_id = row.get::<_, i64>(1)?;
        let persisted_count = row.get::<_, i64>(2)?;
        let persisted_digest = row.get::<_, Vec<u8>>(3)?;
        let state = row.get::<_, String>(4)?;
        let sealed_scope = row.get::<_, Option<Vec<u8>>>(5)?;
        let sealed_outcomes = row.get::<_, Option<Vec<u8>>>(6)?;
        let (actual_count, actual_digest) =
            crate::repository::recompute_time_session_scope_manifest(connection, scan_run_id)?;
        if actual_count != persisted_count
            || persisted_digest.as_slice() != actual_digest.as_bytes()
        {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "capture-time session id {id} has a stale exact-scope manifest"
            )));
        }
        if matches!(state.as_str(), "complete" | "partial") {
            if sealed_scope.as_deref() != Some(actual_digest.as_bytes()) {
                return Err(StoreError::MigrationHistoryMismatch(format!(
                    "capture-time session id {id} has a stale sealed exact-scope manifest"
                )));
            }
            let actual_outcomes =
                crate::repository::recompute_time_session_outcome_manifest(connection, id)?;
            if sealed_outcomes.as_deref() != Some(actual_outcomes.as_bytes()) {
                return Err(StoreError::MigrationHistoryMismatch(format!(
                    "capture-time session id {id} has a stale sealed outcome manifest"
                )));
            }
        }
    }
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_time_sessions AS time_session \
             WHERE ( \
                 SELECT COALESCE(sum(report.usage_bytes_read), 0) \
                 FROM metadata_extraction_reports AS report \
                 WHERE report.time_session_id = time_session.id \
             ) > time_session.max_total_read_bytes / 2 \
         )",
        "capture-time session exceeded its immutable double-extraction read budget",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM capture_time_group_outcomes AS outcome \
             JOIN scan_time_sessions AS time_session \
               ON time_session.id = outcome.time_session_id \
             JOIN exact_group_builds AS exact_build \
               ON exact_build.id = outcome.exact_group_build_id \
              AND exact_build.scan_run_id = outcome.scan_run_id \
              AND exact_build.volume_id = outcome.volume_id \
             WHERE exact_build.state <> 'verified' \
                OR outcome.scan_run_id <> time_session.scan_run_id \
                OR outcome.volume_id <> time_session.volume_id \
                OR EXISTS ( \
                    SELECT 1 FROM metadata_extraction_reports AS report \
                    WHERE report.time_session_id = outcome.time_session_id \
                      AND report.exact_group_build_id = outcome.exact_group_build_id \
                      AND (report.state = 'draft' \
                           OR report.finalized_at_ms IS NULL \
                           OR report.finalized_at_ms > outcome.created_at_ms) \
                ) \
                OR EXISTS ( \
                    SELECT 1 FROM capture_time_analysis_builds AS build \
                    WHERE build.time_session_id = outcome.time_session_id \
                      AND build.exact_group_build_id = outcome.exact_group_build_id \
                      AND (build.state = 'draft' \
                           OR build.finalized_at_ms IS NULL \
                           OR build.finalized_at_ms > outcome.created_at_ms) \
                ) \
                OR (outcome.outcome = 'evidence' AND NOT EXISTS ( \
                    SELECT 1 FROM capture_time_analysis_builds AS build \
                    WHERE build.id = outcome.analysis_build_id \
                      AND build.time_session_id = outcome.time_session_id \
                      AND build.exact_group_build_id = outcome.exact_group_build_id \
                      AND build.state = 'sealed' \
                )) \
                OR (outcome.outcome IN ('unavailable', 'failed') AND EXISTS ( \
                    SELECT 1 FROM capture_time_analysis_builds AS build \
                    WHERE build.time_session_id = outcome.time_session_id \
                      AND build.exact_group_build_id = outcome.exact_group_build_id \
                      AND build.state = 'sealed' \
                )) \
         )",
        "capture-time group outcome is detached from its explicit terminal result",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM metadata_extraction_reports AS report \
             JOIN scan_time_sessions AS time_session \
               ON time_session.id = report.time_session_id \
             JOIN exact_group_builds AS exact_build \
               ON exact_build.id = report.exact_group_build_id \
              AND exact_build.scan_run_id = report.scan_run_id \
              AND exact_build.volume_id = report.volume_id \
             JOIN media_observation_snapshots AS observation \
               ON observation.id = report.metadata_probe_observation_id \
              AND observation.scan_run_id = report.scan_run_id \
              AND observation.volume_id = report.volume_id \
             JOIN observation_fingerprints AS fingerprint \
               ON fingerprint.id = report.metadata_probe_fingerprint_id \
              AND fingerprint.media_observation_snapshot_id = observation.id \
              AND fingerprint.scan_run_id = observation.scan_run_id \
              AND fingerprint.volume_id = observation.volume_id \
             WHERE exact_build.state <> 'verified' \
                OR report.core_session_id <> time_session.core_session_id \
                OR report.created_at_ms < time_session.created_at_ms \
                OR report.probe_ordinal >= time_session.max_probe_count_per_group \
                OR report.source_size_bytes <> observation.size_bytes \
                OR fingerprint.fingerprint_kind <> 'exact_bytes' \
                OR fingerprint.source_signature_before <> observation.source_signature \
                OR fingerprint.source_signature_after <> observation.source_signature \
                OR report.effective_max_total_bytes_read > \
                    time_session.max_report_total_bytes_read \
                OR report.effective_max_read_operations > \
                    time_session.max_report_read_operations \
                OR report.effective_max_retained_field_bytes > \
                    time_session.max_report_retained_field_bytes \
                OR report.effective_max_fields > time_session.max_report_fields \
                OR report.expected_issue_count > time_session.max_report_issues \
                OR (report.state = 'sealed' AND ( \
                    (SELECT count(*) FROM metadata_extraction_fields AS field \
                     WHERE field.report_id = report.id) <> report.expected_field_count \
                    OR (SELECT count(*) FROM metadata_extraction_issues AS issue \
                        WHERE issue.report_id = report.id) <> report.expected_issue_count \
                    OR COALESCE(( \
                        SELECT sum(length(field.raw_bytes)) \
                        FROM metadata_extraction_fields AS field \
                        WHERE field.report_id = report.id \
                    ), 0) <> report.expected_retained_field_bytes \
                    OR NOT EXISTS ( \
                        SELECT 1 FROM metadata_source_revalidations AS revalidation \
                        WHERE revalidation.report_id = report.id \
                          AND revalidation.source_key IS NOT NULL \
                          AND revalidation.lineage_key IS NOT NULL \
                          AND revalidation.first_report_digest = report.retained_report_digest \
                          AND revalidation.second_report_digest = report.retained_report_digest \
                          AND revalidation.source_signature_before = observation.source_signature \
                          AND revalidation.source_signature_after = observation.source_signature \
                    ) \
                )) \
         )",
        "metadata extraction report is detached, over budget, or incompletely sealed",
    )?;
    let mut report_manifest_statement = connection.prepare(
        "SELECT id, expected_manifest_digest, sealed_manifest_digest \
         FROM metadata_extraction_reports WHERE state = 'sealed' ORDER BY id",
    )?;
    let mut report_manifest_rows = report_manifest_statement.query([])?;
    while let Some(row) = report_manifest_rows.next()? {
        let id = row.get::<_, i64>(0)?;
        let expected = row.get::<_, Vec<u8>>(1)?;
        let sealed = row.get::<_, Vec<u8>>(2)?;
        let actual = crate::repository::recompute_metadata_report_manifest(connection, id)?;
        if expected.as_slice() != actual.as_bytes() || sealed.as_slice() != actual.as_bytes() {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "metadata extraction report id {id} has a stale sealed manifest"
            )));
        }
    }
    let mut source_key_statement = connection.prepare(
        "SELECT report_id, source_key, lineage_key \
         FROM metadata_source_revalidations ORDER BY report_id",
    )?;
    let mut source_key_rows = source_key_statement.query([])?;
    while let Some(row) = source_key_rows.next()? {
        let report_id = row.get::<_, i64>(0)?;
        let persisted_source = row.get::<_, Vec<u8>>(1)?;
        let persisted_lineage = row.get::<_, Vec<u8>>(2)?;
        let (actual_source, actual_lineage) =
            crate::repository::recompute_metadata_source_keys(connection, report_id)?;
        if persisted_source.as_slice() != actual_source.as_bytes()
            || persisted_lineage.as_slice() != actual_lineage.as_bytes()
        {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "metadata report id {report_id} has stale source or lineage identity"
            )));
        }
    }
    let mut raw_digest_statement = connection
        .prepare("SELECT id, raw_bytes, raw_digest FROM metadata_extraction_fields ORDER BY id")?;
    let mut raw_digest_rows = raw_digest_statement.query([])?;
    while let Some(row) = raw_digest_rows.next()? {
        let id = row.get::<_, i64>(0)?;
        let raw_bytes = row.get::<_, Vec<u8>>(1)?;
        let raw_digest = row.get::<_, Vec<u8>>(2)?;
        if raw_digest.as_slice() != blake3::hash(&raw_bytes).as_bytes() {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "metadata extraction field id {id} has a stale raw-byte digest"
            )));
        }
    }
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM metadata_extraction_fields AS field \
             JOIN metadata_extraction_reports AS report ON report.id = field.report_id \
             WHERE field.absolute_offset > report.source_size_bytes \
                OR field.byte_len > report.source_size_bytes - field.absolute_offset \
                OR field.byte_len > report.effective_max_field_bytes \
                OR COALESCE(field.tiff_header_offset, 0) > report.source_size_bytes \
                OR COALESCE(field.tiff_ifd_offset, 0) > report.source_size_bytes \
                OR COALESCE(field.jpeg_app1_offset, 0) > report.source_size_bytes \
                OR COALESCE(field.bmff_box_offset, 0) > report.source_size_bytes \
         )",
        "metadata field locator exceeds its immutable source or extraction budget",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM metadata_extraction_fields AS field \
             JOIN metadata_extraction_reports AS report ON report.id = field.report_id \
             WHERE field.created_at_ms < report.created_at_ms \
                OR (report.finalized_at_ms IS NOT NULL \
                    AND field.created_at_ms > report.finalized_at_ms) \
             UNION ALL \
             SELECT 1 FROM metadata_extraction_issues AS issue \
             JOIN metadata_extraction_reports AS report ON report.id = issue.report_id \
             WHERE issue.created_at_ms < report.created_at_ms \
                OR (report.finalized_at_ms IS NOT NULL \
                    AND issue.created_at_ms > report.finalized_at_ms) \
             UNION ALL \
             SELECT 1 FROM metadata_source_revalidations AS revalidation \
             JOIN metadata_extraction_reports AS report ON report.id = revalidation.report_id \
             WHERE revalidation.revalidated_at_ms < report.created_at_ms \
                OR (report.finalized_at_ms IS NOT NULL \
                    AND revalidation.revalidated_at_ms > report.finalized_at_ms) \
             LIMIT 1 \
         )",
        "metadata extraction evidence chronology is inconsistent",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM capture_time_analysis_builds AS build \
             JOIN scan_time_sessions AS time_session \
               ON time_session.id = build.time_session_id \
              AND time_session.scan_run_id = build.scan_run_id \
              AND time_session.volume_id = build.volume_id \
             JOIN exact_group_builds AS exact_build \
               ON exact_build.id = build.exact_group_build_id \
              AND exact_build.scan_run_id = build.scan_run_id \
              AND exact_build.volume_id = build.volume_id \
             WHERE exact_build.state <> 'verified' \
                OR build.created_at_ms < time_session.created_at_ms \
                OR build.expected_member_count <> exact_build.expected_member_count \
                OR (build.state = 'sealed' AND ( \
                    (SELECT count(*) FROM capture_time_analysis_sources AS source \
                     WHERE source.analysis_build_id = build.id) <> build.expected_source_count \
                    OR (SELECT count(*) FROM capture_time_observations AS observation \
                        WHERE observation.analysis_build_id = build.id) <> \
                       build.expected_observation_count \
                    OR (SELECT count(*) FROM capture_time_candidates AS candidate \
                        WHERE candidate.analysis_build_id = build.id) <> \
                       build.expected_candidate_count \
                    OR (SELECT count(*) FROM capture_time_policy_issues AS issue \
                        WHERE issue.analysis_build_id = build.id) <> build.expected_issue_count \
                    OR (SELECT count(*) FROM capture_time_member_assessments AS member \
                        WHERE member.analysis_build_id = build.id) <> build.expected_member_count \
                    OR (SELECT count(*) FROM capture_time_recommendations AS recommendation \
                        WHERE recommendation.analysis_build_id = build.id) <> \
                       build.expected_recommendation_count \
                    OR (build.selected_candidate_ordinal IS NOT NULL AND NOT EXISTS ( \
                        SELECT 1 FROM capture_time_candidates AS candidate \
                        WHERE candidate.analysis_build_id = build.id \
                          AND candidate.ordinal = build.selected_candidate_ordinal \
                    )) \
                    OR (build.decision = 'evidence_eligible' AND NOT EXISTS ( \
                        SELECT 1 FROM capture_time_candidates AS candidate \
                        WHERE candidate.analysis_build_id = build.id \
                          AND candidate.ordinal = build.selected_candidate_ordinal \
                          AND candidate.evidence_gate = 'eligible' \
                    )) \
                )) \
         )",
        "capture-time analysis is detached or its sealed counts are stale",
    )?;
    let mut analysis_manifest_statement = connection.prepare(
        "SELECT id, expected_manifest_digest, sealed_manifest_digest \
         FROM capture_time_analysis_builds WHERE state = 'sealed' ORDER BY id",
    )?;
    let mut analysis_manifest_rows = analysis_manifest_statement.query([])?;
    while let Some(row) = analysis_manifest_rows.next()? {
        let id = row.get::<_, i64>(0)?;
        let expected = row.get::<_, Vec<u8>>(1)?;
        let sealed = row.get::<_, Vec<u8>>(2)?;
        let actual = crate::repository::recompute_capture_time_analysis_manifest(connection, id)?;
        if expected.as_slice() != actual.as_bytes() || sealed.as_slice() != actual.as_bytes() {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "capture-time analysis id {id} has a stale sealed manifest"
            )));
        }
    }
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM capture_time_analysis_builds AS build \
             WHERE ( \
                 SELECT COALESCE(sum(report.expected_retained_field_bytes), 0) \
                 FROM capture_time_analysis_sources AS source \
                 JOIN metadata_extraction_reports AS report ON report.id = source.report_id \
                 WHERE source.analysis_build_id = build.id \
             ) > 33554432 \
                OR ( \
                    SELECT COALESCE(sum(report.expected_issue_count), 0) \
                    FROM capture_time_analysis_sources AS source \
                    JOIN metadata_extraction_reports AS report ON report.id = source.report_id \
                    WHERE source.analysis_build_id = build.id \
                ) > 8192 \
                OR ( \
                    SELECT COALESCE(sum(length(field.bmff_box_path) / 4), 0) \
                    FROM capture_time_analysis_sources AS source \
                    JOIN metadata_extraction_fields AS field \
                      ON field.report_id = source.report_id \
                    WHERE source.analysis_build_id = build.id \
                ) > 49152 \
                OR length(CAST(build.policy_context_json AS BLOB)) + ( \
                    SELECT COALESCE(sum( \
                        length(CAST(candidate.evidence_kinds_json AS BLOB)) \
                        + length(CAST(candidate.source_keys_json AS BLOB)) \
                        + length(CAST(candidate.lineage_keys_json AS BLOB)) \
                        + length(CAST(candidate.observation_ordinals_json AS BLOB)) \
                        + length(CAST(candidate.anomalies_json AS BLOB)) \
                        + length(CAST(candidate.blockers_json AS BLOB)) \
                    ), 0) \
                    FROM capture_time_candidates AS candidate \
                    WHERE candidate.analysis_build_id = build.id \
                ) + ( \
                    SELECT COALESCE(sum( \
                        length(CAST(issue.observation_ordinals_json AS BLOB)) \
                        + length(CAST(issue.source_keys_json AS BLOB)) \
                        + length(CAST(issue.lineage_keys_json AS BLOB)) \
                        + length(CAST(issue.context AS BLOB)) \
                    ), 0) \
                    FROM capture_time_policy_issues AS issue \
                    WHERE issue.analysis_build_id = build.id \
                ) > 16777216 \
         )",
        "capture-time analysis exceeds raw, issue, BMFF-path, or JSON byte limits",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM capture_time_analysis_sources AS source \
             JOIN capture_time_analysis_builds AS build ON build.id = source.analysis_build_id \
             JOIN metadata_extraction_reports AS report ON report.id = source.report_id \
             WHERE source.created_at_ms < MAX(build.created_at_ms, report.finalized_at_ms) \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND source.created_at_ms > build.finalized_at_ms) \
             UNION ALL \
             SELECT 1 FROM capture_time_observations AS observation \
             JOIN capture_time_analysis_builds AS build \
               ON build.id = observation.analysis_build_id \
             WHERE observation.created_at_ms < build.created_at_ms \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND observation.created_at_ms > build.finalized_at_ms) \
             UNION ALL \
             SELECT 1 FROM capture_time_candidates AS candidate \
             JOIN capture_time_analysis_builds AS build ON build.id = candidate.analysis_build_id \
             WHERE candidate.created_at_ms < build.created_at_ms \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND candidate.created_at_ms > build.finalized_at_ms) \
             UNION ALL \
             SELECT 1 FROM capture_time_policy_issues AS issue \
             JOIN capture_time_analysis_builds AS build ON build.id = issue.analysis_build_id \
             WHERE issue.created_at_ms < build.created_at_ms \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND issue.created_at_ms > build.finalized_at_ms) \
             UNION ALL \
             SELECT 1 FROM capture_time_member_assessments AS member \
             JOIN capture_time_analysis_builds AS build ON build.id = member.analysis_build_id \
             WHERE member.created_at_ms < build.created_at_ms \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND member.created_at_ms > build.finalized_at_ms) \
             UNION ALL \
             SELECT 1 FROM capture_time_recommendations AS recommendation \
             JOIN capture_time_analysis_builds AS build \
               ON build.id = recommendation.analysis_build_id \
             WHERE recommendation.created_at_ms < build.created_at_ms \
                OR (build.finalized_at_ms IS NOT NULL \
                    AND recommendation.created_at_ms > build.finalized_at_ms) \
             UNION ALL \
             SELECT 1 FROM capture_time_group_outcomes AS outcome \
             JOIN scan_time_sessions AS time_session ON time_session.id = outcome.time_session_id \
             WHERE outcome.created_at_ms < time_session.created_at_ms \
                OR (time_session.finalized_at_ms IS NOT NULL \
                    AND outcome.created_at_ms > time_session.finalized_at_ms) \
             LIMIT 1 \
         )",
        "capture-time evidence chronology is inconsistent",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM capture_time_recommendations AS recommendation \
             JOIN capture_time_analysis_builds AS build \
               ON build.id = recommendation.analysis_build_id \
             WHERE recommendation.evidence_only <> 1 \
                OR recommendation.write_authorized <> 0 \
                OR recommendation.volume_id <> build.volume_id \
                OR recommendation.scan_run_id <> build.scan_run_id \
                OR recommendation.exact_group_build_id <> build.exact_group_build_id \
                OR (recommendation.time_donor_observation_id IS NOT NULL AND NOT EXISTS ( \
                    SELECT 1 FROM capture_time_member_assessments AS member \
                    JOIN capture_time_candidates AS candidate \
                      ON candidate.analysis_build_id = member.analysis_build_id \
                     AND candidate.id = member.candidate_id \
                    WHERE member.analysis_build_id = recommendation.analysis_build_id \
                      AND member.media_observation_snapshot_id = \
                          recommendation.time_donor_observation_id \
                      AND member.candidate_id = recommendation.candidate_id \
                      AND member.donor_eligibility = 'eligible' \
                      AND candidate.evidence_gate = 'eligible' \
                      AND candidate.semantic_kind = 'utc' \
                )) \
         )",
        "capture-time recommendation escaped its evidence-only donor boundary",
    )?;
    validate_capture_time_normalized_values(connection)?;
    validate_capture_time_json_evidence(connection)?;
    crate::repository::validate_capture_time_candidate_supports(connection)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_normalized_capture_time(
    entity: &str,
    id: i64,
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    nanosecond: i64,
    semantic_kind: &str,
    offset_kind: &str,
    utc_offset_minutes: Option<i64>,
    utc_seconds_decimal: Option<&str>,
    utc_nanoseconds: Option<i64>,
    precision_ns: i64,
) -> Result<()> {
    let invalid = |reason: &str| {
        StoreError::MigrationHistoryMismatch(format!(
            "{entity} id {id} has an invalid normalized capture time: {reason}"
        ))
    };
    if !(1..=9_999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
        || !(0..=999_999_999).contains(&nanosecond)
        || !(1..=1_000_000_000).contains(&precision_ns)
        || nanosecond % precision_ns != 0
    {
        return Err(invalid("wall components or precision are inconsistent"));
    }

    match semantic_kind {
        "floating" => {
            if offset_kind != "missing"
                || utc_offset_minutes.is_some()
                || utc_seconds_decimal.is_some()
                || utc_nanoseconds.is_some()
            {
                return Err(invalid("floating time contains an invented UTC instant"));
            }
        }
        "utc" => {
            let offset = utc_offset_minutes
                .filter(|value| (-840..=840).contains(value))
                .ok_or_else(|| invalid("UTC offset is missing or outside +/-14:00"))?;
            if !matches!(offset_kind, "explicit" | "quicktime_epoch_assumed_utc")
                || (offset_kind == "quicktime_epoch_assumed_utc" && offset != 0)
            {
                return Err(invalid("UTC offset provenance is inconsistent"));
            }
            let decimal = utc_seconds_decimal.ok_or_else(|| invalid("UTC seconds are missing"))?;
            let utc_seconds = parse_canonical_i128(decimal)
                .ok_or_else(|| invalid("UTC seconds are not a canonical signed i128 decimal"))?;
            let persisted_nanoseconds = utc_nanoseconds
                .filter(|value| (0..=999_999_999).contains(value))
                .ok_or_else(|| invalid("UTC nanoseconds are missing or out of range"))?;
            let wall_seconds = wall_unix_seconds(year, month, day, hour, minute, second)
                .ok_or_else(|| invalid("wall time arithmetic overflowed"))?;
            let expected_utc = wall_seconds
                .checked_sub(i128::from(offset) * 60)
                .ok_or_else(|| invalid("wall-offset conversion overflowed"))?;
            if expected_utc != utc_seconds || persisted_nanoseconds != nanosecond {
                return Err(invalid("wall time, offset, and UTC instant disagree"));
            }
        }
        _ => return Err(invalid("unknown semantic kind")),
    }
    Ok(())
}

fn validate_capture_time_normalized_values(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT 'capture_time_observations', id, wall_year, wall_month, wall_day, \
                wall_hour, wall_minute, wall_second, wall_nanosecond, semantic_kind, \
                offset_kind, utc_offset_minutes, utc_seconds_decimal, utc_nanoseconds, \
                normalized_precision_ns \
         FROM capture_time_observations \
         WHERE interpretation_kind = 'timestamp' \
         UNION ALL \
         SELECT 'capture_time_candidates', id, wall_year, wall_month, wall_day, \
                wall_hour, wall_minute, wall_second, wall_nanosecond, semantic_kind, \
                offset_kind, utc_offset_minutes, utc_seconds_decimal, utc_nanoseconds, \
                precision_ns \
         FROM capture_time_candidates \
         ORDER BY 1, 2",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let entity = row.get::<_, String>(0)?;
        let id = row.get::<_, i64>(1)?;
        validate_normalized_capture_time(
            &entity,
            id,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            &row.get::<_, String>(9)?,
            &row.get::<_, String>(10)?,
            row.get(11)?,
            row.get::<_, Option<String>>(12)?.as_deref(),
            row.get(13)?,
            row.get(14)?,
        )?;
    }

    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM capture_time_observations AS observation \
             WHERE observation.interpretation_kind = 'subsecond' \
               AND (observation.subsecond_precision_ns <> \
                        CASE observation.subsecond_digits \
                            WHEN 1 THEN 100000000 \
                            WHEN 2 THEN 10000000 \
                            WHEN 3 THEN 1000000 \
                            WHEN 4 THEN 100000 \
                            WHEN 5 THEN 10000 \
                            WHEN 6 THEN 1000 \
                            WHEN 7 THEN 100 \
                            WHEN 8 THEN 10 \
                            WHEN 9 THEN 1 \
                        END \
                    OR observation.subsecond_nanosecond % \
                        observation.subsecond_precision_ns <> 0) \
         )",
        "capture-time subsecond interpretation has inconsistent digits or precision",
    )?;
    Ok(())
}

fn validate_capture_time_json_evidence(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT id, policy_context_json, policy_context_digest \
         FROM capture_time_analysis_builds ORDER BY id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let id = row.get::<_, i64>(0)?;
        let stored = row.get::<_, String>(1)?;
        let persisted_digest = row.get::<_, Vec<u8>>(2)?;
        let parsed: serde_json::Value = serde_json::from_str(&stored).map_err(|error| {
            StoreError::MigrationHistoryMismatch(format!(
                "capture-time analysis id {id} has invalid policy JSON: {error}"
            ))
        })?;
        let policy = parsed.as_object().ok_or_else(|| {
            StoreError::MigrationHistoryMismatch(format!(
                "capture-time analysis id {id} policy JSON is not an object"
            ))
        })?;
        if policy
            .get("sentinel_rules")
            .is_some_and(|rules| rules.as_array().map_or(true, |items| items.len() > 1_024))
        {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "capture-time analysis id {id} has invalid or oversized sentinel rules"
            )));
        }
        let canonical = canonical_json_text(&parsed).map_err(StoreError::from)?;
        if canonical != stored {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "capture-time analysis id {id} has non-canonical policy JSON"
            )));
        }
        let expected_digest = crate::repository::compute_time_policy_context_digest(&parsed)?;
        if persisted_digest.as_slice() != expected_digest.as_bytes() {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "capture-time analysis id {id} has a stale policy-context digest"
            )));
        }
    }

    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM capture_time_candidates AS candidate \
             WHERE json_type(candidate.evidence_kinds_json) <> 'array' \
                OR candidate.evidence_kinds_json <> json(candidate.evidence_kinds_json) \
                OR json_array_length(candidate.evidence_kinds_json) NOT BETWEEN 1 AND 8192 \
                OR json_type(candidate.source_keys_json) <> 'array' \
                OR candidate.source_keys_json <> json(candidate.source_keys_json) \
                OR json_array_length(candidate.source_keys_json) NOT BETWEEN 1 AND 4096 \
                OR json_type(candidate.lineage_keys_json) <> 'array' \
                OR candidate.lineage_keys_json <> json(candidate.lineage_keys_json) \
                OR json_array_length(candidate.lineage_keys_json) NOT BETWEEN 1 AND 4096 \
                OR json_type(candidate.observation_ordinals_json) <> 'array' \
                OR candidate.observation_ordinals_json <> \
                    json(candidate.observation_ordinals_json) \
                OR json_array_length(candidate.observation_ordinals_json) \
                    NOT BETWEEN 1 AND 8192 \
                OR json_type(candidate.anomalies_json) <> 'array' \
                OR candidate.anomalies_json <> json(candidate.anomalies_json) \
                OR json_array_length(candidate.anomalies_json) > 8192 \
                OR json_type(candidate.blockers_json) <> 'array' \
                OR candidate.blockers_json <> json(candidate.blockers_json) \
                OR json_array_length(candidate.blockers_json) > 8192 \
                OR (candidate.evidence_gate = 'eligible' AND ( \
                    candidate.confidence <> 'high' \
                    OR candidate.semantic_kind <> 'utc' \
                    OR candidate.offset_kind <> 'explicit' \
                    OR json_array_length(candidate.blockers_json) <> 0 \
                )) \
                OR (candidate.evidence_gate = 'blocked' \
                    AND json_array_length(candidate.blockers_json) < 1) \
         )",
        "capture-time candidate JSON is non-canonical, oversized, or gate-inconsistent",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM capture_time_policy_issues AS issue \
             WHERE issue.issue_code NOT IN ( \
                    'invalid_field', 'invalid_companion', 'orphan_exif_companion', \
                    'repeated_field_conflict', 'lineage_conflict', \
                    'strong_evidence_conflict', \
                    'strong_evidence_within_tolerance_ambiguous', \
                    'possible_timezone_conflict', 'sentinel_value', 'obvious_future', \
                    'outside_automatic_range', \
                    'quicktime_epoch_semantic_uncertainty', \
                    'extraction_report_untrusted', 'extraction_report_contradiction', \
                    'parser_identity_mismatch', 'field_encoding_mismatch', \
                    'container_format_mismatch', 'metadata_locator_mismatch', \
                    'duplicate_source_identity', 'unknown_parser_identity', \
                    'extraction_budget_contradiction', 'analysis_limit_exceeded' \
                ) \
                OR (issue.field_kind IS NOT NULL AND issue.field_kind NOT IN ( \
                    'exif_date_time_original', 'exif_create_date', 'exif_modify_date', \
                    'exif_offset_time_original', 'exif_subsec_time_original', \
                    'quicktime_movie_header_creation_time', \
                    'quicktime_metadata_creation_date' \
                )) \
                OR json_type(issue.observation_ordinals_json) <> 'array' \
                OR issue.observation_ordinals_json <> \
                    json(issue.observation_ordinals_json) \
                OR json_array_length(issue.observation_ordinals_json) > 8192 \
                OR json_type(issue.source_keys_json) <> 'array' \
                OR issue.source_keys_json <> json(issue.source_keys_json) \
                OR json_array_length(issue.source_keys_json) > 4096 \
                OR json_type(issue.lineage_keys_json) <> 'array' \
                OR issue.lineage_keys_json <> json(issue.lineage_keys_json) \
                OR json_array_length(issue.lineage_keys_json) > 4096 \
         )",
        "capture-time policy issue JSON or enum evidence is non-canonical",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM capture_time_candidates AS candidate, \
                  json_each(candidate.evidence_kinds_json) AS item \
             WHERE item.type <> 'text' \
                OR item.value NOT IN ( \
                    'exif_date_time_original', 'exif_create_date', 'exif_modify_date', \
                    'quicktime_metadata_creation_date', \
                    'quicktime_movie_header_creation_time' \
                ) \
             UNION ALL \
             SELECT 1 \
             FROM capture_time_candidates AS candidate, \
                  json_each(candidate.anomalies_json) AS item \
             WHERE item.type <> 'text' \
                OR item.value NOT IN ( \
                    'missing_offset', 'sentinel_value', 'obvious_future', \
                    'outside_automatic_range', \
                    'quicktime_epoch_semantic_uncertainty', 'invalid_companion' \
                ) \
             UNION ALL \
             SELECT 1 \
             FROM capture_time_candidates AS candidate, \
                  json_each(candidate.blockers_json) AS item \
             WHERE item.type <> 'text' \
                OR item.value NOT IN ( \
                    'confidence_below_high', 'no_utc_instant', 'evidence_conflict', \
                    'sentinel_value', 'obvious_future', 'outside_automatic_range', \
                    'quicktime_epoch_semantic_uncertainty', 'invalid_evidence_present', \
                    'extraction_report_untrusted', 'source_not_revalidated', \
                    'multiple_strong_values_within_tolerance' \
                ) \
             LIMIT 1 \
         )",
        "capture-time candidate JSON contains an unknown or non-text enum",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM capture_time_candidates AS candidate, \
                  json_each(candidate.source_keys_json) AS item \
             WHERE item.type <> 'text' \
                OR length(item.value) <> 64 \
                OR item.value GLOB '*[^0-9a-f]*' \
                OR NOT EXISTS ( \
                    SELECT 1 FROM capture_time_analysis_sources AS source \
                    WHERE source.analysis_build_id = candidate.analysis_build_id \
                      AND lower(hex(source.source_key)) = item.value \
                ) \
             UNION ALL \
             SELECT 1 \
             FROM capture_time_candidates AS candidate, \
                  json_each(candidate.lineage_keys_json) AS item \
             WHERE item.type <> 'text' \
                OR length(item.value) <> 64 \
                OR item.value GLOB '*[^0-9a-f]*' \
                OR NOT EXISTS ( \
                    SELECT 1 FROM capture_time_analysis_sources AS source \
                    WHERE source.analysis_build_id = candidate.analysis_build_id \
                      AND lower(hex(source.lineage_key)) = item.value \
                ) \
             UNION ALL \
             SELECT 1 \
             FROM capture_time_candidates AS candidate, \
                  json_each(candidate.observation_ordinals_json) AS item \
             WHERE item.type <> 'integer' \
                OR item.value < 0 \
                OR NOT EXISTS ( \
                    SELECT 1 FROM capture_time_observations AS observation \
                    WHERE observation.analysis_build_id = candidate.analysis_build_id \
                      AND observation.ordinal = item.value \
                ) \
             LIMIT 1 \
         )",
        "capture-time candidate JSON references an invalid source, lineage, or observation",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM ( \
                 SELECT candidate.id, item.value \
                 FROM capture_time_candidates AS candidate, \
                      json_each(candidate.evidence_kinds_json) AS item \
                 GROUP BY candidate.id, item.value HAVING count(*) > 1 \
                 UNION ALL \
                 SELECT candidate.id, item.value \
                 FROM capture_time_candidates AS candidate, \
                      json_each(candidate.source_keys_json) AS item \
                 GROUP BY candidate.id, item.value HAVING count(*) > 1 \
                 UNION ALL \
                 SELECT candidate.id, item.value \
                 FROM capture_time_candidates AS candidate, \
                      json_each(candidate.lineage_keys_json) AS item \
                 GROUP BY candidate.id, item.value HAVING count(*) > 1 \
                 UNION ALL \
                 SELECT candidate.id, item.value \
                 FROM capture_time_candidates AS candidate, \
                      json_each(candidate.observation_ordinals_json) AS item \
                 GROUP BY candidate.id, item.value HAVING count(*) > 1 \
                 UNION ALL \
                 SELECT candidate.id, item.value \
                 FROM capture_time_candidates AS candidate, \
                      json_each(candidate.anomalies_json) AS item \
                 GROUP BY candidate.id, item.value HAVING count(*) > 1 \
                 UNION ALL \
                 SELECT candidate.id, item.value \
                 FROM capture_time_candidates AS candidate, \
                      json_each(candidate.blockers_json) AS item \
                 GROUP BY candidate.id, item.value HAVING count(*) > 1 \
             ) LIMIT 1 \
         )",
        "capture-time candidate JSON contains duplicate support that could amplify confidence",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM capture_time_policy_issues AS issue, \
                  json_each(issue.source_keys_json) AS item \
             WHERE item.type <> 'text' \
                OR length(item.value) <> 64 \
                OR item.value GLOB '*[^0-9a-f]*' \
                OR NOT EXISTS ( \
                    SELECT 1 FROM capture_time_analysis_sources AS source \
                    WHERE source.analysis_build_id = issue.analysis_build_id \
                      AND lower(hex(source.source_key)) = item.value \
                ) \
             UNION ALL \
             SELECT 1 \
             FROM capture_time_policy_issues AS issue, \
                  json_each(issue.lineage_keys_json) AS item \
             WHERE item.type <> 'text' \
                OR length(item.value) <> 64 \
                OR item.value GLOB '*[^0-9a-f]*' \
                OR NOT EXISTS ( \
                    SELECT 1 FROM capture_time_analysis_sources AS source \
                    WHERE source.analysis_build_id = issue.analysis_build_id \
                      AND lower(hex(source.lineage_key)) = item.value \
                ) \
             UNION ALL \
             SELECT 1 \
             FROM capture_time_policy_issues AS issue, \
                  json_each(issue.observation_ordinals_json) AS item \
             WHERE item.type <> 'integer' \
                OR item.value < 0 \
                OR NOT EXISTS ( \
                    SELECT 1 FROM capture_time_observations AS observation \
                    WHERE observation.analysis_build_id = issue.analysis_build_id \
                      AND observation.ordinal = item.value \
                ) \
             LIMIT 1 \
         )",
        "capture-time policy issue JSON references invalid evidence",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM ( \
                 SELECT issue.id, item.value \
                 FROM capture_time_policy_issues AS issue, \
                      json_each(issue.source_keys_json) AS item \
                 GROUP BY issue.id, item.value HAVING count(*) > 1 \
                 UNION ALL \
                 SELECT issue.id, item.value \
                 FROM capture_time_policy_issues AS issue, \
                      json_each(issue.lineage_keys_json) AS item \
                 GROUP BY issue.id, item.value HAVING count(*) > 1 \
                 UNION ALL \
                 SELECT issue.id, item.value \
                 FROM capture_time_policy_issues AS issue, \
                      json_each(issue.observation_ordinals_json) AS item \
                 GROUP BY issue.id, item.value HAVING count(*) > 1 \
             ) LIMIT 1 \
         )",
        "capture-time policy issue JSON contains duplicate references",
    )?;
    Ok(())
}

fn canonical_json_text(value: &serde_json::Value) -> serde_json::Result<String> {
    serde_json::to_string(&canonicalize_json_value(value))
}

fn canonicalize_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonicalize_json_value).collect())
        }
        serde_json::Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            let mut canonical = serde_json::Map::new();
            for (key, value) in entries {
                canonical.insert(key.clone(), canonicalize_json_value(value));
            }
            serde_json::Value::Object(canonical)
        }
        scalar => scalar.clone(),
    }
}

fn parse_canonical_i128(value: &str) -> Option<i128> {
    if value.is_empty()
        || value.starts_with('+')
        || value == "-0"
        || (value.starts_with('0') && value.len() > 1)
        || (value.starts_with("-0"))
        || value.trim() != value
    {
        return None;
    }
    let parsed = value.parse::<i128>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn wall_unix_seconds(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> Option<i128> {
    let adjusted_year = year.checked_sub(i64::from(month <= 2))?;
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year.checked_sub(era.checked_mul(400)?)?;
    let shifted_month = month.checked_add(if month > 2 { -3 } else { 9 })?;
    let day_of_year = 153_i64
        .checked_mul(shifted_month)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(day.checked_sub(1)?)?;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era / 4)?
        .checked_sub(year_of_era / 100)?
        .checked_add(day_of_year)?;
    let days = era
        .checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)?;
    i128::from(days)
        .checked_mul(86_400)?
        .checked_add(i128::from(hour) * 3_600)?
        .checked_add(i128::from(minute) * 60)?
        .checked_add(i128::from(second))
}

fn validate_v6_upgrade_preconditions(connection: &Connection) -> Result<()> {
    validate_v6_evidence_chronology(connection)?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 \
             FROM scan_issues AS issue \
             JOIN scan_run_sessions AS session \
               ON session.scan_run_id = issue.scan_run_id \
              AND session.volume_id = issue.volume_id \
             WHERE issue.media_file_id IS NOT NULL \
               AND NOT EXISTS ( \
                   SELECT 1 FROM media_observation_snapshots AS observation \
                   WHERE observation.scan_run_id = issue.scan_run_id \
                     AND observation.volume_id = issue.volume_id \
                     AND observation.media_file_id = issue.media_file_id \
               ) \
         )",
        "v5 scan issue references media that was not observed by its run",
    )
}

fn validate_v6_evidence_chronology(connection: &Connection) -> Result<()> {
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM scan_stage_seals AS seal \
             WHERE (seal.stage = 'enumeration' AND seal.sealed_at_ms < COALESCE(( \
                       SELECT max(observation.observed_at_ms) \
                       FROM media_observation_snapshots AS observation \
                       WHERE observation.scan_run_id = seal.scan_run_id \
                   ), 0)) \
                OR (seal.stage = 'sampling' AND seal.sealed_at_ms < COALESCE(( \
                       SELECT max(fingerprint.completed_at_ms) \
                       FROM observation_fingerprints AS fingerprint \
                       WHERE fingerprint.scan_run_id = seal.scan_run_id \
                         AND fingerprint.fingerprint_kind = 'sample' \
                   ), 0)) \
                OR (seal.stage = 'full_hash' AND seal.sealed_at_ms < COALESCE(( \
                       SELECT max(fingerprint.completed_at_ms) \
                       FROM observation_fingerprints AS fingerprint \
                       WHERE fingerprint.scan_run_id = seal.scan_run_id \
                         AND fingerprint.fingerprint_kind = 'exact_bytes' \
                         AND fingerprint.read_origin = 'full_hash_read' \
                   ), 0)) \
                OR (seal.stage = 'exact_verification' AND seal.sealed_at_ms < MAX( \
                       COALESCE(( \
                           SELECT max(edge.verified_at_ms) \
                           FROM exact_verification_edges AS edge \
                           WHERE edge.scan_run_id = seal.scan_run_id \
                       ), 0), \
                       COALESCE(( \
                           SELECT max(build.finalized_at_ms) \
                           FROM exact_group_builds AS build \
                           WHERE build.scan_run_id = seal.scan_run_id \
                             AND build.state = 'verified' \
                       ), 0) \
                   )) \
         )",
        "scan stage seal predates the evidence it seals",
    )?;
    reject_if_exists(
        connection,
        "SELECT EXISTS( \
             SELECT 1 FROM exact_group_builds AS build \
             WHERE build.state = 'verified' \
               AND build.finalized_at_ms < COALESCE(( \
                   SELECT max(edge.verified_at_ms) \
                   FROM exact_verification_edges AS edge \
                   WHERE edge.exact_group_build_id = build.id \
               ), 0) \
         )",
        "verified exact group predates its comparison evidence",
    )
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
    if version >= 5 {
        for (table, predicate) in [
            (
                "namespace_profiles",
                String::from(
                    "(profile_key IS NOT NULL AND length(profile_key) <> 32) \
                     OR (bound_mount_session_key IS NOT NULL \
                         AND length(CAST(bound_mount_session_key AS BLOB)) <> 64)",
                ),
            ),
            (
                "scan_job_scopes",
                format!(
                    "length(CAST(root_display AS BLOB)) > {path} \
                     OR length(mount_relative_root_raw) > {path} \
                     OR (legacy_semantic_path_key IS NOT NULL \
                         AND length(legacy_semantic_path_key) NOT BETWEEN 1 AND {path_key})"
                ),
            ),
            (
                "scan_run_sessions",
                format!(
                    "length(CAST(mount_session_key AS BLOB)) <> 64 \
                     OR length(mount_relative_root_raw) > {path}"
                ),
            ),
            (
                "media_namespace_paths",
                format!(
                    "length(CAST(display_path AS BLOB)) NOT BETWEEN 1 AND {path} \
                     OR length(mount_relative_path_raw) NOT BETWEEN 1 AND {path}"
                ),
            ),
            (
                "media_observation_snapshots",
                format!(
                    "length(CAST(display_path AS BLOB)) NOT BETWEEN 1 AND {path} \
                     OR length(root_relative_path_raw) NOT BETWEEN 1 AND {path} \
                     OR (native_file_id IS NOT NULL \
                         AND length(native_file_id) NOT BETWEEN 1 AND {identifier})"
                ),
            ),
            (
                "observation_fingerprints",
                format!(
                    "length(CAST(algorithm AS BLOB)) NOT BETWEEN 1 AND {identifier} \
                     OR length(digest) NOT BETWEEN 1 AND {identifier}"
                ),
            ),
            (
                "exact_group_builds",
                format!(
                    "length(build_key) <> 32 \
                     OR length(expected_manifest_digest) <> 32 \
                     OR (group_key IS NOT NULL AND length(group_key) <> 32) \
                     OR (abandon_reason_code IS NOT NULL \
                         AND length(CAST(abandon_reason_code AS BLOB)) \
                             NOT BETWEEN 1 AND {identifier}) \
                     OR (abandon_reason_message IS NOT NULL \
                         AND length(CAST(abandon_reason_message AS BLOB)) \
                             NOT BETWEEN 1 AND {text})"
                ),
            ),
        ] {
            reject_if_exists(
                connection,
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {predicate})"),
                "stored v5 evidence exceeds a repository value bound",
            )?;
        }
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
    if version >= 5 {
        let mut statement = connection.prepare(
            "SELECT scan_job_id, root_display, mount_relative_root_raw, path_encoding \
             FROM scan_job_scopes ORDER BY scan_job_id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            validate_path_row(
                "scan_job_scopes",
                row.get(0)?,
                &row.get::<_, String>(1)?,
                &row.get::<_, Vec<u8>>(2)?,
                &row.get::<_, String>(3)?,
                true,
            )?;
        }

        let mut statement = connection.prepare(
            "SELECT session.scan_run_id, run.root_relative_path, \
                    session.mount_relative_root_raw, session.path_encoding \
             FROM scan_run_sessions AS session \
             JOIN scan_runs AS run ON run.id = session.scan_run_id \
             ORDER BY session.scan_run_id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            validate_path_row(
                "scan_run_sessions",
                row.get(0)?,
                &row.get::<_, String>(1)?,
                &row.get::<_, Vec<u8>>(2)?,
                &row.get::<_, String>(3)?,
                true,
            )?;
        }

        for (table, id_column, display_column, raw_column) in [
            (
                "media_namespace_paths",
                "id",
                "display_path",
                "mount_relative_path_raw",
            ),
            (
                "media_observation_snapshots",
                "id",
                "display_path",
                "root_relative_path_raw",
            ),
        ] {
            let sql = format!(
                "SELECT {id_column}, {display_column}, {raw_column}, path_encoding \
                 FROM {table} ORDER BY {id_column}"
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
                    false,
                )?;
            }
        }

        let mut statement = connection.prepare(
            "SELECT observation.id, session.mount_relative_root_raw, \
                    session.path_encoding, namespace_path.mount_relative_path_raw, \
                    namespace_path.path_encoding, observation.root_relative_path_raw, \
                    observation.path_encoding \
             FROM media_observation_snapshots AS observation \
             JOIN scan_run_sessions AS session \
               ON session.scan_run_id = observation.scan_run_id \
              AND session.volume_id = observation.volume_id \
              AND session.capability_profile_id = observation.capability_profile_id \
              AND session.namespace_profile_id = observation.namespace_profile_id \
             JOIN media_namespace_paths AS namespace_path \
               ON namespace_path.id = observation.media_namespace_path_id \
              AND namespace_path.volume_id = observation.volume_id \
              AND namespace_path.media_file_id = observation.media_file_id \
              AND namespace_path.namespace_profile_id = observation.namespace_profile_id \
             ORDER BY observation.id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let observation_id = row.get::<_, i64>(0)?;
            crate::repository::validate_v5_path_relation(
                &row.get::<_, Vec<u8>>(1)?,
                &row.get::<_, String>(2)?,
                &row.get::<_, Vec<u8>>(3)?,
                &row.get::<_, String>(4)?,
                &row.get::<_, Vec<u8>>(5)?,
                &row.get::<_, String>(6)?,
            )
            .map_err(|error| {
                StoreError::MigrationHistoryMismatch(format!(
                    "media observation id {observation_id} escapes its bound scan root: {error}"
                ))
            })?;
        }
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
    if migration.version == 6 {
        validate_v6_upgrade_preconditions(connection)?;
    }
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
    let mut begin_body_start = None;
    let mut commit_start = None;
    let mut offset = 0_usize;

    for segment in sql.split_inclusive('\n') {
        let without_lf = segment.strip_suffix('\n').unwrap_or(segment);
        let line = without_lf.strip_suffix('\r').unwrap_or(without_lf);
        match line {
            "BEGIN IMMEDIATE;" => {
                if begin_body_start.replace(offset + segment.len()).is_some() {
                    return Err(StoreError::MalformedMigration(
                        "initial migration must contain exactly one BEGIN IMMEDIATE boundary",
                    ));
                }
            }
            "COMMIT;" => {
                if commit_start.replace(offset).is_some() {
                    return Err(StoreError::MalformedMigration(
                        "initial migration must contain exactly one COMMIT boundary",
                    ));
                }
            }
            _ => {}
        }
        offset = offset
            .checked_add(segment.len())
            .ok_or(StoreError::MalformedMigration(
                "initial migration line offset overflowed",
            ))?;
    }

    let begin_body_start = begin_body_start.ok_or(StoreError::MalformedMigration(
        "initial migration must contain one BEGIN IMMEDIATE boundary",
    ))?;
    let commit_start = commit_start.ok_or(StoreError::MalformedMigration(
        "initial migration must end with COMMIT",
    ))?;
    if commit_start < begin_body_start {
        return Err(StoreError::MalformedMigration(
            "initial migration COMMIT precedes BEGIN IMMEDIATE",
        ));
    }
    let commit_line_end = sql[commit_start..]
        .find('\n')
        .map_or(sql.len(), |relative| commit_start + relative + 1);
    if !sql[commit_line_end..].trim().is_empty() {
        return Err(StoreError::MalformedMigration(
            "unexpected content follows initial migration COMMIT",
        ));
    }
    Ok(&sql[begin_body_start..commit_start])
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
        apply_migration, migrate, preflight_existing, reconcile_stale_scan_sessions,
        strip_transaction, validate_capture_time_declared_bounds,
        validate_capture_time_json_evidence, validate_capture_time_normalized_values,
        validate_current_schema, Migration, MIGRATIONS,
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
        apply_migration(&mut connection, &MIGRATIONS[4], 1_004, false)?;
        apply_migration(&mut connection, &MIGRATIONS[5], 1_005, false)?;
        apply_migration(&mut connection, &MIGRATIONS[6], 1_006, false)?;
        apply_migration(&mut connection, &MIGRATIONS[7], 1_007, false)?;
        apply_migration(&mut connection, &MIGRATIONS[8], 1_008, false)?;
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
    fn initial_transaction_parser_accepts_crlf_without_relaxing_boundaries() -> crate::Result<()> {
        const CRLF: &str =
            "-- initial\r\nBEGIN IMMEDIATE;\r\nCREATE TABLE item(id INTEGER);\r\nCOMMIT;\r\n";
        assert_eq!(
            strip_transaction(CRLF)?,
            "CREATE TABLE item(id INTEGER);\r\n"
        );

        const DUPLICATE_BEGIN: &str =
            "BEGIN IMMEDIATE;\r\nBEGIN IMMEDIATE;\r\nSELECT 1;\r\nCOMMIT;\r\n";
        assert!(strip_transaction(DUPLICATE_BEGIN).is_err());
        const DUPLICATE_COMMIT: &str = "BEGIN IMMEDIATE;\r\nSELECT 1;\r\nCOMMIT;\r\nCOMMIT;\r\n";
        assert!(strip_transaction(DUPLICATE_COMMIT).is_err());
        const TRAILING_SQL: &str = "BEGIN IMMEDIATE;\r\nSELECT 1;\r\nCOMMIT;\r\nSELECT 2;\r\n";
        assert!(strip_transaction(TRAILING_SQL).is_err());
        Ok(())
    }

    #[test]
    fn version_seven_accepts_crlf_without_changing_transaction_boundaries() -> crate::Result<()> {
        let mut connection = empty_version_six_connection()?;
        let crlf_sql = MIGRATIONS[6].sql.replace('\n', "\r\n").into_boxed_str();
        let crlf_sql = Box::leak(crlf_sql);
        let migration = Migration {
            version: 7,
            name: "capture_time_evidence_crlf_test",
            sql: crlf_sql,
            strips_embedded_transaction: false,
        };

        apply_migration(&mut connection, &migration, 1_006, false)?;
        assert_eq!(read_test_user_version(&connection)?, 7);
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM pragma_table_list \
                 WHERE name = 'scan_time_sessions' AND strict = 1",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            1
        );
        Ok(())
    }

    #[test]
    fn version_seven_statement_failure_rolls_back_every_v7_object() -> crate::Result<()> {
        let mut connection = empty_version_six_connection()?;
        let failing_sql = format!(
            "{}\nINSERT INTO definitely_missing_v7_fault_target VALUES (1);\n",
            MIGRATIONS[6].sql
        )
        .into_boxed_str();
        let failing_sql = Box::leak(failing_sql);
        let migration = Migration {
            version: 7,
            name: "capture_time_evidence_fault_test",
            sql: failing_sql,
            strips_embedded_transaction: false,
        };

        assert!(apply_migration(&mut connection, &migration, 1_006, false).is_err());
        assert_eq!(read_test_user_version(&connection)?, 6);
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM guiying_schema_migrations",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            6
        );
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM sqlite_schema \
                 WHERE name IN ( \
                     'scan_time_sessions', 'metadata_extraction_reports', \
                     'capture_time_analysis_builds', \
                     'trg_capture_time_recommendations_no_update_v7' \
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            0
        );
        Ok(())
    }

    #[test]
    fn version_seven_schema_manifest_covers_evidence_only_triggers() -> crate::Result<()> {
        let connection = empty_latest_connection()?;
        validate_current_schema(&connection)?;
        connection.execute_batch("DROP TRIGGER trg_capture_time_recommendations_no_update_v7;")?;
        assert!(validate_current_schema(&connection).is_err());
        Ok(())
    }

    #[test]
    fn version_seven_never_promotes_legacy_time_candidates() -> crate::Result<()> {
        let mut connection = empty_version_six_connection()?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute_batch(
            "INSERT INTO time_candidates ( \
                 id, candidate_key, volume_id, media_file_id, scan_run_id, source_kind, \
                 raw_value, raw_encoding, parse_status, offset_kind, precision_kind, \
                 confidence_basis_points, ambiguity, normalized_at_ms, created_at_ms \
             ) VALUES ( \
                 1, zeroblob(32), 91, 92, 93, 'exif', x'01', 'ascii', 'unparseable', \
                 'absent', 'unknown', 0, 'invalid_value', 1, 1 \
             );",
        )?;
        apply_migration(&mut connection, &MIGRATIONS[6], 1_006, false)?;
        assert_eq!(
            connection.query_row("SELECT count(*) FROM time_candidates", [], |row| {
                row.get::<_, i64>(0)
            })?,
            1
        );
        assert_eq!(
            connection.query_row("SELECT count(*) FROM capture_time_candidates", [], |row| {
                row.get::<_, i64>(0)
            },)?,
            0
        );
        Ok(())
    }

    #[test]
    fn version_seven_collision_is_atomic_and_preserves_v6_history() -> crate::Result<()> {
        let mut connection = empty_version_six_connection()?;
        connection
            .execute_batch("CREATE TABLE scan_time_sessions(id INTEGER PRIMARY KEY) STRICT;")?;
        assert!(apply_migration(&mut connection, &MIGRATIONS[6], 1_006, false).is_err());
        assert_eq!(read_test_user_version(&connection)?, 6);
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM guiying_schema_migrations",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            6
        );
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM sqlite_schema \
                 WHERE name = 'metadata_extraction_reports'",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            0
        );
        Ok(())
    }

    #[test]
    fn version_seven_reopen_validators_reject_calendar_utc_and_policy_tampering(
    ) -> crate::Result<()> {
        let connection = empty_latest_connection()?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute_batch(
            "DROP TRIGGER trg_capture_time_candidates_insert_guard_v7; \
             DROP TRIGGER trg_capture_time_builds_insert_guard_v7; \
             INSERT INTO capture_time_candidates ( \
                 id, analysis_build_id, ordinal, wall_year, wall_month, wall_day, \
                 wall_hour, wall_minute, wall_second, wall_nanosecond, semantic_kind, \
                 offset_kind, utc_offset_minutes, utc_seconds_decimal, utc_nanoseconds, \
                 precision_ns, confidence, evidence_gate, evidence_kinds_json, \
                 source_keys_json, lineage_keys_json, observation_ordinals_json, \
                 anomalies_json, blockers_json, created_at_ms \
             ) VALUES ( \
                 1, 1, 0, 2023, 2, 30, 0, 0, 0, 0, 'utc', 'explicit', 0, \
                 '1677715200', 0, 1000000000, 'low', 'blocked', \
                 '[\"exif_date_time_original\"]', '[\"0000000000000000000000000000000000000000000000000000000000000000\"]', \
                 '[\"0000000000000000000000000000000000000000000000000000000000000000\"]', \
                 '[0]', '[]', '[\"confidence_below_high\"]', 1 \
             ); \
             INSERT INTO capture_time_analysis_builds ( \
                 id, time_session_id, volume_id, scan_run_id, exact_group_build_id, \
                 policy_name, policy_version, policy_context_json, policy_context_digest, \
                 expected_source_count, expected_observation_count, expected_candidate_count, \
                 expected_issue_count, expected_member_count, expected_recommendation_count, \
                 expected_manifest_digest, created_at_ms \
             ) VALUES ( \
                 2, 1, 1, 1, 1, 'guiying-time', '1', '{\"a\":1}', zeroblob(32), \
                 1, 0, 0, 0, 2, 1, zeroblob(32), 1 \
             );",
        )?;
        assert!(validate_capture_time_normalized_values(&connection).is_err());
        assert!(validate_capture_time_json_evidence(&connection).is_err());
        Ok(())
    }

    #[test]
    fn version_seven_stale_drafts_are_abandoned_without_deleting_children() -> crate::Result<()> {
        let mut connection = empty_latest_connection()?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute_batch(
            "DROP TRIGGER trg_scan_time_sessions_insert_guard_v7; \
             DROP TRIGGER trg_metadata_reports_insert_guard_v7; \
             DROP TRIGGER trg_capture_time_builds_insert_guard_v7; \
             DROP TRIGGER trg_metadata_issues_insert_guard_v7; \
             DROP TRIGGER trg_capture_time_sources_insert_guard_v7; \
             INSERT INTO scan_time_sessions ( \
                 id, time_session_key, volume_id, scan_run_id, core_session_id, \
                 schema_contract_version, expected_group_count, max_total_read_bytes, \
                 max_probe_count_per_group, max_report_total_bytes_read, \
                 max_report_read_operations, max_report_retained_field_bytes, \
                 max_report_fields, max_report_issues, expected_manifest_digest, created_at_ms \
             ) VALUES ( \
                 1, zeroblob(32), 1, 1, zeroblob(32), 1, 1, 4294967296, 4, \
                 8388608, 32768, 262144, 128, 128, zeroblob(32), 1 \
             ); \
             INSERT INTO metadata_extraction_reports ( \
                 id, time_session_id, volume_id, scan_run_id, core_session_id, \
                 exact_group_build_id, metadata_probe_observation_id, \
                 metadata_probe_fingerprint_id, probe_ordinal, source_size_bytes, \
                 report_parser_name, report_parser_version, extraction_status, \
                 effective_max_total_bytes_read, effective_max_read_operations, \
                 effective_max_retained_field_bytes, effective_max_field_bytes, \
                 effective_max_fields, effective_max_jpeg_segments, \
                 effective_max_ifd_entries, effective_max_ifd_depth, \
                 effective_max_bmff_boxes, effective_max_bmff_depth, usage_bytes_read, \
                 usage_read_operations, usage_retained_field_bytes, usage_fields_emitted, \
                 usage_jpeg_segments_visited, usage_ifd_entries_visited, \
                 usage_bmff_boxes_visited, usage_max_depth_observed, expected_field_count, \
                 expected_issue_count, expected_retained_field_bytes, retained_report_digest, \
                 expected_manifest_digest, created_at_ms \
             ) VALUES ( \
                 1, 1, 1, 1, zeroblob(32), 1, 1, 1, 0, 0, 'guiying-metadata', '1', \
                 'unsupported', 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, \
                 0, 0, 0, 0, 0, zeroblob(32), zeroblob(32), 1 \
             ); \
             INSERT INTO capture_time_analysis_builds ( \
                 id, time_session_id, volume_id, scan_run_id, exact_group_build_id, \
                 policy_name, policy_version, policy_context_json, policy_context_digest, \
                 expected_source_count, expected_observation_count, expected_candidate_count, \
                 expected_issue_count, expected_member_count, expected_recommendation_count, \
                 expected_manifest_digest, created_at_ms \
             ) VALUES ( \
                 1, 1, 1, 1, 1, 'guiying-time', '1', '{}', zeroblob(32), \
                 1, 0, 0, 0, 2, 1, zeroblob(32), 1 \
             ); \
             INSERT INTO metadata_extraction_issues ( \
                 id, report_id, ordinal, parser_name, parser_version, issue_code, \
                 source_offset, context, created_at_ms \
             ) VALUES (1, 1, 0, 'guiying-metadata', '1', 'invalid_source', NULL, 'late', 11); \
             INSERT INTO capture_time_analysis_sources ( \
                 analysis_build_id, ordinal, report_id, source_key, lineage_key, \
                 binding_status, created_at_ms \
             ) VALUES (1, 0, 1, zeroblob(32), zeroblob(32), \
                       'reextracted_pinned_source', 10);",
        )?;
        reconcile_stale_scan_sessions(&mut connection, 2)?;
        let states: (String, i64, String, i64, String, i64) = connection.query_row(
            "SELECT time_session.state, time_session.finalized_at_ms, \
                    report.state, report.finalized_at_ms, build.state, build.finalized_at_ms \
             FROM scan_time_sessions AS time_session \
             JOIN metadata_extraction_reports AS report ON report.time_session_id = time_session.id \
             JOIN capture_time_analysis_builds AS build ON build.time_session_id = time_session.id",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        assert_eq!(
            states,
            (
                "abandoned".into(),
                11,
                "abandoned".into(),
                11,
                "abandoned".into(),
                10,
            )
        );
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM metadata_extraction_reports",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            1
        );
        Ok(())
    }

    #[test]
    fn version_four_active_attempt_becomes_nonrecoverable_history() -> crate::Result<()> {
        let mut connection = seeded_version_four_connection()?;
        apply_migration(&mut connection, &MIGRATIONS[4], 1_004, false)?;

        let (job_state, job_version): (String, i64) = connection.query_row(
            "SELECT state, state_version FROM scan_jobs WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!((job_state.as_str(), job_version), ("failed", 1));
        let (run_state, run_version, error_code): (String, i64, String) = connection.query_row(
            "SELECT state, state_version, last_error_code FROM scan_runs WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!((run_state.as_str(), run_version), ("interrupted", 1));
        assert_eq!(error_code, "PROCESS_UPGRADED_WITH_ACTIVE_RUN");

        let legacy_scope: (String, i64, Option<Vec<u8>>, Option<Vec<u8>>) = connection.query_row(
            "SELECT origin, recoverable, stable_root_path_key, root_scope_key \
                 FROM scan_job_scopes WHERE scan_job_id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(legacy_scope.0, "legacy_session_v4");
        assert_eq!(legacy_scope.1, 0);
        assert!(legacy_scope.2.is_none());
        assert!(legacy_scope.3.is_none());
        assert_eq!(
            connection.query_row("SELECT count(*) FROM scan_run_sessions", [], |row| row
                .get::<_, i64>(0),)?,
            0
        );
        assert_eq!(
            connection.query_row("SELECT count(*) FROM observation_fingerprints", [], |row| {
                row.get::<_, i64>(0)
            },)?,
            0
        );
        assert_eq!(
            connection.query_row("SELECT count(*) FROM exact_group_builds", [], |row| row
                .get::<_, i64>(0),)?,
            0
        );
        {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "INSERT INTO scan_runs ( \
                     id, run_key, volume_id, capability_profile_id, root_relative_path, \
                     root_path_key, scan_mode, state, created_at_ms, updated_at_ms \
                 ) VALUES (2, 'legacy-retry', 1, 1, '', x'01', 'resume', 'queued', 2, 2);",
            )?;
            let error = transaction
                .execute(
                    "INSERT INTO scan_job_runs ( \
                         scan_job_id, scan_run_id, volume_id, attempt_number, created_at_ms \
                     ) VALUES (1, 2, 1, 2, 2)",
                    [],
                )
                .expect_err("legacy v4 scope accepted a new attempt");
            assert!(error.to_string().contains("legacy or unscoped"));
            transaction.rollback()?;
        }
        apply_migration(&mut connection, &MIGRATIONS[5], 1_005, false)?;
        apply_migration(&mut connection, &MIGRATIONS[6], 1_006, false)?;
        apply_migration(&mut connection, &MIGRATIONS[7], 1_007, false)?;
        apply_migration(&mut connection, &MIGRATIONS[8], 1_008, false)?;
        validate_current_schema(&connection)?;
        Ok(())
    }

    #[test]
    fn version_four_unbound_queued_job_is_failed_not_stranded() -> crate::Result<()> {
        let mut connection = seeded_version_four_connection()?;
        connection.execute_batch(
            "INSERT INTO scan_jobs ( \
                 id, job_key, volume_id, root_relative_path, root_path_key, \
                 state, created_at_ms, updated_at_ms \
             ) VALUES (2, 'unbound-job', 1, 'Pictures', x'02', 'queued', 2, 2); \
             INSERT INTO scan_job_roots ( \
                 scan_job_id, volume_id, capability_profile_id, path_semantics_version, \
                 relative_path_raw, path_encoding, semantic_path_key, created_at_ms \
             ) VALUES (2, 1, NULL, 1, CAST('Pictures' AS BLOB), 'utf8', x'02', 2);",
        )?;

        apply_migration(&mut connection, &MIGRATIONS[4], 1_004, false)?;
        let state: (String, i64, Option<i64>) = connection.query_row(
            "SELECT state, state_version, active_scan_run_id FROM scan_jobs WHERE id = 2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!((state.0.as_str(), state.1, state.2), ("failed", 1, None));
        let scope: (String, i64) = connection.query_row(
            "SELECT namespace.origin, scope.recoverable \
             FROM scan_job_scopes AS scope \
             JOIN namespace_profiles AS namespace \
               ON namespace.id = scope.namespace_profile_id \
             WHERE scope.scan_job_id = 2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!((scope.0.as_str(), scope.1), ("legacy_session_v4", 0));
        apply_migration(&mut connection, &MIGRATIONS[5], 1_005, false)?;
        apply_migration(&mut connection, &MIGRATIONS[6], 1_006, false)?;
        apply_migration(&mut connection, &MIGRATIONS[7], 1_007, false)?;
        apply_migration(&mut connection, &MIGRATIONS[8], 1_008, false)?;
        validate_current_schema(&connection)?;
        Ok(())
    }

    #[test]
    fn dirty_version_four_upgrade_rolls_back_every_v5_object() -> crate::Result<()> {
        let mut connection = seeded_version_four_connection()?;
        connection.execute_batch(
            "DROP TRIGGER trg_scan_job_roots_no_delete_v4; \
             DELETE FROM scan_job_roots WHERE scan_job_id = 1;",
        )?;

        assert!(apply_migration(&mut connection, &MIGRATIONS[4], 1_004, false).is_err());
        assert_eq!(read_test_user_version(&connection)?, 4);
        let registered: i64 = connection.query_row(
            "SELECT count(*) FROM guiying_schema_migrations",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(registered, 4);
        let v5_objects: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_schema \
             WHERE name IN ('namespace_profiles', 'scan_run_sessions', \
                            'observation_fingerprints')",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(v5_objects, 0);
        Ok(())
    }

    #[test]
    fn exact_group_finalize_rejects_reclaimable_integer_overflow() -> crate::Result<()> {
        let connection = empty_latest_connection()?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute_batch(
            "DROP TRIGGER trg_scan_runs_initial_state_v5; \
             DROP TRIGGER trg_scan_run_sessions_insert_guard_v5; \
             DROP TRIGGER trg_media_observation_snapshots_insert_guard_v5; \
             DROP TRIGGER trg_exact_group_builds_insert_guard_v5; \
             DROP TRIGGER trg_exact_group_build_members_insert_guard_v5; \
             DROP TRIGGER trg_exact_verification_edges_insert_guard_v5; \
             INSERT INTO volumes ( \
                 id, identity_key, identity_strength, marker_uuid, filesystem_type, \
                 is_network, is_read_only, first_seen_at_ms, last_seen_at_ms, \
                 created_at_ms, updated_at_ms \
             ) VALUES (1, 'volume', 'strong', 'marker', 'apfs', 0, 1, 1, 1, 1, 1); \
             INSERT INTO capability_profiles ( \
                 id, volume_id, profile_hash, profile_hash_version, probe_mode, probe_status, \
                 observed_at_ms, os_build, mount_session_key, probe_protocol_version, \
                 path_encoding_family, path_semantics_version, can_read, is_current, created_at_ms \
             ) VALUES ( \
                 1, 1, zeroblob(32), 2, 'passive', 'complete', 1, 'test', \
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
                 1, 'unix', 1, 1, 1, 1 \
             ); \
             INSERT INTO scan_runs ( \
                 id, run_key, volume_id, capability_profile_id, root_relative_path, \
                 root_path_key, scan_mode, state, started_at_ms, created_at_ms, updated_at_ms, \
                 attempt_strategy \
             ) VALUES ( \
                 1, 'run', 1, 1, '', zeroblob(32), 'full', 'running', 1, 1, 1, \
                 'initial_full_v1' \
             ); \
             INSERT INTO scan_run_sessions ( \
                 scan_run_id, scan_job_id, volume_id, capability_profile_id, \
                 namespace_profile_id, mount_session_key, mount_relative_root_raw, \
                 path_encoding, stable_root_path_key, root_scope_key, \
                 root_object_signature, created_at_ms \
             ) VALUES ( \
                 1, 1, 1, 1, 1, \
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
                 x'', 'utf8', zeroblob(32), \
                 x'0101010101010101010101010101010101010101010101010101010101010101', \
                 zeroblob(32), 1 \
             ); \
             INSERT INTO media_observation_snapshots ( \
                 id, volume_id, scan_run_id, media_namespace_path_id, media_file_id, \
                 namespace_profile_id, capability_profile_id, root_relative_path_raw, \
                 path_encoding, display_path, source_signature, stat_signature_version, \
                 file_object_key, file_mode, entry_type, size_bytes, modified_time_seconds, \
                 modified_time_nanoseconds, changed_time_seconds, changed_time_nanoseconds, \
                 timestamp_storage_unit_ns, timestamp_granularity_ns, observed_at_ms \
             ) VALUES \
                 (1, 1, 1, 1, 1, 1, 1, x'61', 'utf8', 'a', \
                  x'1111111111111111111111111111111111111111111111111111111111111111', \
                  1, x'2121212121212121212121212121212121212121212121212121212121212121', \
                  33188, 'regular', 9223372036854775807, 1, 0, 1, 0, 1, 1, 1), \
                 (2, 1, 1, 2, 2, 1, 1, x'62', 'utf8', 'b', \
                  x'1212121212121212121212121212121212121212121212121212121212121212', \
                  1, x'2222222222222222222222222222222222222222222222222222222222222222', \
                  33188, 'regular', 9223372036854775807, 1, 0, 1, 0, 1, 1, 1), \
                 (3, 1, 1, 3, 3, 1, 1, x'63', 'utf8', 'c', \
                  x'1313131313131313131313131313131313131313131313131313131313131313', \
                  1, x'2323232323232323232323232323232323232323232323232323232323232323', \
                  33188, 'regular', 9223372036854775807, 1, 0, 1, 0, 1, 1, 1); \
             INSERT INTO exact_group_builds ( \
                 id, build_key, volume_id, scan_run_id, representative_observation_id, \
                 representative_fingerprint_id, expected_member_count, expected_edge_count, \
                 expected_manifest_digest, state, created_at_ms \
             ) VALUES (1, zeroblob(32), 1, 1, 1, 1, 3, 2, zeroblob(32), 'draft', 1); \
             INSERT INTO exact_group_build_members ( \
                 exact_group_build_id, volume_id, scan_run_id, ordinal, \
                 media_observation_snapshot_id, observation_fingerprint_id, sort_rank, \
                 manifest_leaf, created_at_ms \
             ) VALUES \
                 (1, 1, 1, 0, 1, 1, 0, \
                  x'3131313131313131313131313131313131313131313131313131313131313131', 1), \
                 (1, 1, 1, 1, 2, 2, 1, \
                  x'3232323232323232323232323232323232323232323232323232323232323232', 1), \
                 (1, 1, 1, 2, 3, 3, 2, \
                  x'3333333333333333333333333333333333333333333333333333333333333333', 1); \
             INSERT INTO exact_verification_edges ( \
                 exact_group_build_id, volume_id, scan_run_id, representative_observation_id, \
                 representative_fingerprint_id, member_observation_id, member_fingerprint_id, \
                 representative_source_signature, member_source_signature, compared_bytes, \
                 verified_at_ms \
             ) VALUES \
                 (1, 1, 1, 1, 1, 2, 2, \
                  x'1111111111111111111111111111111111111111111111111111111111111111', \
                  x'1212121212121212121212121212121212121212121212121212121212121212', \
                  9223372036854775807, 2), \
                 (1, 1, 1, 1, 1, 3, 3, \
                  x'1111111111111111111111111111111111111111111111111111111111111111', \
                  x'1313131313131313131313131313131313131313131313131313131313131313', \
                  9223372036854775807, 2);",
        )?;

        let error = connection
            .execute(
                "UPDATE exact_group_builds \
                    SET state = 'verified', group_key = zeroblob(32), \
                        independent_file_count = 3, \
                        logical_reclaimable_bytes = 9223372036854775807, \
                        finalized_at_ms = 2 \
                  WHERE id = 1",
                [],
            )
            .expect_err("overflowing reclaimable byte calculation was accepted");
        assert!(error.to_string().contains("complete manifest and edge set"));
        Ok(())
    }

    #[test]
    fn version_five_timestamp_unit_migrates_to_unknown_actual_precision() -> crate::Result<()> {
        let mut connection = empty_version_five_connection()?;
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute_batch(
            "DROP TRIGGER trg_media_observation_snapshots_insert_guard_v5; \
             INSERT INTO media_observation_snapshots ( \
                 id, volume_id, scan_run_id, media_namespace_path_id, media_file_id, \
                 namespace_profile_id, capability_profile_id, root_relative_path_raw, \
                 path_encoding, display_path, source_signature, stat_signature_version, \
                 file_mode, entry_type, size_bytes, modified_time_seconds, \
                 modified_time_nanoseconds, changed_time_seconds, changed_time_nanoseconds, \
                 timestamp_granularity_ns, observed_at_ms \
             ) VALUES ( \
                 1, 1, 1, 1, 1, 1, 1, x'61', 'utf8', 'a', zeroblob(32), 1, \
                 33188, 'regular', 1, 1, 0, 1, 0, 1, 1 \
             );",
        )?;

        apply_migration(&mut connection, &MIGRATIONS[5], 1_005, false)?;
        let precision: (i64, Option<i64>) = connection.query_row(
            "SELECT timestamp_storage_unit_ns, timestamp_granularity_ns \
             FROM media_observation_snapshots WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(precision, (1, None));
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
                crate::StoreError::LegacyEvidenceApiDisabled {
                    api: "transition_scan_job_and_run"
                }
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
            crate::StoreError::LegacyEvidenceApiDisabled {
                api: "create_scan_job"
            }
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

    fn seeded_version_four_connection() -> crate::Result<Connection> {
        let mut connection = seeded_version_two_connection()?;
        apply_migration(&mut connection, &MIGRATIONS[2], 1_002, false)?;
        apply_migration(&mut connection, &MIGRATIONS[3], 1_003, false)?;
        Ok(connection)
    }

    fn empty_latest_connection() -> crate::Result<Connection> {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            apply_migration(
                &mut connection,
                migration,
                1_000 + i64::try_from(index).expect("five migrations fit i64"),
                index == 0,
            )?;
        }
        Ok(connection)
    }

    fn empty_version_five_connection() -> crate::Result<Connection> {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        for (index, migration) in MIGRATIONS.iter().take(5).enumerate() {
            apply_migration(
                &mut connection,
                migration,
                1_000 + i64::try_from(index).expect("five migrations fit i64"),
                index == 0,
            )?;
        }
        Ok(connection)
    }

    fn empty_version_six_connection() -> crate::Result<Connection> {
        let mut connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        for (index, migration) in MIGRATIONS.iter().take(6).enumerate() {
            apply_migration(
                &mut connection,
                migration,
                1_000 + i64::try_from(index).expect("six migrations fit i64"),
                index == 0,
            )?;
        }
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

    #[test]
    fn version_seven_reopen_bounds_reject_check_bypassed_zero_limits() -> crate::Result<()> {
        let connection = empty_latest_connection()?;
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
                 expected_manifest_digest, state, abandon_reason_code, created_at_ms, \
                 finalized_at_ms \
             ) VALUES ( \
                 1, 1, 1, 1, zeroblob(32), 1, 1, 1, 0, 0, 'parser', '1', 'failed', \
                 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, \
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, zeroblob(32), zeroblob(32), \
                 'abandoned', 'TEST_TAMPER', 1, 1 \
             )",
            [],
        )?;
        connection.execute_batch(&trigger_sql)?;
        connection.pragma_update(None, "ignore_check_constraints", false)?;

        let error = validate_capture_time_declared_bounds(&connection)
            .expect_err("reopen bounds accepted a zero effective extraction limit");
        assert!(error
            .to_string()
            .contains("typed limits, usage, or state bounds"));
        Ok(())
    }
}
