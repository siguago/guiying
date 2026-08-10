use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::error::{Result, StoreError};
use crate::model::{
    CapabilityProfileInput, MediaFileInput, NewScanIssue, NewScanJob, NewScanReport, NewScanRun,
    ScanCheckpointInput, VolumeInput, MAX_IDENTIFIER_BYTES, MAX_JSON_BYTES, MAX_OPAQUE_BLOB_BYTES,
    MAX_PATH_BYTES, MAX_TEXT_BYTES,
};

/// Repository operations scoped to one short SQLite write transaction.
pub struct RepositoryTx<'transaction> {
    transaction: &'transaction Transaction<'transaction>,
    poisoned: bool,
}

impl<'transaction> RepositoryTx<'transaction> {
    pub(crate) fn new(transaction: &'transaction Transaction<'transaction>) -> Self {
        Self {
            transaction,
            poisoned: false,
        }
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn run_mutator<T>(
        &mut self,
        operation: impl FnOnce(&mut RepositoryTx<'transaction>) -> Result<T>,
    ) -> Result<T> {
        if self.poisoned {
            return Err(StoreError::WriteTransactionPoisoned);
        }
        let result = operation(self);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub fn upsert_volume(&mut self, input: &VolumeInput) -> Result<i64> {
        self.run_mutator(|repository| repository.upsert_volume_impl(input))
    }

    pub fn set_current_capability_profile(
        &mut self,
        input: &CapabilityProfileInput,
    ) -> Result<i64> {
        self.run_mutator(|repository| repository.set_current_capability_profile_impl(input))
    }

    pub fn create_scan_job(&mut self, input: &NewScanJob) -> Result<i64> {
        self.run_mutator(|repository| repository.create_scan_job_impl(input))
    }

    pub fn create_scan_run(&mut self, input: &NewScanRun) -> Result<i64> {
        self.run_mutator(|repository| repository.create_scan_run_impl(input))
    }

    pub fn upsert_media_file(&mut self, input: &MediaFileInput) -> Result<i64> {
        self.run_mutator(|repository| repository.upsert_media_file_impl(input))
    }

    pub fn record_scan_issue(&mut self, input: &NewScanIssue) -> Result<i64> {
        self.run_mutator(|repository| repository.record_scan_issue_impl(input))
    }

    pub fn write_scan_report(&mut self, input: &NewScanReport) -> Result<i64> {
        self.run_mutator(|repository| repository.write_scan_report_impl(input))
    }

    pub fn update_scan_progress(
        &mut self,
        scan_run_id: i64,
        discovered_count: i64,
        fingerprinted_count: i64,
        error_count: i64,
        logical_bytes_seen: i64,
        heartbeat_at_ms: i64,
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.update_scan_progress_impl(
                scan_run_id,
                discovered_count,
                fingerprinted_count,
                error_count,
                logical_bytes_seen,
                heartbeat_at_ms,
            )
        })
    }

    pub fn save_scan_checkpoint(&mut self, input: &ScanCheckpointInput) -> Result<i64> {
        self.run_mutator(|repository| repository.save_scan_checkpoint_impl(input))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transition_scan_job_and_run(
        &mut self,
        scan_job_id: i64,
        scan_run_id: i64,
        expected_capability_profile_id: i64,
        expected_mount_session_key: &str,
        expected_job_state: &str,
        expected_job_version: i64,
        expected_run_state: &str,
        expected_run_version: i64,
        target_job_state: &str,
        target_run_state: &str,
        now_ms: i64,
        last_error: Option<(&str, &str)>,
    ) -> Result<(i64, i64)> {
        self.run_mutator(|repository| {
            repository.transition_scan_job_and_run_impl(
                scan_job_id,
                scan_run_id,
                expected_capability_profile_id,
                expected_mount_session_key,
                expected_job_state,
                expected_job_version,
                expected_run_state,
                expected_run_version,
                target_job_state,
                target_run_state,
                now_ms,
                last_error,
            )
        })
    }

    fn upsert_volume_impl(&mut self, input: &VolumeInput) -> Result<i64> {
        validate_volume(input)?;

        let conflicting_key = self
            .transaction
            .query_row(
                "SELECT identity_key FROM volumes \
                 WHERE identity_key <> ?1 \
                   AND ((?2 IS NOT NULL AND marker_uuid = ?2) \
                     OR (?3 IS NOT NULL AND native_uuid = ?3)) \
                 LIMIT 1",
                params![input.identity_key, input.marker_uuid, input.native_uuid],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(conflicting_key) = conflicting_key {
            return Err(StoreError::VolumeIdentityConflict {
                identity_key: input.identity_key.clone(),
                reason: format!(
                    "strong identifier is already bound to identity key {conflicting_key:?}"
                ),
            });
        }

        let existing = self
            .transaction
            .query_row(
                "SELECT id, identity_strength, marker_uuid, native_uuid \
                 FROM volumes WHERE identity_key = ?1",
                [&input.identity_key],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;

        if let Some((id, existing_strength, marker_uuid, native_uuid)) = existing {
            reject_identifier_change(
                &input.identity_key,
                "marker_uuid",
                marker_uuid.as_deref(),
                input.marker_uuid.as_deref(),
            )?;
            reject_identifier_change(
                &input.identity_key,
                "native_uuid",
                native_uuid.as_deref(),
                input.native_uuid.as_deref(),
            )?;
            let identity_strength = controlled_identity_upgrade(
                &input.identity_key,
                &existing_strength,
                &input.identity_strength,
                marker_uuid.as_deref(),
                input.marker_uuid.as_deref(),
                native_uuid.as_deref(),
                input.native_uuid.as_deref(),
            )?;
            let requires_identity_write = identity_strength != existing_strength
                || (marker_uuid.is_none() && input.marker_uuid.is_some())
                || (native_uuid.is_none() && input.native_uuid.is_some());
            let changed = self.transaction.execute(
                "UPDATE volumes SET \
                     identity_strength = ?2, \
                     marker_uuid = COALESCE(?3, marker_uuid), \
                     native_uuid = COALESCE(?4, native_uuid), \
                     filesystem_type = ?5, display_name = ?6, mount_source = ?7, \
                     last_mount_path = ?8, transport = ?9, is_network = ?10, is_read_only = ?11, \
                     last_seen_at_ms = ?12, updated_at_ms = ?12 \
                 WHERE id = ?1 AND updated_at_ms <= ?12",
                params![
                    id,
                    identity_strength,
                    input.marker_uuid,
                    input.native_uuid,
                    input.filesystem_type,
                    input.display_name,
                    input.mount_source,
                    input.last_mount_path,
                    input.transport,
                    bool_to_integer(input.is_network),
                    bool_to_integer(input.is_read_only),
                    input.now_ms,
                ],
            )?;
            if requires_identity_write && changed != 1 {
                return Err(StoreError::ConcurrencyConflict {
                    entity: "volume_identity_upgrade",
                    id,
                });
            }
            return Ok(id);
        }

        self.transaction.execute(
            "INSERT INTO volumes ( \
                 identity_key, identity_strength, marker_uuid, native_uuid, filesystem_type, \
                 display_name, mount_source, last_mount_path, transport, is_network, is_read_only, \
                 first_seen_at_ms, last_seen_at_ms, created_at_ms, updated_at_ms \
             ) VALUES ( \
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, ?12, ?12 \
             ) \
             ON CONFLICT(identity_key) DO NOTHING",
            params![
                input.identity_key,
                input.identity_strength,
                input.marker_uuid,
                input.native_uuid,
                input.filesystem_type,
                input.display_name,
                input.mount_source,
                input.last_mount_path,
                input.transport,
                bool_to_integer(input.is_network),
                bool_to_integer(input.is_read_only),
                input.now_ms,
            ],
        )?;
        self.transaction
            .query_row(
                "SELECT id FROM volumes WHERE identity_key = ?1",
                [&input.identity_key],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }

    fn set_current_capability_profile_impl(
        &mut self,
        input: &CapabilityProfileInput,
    ) -> Result<i64> {
        validate_capability_profile(input)?;
        let raw_capabilities_json =
            serialize_optional_json("raw_capabilities", &input.raw_capabilities, MAX_JSON_BYTES)?;
        let profile_hash = compute_capability_profile_hash(input)?;
        let existing = self
            .transaction
            .query_row(
                "SELECT id, profile_hash_version, probe_mode, probe_status, os_build, \
                        mount_session_key, probe_protocol_version, driver_name, driver_version, \
                        mount_flags, case_behavior, unicode_behavior, path_encoding_family, \
                        path_semantics_version, \
                        can_read, can_write, can_rename_same_volume, can_rename_exclusive, \
                        can_no_replace, can_sync_directory, can_append_durable, single_writer, \
                        can_set_birth_time, can_set_modified_time, can_use_xattrs, \
                        can_use_hard_links, can_use_clones, has_persistent_file_ids, \
                        timestamp_granularity_ns, maximum_name_bytes, maximum_file_bytes, \
                        raw_capabilities_json \
                 FROM capability_profiles WHERE volume_id = ?1 AND profile_hash = ?2",
                params![input.volume_id, profile_hash.as_slice()],
                stored_capability_from_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing.profile_hash_version != CAPABILITY_HASH_VERSION
                || !existing.matches_input(input, raw_capabilities_json.as_deref())
            {
                return Err(StoreError::IdempotencyConflict {
                    entity: "capability_profile_hash",
                    key: hex_hash(&profile_hash),
                });
            }
            self.transaction.execute(
                "UPDATE capability_profiles SET is_current = (id = ?2) WHERE volume_id = ?1",
                params![input.volume_id, existing.id],
            )?;
            return Ok(existing.id);
        }

        self.transaction.execute(
            "UPDATE capability_profiles SET is_current = 0 \
             WHERE volume_id = ?1 AND is_current = 1",
            [input.volume_id],
        )?;
        self.transaction.execute(
            "INSERT INTO capability_profiles ( \
                 volume_id, profile_hash, profile_hash_version, probe_mode, probe_status, \
                 observed_at_ms, os_build, mount_session_key, probe_protocol_version, \
                 driver_name, driver_version, mount_flags, case_behavior, unicode_behavior, \
                 path_encoding_family, path_semantics_version, can_read, can_write, can_rename_same_volume, \
                 can_rename_exclusive, can_no_replace, can_sync_directory, can_append_durable, \
                 single_writer, can_set_birth_time, can_set_modified_time, can_use_xattrs, \
                 can_use_hard_links, can_use_clones, has_persistent_file_ids, \
                 timestamp_granularity_ns, maximum_name_bytes, maximum_file_bytes, \
                 raw_capabilities_json, is_current, created_at_ms \
             ) VALUES ( \
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                 ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, \
                 ?29, ?30, ?31, ?32, ?33, ?34, 1, ?6 \
             ) \
             ON CONFLICT(volume_id, profile_hash) DO UPDATE SET is_current = 1",
            params![
                input.volume_id,
                profile_hash.as_slice(),
                CAPABILITY_HASH_VERSION,
                input.probe_mode,
                input.probe_status,
                input.observed_at_ms,
                input.os_build,
                input.mount_session_key,
                input.probe_protocol_version,
                input.driver_name,
                input.driver_version,
                input.mount_flags,
                input.case_behavior,
                input.unicode_behavior,
                input.path_encoding_family,
                input.path_semantics_version,
                optional_bool_to_integer(input.can_read),
                optional_bool_to_integer(input.can_write),
                optional_bool_to_integer(input.can_rename_same_volume),
                optional_bool_to_integer(input.can_rename_exclusive),
                optional_bool_to_integer(input.can_no_replace),
                optional_bool_to_integer(input.can_sync_directory),
                optional_bool_to_integer(input.can_append_durable),
                optional_bool_to_integer(input.single_writer),
                optional_bool_to_integer(input.can_set_birth_time),
                optional_bool_to_integer(input.can_set_modified_time),
                optional_bool_to_integer(input.can_use_xattrs),
                optional_bool_to_integer(input.can_use_hard_links),
                optional_bool_to_integer(input.can_use_clones),
                optional_bool_to_integer(input.has_persistent_file_ids),
                input.timestamp_granularity_ns,
                input.maximum_name_bytes,
                input.maximum_file_bytes,
                raw_capabilities_json,
            ],
        )?;
        self.transaction
            .query_row(
                "SELECT id FROM capability_profiles WHERE volume_id = ?1 AND profile_hash = ?2",
                params![input.volume_id, profile_hash.as_slice()],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }

    fn create_scan_job_impl(&mut self, input: &NewScanJob) -> Result<i64> {
        validate_scan_job(input)?;
        let root_encoding = validate_raw_relative_path(
            &input.root_relative_path,
            &input.root_relative_path_raw,
            &input.root_path_encoding,
            true,
        )?;
        self.validate_path_semantics_profile(
            input.volume_id,
            input.capability_profile_id,
            input.path_semantics_version,
            root_encoding,
        )?;
        let config_json = serialize_optional_json("config", &input.config, MAX_JSON_BYTES)?;
        let inserted = self
            .transaction
            .query_row(
                "INSERT INTO scan_jobs ( \
                     job_key, volume_id, root_relative_path, root_path_key, config_json, \
                     created_at_ms, updated_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6) \
                 ON CONFLICT(job_key) DO NOTHING \
                 RETURNING id",
                params![
                    input.job_key,
                    input.volume_id,
                    input.root_relative_path,
                    input.root_path_key.as_bytes(),
                    config_json,
                    input.created_at_ms,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if let Some(id) = inserted {
            self.insert_scan_job_root(input, id, root_encoding)?;
            return Ok(id);
        }

        let existing = self.transaction.query_row(
            "SELECT id, volume_id, root_relative_path, root_path_key, config_json \
             FROM scan_jobs WHERE job_key = ?1",
            [&input.job_key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )?;
        let expected_config = serialize_optional_json("config", &input.config, MAX_JSON_BYTES)?;
        if existing.1 != input.volume_id
            || existing.2 != input.root_relative_path
            || existing.3.as_slice() != input.root_path_key.as_bytes()
            || existing.4 != expected_config
        {
            return Err(StoreError::IdempotencyConflict {
                entity: "scan_job",
                key: input.job_key.clone(),
            });
        }
        self.validate_existing_scan_job_root(input, existing.0, root_encoding)?;
        Ok(existing.0)
    }

    fn create_scan_run_impl(&mut self, input: &NewScanRun) -> Result<i64> {
        validate_scan_run(input)?;
        let root_encoding = validate_raw_relative_path(
            &input.root_relative_path,
            &input.root_relative_path_raw,
            &input.root_path_encoding,
            true,
        )?;
        self.validate_path_semantics_profile(
            input.volume_id,
            input.capability_profile_id,
            input.path_semantics_version,
            root_encoding,
        )?;
        let existing = self
            .transaction
            .query_row(
                "SELECT 1 FROM scan_runs WHERE run_key = ?1",
                [&input.run_key],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if existing {
            let scan_run_id = self.validate_existing_scan_run(input)?;
            self.validate_existing_scan_run_root(input, scan_run_id, root_encoding)?;
            self.bind_run_to_job(input, scan_run_id, false)?;
            return Ok(scan_run_id);
        }

        self.validate_scan_run_binding(input)?;
        let config_json = serialize_optional_json("config", &input.config, MAX_JSON_BYTES)?;
        let inserted = self
            .transaction
            .query_row(
                "INSERT INTO scan_runs ( \
                     run_key, volume_id, capability_profile_id, parent_scan_run_id, \
                     root_relative_path, root_path_key, scan_mode, config_json, \
                     created_at_ms, updated_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9) \
                 ON CONFLICT(run_key) DO NOTHING \
                 RETURNING id",
                params![
                    input.run_key,
                    input.volume_id,
                    input.capability_profile_id,
                    input.parent_scan_run_id,
                    input.root_relative_path,
                    input.root_path_key.as_bytes(),
                    input.scan_mode,
                    config_json,
                    input.created_at_ms,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        let scan_run_id = if let Some(id) = inserted {
            id
        } else {
            return Err(StoreError::IdempotencyConflict {
                entity: "scan_run",
                key: input.run_key.clone(),
            });
        };
        self.insert_scan_run_root(input, scan_run_id, root_encoding)?;
        self.bind_run_to_job(input, scan_run_id, true)?;
        Ok(scan_run_id)
    }

    fn upsert_media_file_impl(&mut self, input: &MediaFileInput) -> Result<i64> {
        let path_encoding = validate_media_file(input)?;
        self.validate_scan_run_profile(
            input.volume_id,
            input.scan_run_id,
            input.capability_profile_id,
            input.path_semantics_version,
            path_encoding,
        )?;
        let metadata_json = serialize_optional_json("metadata", &input.metadata, MAX_JSON_BYTES)?;
        let existing_media_file_id = self
            .transaction
            .query_row(
                "SELECT media_file_id FROM media_path_keys \
                 WHERE volume_id = ?1 AND capability_profile_id = ?2 \
                   AND path_semantics_version = ?3 AND semantic_path_key = ?4",
                params![
                    input.volume_id,
                    input.capability_profile_id,
                    input.path_semantics_version,
                    input.path_key.as_bytes(),
                ],
                |row| row.get(0),
            )
            .optional()?;

        let (media_file_id, is_current_observation) = if let Some(media_file_id) =
            existing_media_file_id
        {
            let changed = self.update_media_file(media_file_id, input, metadata_json.as_deref())?;
            (media_file_id, changed)
        } else {
            let storage_path_key = scoped_storage_path_key(input)?;
            self.insert_media_file(input, &storage_path_key, metadata_json.as_deref())?;
            let media_file_id = self.transaction.last_insert_rowid();
            self.transaction.execute(
                "INSERT INTO media_path_keys ( \
                     volume_id, media_file_id, capability_profile_id, path_semantics_version, \
                     semantic_path_key, created_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    input.volume_id,
                    media_file_id,
                    input.capability_profile_id,
                    input.path_semantics_version,
                    input.path_key.as_bytes(),
                    input.observed_at_ms,
                ],
            )?;
            (media_file_id, true)
        };

        if is_current_observation {
            self.transaction.execute(
                "INSERT INTO media_file_paths ( \
                 volume_id, media_file_id, relative_path_raw, path_encoding, created_at_ms, \
                 updated_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5) \
             ON CONFLICT(volume_id, media_file_id) DO UPDATE SET \
                 relative_path_raw = excluded.relative_path_raw, \
                 path_encoding = excluded.path_encoding, \
                 updated_at_ms = excluded.updated_at_ms \
             WHERE EXISTS ( \
                 SELECT 1 FROM media_files AS media \
                 WHERE media.id = excluded.media_file_id \
                   AND media.volume_id = excluded.volume_id \
                   AND media.last_seen_scan_run_id = ?6 \
             )",
                params![
                    input.volume_id,
                    media_file_id,
                    input.relative_path_raw,
                    path_encoding,
                    input.observed_at_ms,
                    input.scan_run_id,
                ],
            )?;
        }
        self.insert_media_observation(input, media_file_id, path_encoding)?;
        Ok(media_file_id)
    }

    fn record_scan_issue_impl(&mut self, input: &NewScanIssue) -> Result<i64> {
        validate_scan_issue(input)?;
        let details_json = serialize_optional_json("details", &input.details, MAX_JSON_BYTES)?;
        let inserted = self
            .transaction
            .query_row(
                "INSERT INTO scan_issues ( \
                     issue_key, volume_id, scan_run_id, media_file_id, severity, stage, code, \
                     message, details_json, occurred_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
                 ON CONFLICT(issue_key) DO NOTHING \
                 RETURNING id",
                params![
                    input.issue_key,
                    input.volume_id,
                    input.scan_run_id,
                    input.media_file_id,
                    input.severity,
                    input.stage,
                    input.code,
                    input.message,
                    details_json,
                    input.occurred_at_ms,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if let Some(id) = inserted {
            return Ok(id);
        }
        let existing = self.transaction.query_row(
            "SELECT id, volume_id, scan_run_id, media_file_id, severity, stage, code, message, \
                    details_json, occurred_at_ms \
             FROM scan_issues WHERE issue_key = ?1",
            [&input.issue_key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )?;
        let matches = existing.1 == input.volume_id
            && existing.2 == input.scan_run_id
            && existing.3 == input.media_file_id
            && existing.4 == input.severity
            && existing.5 == input.stage
            && existing.6 == input.code
            && existing.7 == input.message
            && existing.8 == serialize_optional_json("details", &input.details, MAX_JSON_BYTES)?
            && existing.9 == input.occurred_at_ms;
        if !matches {
            return Err(StoreError::IdempotencyConflict {
                entity: "scan_issue",
                key: input.issue_key.clone(),
            });
        }
        Ok(existing.0)
    }

    fn write_scan_report_impl(&mut self, input: &NewScanReport) -> Result<i64> {
        validate_scan_report(input)?;
        let report_json = serialize_canonical_json(&input.report)?;
        if report_json.len() > crate::model::MAX_SCAN_REPORT_JSON_BYTES {
            return Err(StoreError::invalid_input(
                "report",
                format!(
                    "serialized report exceeds {} bytes",
                    crate::model::MAX_SCAN_REPORT_JSON_BYTES
                ),
            ));
        }
        let inserted = self
            .transaction
            .query_row(
                "INSERT INTO scan_reports ( \
                     report_key, volume_id, scan_run_id, report_version, report_json, generated_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(report_key) DO NOTHING \
                 RETURNING id",
                params![
                    input.report_key,
                    input.volume_id,
                    input.scan_run_id,
                    input.report_version,
                    report_json,
                    input.generated_at_ms,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if let Some(id) = inserted {
            return Ok(id);
        }
        let existing = self.transaction.query_row(
            "SELECT id, volume_id, scan_run_id, report_version, report_json, generated_at_ms \
             FROM scan_reports WHERE report_key = ?1",
            [&input.report_key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )?;
        if existing.1 != input.volume_id
            || existing.2 != input.scan_run_id
            || existing.3 != input.report_version
            || existing.4 != report_json
            || existing.5 != input.generated_at_ms
        {
            return Err(StoreError::IdempotencyConflict {
                entity: "scan_report",
                key: input.report_key.clone(),
            });
        }
        Ok(existing.0)
    }

    fn update_scan_progress_impl(
        &mut self,
        scan_run_id: i64,
        discovered_count: i64,
        fingerprinted_count: i64,
        error_count: i64,
        logical_bytes_seen: i64,
        heartbeat_at_ms: i64,
    ) -> Result<()> {
        for (field, value) in [
            ("discovered_count", discovered_count),
            ("fingerprinted_count", fingerprinted_count),
            ("error_count", error_count),
            ("logical_bytes_seen", logical_bytes_seen),
            ("heartbeat_at_ms", heartbeat_at_ms),
        ] {
            require_nonnegative(field, value)?;
        }
        if fingerprinted_count > discovered_count {
            return Err(StoreError::invalid_input(
                "fingerprinted_count",
                "fingerprinted count cannot exceed discovered count",
            ));
        }
        let changed = self.transaction.execute(
            "UPDATE scan_runs SET \
                 discovered_count = ?2, fingerprinted_count = ?3, error_count = ?4, \
                 logical_bytes_seen = ?5, heartbeat_at_ms = ?6, updated_at_ms = ?6 \
             WHERE id = ?1 \
               AND state = 'running' \
               AND discovered_count <= ?2 \
               AND fingerprinted_count <= ?3 \
               AND error_count <= ?4 \
               AND logical_bytes_seen <= ?5 \
               AND updated_at_ms <= ?6",
            params![
                scan_run_id,
                discovered_count,
                fingerprinted_count,
                error_count,
                logical_bytes_seen,
                heartbeat_at_ms,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_run_progress",
                id: scan_run_id,
            });
        }
        Ok(())
    }

    fn save_scan_checkpoint_impl(&mut self, input: &ScanCheckpointInput) -> Result<i64> {
        require_positive("scan_run_id", input.scan_run_id)?;
        require_positive("volume_id", input.volume_id)?;
        require_positive("cursor_version", input.cursor_version)?;
        for (field, value) in [
            ("discovered_count", input.discovered_count),
            ("fingerprinted_count", input.fingerprinted_count),
            ("error_count", input.error_count),
            ("logical_bytes_seen", input.logical_bytes_seen),
            ("saved_at_ms", input.saved_at_ms),
        ] {
            require_nonnegative(field, value)?;
        }
        if input.fingerprinted_count > input.discovered_count {
            return Err(StoreError::invalid_input(
                "fingerprinted_count",
                "fingerprinted count cannot exceed discovered count",
            ));
        }
        let cursor_json = serialize_canonical_json(&input.cursor)?;
        if cursor_json.len() > 1024 * 1024 {
            return Err(StoreError::invalid_input(
                "cursor",
                "serialized checkpoint cursor exceeds 1 MiB",
            ));
        }
        let existing = self
            .transaction
            .query_row(
                "SELECT checkpoint_version, discovered_count, fingerprinted_count, error_count, \
                        logical_bytes_seen, saved_at_ms \
                 FROM scan_checkpoints WHERE scan_run_id = ?1 AND volume_id = ?2",
                params![input.scan_run_id, input.volume_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;
        let next_version = match (existing, input.expected_previous_version) {
            (None, None) => 1,
            (Some(existing), Some(expected))
                if existing.0 == expected
                    && existing.1 <= input.discovered_count
                    && existing.2 <= input.fingerprinted_count
                    && existing.3 <= input.error_count
                    && existing.4 <= input.logical_bytes_seen
                    && existing.5 <= input.saved_at_ms =>
            {
                expected.checked_add(1).ok_or_else(|| {
                    StoreError::invalid_input("checkpoint_version", "checkpoint version overflow")
                })?
            }
            _ => {
                return Err(StoreError::ConcurrencyConflict {
                    entity: "scan_checkpoint",
                    id: input.scan_run_id,
                });
            }
        };

        let changed = self.transaction.execute(
            "INSERT INTO scan_checkpoints ( \
                 scan_run_id, volume_id, checkpoint_version, cursor_version, cursor_json, discovered_count, \
                 fingerprinted_count, error_count, logical_bytes_seen, saved_at_ms \
             ) \
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10 \
             WHERE EXISTS ( \
                 SELECT 1 FROM scan_runs \
                 WHERE id = ?1 AND volume_id = ?2 AND state = 'running' \
                   AND discovered_count = ?6 AND fingerprinted_count = ?7 \
                   AND error_count = ?8 AND logical_bytes_seen = ?9 \
             ) \
             ON CONFLICT(scan_run_id) DO UPDATE SET \
                 checkpoint_version = excluded.checkpoint_version, \
                 cursor_version = excluded.cursor_version, \
                 cursor_json = excluded.cursor_json, \
                 discovered_count = excluded.discovered_count, \
                 fingerprinted_count = excluded.fingerprinted_count, \
                 error_count = excluded.error_count, \
                 logical_bytes_seen = excluded.logical_bytes_seen, \
                 saved_at_ms = excluded.saved_at_ms \
             WHERE scan_checkpoints.volume_id = excluded.volume_id \
               AND scan_checkpoints.checkpoint_version + 1 = excluded.checkpoint_version",
            params![
                input.scan_run_id,
                input.volume_id,
                next_version,
                input.cursor_version,
                cursor_json,
                input.discovered_count,
                input.fingerprinted_count,
                input.error_count,
                input.logical_bytes_seen,
                input.saved_at_ms,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_checkpoint",
                id: input.scan_run_id,
            });
        }
        Ok(next_version)
    }

    /// Atomically advances a bound job and run using optimistic versions for
    /// both records. Starting/resuming writes the job first; pausing and every
    /// terminal edge write the run first so the immediate schema guards always
    /// observe an allowed adjacent state.
    #[allow(clippy::too_many_arguments)]
    fn transition_scan_job_and_run_impl(
        &mut self,
        scan_job_id: i64,
        scan_run_id: i64,
        expected_capability_profile_id: i64,
        expected_mount_session_key: &str,
        expected_job_state: &str,
        expected_job_version: i64,
        expected_run_state: &str,
        expected_run_version: i64,
        target_job_state: &str,
        target_run_state: &str,
        now_ms: i64,
        last_error: Option<(&str, &str)>,
    ) -> Result<(i64, i64)> {
        require_positive(
            "expected_capability_profile_id",
            expected_capability_profile_id,
        )?;
        require_bounded_nonempty(
            "expected_mount_session_key",
            expected_mount_session_key,
            MAX_IDENTIFIER_BYTES,
        )?;
        let order = validate_job_run_transition(
            expected_job_state,
            expected_run_state,
            target_job_state,
            target_run_state,
        )?;
        let is_bound = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM scan_jobs AS job \
                 JOIN scan_job_runs AS binding \
                   ON binding.scan_job_id = job.id \
                  AND binding.scan_run_id = job.active_scan_run_id \
                  AND binding.volume_id = job.volume_id \
                 WHERE job.id = ?1 AND job.active_scan_run_id = ?2 \
             )",
            params![scan_job_id, scan_run_id],
            |row| row.get::<_, bool>(0),
        )?;
        if !is_bound {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_job_run_binding",
                id: scan_job_id,
            });
        }

        if target_job_state == "running" && target_run_state == "running" {
            self.validate_running_transition_profile(
                scan_job_id,
                scan_run_id,
                expected_capability_profile_id,
                expected_mount_session_key,
            )?;
        }

        self.transaction
            .execute_batch("SAVEPOINT guiying_scan_pair_transition_v4")?;
        let result = (|| match order {
            TransitionOrder::JobThenRun => {
                let job_version = self.transition_scan_job(
                    scan_job_id,
                    expected_job_state,
                    expected_job_version,
                    target_job_state,
                    now_ms,
                )?;
                let run_version = self.transition_scan_run(
                    scan_run_id,
                    expected_run_state,
                    expected_run_version,
                    target_run_state,
                    now_ms,
                    last_error,
                )?;
                Ok((job_version, run_version))
            }
            TransitionOrder::RunThenJob => {
                let run_version = self.transition_scan_run(
                    scan_run_id,
                    expected_run_state,
                    expected_run_version,
                    target_run_state,
                    now_ms,
                    last_error,
                )?;
                let job_version = self.transition_scan_job(
                    scan_job_id,
                    expected_job_state,
                    expected_job_version,
                    target_job_state,
                    now_ms,
                )?;
                Ok((job_version, run_version))
            }
        })();
        match result {
            Ok(versions) => {
                self.transaction
                    .execute_batch("RELEASE guiying_scan_pair_transition_v4")?;
                Ok(versions)
            }
            Err(error) => {
                self.transaction.execute_batch(
                    "ROLLBACK TO guiying_scan_pair_transition_v4; \
                     RELEASE guiying_scan_pair_transition_v4;",
                )?;
                Err(error)
            }
        }
    }

    fn transition_scan_job(
        &mut self,
        scan_job_id: i64,
        expected_state: &str,
        expected_version: i64,
        target_state: &str,
        now_ms: i64,
    ) -> Result<i64> {
        require_nonnegative("expected_version", expected_version)?;
        require_nonnegative("now_ms", now_ms)?;
        validate_job_transition(expected_state, target_state)?;
        let next_version = expected_version.checked_add(1).ok_or_else(|| {
            StoreError::invalid_input("expected_version", "state version overflow")
        })?;
        let observed = self
            .transaction
            .query_row(
                "UPDATE scan_jobs SET state = ?4, state_version = ?3, updated_at_ms = ?5 \
                 WHERE id = ?1 AND state = ?2 AND state_version = ?3 - 1 AND updated_at_ms <= ?5 \
                 RETURNING state_version",
                params![
                    scan_job_id,
                    expected_state,
                    next_version,
                    target_state,
                    now_ms,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        observed.ok_or(StoreError::ConcurrencyConflict {
            entity: "scan_job",
            id: scan_job_id,
        })
    }

    fn transition_scan_run(
        &mut self,
        scan_run_id: i64,
        expected_state: &str,
        expected_version: i64,
        target_state: &str,
        now_ms: i64,
        last_error: Option<(&str, &str)>,
    ) -> Result<i64> {
        require_positive("scan_run_id", scan_run_id)?;
        require_nonnegative("expected_version", expected_version)?;
        require_nonnegative("now_ms", now_ms)?;
        validate_run_transition(expected_state, target_state)?;
        validate_transition_error(target_state, last_error)?;
        let (error_code, error_message) = last_error
            .map(|(code, message)| (Some(code), Some(message)))
            .unwrap_or((None, None));
        let next_version = expected_version.checked_add(1).ok_or_else(|| {
            StoreError::invalid_input("expected_version", "state version overflow")
        })?;
        let observed = self
            .transaction
            .query_row(
                "UPDATE scan_runs SET \
                 state = ?3, \
                 state_version = ?4, \
                 started_at_ms = CASE \
                     WHEN ?3 = 'running' \
                       OR (?3 IN ('completed', 'failed', 'cancelled', 'interrupted') \
                           AND started_at_ms IS NULL) \
                     THEN COALESCE(started_at_ms, ?5) \
                     ELSE started_at_ms \
                 END, \
                 heartbeat_at_ms = CASE \
                     WHEN ?3 IN ('running', 'paused') THEN ?5 \
                     ELSE heartbeat_at_ms \
                 END, \
                 finished_at_ms = CASE \
                     WHEN ?3 IN ('completed', 'failed', 'cancelled', 'interrupted') THEN ?5 \
                     ELSE NULL \
                 END, \
                 last_error_code = ?6, \
                 last_error_message = ?7, \
                 updated_at_ms = ?5 \
             WHERE id = ?1 AND state = ?2 AND state_version = ?4 - 1 \
               AND updated_at_ms <= ?5 \
             RETURNING state_version",
                params![
                    scan_run_id,
                    expected_state,
                    target_state,
                    next_version,
                    now_ms,
                    error_code,
                    error_message,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        observed.ok_or(StoreError::ConcurrencyConflict {
            entity: "scan_run",
            id: scan_run_id,
        })
    }

    fn validate_path_semantics_profile(
        &self,
        volume_id: i64,
        capability_profile_id: i64,
        path_semantics_version: i64,
        path_encoding: &str,
    ) -> Result<()> {
        let matches = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM capability_profiles \
                 WHERE id = ?1 AND volume_id = ?2 AND path_semantics_version = ?3 \
                   AND profile_hash_version = 2 \
                   AND is_current = 1 \
                   AND probe_status = 'complete' \
                   AND can_read = 1 \
                   AND mount_session_key IS NOT NULL \
                   AND probe_protocol_version IS NOT NULL \
                   AND case_behavior IS NOT NULL \
                   AND unicode_behavior IS NOT NULL \
                   AND path_encoding_family IS NOT NULL \
                   AND ((path_encoding_family = 'unix' AND ?4 IN ('utf8', 'unix_bytes')) \
                     OR (path_encoding_family = 'windows' AND ?4 = 'windows_utf16_le')) \
             )",
            params![
                capability_profile_id,
                volume_id,
                path_semantics_version,
                path_encoding
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !matches {
            return Err(StoreError::IdempotencyConflict {
                entity: "path_semantics_profile",
                key: format!("{volume_id}:{capability_profile_id}:{path_semantics_version}"),
            });
        }
        Ok(())
    }

    fn validate_scan_run_profile(
        &self,
        volume_id: i64,
        scan_run_id: i64,
        capability_profile_id: i64,
        path_semantics_version: i64,
        path_encoding: &str,
    ) -> Result<()> {
        let matches = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM scan_runs AS run \
                 JOIN capability_profiles AS profile \
                   ON profile.id = run.capability_profile_id \
                  AND profile.volume_id = run.volume_id \
                 WHERE run.id = ?1 AND run.volume_id = ?2 \
                   AND run.state = 'running' \
                   AND run.capability_profile_id = ?3 \
                   AND profile.path_semantics_version = ?4 \
                   AND profile.profile_hash_version = 2 \
                   AND profile.is_current = 1 \
                   AND profile.probe_status = 'complete' \
                   AND profile.can_read = 1 \
                   AND profile.mount_session_key IS NOT NULL \
                   AND profile.probe_protocol_version IS NOT NULL \
                   AND profile.case_behavior IS NOT NULL \
                   AND profile.unicode_behavior IS NOT NULL \
                   AND profile.path_encoding_family IS NOT NULL \
                   AND ((profile.path_encoding_family = 'unix' AND ?5 IN ('utf8', 'unix_bytes')) \
                     OR (profile.path_encoding_family = 'windows' AND ?5 = 'windows_utf16_le')) \
             )",
            params![
                scan_run_id,
                volume_id,
                capability_profile_id,
                path_semantics_version,
                path_encoding
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !matches {
            return Err(StoreError::IdempotencyConflict {
                entity: "scan_run_path_semantics_profile",
                key: scan_run_id.to_string(),
            });
        }
        Ok(())
    }

    fn validate_running_transition_profile(
        &self,
        scan_job_id: i64,
        scan_run_id: i64,
        expected_capability_profile_id: i64,
        expected_mount_session_key: &str,
    ) -> Result<()> {
        let matches = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 \
                 FROM scan_jobs AS job \
                 JOIN scan_job_runs AS binding \
                   ON binding.scan_job_id = job.id \
                  AND binding.scan_run_id = job.active_scan_run_id \
                  AND binding.volume_id = job.volume_id \
                 JOIN scan_runs AS run \
                   ON run.id = binding.scan_run_id \
                  AND run.volume_id = binding.volume_id \
                 JOIN scan_job_roots AS job_root \
                   ON job_root.scan_job_id = job.id \
                  AND job_root.volume_id = job.volume_id \
                 JOIN scan_run_roots AS run_root \
                   ON run_root.scan_run_id = run.id \
                  AND run_root.volume_id = run.volume_id \
                 JOIN capability_profiles AS profile \
                   ON profile.id = run.capability_profile_id \
                  AND profile.volume_id = run.volume_id \
                 WHERE job.id = ?1 AND run.id = ?2 \
                   AND job_root.capability_profile_id = ?3 \
                   AND run_root.capability_profile_id = ?3 \
                   AND run.capability_profile_id = ?3 \
                   AND profile.mount_session_key = ?4 \
                   AND profile.profile_hash_version = 2 \
                   AND profile.is_current = 1 \
                   AND profile.probe_status = 'complete' \
                   AND profile.can_read = 1 \
                   AND profile.probe_protocol_version IS NOT NULL \
                   AND profile.case_behavior IS NOT NULL \
                   AND profile.unicode_behavior IS NOT NULL \
                   AND profile.path_encoding_family IS NOT NULL \
                   AND profile.path_semantics_version = job_root.path_semantics_version \
                   AND profile.path_semantics_version = run_root.path_semantics_version \
                   AND job_root.relative_path_raw = run_root.relative_path_raw \
                   AND job_root.path_encoding = run_root.path_encoding \
                   AND job_root.semantic_path_key = run_root.semantic_path_key \
                   AND ((profile.path_encoding_family = 'unix' \
                         AND run_root.path_encoding IN ('utf8', 'unix_bytes')) \
                     OR (profile.path_encoding_family = 'windows' \
                         AND run_root.path_encoding = 'windows_utf16_le')) \
             )",
            params![
                scan_job_id,
                scan_run_id,
                expected_capability_profile_id,
                expected_mount_session_key,
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !matches {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_start_capability_profile",
                id: scan_run_id,
            });
        }
        Ok(())
    }

    fn insert_scan_job_root(
        &self,
        input: &NewScanJob,
        scan_job_id: i64,
        path_encoding: &str,
    ) -> Result<()> {
        self.transaction.execute(
            "INSERT INTO scan_job_roots ( \
                 scan_job_id, volume_id, capability_profile_id, path_semantics_version, \
                 relative_path_raw, path_encoding, semantic_path_key, created_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                scan_job_id,
                input.volume_id,
                input.capability_profile_id,
                input.path_semantics_version,
                input.root_relative_path_raw,
                path_encoding,
                input.root_path_key.as_bytes(),
                input.created_at_ms,
            ],
        )?;
        Ok(())
    }

    fn validate_existing_scan_job_root(
        &self,
        input: &NewScanJob,
        scan_job_id: i64,
        path_encoding: &str,
    ) -> Result<()> {
        let matches = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM scan_job_roots \
                 WHERE scan_job_id = ?1 AND volume_id = ?2 \
                   AND capability_profile_id = ?3 AND path_semantics_version = ?4 \
                   AND relative_path_raw = ?5 AND path_encoding = ?6 \
                   AND semantic_path_key = ?7 \
             )",
            params![
                scan_job_id,
                input.volume_id,
                input.capability_profile_id,
                input.path_semantics_version,
                input.root_relative_path_raw,
                path_encoding,
                input.root_path_key.as_bytes(),
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !matches {
            return Err(StoreError::IdempotencyConflict {
                entity: "scan_job_root",
                key: input.job_key.clone(),
            });
        }
        Ok(())
    }

    fn insert_scan_run_root(
        &self,
        input: &NewScanRun,
        scan_run_id: i64,
        path_encoding: &str,
    ) -> Result<()> {
        self.transaction.execute(
            "INSERT INTO scan_run_roots ( \
                 scan_run_id, volume_id, capability_profile_id, path_semantics_version, \
                 relative_path_raw, path_encoding, semantic_path_key, created_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                scan_run_id,
                input.volume_id,
                input.capability_profile_id,
                input.path_semantics_version,
                input.root_relative_path_raw,
                path_encoding,
                input.root_path_key.as_bytes(),
                input.created_at_ms,
            ],
        )?;
        Ok(())
    }

    fn validate_existing_scan_run_root(
        &self,
        input: &NewScanRun,
        scan_run_id: i64,
        path_encoding: &str,
    ) -> Result<()> {
        let matches = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM scan_run_roots \
                 WHERE scan_run_id = ?1 AND volume_id = ?2 \
                   AND capability_profile_id = ?3 AND path_semantics_version = ?4 \
                   AND relative_path_raw = ?5 AND path_encoding = ?6 \
                   AND semantic_path_key = ?7 \
             )",
            params![
                scan_run_id,
                input.volume_id,
                input.capability_profile_id,
                input.path_semantics_version,
                input.root_relative_path_raw,
                path_encoding,
                input.root_path_key.as_bytes(),
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !matches {
            return Err(StoreError::IdempotencyConflict {
                entity: "scan_run_root",
                key: input.run_key.clone(),
            });
        }
        Ok(())
    }

    fn insert_media_file(
        &self,
        input: &MediaFileInput,
        storage_path_key: &[u8; 32],
        metadata_json: Option<&str>,
    ) -> Result<()> {
        self.transaction.execute(
            "INSERT INTO media_files ( \
                 volume_id, first_seen_scan_run_id, last_seen_scan_run_id, relative_path, path_key, \
                 entry_type, media_kind, mime_type, file_extension, lifecycle_state, size_bytes, \
                 allocated_bytes, native_file_id, native_file_generation, link_count, is_sparse, \
                 may_share_content, birth_time_ns, modified_time_ns, changed_time_ns, \
                 accessed_time_ns, timestamp_granularity_ns, stat_signature, metadata_json, \
                 created_at_ms, updated_at_ms \
             ) VALUES ( \
                 ?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?24 \
             )",
            params![
                input.volume_id,
                input.scan_run_id,
                input.relative_path,
                storage_path_key.as_slice(),
                input.entry_type,
                input.media_kind,
                input.mime_type,
                input.file_extension,
                input.lifecycle_state,
                input.size_bytes,
                input.allocated_bytes,
                input.native_file_id,
                input.native_file_generation,
                input.link_count,
                optional_bool_to_integer(input.is_sparse),
                optional_bool_to_integer(input.may_share_content),
                input.birth_time_ns,
                input.modified_time_ns,
                input.changed_time_ns,
                input.accessed_time_ns,
                input.timestamp_granularity_ns,
                input.stat_signature,
                metadata_json,
                input.observed_at_ms,
            ],
        )?;
        Ok(())
    }

    fn update_media_file(
        &self,
        media_file_id: i64,
        input: &MediaFileInput,
        metadata_json: Option<&str>,
    ) -> Result<bool> {
        let changed = self.transaction.execute(
            "UPDATE media_files SET \
                 last_seen_scan_run_id = ?2, relative_path = ?3, entry_type = ?4, \
                 media_kind = ?5, mime_type = ?6, file_extension = ?7, lifecycle_state = ?8, \
                 size_bytes = ?9, allocated_bytes = ?10, native_file_id = ?11, \
                 native_file_generation = ?12, link_count = ?13, is_sparse = ?14, \
                 may_share_content = ?15, birth_time_ns = ?16, modified_time_ns = ?17, \
                 changed_time_ns = ?18, accessed_time_ns = ?19, timestamp_granularity_ns = ?20, \
                 stat_signature = ?21, metadata_json = ?22, updated_at_ms = ?23 \
             WHERE id = ?1 AND volume_id = ?24 \
               AND (updated_at_ms < ?23 \
                    OR (updated_at_ms = ?23 AND last_seen_scan_run_id <= ?2))",
            params![
                media_file_id,
                input.scan_run_id,
                input.relative_path,
                input.entry_type,
                input.media_kind,
                input.mime_type,
                input.file_extension,
                input.lifecycle_state,
                input.size_bytes,
                input.allocated_bytes,
                input.native_file_id,
                input.native_file_generation,
                input.link_count,
                optional_bool_to_integer(input.is_sparse),
                optional_bool_to_integer(input.may_share_content),
                input.birth_time_ns,
                input.modified_time_ns,
                input.changed_time_ns,
                input.accessed_time_ns,
                input.timestamp_granularity_ns,
                input.stat_signature,
                metadata_json,
                input.observed_at_ms,
                input.volume_id,
            ],
        )?;
        Ok(changed == 1)
    }

    fn insert_media_observation(
        &self,
        input: &MediaFileInput,
        media_file_id: i64,
        path_encoding: &str,
    ) -> Result<()> {
        let inserted = self
            .transaction
            .query_row(
                "INSERT INTO media_file_observations ( \
                     volume_id, media_file_id, scan_run_id, capability_profile_id, \
                     path_semantics_version, relative_path, relative_path_raw, path_encoding, \
                     semantic_path_key, observed_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
                 ON CONFLICT(scan_run_id, media_file_id) DO NOTHING \
                 RETURNING id",
                params![
                    input.volume_id,
                    media_file_id,
                    input.scan_run_id,
                    input.capability_profile_id,
                    input.path_semantics_version,
                    input.relative_path,
                    input.relative_path_raw,
                    path_encoding,
                    input.path_key.as_bytes(),
                    input.observed_at_ms,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if inserted.is_some() {
            return Ok(());
        }
        let matches = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM media_file_observations \
                 WHERE scan_run_id = ?1 AND media_file_id = ?2 AND volume_id = ?3 \
                   AND capability_profile_id = ?4 AND path_semantics_version = ?5 \
                   AND relative_path = ?6 AND relative_path_raw = ?7 AND path_encoding = ?8 \
                   AND semantic_path_key = ?9 AND observed_at_ms = ?10 \
             )",
            params![
                input.scan_run_id,
                media_file_id,
                input.volume_id,
                input.capability_profile_id,
                input.path_semantics_version,
                input.relative_path,
                input.relative_path_raw,
                path_encoding,
                input.path_key.as_bytes(),
                input.observed_at_ms,
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !matches {
            return Err(StoreError::IdempotencyConflict {
                entity: "media_file_observation",
                key: format!("{}:{media_file_id}", input.scan_run_id),
            });
        }
        Ok(())
    }

    fn validate_existing_scan_run(&self, input: &NewScanRun) -> Result<i64> {
        let existing = self.transaction.query_row(
            "SELECT id, volume_id, capability_profile_id, parent_scan_run_id, root_relative_path, \
                    root_path_key, scan_mode, config_json \
             FROM scan_runs WHERE run_key = ?1",
            [&input.run_key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )?;
        let matches = existing.1 == input.volume_id
            && existing.2 == input.capability_profile_id
            && existing.3 == input.parent_scan_run_id
            && existing.4 == input.root_relative_path
            && existing.5.as_slice() == input.root_path_key.as_bytes()
            && existing.6 == input.scan_mode
            && existing.7 == serialize_optional_json("config", &input.config, MAX_JSON_BYTES)?;
        if !matches {
            return Err(StoreError::IdempotencyConflict {
                entity: "scan_run",
                key: input.run_key.clone(),
            });
        }
        Ok(existing.0)
    }

    fn bind_run_to_job(
        &self,
        input: &NewScanRun,
        scan_run_id: i64,
        was_inserted: bool,
    ) -> Result<()> {
        let active_scan_run_id = self.transaction.query_row(
            "SELECT active_scan_run_id FROM scan_jobs WHERE id = ?1 AND volume_id = ?2",
            params![input.scan_job_id, input.volume_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        if !was_inserted && active_scan_run_id != Some(scan_run_id) {
            return Err(StoreError::IdempotencyConflict {
                entity: "scan_run_active_binding",
                key: input.run_key.clone(),
            });
        }
        if was_inserted {
            if let Some(previous_run_id) = active_scan_run_id {
                let can_replace = self.transaction.query_row(
                    "SELECT EXISTS( \
                         SELECT 1 FROM scan_jobs AS job \
                         JOIN scan_runs AS run \
                           ON run.id = ?2 AND run.volume_id = job.volume_id \
                         WHERE job.id = ?1 AND job.state = 'failed' \
                           AND run.state IN ('failed', 'interrupted') \
                     )",
                    params![input.scan_job_id, previous_run_id],
                    |row| row.get::<_, bool>(0),
                )?;
                if !can_replace {
                    return Err(StoreError::ConcurrencyConflict {
                        entity: "scan_job_active_run_replacement",
                        id: input.scan_job_id,
                    });
                }
            }
        }
        let existing_job: Option<i64> = self
            .transaction
            .query_row(
                "SELECT scan_job_id FROM scan_job_runs WHERE scan_run_id = ?1",
                [scan_run_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(job_id) = existing_job {
            if job_id != input.scan_job_id {
                return Err(StoreError::IdempotencyConflict {
                    entity: "scan_run_job_binding",
                    key: input.run_key.clone(),
                });
            }
        } else {
            let attempt_number: i64 = self.transaction.query_row(
                "SELECT COALESCE(MAX(attempt_number), 0) + 1 \
                 FROM scan_job_runs WHERE scan_job_id = ?1",
                [input.scan_job_id],
                |row| row.get(0),
            )?;
            self.transaction.execute(
                "INSERT INTO scan_job_runs ( \
                     scan_job_id, scan_run_id, volume_id, attempt_number, created_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    input.scan_job_id,
                    scan_run_id,
                    input.volume_id,
                    attempt_number,
                    input.created_at_ms,
                ],
            )?;
        }
        let changed = self.transaction.execute(
            "UPDATE scan_jobs SET active_scan_run_id = ?2, updated_at_ms = MAX(updated_at_ms, ?3) \
             WHERE id = ?1 AND volume_id = ?4 \
               AND root_relative_path = ?5 AND root_path_key = ?6",
            params![
                input.scan_job_id,
                scan_run_id,
                input.created_at_ms,
                input.volume_id,
                input.root_relative_path,
                input.root_path_key.as_bytes(),
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_run_job_binding",
                id: input.scan_job_id,
            });
        }
        Ok(())
    }

    fn validate_scan_run_binding(&self, input: &NewScanRun) -> Result<()> {
        let job = self.transaction.query_row(
            "SELECT job.volume_id, job.root_relative_path, job.root_path_key, job.state, \
                    root.relative_path_raw, root.path_encoding, root.path_semantics_version, \
                    root.capability_profile_id \
             FROM scan_jobs AS job \
             JOIN scan_job_roots AS root ON root.scan_job_id = job.id \
             WHERE job.id = ?1",
            [input.scan_job_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            },
        )?;
        if job.0 != input.volume_id
            || job.1 != input.root_relative_path
            || job.2.as_slice() != input.root_path_key.as_bytes()
            || !matches!(job.3.as_str(), "queued" | "running" | "paused" | "failed")
            || job.4 != input.root_relative_path_raw
            || job.5 != input.root_path_encoding
            || job.6 != input.path_semantics_version
            || job.7 != Some(input.capability_profile_id)
        {
            return Err(StoreError::IdempotencyConflict {
                entity: "scan_run_job_root_or_state",
                key: input.run_key.clone(),
            });
        }

        let capability_matches = self.transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM capability_profiles \
             WHERE id = ?1 AND volume_id = ?2)",
            params![input.capability_profile_id, input.volume_id],
            |row| row.get::<_, bool>(0),
        )?;
        if !capability_matches {
            return Err(StoreError::IdempotencyConflict {
                entity: "scan_run_capability_volume",
                key: input.run_key.clone(),
            });
        }

        if let Some(parent_scan_run_id) = input.parent_scan_run_id {
            let parent_matches = self.transaction.query_row(
                "SELECT EXISTS( \
                     SELECT 1 FROM scan_runs AS run \
                     JOIN scan_run_roots AS root ON root.scan_run_id = run.id \
                     WHERE run.id = ?1 AND run.volume_id = ?2 \
                       AND run.root_relative_path = ?3 AND run.root_path_key = ?4 \
                       AND root.relative_path_raw = ?5 AND root.path_encoding = ?6 \
                       AND root.path_semantics_version = ?7 \
                 )",
                params![
                    parent_scan_run_id,
                    input.volume_id,
                    input.root_relative_path,
                    input.root_path_key.as_bytes(),
                    input.root_relative_path_raw,
                    input.root_path_encoding,
                    input.path_semantics_version,
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if !parent_matches {
                return Err(StoreError::IdempotencyConflict {
                    entity: "scan_run_parent_root",
                    key: input.run_key.clone(),
                });
            }
        }
        Ok(())
    }
}

fn validate_volume(input: &VolumeInput) -> Result<()> {
    require_bounded_nonempty("identity_key", &input.identity_key, MAX_IDENTIFIER_BYTES)?;
    validate_identity_strength(&input.identity_strength)?;
    require_bounded_nonempty(
        "filesystem_type",
        &input.filesystem_type,
        MAX_IDENTIFIER_BYTES,
    )?;
    require_nonnegative("now_ms", input.now_ms)?;
    validate_optional_bounded(
        "marker_uuid",
        input.marker_uuid.as_deref(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_optional_bounded(
        "native_uuid",
        input.native_uuid.as_deref(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_optional_bounded(
        "display_name",
        input.display_name.as_deref(),
        MAX_TEXT_BYTES,
    )?;
    validate_optional_bounded(
        "mount_source",
        input.mount_source.as_deref(),
        MAX_PATH_BYTES,
    )?;
    validate_optional_bounded(
        "last_mount_path",
        input.last_mount_path.as_deref(),
        MAX_PATH_BYTES,
    )?;
    validate_optional_bounded(
        "transport",
        input.transport.as_deref(),
        MAX_IDENTIFIER_BYTES,
    )?;
    if input.identity_strength == "strong"
        && input.marker_uuid.is_none()
        && input.native_uuid.is_none()
    {
        return Err(StoreError::invalid_input(
            "identity_strength",
            "strong volume identity requires a marker UUID or native UUID",
        ));
    }
    Ok(())
}

fn validate_capability_profile(input: &CapabilityProfileInput) -> Result<()> {
    require_positive("volume_id", input.volume_id)?;
    if !matches!(input.probe_mode.as_str(), "passive" | "active") {
        return Err(StoreError::invalid_input(
            "probe_mode",
            "expected passive or active",
        ));
    }
    if !matches!(
        input.probe_status.as_str(),
        "complete" | "partial" | "failed"
    ) {
        return Err(StoreError::invalid_input(
            "probe_status",
            "expected complete, partial, or failed",
        ));
    }
    require_nonnegative("observed_at_ms", input.observed_at_ms)?;
    require_bounded_nonempty("os_build", &input.os_build, MAX_IDENTIFIER_BYTES)?;
    validate_optional_bounded(
        "mount_session_key",
        input.mount_session_key.as_deref(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_optional_positive("probe_protocol_version", input.probe_protocol_version)?;
    validate_optional_bounded(
        "driver_name",
        input.driver_name.as_deref(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_optional_bounded(
        "driver_version",
        input.driver_version.as_deref(),
        MAX_IDENTIFIER_BYTES,
    )?;
    if input.case_behavior.as_deref().is_some_and(|value| {
        !matches!(
            value,
            "sensitive" | "insensitive_preserving" | "insensitive_nonpreserving"
        )
    }) {
        return Err(StoreError::invalid_input(
            "case_behavior",
            "unsupported case behavior",
        ));
    }
    if input
        .unicode_behavior
        .as_deref()
        .is_some_and(|value| !matches!(value, "exact" | "nfc" | "nfd" | "normalizing_other"))
    {
        return Err(StoreError::invalid_input(
            "unicode_behavior",
            "unsupported Unicode behavior",
        ));
    }
    if input
        .path_encoding_family
        .as_deref()
        .is_some_and(|value| !matches!(value, "unix" | "windows"))
    {
        return Err(StoreError::invalid_input(
            "path_encoding_family",
            "expected unix or windows",
        ));
    }
    require_positive("path_semantics_version", input.path_semantics_version)?;
    validate_optional_positive("timestamp_granularity_ns", input.timestamp_granularity_ns)?;
    validate_optional_positive("maximum_name_bytes", input.maximum_name_bytes)?;
    validate_optional_nonnegative("maximum_file_bytes", input.maximum_file_bytes)?;
    let _ = serialize_optional_json("raw_capabilities", &input.raw_capabilities, MAX_JSON_BYTES)?;
    Ok(())
}

fn validate_scan_job(input: &NewScanJob) -> Result<()> {
    require_bounded_nonempty("job_key", &input.job_key, MAX_IDENTIFIER_BYTES)?;
    require_positive("volume_id", input.volume_id)?;
    require_positive("capability_profile_id", input.capability_profile_id)?;
    require_positive("path_semantics_version", input.path_semantics_version)?;
    validate_relative_path("root_relative_path", &input.root_relative_path, true)?;
    require_nonnegative("created_at_ms", input.created_at_ms)
}

fn validate_scan_run(input: &NewScanRun) -> Result<()> {
    require_bounded_nonempty("run_key", &input.run_key, MAX_IDENTIFIER_BYTES)?;
    require_positive("volume_id", input.volume_id)?;
    require_positive("scan_job_id", input.scan_job_id)?;
    require_positive("capability_profile_id", input.capability_profile_id)?;
    require_positive("path_semantics_version", input.path_semantics_version)?;
    validate_relative_path("root_relative_path", &input.root_relative_path, true)?;
    require_bounded_nonempty("scan_mode", &input.scan_mode, MAX_IDENTIFIER_BYTES)?;
    require_nonnegative("created_at_ms", input.created_at_ms)
}

fn validate_media_file(input: &MediaFileInput) -> Result<&'static str> {
    require_positive("volume_id", input.volume_id)?;
    require_positive("scan_run_id", input.scan_run_id)?;
    require_positive("capability_profile_id", input.capability_profile_id)?;
    require_positive("path_semantics_version", input.path_semantics_version)?;
    validate_relative_path("relative_path", &input.relative_path, false)?;
    let path_encoding = validate_raw_relative_path(
        &input.relative_path,
        &input.relative_path_raw,
        &input.path_encoding,
        false,
    )?;
    require_bounded_nonempty("entry_type", &input.entry_type, MAX_IDENTIFIER_BYTES)?;
    require_bounded_nonempty("media_kind", &input.media_kind, MAX_IDENTIFIER_BYTES)?;
    require_bounded_nonempty(
        "lifecycle_state",
        &input.lifecycle_state,
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_optional_bounded(
        "mime_type",
        input.mime_type.as_deref(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_optional_bounded(
        "file_extension",
        input.file_extension.as_deref(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_optional_nonnegative("size_bytes", input.size_bytes)?;
    validate_optional_nonnegative("allocated_bytes", input.allocated_bytes)?;
    validate_optional_positive("link_count", input.link_count)?;
    validate_optional_positive("timestamp_granularity_ns", input.timestamp_granularity_ns)?;
    validate_optional_blob("native_file_id", input.native_file_id.as_deref())?;
    if input
        .stat_signature
        .as_ref()
        .is_some_and(|signature| signature.len() != 32)
    {
        return Err(StoreError::invalid_input(
            "stat_signature",
            "stat signature must contain exactly 32 bytes",
        ));
    }
    require_nonnegative("observed_at_ms", input.observed_at_ms)?;
    Ok(path_encoding)
}

fn validate_raw_relative_path(
    display: &str,
    value: &[u8],
    encoding: &str,
    allow_empty: bool,
) -> Result<&'static str> {
    if value.len() > MAX_PATH_BYTES {
        return Err(StoreError::invalid_input(
            "relative_path_raw",
            format!("raw path exceeds {MAX_PATH_BYTES} bytes"),
        ));
    }
    if display.is_empty() && !value.is_empty() {
        return Err(StoreError::invalid_input(
            "relative_path_raw",
            "a volume-root display path must also have an empty raw path",
        ));
    }
    if value.is_empty() {
        if !allow_empty || !display.is_empty() {
            return Err(StoreError::invalid_input(
                "relative_path_raw",
                "raw path must not be empty",
            ));
        }
        return match encoding {
            "utf8" => Ok("utf8"),
            "unix_bytes" => Ok("unix_bytes"),
            "windows_utf16_le" => Ok("windows_utf16_le"),
            _ => Err(StoreError::invalid_input(
                "path_encoding",
                "unsupported raw path encoding",
            )),
        };
    }
    let canonical_encoding = match encoding {
        "utf8" | "unix_bytes" => {
            if value.first() == Some(&b'/') || value.contains(&0) {
                return Err(StoreError::invalid_input(
                    "relative_path_raw",
                    "Unix path must be relative and contain no NUL",
                ));
            }
            if value
                .split(|byte| *byte == b'/')
                .any(|component| component.is_empty() || component == b"." || component == b"..")
            {
                return Err(StoreError::invalid_input(
                    "relative_path_raw",
                    "Unix path contains an empty, dot, or parent component",
                ));
            }
            if encoding == "utf8" && std::str::from_utf8(value).is_err() {
                return Err(StoreError::invalid_input(
                    "relative_path_raw",
                    "utf8 path encoding requires valid UTF-8 bytes",
                ));
            }
            if encoding == "utf8" && value != display.as_bytes() {
                return Err(StoreError::invalid_input(
                    "relative_path",
                    "utf8 raw path must exactly match display text",
                ));
            }
            if encoding == "utf8" {
                "utf8"
            } else {
                "unix_bytes"
            }
        }
        "windows_utf16_le" => {
            validate_windows_utf16_relative_path(value)?;
            "windows_utf16_le"
        }
        _ => {
            return Err(StoreError::invalid_input(
                "path_encoding",
                "unsupported raw path encoding",
            ));
        }
    };
    Ok(canonical_encoding)
}

pub(crate) fn validate_persisted_path_evidence(
    display: &str,
    raw: &[u8],
    encoding: &str,
    allow_empty: bool,
) -> Result<()> {
    validate_relative_path("relative_path", display, allow_empty)?;
    validate_raw_relative_path(display, raw, encoding, allow_empty)?;
    Ok(())
}

/// Legacy schemas did not bind UTF-8 path evidence to a platform namespace.
/// Accept only the intersection of the Unix and ordinary Win32 relative-path
/// rules so an ambiguous legacy row cannot acquire a trusted v4 profile.
pub(crate) fn validate_legacy_portable_utf8_path(display: &str, allow_empty: bool) -> Result<()> {
    validate_persisted_path_evidence(display, display.as_bytes(), "utf8", allow_empty)?;
    if display.is_empty() {
        return Ok(());
    }
    let windows_bytes = display
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    validate_windows_utf16_relative_path(&windows_bytes)
}

fn validate_windows_utf16_relative_path(value: &[u8]) -> Result<()> {
    let mut chunks = value.chunks_exact(2);
    let code_units = chunks
        .by_ref()
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    if !chunks.remainder().is_empty() {
        return Err(StoreError::invalid_input(
            "relative_path_raw",
            "windows_utf16_le path must contain complete 16-bit code units",
        ));
    }
    if code_units
        .first()
        .is_some_and(|unit| *unit == b'/' as u16 || *unit == b'\\' as u16)
        || code_units.contains(&0)
        || code_units.contains(&(b':' as u16))
    {
        return Err(StoreError::invalid_input(
            "relative_path_raw",
            "Windows path must be relative and contain no NUL, drive prefix, or alternate-data-stream colon",
        ));
    }
    if code_units
        .split(|unit| *unit == b'/' as u16 || *unit == b'\\' as u16)
        .any(|component| {
            component.is_empty()
                || component == [b'.' as u16]
                || component == [b'.' as u16, b'.' as u16]
                || component
                    .last()
                    .is_some_and(|unit| *unit == b'.' as u16 || *unit == b' ' as u16)
                || is_windows_device_component(component)
        })
    {
        return Err(StoreError::invalid_input(
            "relative_path_raw",
            "Windows path contains an empty, dot, or parent component",
        ));
    }
    Ok(())
}

fn is_windows_device_component(component: &[u16]) -> bool {
    let Some(ascii) = component
        .iter()
        .map(|unit| u8::try_from(*unit).ok())
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let base = ascii
        .split(|byte| *byte == b'.')
        .next()
        .unwrap_or_default()
        .iter()
        .map(u8::to_ascii_uppercase)
        .collect::<Vec<_>>();
    matches!(base.as_slice(), b"CON" | b"PRN" | b"AUX" | b"NUL")
        || (base.len() == 4
            && matches!(&base[..3], b"COM" | b"LPT")
            && matches!(base[3], b'1'..=b'9'))
}

fn validate_scan_issue(input: &NewScanIssue) -> Result<()> {
    require_bounded_nonempty("issue_key", &input.issue_key, MAX_IDENTIFIER_BYTES)?;
    require_positive("volume_id", input.volume_id)?;
    require_positive("scan_run_id", input.scan_run_id)?;
    if input.media_file_id.is_some_and(|id| id <= 0) {
        return Err(StoreError::invalid_input(
            "media_file_id",
            "value must be positive",
        ));
    }
    require_bounded_nonempty("severity", &input.severity, MAX_IDENTIFIER_BYTES)?;
    require_bounded_nonempty("stage", &input.stage, MAX_IDENTIFIER_BYTES)?;
    require_bounded_nonempty("code", &input.code, MAX_IDENTIFIER_BYTES)?;
    require_bounded_nonempty("message", &input.message, MAX_TEXT_BYTES)?;
    require_nonnegative("occurred_at_ms", input.occurred_at_ms)
}

fn validate_scan_report(input: &NewScanReport) -> Result<()> {
    require_bounded_nonempty("report_key", &input.report_key, MAX_IDENTIFIER_BYTES)?;
    require_positive("volume_id", input.volume_id)?;
    require_positive("scan_run_id", input.scan_run_id)?;
    require_positive("report_version", input.report_version)?;
    require_nonnegative("generated_at_ms", input.generated_at_ms)
}

fn validate_relative_path(field: &'static str, value: &str, allow_empty: bool) -> Result<()> {
    if value.len() > MAX_PATH_BYTES {
        return Err(StoreError::invalid_input(
            field,
            format!("path exceeds {MAX_PATH_BYTES} bytes"),
        ));
    }
    if value.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(StoreError::invalid_input(field, "path must not be empty"))
        };
    }
    if value.starts_with('/') || value.contains('\0') {
        return Err(StoreError::invalid_input(
            field,
            "path must be relative and contain no NUL",
        ));
    }
    if value
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(StoreError::invalid_input(
            field,
            "path contains an empty, dot, or parent component",
        ));
    }
    Ok(())
}

fn validate_job_transition(from: &str, to: &str) -> Result<()> {
    let allowed = matches!(
        (from, to),
        ("queued", "running")
            | ("queued", "cancelled")
            | ("running", "paused")
            | ("running", "completed")
            | ("running", "failed")
            | ("running", "cancelled")
            | ("paused", "running")
            | ("paused", "failed")
            | ("paused", "cancelled")
            | ("failed", "running")
    );
    if !allowed {
        return Err(StoreError::invalid_input(
            "target_state",
            format!("unsupported scan job transition {from} -> {to}"),
        ));
    }
    Ok(())
}

fn validate_run_transition(from: &str, to: &str) -> Result<()> {
    let allowed = matches!(
        (from, to),
        ("queued", "running")
            | ("queued", "cancelled")
            | ("running", "paused")
            | ("running", "completed")
            | ("running", "failed")
            | ("running", "cancelled")
            | ("running", "interrupted")
            | ("paused", "running")
            | ("paused", "failed")
            | ("paused", "cancelled")
            | ("paused", "interrupted")
    );
    if !allowed {
        return Err(StoreError::invalid_input(
            "target_state",
            format!("unsupported scan run transition {from} -> {to}"),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TransitionOrder {
    JobThenRun,
    RunThenJob,
}

fn validate_job_run_transition(
    job_from: &str,
    run_from: &str,
    job_to: &str,
    run_to: &str,
) -> Result<TransitionOrder> {
    let order = match (job_from, run_from, job_to, run_to) {
        ("queued", "queued", "running", "running")
        | ("paused", "paused", "running", "running")
        | ("failed", "queued", "running", "running") => TransitionOrder::JobThenRun,
        ("running", "running", "paused", "paused")
        | ("running", "running", "completed", "completed")
        | ("queued", "queued", "cancelled", "cancelled")
        | ("running", "running", "cancelled", "cancelled")
        | ("paused", "paused", "cancelled", "cancelled")
        | ("running", "running", "failed", "failed")
        | ("paused", "paused", "failed", "failed")
        | ("running", "running", "failed", "interrupted")
        | ("paused", "paused", "failed", "interrupted") => TransitionOrder::RunThenJob,
        _ => {
            return Err(StoreError::invalid_input(
                "target_state",
                format!(
                    "unsupported coordinated transition job {job_from}->{job_to}, run {run_from}->{run_to}"
                ),
            ));
        }
    };
    validate_job_transition(job_from, job_to)?;
    validate_run_transition(run_from, run_to)?;
    Ok(order)
}

fn validate_transition_error(target_state: &str, last_error: Option<(&str, &str)>) -> Result<()> {
    match (target_state, last_error) {
        ("failed" | "interrupted", Some((code, message))) => {
            require_bounded_nonempty("last_error_code", code, MAX_IDENTIFIER_BYTES)?;
            require_bounded_nonempty("last_error_message", message, MAX_TEXT_BYTES)
        }
        ("failed" | "interrupted", None) => Err(StoreError::invalid_input(
            "last_error",
            "failed or interrupted scan runs require an error code and message",
        )),
        (_, Some(_)) => Err(StoreError::invalid_input(
            "last_error",
            "non-error scan states cannot carry last-error evidence",
        )),
        (_, None) => Ok(()),
    }
}

fn require_bounded_nonempty(field: &'static str, value: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(StoreError::invalid_input(field, "value must not be empty"));
    }
    if value.len() > max_bytes {
        return Err(StoreError::invalid_input(
            field,
            format!("value exceeds {max_bytes} UTF-8 bytes"),
        ));
    }
    Ok(())
}

fn validate_optional_bounded(
    field: &'static str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<()> {
    if let Some(value) = value {
        require_bounded_nonempty(field, value, max_bytes)?;
    }
    Ok(())
}

fn validate_identity_strength(value: &str) -> Result<()> {
    if matches!(value, "weak" | "medium" | "strong") {
        Ok(())
    } else {
        Err(StoreError::invalid_input(
            "identity_strength",
            "expected weak, medium, or strong",
        ))
    }
}

fn identity_rank(value: &str) -> Result<u8> {
    match value {
        "weak" => Ok(0),
        "medium" => Ok(1),
        "strong" => Ok(2),
        _ => Err(StoreError::invalid_input(
            "identity_strength",
            "expected weak, medium, or strong",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn controlled_identity_upgrade(
    identity_key: &str,
    existing_strength: &str,
    observed_strength: &str,
    existing_marker: Option<&str>,
    observed_marker: Option<&str>,
    existing_native: Option<&str>,
    observed_native: Option<&str>,
) -> Result<String> {
    let existing_rank = identity_rank(existing_strength)?;
    let observed_rank = identity_rank(observed_strength)?;
    let adds_marker = existing_marker.is_none() && observed_marker.is_some();
    let adds_native = existing_native.is_none() && observed_native.is_some();
    let controlled_upgrade = existing_strength == "weak"
        && observed_strength == "strong"
        && (adds_marker || adds_native);
    if controlled_upgrade {
        return Ok(observed_strength.to_owned());
    }
    if adds_marker || adds_native {
        return Err(StoreError::VolumeIdentityConflict {
            identity_key: identity_key.to_owned(),
            reason: "strong identity fields may only be filled during a weak-to-strong upgrade"
                .into(),
        });
    }
    if observed_rank <= existing_rank {
        return Ok(existing_strength.to_owned());
    }

    Err(StoreError::VolumeIdentityConflict {
        identity_key: identity_key.to_owned(),
        reason: "strong identity fields may only be filled during a weak-to-strong upgrade".into(),
    })
}

fn reject_identifier_change(
    identity_key: &str,
    field: &str,
    existing: Option<&str>,
    observed: Option<&str>,
) -> Result<()> {
    if let (Some(existing), Some(observed)) = (existing, observed) {
        if existing != observed {
            return Err(StoreError::VolumeIdentityConflict {
                identity_key: identity_key.to_owned(),
                reason: format!("{field} changed from {existing:?} to {observed:?}"),
            });
        }
    }
    Ok(())
}

fn validate_optional_blob(field: &'static str, value: Option<&[u8]>) -> Result<()> {
    if value.is_some_and(|value| value.len() > MAX_OPAQUE_BLOB_BYTES) {
        return Err(StoreError::invalid_input(
            field,
            format!("value exceeds {MAX_OPAQUE_BLOB_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn validate_optional_positive(field: &'static str, value: Option<i64>) -> Result<()> {
    if value.is_some_and(|value| value <= 0) {
        return Err(StoreError::invalid_input(field, "value must be positive"));
    }
    Ok(())
}

fn validate_optional_nonnegative(field: &'static str, value: Option<i64>) -> Result<()> {
    if value.is_some_and(|value| value < 0) {
        return Err(StoreError::invalid_input(
            field,
            "value must be non-negative",
        ));
    }
    Ok(())
}

fn require_positive(field: &'static str, value: i64) -> Result<()> {
    if value <= 0 {
        return Err(StoreError::invalid_input(field, "value must be positive"));
    }
    Ok(())
}

fn require_nonnegative(field: &'static str, value: i64) -> Result<()> {
    if value < 0 {
        return Err(StoreError::invalid_input(
            field,
            "value must be non-negative",
        ));
    }
    Ok(())
}

fn bool_to_integer(value: bool) -> i64 {
    i64::from(value)
}

fn optional_bool_to_integer(value: Option<bool>) -> Option<i64> {
    value.map(bool_to_integer)
}

fn serialize_optional_json(
    field: &'static str,
    value: &Option<serde_json::Value>,
    max_bytes: usize,
) -> Result<Option<String>> {
    let serialized = value
        .as_ref()
        .map(serialize_canonical_json)
        .transpose()
        .map_err(StoreError::from)?;
    if serialized
        .as_ref()
        .is_some_and(|serialized| serialized.len() > max_bytes)
    {
        return Err(StoreError::invalid_input(
            field,
            format!("serialized JSON exceeds {max_bytes} bytes"),
        ));
    }
    Ok(serialized)
}

fn serialize_canonical_json(value: &serde_json::Value) -> serde_json::Result<String> {
    serde_json::to_string(&canonicalize_json(value))
}

fn canonicalize_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonicalize_json).collect())
        }
        serde_json::Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            let mut canonical = serde_json::Map::new();
            for (key, value) in entries {
                canonical.insert(key.clone(), canonicalize_json(value));
            }
            serde_json::Value::Object(canonical)
        }
        scalar => scalar.clone(),
    }
}

const LEGACY_CAPABILITY_HASH_VERSION: i64 = 1;
const CAPABILITY_HASH_VERSION: i64 = 2;
const MAX_CAPABILITY_PROFILES: i64 = 100_000;

#[derive(serde::Serialize)]
struct LegacyCapabilityHashMaterial<'a> {
    format_version: u8,
    probe_mode: &'a str,
    probe_status: &'a str,
    os_build: &'a str,
    driver_name: &'a Option<String>,
    driver_version: &'a Option<String>,
    can_read: Option<bool>,
    can_write: Option<bool>,
    can_rename_same_volume: Option<bool>,
    can_rename_exclusive: Option<bool>,
    can_set_birth_time: Option<bool>,
    can_set_modified_time: Option<bool>,
    can_use_xattrs: Option<bool>,
    has_persistent_file_ids: Option<bool>,
    timestamp_granularity_ns: Option<i64>,
    raw_capabilities: &'a Option<serde_json::Value>,
}

#[derive(serde::Serialize)]
struct CapabilityHashMaterial<'a> {
    format_version: u8,
    probe_mode: &'a str,
    probe_status: &'a str,
    os_build: &'a str,
    mount_session_key: &'a Option<String>,
    probe_protocol_version: Option<i64>,
    driver_name: &'a Option<String>,
    driver_version: &'a Option<String>,
    mount_flags: Option<i64>,
    case_behavior: &'a Option<String>,
    unicode_behavior: &'a Option<String>,
    path_encoding_family: &'a Option<String>,
    path_semantics_version: i64,
    can_read: Option<bool>,
    can_write: Option<bool>,
    can_rename_same_volume: Option<bool>,
    can_rename_exclusive: Option<bool>,
    can_no_replace: Option<bool>,
    can_sync_directory: Option<bool>,
    can_append_durable: Option<bool>,
    single_writer: Option<bool>,
    can_set_birth_time: Option<bool>,
    can_set_modified_time: Option<bool>,
    can_use_xattrs: Option<bool>,
    can_use_hard_links: Option<bool>,
    can_use_clones: Option<bool>,
    has_persistent_file_ids: Option<bool>,
    timestamp_granularity_ns: Option<i64>,
    maximum_name_bytes: Option<i64>,
    maximum_file_bytes: Option<i64>,
    raw_capabilities: &'a Option<serde_json::Value>,
}

/// Computes the internally defined, versioned capability identity.
/// Observation time and volume id are intentionally excluded: the same probed
/// capabilities remain idempotent when observed again on the same volume.
pub fn compute_capability_profile_hash(input: &CapabilityProfileInput) -> Result<[u8; 32]> {
    validate_capability_profile(input)?;
    let material = CapabilityHashMaterial {
        format_version: u8::try_from(CAPABILITY_HASH_VERSION)
            .map_err(|_| StoreError::invalid_input("profile_hash", "hash version overflow"))?,
        probe_mode: &input.probe_mode,
        probe_status: &input.probe_status,
        os_build: &input.os_build,
        mount_session_key: &input.mount_session_key,
        probe_protocol_version: input.probe_protocol_version,
        driver_name: &input.driver_name,
        driver_version: &input.driver_version,
        mount_flags: input.mount_flags,
        case_behavior: &input.case_behavior,
        unicode_behavior: &input.unicode_behavior,
        path_encoding_family: &input.path_encoding_family,
        path_semantics_version: input.path_semantics_version,
        can_read: input.can_read,
        can_write: input.can_write,
        can_rename_same_volume: input.can_rename_same_volume,
        can_rename_exclusive: input.can_rename_exclusive,
        can_no_replace: input.can_no_replace,
        can_sync_directory: input.can_sync_directory,
        can_append_durable: input.can_append_durable,
        single_writer: input.single_writer,
        can_set_birth_time: input.can_set_birth_time,
        can_set_modified_time: input.can_set_modified_time,
        can_use_xattrs: input.can_use_xattrs,
        can_use_hard_links: input.can_use_hard_links,
        can_use_clones: input.can_use_clones,
        has_persistent_file_ids: input.has_persistent_file_ids,
        timestamp_granularity_ns: input.timestamp_granularity_ns,
        maximum_name_bytes: input.maximum_name_bytes,
        maximum_file_bytes: input.maximum_file_bytes,
        raw_capabilities: &input.raw_capabilities,
    };
    let material_value = serde_json::to_value(material)?;
    let bytes = canonical_json_bytes(&material_value)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Encodes JSON without relying on `serde_json::Map`'s feature-selected
/// iteration order. Type tags and fixed-width length domains keep adjacent
/// values unambiguous; object keys are ordered by their UTF-8 bytes.
fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    encode_canonical_json(value, &mut output)?;
    Ok(output)
}

fn encode_canonical_json(value: &serde_json::Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        serde_json::Value::Null => output.push(0),
        serde_json::Value::Bool(false) => output.push(1),
        serde_json::Value::Bool(true) => output.push(2),
        serde_json::Value::Number(number) => {
            output.push(3);
            encode_length_prefixed(number.to_string().as_bytes(), output)?;
        }
        serde_json::Value::String(string) => {
            output.push(4);
            encode_length_prefixed(string.as_bytes(), output)?;
        }
        serde_json::Value::Array(values) => {
            output.push(5);
            encode_count(values.len(), output)?;
            for value in values {
                encode_canonical_json(value, output)?;
            }
        }
        serde_json::Value::Object(map) => {
            output.push(6);
            encode_count(map.len(), output)?;
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (key, value) in entries {
                encode_length_prefixed(key.as_bytes(), output)?;
                encode_canonical_json(value, output)?;
            }
        }
    }
    Ok(())
}

fn encode_count(count: usize, output: &mut Vec<u8>) -> Result<()> {
    let count = u64::try_from(count)
        .map_err(|_| StoreError::invalid_input("canonical_json", "value count overflow"))?;
    output.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn encode_length_prefixed(bytes: &[u8], output: &mut Vec<u8>) -> Result<()> {
    encode_count(bytes.len(), output)?;
    output.extend_from_slice(bytes);
    Ok(())
}

pub(crate) fn compute_legacy_capability_profile_hash(
    input: &CapabilityProfileInput,
) -> Result<[u8; 32]> {
    let material = LegacyCapabilityHashMaterial {
        format_version: u8::try_from(LEGACY_CAPABILITY_HASH_VERSION)
            .map_err(|_| StoreError::invalid_input("profile_hash", "hash version overflow"))?,
        probe_mode: &input.probe_mode,
        probe_status: &input.probe_status,
        os_build: &input.os_build,
        driver_name: &input.driver_name,
        driver_version: &input.driver_version,
        can_read: input.can_read,
        can_write: input.can_write,
        can_rename_same_volume: input.can_rename_same_volume,
        can_rename_exclusive: input.can_rename_exclusive,
        can_set_birth_time: input.can_set_birth_time,
        can_set_modified_time: input.can_set_modified_time,
        can_use_xattrs: input.can_use_xattrs,
        has_persistent_file_ids: input.has_persistent_file_ids,
        timestamp_granularity_ns: input.timestamp_granularity_ns,
        raw_capabilities: &input.raw_capabilities,
    };
    let bytes = serde_json::to_vec(&material)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

pub(crate) fn validate_capability_profile_hashes(
    connection: &Connection,
    schema_version: i64,
) -> Result<()> {
    if schema_version < 1 {
        return Ok(());
    }
    if schema_version < 4 {
        audit_legacy_capability_profiles(connection)?;
        return Ok(());
    }

    reject_oversized_capability_json(connection)?;
    enforce_total_capability_json_budget(connection)?;
    enforce_capability_profile_count(connection)?;
    let mut statement = connection.prepare(
        "SELECT id, profile_hash_version, probe_mode, probe_status, os_build, \
                mount_session_key, probe_protocol_version, driver_name, driver_version, \
                mount_flags, case_behavior, unicode_behavior, path_encoding_family, \
                path_semantics_version, \
                can_read, can_write, can_rename_same_volume, can_rename_exclusive, \
                can_no_replace, can_sync_directory, can_append_durable, single_writer, \
                can_set_birth_time, can_set_modified_time, can_use_xattrs, \
                can_use_hard_links, can_use_clones, has_persistent_file_ids, \
                timestamp_granularity_ns, maximum_name_bytes, maximum_file_bytes, \
                raw_capabilities_json, profile_hash, volume_id \
         FROM capability_profiles ORDER BY id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let stored = stored_capability_from_row(row)?;
        if stored.profile_hash_version != CAPABILITY_HASH_VERSION {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "capability profile {} uses unsupported hash version {}",
                stored.id, stored.profile_hash_version
            )));
        }
        let observed = row.get::<_, Vec<u8>>(32)?;
        let volume_id = row.get::<_, i64>(33)?;
        let input = stored.to_input(volume_id)?;
        let expected = compute_capability_profile_hash(&input)?;
        if observed.as_slice() != expected {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "capability profile {} canonical hash mismatch",
                stored.id
            )));
        }
    }
    Ok(())
}

pub(crate) fn upgrade_capability_profile_hashes_to_v2(connection: &Connection) -> Result<()> {
    let replacements = audit_legacy_capability_profiles(connection)?;
    for (id, hash) in replacements {
        let changed = connection.execute(
            "UPDATE capability_profiles SET profile_hash = ?2 WHERE id = ?1",
            params![id, hash.as_slice()],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "capability_profile_hash_upgrade",
                id,
            });
        }
    }
    Ok(())
}

#[derive(Debug)]
struct StoredCapabilityProfile {
    id: i64,
    profile_hash_version: i64,
    probe_mode: String,
    probe_status: String,
    os_build: String,
    mount_session_key: Option<String>,
    probe_protocol_version: Option<i64>,
    driver_name: Option<String>,
    driver_version: Option<String>,
    mount_flags: Option<i64>,
    case_behavior: Option<String>,
    unicode_behavior: Option<String>,
    path_encoding_family: Option<String>,
    path_semantics_version: i64,
    can_read: Option<i64>,
    can_write: Option<i64>,
    can_rename_same_volume: Option<i64>,
    can_rename_exclusive: Option<i64>,
    can_no_replace: Option<i64>,
    can_sync_directory: Option<i64>,
    can_append_durable: Option<i64>,
    single_writer: Option<i64>,
    can_set_birth_time: Option<i64>,
    can_set_modified_time: Option<i64>,
    can_use_xattrs: Option<i64>,
    can_use_hard_links: Option<i64>,
    can_use_clones: Option<i64>,
    has_persistent_file_ids: Option<i64>,
    timestamp_granularity_ns: Option<i64>,
    maximum_name_bytes: Option<i64>,
    maximum_file_bytes: Option<i64>,
    raw_capabilities_json: Option<String>,
}

impl StoredCapabilityProfile {
    fn matches_input(&self, input: &CapabilityProfileInput, raw_json: Option<&str>) -> bool {
        self.probe_mode == input.probe_mode
            && self.probe_status == input.probe_status
            && self.os_build == input.os_build
            && self.mount_session_key == input.mount_session_key
            && self.probe_protocol_version == input.probe_protocol_version
            && self.driver_name == input.driver_name
            && self.driver_version == input.driver_version
            && self.mount_flags == input.mount_flags
            && self.case_behavior == input.case_behavior
            && self.unicode_behavior == input.unicode_behavior
            && self.path_encoding_family == input.path_encoding_family
            && self.path_semantics_version == input.path_semantics_version
            && self.can_read == optional_bool_to_integer(input.can_read)
            && self.can_write == optional_bool_to_integer(input.can_write)
            && self.can_rename_same_volume == optional_bool_to_integer(input.can_rename_same_volume)
            && self.can_rename_exclusive == optional_bool_to_integer(input.can_rename_exclusive)
            && self.can_no_replace == optional_bool_to_integer(input.can_no_replace)
            && self.can_sync_directory == optional_bool_to_integer(input.can_sync_directory)
            && self.can_append_durable == optional_bool_to_integer(input.can_append_durable)
            && self.single_writer == optional_bool_to_integer(input.single_writer)
            && self.can_set_birth_time == optional_bool_to_integer(input.can_set_birth_time)
            && self.can_set_modified_time == optional_bool_to_integer(input.can_set_modified_time)
            && self.can_use_xattrs == optional_bool_to_integer(input.can_use_xattrs)
            && self.can_use_hard_links == optional_bool_to_integer(input.can_use_hard_links)
            && self.can_use_clones == optional_bool_to_integer(input.can_use_clones)
            && self.has_persistent_file_ids
                == optional_bool_to_integer(input.has_persistent_file_ids)
            && self.timestamp_granularity_ns == input.timestamp_granularity_ns
            && self.maximum_name_bytes == input.maximum_name_bytes
            && self.maximum_file_bytes == input.maximum_file_bytes
            && self.raw_capabilities_json.as_deref() == raw_json
    }

    fn to_input(&self, volume_id: i64) -> Result<CapabilityProfileInput> {
        Ok(CapabilityProfileInput {
            volume_id,
            probe_mode: self.probe_mode.clone(),
            probe_status: self.probe_status.clone(),
            observed_at_ms: 0,
            os_build: self.os_build.clone(),
            mount_session_key: self.mount_session_key.clone(),
            probe_protocol_version: self.probe_protocol_version,
            driver_name: self.driver_name.clone(),
            driver_version: self.driver_version.clone(),
            mount_flags: self.mount_flags,
            case_behavior: self.case_behavior.clone(),
            unicode_behavior: self.unicode_behavior.clone(),
            path_encoding_family: self.path_encoding_family.clone(),
            path_semantics_version: self.path_semantics_version,
            can_read: integer_to_optional_bool("can_read", self.can_read)?,
            can_write: integer_to_optional_bool("can_write", self.can_write)?,
            can_rename_same_volume: integer_to_optional_bool(
                "can_rename_same_volume",
                self.can_rename_same_volume,
            )?,
            can_rename_exclusive: integer_to_optional_bool(
                "can_rename_exclusive",
                self.can_rename_exclusive,
            )?,
            can_no_replace: integer_to_optional_bool("can_no_replace", self.can_no_replace)?,
            can_sync_directory: integer_to_optional_bool(
                "can_sync_directory",
                self.can_sync_directory,
            )?,
            can_append_durable: integer_to_optional_bool(
                "can_append_durable",
                self.can_append_durable,
            )?,
            single_writer: integer_to_optional_bool("single_writer", self.single_writer)?,
            can_set_birth_time: integer_to_optional_bool(
                "can_set_birth_time",
                self.can_set_birth_time,
            )?,
            can_set_modified_time: integer_to_optional_bool(
                "can_set_modified_time",
                self.can_set_modified_time,
            )?,
            can_use_xattrs: integer_to_optional_bool("can_use_xattrs", self.can_use_xattrs)?,
            can_use_hard_links: integer_to_optional_bool(
                "can_use_hard_links",
                self.can_use_hard_links,
            )?,
            can_use_clones: integer_to_optional_bool("can_use_clones", self.can_use_clones)?,
            has_persistent_file_ids: integer_to_optional_bool(
                "has_persistent_file_ids",
                self.has_persistent_file_ids,
            )?,
            timestamp_granularity_ns: self.timestamp_granularity_ns,
            maximum_name_bytes: self.maximum_name_bytes,
            maximum_file_bytes: self.maximum_file_bytes,
            raw_capabilities: parse_raw_capabilities(self.raw_capabilities_json.as_deref())?,
        })
    }
}

fn stored_capability_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredCapabilityProfile> {
    Ok(StoredCapabilityProfile {
        id: row.get(0)?,
        profile_hash_version: row.get(1)?,
        probe_mode: row.get(2)?,
        probe_status: row.get(3)?,
        os_build: row.get(4)?,
        mount_session_key: row.get(5)?,
        probe_protocol_version: row.get(6)?,
        driver_name: row.get(7)?,
        driver_version: row.get(8)?,
        mount_flags: row.get(9)?,
        case_behavior: row.get(10)?,
        unicode_behavior: row.get(11)?,
        path_encoding_family: row.get(12)?,
        path_semantics_version: row.get(13)?,
        can_read: row.get(14)?,
        can_write: row.get(15)?,
        can_rename_same_volume: row.get(16)?,
        can_rename_exclusive: row.get(17)?,
        can_no_replace: row.get(18)?,
        can_sync_directory: row.get(19)?,
        can_append_durable: row.get(20)?,
        single_writer: row.get(21)?,
        can_set_birth_time: row.get(22)?,
        can_set_modified_time: row.get(23)?,
        can_use_xattrs: row.get(24)?,
        can_use_hard_links: row.get(25)?,
        can_use_clones: row.get(26)?,
        has_persistent_file_ids: row.get(27)?,
        timestamp_granularity_ns: row.get(28)?,
        maximum_name_bytes: row.get(29)?,
        maximum_file_bytes: row.get(30)?,
        raw_capabilities_json: row.get(31)?,
    })
}

fn audit_legacy_capability_profiles(connection: &Connection) -> Result<Vec<(i64, [u8; 32])>> {
    reject_oversized_capability_json(connection)?;
    enforce_total_capability_json_budget(connection)?;
    enforce_capability_profile_count(connection)?;
    let mut statement = connection.prepare(
        "SELECT id, profile_hash, volume_id, probe_mode, probe_status, observed_at_ms, os_build, \
                driver_name, driver_version, can_read, can_write, \
                can_rename_same_volume, can_rename_exclusive, can_set_birth_time, \
                can_set_modified_time, can_use_xattrs, has_persistent_file_ids, \
                timestamp_granularity_ns, raw_capabilities_json \
         FROM capability_profiles ORDER BY id",
    )?;
    let mut rows = statement.query([])?;
    let mut replacements = Vec::new();
    while let Some(row) = rows.next()? {
        let id = row.get::<_, i64>(0)?;
        let observed = row.get::<_, Vec<u8>>(1)?;
        let raw_json = row.get::<_, Option<String>>(18)?;
        let input = CapabilityProfileInput {
            volume_id: row.get(2)?,
            probe_mode: row.get(3)?,
            probe_status: row.get(4)?,
            observed_at_ms: row.get(5)?,
            os_build: row.get(6)?,
            mount_session_key: None,
            probe_protocol_version: None,
            driver_name: row.get(7)?,
            driver_version: row.get(8)?,
            mount_flags: None,
            case_behavior: None,
            unicode_behavior: None,
            path_encoding_family: None,
            path_semantics_version: 1,
            can_read: integer_to_optional_bool("can_read", row.get(9)?)?,
            can_write: integer_to_optional_bool("can_write", row.get(10)?)?,
            can_rename_same_volume: integer_to_optional_bool(
                "can_rename_same_volume",
                row.get(11)?,
            )?,
            can_rename_exclusive: integer_to_optional_bool("can_rename_exclusive", row.get(12)?)?,
            can_no_replace: None,
            can_sync_directory: None,
            can_append_durable: None,
            single_writer: None,
            can_set_birth_time: integer_to_optional_bool("can_set_birth_time", row.get(13)?)?,
            can_set_modified_time: integer_to_optional_bool("can_set_modified_time", row.get(14)?)?,
            can_use_xattrs: integer_to_optional_bool("can_use_xattrs", row.get(15)?)?,
            can_use_hard_links: None,
            can_use_clones: None,
            has_persistent_file_ids: integer_to_optional_bool(
                "has_persistent_file_ids",
                row.get(16)?,
            )?,
            timestamp_granularity_ns: row.get(17)?,
            maximum_name_bytes: None,
            maximum_file_bytes: None,
            raw_capabilities: parse_raw_capabilities(raw_json.as_deref())?,
        };
        let legacy = compute_legacy_capability_profile_hash(&input)?;
        if observed.as_slice() != legacy {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "capability profile {id} legacy hash mismatch"
            )));
        }
        replacements.push((id, compute_capability_profile_hash(&input)?));
    }
    Ok(replacements)
}

fn enforce_total_capability_json_budget(connection: &Connection) -> Result<()> {
    const MAX_TOTAL_CAPABILITY_JSON_BYTES: i64 = 64 * 1024 * 1024;
    let total = connection.query_row(
        "SELECT COALESCE(sum(length(CAST(raw_capabilities_json AS BLOB))), 0) \
         FROM capability_profiles",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    if total > MAX_TOTAL_CAPABILITY_JSON_BYTES {
        return Err(StoreError::MigrationHistoryMismatch(format!(
            "capability profile JSON total {total} exceeds {MAX_TOTAL_CAPABILITY_JSON_BYTES} bytes"
        )));
    }
    Ok(())
}

fn reject_oversized_capability_json(connection: &Connection) -> Result<()> {
    let oversized = connection.query_row(
        "SELECT EXISTS( \
             SELECT 1 FROM capability_profiles \
             WHERE raw_capabilities_json IS NOT NULL \
               AND length(CAST(raw_capabilities_json AS BLOB)) > ?1 \
         )",
        [i64::try_from(MAX_JSON_BYTES)
            .map_err(|_| StoreError::invalid_input("raw_capabilities", "size overflow"))?],
        |row| row.get::<_, bool>(0),
    )?;
    if oversized {
        return Err(StoreError::MigrationHistoryMismatch(
            "capability profile JSON exceeds the bounded validation limit".into(),
        ));
    }
    Ok(())
}

fn enforce_capability_profile_count(connection: &Connection) -> Result<()> {
    let count = connection.query_row("SELECT count(*) FROM capability_profiles", [], |row| {
        row.get::<_, i64>(0)
    })?;
    if count > MAX_CAPABILITY_PROFILES {
        return Err(StoreError::MigrationHistoryMismatch(format!(
            "capability profile count {count} exceeds {MAX_CAPABILITY_PROFILES}"
        )));
    }
    Ok(())
}

fn parse_raw_capabilities(value: Option<&str>) -> Result<Option<serde_json::Value>> {
    value
        .map(serde_json::from_str)
        .transpose()
        .map_err(StoreError::from)
}

fn integer_to_optional_bool(field: &'static str, value: Option<i64>) -> Result<Option<bool>> {
    match value {
        None => Ok(None),
        Some(0) => Ok(Some(false)),
        Some(1) => Ok(Some(true)),
        Some(value) => Err(StoreError::invalid_input(
            field,
            format!("stored Boolean has invalid integer value {value}"),
        )),
    }
}

fn scoped_storage_path_key(input: &MediaFileInput) -> Result<[u8; 32]> {
    require_positive("volume_id", input.volume_id)?;
    require_positive("capability_profile_id", input.capability_profile_id)?;
    require_positive("path_semantics_version", input.path_semantics_version)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying-media-path-storage-key\0v1\0");
    hasher.update(&input.volume_id.to_le_bytes());
    hasher.update(&input.capability_profile_id.to_le_bytes());
    hasher.update(&input.path_semantics_version.to_le_bytes());
    let key_length = u64::try_from(input.path_key.as_bytes().len())
        .map_err(|_| StoreError::invalid_input("path_key", "path key length overflow"))?;
    hasher.update(&key_length.to_le_bytes());
    hasher.update(input.path_key.as_bytes());
    Ok(*hasher.finalize().as_bytes())
}

fn hex_hash(hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(hash.len() * 2);
    for byte in hash {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
