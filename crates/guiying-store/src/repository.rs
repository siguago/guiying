use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::error::{Result, StoreError};
use crate::model::{
    BeginCaptureTimeAnalysisInput, BeginExactGroupInput, BeginMetadataReportInput,
    BeginTimeSessionInput, CapabilityProfileInput, CaptureTimeAnalysisManifestPlan,
    CaptureTimeAnalysisSourceInput, CaptureTimeCandidateInput, CaptureTimeDecision,
    CaptureTimeMemberAssessmentInput, CaptureTimeObservationInput,
    CaptureTimeObservationInterpretationInput, CaptureTimePolicyIssueInput,
    CaptureTimeRecommendationInput, CoreDirectoryObservationInput, CoreFileObservationInput,
    CoreSessionId, CoreSessionInput, CoverageOutcomeInput, CoverageStatus, ExactGroupKey,
    ExactGroupManifestMember, ExactGroupMemberInput, ExactVerificationEdgeInput,
    FileTimestampParts, FreshFingerprintInput, FreshFingerprintKind, ManifestDigest,
    MediaFileInput, MetadataContainerLocator, MetadataExtractionIssueInput, MetadataFieldInput,
    MetadataReportManifestPlan, MetadataSourceRevalidationInput, MountSessionKey,
    NamespaceProfileInput, NewBoundScanRun, NewScanIssue, NewScanJob, NewScanReport, NewScanRun,
    NewScopedScanJob, ObservationInput, RecordTimeGroupOutcomeInput, RunEvidenceGuard,
    ScanCheckpointInput, ScanStage, SourceSignature, TimeEvidenceGuard, TimeEvidenceManifestDigest,
    TimeExactFingerprintMaterial, TimeLineageKey, TimeSessionOutcome, TimeSourceKey,
    TimeSourceKeyMaterial, VerifiedExactGroup, VolumeInput, MAX_IDENTIFIER_BYTES, MAX_JSON_BYTES,
    MAX_OPAQUE_BLOB_BYTES, MAX_PATH_BYTES, MAX_TEXT_BYTES, MAX_TIME_EVIDENCE_BATCH,
    MAX_TIME_EVIDENCE_PAGE_BYTES,
};

const MAX_V5_WRITE_BATCH: usize = 128;

/// Repository operations scoped to one short SQLite write transaction.
pub struct RepositoryTx<'transaction> {
    transaction: &'transaction Transaction<'transaction>,
    store_instance_key: [u8; 32],
    poisoned: bool,
    bound_core_sessions: Vec<(i64, [u8; 32])>,
}

impl<'transaction> RepositoryTx<'transaction> {
    #[cfg(test)]
    pub(crate) fn new(transaction: &'transaction Transaction<'transaction>) -> Self {
        Self {
            transaction,
            store_instance_key: [0; 32],
            poisoned: false,
            bound_core_sessions: Vec::new(),
        }
    }

    pub(crate) fn new_bound(
        transaction: &'transaction Transaction<'transaction>,
        store_instance_key: [u8; 32],
    ) -> Self {
        Self {
            transaction,
            store_instance_key,
            poisoned: false,
            bound_core_sessions: Vec::new(),
        }
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) fn take_bound_core_sessions(&mut self) -> Vec<(i64, [u8; 32])> {
        std::mem::take(&mut self.bound_core_sessions)
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

    pub fn create_scan_job(&mut self, _input: &NewScanJob) -> Result<i64> {
        self.run_mutator(|_| {
            Err(StoreError::LegacyEvidenceApiDisabled {
                api: "create_scan_job",
            })
        })
    }

    pub fn create_scan_run(&mut self, _input: &NewScanRun) -> Result<i64> {
        self.run_mutator(|_| {
            Err(StoreError::LegacyEvidenceApiDisabled {
                api: "create_scan_run",
            })
        })
    }

    pub fn upsert_media_file(&mut self, _input: &MediaFileInput) -> Result<i64> {
        self.run_mutator(|_| {
            Err(StoreError::LegacyEvidenceApiDisabled {
                api: "upsert_media_file",
            })
        })
    }

    pub fn record_scan_issue(&mut self, _input: &NewScanIssue) -> Result<i64> {
        self.run_mutator(|_| {
            Err(StoreError::LegacyEvidenceApiDisabled {
                api: "record_scan_issue",
            })
        })
    }

    pub fn record_bound_scan_issue(
        &mut self,
        guard: &RunEvidenceGuard,
        input: &NewScanIssue,
    ) -> Result<i64> {
        self.run_mutator(|repository| repository.record_bound_scan_issue_impl(guard, input))
    }

    pub fn write_scan_report(&mut self, _input: &NewScanReport) -> Result<i64> {
        self.run_mutator(|_| {
            Err(StoreError::LegacyEvidenceApiDisabled {
                api: "write_scan_report",
            })
        })
    }

    pub fn update_scan_progress(
        &mut self,
        _scan_run_id: i64,
        _discovered_count: i64,
        _fingerprinted_count: i64,
        _error_count: i64,
        _logical_bytes_seen: i64,
        _heartbeat_at_ms: i64,
    ) -> Result<()> {
        self.run_mutator(|_| {
            Err(StoreError::LegacyEvidenceApiDisabled {
                api: "update_scan_progress",
            })
        })
    }

    pub fn update_bound_scan_progress(
        &mut self,
        guard: &RunEvidenceGuard,
        discovered_count: i64,
        fingerprinted_count: i64,
        error_count: i64,
        logical_bytes_seen: i64,
        heartbeat_at_ms: i64,
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.update_bound_scan_progress_impl(
                guard,
                discovered_count,
                fingerprinted_count,
                error_count,
                logical_bytes_seen,
                heartbeat_at_ms,
            )
        })
    }

    pub fn save_scan_checkpoint(&mut self, _input: &ScanCheckpointInput) -> Result<i64> {
        self.run_mutator(|_| {
            Err(StoreError::LegacyEvidenceApiDisabled {
                api: "save_scan_checkpoint",
            })
        })
    }

    pub fn save_bound_scan_checkpoint(
        &mut self,
        guard: &RunEvidenceGuard,
        input: &ScanCheckpointInput,
    ) -> Result<i64> {
        self.run_mutator(|repository| repository.save_bound_scan_checkpoint_impl(guard, input))
    }

    pub fn register_namespace_profile(&mut self, input: &NamespaceProfileInput) -> Result<i64> {
        self.run_mutator(|repository| repository.register_namespace_profile_impl(input))
    }

    pub fn create_scoped_scan_job(&mut self, input: &NewScopedScanJob) -> Result<i64> {
        self.run_mutator(|repository| repository.create_scoped_scan_job_impl(input))
    }

    pub fn create_bound_scan_run(&mut self, input: &NewBoundScanRun) -> Result<i64> {
        self.run_mutator(|repository| repository.create_bound_scan_run_impl(input))
    }

    pub fn record_observation_batch(
        &mut self,
        guard: &RunEvidenceGuard,
        inputs: &[ObservationInput],
    ) -> Result<Vec<i64>> {
        self.run_mutator(|repository| repository.record_observation_batch_impl(guard, inputs))
    }

    /// Binds one authenticated, process-local core scanner to the current
    /// volume-backed run. The stored id is evidence, never durable read
    /// authority after process restart.
    pub fn bind_core_session(
        &mut self,
        guard: &RunEvidenceGuard,
        input: &CoreSessionInput,
    ) -> Result<()> {
        self.run_mutator(|repository| repository.bind_core_session_impl(guard, input))
    }

    /// Atomically records immutable media observations and their opaque core
    /// tickets. A ticket failure rolls back the matching observation too.
    pub fn record_core_observation_batch(
        &mut self,
        guard: &RunEvidenceGuard,
        core_session_id: &CoreSessionId,
        inputs: &[CoreFileObservationInput],
    ) -> Result<Vec<i64>> {
        self.run_mutator(|repository| {
            repository.record_core_observation_batch_impl(guard, core_session_id, inputs)
        })
    }

    /// Records authenticated directory tickets for later volume-bracketed
    /// coverage replay. Opaque ticket bytes are never interpreted as paths.
    pub fn record_core_directory_batch(
        &mut self,
        guard: &RunEvidenceGuard,
        core_session_id: &CoreSessionId,
        inputs: &[CoreDirectoryObservationInput],
    ) -> Result<Vec<i64>> {
        self.run_mutator(|repository| {
            repository.record_core_directory_batch_impl(guard, core_session_id, inputs)
        })
    }

    /// Persists the terminal result of core replay plus volume verification.
    /// Only `Complete` evidence can later unlock exact-stage sealing.
    pub fn record_core_coverage(
        &mut self,
        guard: &RunEvidenceGuard,
        core_session_id: &CoreSessionId,
        input: &CoverageOutcomeInput,
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.record_core_coverage_impl(guard, core_session_id, input)
        })
    }

    pub fn seal_scan_stage(
        &mut self,
        guard: &RunEvidenceGuard,
        stage: ScanStage,
        item_count: i64,
        logical_bytes: i64,
        sealed_at_ms: i64,
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.seal_scan_stage_impl(guard, stage, item_count, logical_bytes, sealed_at_ms)
        })
    }

    pub fn record_fingerprint_fresh_batch(
        &mut self,
        guard: &RunEvidenceGuard,
        inputs: &[FreshFingerprintInput],
    ) -> Result<Vec<i64>> {
        self.run_mutator(|repository| repository.record_fingerprint_fresh_batch_impl(guard, inputs))
    }

    pub fn begin_exact_group(
        &mut self,
        guard: &RunEvidenceGuard,
        input: &BeginExactGroupInput,
    ) -> Result<i64> {
        self.run_mutator(|repository| repository.begin_exact_group_impl(guard, input))
    }

    pub fn append_exact_group_members(
        &mut self,
        guard: &RunEvidenceGuard,
        build_id: i64,
        inputs: &[ExactGroupMemberInput],
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.append_exact_group_members_impl(guard, build_id, inputs)
        })
    }

    pub fn append_exact_verification_edges(
        &mut self,
        guard: &RunEvidenceGuard,
        build_id: i64,
        inputs: &[ExactVerificationEdgeInput],
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.append_exact_verification_edges_impl(guard, build_id, inputs)
        })
    }

    pub fn finalize_exact_group(
        &mut self,
        guard: &RunEvidenceGuard,
        build_id: i64,
        finalized_at_ms: i64,
    ) -> Result<VerifiedExactGroup> {
        self.run_mutator(|repository| {
            repository.finalize_exact_group_impl(guard, build_id, finalized_at_ms)
        })
    }

    pub fn abandon_exact_group_draft(
        &mut self,
        guard: &RunEvidenceGuard,
        build_id: i64,
        abandoned_at_ms: i64,
        reason_code: &str,
        reason_message: Option<&str>,
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.abandon_exact_group_draft_impl(
                guard,
                build_id,
                abandoned_at_ms,
                reason_code,
                reason_message,
            )
        })
    }

    pub fn abandon_group_drafts_for_terminal_run(
        &mut self,
        scan_run_id: i64,
        now_ms: i64,
    ) -> Result<u64> {
        self.run_mutator(|repository| {
            repository.abandon_group_drafts_for_terminal_run_impl(scan_run_id, now_ms)
        })
    }

    pub fn begin_time_session(
        &mut self,
        guard: &TimeEvidenceGuard,
        input: &BeginTimeSessionInput,
    ) -> Result<i64> {
        self.run_mutator(|repository| repository.begin_time_session_impl(guard, input))
    }

    pub fn finalize_time_session(
        &mut self,
        guard: &TimeEvidenceGuard,
        time_session_id: i64,
        outcome: TimeSessionOutcome,
        finalized_at_ms: i64,
    ) -> Result<TimeEvidenceManifestDigest> {
        self.run_mutator(|repository| {
            repository.finalize_time_session_impl(guard, time_session_id, outcome, finalized_at_ms)
        })
    }

    pub fn record_time_group_non_evidence_outcome(
        &mut self,
        guard: &TimeEvidenceGuard,
        input: &RecordTimeGroupOutcomeInput,
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.record_time_group_non_evidence_outcome_impl(guard, input)
        })
    }

    pub fn abandon_time_session(
        &mut self,
        guard: &TimeEvidenceGuard,
        time_session_id: i64,
        abandoned_at_ms: i64,
        reason_code: &str,
        reason_message: Option<&str>,
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.abandon_time_session_impl(
                guard,
                time_session_id,
                abandoned_at_ms,
                reason_code,
                reason_message,
            )
        })
    }

    pub fn begin_metadata_report(
        &mut self,
        guard: &TimeEvidenceGuard,
        input: &BeginMetadataReportInput,
    ) -> Result<i64> {
        self.run_mutator(|repository| repository.begin_metadata_report_impl(guard, input))
    }

    pub fn append_metadata_fields_batch(
        &mut self,
        guard: &TimeEvidenceGuard,
        report_id: i64,
        inputs: &[MetadataFieldInput],
    ) -> Result<Vec<i64>> {
        self.run_mutator(|repository| {
            repository.append_metadata_fields_batch_impl(guard, report_id, inputs)
        })
    }

    pub fn append_metadata_issues_batch(
        &mut self,
        guard: &TimeEvidenceGuard,
        report_id: i64,
        inputs: &[MetadataExtractionIssueInput],
    ) -> Result<Vec<i64>> {
        self.run_mutator(|repository| {
            repository.append_metadata_issues_batch_impl(guard, report_id, inputs)
        })
    }

    pub fn seal_metadata_report(
        &mut self,
        guard: &TimeEvidenceGuard,
        report_id: i64,
        revalidation: &MetadataSourceRevalidationInput,
        finalized_at_ms: i64,
    ) -> Result<TimeEvidenceManifestDigest> {
        self.run_mutator(|repository| {
            repository.seal_metadata_report_impl(guard, report_id, revalidation, finalized_at_ms)
        })
    }

    pub fn abandon_metadata_report(
        &mut self,
        guard: &TimeEvidenceGuard,
        report_id: i64,
        abandoned_at_ms: i64,
        reason_code: &str,
        reason_message: Option<&str>,
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.abandon_metadata_report_impl(
                guard,
                report_id,
                abandoned_at_ms,
                reason_code,
                reason_message,
            )
        })
    }

    pub fn begin_capture_time_analysis(
        &mut self,
        guard: &TimeEvidenceGuard,
        input: &BeginCaptureTimeAnalysisInput,
    ) -> Result<i64> {
        self.run_mutator(|repository| repository.begin_capture_time_analysis_impl(guard, input))
    }

    pub fn append_capture_time_sources_batch(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        inputs: &[CaptureTimeAnalysisSourceInput],
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.append_capture_time_sources_batch_impl(guard, analysis_build_id, inputs)
        })
    }

    pub fn append_capture_time_observations_batch(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        inputs: &[CaptureTimeObservationInput],
    ) -> Result<Vec<i64>> {
        self.run_mutator(|repository| {
            repository.append_capture_time_observations_batch_impl(guard, analysis_build_id, inputs)
        })
    }

    pub fn append_capture_time_candidates_batch(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        inputs: &[CaptureTimeCandidateInput],
    ) -> Result<Vec<i64>> {
        self.run_mutator(|repository| {
            repository.append_capture_time_candidates_batch_impl(guard, analysis_build_id, inputs)
        })
    }

    pub fn append_capture_time_policy_issues_batch(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        inputs: &[CaptureTimePolicyIssueInput],
    ) -> Result<Vec<i64>> {
        self.run_mutator(|repository| {
            repository.append_capture_time_policy_issues_batch_impl(
                guard,
                analysis_build_id,
                inputs,
            )
        })
    }

    pub fn append_capture_time_members_batch(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        inputs: &[CaptureTimeMemberAssessmentInput],
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.append_capture_time_members_batch_impl(guard, analysis_build_id, inputs)
        })
    }

    pub fn append_capture_time_recommendation(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        input: &CaptureTimeRecommendationInput,
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.append_capture_time_recommendation_impl(guard, analysis_build_id, input)
        })
    }

    pub fn seal_capture_time_analysis(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        decision: CaptureTimeDecision,
        selected_candidate_ordinal: Option<i64>,
        finalized_at_ms: i64,
    ) -> Result<TimeEvidenceManifestDigest> {
        self.run_mutator(|repository| {
            repository.seal_capture_time_analysis_impl(
                guard,
                analysis_build_id,
                decision,
                selected_candidate_ordinal,
                finalized_at_ms,
            )
        })
    }

    pub fn abandon_capture_time_analysis(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        abandoned_at_ms: i64,
        reason_code: &str,
        reason_message: Option<&str>,
    ) -> Result<()> {
        self.run_mutator(|repository| {
            repository.abandon_capture_time_analysis_impl(
                guard,
                analysis_build_id,
                abandoned_at_ms,
                reason_code,
                reason_message,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transition_scan_job_and_run(
        &mut self,
        _scan_job_id: i64,
        _scan_run_id: i64,
        _expected_capability_profile_id: i64,
        _expected_mount_session_key: &str,
        _expected_job_state: &str,
        _expected_job_version: i64,
        _expected_run_state: &str,
        _expected_run_version: i64,
        _target_job_state: &str,
        _target_run_state: &str,
        _now_ms: i64,
        _last_error: Option<(&str, &str)>,
    ) -> Result<(i64, i64)> {
        self.run_mutator(|_| {
            Err(StoreError::LegacyEvidenceApiDisabled {
                api: "transition_scan_job_and_run",
            })
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transition_bound_scan_job_and_run(
        &mut self,
        guard: &RunEvidenceGuard,
        scan_job_id: i64,
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
            repository.transition_bound_scan_job_and_run_impl(
                guard,
                scan_job_id,
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

    // These fail-closed implementation slots keep downstream crates buildable
    // while the v7 SQL contract is wired below. They are replaced in-place by
    // the transactional implementations before this API is exported.
    fn begin_time_session_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        input: &BeginTimeSessionInput,
    ) -> Result<i64> {
        let context = self.validate_time_evidence_guard(guard)?;
        let earliest_created_at_ms = self
            .transaction
            .query_row(
                "SELECT max(core.bound_at_ms, exact_seal.sealed_at_ms) \
                 FROM scan_core_sessions AS core \
                 JOIN scan_stage_seals AS exact_seal \
                   ON exact_seal.scan_run_id = core.scan_run_id \
                  AND exact_seal.volume_id = core.volume_id \
                  AND exact_seal.stage = 'exact_verification' \
                 WHERE core.scan_run_id = ?1 AND core.volume_id = ?2 \
                   AND core.core_session_id = ?3",
                params![
                    guard.run().scan_run_id,
                    context.volume_id,
                    guard.core_session_id().as_bytes().as_slice(),
                ],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StoreError::ConcurrencyConflict {
                    entity: "time_session_chronology_guard",
                    id: guard.run().scan_run_id,
                },
                other => StoreError::from(other),
            })?;
        if input.created_at_ms < earliest_created_at_ms {
            return Err(StoreError::invalid_input(
                "created_at_ms",
                "time session creation predates its bound core or exact-verification seal",
            ));
        }
        let (group_count, manifest) =
            recompute_time_session_scope_manifest(self.transaction, guard.run().scan_run_id)?;
        if group_count != input.expected_group_count || manifest != input.expected_manifest_digest {
            return Err(StoreError::invalid_input(
                "time_session_manifest",
                "caller scope does not match the sealed verified exact-group set",
            ));
        }
        if let Some((id, matches)) = self
            .transaction
            .query_row(
                "SELECT id, time_session_key = ?2 AND core_session_id = ?3 \
                     AND expected_group_count = ?4 AND max_total_read_bytes = ?5 \
                     AND max_probe_count_per_group = ?6 \
                     AND max_report_total_bytes_read = ?7 \
                     AND max_report_read_operations = ?8 \
                     AND max_report_retained_field_bytes = ?9 \
                     AND max_report_fields = ?10 AND max_report_issues = ?11 \
                     AND expected_manifest_digest = ?12 AND created_at_ms = ?13 \
                     AND volume_id = ?14 AND schema_contract_version = 1 \
                     AND scope_manifest_version = 1 AND outcome_manifest_version = 2 \
                 FROM scan_time_sessions WHERE scan_run_id = ?1",
                params![
                    guard.run().scan_run_id,
                    input.time_session_key.as_bytes().as_slice(),
                    guard.core_session_id().as_bytes().as_slice(),
                    input.expected_group_count,
                    input.budget.max_total_read_bytes,
                    input.budget.max_probe_count_per_group,
                    input.budget.max_report_total_bytes_read,
                    input.budget.max_report_read_operations,
                    input.budget.max_report_retained_field_bytes,
                    input.budget.max_report_fields,
                    input.budget.max_report_issues,
                    input.expected_manifest_digest.as_bytes().as_slice(),
                    input.created_at_ms,
                    context.volume_id,
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
        {
            return if matches {
                Ok(id)
            } else {
                Err(StoreError::IdempotencyConflict {
                    entity: "time_session",
                    key: guard.run().scan_run_id.to_string(),
                })
            };
        }
        self.transaction.execute(
            "INSERT INTO scan_time_sessions ( \
                 time_session_key, volume_id, scan_run_id, core_session_id, \
                 schema_contract_version, expected_group_count, max_total_read_bytes, \
                 max_probe_count_per_group, max_report_total_bytes_read, \
                 max_report_read_operations, max_report_retained_field_bytes, \
                 max_report_fields, max_report_issues, expected_manifest_digest, created_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                input.time_session_key.as_bytes().as_slice(),
                context.volume_id,
                guard.run().scan_run_id,
                guard.core_session_id().as_bytes().as_slice(),
                input.expected_group_count,
                input.budget.max_total_read_bytes,
                input.budget.max_probe_count_per_group,
                input.budget.max_report_total_bytes_read,
                input.budget.max_report_read_operations,
                input.budget.max_report_retained_field_bytes,
                input.budget.max_report_fields,
                input.budget.max_report_issues,
                input.expected_manifest_digest.as_bytes().as_slice(),
                input.created_at_ms,
            ],
        )?;
        Ok(self.transaction.last_insert_rowid())
    }

    fn finalize_time_session_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        time_session_id: i64,
        outcome: TimeSessionOutcome,
        finalized_at_ms: i64,
    ) -> Result<TimeEvidenceManifestDigest> {
        self.validate_time_evidence_guard(guard)?;
        require_positive("time_session_id", time_session_id)?;
        require_nonnegative("finalized_at_ms", finalized_at_ms)?;
        let session = self.transaction.query_row(
            "SELECT scan_run_id, core_session_id, state, expected_group_count, \
                    evidence_group_count, unavailable_group_count, failed_group_count, \
                    max_total_read_bytes, expected_manifest_digest, sealed_manifest_digest, \
                    sealed_outcome_manifest_digest, created_at_ms, finalized_at_ms \
             FROM scan_time_sessions WHERE id = ?1",
            [time_session_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                ))
            },
        )?;
        if session.0 != guard.run().scan_run_id
            || session.1.as_slice() != guard.core_session_id().as_bytes()
        {
            return Err(StoreError::ConcurrencyConflict {
                entity: "time_session_guard",
                id: time_session_id,
            });
        }
        let expected_scope =
            TimeEvidenceManifestDigest::from_runtime_evidence(fixed_32_from_sql(session.8, 8)?);
        let (scope_count, observed_scope) =
            recompute_time_session_scope_manifest(self.transaction, session.0)?;
        if scope_count != session.3 || observed_scope != expected_scope {
            return Err(StoreError::invalid_input(
                "time_session_scope_manifest",
                "the current verified exact-group scope differs from the frozen session scope",
            ));
        }
        let open_child_count = self.transaction.query_row(
            "SELECT \
                 (SELECT count(*) FROM metadata_extraction_reports \
                  WHERE time_session_id = ?1 AND state = 'draft') + \
                 (SELECT count(*) FROM capture_time_analysis_builds \
                  WHERE time_session_id = ?1 AND state = 'draft')",
            [time_session_id],
            |row| row.get::<_, i64>(0),
        )?;
        if open_child_count != 0 {
            return Err(StoreError::invalid_input(
                "time_session_children",
                "all metadata reports and analyses must be terminal before session finalization",
            ));
        }
        let mut total_report_read_bytes = 0_i64;
        let mut statement = self.transaction.prepare(
            "SELECT usage_bytes_read FROM metadata_extraction_reports \
             WHERE time_session_id = ?1 ORDER BY id",
        )?;
        let mut rows = statement.query([time_session_id])?;
        while let Some(row) = rows.next()? {
            let bytes = row.get::<_, i64>(0)?;
            if bytes < 0 {
                return Err(StoreError::invalid_input(
                    "metadata_report_usage",
                    "stored report read usage is negative",
                ));
            }
            total_report_read_bytes =
                total_report_read_bytes.checked_add(bytes).ok_or_else(|| {
                    StoreError::invalid_input("max_total_read_bytes", "read usage sum overflow")
                })?;
        }
        if total_report_read_bytes > session.7 / 2 {
            return Err(StoreError::invalid_input(
                "max_total_read_bytes",
                "two pinned extraction passes exceed the frozen session read budget",
            ));
        }
        let counts = self.transaction.query_row(
            "SELECT \
                 sum(CASE WHEN outcome = 'evidence' THEN 1 ELSE 0 END), \
                 sum(CASE WHEN outcome = 'unavailable' THEN 1 ELSE 0 END), \
                 sum(CASE WHEN outcome = 'failed' THEN 1 ELSE 0 END), count(*) \
             FROM capture_time_group_outcomes WHERE time_session_id = ?1",
            [time_session_id],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        if counts.3 > session.3
            || (outcome == TimeSessionOutcome::Complete && counts.3 != session.3)
        {
            return Err(StoreError::invalid_input(
                "time_session_outcomes",
                "complete sessions require one outcome per frozen group and partial sessions cannot exceed scope",
            ));
        }
        let missing_sealed_analysis_outcome = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM capture_time_analysis_builds AS build \
                 WHERE build.time_session_id = ?1 AND build.state = 'sealed' \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM capture_time_group_outcomes AS group_outcome \
                       WHERE group_outcome.time_session_id = build.time_session_id \
                         AND group_outcome.exact_group_build_id = build.exact_group_build_id \
                         AND group_outcome.outcome = 'evidence' \
                         AND group_outcome.analysis_build_id = build.id \
                   ) \
             )",
            [time_session_id],
            |row| row.get::<_, bool>(0),
        )?;
        if missing_sealed_analysis_outcome {
            return Err(StoreError::invalid_input(
                "time_session_outcomes",
                "a sealed analysis is missing its immutable evidence outcome",
            ));
        }
        let latest_child_ms = self.transaction.query_row(
            "SELECT max(value) FROM ( \
                 SELECT created_at_ms AS value FROM scan_time_sessions WHERE id = ?1 \
                 UNION ALL SELECT finalized_at_ms FROM metadata_extraction_reports \
                     WHERE time_session_id = ?1 AND finalized_at_ms IS NOT NULL \
                 UNION ALL SELECT finalized_at_ms FROM capture_time_analysis_builds \
                     WHERE time_session_id = ?1 AND finalized_at_ms IS NOT NULL \
                 UNION ALL SELECT created_at_ms FROM capture_time_group_outcomes \
                     WHERE time_session_id = ?1 \
             )",
            [time_session_id],
            |row| row.get::<_, i64>(0),
        )?;
        if finalized_at_ms < latest_child_ms {
            return Err(StoreError::invalid_input(
                "finalized_at_ms",
                "session finalization predates retained terminal evidence",
            ));
        }
        let outcome_manifest = recompute_time_session_outcome_manifest_for_terminal(
            self.transaction,
            time_session_id,
            outcome.as_storage_str(),
            finalized_at_ms,
        )?;
        if matches!(session.2.as_str(), "complete" | "partial") {
            return if session.2 == outcome.as_storage_str()
                && session.4 == Some(counts.0)
                && session.5 == Some(counts.1)
                && session.6 == Some(counts.2)
                && session
                    .9
                    .as_deref()
                    .is_some_and(|value| value == observed_scope.as_bytes())
                && session
                    .10
                    .as_deref()
                    .is_some_and(|value| value == outcome_manifest.as_bytes())
                && session.12 == Some(finalized_at_ms)
            {
                Ok(outcome_manifest)
            } else {
                Err(StoreError::IdempotencyConflict {
                    entity: "time_session_finalization",
                    key: time_session_id.to_string(),
                })
            };
        }
        if session.2 != "draft" || finalized_at_ms < session.11 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "draft_time_session",
                id: time_session_id,
            });
        }
        let changed = self.transaction.execute(
            "UPDATE scan_time_sessions \
             SET state = ?2, evidence_group_count = ?3, unavailable_group_count = ?4, \
                 failed_group_count = ?5, sealed_manifest_digest = ?6, \
                 sealed_outcome_manifest_digest = ?7, finalized_at_ms = ?8 \
             WHERE id = ?1 AND state = 'draft'",
            params![
                time_session_id,
                outcome.as_storage_str(),
                counts.0,
                counts.1,
                counts.2,
                observed_scope.as_bytes().as_slice(),
                outcome_manifest.as_bytes().as_slice(),
                finalized_at_ms,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "time_session_finalization",
                id: time_session_id,
            });
        }
        Ok(outcome_manifest)
    }

    fn record_time_group_non_evidence_outcome_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        input: &RecordTimeGroupOutcomeInput,
    ) -> Result<()> {
        let context = self.validate_time_evidence_guard(guard)?;
        let session_matches = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM scan_time_sessions AS session \
                 JOIN exact_group_builds AS exact_build \
                   ON exact_build.id = ?2 AND exact_build.volume_id = session.volume_id \
                  AND exact_build.scan_run_id = session.scan_run_id \
                  AND exact_build.state = 'verified' \
                 WHERE session.id = ?1 AND session.volume_id = ?3 \
                   AND session.scan_run_id = ?4 AND session.core_session_id = ?5 \
                   AND session.state = 'draft' \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM capture_time_analysis_builds AS build \
                       WHERE build.time_session_id = session.id \
                         AND build.exact_group_build_id = exact_build.id \
                         AND build.state = 'sealed' \
                   ) \
             )",
            params![
                input.time_session_id,
                input.exact_group_build_id,
                context.volume_id,
                guard.run().scan_run_id,
                guard.core_session_id().as_bytes().as_slice(),
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !session_matches {
            return Err(StoreError::ConcurrencyConflict {
                entity: "draft_time_group_outcome_guard",
                id: input.exact_group_build_id,
            });
        }
        let latest_group_evidence_ms = latest_time_group_terminal_evidence_ms(
            self.transaction,
            input.time_session_id,
            input.exact_group_build_id,
        )?;
        if input.created_at_ms < latest_group_evidence_ms {
            return Err(StoreError::invalid_input(
                "created_at_ms",
                "group outcome predates retained terminal report or analysis evidence",
            ));
        }
        let existing = self
            .transaction
            .query_row(
                "SELECT outcome, analysis_build_id, reason_code, created_at_ms \
                 FROM capture_time_group_outcomes \
                 WHERE time_session_id = ?1 AND exact_group_build_id = ?2",
                params![input.time_session_id, input.exact_group_build_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            return if existing.0 == input.outcome.as_storage_str()
                && existing.1.is_none()
                && existing.2 == input.reason_code
                && existing.3 == input.created_at_ms
            {
                Ok(())
            } else {
                Err(StoreError::IdempotencyConflict {
                    entity: "time_group_outcome",
                    key: format!("{}:{}", input.time_session_id, input.exact_group_build_id),
                })
            };
        }
        self.transaction.execute(
            "INSERT INTO capture_time_group_outcomes ( \
                 time_session_id, exact_group_build_id, volume_id, scan_run_id, outcome, \
                 analysis_build_id, reason_code, created_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
            params![
                input.time_session_id,
                input.exact_group_build_id,
                context.volume_id,
                guard.run().scan_run_id,
                input.outcome.as_storage_str(),
                input.reason_code,
                input.created_at_ms,
            ],
        )?;
        Ok(())
    }

    fn abandon_time_session_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        time_session_id: i64,
        abandoned_at_ms: i64,
        reason_code: &str,
        reason_message: Option<&str>,
    ) -> Result<()> {
        self.validate_time_evidence_guard(guard)?;
        require_positive("time_session_id", time_session_id)?;
        require_nonnegative("abandoned_at_ms", abandoned_at_ms)?;
        require_bounded_nonempty("reason_code", reason_code, 256)?;
        validate_optional_bounded("reason_message", reason_message, MAX_TEXT_BYTES)?;
        let stored = self.transaction.query_row(
            "SELECT scan_run_id, core_session_id, state, abandon_reason_code, \
                    abandon_reason_message, created_at_ms, finalized_at_ms \
             FROM scan_time_sessions WHERE id = ?1",
            [time_session_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            },
        )?;
        if stored.0 != guard.run().scan_run_id
            || stored.1.as_slice() != guard.core_session_id().as_bytes()
        {
            return Err(StoreError::ConcurrencyConflict {
                entity: "time_session_guard",
                id: time_session_id,
            });
        }
        if stored.2 == "abandoned" {
            return if stored.3.as_deref() == Some(reason_code)
                && stored.4.as_deref() == reason_message
                && stored.6 == Some(abandoned_at_ms)
            {
                Ok(())
            } else {
                Err(StoreError::IdempotencyConflict {
                    entity: "time_session_abandonment",
                    key: time_session_id.to_string(),
                })
            };
        }
        if stored.2 != "draft" || abandoned_at_ms < stored.5 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "draft_time_session",
                id: time_session_id,
            });
        }
        let open_child_count = self.transaction.query_row(
            "SELECT \
                 (SELECT count(*) FROM metadata_extraction_reports \
                  WHERE time_session_id = ?1 AND state = 'draft') + \
                 (SELECT count(*) FROM capture_time_analysis_builds \
                  WHERE time_session_id = ?1 AND state = 'draft')",
            [time_session_id],
            |row| row.get::<_, i64>(0),
        )?;
        if open_child_count != 0 {
            return Err(StoreError::invalid_input(
                "time_session_children",
                "draft reports and analyses must be explicitly abandoned before the session",
            ));
        }
        let latest_child_ms = self.transaction.query_row(
            "SELECT max(value) FROM ( \
                 SELECT created_at_ms AS value FROM scan_time_sessions WHERE id = ?1 \
                 UNION ALL SELECT finalized_at_ms FROM metadata_extraction_reports \
                     WHERE time_session_id = ?1 AND finalized_at_ms IS NOT NULL \
                 UNION ALL SELECT finalized_at_ms FROM capture_time_analysis_builds \
                     WHERE time_session_id = ?1 AND finalized_at_ms IS NOT NULL \
                 UNION ALL SELECT created_at_ms FROM capture_time_group_outcomes \
                     WHERE time_session_id = ?1 \
             )",
            [time_session_id],
            |row| row.get::<_, i64>(0),
        )?;
        if abandoned_at_ms < latest_child_ms {
            return Err(StoreError::invalid_input(
                "abandoned_at_ms",
                "session abandonment predates retained terminal evidence",
            ));
        }
        let changed = self.transaction.execute(
            "UPDATE scan_time_sessions \
             SET state = 'abandoned', abandon_reason_code = ?2, \
                 abandon_reason_message = ?3, finalized_at_ms = ?4 \
             WHERE id = ?1 AND state = 'draft'",
            params![
                time_session_id,
                reason_code,
                reason_message,
                abandoned_at_ms
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "time_session_abandonment",
                id: time_session_id,
            });
        }
        Ok(())
    }

    fn begin_metadata_report_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        input: &BeginMetadataReportInput,
    ) -> Result<i64> {
        let context = self.validate_time_evidence_guard(guard)?;
        validate_metadata_report_input(input)?;
        let session_header = self
            .transaction
            .query_row(
                "SELECT created_at_ms, max_probe_count_per_group \
                 FROM scan_time_sessions \
                 WHERE id = ?1 AND volume_id = ?2 AND scan_run_id = ?3 \
                   AND core_session_id = ?4 AND state = 'draft'",
                params![
                    input.time_session_id,
                    context.volume_id,
                    guard.run().scan_run_id,
                    guard.core_session_id().as_bytes().as_slice(),
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let Some((session_created_at_ms, max_probe_count)) = session_header else {
            return Err(StoreError::ConcurrencyConflict {
                entity: "draft_time_session",
                id: input.time_session_id,
            });
        };
        if input.created_at_ms < session_created_at_ms {
            return Err(StoreError::invalid_input(
                "created_at_ms",
                "metadata report creation predates its time session",
            ));
        }
        if input.probe_ordinal >= max_probe_count {
            return Err(StoreError::invalid_input(
                "probe_ordinal",
                "metadata probe ordinal exceeds the frozen per-group probe budget",
            ));
        }
        let probe_is_exact_member = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM scan_time_sessions AS time_session \
                 JOIN exact_group_builds AS exact_build \
                   ON exact_build.id = ?2 AND exact_build.volume_id = time_session.volume_id \
                  AND exact_build.scan_run_id = time_session.scan_run_id \
                  AND exact_build.state = 'verified' \
                 JOIN exact_group_build_members AS member \
                   ON member.exact_group_build_id = exact_build.id \
                  AND member.volume_id = exact_build.volume_id \
                  AND member.scan_run_id = exact_build.scan_run_id \
                  AND member.media_observation_snapshot_id = ?3 \
                  AND member.observation_fingerprint_id = ?4 \
                 JOIN observation_fingerprints AS fingerprint \
                   ON fingerprint.id = member.observation_fingerprint_id \
                  AND fingerprint.media_observation_snapshot_id = member.media_observation_snapshot_id \
                  AND fingerprint.fingerprint_kind = 'exact_bytes' \
                  AND fingerprint.read_origin = 'full_hash_read' \
                 WHERE time_session.id = ?1 AND time_session.state = 'draft' \
                   AND time_session.scan_run_id = ?5 AND time_session.volume_id = ?6 \
                   AND time_session.core_session_id = ?7 \
             )",
            params![
                input.time_session_id,
                input.exact_group_build_id,
                input.metadata_probe_observation_id,
                input.metadata_probe_fingerprint_id,
                guard.run().scan_run_id,
                context.volume_id,
                guard.core_session_id().as_bytes().as_slice(),
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !probe_is_exact_member {
            return Err(StoreError::invalid_input(
                "metadata_probe",
                "report probe must be a full-read exact fingerprint member of the sealed group",
            ));
        }
        if let Some((id, matches)) = self
            .transaction
            .query_row(
                "SELECT id, metadata_probe_observation_id = ?4 \
                     AND metadata_probe_fingerprint_id = ?5 \
                     AND source_size_bytes = ?6 AND retained_report_digest = ?7 \
                     AND expected_manifest_digest = ?8 AND expected_field_count = ?9 \
                     AND expected_issue_count = ?10 \
                     AND expected_retained_field_bytes = ?11 \
                     AND report_parser_name = ?12 AND report_parser_version = ?13 \
                     AND detected_format IS ?14 AND extraction_status = ?15 \
                     AND effective_max_total_bytes_read = ?16 \
                     AND effective_max_read_operations = ?17 \
                     AND effective_max_retained_field_bytes = ?18 \
                     AND effective_max_field_bytes = ?19 AND effective_max_fields = ?20 \
                     AND effective_max_jpeg_segments = ?21 \
                     AND effective_max_ifd_entries = ?22 AND effective_max_ifd_depth = ?23 \
                     AND effective_max_bmff_boxes = ?24 AND effective_max_bmff_depth = ?25 \
                     AND usage_bytes_read = ?26 AND usage_read_operations = ?27 \
                     AND usage_retained_field_bytes = ?28 AND usage_fields_emitted = ?29 \
                     AND usage_jpeg_segments_visited = ?30 \
                     AND usage_ifd_entries_visited = ?31 \
                     AND usage_bmff_boxes_visited = ?32 \
                     AND usage_max_depth_observed = ?33 AND created_at_ms = ?34 \
                     AND volume_id = ?35 AND scan_run_id = ?36 AND core_session_id = ?37 \
                     AND manifest_version = 1 \
                 FROM metadata_extraction_reports \
                 WHERE time_session_id = ?1 AND exact_group_build_id = ?2 AND probe_ordinal = ?3",
                params![
                    input.time_session_id,
                    input.exact_group_build_id,
                    input.probe_ordinal,
                    input.metadata_probe_observation_id,
                    input.metadata_probe_fingerprint_id,
                    input.source_size_bytes,
                    input.retained_report_digest.as_bytes().as_slice(),
                    input.expected_manifest_digest.as_bytes().as_slice(),
                    input.expected_field_count,
                    input.expected_issue_count,
                    input.expected_retained_field_bytes,
                    input.parser.name,
                    input.parser.version,
                    input.detected_format.map(|value| value.as_storage_str()),
                    input.extraction_status.as_storage_str(),
                    input.limits.total_bytes_read,
                    input.limits.read_operations,
                    input.limits.retained_field_bytes,
                    input.limits.field_bytes,
                    input.limits.fields,
                    input.limits.jpeg_segments,
                    input.limits.ifd_entries,
                    input.limits.ifd_depth,
                    input.limits.bmff_boxes,
                    input.limits.bmff_depth,
                    input.usage.bytes_read,
                    input.usage.read_operations,
                    input.usage.retained_field_bytes,
                    input.usage.fields_emitted,
                    input.usage.jpeg_segments_visited,
                    input.usage.ifd_entries_visited,
                    input.usage.bmff_boxes_visited,
                    input.usage.max_depth_observed,
                    input.created_at_ms,
                    context.volume_id,
                    guard.run().scan_run_id,
                    guard.core_session_id().as_bytes().as_slice(),
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
        {
            return if matches {
                Ok(id)
            } else {
                Err(StoreError::IdempotencyConflict {
                    entity: "metadata_report",
                    key: format!(
                        "{}:{}:{}",
                        input.time_session_id, input.exact_group_build_id, input.probe_ordinal
                    ),
                })
            };
        }
        self.transaction.execute(
            "INSERT INTO metadata_extraction_reports ( \
                 time_session_id, volume_id, scan_run_id, core_session_id, exact_group_build_id, \
                 metadata_probe_observation_id, metadata_probe_fingerprint_id, probe_ordinal, \
                 source_size_bytes, report_parser_name, report_parser_version, detected_format, \
                 extraction_status, effective_max_total_bytes_read, \
                 effective_max_read_operations, effective_max_retained_field_bytes, \
                 effective_max_field_bytes, effective_max_fields, effective_max_jpeg_segments, \
                 effective_max_ifd_entries, effective_max_ifd_depth, effective_max_bmff_boxes, \
                 effective_max_bmff_depth, usage_bytes_read, usage_read_operations, \
                 usage_retained_field_bytes, usage_fields_emitted, usage_jpeg_segments_visited, \
                 usage_ifd_entries_visited, usage_bmff_boxes_visited, usage_max_depth_observed, \
                 expected_field_count, expected_issue_count, expected_retained_field_bytes, \
                 retained_report_digest, expected_manifest_digest, created_at_ms \
             ) VALUES ( \
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, \
                 ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, \
                 ?31, ?32, ?33, ?34, ?35, ?36, ?37 \
             )",
            params![
                input.time_session_id,
                context.volume_id,
                guard.run().scan_run_id,
                guard.core_session_id().as_bytes().as_slice(),
                input.exact_group_build_id,
                input.metadata_probe_observation_id,
                input.metadata_probe_fingerprint_id,
                input.probe_ordinal,
                input.source_size_bytes,
                input.parser.name,
                input.parser.version,
                input.detected_format.map(|value| value.as_storage_str()),
                input.extraction_status.as_storage_str(),
                input.limits.total_bytes_read,
                input.limits.read_operations,
                input.limits.retained_field_bytes,
                input.limits.field_bytes,
                input.limits.fields,
                input.limits.jpeg_segments,
                input.limits.ifd_entries,
                input.limits.ifd_depth,
                input.limits.bmff_boxes,
                input.limits.bmff_depth,
                input.usage.bytes_read,
                input.usage.read_operations,
                input.usage.retained_field_bytes,
                input.usage.fields_emitted,
                input.usage.jpeg_segments_visited,
                input.usage.ifd_entries_visited,
                input.usage.bmff_boxes_visited,
                input.usage.max_depth_observed,
                input.expected_field_count,
                input.expected_issue_count,
                input.expected_retained_field_bytes,
                input.retained_report_digest.as_bytes().as_slice(),
                input.expected_manifest_digest.as_bytes().as_slice(),
                input.created_at_ms,
            ],
        )?;
        Ok(self.transaction.last_insert_rowid())
    }

    fn append_metadata_fields_batch_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        report_id: i64,
        inputs: &[MetadataFieldInput],
    ) -> Result<Vec<i64>> {
        self.validate_time_evidence_guard(guard)?;
        validate_time_batch("metadata_fields", inputs.len())?;
        require_draft_report_for_guard(self.transaction, guard, report_id)?;
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            validate_metadata_field_input(input)?;
            let locator = StoredLocatorColumns::from(&input.locator.container);
            let existing = self
                .transaction
                .query_row(
                    "SELECT id, parser_name, parser_version, field_kind, encoding, \
                            absolute_offset, byte_len, raw_bytes, raw_digest, container_kind, \
                            tiff_header_offset, tiff_ifd_offset, tiff_tag, tiff_byte_order, \
                            jpeg_app1_offset, bmff_box_offset, bmff_box_path, created_at_ms \
                     FROM metadata_extraction_fields WHERE report_id = ?1 AND ordinal = ?2",
                    params![report_id, input.ordinal],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, Vec<u8>>(7)?,
                            row.get::<_, Vec<u8>>(8)?,
                            row.get::<_, String>(9)?,
                            row.get::<_, Option<i64>>(10)?,
                            row.get::<_, Option<i64>>(11)?,
                            row.get::<_, Option<i64>>(12)?,
                            row.get::<_, Option<String>>(13)?,
                            row.get::<_, Option<i64>>(14)?,
                            row.get::<_, Option<i64>>(15)?,
                            row.get::<_, Option<Vec<u8>>>(16)?,
                            row.get::<_, i64>(17)?,
                        ))
                    },
                )
                .optional()?;
            if let Some(existing) = existing {
                let matches = existing.1 == input.parser.name
                    && existing.2 == input.parser.version
                    && existing.3 == input.field_kind.as_storage_str()
                    && existing.4 == input.encoding.as_storage_str()
                    && existing.5 == input.locator.absolute_offset
                    && existing.6 == input.locator.byte_len
                    && existing.7 == input.raw_bytes
                    && existing.8.as_slice() == input.raw_digest.as_bytes()
                    && existing.9 == locator.kind
                    && existing.10 == locator.tiff_header_offset
                    && existing.11 == locator.tiff_ifd_offset
                    && existing.12 == locator.tiff_tag
                    && existing.13.as_deref() == locator.tiff_byte_order
                    && existing.14 == locator.jpeg_app1_offset
                    && existing.15 == locator.bmff_box_offset
                    && existing.16.as_deref() == locator.bmff_box_path
                    && existing.17 == input.created_at_ms;
                if !matches {
                    return Err(StoreError::IdempotencyConflict {
                        entity: "metadata_field",
                        key: format!("{report_id}:{}", input.ordinal),
                    });
                }
                ids.push(existing.0);
                continue;
            }
            self.transaction.execute(
                "INSERT INTO metadata_extraction_fields ( \
                     report_id, ordinal, parser_name, parser_version, field_kind, encoding, \
                     absolute_offset, byte_len, raw_bytes, raw_digest, container_kind, \
                     tiff_header_offset, tiff_ifd_offset, tiff_tag, tiff_byte_order, \
                     jpeg_app1_offset, bmff_box_offset, bmff_box_path, created_at_ms \
                 ) VALUES ( \
                     ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                     ?16, ?17, ?18, ?19 \
                 )",
                params![
                    report_id,
                    input.ordinal,
                    input.parser.name,
                    input.parser.version,
                    input.field_kind.as_storage_str(),
                    input.encoding.as_storage_str(),
                    input.locator.absolute_offset,
                    input.locator.byte_len,
                    input.raw_bytes,
                    input.raw_digest.as_bytes().as_slice(),
                    locator.kind,
                    locator.tiff_header_offset,
                    locator.tiff_ifd_offset,
                    locator.tiff_tag,
                    locator.tiff_byte_order,
                    locator.jpeg_app1_offset,
                    locator.bmff_box_offset,
                    locator.bmff_box_path,
                    input.created_at_ms,
                ],
            )?;
            ids.push(self.transaction.last_insert_rowid());
        }
        Ok(ids)
    }

    fn append_metadata_issues_batch_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        report_id: i64,
        inputs: &[MetadataExtractionIssueInput],
    ) -> Result<Vec<i64>> {
        self.validate_time_evidence_guard(guard)?;
        validate_time_batch("metadata_issues", inputs.len())?;
        require_draft_report_for_guard(self.transaction, guard, report_id)?;
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            let existing = self
                .transaction
                .query_row(
                    "SELECT id, parser_name, parser_version, issue_code, source_offset, context, \
                            created_at_ms \
                     FROM metadata_extraction_issues WHERE report_id = ?1 AND ordinal = ?2",
                    params![report_id, input.ordinal],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Option<i64>>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing.1 != input.parser.name
                    || existing.2 != input.parser.version
                    || existing.3 != input.issue_code.as_storage_str()
                    || existing.4 != input.source_offset
                    || existing.5 != input.context
                    || existing.6 != input.created_at_ms
                {
                    return Err(StoreError::IdempotencyConflict {
                        entity: "metadata_issue",
                        key: format!("{report_id}:{}", input.ordinal),
                    });
                }
                ids.push(existing.0);
                continue;
            }
            self.transaction.execute(
                "INSERT INTO metadata_extraction_issues ( \
                     report_id, ordinal, parser_name, parser_version, issue_code, source_offset, \
                     context, created_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    report_id,
                    input.ordinal,
                    input.parser.name,
                    input.parser.version,
                    input.issue_code.as_storage_str(),
                    input.source_offset,
                    input.context,
                    input.created_at_ms,
                ],
            )?;
            ids.push(self.transaction.last_insert_rowid());
        }
        Ok(ids)
    }

    fn seal_metadata_report_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        report_id: i64,
        revalidation: &MetadataSourceRevalidationInput,
        finalized_at_ms: i64,
    ) -> Result<TimeEvidenceManifestDigest> {
        self.validate_time_evidence_guard(guard)?;
        require_positive("report_id", report_id)?;
        require_nonnegative("finalized_at_ms", finalized_at_ms)?;
        let report = self.transaction.query_row(
            "SELECT time_session_id, volume_id, scan_run_id, core_session_id, \
                    exact_group_build_id, metadata_probe_observation_id, retained_report_digest, \
                    expected_manifest_digest, sealed_manifest_digest, state, created_at_ms, \
                    finalized_at_ms \
             FROM metadata_extraction_reports WHERE id = ?1",
            [report_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                ))
            },
        )?;
        if report.2 != guard.run().scan_run_id
            || report.3.as_slice() != guard.core_session_id().as_bytes()
        {
            return Err(StoreError::ConcurrencyConflict {
                entity: "metadata_report_guard",
                id: report_id,
            });
        }
        let latest_extraction_ms =
            latest_metadata_report_extraction_ms(self.transaction, report_id)?;
        let expected =
            TimeEvidenceManifestDigest::from_runtime_evidence(fixed_32_from_sql(report.7, 7)?);
        if report.9 == "sealed" {
            let (expected_source_key, expected_lineage_key) =
                recompute_metadata_source_keys(self.transaction, report_id)?;
            if revalidation.source_key != expected_source_key
                || revalidation.lineage_key != expected_lineage_key
                || report.11 != Some(finalized_at_ms)
            {
                return Err(StoreError::IdempotencyConflict {
                    entity: "metadata_report_seal",
                    key: report_id.to_string(),
                });
            }
            let stored_revalidation = self.transaction.query_row(
                "SELECT source_key, lineage_key, source_signature_before, \
                        source_signature_after, first_report_digest, second_report_digest, \
                        revalidated_at_ms \
                 FROM metadata_source_revalidations WHERE report_id = ?1",
                [report_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )?;
            if stored_revalidation.0.as_slice() != revalidation.source_key.as_bytes()
                || stored_revalidation.1.as_slice() != revalidation.lineage_key.as_bytes()
                || stored_revalidation.2.as_slice()
                    != revalidation.source_signature_before.as_bytes()
                || stored_revalidation.3.as_slice()
                    != revalidation.source_signature_after.as_bytes()
                || stored_revalidation.4.as_slice() != revalidation.first_report_digest.as_bytes()
                || stored_revalidation.5.as_slice() != revalidation.second_report_digest.as_bytes()
                || stored_revalidation.6 != revalidation.revalidated_at_ms
            {
                return Err(StoreError::IdempotencyConflict {
                    entity: "metadata_report_seal",
                    key: report_id.to_string(),
                });
            }
            if stored_revalidation.6 < latest_extraction_ms
                || report.11.is_none()
                || report
                    .11
                    .is_some_and(|sealed_at_ms| sealed_at_ms < stored_revalidation.6)
            {
                return Err(StoreError::invalid_input(
                    "metadata_report_chronology",
                    "sealed report predates retained extraction or source revalidation evidence",
                ));
            }
            let observed = recompute_metadata_report_manifest(self.transaction, report_id)?;
            return if observed == expected
                && report
                    .8
                    .as_deref()
                    .is_some_and(|digest| digest == expected.as_bytes())
            {
                Ok(observed)
            } else {
                Err(StoreError::invalid_input(
                    "metadata_report_manifest",
                    "sealed report manifest no longer matches its expected digest",
                ))
            };
        }
        if report.9 != "draft" {
            return Err(StoreError::ConcurrencyConflict {
                entity: "draft_metadata_report",
                id: report_id,
            });
        }
        if revalidation.revalidated_at_ms < latest_extraction_ms {
            return Err(StoreError::invalid_input(
                "revalidated_at_ms",
                "source revalidation predates retained metadata fields or issues",
            ));
        }
        if finalized_at_ms < revalidation.revalidated_at_ms {
            return Err(StoreError::invalid_input(
                "finalized_at_ms",
                "report finalization predates retained extraction or source revalidation evidence",
            ));
        }
        if report.6.as_slice() != revalidation.first_report_digest.as_bytes()
            || revalidation.first_report_digest != revalidation.second_report_digest
        {
            return Err(StoreError::invalid_input(
                "metadata_revalidation",
                "revalidation digest does not reproduce the retained report",
            ));
        }
        let (expected_source_key, expected_lineage_key) =
            recompute_metadata_source_keys(self.transaction, report_id)?;
        if revalidation.source_key != expected_source_key
            || revalidation.lineage_key != expected_lineage_key
        {
            return Err(StoreError::invalid_input(
                "metadata_revalidation_identity",
                "source or lineage key does not match the persisted exact probe graph",
            ));
        }
        let existing = self
            .transaction
            .query_row(
                "SELECT source_key, lineage_key, source_signature_before, source_signature_after, \
                        first_report_digest, second_report_digest, revalidated_at_ms \
                 FROM metadata_source_revalidations WHERE report_id = ?1",
                [report_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing.0.as_slice() != revalidation.source_key.as_bytes()
                || existing.1.as_slice() != revalidation.lineage_key.as_bytes()
                || existing.2.as_slice() != revalidation.source_signature_before.as_bytes()
                || existing.3.as_slice() != revalidation.source_signature_after.as_bytes()
                || existing.4.as_slice() != revalidation.first_report_digest.as_bytes()
                || existing.5.as_slice() != revalidation.second_report_digest.as_bytes()
                || existing.6 != revalidation.revalidated_at_ms
            {
                return Err(StoreError::IdempotencyConflict {
                    entity: "metadata_source_revalidation",
                    key: report_id.to_string(),
                });
            }
        } else {
            self.transaction.execute(
                "INSERT INTO metadata_source_revalidations ( \
                     report_id, time_session_id, volume_id, scan_run_id, core_session_id, \
                     exact_group_build_id, metadata_probe_observation_id, source_key, \
                     source_key_version, lineage_key, lineage_key_version, \
                     source_signature_before, source_signature_after, first_report_digest, \
                     second_report_digest, outcome, descriptor_revalidated, path_revalidated, \
                     session_revalidated, trust_scope, revalidated_at_ms \
                 ) VALUES ( \
                     ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 2, ?9, 1, ?10, ?11, ?12, ?13, \
                     'reextracted_pinned_exact', 1, 1, 1, 'historical_proof_only', ?14 \
                 )",
                params![
                    report_id,
                    report.0,
                    report.1,
                    report.2,
                    report.3,
                    report.4,
                    report.5,
                    revalidation.source_key.as_bytes().as_slice(),
                    revalidation.lineage_key.as_bytes().as_slice(),
                    revalidation.source_signature_before.as_bytes().as_slice(),
                    revalidation.source_signature_after.as_bytes().as_slice(),
                    revalidation.first_report_digest.as_bytes().as_slice(),
                    revalidation.second_report_digest.as_bytes().as_slice(),
                    revalidation.revalidated_at_ms,
                ],
            )?;
        }
        let observed = recompute_metadata_report_manifest(self.transaction, report_id)?;
        if observed != expected {
            return Err(StoreError::invalid_input(
                "metadata_report_manifest",
                "database-streamed report manifest differs from the frozen expected digest",
            ));
        }
        let changed = self.transaction.execute(
            "UPDATE metadata_extraction_reports \
             SET state = 'sealed', sealed_manifest_digest = ?2, finalized_at_ms = ?3 \
             WHERE id = ?1 AND state = 'draft'",
            params![report_id, observed.as_bytes().as_slice(), finalized_at_ms],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "metadata_report_seal",
                id: report_id,
            });
        }
        Ok(observed)
    }

    fn abandon_metadata_report_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        report_id: i64,
        abandoned_at_ms: i64,
        reason_code: &str,
        reason_message: Option<&str>,
    ) -> Result<()> {
        self.validate_time_evidence_guard(guard)?;
        require_positive("report_id", report_id)?;
        require_nonnegative("abandoned_at_ms", abandoned_at_ms)?;
        require_bounded_nonempty("reason_code", reason_code, 256)?;
        validate_optional_bounded("reason_message", reason_message, MAX_TEXT_BYTES)?;
        let stored = self.transaction.query_row(
            "SELECT scan_run_id, core_session_id, state, abandon_reason_code, \
                    abandon_reason_message, created_at_ms, finalized_at_ms, \
                    max(created_at_ms, \
                        COALESCE((SELECT max(created_at_ms) FROM metadata_extraction_fields \
                                  WHERE report_id = metadata_extraction_reports.id), created_at_ms), \
                        COALESCE((SELECT max(created_at_ms) FROM metadata_extraction_issues \
                                  WHERE report_id = metadata_extraction_reports.id), created_at_ms), \
                        COALESCE((SELECT max(revalidated_at_ms) \
                                  FROM metadata_source_revalidations \
                                  WHERE report_id = metadata_extraction_reports.id), created_at_ms)) \
             FROM metadata_extraction_reports WHERE id = ?1",
            [report_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )?;
        if stored.0 != guard.run().scan_run_id
            || stored.1.as_slice() != guard.core_session_id().as_bytes()
        {
            return Err(StoreError::ConcurrencyConflict {
                entity: "metadata_report_guard",
                id: report_id,
            });
        }
        if stored.2 == "abandoned" {
            if stored.6.is_none() || stored.6.is_some_and(|value| value < stored.7) {
                return Err(StoreError::invalid_input(
                    "metadata_report_chronology",
                    "abandoned report predates retained extraction or revalidation evidence",
                ));
            }
            return if stored.3.as_deref() == Some(reason_code)
                && stored.4.as_deref() == reason_message
                && stored.6 == Some(abandoned_at_ms)
            {
                Ok(())
            } else {
                Err(StoreError::IdempotencyConflict {
                    entity: "metadata_report_abandonment",
                    key: report_id.to_string(),
                })
            };
        }
        if stored.2 != "draft" {
            return Err(StoreError::ConcurrencyConflict {
                entity: "draft_metadata_report",
                id: report_id,
            });
        }
        if abandoned_at_ms < stored.7 {
            return Err(StoreError::invalid_input(
                "abandoned_at_ms",
                "report abandonment predates retained extraction or revalidation evidence",
            ));
        }
        let changed = self.transaction.execute(
            "UPDATE metadata_extraction_reports \
             SET state = 'abandoned', abandon_reason_code = ?2, \
                 abandon_reason_message = ?3, finalized_at_ms = ?4 \
             WHERE id = ?1 AND scan_run_id = ?5 AND core_session_id = ?6 AND state = 'draft'",
            params![
                report_id,
                reason_code,
                reason_message,
                abandoned_at_ms,
                guard.run().scan_run_id,
                guard.core_session_id().as_bytes().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "metadata_report_abandonment",
                id: report_id,
            });
        }
        Ok(())
    }

    fn begin_capture_time_analysis_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        input: &BeginCaptureTimeAnalysisInput,
    ) -> Result<i64> {
        let context = self.validate_time_evidence_guard(guard)?;
        let observed_context_digest =
            compute_time_policy_context_digest(&input.policy_context_json)?;
        if observed_context_digest != input.policy_context_digest {
            return Err(StoreError::invalid_input(
                "policy_context_digest",
                "policy context digest does not match canonical JSON",
            ));
        }
        let policy_context_json = serialize_canonical_json(&input.policy_context_json)?;
        if policy_context_json.len() > MAX_JSON_BYTES {
            return Err(StoreError::invalid_input(
                "policy_context_json",
                "canonical policy context exceeds 1 MiB",
            ));
        }
        let session_created_at_ms = self
            .transaction
            .query_row(
                "SELECT time_session.created_at_ms \
                 FROM scan_time_sessions AS time_session \
                 JOIN exact_group_builds AS exact_build \
                   ON exact_build.id = ?2 \
                  AND exact_build.volume_id = time_session.volume_id \
                  AND exact_build.scan_run_id = time_session.scan_run_id \
                  AND exact_build.state = 'verified' \
                 WHERE time_session.id = ?1 AND time_session.volume_id = ?3 \
                   AND time_session.scan_run_id = ?4 AND time_session.core_session_id = ?5 \
                   AND time_session.state = 'draft'",
                params![
                    input.time_session_id,
                    input.exact_group_build_id,
                    context.volume_id,
                    guard.run().scan_run_id,
                    guard.core_session_id().as_bytes().as_slice(),
                ],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StoreError::ConcurrencyConflict {
                    entity: "capture_time_analysis_scope",
                    id: input.exact_group_build_id,
                },
                other => StoreError::from(other),
            })?;
        if input.created_at_ms < session_created_at_ms {
            return Err(StoreError::invalid_input(
                "created_at_ms",
                "capture-time analysis creation predates its time session",
            ));
        }
        if let Some((id, matches)) = self
            .transaction
            .query_row(
                "SELECT id, policy_name = ?3 AND policy_version = ?4 \
                     AND policy_context_json = ?5 AND policy_context_digest = ?6 \
                     AND expected_source_count = ?7 AND expected_observation_count = ?8 \
                     AND expected_candidate_count = ?9 AND expected_issue_count = ?10 \
                     AND expected_member_count = ?11 AND expected_recommendation_count = ?12 \
                     AND expected_manifest_digest = ?13 AND created_at_ms = ?14 \
                     AND volume_id = ?15 AND scan_run_id = ?16 AND manifest_version = 1 \
                 FROM capture_time_analysis_builds \
                 WHERE time_session_id = ?1 AND exact_group_build_id = ?2",
                params![
                    input.time_session_id,
                    input.exact_group_build_id,
                    input.policy_name,
                    input.policy_version,
                    policy_context_json,
                    input.policy_context_digest.as_bytes().as_slice(),
                    input.expected_source_count,
                    input.expected_observation_count,
                    input.expected_candidate_count,
                    input.expected_issue_count,
                    input.expected_member_count,
                    input.expected_recommendation_count,
                    input.expected_manifest_digest.as_bytes().as_slice(),
                    input.created_at_ms,
                    context.volume_id,
                    guard.run().scan_run_id,
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
        {
            return if matches {
                Ok(id)
            } else {
                Err(StoreError::IdempotencyConflict {
                    entity: "capture_time_analysis",
                    key: format!("{}:{}", input.time_session_id, input.exact_group_build_id),
                })
            };
        }
        self.transaction.execute(
            "INSERT INTO capture_time_analysis_builds ( \
                 time_session_id, volume_id, scan_run_id, exact_group_build_id, policy_name, \
                 policy_version, policy_context_json, policy_context_digest, \
                 expected_source_count, expected_observation_count, expected_candidate_count, \
                 expected_issue_count, expected_member_count, expected_recommendation_count, \
                 expected_manifest_digest, created_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                input.time_session_id,
                context.volume_id,
                guard.run().scan_run_id,
                input.exact_group_build_id,
                input.policy_name,
                input.policy_version,
                policy_context_json,
                input.policy_context_digest.as_bytes().as_slice(),
                input.expected_source_count,
                input.expected_observation_count,
                input.expected_candidate_count,
                input.expected_issue_count,
                input.expected_member_count,
                input.expected_recommendation_count,
                input.expected_manifest_digest.as_bytes().as_slice(),
                input.created_at_ms,
            ],
        )?;
        Ok(self.transaction.last_insert_rowid())
    }

    fn append_capture_time_sources_batch_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        inputs: &[CaptureTimeAnalysisSourceInput],
    ) -> Result<()> {
        self.validate_time_evidence_guard(guard)?;
        validate_time_batch("capture_time_sources", inputs.len())?;
        require_draft_analysis_for_guard(self.transaction, guard, analysis_build_id)?;
        for input in inputs {
            let existing = self
                .transaction
                .query_row(
                    "SELECT report_id, source_key, lineage_key, binding_status, created_at_ms \
                     FROM capture_time_analysis_sources \
                     WHERE analysis_build_id = ?1 AND ordinal = ?2",
                    params![analysis_build_id, input.ordinal],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing.0 != input.report_id
                    || existing.1.as_slice() != input.source_key.as_bytes()
                    || existing.2.as_slice() != input.lineage_key.as_bytes()
                    || existing.3 != "reextracted_pinned_source"
                    || existing.4 != input.created_at_ms
                {
                    return Err(StoreError::IdempotencyConflict {
                        entity: "capture_time_source",
                        key: format!("{analysis_build_id}:{}", input.ordinal),
                    });
                }
                continue;
            }
            self.transaction.execute(
                "INSERT INTO capture_time_analysis_sources ( \
                     analysis_build_id, ordinal, report_id, source_key, lineage_key, \
                     binding_status, created_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'reextracted_pinned_source', ?6)",
                params![
                    analysis_build_id,
                    input.ordinal,
                    input.report_id,
                    input.source_key.as_bytes().as_slice(),
                    input.lineage_key.as_bytes().as_slice(),
                    input.created_at_ms,
                ],
            )?;
        }
        Ok(())
    }

    fn append_capture_time_observations_batch_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        inputs: &[CaptureTimeObservationInput],
    ) -> Result<Vec<i64>> {
        self.validate_time_evidence_guard(guard)?;
        validate_time_batch("capture_time_observations", inputs.len())?;
        require_draft_analysis_for_guard(self.transaction, guard, analysis_build_id)?;
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            let columns = StoredInterpretationColumns::from(&input.interpretation);
            self.transaction.execute(
                "INSERT INTO capture_time_observations ( \
                     analysis_build_id, ordinal, source_ordinal, report_id, metadata_field_id, \
                     interpretation_kind, wall_year, wall_month, wall_day, wall_hour, wall_minute, \
                     wall_second, wall_nanosecond, semantic_kind, offset_kind, utc_offset_minutes, \
                     utc_seconds_decimal, utc_nanoseconds, normalized_precision_ns, \
                     parsed_offset_minutes, subsecond_nanosecond, subsecond_digits, \
                     subsecond_precision_ns, rejection_code, created_at_ms \
                 ) SELECT ?1, ?2, ?3, field.report_id, field.id, ?4, ?5, ?6, ?7, ?8, ?9, ?10, \
                          ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23 \
                   FROM metadata_extraction_fields AS field WHERE field.id = ?24 \
                 ON CONFLICT(analysis_build_id, ordinal) DO NOTHING",
                params![
                    analysis_build_id,
                    input.ordinal,
                    input.source_ordinal,
                    columns.kind,
                    columns.wall_year,
                    columns.wall_month,
                    columns.wall_day,
                    columns.wall_hour,
                    columns.wall_minute,
                    columns.wall_second,
                    columns.wall_nanosecond,
                    columns.semantic_kind,
                    columns.offset_kind,
                    columns.utc_offset_minutes,
                    columns.utc_seconds_decimal,
                    columns.utc_nanoseconds,
                    columns.normalized_precision_ns,
                    columns.parsed_offset_minutes,
                    columns.subsecond_nanosecond,
                    columns.subsecond_digits,
                    columns.subsecond_precision_ns,
                    columns.rejection_code,
                    input.created_at_ms,
                    input.metadata_field_id,
                ],
            )?;
            let row = self.transaction.query_row(
                "SELECT id, metadata_field_id = ?3 AND source_ordinal = ?4 \
                     AND interpretation_kind = ?5 AND wall_year IS ?6 AND wall_month IS ?7 \
                     AND wall_day IS ?8 AND wall_hour IS ?9 AND wall_minute IS ?10 \
                     AND wall_second IS ?11 AND wall_nanosecond IS ?12 \
                     AND semantic_kind IS ?13 AND offset_kind IS ?14 \
                     AND utc_offset_minutes IS ?15 AND utc_seconds_decimal IS ?16 \
                     AND utc_nanoseconds IS ?17 AND normalized_precision_ns IS ?18 \
                     AND parsed_offset_minutes IS ?19 AND subsecond_nanosecond IS ?20 \
                     AND subsecond_digits IS ?21 AND subsecond_precision_ns IS ?22 \
                     AND rejection_code IS ?23 AND created_at_ms = ?24 \
                 FROM capture_time_observations \
                 WHERE analysis_build_id = ?1 AND ordinal = ?2",
                params![
                    analysis_build_id,
                    input.ordinal,
                    input.metadata_field_id,
                    input.source_ordinal,
                    columns.kind,
                    columns.wall_year,
                    columns.wall_month,
                    columns.wall_day,
                    columns.wall_hour,
                    columns.wall_minute,
                    columns.wall_second,
                    columns.wall_nanosecond,
                    columns.semantic_kind,
                    columns.offset_kind,
                    columns.utc_offset_minutes,
                    columns.utc_seconds_decimal,
                    columns.utc_nanoseconds,
                    columns.normalized_precision_ns,
                    columns.parsed_offset_minutes,
                    columns.subsecond_nanosecond,
                    columns.subsecond_digits,
                    columns.subsecond_precision_ns,
                    columns.rejection_code,
                    input.created_at_ms,
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?)),
            )?;
            if !row.1 {
                return Err(StoreError::IdempotencyConflict {
                    entity: "capture_time_observation",
                    key: format!("{analysis_build_id}:{}", input.ordinal),
                });
            }
            ids.push(row.0);
        }
        Ok(ids)
    }

    fn append_capture_time_candidates_batch_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        inputs: &[CaptureTimeCandidateInput],
    ) -> Result<Vec<i64>> {
        self.validate_time_evidence_guard(guard)?;
        validate_time_batch("capture_time_candidates", inputs.len())?;
        require_draft_analysis_for_guard(self.transaction, guard, analysis_build_id)?;
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            validate_candidate_references(self.transaction, analysis_build_id, input)?;
            if input.evidence_gate.as_storage_str() == "eligible" {
                validate_eligible_candidate_support(
                    self.transaction,
                    &CandidateSupportClaim::from_input(analysis_build_id, input),
                )?;
            }
            let wall = input.timestamp.wall_time();
            let evidence_kinds_json = serde_json::to_string(
                &input
                    .evidence_kinds
                    .iter()
                    .map(|value| value.as_storage_str())
                    .collect::<Vec<_>>(),
            )?;
            let source_keys_json = serde_json::to_string(
                &input
                    .source_keys
                    .iter()
                    .map(|value| lower_hex(value.as_bytes()))
                    .collect::<Vec<_>>(),
            )?;
            let lineage_keys_json = serde_json::to_string(
                &input
                    .lineage_keys
                    .iter()
                    .map(|value| lower_hex(value.as_bytes()))
                    .collect::<Vec<_>>(),
            )?;
            let observation_ordinals_json = serde_json::to_string(&input.observation_ordinals)?;
            let anomalies_json = serde_json::to_string(
                &input
                    .anomalies
                    .iter()
                    .map(|value| value.as_storage_str())
                    .collect::<Vec<_>>(),
            )?;
            let blockers_json = serde_json::to_string(
                &input
                    .evidence_gate
                    .blockers()
                    .iter()
                    .map(|value| value.as_storage_str())
                    .collect::<Vec<_>>(),
            )?;
            for (field, value) in [
                ("evidence_kinds_json", &evidence_kinds_json),
                ("source_keys_json", &source_keys_json),
                ("lineage_keys_json", &lineage_keys_json),
                ("observation_ordinals_json", &observation_ordinals_json),
                ("anomalies_json", &anomalies_json),
                ("blockers_json", &blockers_json),
            ] {
                if value.len() > MAX_JSON_BYTES {
                    return Err(StoreError::invalid_input(
                        field,
                        "candidate JSON exceeds 1 MiB",
                    ));
                }
            }
            self.transaction.execute(
                "INSERT INTO capture_time_candidates ( \
                     analysis_build_id, ordinal, wall_year, wall_month, wall_day, wall_hour, \
                     wall_minute, wall_second, wall_nanosecond, semantic_kind, offset_kind, \
                     utc_offset_minutes, utc_seconds_decimal, utc_nanoseconds, precision_ns, \
                     confidence, evidence_gate, evidence_kinds_json, source_keys_json, \
                     lineage_keys_json, observation_ordinals_json, anomalies_json, blockers_json, \
                     created_at_ms \
                 ) VALUES ( \
                     ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                     ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24 \
                 ) ON CONFLICT(analysis_build_id, ordinal) DO NOTHING",
                params![
                    analysis_build_id,
                    input.ordinal,
                    i64::from(wall.year()),
                    i64::from(wall.month()),
                    i64::from(wall.day()),
                    i64::from(wall.hour()),
                    i64::from(wall.minute()),
                    i64::from(wall.second()),
                    i64::from(wall.nanosecond()),
                    input.timestamp.semantic_kind().as_storage_str(),
                    input.timestamp.offset_kind().as_storage_str(),
                    input.timestamp.utc_offset_minutes().map(i64::from),
                    input.timestamp.utc_seconds_decimal(),
                    input.timestamp.utc_nanoseconds().map(i64::from),
                    i64::from(input.timestamp.precision_ns()),
                    input.confidence.as_storage_str(),
                    input.evidence_gate.as_storage_str(),
                    evidence_kinds_json,
                    source_keys_json,
                    lineage_keys_json,
                    observation_ordinals_json,
                    anomalies_json,
                    blockers_json,
                    input.created_at_ms,
                ],
            )?;
            let stored = self.transaction.query_row(
                "SELECT id, wall_year = ?3 AND wall_month = ?4 AND wall_day = ?5 \
                     AND wall_hour = ?6 AND wall_minute = ?7 AND wall_second = ?8 \
                     AND wall_nanosecond = ?9 AND semantic_kind = ?10 AND offset_kind = ?11 \
                     AND utc_offset_minutes IS ?12 AND utc_seconds_decimal IS ?13 \
                     AND utc_nanoseconds IS ?14 AND precision_ns = ?15 AND confidence = ?16 \
                     AND evidence_gate = ?17 AND evidence_kinds_json = ?18 \
                     AND source_keys_json = ?19 AND lineage_keys_json = ?20 \
                     AND observation_ordinals_json = ?21 AND anomalies_json = ?22 \
                     AND blockers_json = ?23 AND created_at_ms = ?24 \
                 FROM capture_time_candidates WHERE analysis_build_id = ?1 AND ordinal = ?2",
                params![
                    analysis_build_id,
                    input.ordinal,
                    i64::from(wall.year()),
                    i64::from(wall.month()),
                    i64::from(wall.day()),
                    i64::from(wall.hour()),
                    i64::from(wall.minute()),
                    i64::from(wall.second()),
                    i64::from(wall.nanosecond()),
                    input.timestamp.semantic_kind().as_storage_str(),
                    input.timestamp.offset_kind().as_storage_str(),
                    input.timestamp.utc_offset_minutes().map(i64::from),
                    input.timestamp.utc_seconds_decimal(),
                    input.timestamp.utc_nanoseconds().map(i64::from),
                    i64::from(input.timestamp.precision_ns()),
                    input.confidence.as_storage_str(),
                    input.evidence_gate.as_storage_str(),
                    evidence_kinds_json,
                    source_keys_json,
                    lineage_keys_json,
                    observation_ordinals_json,
                    anomalies_json,
                    blockers_json,
                    input.created_at_ms,
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?)),
            )?;
            if !stored.1 {
                return Err(StoreError::IdempotencyConflict {
                    entity: "capture_time_candidate",
                    key: format!("{analysis_build_id}:{}", input.ordinal),
                });
            }
            ids.push(stored.0);
        }
        Ok(ids)
    }

    fn append_capture_time_policy_issues_batch_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        inputs: &[CaptureTimePolicyIssueInput],
    ) -> Result<Vec<i64>> {
        self.validate_time_evidence_guard(guard)?;
        validate_time_batch("capture_time_policy_issues", inputs.len())?;
        require_draft_analysis_for_guard(self.transaction, guard, analysis_build_id)?;
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            validate_policy_issue_references(self.transaction, analysis_build_id, input)?;
            let observation_ordinals_json = serde_json::to_string(&input.observation_ordinals)?;
            let source_keys_json = serde_json::to_string(
                &input
                    .source_keys
                    .iter()
                    .map(|value| lower_hex(value.as_bytes()))
                    .collect::<Vec<_>>(),
            )?;
            let lineage_keys_json = serde_json::to_string(
                &input
                    .lineage_keys
                    .iter()
                    .map(|value| lower_hex(value.as_bytes()))
                    .collect::<Vec<_>>(),
            )?;
            self.transaction.execute(
                "INSERT INTO capture_time_policy_issues ( \
                     analysis_build_id, ordinal, issue_code, field_kind, \
                     observation_ordinals_json, source_keys_json, lineage_keys_json, context, \
                     created_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT(analysis_build_id, ordinal) DO NOTHING",
                params![
                    analysis_build_id,
                    input.ordinal,
                    input.code,
                    input.field_kind.map(|value| value.as_storage_str()),
                    observation_ordinals_json,
                    source_keys_json,
                    lineage_keys_json,
                    input.context,
                    input.created_at_ms,
                ],
            )?;
            let stored = self.transaction.query_row(
                "SELECT id, issue_code = ?3 AND field_kind IS ?4 \
                     AND observation_ordinals_json = ?5 AND source_keys_json = ?6 \
                     AND lineage_keys_json = ?7 AND context = ?8 AND created_at_ms = ?9 \
                 FROM capture_time_policy_issues \
                 WHERE analysis_build_id = ?1 AND ordinal = ?2",
                params![
                    analysis_build_id,
                    input.ordinal,
                    input.code,
                    input.field_kind.map(|value| value.as_storage_str()),
                    observation_ordinals_json,
                    source_keys_json,
                    lineage_keys_json,
                    input.context,
                    input.created_at_ms,
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?)),
            )?;
            if !stored.1 {
                return Err(StoreError::IdempotencyConflict {
                    entity: "capture_time_policy_issue",
                    key: format!("{analysis_build_id}:{}", input.ordinal),
                });
            }
            ids.push(stored.0);
        }
        Ok(ids)
    }

    fn append_capture_time_members_batch_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        inputs: &[CaptureTimeMemberAssessmentInput],
    ) -> Result<()> {
        let context = self.validate_time_evidence_guard(guard)?;
        validate_time_batch("capture_time_members", inputs.len())?;
        require_draft_analysis_for_guard(self.transaction, guard, analysis_build_id)?;
        let exact_group_build_id = self.transaction.query_row(
            "SELECT exact_group_build_id FROM capture_time_analysis_builds WHERE id = ?1",
            [analysis_build_id],
            |row| row.get::<_, i64>(0),
        )?;
        for input in inputs {
            let candidate = input
                .candidate_ordinal
                .map(|ordinal| {
                    self.transaction
                        .query_row(
                            "SELECT id, utc_seconds_decimal, utc_nanoseconds, precision_ns \
                             FROM capture_time_candidates \
                             WHERE analysis_build_id = ?1 AND ordinal = ?2 \
                               AND evidence_gate = 'eligible' AND semantic_kind = 'utc'",
                            params![analysis_build_id, ordinal],
                            |row| {
                                Ok(StoredMemberCandidate {
                                    id: row.get(0)?,
                                    utc_seconds_decimal: row.get(1)?,
                                    utc_nanoseconds: row.get(2)?,
                                    precision_ns: row.get(3)?,
                                })
                            },
                        )
                        .map_err(|error| match error {
                            rusqlite::Error::QueryReturnedNoRows => StoreError::invalid_input(
                                "member_candidate_ordinal",
                                "member candidate must be eligible UTC evidence in its analysis",
                            ),
                            other => StoreError::from(other),
                        })
                })
                .transpose()?;
            let candidate_id = candidate.as_ref().map(|candidate| candidate.id);
            let observation = self
                .transaction
                .query_row(
                    "SELECT observation.birth_time_seconds, observation.birth_time_nanoseconds, \
                            observation.modified_time_seconds, \
                            observation.modified_time_nanoseconds, \
                            observation.timestamp_granularity_ns \
                     FROM exact_group_build_members AS member \
                     JOIN media_observation_snapshots AS observation \
                       ON observation.id = member.media_observation_snapshot_id \
                      AND observation.volume_id = member.volume_id \
                      AND observation.scan_run_id = member.scan_run_id \
                     WHERE member.exact_group_build_id = ?1 AND member.ordinal = ?2 \
                       AND member.media_observation_snapshot_id = ?3",
                    params![
                        exact_group_build_id,
                        input.member_ordinal,
                        input.media_observation_snapshot_id,
                    ],
                    |row| {
                        Ok(StoredMemberObservation {
                            birth_time_seconds: row.get(0)?,
                            birth_time_nanoseconds: row.get(1)?,
                            modified_time_seconds: row.get(2)?,
                            modified_time_nanoseconds: row.get(3)?,
                            timestamp_granularity_ns: row.get(4)?,
                        })
                    },
                )
                .map_err(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::invalid_input(
                        "capture_time_member",
                        "assessment does not identify the exact member at its ordinal",
                    ),
                    other => StoreError::from(other),
                })?;
            validate_member_assessment_policy(input, candidate.as_ref(), &observation)?;
            let existing = self
                .transaction
                .query_row(
                    "SELECT media_observation_snapshot_id, candidate_id, birth_time_relation, \
                            modified_time_relation, donor_eligibility, reason_code, created_at_ms \
                     FROM capture_time_member_assessments \
                     WHERE analysis_build_id = ?1 AND member_ordinal = ?2",
                    params![analysis_build_id, input.member_ordinal],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing.0 != input.media_observation_snapshot_id
                    || existing.1 != candidate_id
                    || existing.2 != input.birth_time_relation.as_storage_str()
                    || existing.3 != input.modified_time_relation.as_storage_str()
                    || existing.4 != input.donor_eligibility.as_storage_str()
                    || existing.5 != input.reason_code
                    || existing.6 != input.created_at_ms
                {
                    return Err(StoreError::IdempotencyConflict {
                        entity: "capture_time_member",
                        key: format!("{analysis_build_id}:{}", input.member_ordinal),
                    });
                }
                continue;
            }
            self.transaction.execute(
                "INSERT INTO capture_time_member_assessments ( \
                     analysis_build_id, member_ordinal, volume_id, scan_run_id, \
                     exact_group_build_id, media_observation_snapshot_id, candidate_id, \
                     birth_time_relation, modified_time_relation, donor_eligibility, \
                     reason_code, created_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    analysis_build_id,
                    input.member_ordinal,
                    context.volume_id,
                    guard.run().scan_run_id,
                    exact_group_build_id,
                    input.media_observation_snapshot_id,
                    candidate_id,
                    input.birth_time_relation.as_storage_str(),
                    input.modified_time_relation.as_storage_str(),
                    input.donor_eligibility.as_storage_str(),
                    input.reason_code,
                    input.created_at_ms,
                ],
            )?;
        }
        Ok(())
    }

    fn append_capture_time_recommendation_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        input: &CaptureTimeRecommendationInput,
    ) -> Result<()> {
        let context = self.validate_time_evidence_guard(guard)?;
        require_draft_analysis_for_guard(self.transaction, guard, analysis_build_id)?;
        if input.keeper_observation_id.is_some()
            || input.time_donor_observation_id.is_some()
            || input.candidate_id.is_some()
            || input.keeper_policy_name.is_some()
            || input.keeper_policy_version.is_some()
            || input.time_donor_policy_name.is_some()
            || input.time_donor_policy_version.is_some()
        {
            return Err(StoreError::invalid_input(
                "capture_time_recommendation",
                "v7 has no keeper policy; keeper, donor, candidate, and policy identities must all be absent",
            ));
        }
        let exact_group_build_id = self.transaction.query_row(
            "SELECT exact_group_build_id FROM capture_time_analysis_builds WHERE id = ?1",
            [analysis_build_id],
            |row| row.get::<_, i64>(0),
        )?;
        let existing = self
            .transaction
            .query_row(
                "SELECT keeper_observation_id, time_donor_observation_id, candidate_id, \
                        keeper_policy_name, keeper_policy_version, time_donor_policy_name, \
                        time_donor_policy_version, evidence_only, write_authorized, reason_code, \
                        created_at_ms \
                 FROM capture_time_recommendations WHERE analysis_build_id = ?1",
                [analysis_build_id],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, i64>(10)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            return if existing.0.is_none()
                && existing.1.is_none()
                && existing.2.is_none()
                && existing.3.is_none()
                && existing.4.is_none()
                && existing.5.is_none()
                && existing.6.is_none()
                && existing.7 == 1
                && existing.8 == 0
                && existing.9 == input.reason_code
                && existing.10 == input.created_at_ms
            {
                Ok(())
            } else {
                Err(StoreError::IdempotencyConflict {
                    entity: "capture_time_recommendation",
                    key: analysis_build_id.to_string(),
                })
            };
        }
        self.transaction.execute(
            "INSERT INTO capture_time_recommendations ( \
                 analysis_build_id, volume_id, scan_run_id, exact_group_build_id, \
                 keeper_observation_id, time_donor_observation_id, candidate_id, \
                 keeper_policy_name, keeper_policy_version, time_donor_policy_name, \
                 time_donor_policy_version, evidence_only, write_authorized, reason_code, \
                 created_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1, 0, ?5, ?6)",
            params![
                analysis_build_id,
                context.volume_id,
                guard.run().scan_run_id,
                exact_group_build_id,
                input.reason_code,
                input.created_at_ms,
            ],
        )?;
        Ok(())
    }

    fn seal_capture_time_analysis_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        decision: CaptureTimeDecision,
        selected_candidate_ordinal: Option<i64>,
        finalized_at_ms: i64,
    ) -> Result<TimeEvidenceManifestDigest> {
        self.validate_time_evidence_guard(guard)?;
        require_positive("analysis_build_id", analysis_build_id)?;
        require_nonnegative("finalized_at_ms", finalized_at_ms)?;
        let selected_required = matches!(
            decision,
            CaptureTimeDecision::ReviewRequired | CaptureTimeDecision::EvidenceEligible
        );
        if selected_required != selected_candidate_ordinal.is_some()
            || selected_candidate_ordinal.is_some_and(|ordinal| ordinal < 0)
        {
            return Err(StoreError::invalid_input(
                "selected_candidate_ordinal",
                "review/evidence decisions require one non-negative candidate ordinal; conflict/no-evidence decisions forbid it",
            ));
        }
        let build = self.transaction.query_row(
            "SELECT build.time_session_id, build.exact_group_build_id, build.scan_run_id, \
                    time_session.core_session_id, build.expected_source_count, \
                    build.expected_observation_count, build.expected_candidate_count, \
                    build.expected_issue_count, build.expected_member_count, \
                    build.expected_recommendation_count, build.expected_manifest_digest, \
                    build.sealed_manifest_digest, build.state, build.decision, \
                    build.selected_candidate_ordinal, build.created_at_ms, build.finalized_at_ms \
             FROM capture_time_analysis_builds AS build \
             JOIN scan_time_sessions AS time_session ON time_session.id = build.time_session_id \
             WHERE build.id = ?1",
            [analysis_build_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, Option<Vec<u8>>>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<i64>>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, Option<i64>>(16)?,
                ))
            },
        )?;
        if build.2 != guard.run().scan_run_id
            || build.3.as_slice() != guard.core_session_id().as_bytes()
        {
            return Err(StoreError::ConcurrencyConflict {
                entity: "capture_time_analysis_guard",
                id: analysis_build_id,
            });
        }
        validate_capture_time_candidate_supports_for_analysis(
            self.transaction,
            Some(analysis_build_id),
        )?;
        let latest_child_ms =
            latest_capture_time_analysis_child_ms(self.transaction, analysis_build_id)?;
        let latest_group_evidence_ms =
            latest_time_group_terminal_evidence_ms(self.transaction, build.0, build.1)?;
        let latest_evidence_ms = latest_child_ms.max(latest_group_evidence_ms);
        let expected =
            TimeEvidenceManifestDigest::from_runtime_evidence(fixed_32_from_sql(build.10, 10)?);
        let observed =
            recompute_capture_time_analysis_manifest(self.transaction, analysis_build_id)?;
        if build.12 == "sealed" {
            let outcome_matches = self.transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_time_group_outcomes \
                               WHERE time_session_id = ?1 AND exact_group_build_id = ?2 \
                                 AND outcome = 'evidence' AND analysis_build_id = ?3 \
                                 AND reason_code = 'sealed_analysis_evidence' \
                                 AND created_at_ms = ?4)",
                params![build.0, build.1, analysis_build_id, finalized_at_ms],
                |row| row.get::<_, bool>(0),
            )?;
            if build.16.is_none() || build.16.is_some_and(|value| value < latest_evidence_ms) {
                return Err(StoreError::invalid_input(
                    "capture_time_analysis_chronology",
                    "sealed analysis predates retained child or group evidence",
                ));
            }
            return if build.13.as_deref() == Some(decision.as_storage_str())
                && build.14 == selected_candidate_ordinal
                && build.16 == Some(finalized_at_ms)
                && build
                    .11
                    .as_deref()
                    .is_some_and(|digest| digest == expected.as_bytes())
                && observed == expected
                && outcome_matches
            {
                Ok(observed)
            } else {
                Err(StoreError::IdempotencyConflict {
                    entity: "capture_time_analysis_seal",
                    key: analysis_build_id.to_string(),
                })
            };
        }
        if build.12 != "draft" {
            return Err(StoreError::ConcurrencyConflict {
                entity: "draft_capture_time_analysis",
                id: analysis_build_id,
            });
        }
        if finalized_at_ms < latest_evidence_ms {
            return Err(StoreError::invalid_input(
                "finalized_at_ms",
                "analysis finalization predates retained child or group evidence",
            ));
        }
        require_draft_analysis_for_guard(self.transaction, guard, analysis_build_id)?;
        let counts = self.transaction.query_row(
            "SELECT \
                 (SELECT count(*) FROM capture_time_analysis_sources WHERE analysis_build_id = ?1), \
                 (SELECT count(*) FROM capture_time_observations WHERE analysis_build_id = ?1), \
                 (SELECT count(*) FROM capture_time_candidates WHERE analysis_build_id = ?1), \
                 (SELECT count(*) FROM capture_time_policy_issues WHERE analysis_build_id = ?1), \
                 (SELECT count(*) FROM capture_time_member_assessments WHERE analysis_build_id = ?1), \
                 (SELECT count(*) FROM capture_time_recommendations WHERE analysis_build_id = ?1)",
            [analysis_build_id],
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
        )?;
        if counts != (build.4, build.5, build.6, build.7, build.8, build.9) {
            return Err(StoreError::invalid_input(
                "capture_time_analysis_counts",
                "database evidence counts do not match the frozen analysis header",
            ));
        }
        if let Some(ordinal) = selected_candidate_ordinal {
            let eligible = self
                .transaction
                .query_row(
                    "SELECT evidence_gate = 'eligible' FROM capture_time_candidates \
                 WHERE analysis_build_id = ?1 AND ordinal = ?2",
                    params![analysis_build_id, ordinal],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::invalid_input(
                        "selected_candidate_ordinal",
                        "selected candidate is absent from the analysis",
                    ),
                    other => StoreError::from(other),
                })?;
            if decision == CaptureTimeDecision::EvidenceEligible && !eligible {
                return Err(StoreError::invalid_input(
                    "selected_candidate_ordinal",
                    "evidence-eligible decision requires an eligible selected candidate",
                ));
            }
        }
        if observed != expected {
            return Err(StoreError::invalid_input(
                "capture_time_analysis_manifest",
                "database-streamed analysis manifest differs from the frozen expected digest",
            ));
        }
        let changed = self.transaction.execute(
            "UPDATE capture_time_analysis_builds \
             SET state = 'sealed', decision = ?2, selected_candidate_ordinal = ?3, \
                 sealed_manifest_digest = ?4, finalized_at_ms = ?5 \
             WHERE id = ?1 AND state = 'draft'",
            params![
                analysis_build_id,
                decision.as_storage_str(),
                selected_candidate_ordinal,
                observed.as_bytes().as_slice(),
                finalized_at_ms,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "capture_time_analysis_seal",
                id: analysis_build_id,
            });
        }
        self.transaction.execute(
            "INSERT INTO capture_time_group_outcomes ( \
                 time_session_id, exact_group_build_id, volume_id, scan_run_id, outcome, \
                 analysis_build_id, reason_code, created_at_ms \
             ) SELECT time_session_id, exact_group_build_id, volume_id, scan_run_id, \
                      'evidence', id, 'sealed_analysis_evidence', ?2 \
               FROM capture_time_analysis_builds WHERE id = ?1",
            params![analysis_build_id, finalized_at_ms],
        )?;
        Ok(observed)
    }

    fn abandon_capture_time_analysis_impl(
        &mut self,
        guard: &TimeEvidenceGuard,
        analysis_build_id: i64,
        abandoned_at_ms: i64,
        reason_code: &str,
        reason_message: Option<&str>,
    ) -> Result<()> {
        self.validate_time_evidence_guard(guard)?;
        require_positive("analysis_build_id", analysis_build_id)?;
        require_nonnegative("abandoned_at_ms", abandoned_at_ms)?;
        require_bounded_nonempty("reason_code", reason_code, 256)?;
        validate_optional_bounded("reason_message", reason_message, MAX_TEXT_BYTES)?;
        let stored = self.transaction.query_row(
            "SELECT build.time_session_id, build.exact_group_build_id, build.scan_run_id, \
                    time_session.core_session_id, build.state, build.abandon_reason_code, \
                    build.abandon_reason_message, build.created_at_ms, build.finalized_at_ms \
             FROM capture_time_analysis_builds AS build \
             JOIN scan_time_sessions AS time_session ON time_session.id = build.time_session_id \
             WHERE build.id = ?1",
            [analysis_build_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            },
        )?;
        if stored.2 != guard.run().scan_run_id
            || stored.3.as_slice() != guard.core_session_id().as_bytes()
        {
            return Err(StoreError::ConcurrencyConflict {
                entity: "capture_time_analysis_guard",
                id: analysis_build_id,
            });
        }
        let latest_child_ms =
            latest_capture_time_analysis_child_ms(self.transaction, analysis_build_id)?;
        let latest_group_evidence_ms =
            latest_time_group_terminal_evidence_ms(self.transaction, stored.0, stored.1)?;
        let latest_evidence_ms = latest_child_ms.max(latest_group_evidence_ms);
        if stored.4 == "abandoned" {
            let outcome_matches = self.transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_time_group_outcomes \
                               WHERE time_session_id = ?1 AND exact_group_build_id = ?2 \
                                 AND outcome = 'failed' AND analysis_build_id IS NULL \
                                 AND reason_code = ?3 AND created_at_ms = ?4)",
                params![stored.0, stored.1, reason_code, abandoned_at_ms],
                |row| row.get::<_, bool>(0),
            )?;
            if stored.8.is_none() || stored.8.is_some_and(|value| value < latest_evidence_ms) {
                return Err(StoreError::invalid_input(
                    "capture_time_analysis_chronology",
                    "abandoned analysis predates retained child or group evidence",
                ));
            }
            return if stored.5.as_deref() == Some(reason_code)
                && stored.6.as_deref() == reason_message
                && stored.8 == Some(abandoned_at_ms)
                && outcome_matches
            {
                Ok(())
            } else {
                Err(StoreError::IdempotencyConflict {
                    entity: "capture_time_analysis_abandonment",
                    key: analysis_build_id.to_string(),
                })
            };
        }
        if stored.4 != "draft" {
            return Err(StoreError::ConcurrencyConflict {
                entity: "draft_capture_time_analysis",
                id: analysis_build_id,
            });
        }
        if abandoned_at_ms < latest_evidence_ms {
            return Err(StoreError::invalid_input(
                "abandoned_at_ms",
                "analysis abandonment predates retained child or group evidence",
            ));
        }
        require_draft_analysis_for_guard(self.transaction, guard, analysis_build_id)?;
        let changed = self.transaction.execute(
            "UPDATE capture_time_analysis_builds \
             SET state = 'abandoned', abandon_reason_code = ?2, \
                 abandon_reason_message = ?3, finalized_at_ms = ?4 \
             WHERE id = ?1 AND state = 'draft'",
            params![
                analysis_build_id,
                reason_code,
                reason_message,
                abandoned_at_ms
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "capture_time_analysis_abandonment",
                id: analysis_build_id,
            });
        }
        self.transaction.execute(
            "INSERT INTO capture_time_group_outcomes ( \
                 time_session_id, exact_group_build_id, volume_id, scan_run_id, outcome, \
                 analysis_build_id, reason_code, created_at_ms \
             ) SELECT time_session_id, exact_group_build_id, volume_id, scan_run_id, \
                      'failed', NULL, ?2, ?3 \
               FROM capture_time_analysis_builds WHERE id = ?1",
            params![analysis_build_id, reason_code, abandoned_at_ms],
        )?;
        Ok(())
    }

    fn register_namespace_profile_impl(&mut self, input: &NamespaceProfileInput) -> Result<i64> {
        validate_namespace_profile(input)?;
        let bound_mount_session_key = input
            .bound_mount_session_key
            .map(MountSessionKey::to_storage_hex);
        let volume_strength = self.transaction.query_row(
            "SELECT identity_strength FROM volumes WHERE id = ?1",
            [input.volume_id],
            |row| row.get::<_, String>(0),
        )?;
        if input.reuse_scope == "cross_session" && volume_strength != "strong" {
            return Err(StoreError::invalid_input(
                "reuse_scope",
                "cross-session namespace reuse requires a strong volume identity",
            ));
        }

        let existing = self
            .transaction
            .query_row(
                "SELECT id, profile_version, origin, native_path_encoding, case_behavior, \
                        unicode_behavior, key_strategy, key_algorithm_version, reuse_scope, \
                        bound_mount_session_key, legacy_capability_profile_id, created_at_ms \
                 FROM namespace_profiles \
                 WHERE volume_id = ?1 AND profile_key = ?2 \
                   AND bound_mount_session_key IS ?3",
                params![
                    input.volume_id,
                    input.profile_key.as_bytes().as_slice(),
                    bound_mount_session_key,
                ],
                |row| {
                    Ok(StoredNamespaceProfile {
                        id: row.get(0)?,
                        profile_version: row.get(1)?,
                        origin: row.get(2)?,
                        native_path_encoding: row.get(3)?,
                        case_behavior: row.get(4)?,
                        unicode_behavior: row.get(5)?,
                        key_strategy: row.get(6)?,
                        key_algorithm_version: row.get(7)?,
                        reuse_scope: row.get(8)?,
                        bound_mount_session_key: row.get(9)?,
                        legacy_capability_profile_id: row.get(10)?,
                        created_at_ms: row.get(11)?,
                    })
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            let matches = existing.profile_version == input.profile_version
                && existing.origin == "observed_v5"
                && existing.native_path_encoding.as_deref()
                    == Some(input.native_path_encoding.as_str())
                && existing.case_behavior.as_deref() == Some(input.case_behavior.as_str())
                && existing.unicode_behavior.as_deref() == Some(input.unicode_behavior.as_str())
                && existing.key_strategy.as_deref() == Some(input.key_strategy.as_str())
                && existing.key_algorithm_version == Some(input.key_algorithm_version)
                && existing.reuse_scope == input.reuse_scope
                && existing.bound_mount_session_key == bound_mount_session_key
                && existing.legacy_capability_profile_id.is_none()
                && existing.created_at_ms == input.created_at_ms;
            if !matches {
                return Err(StoreError::IdempotencyConflict {
                    entity: "namespace_profile",
                    key: hex_hash(input.profile_key.as_bytes()),
                });
            }
            return Ok(existing.id);
        }

        self.transaction.execute(
            "INSERT INTO namespace_profiles ( \
                 volume_id, profile_key, profile_version, origin, native_path_encoding, \
                 case_behavior, unicode_behavior, key_strategy, key_algorithm_version, \
                 reuse_scope, bound_mount_session_key, legacy_capability_profile_id, created_at_ms \
             ) VALUES (?1, ?2, ?3, 'observed_v5', ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11)",
            params![
                input.volume_id,
                input.profile_key.as_bytes().as_slice(),
                input.profile_version,
                input.native_path_encoding,
                input.case_behavior,
                input.unicode_behavior,
                input.key_strategy,
                input.key_algorithm_version,
                input.reuse_scope,
                bound_mount_session_key,
                input.created_at_ms,
            ],
        )?;
        Ok(self.transaction.last_insert_rowid())
    }

    fn create_scoped_scan_job_impl(&mut self, input: &NewScopedScanJob) -> Result<i64> {
        validate_scoped_scan_job(input)?;
        let config_json = serialize_optional_json("config", &input.config, MAX_JSON_BYTES)?;
        let (reuse_scope, identity_strength, key_algorithm_version): (String, String, i64) =
            self.transaction.query_row(
                "SELECT namespace.reuse_scope, volume.identity_strength, \
                        namespace.key_algorithm_version \
                 FROM namespace_profiles AS namespace \
                 JOIN volumes AS volume ON volume.id = namespace.volume_id \
                 WHERE namespace.id = ?1 AND namespace.volume_id = ?2 \
                   AND namespace.origin = 'observed_v5' \
                   AND namespace.profile_key IS NOT NULL \
                   AND namespace.native_path_encoding IS NOT NULL \
                   AND namespace.key_strategy IS NOT NULL \
                   AND namespace.key_algorithm_version IS NOT NULL \
                   AND ((namespace.reuse_scope = 'cross_session' \
                         AND namespace.bound_mount_session_key IS NULL) \
                     OR (namespace.reuse_scope = 'current_session_only' \
                         AND length(namespace.bound_mount_session_key) = 64 \
                         AND namespace.bound_mount_session_key = lower(namespace.bound_mount_session_key) \
                         AND namespace.bound_mount_session_key NOT GLOB '*[^0-9a-f]*'))",
                params![input.namespace_profile_id, input.volume_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        let recoverable = reuse_scope == "cross_session" && identity_strength == "strong";

        let existing = self
            .transaction
            .query_row(
                "SELECT job.id, job.volume_id, job.root_relative_path, job.root_path_key, \
                        job.config_json, job.created_at_ms, scope.namespace_profile_id, \
                        scope.origin, scope.root_display, scope.mount_relative_root_raw, \
                        scope.path_encoding, scope.stable_root_path_key, scope.root_scope_key, \
                        scope.legacy_semantic_path_key, scope.recoverable, scope.created_at_ms \
                 FROM scan_jobs AS job \
                 LEFT JOIN scan_job_scopes AS scope ON scope.scan_job_id = job.id \
                 WHERE job.job_key = ?1",
                [&input.job_key],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<Vec<u8>>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, Option<Vec<u8>>>(11)?,
                        row.get::<_, Option<Vec<u8>>>(12)?,
                        row.get::<_, Option<Vec<u8>>>(13)?,
                        row.get::<_, Option<i64>>(14)?,
                        row.get::<_, Option<i64>>(15)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            let matches = existing.1 == input.volume_id
                && existing.2 == input.root_display
                && existing.3.as_slice() == input.stable_root_path_key.as_bytes()
                && existing.4.as_deref() == config_json.as_deref()
                && existing.5 == input.created_at_ms
                && existing.6 == Some(input.namespace_profile_id)
                && existing.7.as_deref() == Some("observed_v5")
                && existing.8.as_deref() == Some(input.root_display.as_str())
                && existing.9.as_deref() == Some(input.mount_relative_root_raw.as_slice())
                && existing.10.as_deref() == Some(input.path_encoding.as_str())
                && existing.11.as_deref() == Some(input.stable_root_path_key.as_bytes().as_slice())
                && existing.12.as_deref() == Some(input.root_scope_key.as_bytes().as_slice())
                && existing.13.is_none()
                && existing.14 == Some(i64::from(recoverable))
                && existing.15 == Some(input.created_at_ms);
            if !matches {
                return Err(StoreError::IdempotencyConflict {
                    entity: "scoped_scan_job",
                    key: input.job_key.clone(),
                });
            }
            return Ok(existing.0);
        }

        self.transaction.execute(
            "INSERT INTO scan_jobs ( \
                 job_key, volume_id, root_relative_path, root_path_key, state, config_json, \
                 active_scan_run_id, state_version, created_at_ms, updated_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, 'queued', ?5, NULL, 0, ?6, ?6)",
            params![
                input.job_key,
                input.volume_id,
                input.root_display,
                input.stable_root_path_key.as_bytes().as_slice(),
                config_json,
                input.created_at_ms,
            ],
        )?;
        let job_id = self.transaction.last_insert_rowid();
        self.transaction.execute(
            "INSERT INTO scan_job_roots ( \
                 scan_job_id, volume_id, capability_profile_id, path_semantics_version, \
                 relative_path_raw, path_encoding, semantic_path_key, created_at_ms \
             ) VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7)",
            params![
                job_id,
                input.volume_id,
                key_algorithm_version,
                input.mount_relative_root_raw,
                input.path_encoding,
                input.stable_root_path_key.as_bytes().as_slice(),
                input.created_at_ms,
            ],
        )?;
        self.transaction.execute(
            "INSERT INTO scan_job_scopes ( \
                 scan_job_id, volume_id, namespace_profile_id, origin, root_display, \
                 mount_relative_root_raw, path_encoding, stable_root_path_key, root_scope_key, \
                 legacy_semantic_path_key, recoverable, created_at_ms \
             ) VALUES (?1, ?2, ?3, 'observed_v5', ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10)",
            params![
                job_id,
                input.volume_id,
                input.namespace_profile_id,
                input.root_display,
                input.mount_relative_root_raw,
                input.path_encoding,
                input.stable_root_path_key.as_bytes().as_slice(),
                input.root_scope_key.as_bytes().as_slice(),
                i64::from(recoverable),
                input.created_at_ms,
            ],
        )?;
        Ok(job_id)
    }

    fn create_bound_scan_run_impl(&mut self, input: &NewBoundScanRun) -> Result<i64> {
        validate_bound_scan_run(input)?;
        let config_json = serialize_optional_json("config", &input.config, MAX_JSON_BYTES)?;
        let mount_session_hex = input.mount_session_key.to_storage_hex();
        let stored_scope = self.transaction.query_row(
            "SELECT job.volume_id, scope.root_display, job.state, job.active_scan_run_id, \
                    scope.namespace_profile_id, scope.mount_relative_root_raw, \
                    scope.path_encoding, scope.stable_root_path_key, scope.root_scope_key, \
                    scope.recoverable, namespace.reuse_scope, \
                    namespace.bound_mount_session_key, volume.identity_strength \
             FROM scan_jobs AS job \
             JOIN scan_job_scopes AS scope ON scope.scan_job_id = job.id \
             JOIN namespace_profiles AS namespace \
               ON namespace.id = scope.namespace_profile_id \
              AND namespace.volume_id = scope.volume_id \
             JOIN volumes AS volume ON volume.id = job.volume_id \
             WHERE job.id = ?1 AND scope.origin = 'observed_v5'",
            [input.scan_job_id],
            |row| {
                Ok(StoredScopedJob {
                    volume_id: row.get(0)?,
                    root_display: row.get(1)?,
                    state: row.get(2)?,
                    active_scan_run_id: row.get(3)?,
                    namespace_profile_id: row.get(4)?,
                    scope_raw: row.get(5)?,
                    scope_encoding: row.get(6)?,
                    scope_stable_key: row.get(7)?,
                    scope_root_key: row.get(8)?,
                    recoverable: row.get(9)?,
                    reuse_scope: row.get(10)?,
                    bound_mount_session_key: row.get(11)?,
                    identity_strength: row.get(12)?,
                })
            },
        )?;
        if stored_scope.volume_id != input.volume_id
            || stored_scope.scope_raw != input.mount_relative_root_raw
            || stored_scope.scope_encoding != input.path_encoding
            || stored_scope.scope_stable_key.as_slice() != input.stable_root_path_key.as_bytes()
            || stored_scope.scope_root_key.as_slice() != input.root_scope_key.as_bytes()
        {
            return Err(StoreError::IdempotencyConflict {
                entity: "bound_scan_run_scope",
                key: input.run_key.clone(),
            });
        }
        let namespace_mount_matches = match stored_scope.reuse_scope.as_str() {
            "cross_session" => stored_scope.bound_mount_session_key.is_none(),
            "current_session_only" => {
                stored_scope.bound_mount_session_key.as_deref() == Some(&mount_session_hex)
            }
            _ => false,
        };
        if !namespace_mount_matches {
            return Err(StoreError::ConcurrencyConflict {
                entity: "bound_run_namespace_mount_session",
                id: input.scan_job_id,
            });
        }
        if let Some(existing_id) = self.find_existing_bound_scan_run(
            input,
            &stored_scope,
            config_json.as_deref(),
            &mount_session_hex,
        )? {
            return Ok(existing_id);
        }

        let attempt_count: i64 = self.transaction.query_row(
            "SELECT count(*) FROM scan_job_runs WHERE scan_job_id = ?1",
            [input.scan_job_id],
            |row| row.get(0),
        )?;
        if attempt_count > 0
            && (stored_scope.recoverable != 1
                || stored_scope.reuse_scope != "cross_session"
                || stored_scope.identity_strength != "strong")
        {
            return Err(StoreError::invalid_input(
                "scan_job_id",
                "a subsequent run requires a recoverable strong cross-session scope",
            ));
        }
        if attempt_count > 0 && input.parent_scan_run_id.is_none() {
            return Err(StoreError::invalid_input(
                "parent_scan_run_id",
                "a subsequent run must identify its terminal predecessor",
            ));
        }
        if attempt_count > 0 && input.parent_scan_run_id != stored_scope.active_scan_run_id {
            return Err(StoreError::IdempotencyConflict {
                entity: "bound_scan_run_parent_lineage",
                key: input.run_key.clone(),
            });
        }
        if !matches!(
            stored_scope.state.as_str(),
            "queued" | "failed" | "completed" | "cancelled"
        ) {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scoped_scan_job_state",
                id: input.scan_job_id,
            });
        }
        if let Some(active_run_id) = stored_scope.active_scan_run_id {
            let replaceable = self.transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM scan_runs \
                 WHERE id = ?1 AND state IN ('failed', 'interrupted', 'completed', 'cancelled'))",
                [active_run_id],
                |row| row.get::<_, bool>(0),
            )?;
            if !replaceable {
                return Err(StoreError::ConcurrencyConflict {
                    entity: "scoped_scan_job_active_run",
                    id: active_run_id,
                });
            }
        }

        let path_semantics_version: i64 = self
            .transaction
            .query_row(
                "SELECT path_semantics_version FROM capability_profiles \
             WHERE id = ?1 AND volume_id = ?2 AND profile_hash_version = 2 \
               AND is_current = 1 AND probe_status = 'complete' AND can_read = 1 \
               AND mount_session_key = ?3 AND length(mount_session_key) = 64 \
               AND mount_session_key = lower(mount_session_key) \
               AND mount_session_key NOT GLOB '*[^0-9a-f]*' \
               AND probe_protocol_version IS NOT NULL \
               AND path_encoding_family IS NOT NULL \
               AND ((path_encoding_family = 'unix' AND ?4 IN ('utf8', 'unix_bytes')) \
                 OR (path_encoding_family = 'windows' AND ?4 = 'windows_utf16_le'))",
                params![
                    input.capability_profile_id,
                    input.volume_id,
                    mount_session_hex,
                    input.path_encoding,
                ],
                |row| row.get(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StoreError::ConcurrencyConflict {
                    entity: "bound_run_capability_profile",
                    id: input.capability_profile_id,
                },
                other => StoreError::from(other),
            })?;

        validate_bound_run_parent(
            self.transaction,
            input,
            stored_scope.namespace_profile_id,
            input.root_scope_key.as_bytes(),
        )?;
        self.transaction.execute(
            "INSERT INTO scan_runs ( \
                 run_key, volume_id, capability_profile_id, parent_scan_run_id, \
                 root_relative_path, root_path_key, scan_mode, state, config_json, \
                 discovered_count, fingerprinted_count, error_count, logical_bytes_seen, \
                 created_at_ms, updated_at_ms, state_version \
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', ?8, 0, 0, 0, 0, ?9, ?9, 0)",
            params![
                input.run_key,
                input.volume_id,
                input.capability_profile_id,
                input.parent_scan_run_id,
                stored_scope.root_display,
                input.stable_root_path_key.as_bytes().as_slice(),
                input.scan_mode,
                config_json,
                input.created_at_ms,
            ],
        )?;
        let run_id = self.transaction.last_insert_rowid();
        let attempt_number = attempt_count
            .checked_add(1)
            .ok_or_else(|| StoreError::invalid_input("attempt_number", "attempt count overflow"))?;
        self.transaction.execute(
            "INSERT INTO scan_run_roots ( \
                 scan_run_id, volume_id, capability_profile_id, path_semantics_version, \
                 relative_path_raw, path_encoding, semantic_path_key, created_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                run_id,
                input.volume_id,
                input.capability_profile_id,
                path_semantics_version,
                input.mount_relative_root_raw,
                input.path_encoding,
                input.stable_root_path_key.as_bytes().as_slice(),
                input.created_at_ms,
            ],
        )?;
        self.transaction.execute(
            "INSERT INTO scan_job_runs ( \
                 scan_job_id, scan_run_id, volume_id, attempt_number, created_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                input.scan_job_id,
                run_id,
                input.volume_id,
                attempt_number,
                input.created_at_ms,
            ],
        )?;
        self.transaction.execute(
            "INSERT INTO scan_run_sessions ( \
                 scan_run_id, scan_job_id, volume_id, capability_profile_id, \
                 namespace_profile_id, mount_session_key, mount_relative_root_raw, \
                 path_encoding, stable_root_path_key, root_scope_key, root_object_signature, \
                 created_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                run_id,
                input.scan_job_id,
                input.volume_id,
                input.capability_profile_id,
                stored_scope.namespace_profile_id,
                mount_session_hex,
                input.mount_relative_root_raw,
                input.path_encoding,
                input.stable_root_path_key.as_bytes().as_slice(),
                input.root_scope_key.as_bytes().as_slice(),
                input.root_object_signature.as_bytes().as_slice(),
                input.created_at_ms,
            ],
        )?;
        let changed = self.transaction.execute(
            "UPDATE scan_jobs SET active_scan_run_id = ?2, updated_at_ms = MAX(updated_at_ms, ?3) \
                 WHERE id = ?1 AND state IN ('queued', 'failed', 'completed', 'cancelled')",
            params![input.scan_job_id, run_id, input.created_at_ms],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scoped_scan_job_binding",
                id: input.scan_job_id,
            });
        }
        Ok(run_id)
    }

    fn find_existing_bound_scan_run(
        &self,
        input: &NewBoundScanRun,
        scope: &StoredScopedJob,
        config_json: Option<&str>,
        mount_session_hex: &str,
    ) -> Result<Option<i64>> {
        let existing = self
            .transaction
            .query_row(
                "SELECT run.id, run.volume_id, run.capability_profile_id, run.parent_scan_run_id, \
                        run.root_relative_path, run.root_path_key, run.scan_mode, run.config_json, \
                        run.created_at_ms, session.scan_job_id, session.namespace_profile_id, \
                        session.mount_session_key, session.mount_relative_root_raw, \
                        session.path_encoding, session.stable_root_path_key, \
                        session.root_scope_key, session.root_object_signature, session.created_at_ms \
                 FROM scan_runs AS run \
                 LEFT JOIN scan_run_sessions AS session ON session.scan_run_id = run.id \
                 WHERE run.run_key = ?1",
                [&input.run_key],
                |row| {
                    Ok(StoredBoundScanRun {
                        id: row.get(0)?,
                        volume_id: row.get(1)?,
                        capability_profile_id: row.get(2)?,
                        parent_scan_run_id: row.get(3)?,
                        root_display: row.get(4)?,
                        stable_root_path_key: row.get(5)?,
                        scan_mode: row.get(6)?,
                        config_json: row.get(7)?,
                        created_at_ms: row.get(8)?,
                        scan_job_id: row.get(9)?,
                        namespace_profile_id: row.get(10)?,
                        mount_session_key: row.get(11)?,
                        mount_relative_root_raw: row.get(12)?,
                        path_encoding: row.get(13)?,
                        session_stable_root_path_key: row.get(14)?,
                        root_scope_key: row.get(15)?,
                        root_object_signature: row.get(16)?,
                        session_created_at_ms: row.get(17)?,
                    })
                },
            )
            .optional()?;
        let Some(existing) = existing else {
            return Ok(None);
        };
        let matches = existing.volume_id == input.volume_id
            && existing.capability_profile_id == input.capability_profile_id
            && existing.parent_scan_run_id == input.parent_scan_run_id
            && existing.root_display == scope.root_display
            && existing.stable_root_path_key.as_slice() == input.stable_root_path_key.as_bytes()
            && existing.scan_mode == input.scan_mode
            && existing.config_json.as_deref() == config_json
            && existing.created_at_ms == input.created_at_ms
            && existing.scan_job_id == Some(input.scan_job_id)
            && existing.namespace_profile_id == Some(scope.namespace_profile_id)
            && existing.mount_session_key.as_deref() == Some(mount_session_hex)
            && existing.mount_relative_root_raw.as_deref()
                == Some(input.mount_relative_root_raw.as_slice())
            && existing.path_encoding.as_deref() == Some(input.path_encoding.as_str())
            && existing.session_stable_root_path_key.as_deref()
                == Some(input.stable_root_path_key.as_bytes().as_slice())
            && existing.root_scope_key.as_deref()
                == Some(input.root_scope_key.as_bytes().as_slice())
            && existing.root_object_signature.as_deref()
                == Some(input.root_object_signature.as_bytes().as_slice())
            && existing.session_created_at_ms == Some(input.created_at_ms);
        if !matches {
            return Err(StoreError::IdempotencyConflict {
                entity: "bound_scan_run",
                key: input.run_key.clone(),
            });
        }
        Ok(Some(existing.id))
    }

    fn record_observation_batch_impl(
        &mut self,
        guard: &RunEvidenceGuard,
        inputs: &[ObservationInput],
    ) -> Result<Vec<i64>> {
        validate_v5_batch("observations", inputs.len())?;
        let context = self.validate_v5_run_guard(guard)?;
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            validate_observation(input, context.path_encoding.as_str())?;
            validate_observation_path_binding(&context, input)?;
            ids.push(self.record_one_observation(&context, input)?);
        }
        Ok(ids)
    }

    fn bind_core_session_impl(
        &mut self,
        guard: &RunEvidenceGuard,
        input: &CoreSessionInput,
    ) -> Result<()> {
        let context = self.validate_v5_run_guard(guard)?;
        require_nonnegative("bound_at_ms", input.bound_at_ms)?;
        let existing = self
            .transaction
            .query_row(
                "SELECT volume_id, capability_profile_id, namespace_profile_id, \
                        core_session_id, trust_scope, engine_contract_version, root_index, \
                        root_kind, root_object_signature, root_source_signature, bound_at_ms \
                 FROM scan_core_sessions WHERE scan_run_id = ?1",
                params![guard.scan_run_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                        row.get::<_, i64>(10)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            let matches = existing.0 == context.volume_id
                && existing.1 == context.capability_profile_id
                && existing.2 == context.namespace_profile_id
                && existing.3.as_slice() == input.core_session_id.as_bytes()
                && existing.4 == "current_core_session_only"
                && existing.5 == 1
                && existing.6 == 0
                && existing.7 == "directory"
                && existing.8.as_slice() == input.root_object_signature.as_bytes()
                && existing.9.as_slice() == input.root_source_signature.as_bytes()
                && existing.10 == input.bound_at_ms;
            if matches {
                self.bound_core_sessions
                    .push((guard.scan_run_id, input.core_session_id.into_bytes()));
                return Ok(());
            }
            return Err(StoreError::IdempotencyConflict {
                entity: "core_scan_session",
                key: guard.scan_run_id.to_string(),
            });
        }

        self.transaction.execute(
            "INSERT INTO scan_core_sessions ( \
                 scan_run_id, volume_id, capability_profile_id, namespace_profile_id, \
                 core_session_id, trust_scope, engine_contract_version, root_index, root_kind, \
                 root_object_signature, root_source_signature, bound_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'current_core_session_only', 1, 0, \
                       'directory', ?6, ?7, ?8)",
            params![
                guard.scan_run_id,
                context.volume_id,
                context.capability_profile_id,
                context.namespace_profile_id,
                input.core_session_id.as_bytes().as_slice(),
                input.root_object_signature.as_bytes().as_slice(),
                input.root_source_signature.as_bytes().as_slice(),
                input.bound_at_ms,
            ],
        )?;
        self.bound_core_sessions
            .push((guard.scan_run_id, input.core_session_id.into_bytes()));
        Ok(())
    }

    fn record_core_observation_batch_impl(
        &mut self,
        guard: &RunEvidenceGuard,
        core_session_id: &CoreSessionId,
        inputs: &[CoreFileObservationInput],
    ) -> Result<Vec<i64>> {
        validate_v5_batch("core_file_observations", inputs.len())?;
        let context = self.validate_core_session_guard(guard, core_session_id)?;
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            validate_observation(&input.observation, context.path_encoding.as_str())?;
            validate_observation_path_binding(&context, &input.observation)?;
            validate_opaque_ticket(&input.ticket_blob)?;
            require_nonnegative("ticket_created_at_ms", input.ticket_created_at_ms)?;
            if input.ticket_created_at_ms < input.observation.observed_at_ms {
                return Err(StoreError::invalid_input(
                    "ticket_created_at_ms",
                    "file ticket cannot predate its observation",
                ));
            }
            let observation_id = self.record_one_observation(&context, &input.observation)?;
            let existing = self
                .transaction
                .query_row(
                    "SELECT volume_id, scan_run_id, core_session_id, source_signature, \
                            ticket_format_version, ticket_blob, ticket_sort_key, created_at_ms \
                     FROM scan_file_tickets WHERE media_observation_snapshot_id = ?1",
                    params![observation_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                            row.get::<_, i64>(7)?,
                        ))
                    },
                )
                .optional()?;
            if let Some(existing) = existing {
                let matches = existing.0 == context.volume_id
                    && existing.1 == guard.scan_run_id
                    && existing.2.as_slice() == core_session_id.as_bytes()
                    && existing.3.as_slice() == input.observation.source_signature.as_bytes()
                    && existing.4 == 1
                    && existing.5 == input.ticket_blob
                    && existing.6.as_slice() == input.ticket_sort_key.as_bytes()
                    && existing.7 == input.ticket_created_at_ms;
                if !matches {
                    return Err(StoreError::IdempotencyConflict {
                        entity: "core_file_ticket",
                        key: observation_id.to_string(),
                    });
                }
                ids.push(observation_id);
                continue;
            }
            self.transaction.execute(
                "INSERT INTO scan_file_tickets ( \
                     media_observation_snapshot_id, volume_id, scan_run_id, core_session_id, \
                     source_signature, ticket_format_version, ticket_blob, ticket_sort_key, \
                     created_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8)",
                params![
                    observation_id,
                    context.volume_id,
                    guard.scan_run_id,
                    core_session_id.as_bytes().as_slice(),
                    input.observation.source_signature.as_bytes().as_slice(),
                    input.ticket_blob,
                    input.ticket_sort_key.as_bytes().as_slice(),
                    input.ticket_created_at_ms,
                ],
            )?;
            ids.push(observation_id);
        }
        Ok(ids)
    }

    fn record_core_directory_batch_impl(
        &mut self,
        guard: &RunEvidenceGuard,
        core_session_id: &CoreSessionId,
        inputs: &[CoreDirectoryObservationInput],
    ) -> Result<Vec<i64>> {
        validate_v5_batch("core_directory_observations", inputs.len())?;
        let context = self.validate_core_session_guard(guard, core_session_id)?;
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            validate_directory_observation(input, context.path_encoding.as_str())?;
            validate_opaque_ticket(&input.ticket_blob)?;
            let existing = self
                .transaction
                .query_row(
                    "SELECT id, volume_id, core_session_id, display_path, source_signature, \
                            directory_object_signature, ticket_format_version, ticket_blob, \
                            ticket_sort_key, observed_at_ms \
                     FROM scan_directory_observations \
                     WHERE scan_run_id = ?1 AND root_index = 0 AND path_encoding = ?2 \
                       AND root_relative_path_raw = ?3",
                    params![
                        guard.scan_run_id,
                        input.path_encoding,
                        input.root_relative_path_raw,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, Vec<u8>>(7)?,
                            row.get::<_, Vec<u8>>(8)?,
                            row.get::<_, i64>(9)?,
                        ))
                    },
                )
                .optional()?;
            if let Some(existing) = existing {
                let matches = existing.1 == context.volume_id
                    && existing.2.as_slice() == core_session_id.as_bytes()
                    && existing.3 == input.display_path
                    && existing.4.as_slice() == input.source_signature.as_bytes()
                    && existing.5.as_slice() == input.directory_object_signature.as_bytes()
                    && existing.6 == 1
                    && existing.7 == input.ticket_blob
                    && existing.8.as_slice() == input.ticket_sort_key.as_bytes()
                    && existing.9 == input.observed_at_ms;
                if !matches {
                    return Err(StoreError::IdempotencyConflict {
                        entity: "core_directory_ticket",
                        key: existing.0.to_string(),
                    });
                }
                ids.push(existing.0);
                continue;
            }
            self.transaction.execute(
                "INSERT INTO scan_directory_observations ( \
                     volume_id, scan_run_id, core_session_id, root_index, \
                     root_relative_path_raw, path_encoding, display_path, source_signature, \
                     directory_object_signature, ticket_format_version, ticket_blob, \
                     ticket_sort_key, observed_at_ms \
                 ) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11)",
                params![
                    context.volume_id,
                    guard.scan_run_id,
                    core_session_id.as_bytes().as_slice(),
                    input.root_relative_path_raw,
                    input.path_encoding,
                    input.display_path,
                    input.source_signature.as_bytes().as_slice(),
                    input.directory_object_signature.as_bytes().as_slice(),
                    input.ticket_blob,
                    input.ticket_sort_key.as_bytes().as_slice(),
                    input.observed_at_ms,
                ],
            )?;
            ids.push(self.transaction.last_insert_rowid());
        }
        Ok(ids)
    }

    fn record_core_coverage_impl(
        &mut self,
        guard: &RunEvidenceGuard,
        core_session_id: &CoreSessionId,
        input: &CoverageOutcomeInput,
    ) -> Result<()> {
        let context = self.validate_core_session_guard(guard, core_session_id)?;
        validate_coverage_outcome(input)?;
        let existing = self
            .transaction
            .query_row(
                "SELECT volume_id, core_session_id, status, directory_count, replayed_count, \
                        stable_count, failed_count, core_manifest_digest, core_seal_digest, \
                        volume_verification_manifest, finalized_at_ms \
                 FROM scan_coverage_outcomes WHERE scan_run_id = ?1",
                params![guard.scan_run_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<Vec<u8>>>(7)?,
                        row.get::<_, Option<Vec<u8>>>(8)?,
                        row.get::<_, Option<Vec<u8>>>(9)?,
                        row.get::<_, i64>(10)?,
                    ))
                },
            )
            .optional()?;
        let manifest = input
            .core_manifest_digest
            .map(|value| value.as_bytes().to_vec());
        let seal = input
            .core_seal_digest
            .map(|value| value.as_bytes().to_vec());
        let volume_manifest = input
            .volume_verification_manifest
            .map(|value| value.as_bytes().to_vec());
        if let Some(existing) = existing {
            let matches = existing.0 == context.volume_id
                && existing.1.as_slice() == core_session_id.as_bytes()
                && existing.2 == input.status.as_storage_str()
                && existing.3 == input.directory_count
                && existing.4 == input.replayed_count
                && existing.5 == input.stable_count
                && existing.6 == input.failed_count
                && existing.7 == manifest
                && existing.8 == seal
                && existing.9 == volume_manifest
                && existing.10 == input.finalized_at_ms;
            if matches {
                return Ok(());
            }
            return Err(StoreError::IdempotencyConflict {
                entity: "core_coverage_outcome",
                key: guard.scan_run_id.to_string(),
            });
        }
        self.transaction.execute(
            "INSERT INTO scan_coverage_outcomes ( \
                 scan_run_id, volume_id, core_session_id, status, directory_count, \
                 replayed_count, stable_count, failed_count, core_manifest_digest, \
                 core_seal_digest, volume_verification_manifest, finalized_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                guard.scan_run_id,
                context.volume_id,
                core_session_id.as_bytes().as_slice(),
                input.status.as_storage_str(),
                input.directory_count,
                input.replayed_count,
                input.stable_count,
                input.failed_count,
                manifest,
                seal,
                volume_manifest,
                input.finalized_at_ms,
            ],
        )?;
        Ok(())
    }

    fn record_one_observation(
        &self,
        context: &BoundRunContext,
        input: &ObservationInput,
    ) -> Result<i64> {
        let mount_display = join_display_path(&context.root_display, &input.display_path)?;
        if input.path_encoding == "utf8"
            && input.mount_relative_path_raw.as_slice() != mount_display.as_bytes()
        {
            return Err(StoreError::invalid_input(
                "mount_relative_path_raw",
                "utf8 mount-relative bytes must match the bound root and display path",
            ));
        }
        let storage_path_key = scoped_v5_storage_path_key(
            context.volume_id,
            context.namespace_profile_id,
            input.stable_path_key.as_bytes(),
        );

        let existing_path = self
            .transaction
            .query_row(
                "SELECT id, volume_id, media_file_id, mount_relative_path_raw, path_encoding, \
                        display_path \
                 FROM media_namespace_paths \
                 WHERE namespace_profile_id = ?1 AND stable_path_key = ?2",
                params![
                    context.namespace_profile_id,
                    input.stable_path_key.as_bytes().as_slice(),
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;
        let (namespace_path_id, media_file_id) = if let Some(existing) = existing_path {
            if existing.1 != context.volume_id
                || existing.3 != input.mount_relative_path_raw
                || existing.4 != input.path_encoding
                || existing.5 != mount_display
            {
                return Err(StoreError::IdempotencyConflict {
                    entity: "media_namespace_path",
                    key: hex_hash(input.stable_path_key.as_bytes()),
                });
            }
            (existing.0, existing.2)
        } else {
            let colliding_media_id = self
                .transaction
                .query_row(
                    "SELECT id FROM media_files WHERE volume_id = ?1 AND path_key = ?2",
                    params![context.volume_id, storage_path_key.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if let Some(colliding_media_id) = colliding_media_id {
                return Err(StoreError::IdempotencyConflict {
                    entity: "v5_media_storage_path",
                    key: colliding_media_id.to_string(),
                });
            }
            self.transaction.execute(
                "INSERT INTO media_files ( \
                     volume_id, first_seen_scan_run_id, last_seen_scan_run_id, relative_path, \
                     path_key, entry_type, media_kind, mime_type, file_extension, lifecycle_state, \
                     size_bytes, allocated_bytes, native_file_id, native_file_generation, \
                     link_count, is_sparse, may_share_content, birth_time_ns, modified_time_ns, \
                     changed_time_ns, accessed_time_ns, timestamp_granularity_ns, stat_signature, \
                     metadata_json, created_at_ms, updated_at_ms \
                 ) VALUES ( \
                     ?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'present', ?9, ?10, ?11, ?12, \
                     ?13, ?14, ?15, NULL, NULL, NULL, NULL, ?16, NULL, NULL, ?17, ?17 \
                 )",
                params![
                    context.volume_id,
                    context.scan_run_id,
                    mount_display,
                    storage_path_key.as_slice(),
                    input.entry_type,
                    input.media_kind,
                    input.mime_type,
                    input.file_extension,
                    input.size_bytes,
                    input.allocated_bytes,
                    input.native_file_id,
                    input.native_file_generation,
                    input.link_count,
                    optional_bool_to_integer(input.is_sparse),
                    optional_bool_to_integer(input.may_share_content),
                    input.timestamp_granularity_ns,
                    input.observed_at_ms,
                ],
            )?;
            let media_file_id = self.transaction.last_insert_rowid();
            self.transaction.execute(
                "INSERT INTO media_namespace_paths ( \
                     volume_id, media_file_id, namespace_profile_id, stable_path_key, \
                     mount_relative_path_raw, path_encoding, display_path, created_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    context.volume_id,
                    media_file_id,
                    context.namespace_profile_id,
                    input.stable_path_key.as_bytes().as_slice(),
                    input.mount_relative_path_raw,
                    input.path_encoding,
                    mount_display,
                    input.observed_at_ms,
                ],
            )?;
            (self.transaction.last_insert_rowid(), media_file_id)
        };

        let existing_observation = self
            .transaction
            .query_row(
                "SELECT id FROM media_observation_snapshots \
                 WHERE scan_run_id = ?1 AND media_file_id = ?2",
                params![context.scan_run_id, media_file_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if let Some(observation_id) = existing_observation {
            if !self.observation_matches(
                observation_id,
                context,
                namespace_path_id,
                media_file_id,
                input,
            )? {
                return Err(StoreError::IdempotencyConflict {
                    entity: "media_observation_snapshot",
                    key: format!("{}:{media_file_id}", context.scan_run_id),
                });
            }
            return Ok(observation_id);
        }

        self.transaction.execute(
            "INSERT INTO media_observation_snapshots ( \
                 volume_id, scan_run_id, media_namespace_path_id, media_file_id, \
                 namespace_profile_id, capability_profile_id, root_relative_path_raw, \
                 path_encoding, display_path, source_signature, stat_signature_version, \
                 file_object_key, native_file_id, native_file_generation, file_mode, entry_type, \
                 size_bytes, allocated_bytes, link_count, is_sparse, may_share_content, \
                 birth_time_seconds, birth_time_nanoseconds, modified_time_seconds, \
                 modified_time_nanoseconds, changed_time_seconds, changed_time_nanoseconds, \
                 accessed_time_seconds, accessed_time_nanoseconds, timestamp_storage_unit_ns, \
                 timestamp_granularity_ns, observed_at_ms \
             ) VALUES ( \
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                 ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, \
                 1, ?30, ?31 \
             )",
            params![
                context.volume_id,
                context.scan_run_id,
                namespace_path_id,
                media_file_id,
                context.namespace_profile_id,
                context.capability_profile_id,
                input.root_relative_path_raw,
                input.path_encoding,
                input.display_path,
                input.source_signature.as_bytes().as_slice(),
                input.stat_signature_version,
                input.file_object_key.map(|key| key.into_bytes().to_vec()),
                input.native_file_id,
                input.native_file_generation,
                input.file_mode,
                input.entry_type,
                input.size_bytes,
                input.allocated_bytes,
                input.link_count,
                optional_bool_to_integer(input.is_sparse),
                optional_bool_to_integer(input.may_share_content),
                timestamp_seconds(input.birth_time),
                timestamp_nanoseconds(input.birth_time),
                input.modified_time.seconds,
                i64::from(input.modified_time.nanoseconds),
                input.changed_time.seconds,
                i64::from(input.changed_time.nanoseconds),
                timestamp_seconds(input.accessed_time),
                timestamp_nanoseconds(input.accessed_time),
                input.timestamp_granularity_ns,
                input.observed_at_ms,
            ],
        )?;
        let observation_id = self.transaction.last_insert_rowid();
        self.transaction.execute(
            "UPDATE media_files SET \
                 last_seen_scan_run_id = ?2, relative_path = ?3, entry_type = ?4, \
                 media_kind = ?5, mime_type = ?6, file_extension = ?7, \
                 lifecycle_state = 'present', size_bytes = ?8, allocated_bytes = ?9, \
                 native_file_id = ?10, native_file_generation = ?11, link_count = ?12, \
                 is_sparse = ?13, may_share_content = ?14, birth_time_ns = ?15, \
                 modified_time_ns = ?16, changed_time_ns = ?17, accessed_time_ns = ?18, \
                 timestamp_granularity_ns = ?19, stat_signature = ?20, updated_at_ms = ?21 \
             WHERE id = ?1 AND volume_id = ?22 \
               AND (updated_at_ms < ?21 \
                 OR (updated_at_ms = ?21 AND last_seen_scan_run_id <= ?2))",
            params![
                media_file_id,
                context.scan_run_id,
                mount_display,
                input.entry_type,
                input.media_kind,
                input.mime_type,
                input.file_extension,
                input.size_bytes,
                input.allocated_bytes,
                input.native_file_id,
                input.native_file_generation,
                input.link_count,
                optional_bool_to_integer(input.is_sparse),
                optional_bool_to_integer(input.may_share_content),
                timestamp_total_ns(input.birth_time),
                timestamp_total_ns(Some(input.modified_time)),
                timestamp_total_ns(Some(input.changed_time)),
                timestamp_total_ns(input.accessed_time),
                input.timestamp_granularity_ns,
                input.source_signature.as_bytes().as_slice(),
                input.observed_at_ms,
                context.volume_id,
            ],
        )?;
        Ok(observation_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn observation_matches(
        &self,
        observation_id: i64,
        context: &BoundRunContext,
        namespace_path_id: i64,
        media_file_id: i64,
        input: &ObservationInput,
    ) -> Result<bool> {
        self.transaction
            .query_row(
                "SELECT EXISTS( \
                     SELECT 1 FROM media_observation_snapshots \
                     WHERE id = ?1 AND volume_id = ?2 AND scan_run_id = ?3 \
                       AND media_namespace_path_id = ?4 AND media_file_id = ?5 \
                       AND namespace_profile_id = ?6 AND capability_profile_id = ?7 \
                       AND root_relative_path_raw = ?8 AND path_encoding = ?9 \
                       AND display_path = ?10 AND source_signature = ?11 \
                       AND stat_signature_version = ?12 AND file_object_key IS ?13 \
                       AND native_file_id IS ?14 AND native_file_generation IS ?15 \
                       AND file_mode = ?16 AND entry_type = ?17 AND size_bytes = ?18 \
                       AND allocated_bytes IS ?19 AND link_count IS ?20 \
                       AND is_sparse IS ?21 AND may_share_content IS ?22 \
                       AND birth_time_seconds IS ?23 AND birth_time_nanoseconds IS ?24 \
                       AND modified_time_seconds = ?25 AND modified_time_nanoseconds = ?26 \
                       AND changed_time_seconds = ?27 AND changed_time_nanoseconds = ?28 \
                       AND accessed_time_seconds IS ?29 AND accessed_time_nanoseconds IS ?30 \
                       AND timestamp_storage_unit_ns = 1 \
                       AND timestamp_granularity_ns IS ?31 AND observed_at_ms = ?32 \
                 )",
                params![
                    observation_id,
                    context.volume_id,
                    context.scan_run_id,
                    namespace_path_id,
                    media_file_id,
                    context.namespace_profile_id,
                    context.capability_profile_id,
                    input.root_relative_path_raw,
                    input.path_encoding,
                    input.display_path,
                    input.source_signature.as_bytes().as_slice(),
                    input.stat_signature_version,
                    input.file_object_key.map(|key| key.into_bytes().to_vec()),
                    input.native_file_id,
                    input.native_file_generation,
                    input.file_mode,
                    input.entry_type,
                    input.size_bytes,
                    input.allocated_bytes,
                    input.link_count,
                    optional_bool_to_integer(input.is_sparse),
                    optional_bool_to_integer(input.may_share_content),
                    timestamp_seconds(input.birth_time),
                    timestamp_nanoseconds(input.birth_time),
                    input.modified_time.seconds,
                    i64::from(input.modified_time.nanoseconds),
                    input.changed_time.seconds,
                    i64::from(input.changed_time.nanoseconds),
                    timestamp_seconds(input.accessed_time),
                    timestamp_nanoseconds(input.accessed_time),
                    input.timestamp_granularity_ns,
                    input.observed_at_ms,
                ],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }

    fn seal_scan_stage_impl(
        &self,
        guard: &RunEvidenceGuard,
        stage: ScanStage,
        item_count: i64,
        logical_bytes: i64,
        sealed_at_ms: i64,
    ) -> Result<()> {
        require_nonnegative("item_count", item_count)?;
        require_nonnegative("logical_bytes", logical_bytes)?;
        require_nonnegative("sealed_at_ms", sealed_at_ms)?;
        let context = self.validate_v5_run_guard(guard)?;
        if let Some(prerequisite) = stage.prerequisite() {
            let present = self.transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM scan_stage_seals \
                 WHERE scan_run_id = ?1 AND stage = ?2)",
                params![guard.scan_run_id, prerequisite.as_storage_str()],
                |row| row.get::<_, bool>(0),
            )?;
            if !present {
                return Err(StoreError::invalid_input(
                    "stage",
                    format!("{} must be sealed first", prerequisite.as_storage_str()),
                ));
            }
        }
        let latest_evidence_ms = match stage {
            ScanStage::Enumeration => self.transaction.query_row(
                "SELECT COALESCE(max(observed_at_ms), 0) \
                 FROM media_observation_snapshots WHERE scan_run_id = ?1",
                [guard.scan_run_id],
                |row| row.get::<_, i64>(0),
            )?,
            ScanStage::Sampling => self.transaction.query_row(
                "SELECT COALESCE(max(completed_at_ms), 0) \
                 FROM observation_fingerprints \
                 WHERE scan_run_id = ?1 AND fingerprint_kind = 'sample'",
                [guard.scan_run_id],
                |row| row.get::<_, i64>(0),
            )?,
            ScanStage::FullHash => self.transaction.query_row(
                "SELECT COALESCE(max(completed_at_ms), 0) \
                 FROM observation_fingerprints \
                 WHERE scan_run_id = ?1 AND fingerprint_kind = 'exact_bytes' \
                   AND read_origin = 'full_hash_read'",
                [guard.scan_run_id],
                |row| row.get::<_, i64>(0),
            )?,
            ScanStage::ExactVerification => self.transaction.query_row(
                "SELECT MAX( \
                     COALESCE((SELECT max(verified_at_ms) FROM exact_verification_edges \
                               WHERE scan_run_id = ?1), 0), \
                     COALESCE((SELECT max(finalized_at_ms) FROM exact_group_builds \
                               WHERE scan_run_id = ?1 AND state = 'verified'), 0), \
                     COALESCE((SELECT finalized_at_ms FROM scan_coverage_outcomes \
                               WHERE scan_run_id = ?1), 0) \
                 )",
                [guard.scan_run_id],
                |row| row.get::<_, i64>(0),
            )?,
        };
        if sealed_at_ms < latest_evidence_ms {
            return Err(StoreError::invalid_input(
                "sealed_at_ms",
                "stage seal cannot predate the evidence it seals",
            ));
        }
        let existing = self
            .transaction
            .query_row(
                "SELECT item_count, logical_bytes, sealed_at_ms FROM scan_stage_seals \
                 WHERE scan_run_id = ?1 AND stage = ?2",
                params![guard.scan_run_id, stage.as_storage_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != (item_count, logical_bytes, sealed_at_ms) {
                return Err(StoreError::IdempotencyConflict {
                    entity: "scan_stage_seal",
                    key: format!("{}:{}", guard.scan_run_id, stage.as_storage_str()),
                });
            }
            return Ok(());
        }
        self.transaction.execute(
            "INSERT INTO scan_stage_seals ( \
                 scan_run_id, volume_id, stage, item_count, logical_bytes, sealed_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                guard.scan_run_id,
                context.volume_id,
                stage.as_storage_str(),
                item_count,
                logical_bytes,
                sealed_at_ms,
            ],
        )?;
        Ok(())
    }

    fn record_fingerprint_fresh_batch_impl(
        &self,
        guard: &RunEvidenceGuard,
        inputs: &[FreshFingerprintInput],
    ) -> Result<Vec<i64>> {
        validate_v5_batch("fingerprints", inputs.len())?;
        let context = self.validate_v5_run_guard(guard)?;
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            validate_fresh_fingerprint(input)?;
            let (source_signature, observed_size): (Vec<u8>, i64) = self.transaction.query_row(
                "SELECT source_signature, size_bytes FROM media_observation_snapshots \
                     WHERE id = ?1 AND scan_run_id = ?2 AND volume_id = ?3 \
                       AND capability_profile_id = ?4",
                params![
                    input.observation_id,
                    guard.scan_run_id,
                    context.volume_id,
                    guard.capability_profile_id,
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if source_signature.as_slice() != input.source_signature_before.as_bytes()
                || source_signature.as_slice() != input.source_signature_after.as_bytes()
                || observed_size != input.observed_size_bytes
            {
                return Err(StoreError::IdempotencyConflict {
                    entity: "fresh_fingerprint_observation",
                    key: input.observation_id.to_string(),
                });
            }
            let existing = self
                .transaction
                .query_row(
                    "SELECT id, read_origin, source_signature_before, source_signature_after, \
                            digest, observed_size_bytes, bytes_read, reached_expected_eof, \
                            completed_at_ms, created_at_ms \
                     FROM observation_fingerprints \
                     WHERE scan_run_id = ?1 AND media_observation_snapshot_id = ?2 \
                       AND fingerprint_kind = ?3 AND algorithm = ?4 \
                       AND algorithm_version = ?5 AND parameters_hash = ?6",
                    params![
                        guard.scan_run_id,
                        input.observation_id,
                        input.fingerprint_kind.as_storage_str(),
                        input.algorithm,
                        input.algorithm_version,
                        input.parameters_hash.as_bytes().as_slice(),
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, i64>(7)?,
                            row.get::<_, i64>(8)?,
                            row.get::<_, i64>(9)?,
                        ))
                    },
                )
                .optional()?;
            if let Some(existing) = existing {
                let matches = existing.1 == input.read_origin.as_storage_str()
                    && existing.2.as_slice() == input.source_signature_before.as_bytes()
                    && existing.3.as_slice() == input.source_signature_after.as_bytes()
                    && existing.4 == input.digest
                    && existing.5 == input.observed_size_bytes
                    && existing.6 == input.bytes_read
                    && existing.7 == i64::from(input.reached_expected_eof)
                    && existing.8 == input.completed_at_ms
                    && existing.9 == input.created_at_ms;
                if !matches {
                    return Err(StoreError::IdempotencyConflict {
                        entity: "observation_fingerprint",
                        key: format!(
                            "{}:{}:{}:{}",
                            input.observation_id,
                            input.fingerprint_kind.as_storage_str(),
                            input.algorithm,
                            input.algorithm_version
                        ),
                    });
                }
                ids.push(existing.0);
                continue;
            }
            match input.fingerprint_kind {
                FreshFingerprintKind::Sample => {
                    self.require_stage_sealed(guard.scan_run_id, ScanStage::Enumeration)?;
                    self.require_stage_open(guard.scan_run_id, ScanStage::Sampling)?;
                }
                FreshFingerprintKind::ExactBytes => match input.read_origin {
                    crate::model::FingerprintReadOrigin::FullHashRead => {
                        self.require_stage_sealed(guard.scan_run_id, ScanStage::Sampling)?;
                        self.require_stage_open(guard.scan_run_id, ScanStage::FullHash)?;
                    }
                    crate::model::FingerprintReadOrigin::ExactCompareRead => {
                        self.require_stage_sealed(guard.scan_run_id, ScanStage::FullHash)?;
                        self.require_stage_open(guard.scan_run_id, ScanStage::ExactVerification)?;
                    }
                    crate::model::FingerprintReadOrigin::SampleRead => {
                        return Err(StoreError::invalid_input(
                            "read_origin",
                            "exact fingerprints cannot originate from a sample read",
                        ));
                    }
                },
            }
            self.transaction.execute(
                "INSERT INTO observation_fingerprints ( \
                     volume_id, scan_run_id, media_observation_snapshot_id, fingerprint_kind, \
                     algorithm, algorithm_version, parameters_hash, read_origin, \
                     source_signature_before, source_signature_after, digest, observed_size_bytes, \
                     bytes_read, reached_expected_eof, completed_at_ms, created_at_ms \
                 ) VALUES ( \
                     ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16 \
                 )",
                params![
                    context.volume_id,
                    guard.scan_run_id,
                    input.observation_id,
                    input.fingerprint_kind.as_storage_str(),
                    input.algorithm,
                    input.algorithm_version,
                    input.parameters_hash.as_bytes().as_slice(),
                    input.read_origin.as_storage_str(),
                    input.source_signature_before.as_bytes().as_slice(),
                    input.source_signature_after.as_bytes().as_slice(),
                    input.digest,
                    input.observed_size_bytes,
                    input.bytes_read,
                    i64::from(input.reached_expected_eof),
                    input.completed_at_ms,
                    input.created_at_ms,
                ],
            )?;
            ids.push(self.transaction.last_insert_rowid());
        }
        Ok(ids)
    }

    fn validate_v5_run_guard(&self, guard: &RunEvidenceGuard) -> Result<BoundRunContext> {
        let context = self.validate_v5_bound_run_guard(guard)?;
        if context.run_state != "running" || context.job_state != "running" {
            return Err(StoreError::ConcurrencyConflict {
                entity: "running_run_evidence_guard",
                id: guard.scan_run_id,
            });
        }
        Ok(context)
    }

    fn validate_core_session_guard(
        &self,
        guard: &RunEvidenceGuard,
        core_session_id: &CoreSessionId,
    ) -> Result<BoundRunContext> {
        let context = self.validate_v5_run_guard(guard)?;
        let matches = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM scan_core_sessions \
                 WHERE scan_run_id = ?1 AND volume_id = ?2 \
                   AND capability_profile_id = ?3 AND namespace_profile_id = ?4 \
                   AND core_session_id = ?5 AND trust_scope = 'current_core_session_only' \
                   AND engine_contract_version = 1 AND root_index = 0 \
                   AND root_kind = 'directory' \
             )",
            params![
                guard.scan_run_id,
                context.volume_id,
                context.capability_profile_id,
                context.namespace_profile_id,
                core_session_id.as_bytes().as_slice(),
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !matches {
            return Err(StoreError::ConcurrencyConflict {
                entity: "core_session_evidence_guard",
                id: guard.scan_run_id,
            });
        }
        Ok(context)
    }

    fn validate_time_evidence_guard(&self, guard: &TimeEvidenceGuard) -> Result<BoundRunContext> {
        if self.store_instance_key == [0; 32]
            || guard.store_instance_key() != &self.store_instance_key
        {
            return Err(StoreError::ConcurrencyConflict {
                entity: "live_time_store_instance_guard",
                id: guard.run().scan_run_id,
            });
        }
        let context = self.validate_v5_bound_run_guard(guard.run())?;
        if context.run_state != "completed" || context.job_state != "completed" {
            return Err(StoreError::ConcurrencyConflict {
                entity: "completed_time_evidence_guard",
                id: guard.run().scan_run_id,
            });
        }
        let matches = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM scan_core_sessions \
                 WHERE scan_run_id = ?1 AND volume_id = ?2 \
                   AND capability_profile_id = ?3 AND namespace_profile_id = ?4 \
                   AND core_session_id = ?5 \
                   AND trust_scope = 'current_core_session_only' \
                   AND engine_contract_version = 1 \
             )",
            params![
                guard.run().scan_run_id,
                context.volume_id,
                context.capability_profile_id,
                context.namespace_profile_id,
                guard.core_session_id().as_bytes().as_slice(),
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !matches {
            return Err(StoreError::ConcurrencyConflict {
                entity: "time_core_session_evidence_guard",
                id: guard.run().scan_run_id,
            });
        }
        Ok(context)
    }

    fn validate_v5_bound_run_guard(&self, guard: &RunEvidenceGuard) -> Result<BoundRunContext> {
        require_positive("scan_run_id", guard.scan_run_id)?;
        require_positive("capability_profile_id", guard.capability_profile_id)?;
        let mount_session_hex = guard.mount_session_key.to_storage_hex();
        self.transaction
            .query_row(
                "SELECT run.volume_id, session.namespace_profile_id, \
                        session.capability_profile_id, namespace.native_path_encoding, \
                        session.mount_relative_root_raw, session.path_encoding, \
                        session.scan_job_id, run.state, job.state, scope.root_display \
                 FROM scan_runs AS run \
                 JOIN scan_run_sessions AS session ON session.scan_run_id = run.id \
                 JOIN scan_jobs AS job \
                   ON job.id = session.scan_job_id AND job.volume_id = session.volume_id \
                  AND job.active_scan_run_id = run.id \
                 JOIN scan_job_scopes AS scope \
                   ON scope.scan_job_id = job.id AND scope.volume_id = job.volume_id \
                  AND scope.namespace_profile_id = session.namespace_profile_id \
                  AND scope.stable_root_path_key = session.stable_root_path_key \
                  AND scope.root_scope_key = session.root_scope_key \
                 JOIN namespace_profiles AS namespace \
                   ON namespace.id = session.namespace_profile_id \
                  AND namespace.volume_id = session.volume_id \
                 JOIN capability_profiles AS capability \
                   ON capability.id = session.capability_profile_id \
                  AND capability.volume_id = session.volume_id \
                 WHERE run.id = ?1 \
                   AND session.capability_profile_id = ?2 \
                   AND session.mount_session_key = ?3 \
                   AND capability.mount_session_key = session.mount_session_key \
                   AND capability.profile_hash_version = 2 AND capability.is_current = 1 \
                   AND capability.probe_status = 'complete' AND capability.can_read = 1 \
                   AND capability.probe_protocol_version IS NOT NULL \
                   AND capability.path_encoding_family IS NOT NULL \
                   AND namespace.origin = 'observed_v5' \
                   AND namespace.reuse_scope <> 'history_only' \
                   AND ((namespace.reuse_scope = 'cross_session' \
                         AND namespace.bound_mount_session_key IS NULL) \
                     OR (namespace.reuse_scope = 'current_session_only' \
                         AND namespace.bound_mount_session_key = session.mount_session_key)) \
                   AND scope.origin = 'observed_v5' \
                   AND scope.mount_relative_root_raw = session.mount_relative_root_raw \
                   AND scope.path_encoding = session.path_encoding",
                params![
                    guard.scan_run_id,
                    guard.capability_profile_id,
                    mount_session_hex,
                ],
                |row| {
                    Ok(BoundRunContext {
                        scan_run_id: guard.scan_run_id,
                        volume_id: row.get(0)?,
                        namespace_profile_id: row.get(1)?,
                        capability_profile_id: row.get(2)?,
                        path_encoding: row.get(3)?,
                        mount_relative_root_raw: row.get(4)?,
                        root_path_encoding: row.get(5)?,
                        scan_job_id: row.get(6)?,
                        run_state: row.get(7)?,
                        job_state: row.get(8)?,
                        root_display: row.get(9)?,
                    })
                },
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StoreError::ConcurrencyConflict {
                    entity: "bound_run_evidence_guard",
                    id: guard.scan_run_id,
                },
                other => StoreError::from(other),
            })
    }

    fn require_stage_sealed(&self, run_id: i64, stage: ScanStage) -> Result<()> {
        let sealed = self.transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM scan_stage_seals \
             WHERE scan_run_id = ?1 AND stage = ?2)",
            params![run_id, stage.as_storage_str()],
            |row| row.get::<_, bool>(0),
        )?;
        if !sealed {
            return Err(StoreError::invalid_input(
                "stage",
                format!("{} is not sealed", stage.as_storage_str()),
            ));
        }
        Ok(())
    }

    fn require_stage_open(&self, run_id: i64, stage: ScanStage) -> Result<()> {
        let sealed = self.transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM scan_stage_seals \
             WHERE scan_run_id = ?1 AND stage = ?2)",
            params![run_id, stage.as_storage_str()],
            |row| row.get::<_, bool>(0),
        )?;
        if sealed {
            return Err(StoreError::ConcurrencyConflict {
                entity: "sealed_scan_stage",
                id: run_id,
            });
        }
        Ok(())
    }

    fn begin_exact_group_impl(
        &self,
        guard: &RunEvidenceGuard,
        input: &BeginExactGroupInput,
    ) -> Result<i64> {
        require_positive("expected_member_count", input.expected_member_count)?;
        if input.expected_member_count < 2 {
            return Err(StoreError::invalid_input(
                "expected_member_count",
                "an exact duplicate group requires at least two members",
            ));
        }
        require_nonnegative("created_at_ms", input.created_at_ms)?;
        let expected_edge_count = input
            .expected_member_count
            .checked_sub(1)
            .ok_or_else(|| StoreError::invalid_input("expected_member_count", "count underflow"))?;
        let context = self.validate_v5_run_guard(guard)?;
        let existing = self
            .transaction
            .query_row(
                "SELECT id, volume_id, representative_observation_id, \
                        representative_fingerprint_id, expected_member_count, \
                        expected_edge_count, expected_manifest_digest, created_at_ms \
                 FROM exact_group_builds \
                 WHERE volume_id = ?1 AND scan_run_id = ?2 AND build_key = ?3",
                params![
                    context.volume_id,
                    guard.scan_run_id,
                    input.build_key.as_bytes().as_slice(),
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            let matches = existing.1 == context.volume_id
                && existing.2 == input.representative_observation_id
                && existing.3 == input.representative_fingerprint_id
                && existing.4 == input.expected_member_count
                && existing.5 == expected_edge_count
                && existing.6.as_slice() == input.expected_manifest_digest.as_bytes()
                && existing.7 == input.created_at_ms;
            if !matches {
                return Err(StoreError::IdempotencyConflict {
                    entity: "exact_group_build",
                    key: hex_hash(input.build_key.as_bytes()),
                });
            }
            return Ok(existing.0);
        }
        self.require_stage_sealed(guard.scan_run_id, ScanStage::FullHash)?;
        self.require_stage_open(guard.scan_run_id, ScanStage::ExactVerification)?;
        let representative = self.load_exact_evidence(
            guard.scan_run_id,
            input.representative_observation_id,
            input.representative_fingerprint_id,
        )?;
        representative.validate_current_exact()?;
        self.transaction.execute(
            "INSERT INTO exact_group_builds ( \
                 build_key, volume_id, scan_run_id, representative_observation_id, \
                 representative_fingerprint_id, expected_member_count, expected_edge_count, \
                 expected_manifest_digest, state, created_at_ms \
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'draft', ?9)",
            params![
                input.build_key.as_bytes().as_slice(),
                context.volume_id,
                guard.scan_run_id,
                input.representative_observation_id,
                input.representative_fingerprint_id,
                input.expected_member_count,
                expected_edge_count,
                input.expected_manifest_digest.as_bytes().as_slice(),
                input.created_at_ms,
            ],
        )?;
        Ok(self.transaction.last_insert_rowid())
    }

    fn append_exact_group_members_impl(
        &self,
        guard: &RunEvidenceGuard,
        build_id: i64,
        inputs: &[ExactGroupMemberInput],
    ) -> Result<()> {
        require_positive("build_id", build_id)?;
        validate_v5_batch("exact group members", inputs.len())?;
        let context = self.validate_v5_run_guard(guard)?;
        self.require_stage_open(guard.scan_run_id, ScanStage::ExactVerification)?;
        let build = self.load_draft_build(guard.scan_run_id, build_id)?;
        for input in inputs {
            require_nonnegative("ordinal", input.ordinal)?;
            require_positive("observation_id", input.observation_id)?;
            require_positive("fingerprint_id", input.fingerprint_id)?;
            require_nonnegative("sort_rank", input.sort_rank)?;
            if input.ordinal >= build.expected_member_count {
                return Err(StoreError::invalid_input(
                    "ordinal",
                    "member ordinal is outside the declared manifest",
                ));
            }
            if input.ordinal == 0
                && (input.observation_id != build.representative_observation_id
                    || input.fingerprint_id != build.representative_fingerprint_id)
            {
                return Err(StoreError::invalid_input(
                    "ordinal",
                    "ordinal zero must be the declared representative",
                ));
            }
            if input.ordinal != 0 && input.observation_id == build.representative_observation_id {
                return Err(StoreError::invalid_input(
                    "observation_id",
                    "the representative may appear only at ordinal zero",
                ));
            }
            let evidence = self.load_exact_evidence(
                guard.scan_run_id,
                input.observation_id,
                input.fingerprint_id,
            )?;
            evidence.validate_current_exact()?;
            let material = evidence.to_manifest_member(input)?;
            let manifest_leaf = compute_exact_group_member_leaf(&material)?;

            let mut statement = self.transaction.prepare(
                "SELECT ordinal, media_observation_snapshot_id, observation_fingerprint_id, \
                        sort_rank, manifest_leaf, created_at_ms \
                 FROM exact_group_build_members \
                 WHERE exact_group_build_id = ?1 \
                   AND (ordinal = ?2 OR media_observation_snapshot_id = ?3)",
            )?;
            let mut rows =
                statement.query(params![build_id, input.ordinal, input.observation_id])?;
            let mut matching_idempotent_row = false;
            let mut conflicting_row = false;
            while let Some(row) = rows.next()? {
                let matches = row.get::<_, i64>(0)? == input.ordinal
                    && row.get::<_, i64>(1)? == input.observation_id
                    && row.get::<_, i64>(2)? == input.fingerprint_id
                    && row.get::<_, i64>(3)? == input.sort_rank
                    && row.get::<_, Vec<u8>>(4)?.as_slice() == manifest_leaf.as_bytes()
                    && row.get::<_, i64>(5)? == build.created_at_ms;
                matching_idempotent_row |= matches;
                conflicting_row |= !matches;
            }
            drop(rows);
            drop(statement);
            if conflicting_row {
                return Err(StoreError::IdempotencyConflict {
                    entity: "exact_group_member",
                    key: format!("{build_id}:{}", input.ordinal),
                });
            }
            if matching_idempotent_row {
                continue;
            }
            self.transaction.execute(
                "INSERT INTO exact_group_build_members ( \
                     exact_group_build_id, volume_id, scan_run_id, ordinal, \
                     media_observation_snapshot_id, observation_fingerprint_id, sort_rank, \
                     manifest_leaf, created_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    build_id,
                    context.volume_id,
                    guard.scan_run_id,
                    input.ordinal,
                    input.observation_id,
                    input.fingerprint_id,
                    input.sort_rank,
                    manifest_leaf.as_bytes().as_slice(),
                    build.created_at_ms,
                ],
            )?;
        }
        Ok(())
    }

    fn append_exact_verification_edges_impl(
        &self,
        guard: &RunEvidenceGuard,
        build_id: i64,
        inputs: &[ExactVerificationEdgeInput],
    ) -> Result<()> {
        require_positive("build_id", build_id)?;
        validate_v5_batch("exact verification edges", inputs.len())?;
        let context = self.validate_v5_run_guard(guard)?;
        self.require_stage_open(guard.scan_run_id, ScanStage::ExactVerification)?;
        let build = self.load_draft_build(guard.scan_run_id, build_id)?;
        let representative = self.load_exact_evidence(
            guard.scan_run_id,
            build.representative_observation_id,
            build.representative_fingerprint_id,
        )?;
        representative.validate_current_exact()?;
        for input in inputs {
            require_positive("member_observation_id", input.member_observation_id)?;
            require_positive("member_fingerprint_id", input.member_fingerprint_id)?;
            require_nonnegative("compared_bytes", input.compared_bytes)?;
            require_nonnegative("verified_at_ms", input.verified_at_ms)?;
            if input.verified_at_ms < build.created_at_ms {
                return Err(StoreError::invalid_input(
                    "verified_at_ms",
                    "verification edge cannot predate its draft group",
                ));
            }
            if input.member_observation_id == build.representative_observation_id {
                return Err(StoreError::invalid_input(
                    "member_observation_id",
                    "the representative cannot have a self-verification edge",
                ));
            }
            let member = self.load_exact_evidence(
                guard.scan_run_id,
                input.member_observation_id,
                input.member_fingerprint_id,
            )?;
            member.validate_current_exact()?;
            if input.representative_source_signature != representative.source_signature
                || input.member_source_signature != member.source_signature
                || input.compared_bytes != representative.size_bytes
                || input.compared_bytes != member.size_bytes
                || !representative.same_fingerprint_material(&member)
            {
                return Err(StoreError::IdempotencyConflict {
                    entity: "exact_verification_edge_evidence",
                    key: format!("{build_id}:{}", input.member_observation_id),
                });
            }
            let member_binding_matches = self.transaction.query_row(
                "SELECT EXISTS( \
                     SELECT 1 FROM exact_group_build_members \
                     WHERE exact_group_build_id = ?1 \
                       AND media_observation_snapshot_id = ?2 \
                       AND observation_fingerprint_id = ?3 \
                 )",
                params![
                    build_id,
                    input.member_observation_id,
                    input.member_fingerprint_id,
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if !member_binding_matches {
                return Err(StoreError::invalid_input(
                    "member_observation_id",
                    "verification edge member is not in the draft manifest",
                ));
            }
            let existing = self
                .transaction
                .query_row(
                    "SELECT representative_observation_id, representative_fingerprint_id, \
                            member_fingerprint_id, representative_source_signature, \
                            member_source_signature, compared_bytes, verified_at_ms \
                     FROM exact_verification_edges \
                     WHERE exact_group_build_id = ?1 AND member_observation_id = ?2",
                    params![build_id, input.member_observation_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .optional()?;
            if let Some(existing) = existing {
                let matches = existing.0 == build.representative_observation_id
                    && existing.1 == build.representative_fingerprint_id
                    && existing.2 == input.member_fingerprint_id
                    && existing.3.as_slice() == input.representative_source_signature.as_bytes()
                    && existing.4.as_slice() == input.member_source_signature.as_bytes()
                    && existing.5 == input.compared_bytes
                    && existing.6 == input.verified_at_ms;
                if !matches {
                    return Err(StoreError::IdempotencyConflict {
                        entity: "exact_verification_edge",
                        key: format!("{build_id}:{}", input.member_observation_id),
                    });
                }
                continue;
            }
            self.transaction.execute(
                "INSERT INTO exact_verification_edges ( \
                     exact_group_build_id, volume_id, scan_run_id, \
                     representative_observation_id, representative_fingerprint_id, \
                     member_observation_id, member_fingerprint_id, \
                     representative_source_signature, member_source_signature, \
                     compared_bytes, verified_at_ms \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    build_id,
                    context.volume_id,
                    guard.scan_run_id,
                    build.representative_observation_id,
                    build.representative_fingerprint_id,
                    input.member_observation_id,
                    input.member_fingerprint_id,
                    input.representative_source_signature.as_bytes().as_slice(),
                    input.member_source_signature.as_bytes().as_slice(),
                    input.compared_bytes,
                    input.verified_at_ms,
                ],
            )?;
        }
        Ok(())
    }

    fn finalize_exact_group_impl(
        &self,
        guard: &RunEvidenceGuard,
        build_id: i64,
        finalized_at_ms: i64,
    ) -> Result<VerifiedExactGroup> {
        require_positive("build_id", build_id)?;
        require_nonnegative("finalized_at_ms", finalized_at_ms)?;
        let _context = self.validate_v5_run_guard(guard)?;
        let state = self.transaction.query_row(
            "SELECT state FROM exact_group_builds WHERE id = ?1 AND scan_run_id = ?2",
            params![build_id, guard.scan_run_id],
            |row| row.get::<_, String>(0),
        )?;
        if state == "verified" {
            return self.load_verified_exact_group(build_id, Some(finalized_at_ms));
        }
        if state != "draft" {
            return Err(StoreError::ConcurrencyConflict {
                entity: "exact_group_build_state",
                id: build_id,
            });
        }
        self.require_stage_open(guard.scan_run_id, ScanStage::ExactVerification)?;
        let build = self.load_draft_build(guard.scan_run_id, build_id)?;
        if finalized_at_ms < build.created_at_ms {
            return Err(StoreError::invalid_input(
                "finalized_at_ms",
                "finalization cannot predate the draft",
            ));
        }
        let (member_count, min_ordinal, max_ordinal): (i64, Option<i64>, Option<i64>) =
            self.transaction.query_row(
                "SELECT count(*), min(ordinal), max(ordinal) \
                 FROM exact_group_build_members WHERE exact_group_build_id = ?1",
                [build_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        if member_count != build.expected_member_count
            || min_ordinal != Some(0)
            || max_ordinal != build.expected_member_count.checked_sub(1)
        {
            return Err(StoreError::invalid_input(
                "exact_group_members",
                "member count or ordinal coverage does not match the draft manifest",
            ));
        }
        let representative_member_matches = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM exact_group_build_members \
                 WHERE exact_group_build_id = ?1 AND ordinal = 0 \
                   AND media_observation_snapshot_id = ?2 \
                   AND observation_fingerprint_id = ?3 \
             )",
            params![
                build_id,
                build.representative_observation_id,
                build.representative_fingerprint_id,
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !representative_member_matches {
            return Err(StoreError::invalid_input(
                "exact_group_members",
                "ordinal zero is not the declared representative",
            ));
        }
        let edge_count: i64 = self.transaction.query_row(
            "SELECT count(*) FROM exact_verification_edges WHERE exact_group_build_id = ?1",
            [build_id],
            |row| row.get(0),
        )?;
        if edge_count != build.expected_edge_count {
            return Err(StoreError::invalid_input(
                "exact_verification_edges",
                "edge count does not match the draft manifest",
            ));
        }
        let latest_edge_ms: i64 = self.transaction.query_row(
            "SELECT COALESCE(max(verified_at_ms), 0) \
             FROM exact_verification_edges WHERE exact_group_build_id = ?1",
            [build_id],
            |row| row.get(0),
        )?;
        if finalized_at_ms < latest_edge_ms {
            return Err(StoreError::invalid_input(
                "finalized_at_ms",
                "group finalization cannot predate its verification edges",
            ));
        }
        let invalid_edge_bindings: i64 = self.transaction.query_row(
            "SELECT count(*) \
             FROM exact_group_build_members AS member \
             LEFT JOIN exact_verification_edges AS edge \
               ON edge.exact_group_build_id = member.exact_group_build_id \
              AND edge.member_observation_id = member.media_observation_snapshot_id \
             WHERE member.exact_group_build_id = ?1 \
               AND ((member.ordinal = 0 AND edge.member_observation_id IS NOT NULL) \
                 OR (member.ordinal > 0 AND ( \
                       edge.member_observation_id IS NULL \
                       OR edge.member_fingerprint_id <> member.observation_fingerprint_id \
                       OR edge.representative_observation_id <> ?2 \
                       OR edge.representative_fingerprint_id <> ?3 \
                 )))",
            params![
                build_id,
                build.representative_observation_id,
                build.representative_fingerprint_id,
            ],
            |row| row.get(0),
        )?;
        if invalid_edge_bindings != 0 {
            return Err(StoreError::invalid_input(
                "exact_verification_edges",
                "each non-representative member must have exactly its own verification edge",
            ));
        }

        let mut manifest_hasher = blake3::Hasher::new();
        manifest_hasher.update(b"guiying.exact-group-manifest.v1\0");
        manifest_hasher.update(&checked_u64("member_count", member_count)?.to_le_bytes());
        let mut common: Option<ExactFingerprintCommon> = None;
        let mut streamed_members = 0_i64;
        let mut statement = self.transaction.prepare(
            "SELECT member.ordinal, member.media_observation_snapshot_id, \
                    member.observation_fingerprint_id, member.sort_rank, member.manifest_leaf, \
                    path.stable_path_key, observation.source_signature, observation.size_bytes, \
                    observation.file_object_key, fingerprint.fingerprint_kind, \
                    fingerprint.algorithm, fingerprint.algorithm_version, \
                    fingerprint.parameters_hash, fingerprint.digest, \
                    fingerprint.observed_size_bytes, fingerprint.bytes_read, \
                    fingerprint.reached_expected_eof, fingerprint.source_signature_before, \
                    fingerprint.source_signature_after \
             FROM exact_group_build_members AS member \
             JOIN media_observation_snapshots AS observation \
               ON observation.id = member.media_observation_snapshot_id \
              AND observation.scan_run_id = member.scan_run_id \
              AND observation.volume_id = member.volume_id \
             JOIN media_namespace_paths AS path \
               ON path.id = observation.media_namespace_path_id \
              AND path.volume_id = observation.volume_id \
             JOIN observation_fingerprints AS fingerprint \
               ON fingerprint.id = member.observation_fingerprint_id \
              AND fingerprint.media_observation_snapshot_id = observation.id \
              AND fingerprint.scan_run_id = observation.scan_run_id \
              AND fingerprint.volume_id = observation.volume_id \
             WHERE member.exact_group_build_id = ?1 \
             ORDER BY member.ordinal",
        )?;
        let mut rows = statement.query([build_id])?;
        while let Some(row) = rows.next()? {
            let evidence = ExactEvidence::from_finalize_row(row)?;
            evidence.validate_current_exact()?;
            if evidence.ordinal != Some(streamed_members) {
                return Err(StoreError::invalid_input(
                    "exact_group_members",
                    "member ordinals are not contiguous",
                ));
            }
            let row_common = ExactFingerprintCommon::from_evidence(&evidence);
            if let Some(expected) = common.as_ref() {
                if expected != &row_common {
                    return Err(StoreError::invalid_input(
                        "exact_group_members",
                        "member exact fingerprints do not have identical material",
                    ));
                }
            } else {
                common = Some(row_common);
            }
            let material = evidence.to_manifest_member_from_stored()?;
            let computed_leaf = compute_exact_group_member_leaf(&material)?;
            if evidence.stored_manifest_leaf.as_deref() != Some(computed_leaf.as_bytes()) {
                return Err(StoreError::invalid_input(
                    "manifest_leaf",
                    "stored member leaf does not match database evidence",
                ));
            }
            manifest_hasher.update(computed_leaf.as_bytes());
            streamed_members = streamed_members.checked_add(1).ok_or_else(|| {
                StoreError::invalid_input("member_count", "member count overflow")
            })?;
        }
        drop(rows);
        drop(statement);
        if streamed_members != build.expected_member_count {
            return Err(StoreError::invalid_input(
                "member_count",
                "streamed member count differs from the draft",
            ));
        }
        let manifest_digest =
            ManifestDigest::from_runtime_evidence(*manifest_hasher.finalize().as_bytes());
        if manifest_digest != build.expected_manifest_digest {
            return Err(StoreError::IdempotencyConflict {
                entity: "exact_group_manifest",
                key: build_id.to_string(),
            });
        }
        let common = common.ok_or_else(|| {
            StoreError::invalid_input("exact_group_members", "group contains no members")
        })?;
        let invalid_edges: i64 = self.transaction.query_row(
            "SELECT count(*) \
             FROM exact_verification_edges AS edge \
             JOIN media_observation_snapshots AS representative \
               ON representative.id = edge.representative_observation_id \
              AND representative.scan_run_id = edge.scan_run_id \
             JOIN media_observation_snapshots AS member \
               ON member.id = edge.member_observation_id \
              AND member.scan_run_id = edge.scan_run_id \
             JOIN observation_fingerprints AS representative_fp \
               ON representative_fp.id = edge.representative_fingerprint_id \
              AND representative_fp.media_observation_snapshot_id = representative.id \
             JOIN observation_fingerprints AS member_fp \
               ON member_fp.id = edge.member_fingerprint_id \
              AND member_fp.media_observation_snapshot_id = member.id \
             WHERE edge.exact_group_build_id = ?1 AND ( \
                    edge.representative_source_signature <> representative.source_signature \
                 OR edge.member_source_signature <> member.source_signature \
                 OR edge.compared_bytes <> representative.size_bytes \
                 OR edge.compared_bytes <> member.size_bytes \
                 OR representative_fp.fingerprint_kind <> 'exact_bytes' \
                 OR member_fp.fingerprint_kind <> 'exact_bytes' \
                 OR representative_fp.source_signature_before <> representative.source_signature \
                 OR representative_fp.source_signature_after <> representative.source_signature \
                 OR member_fp.source_signature_before <> member.source_signature \
                 OR member_fp.source_signature_after <> member.source_signature \
                 OR representative_fp.algorithm <> member_fp.algorithm \
                 OR representative_fp.algorithm_version <> member_fp.algorithm_version \
                 OR representative_fp.parameters_hash <> member_fp.parameters_hash \
                 OR representative_fp.digest <> member_fp.digest \
                 OR representative_fp.observed_size_bytes <> member_fp.observed_size_bytes \
                 OR representative_fp.bytes_read <> representative.size_bytes \
                 OR member_fp.bytes_read <> member.size_bytes \
                 OR representative_fp.reached_expected_eof <> 1 \
                 OR member_fp.reached_expected_eof <> 1 \
             )",
            [build_id],
            |row| row.get(0),
        )?;
        if invalid_edges != 0 {
            return Err(StoreError::invalid_input(
                "exact_verification_edges",
                "verification edge evidence is inconsistent with current observations",
            ));
        }
        self.ensure_no_verified_exact_group_overlap(build_id)?;
        let independent_file_count: i64 = self.transaction.query_row(
            "SELECT count(DISTINCT observation.file_object_key) \
                    + sum(CASE WHEN observation.file_object_key IS NULL THEN 1 ELSE 0 END) \
             FROM exact_group_build_members AS member \
             JOIN media_observation_snapshots AS observation \
               ON observation.id = member.media_observation_snapshot_id \
              AND observation.scan_run_id = member.scan_run_id \
             WHERE member.exact_group_build_id = ?1",
            [build_id],
            |row| row.get(0),
        )?;
        if !(1..=member_count).contains(&independent_file_count) {
            return Err(StoreError::invalid_input(
                "file_object_key",
                "independent physical-file count is outside the member count",
            ));
        }
        let reclaimable_copies = independent_file_count.checked_sub(1).ok_or_else(|| {
            StoreError::invalid_input("independent_file_count", "count underflow")
        })?;
        let logical_reclaimable_bytes = common
            .size_bytes
            .checked_mul(reclaimable_copies)
            .ok_or_else(|| {
                StoreError::invalid_input("logical_reclaimable_bytes", "byte count overflow")
            })?;
        let run_key: String = self.transaction.query_row(
            "SELECT run_key FROM scan_runs WHERE id = ?1",
            [guard.scan_run_id],
            |row| row.get(0),
        )?;
        let group_key = compute_exact_group_key(&run_key, &common, manifest_digest)?;
        let changed = self.transaction.execute(
            "UPDATE exact_group_builds \
             SET state = 'verified', group_key = ?3, independent_file_count = ?4, \
                 logical_reclaimable_bytes = ?5, finalized_at_ms = ?6 \
             WHERE id = ?1 AND scan_run_id = ?2 AND state = 'draft' \
               AND expected_manifest_digest = ?7",
            params![
                build_id,
                guard.scan_run_id,
                group_key.as_bytes().as_slice(),
                independent_file_count,
                logical_reclaimable_bytes,
                finalized_at_ms,
                manifest_digest.as_bytes().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "exact_group_finalize",
                id: build_id,
            });
        }
        Ok(VerifiedExactGroup {
            build_id,
            group_key,
            member_count,
            edge_count,
            independent_file_count,
            logical_reclaimable_bytes,
            manifest_digest,
            finalized_at_ms,
        })
    }

    fn abandon_exact_group_draft_impl(
        &self,
        guard: &RunEvidenceGuard,
        build_id: i64,
        abandoned_at_ms: i64,
        reason_code: &str,
        reason_message: Option<&str>,
    ) -> Result<()> {
        require_positive("build_id", build_id)?;
        require_nonnegative("abandoned_at_ms", abandoned_at_ms)?;
        require_bounded_nonempty("reason_code", reason_code, MAX_IDENTIFIER_BYTES)?;
        validate_optional_bounded("reason_message", reason_message, MAX_TEXT_BYTES)?;
        self.validate_v5_run_guard(guard)?;
        self.require_stage_open(guard.scan_run_id, ScanStage::ExactVerification)?;
        let existing = self.transaction.query_row(
            "SELECT state, created_at_ms, finalized_at_ms, abandon_reason_code, \
                    abandon_reason_message \
             FROM exact_group_builds WHERE id = ?1 AND scan_run_id = ?2",
            params![build_id, guard.scan_run_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )?;
        if existing.0 == "abandoned" {
            if existing.2 == Some(abandoned_at_ms)
                && existing.3.as_deref() == Some(reason_code)
                && existing.4.as_deref() == reason_message
            {
                return Ok(());
            }
            return Err(StoreError::IdempotencyConflict {
                entity: "exact_group_abandonment",
                key: build_id.to_string(),
            });
        }
        if existing.0 != "draft" {
            return Err(StoreError::ConcurrencyConflict {
                entity: "exact_group_build_state",
                id: build_id,
            });
        }
        if abandoned_at_ms < existing.1 {
            return Err(StoreError::invalid_input(
                "abandoned_at_ms",
                "abandonment cannot predate the draft",
            ));
        }
        let changed = self.transaction.execute(
            "UPDATE exact_group_builds \
             SET state = 'abandoned', finalized_at_ms = ?3, abandon_reason_code = ?4, \
                 abandon_reason_message = ?5 \
             WHERE id = ?1 AND scan_run_id = ?2 AND state = 'draft'",
            params![
                build_id,
                guard.scan_run_id,
                abandoned_at_ms,
                reason_code,
                reason_message,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::ConcurrencyConflict {
                entity: "exact_group_abandonment",
                id: build_id,
            });
        }
        Ok(())
    }

    fn abandon_group_drafts_for_terminal_run_impl(
        &self,
        scan_run_id: i64,
        now_ms: i64,
    ) -> Result<u64> {
        require_positive("scan_run_id", scan_run_id)?;
        require_nonnegative("now_ms", now_ms)?;
        let (terminal, newest_draft_created_at): (bool, Option<i64>) = self.transaction.query_row(
            "SELECT run.state IN ('completed', 'failed', 'cancelled', 'interrupted'), \
                    (SELECT max(build.created_at_ms) FROM exact_group_builds AS build \
                     WHERE build.scan_run_id = run.id AND build.state = 'draft') \
             FROM scan_runs AS run WHERE run.id = ?1",
            [scan_run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if !terminal {
            return Err(StoreError::ConcurrencyConflict {
                entity: "terminal_scan_run",
                id: scan_run_id,
            });
        }
        if newest_draft_created_at.is_some_and(|created_at| created_at > now_ms) {
            return Err(StoreError::invalid_input(
                "now_ms",
                "abandon time cannot predate a draft group",
            ));
        }
        let changed = self.transaction.execute(
            "UPDATE exact_group_builds \
             SET state = 'abandoned', finalized_at_ms = ?2, \
                 abandon_reason_code = 'RUN_TERMINATED', \
                 abandon_reason_message = \
                    'run reached a terminal state before draft finalization' \
             WHERE scan_run_id = ?1 AND state = 'draft'",
            params![scan_run_id, now_ms],
        )?;
        u64::try_from(changed)
            .map_err(|_| StoreError::invalid_input("abandoned_group_count", "row count overflow"))
    }

    fn ensure_no_verified_exact_group_overlap(&self, build_id: i64) -> Result<()> {
        let observation_overlap = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 \
                 FROM exact_group_builds AS candidate_build \
                 JOIN exact_group_build_members AS candidate_member \
                   ON candidate_member.exact_group_build_id = candidate_build.id \
                 JOIN exact_group_builds AS verified_build \
                   ON verified_build.scan_run_id = candidate_build.scan_run_id \
                  AND verified_build.volume_id = candidate_build.volume_id \
                  AND verified_build.state = 'verified' \
                  AND verified_build.id <> candidate_build.id \
                 JOIN exact_group_build_members AS verified_member \
                   ON verified_member.exact_group_build_id = verified_build.id \
                  AND verified_member.media_observation_snapshot_id = \
                      candidate_member.media_observation_snapshot_id \
                 WHERE candidate_build.id = ?1 \
             )",
            [build_id],
            |row| row.get::<_, bool>(0),
        )?;
        if observation_overlap {
            return Err(StoreError::IdempotencyConflict {
                entity: "verified_exact_group_observation_overlap",
                key: build_id.to_string(),
            });
        }
        let file_object_overlap = self.transaction.query_row(
            "SELECT EXISTS( \
                 SELECT 1 \
                 FROM exact_group_builds AS candidate_build \
                 JOIN exact_group_build_members AS candidate_member \
                   ON candidate_member.exact_group_build_id = candidate_build.id \
                 JOIN media_observation_snapshots AS candidate_observation \
                   ON candidate_observation.id = \
                      candidate_member.media_observation_snapshot_id \
                  AND candidate_observation.scan_run_id = candidate_member.scan_run_id \
                  AND candidate_observation.volume_id = candidate_member.volume_id \
                 JOIN exact_group_builds AS verified_build \
                   ON verified_build.scan_run_id = candidate_build.scan_run_id \
                  AND verified_build.volume_id = candidate_build.volume_id \
                  AND verified_build.state = 'verified' \
                  AND verified_build.id <> candidate_build.id \
                 JOIN exact_group_build_members AS verified_member \
                   ON verified_member.exact_group_build_id = verified_build.id \
                 JOIN media_observation_snapshots AS verified_observation \
                   ON verified_observation.id = \
                      verified_member.media_observation_snapshot_id \
                  AND verified_observation.scan_run_id = verified_member.scan_run_id \
                  AND verified_observation.volume_id = verified_member.volume_id \
                 WHERE candidate_build.id = ?1 \
                   AND candidate_observation.file_object_key IS NOT NULL \
                   AND candidate_observation.file_object_key = \
                       verified_observation.file_object_key \
             )",
            [build_id],
            |row| row.get::<_, bool>(0),
        )?;
        if file_object_overlap {
            return Err(StoreError::IdempotencyConflict {
                entity: "verified_exact_group_file_object_overlap",
                key: build_id.to_string(),
            });
        }
        Ok(())
    }

    fn load_draft_build(&self, run_id: i64, build_id: i64) -> Result<StoredDraftBuild> {
        self.transaction
            .query_row(
                "SELECT representative_observation_id, representative_fingerprint_id, \
                        expected_member_count, expected_edge_count, expected_manifest_digest, \
                        created_at_ms \
                 FROM exact_group_builds \
                 WHERE id = ?1 AND scan_run_id = ?2 AND state = 'draft'",
                params![build_id, run_id],
                |row| {
                    let manifest = fixed_32_from_sql(row.get::<_, Vec<u8>>(4)?, 4)?;
                    Ok(StoredDraftBuild {
                        representative_observation_id: row.get(0)?,
                        representative_fingerprint_id: row.get(1)?,
                        expected_member_count: row.get(2)?,
                        expected_edge_count: row.get(3)?,
                        expected_manifest_digest: ManifestDigest::from_runtime_evidence(manifest),
                        created_at_ms: row.get(5)?,
                    })
                },
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StoreError::ConcurrencyConflict {
                    entity: "draft_exact_group",
                    id: build_id,
                },
                other => StoreError::from(other),
            })
    }

    fn load_exact_evidence(
        &self,
        run_id: i64,
        observation_id: i64,
        fingerprint_id: i64,
    ) -> Result<ExactEvidence> {
        self.transaction
            .query_row(
                "SELECT observation.id, fingerprint.id, path.stable_path_key, \
                        observation.source_signature, observation.size_bytes, \
                        observation.file_object_key, fingerprint.fingerprint_kind, \
                        fingerprint.algorithm, fingerprint.algorithm_version, \
                        fingerprint.parameters_hash, fingerprint.digest, \
                        fingerprint.observed_size_bytes, fingerprint.bytes_read, \
                        fingerprint.reached_expected_eof, fingerprint.source_signature_before, \
                        fingerprint.source_signature_after \
                 FROM media_observation_snapshots AS observation \
                 JOIN media_namespace_paths AS path \
                   ON path.id = observation.media_namespace_path_id \
                  AND path.volume_id = observation.volume_id \
                 JOIN observation_fingerprints AS fingerprint \
                   ON fingerprint.id = ?3 \
                  AND fingerprint.media_observation_snapshot_id = observation.id \
                  AND fingerprint.scan_run_id = observation.scan_run_id \
                  AND fingerprint.volume_id = observation.volume_id \
                 WHERE observation.scan_run_id = ?1 AND observation.id = ?2",
                params![run_id, observation_id, fingerprint_id],
                ExactEvidence::from_lookup_row,
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StoreError::IdempotencyConflict {
                    entity: "v5_exact_evidence",
                    key: format!("{run_id}:{observation_id}:{fingerprint_id}"),
                },
                other => StoreError::from(other),
            })
    }

    fn load_verified_exact_group(
        &self,
        build_id: i64,
        expected_finalized_at_ms: Option<i64>,
    ) -> Result<VerifiedExactGroup> {
        self.transaction
            .query_row(
                "SELECT group_key, expected_member_count, expected_edge_count, \
                        independent_file_count, logical_reclaimable_bytes, \
                        expected_manifest_digest, finalized_at_ms \
                 FROM exact_group_builds WHERE id = ?1 AND state = 'verified'",
                [build_id],
                |row| {
                    let group_key = fixed_32_from_sql(row.get::<_, Vec<u8>>(0)?, 0)?;
                    let manifest = fixed_32_from_sql(row.get::<_, Vec<u8>>(5)?, 5)?;
                    Ok(VerifiedExactGroup {
                        build_id,
                        group_key: ExactGroupKey::from_runtime_evidence(group_key),
                        member_count: row.get(1)?,
                        edge_count: row.get(2)?,
                        independent_file_count: row.get(3)?,
                        logical_reclaimable_bytes: row.get(4)?,
                        manifest_digest: ManifestDigest::from_runtime_evidence(manifest),
                        finalized_at_ms: row.get(6)?,
                    })
                },
            )
            .map_err(StoreError::from)
            .and_then(|record| {
                if expected_finalized_at_ms
                    .is_some_and(|expected| expected != record.finalized_at_ms)
                {
                    return Err(StoreError::IdempotencyConflict {
                        entity: "exact_group_finalize",
                        key: build_id.to_string(),
                    });
                }
                Ok(record)
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    fn record_bound_scan_issue_impl(
        &mut self,
        guard: &RunEvidenceGuard,
        input: &NewScanIssue,
    ) -> Result<i64> {
        let context = self.validate_v5_run_guard(guard)?;
        if input.scan_run_id != guard.scan_run_id || input.volume_id != context.volume_id {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_issue_run_evidence_guard",
                id: input.scan_run_id,
            });
        }
        if let Some(media_file_id) = input.media_file_id {
            let observed_by_run = self.transaction.query_row(
                "SELECT EXISTS( \
                     SELECT 1 FROM media_observation_snapshots \
                     WHERE scan_run_id = ?1 AND volume_id = ?2 AND media_file_id = ?3 \
                 )",
                params![guard.scan_run_id, context.volume_id, media_file_id],
                |row| row.get::<_, bool>(0),
            )?;
            if !observed_by_run {
                return Err(StoreError::invalid_input(
                    "media_file_id",
                    "scan issue media file must have an observation in this run",
                ));
            }
        }
        self.record_scan_issue_impl(input)
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

    #[allow(dead_code)]
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

    fn update_bound_scan_progress_impl(
        &mut self,
        guard: &RunEvidenceGuard,
        discovered_count: i64,
        fingerprinted_count: i64,
        error_count: i64,
        logical_bytes_seen: i64,
        heartbeat_at_ms: i64,
    ) -> Result<()> {
        self.validate_v5_run_guard(guard)?;
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
                guard.scan_run_id,
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
                id: guard.scan_run_id,
            });
        }
        Ok(())
    }

    fn save_bound_scan_checkpoint_impl(
        &mut self,
        guard: &RunEvidenceGuard,
        input: &ScanCheckpointInput,
    ) -> Result<i64> {
        let context = self.validate_v5_run_guard(guard)?;
        require_positive("scan_run_id", input.scan_run_id)?;
        require_positive("volume_id", input.volume_id)?;
        if input.scan_run_id != guard.scan_run_id || input.volume_id != context.volume_id {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_checkpoint_run_evidence_guard",
                id: input.scan_run_id,
            });
        }
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
    fn transition_bound_scan_job_and_run_impl(
        &mut self,
        guard: &RunEvidenceGuard,
        scan_job_id: i64,
        expected_job_state: &str,
        expected_job_version: i64,
        expected_run_state: &str,
        expected_run_version: i64,
        target_job_state: &str,
        target_run_state: &str,
        now_ms: i64,
        last_error: Option<(&str, &str)>,
    ) -> Result<(i64, i64)> {
        let context = self.validate_v5_bound_run_guard(guard)?;
        if context.scan_job_id != scan_job_id {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_job_run_evidence_guard",
                id: scan_job_id,
            });
        }
        let scan_run_id = guard.scan_run_id;
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

        self.validate_running_transition_profile(
            scan_job_id,
            scan_run_id,
            guard.capability_profile_id,
            &guard.mount_session_key.to_storage_hex(),
        )?;
        if target_job_state == "completed" && target_run_state == "completed" {
            self.require_stage_sealed(scan_run_id, ScanStage::ExactVerification)?;
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
             ) OR EXISTS( \
                 SELECT 1 \
                 FROM scan_jobs AS job \
                 JOIN scan_job_runs AS binding \
                   ON binding.scan_job_id = job.id \
                  AND binding.scan_run_id = job.active_scan_run_id \
                  AND binding.volume_id = job.volume_id \
                 JOIN scan_runs AS run \
                   ON run.id = binding.scan_run_id \
                  AND run.volume_id = binding.volume_id \
                 JOIN scan_job_scopes AS scope \
                   ON scope.scan_job_id = job.id AND scope.volume_id = job.volume_id \
                 JOIN scan_run_sessions AS session \
                   ON session.scan_run_id = run.id \
                  AND session.scan_job_id = job.id \
                  AND session.volume_id = run.volume_id \
                  AND session.namespace_profile_id = scope.namespace_profile_id \
                  AND session.stable_root_path_key = scope.stable_root_path_key \
                  AND session.root_scope_key = scope.root_scope_key \
                 JOIN namespace_profiles AS namespace \
                   ON namespace.id = session.namespace_profile_id \
                  AND namespace.volume_id = session.volume_id \
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
                   AND job_root.capability_profile_id IS NULL \
                   AND run_root.capability_profile_id = ?3 \
                   AND run.capability_profile_id = ?3 \
                   AND session.capability_profile_id = ?3 \
                   AND session.mount_session_key = ?4 \
                   AND profile.mount_session_key = session.mount_session_key \
                   AND profile.profile_hash_version = 2 \
                   AND profile.is_current = 1 \
                   AND profile.probe_status = 'complete' \
                   AND profile.can_read = 1 \
                   AND profile.probe_protocol_version IS NOT NULL \
                   AND profile.path_encoding_family IS NOT NULL \
                   AND namespace.origin = 'observed_v5' \
                   AND namespace.reuse_scope <> 'history_only' \
                   AND scope.origin = 'observed_v5' \
                   AND scope.mount_relative_root_raw = session.mount_relative_root_raw \
                   AND scope.path_encoding = session.path_encoding \
                   AND job_root.relative_path_raw = scope.mount_relative_root_raw \
                   AND job_root.path_encoding = scope.path_encoding \
                   AND job_root.semantic_path_key = scope.stable_root_path_key \
                   AND run_root.relative_path_raw = session.mount_relative_root_raw \
                   AND run_root.path_encoding = session.path_encoding \
                   AND run_root.semantic_path_key = session.stable_root_path_key \
                   AND profile.path_semantics_version = run_root.path_semantics_version \
                   AND ((profile.path_encoding_family = 'unix' \
                         AND session.path_encoding IN ('utf8', 'unix_bytes')) \
                     OR (profile.path_encoding_family = 'windows' \
                         AND session.path_encoding = 'windows_utf16_le')) \
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

#[derive(Debug)]
struct BoundRunContext {
    scan_run_id: i64,
    volume_id: i64,
    namespace_profile_id: i64,
    capability_profile_id: i64,
    path_encoding: String,
    mount_relative_root_raw: Vec<u8>,
    root_path_encoding: String,
    scan_job_id: i64,
    run_state: String,
    job_state: String,
    root_display: String,
}

#[derive(Debug)]
struct StoredNamespaceProfile {
    id: i64,
    profile_version: i64,
    origin: String,
    native_path_encoding: Option<String>,
    case_behavior: Option<String>,
    unicode_behavior: Option<String>,
    key_strategy: Option<String>,
    key_algorithm_version: Option<i64>,
    reuse_scope: String,
    bound_mount_session_key: Option<String>,
    legacy_capability_profile_id: Option<i64>,
    created_at_ms: i64,
}

#[derive(Debug)]
struct StoredScopedJob {
    volume_id: i64,
    root_display: String,
    state: String,
    active_scan_run_id: Option<i64>,
    namespace_profile_id: i64,
    scope_raw: Vec<u8>,
    scope_encoding: String,
    scope_stable_key: Vec<u8>,
    scope_root_key: Vec<u8>,
    recoverable: i64,
    reuse_scope: String,
    bound_mount_session_key: Option<String>,
    identity_strength: String,
}

#[derive(Debug)]
struct StoredBoundScanRun {
    id: i64,
    volume_id: i64,
    capability_profile_id: i64,
    parent_scan_run_id: Option<i64>,
    root_display: String,
    stable_root_path_key: Vec<u8>,
    scan_mode: String,
    config_json: Option<String>,
    created_at_ms: i64,
    scan_job_id: Option<i64>,
    namespace_profile_id: Option<i64>,
    mount_session_key: Option<String>,
    mount_relative_root_raw: Option<Vec<u8>>,
    path_encoding: Option<String>,
    session_stable_root_path_key: Option<Vec<u8>>,
    root_scope_key: Option<Vec<u8>>,
    root_object_signature: Option<Vec<u8>>,
    session_created_at_ms: Option<i64>,
}

#[derive(Debug)]
struct StoredDraftBuild {
    representative_observation_id: i64,
    representative_fingerprint_id: i64,
    expected_member_count: i64,
    expected_edge_count: i64,
    expected_manifest_digest: ManifestDigest,
    created_at_ms: i64,
}

#[derive(Debug, Clone)]
struct ExactEvidence {
    ordinal: Option<i64>,
    observation_id: i64,
    fingerprint_id: i64,
    sort_rank: Option<i64>,
    stored_manifest_leaf: Option<Vec<u8>>,
    stable_path_key: crate::model::StablePathKey,
    source_signature: SourceSignature,
    size_bytes: i64,
    file_object_key: Option<crate::model::FileObjectKey>,
    fingerprint_kind: String,
    algorithm: String,
    algorithm_version: i64,
    parameters_hash: crate::model::ParametersHash,
    digest: Vec<u8>,
    observed_size_bytes: i64,
    bytes_read: i64,
    reached_expected_eof: bool,
    source_signature_before: SourceSignature,
    source_signature_after: SourceSignature,
}

impl ExactEvidence {
    fn from_lookup_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            ordinal: None,
            observation_id: row.get(0)?,
            fingerprint_id: row.get(1)?,
            sort_rank: None,
            stored_manifest_leaf: None,
            stable_path_key: crate::model::StablePathKey::from_volume_adapter(fixed_32_from_sql(
                row.get::<_, Vec<u8>>(2)?,
                2,
            )?),
            source_signature: SourceSignature::from_runtime_evidence(fixed_32_from_sql(
                row.get::<_, Vec<u8>>(3)?,
                3,
            )?),
            size_bytes: row.get(4)?,
            file_object_key: row
                .get::<_, Option<Vec<u8>>>(5)?
                .map(|bytes| fixed_32_from_sql(bytes, 5))
                .transpose()?
                .map(crate::model::FileObjectKey::from_runtime_evidence),
            fingerprint_kind: row.get(6)?,
            algorithm: row.get(7)?,
            algorithm_version: row.get(8)?,
            parameters_hash: crate::model::ParametersHash::from_runtime_evidence(
                fixed_32_from_sql(row.get::<_, Vec<u8>>(9)?, 9)?,
            ),
            digest: row.get(10)?,
            observed_size_bytes: row.get(11)?,
            bytes_read: row.get(12)?,
            reached_expected_eof: row.get::<_, i64>(13)? == 1,
            source_signature_before: SourceSignature::from_runtime_evidence(fixed_32_from_sql(
                row.get::<_, Vec<u8>>(14)?,
                14,
            )?),
            source_signature_after: SourceSignature::from_runtime_evidence(fixed_32_from_sql(
                row.get::<_, Vec<u8>>(15)?,
                15,
            )?),
        })
    }

    fn from_finalize_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            ordinal: Some(row.get(0)?),
            observation_id: row.get(1)?,
            fingerprint_id: row.get(2)?,
            sort_rank: Some(row.get(3)?),
            stored_manifest_leaf: Some(row.get(4)?),
            stable_path_key: crate::model::StablePathKey::from_volume_adapter(fixed_32_from_sql(
                row.get::<_, Vec<u8>>(5)?,
                5,
            )?),
            source_signature: SourceSignature::from_runtime_evidence(fixed_32_from_sql(
                row.get::<_, Vec<u8>>(6)?,
                6,
            )?),
            size_bytes: row.get(7)?,
            file_object_key: row
                .get::<_, Option<Vec<u8>>>(8)?
                .map(|bytes| fixed_32_from_sql(bytes, 8))
                .transpose()?
                .map(crate::model::FileObjectKey::from_runtime_evidence),
            fingerprint_kind: row.get(9)?,
            algorithm: row.get(10)?,
            algorithm_version: row.get(11)?,
            parameters_hash: crate::model::ParametersHash::from_runtime_evidence(
                fixed_32_from_sql(row.get::<_, Vec<u8>>(12)?, 12)?,
            ),
            digest: row.get(13)?,
            observed_size_bytes: row.get(14)?,
            bytes_read: row.get(15)?,
            reached_expected_eof: row.get::<_, i64>(16)? == 1,
            source_signature_before: SourceSignature::from_runtime_evidence(fixed_32_from_sql(
                row.get::<_, Vec<u8>>(17)?,
                17,
            )?),
            source_signature_after: SourceSignature::from_runtime_evidence(fixed_32_from_sql(
                row.get::<_, Vec<u8>>(18)?,
                18,
            )?),
        })
    }

    fn validate_current_exact(&self) -> Result<()> {
        require_positive("observation_id", self.observation_id)?;
        require_positive("fingerprint_id", self.fingerprint_id)?;
        require_nonnegative("size_bytes", self.size_bytes)?;
        require_nonnegative("observed_size_bytes", self.observed_size_bytes)?;
        require_nonnegative("bytes_read", self.bytes_read)?;
        require_bounded_nonempty("algorithm", &self.algorithm, MAX_IDENTIFIER_BYTES)?;
        require_positive("algorithm_version", self.algorithm_version)?;
        if self.digest.is_empty() || self.digest.len() > MAX_OPAQUE_BLOB_BYTES.min(1_024) {
            return Err(StoreError::invalid_input(
                "digest",
                "exact fingerprint digest must contain between 1 and 1024 bytes",
            ));
        }
        if self.fingerprint_kind != "exact_bytes"
            || !self.reached_expected_eof
            || self.observed_size_bytes != self.size_bytes
            || self.bytes_read != self.size_bytes
            || self.source_signature_before != self.source_signature
            || self.source_signature_after != self.source_signature
        {
            return Err(StoreError::invalid_input(
                "exact_fingerprint",
                "fingerprint is not complete current observation evidence",
            ));
        }
        Ok(())
    }

    fn same_fingerprint_material(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm
            && self.algorithm_version == other.algorithm_version
            && self.parameters_hash == other.parameters_hash
            && self.digest == other.digest
            && self.size_bytes == other.size_bytes
    }

    fn to_manifest_member(
        &self,
        input: &ExactGroupMemberInput,
    ) -> Result<ExactGroupManifestMember> {
        Ok(ExactGroupManifestMember {
            ordinal: checked_u64("ordinal", input.ordinal)?,
            observation_id: checked_u64("observation_id", self.observation_id)?,
            fingerprint_id: checked_u64("fingerprint_id", self.fingerprint_id)?,
            sort_rank: checked_u64("sort_rank", input.sort_rank)?,
            stable_path_key: self.stable_path_key,
            source_signature: self.source_signature,
            size_bytes: checked_u64("size_bytes", self.size_bytes)?,
            algorithm: self.algorithm.clone(),
            algorithm_version: checked_u32("algorithm_version", self.algorithm_version)?,
            parameters_hash: self.parameters_hash,
            digest: self.digest.clone(),
            file_object_key: self.file_object_key,
        })
    }

    fn to_manifest_member_from_stored(&self) -> Result<ExactGroupManifestMember> {
        self.to_manifest_member(&ExactGroupMemberInput {
            ordinal: self.ordinal.ok_or_else(|| {
                StoreError::invalid_input("ordinal", "stored member is missing its ordinal")
            })?,
            observation_id: self.observation_id,
            fingerprint_id: self.fingerprint_id,
            sort_rank: self.sort_rank.ok_or_else(|| {
                StoreError::invalid_input("sort_rank", "stored member is missing its sort rank")
            })?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExactFingerprintCommon {
    algorithm: String,
    algorithm_version: i64,
    parameters_hash: crate::model::ParametersHash,
    digest: Vec<u8>,
    size_bytes: i64,
}

impl ExactFingerprintCommon {
    fn from_evidence(evidence: &ExactEvidence) -> Self {
        Self {
            algorithm: evidence.algorithm.clone(),
            algorithm_version: evidence.algorithm_version,
            parameters_hash: evidence.parameters_hash,
            digest: evidence.digest.clone(),
            size_bytes: evidence.size_bytes,
        }
    }
}

#[derive(Debug)]
struct StoredExactGroupAudit {
    id: i64,
    scan_run_id: i64,
    state: String,
    representative_observation_id: i64,
    representative_fingerprint_id: i64,
    expected_member_count: i64,
    expected_edge_count: i64,
    expected_manifest_digest: ManifestDigest,
    group_key: Option<ExactGroupKey>,
    independent_file_count: Option<i64>,
    logical_reclaimable_bytes: Option<i64>,
    created_at_ms: i64,
    finalized_at_ms: Option<i64>,
}

#[derive(Debug)]
struct RecomputedExactGroup {
    member_count: i64,
    edge_count: i64,
    manifest_digest: ManifestDigest,
    group_key: ExactGroupKey,
    independent_file_count: i64,
    logical_reclaimable_bytes: i64,
}

pub(crate) fn verify_all_verified_exact_groups(connection: &Connection) -> Result<()> {
    let mut after_id = 0_i64;
    loop {
        let build_id = connection
            .query_row(
                "SELECT id FROM exact_group_builds \
                 WHERE state = 'verified' AND id > ?1 ORDER BY id LIMIT 1",
                [after_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(build_id) = build_id else {
            return Ok(());
        };
        let build = load_exact_group_audit(connection, build_id).map_err(|error| {
            StoreError::MigrationHistoryMismatch(format!(
                "cannot load verified exact group {build_id}: {error}"
            ))
        })?;
        let recomputed = recompute_exact_group(connection, &build).map_err(|error| {
            StoreError::MigrationHistoryMismatch(format!(
                "cannot verify exact group {build_id}: {error}"
            ))
        })?;
        if build.state != "verified"
            || build.finalized_at_ms.is_none()
            || build
                .finalized_at_ms
                .is_some_and(|time| time < build.created_at_ms)
            || build.group_key != Some(recomputed.group_key)
            || build.independent_file_count != Some(recomputed.independent_file_count)
            || build.logical_reclaimable_bytes != Some(recomputed.logical_reclaimable_bytes)
            || build.expected_member_count != recomputed.member_count
            || build.expected_edge_count != recomputed.edge_count
            || build.expected_manifest_digest != recomputed.manifest_digest
        {
            return Err(StoreError::MigrationHistoryMismatch(format!(
                "verified exact group {build_id} does not match its immutable evidence"
            )));
        }
        after_id = build_id;
    }
}

fn load_exact_group_audit(connection: &Connection, build_id: i64) -> Result<StoredExactGroupAudit> {
    connection
        .query_row(
            "SELECT id, scan_run_id, state, representative_observation_id, \
                    representative_fingerprint_id, expected_member_count, expected_edge_count, \
                    expected_manifest_digest, group_key, independent_file_count, \
                    logical_reclaimable_bytes, created_at_ms, finalized_at_ms \
             FROM exact_group_builds WHERE id = ?1",
            [build_id],
            |row| {
                let expected_manifest_digest = ManifestDigest::from_runtime_evidence(
                    fixed_32_from_sql(row.get::<_, Vec<u8>>(7)?, 7)?,
                );
                let group_key = row
                    .get::<_, Option<Vec<u8>>>(8)?
                    .map(|bytes| fixed_32_from_sql(bytes, 8))
                    .transpose()?
                    .map(ExactGroupKey::from_runtime_evidence);
                Ok(StoredExactGroupAudit {
                    id: row.get(0)?,
                    scan_run_id: row.get(1)?,
                    state: row.get(2)?,
                    representative_observation_id: row.get(3)?,
                    representative_fingerprint_id: row.get(4)?,
                    expected_member_count: row.get(5)?,
                    expected_edge_count: row.get(6)?,
                    expected_manifest_digest,
                    group_key,
                    independent_file_count: row.get(9)?,
                    logical_reclaimable_bytes: row.get(10)?,
                    created_at_ms: row.get(11)?,
                    finalized_at_ms: row.get(12)?,
                })
            },
        )
        .map_err(StoreError::from)
}

fn recompute_exact_group(
    connection: &Connection,
    build: &StoredExactGroupAudit,
) -> Result<RecomputedExactGroup> {
    require_positive("build_id", build.id)?;
    require_positive("scan_run_id", build.scan_run_id)?;
    require_positive(
        "representative_observation_id",
        build.representative_observation_id,
    )?;
    require_positive(
        "representative_fingerprint_id",
        build.representative_fingerprint_id,
    )?;
    if build.expected_member_count < 2
        || build.expected_edge_count
            != build.expected_member_count.checked_sub(1).ok_or_else(|| {
                StoreError::invalid_input("expected_member_count", "member count underflow")
            })?
    {
        return Err(StoreError::invalid_input(
            "expected_member_count",
            "exact group member and edge counts are inconsistent",
        ));
    }
    let (member_count, min_ordinal, max_ordinal): (i64, Option<i64>, Option<i64>) = connection
        .query_row(
            "SELECT count(*), min(ordinal), max(ordinal) \
             FROM exact_group_build_members WHERE exact_group_build_id = ?1",
            [build.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    if member_count != build.expected_member_count
        || min_ordinal != Some(0)
        || max_ordinal != build.expected_member_count.checked_sub(1)
    {
        return Err(StoreError::invalid_input(
            "exact_group_members",
            "member count or ordinal coverage does not match the group manifest",
        ));
    }
    let representative_member_matches = connection.query_row(
        "SELECT EXISTS( \
             SELECT 1 FROM exact_group_build_members \
             WHERE exact_group_build_id = ?1 AND ordinal = 0 \
               AND media_observation_snapshot_id = ?2 \
               AND observation_fingerprint_id = ?3 \
         )",
        params![
            build.id,
            build.representative_observation_id,
            build.representative_fingerprint_id,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !representative_member_matches {
        return Err(StoreError::invalid_input(
            "exact_group_members",
            "ordinal zero is not the declared representative",
        ));
    }
    let edge_count: i64 = connection.query_row(
        "SELECT count(*) FROM exact_verification_edges WHERE exact_group_build_id = ?1",
        [build.id],
        |row| row.get(0),
    )?;
    if edge_count != build.expected_edge_count {
        return Err(StoreError::invalid_input(
            "exact_verification_edges",
            "edge count does not match the group manifest",
        ));
    }
    let invalid_edge_bindings: i64 = connection.query_row(
        "SELECT count(*) \
         FROM exact_group_build_members AS member \
         LEFT JOIN exact_verification_edges AS edge \
           ON edge.exact_group_build_id = member.exact_group_build_id \
          AND edge.member_observation_id = member.media_observation_snapshot_id \
         WHERE member.exact_group_build_id = ?1 \
           AND ((member.ordinal = 0 AND edge.member_observation_id IS NOT NULL) \
             OR (member.ordinal > 0 AND ( \
                   edge.member_observation_id IS NULL \
                   OR edge.member_fingerprint_id <> member.observation_fingerprint_id \
                   OR edge.representative_observation_id <> ?2 \
                   OR edge.representative_fingerprint_id <> ?3 \
             )))",
        params![
            build.id,
            build.representative_observation_id,
            build.representative_fingerprint_id,
        ],
        |row| row.get(0),
    )?;
    if invalid_edge_bindings != 0 {
        return Err(StoreError::invalid_input(
            "exact_verification_edges",
            "each non-representative member must have exactly its own edge",
        ));
    }

    let mut manifest_hasher = blake3::Hasher::new();
    manifest_hasher.update(b"guiying.exact-group-manifest.v1\0");
    manifest_hasher.update(&checked_u64("member_count", member_count)?.to_le_bytes());
    let mut common: Option<ExactFingerprintCommon> = None;
    let mut streamed_members = 0_i64;
    let mut statement = connection.prepare(
        "SELECT member.ordinal, member.media_observation_snapshot_id, \
                member.observation_fingerprint_id, member.sort_rank, member.manifest_leaf, \
                path.stable_path_key, observation.source_signature, observation.size_bytes, \
                observation.file_object_key, fingerprint.fingerprint_kind, \
                fingerprint.algorithm, fingerprint.algorithm_version, \
                fingerprint.parameters_hash, fingerprint.digest, \
                fingerprint.observed_size_bytes, fingerprint.bytes_read, \
                fingerprint.reached_expected_eof, fingerprint.source_signature_before, \
                fingerprint.source_signature_after, member.created_at_ms \
         FROM exact_group_build_members AS member \
         JOIN media_observation_snapshots AS observation \
           ON observation.id = member.media_observation_snapshot_id \
          AND observation.scan_run_id = member.scan_run_id \
          AND observation.volume_id = member.volume_id \
         JOIN media_namespace_paths AS path \
           ON path.id = observation.media_namespace_path_id \
          AND path.volume_id = observation.volume_id \
         JOIN observation_fingerprints AS fingerprint \
           ON fingerprint.id = member.observation_fingerprint_id \
          AND fingerprint.media_observation_snapshot_id = observation.id \
          AND fingerprint.scan_run_id = observation.scan_run_id \
          AND fingerprint.volume_id = observation.volume_id \
         WHERE member.exact_group_build_id = ?1 \
           AND member.scan_run_id = ?2 \
         ORDER BY member.ordinal",
    )?;
    let mut rows = statement.query(params![build.id, build.scan_run_id])?;
    while let Some(row) = rows.next()? {
        let evidence = ExactEvidence::from_finalize_row(row)?;
        evidence.validate_current_exact()?;
        if evidence.ordinal != Some(streamed_members)
            || row.get::<_, i64>(19)? != build.created_at_ms
        {
            return Err(StoreError::invalid_input(
                "exact_group_members",
                "member ordinal or creation evidence is inconsistent",
            ));
        }
        let row_common = ExactFingerprintCommon::from_evidence(&evidence);
        if let Some(expected) = common.as_ref() {
            if expected != &row_common {
                return Err(StoreError::invalid_input(
                    "exact_group_members",
                    "member exact fingerprints do not have identical material",
                ));
            }
        } else {
            common = Some(row_common);
        }
        let material = evidence.to_manifest_member_from_stored()?;
        let computed_leaf = compute_exact_group_member_leaf(&material)?;
        if evidence.stored_manifest_leaf.as_deref() != Some(computed_leaf.as_bytes()) {
            return Err(StoreError::invalid_input(
                "manifest_leaf",
                "stored member leaf does not match database evidence",
            ));
        }
        manifest_hasher.update(computed_leaf.as_bytes());
        streamed_members = streamed_members
            .checked_add(1)
            .ok_or_else(|| StoreError::invalid_input("member_count", "member count overflow"))?;
    }
    drop(rows);
    drop(statement);
    if streamed_members != build.expected_member_count {
        return Err(StoreError::invalid_input(
            "member_count",
            "streamed member count differs from the group",
        ));
    }
    let manifest_digest =
        ManifestDigest::from_runtime_evidence(*manifest_hasher.finalize().as_bytes());
    if manifest_digest != build.expected_manifest_digest {
        return Err(StoreError::invalid_input(
            "exact_group_manifest",
            "recomputed manifest differs from the expected digest",
        ));
    }
    let common = common.ok_or_else(|| {
        StoreError::invalid_input("exact_group_members", "group contains no members")
    })?;
    let invalid_edges: i64 = connection.query_row(
        "SELECT count(*) \
         FROM exact_verification_edges AS edge \
         JOIN media_observation_snapshots AS representative \
           ON representative.id = edge.representative_observation_id \
          AND representative.scan_run_id = edge.scan_run_id \
          AND representative.volume_id = edge.volume_id \
         JOIN media_observation_snapshots AS member \
           ON member.id = edge.member_observation_id \
          AND member.scan_run_id = edge.scan_run_id \
          AND member.volume_id = edge.volume_id \
         JOIN observation_fingerprints AS representative_fp \
           ON representative_fp.id = edge.representative_fingerprint_id \
          AND representative_fp.media_observation_snapshot_id = representative.id \
          AND representative_fp.scan_run_id = edge.scan_run_id \
         JOIN observation_fingerprints AS member_fp \
           ON member_fp.id = edge.member_fingerprint_id \
          AND member_fp.media_observation_snapshot_id = member.id \
          AND member_fp.scan_run_id = edge.scan_run_id \
         WHERE edge.exact_group_build_id = ?1 AND ( \
                edge.verified_at_ms < ?2 \
             OR edge.representative_source_signature <> representative.source_signature \
             OR edge.member_source_signature <> member.source_signature \
             OR edge.compared_bytes <> representative.size_bytes \
             OR edge.compared_bytes <> member.size_bytes \
             OR representative_fp.fingerprint_kind <> 'exact_bytes' \
             OR member_fp.fingerprint_kind <> 'exact_bytes' \
             OR representative_fp.source_signature_before <> representative.source_signature \
             OR representative_fp.source_signature_after <> representative.source_signature \
             OR member_fp.source_signature_before <> member.source_signature \
             OR member_fp.source_signature_after <> member.source_signature \
             OR representative_fp.algorithm <> member_fp.algorithm \
             OR representative_fp.algorithm_version <> member_fp.algorithm_version \
             OR representative_fp.parameters_hash <> member_fp.parameters_hash \
             OR representative_fp.digest <> member_fp.digest \
             OR representative_fp.observed_size_bytes <> member_fp.observed_size_bytes \
             OR representative_fp.bytes_read <> representative.size_bytes \
             OR member_fp.bytes_read <> member.size_bytes \
             OR representative_fp.reached_expected_eof <> 1 \
             OR member_fp.reached_expected_eof <> 1 \
         )",
        params![build.id, build.created_at_ms],
        |row| row.get(0),
    )?;
    if invalid_edges != 0 {
        return Err(StoreError::invalid_input(
            "exact_verification_edges",
            "verification edge evidence is inconsistent with observations",
        ));
    }
    let independent_file_count: i64 = connection.query_row(
        "SELECT count(DISTINCT observation.file_object_key) \
                + sum(CASE WHEN observation.file_object_key IS NULL THEN 1 ELSE 0 END) \
         FROM exact_group_build_members AS member \
         JOIN media_observation_snapshots AS observation \
           ON observation.id = member.media_observation_snapshot_id \
          AND observation.scan_run_id = member.scan_run_id \
          AND observation.volume_id = member.volume_id \
         WHERE member.exact_group_build_id = ?1 AND member.scan_run_id = ?2",
        params![build.id, build.scan_run_id],
        |row| row.get(0),
    )?;
    if !(1..=member_count).contains(&independent_file_count) {
        return Err(StoreError::invalid_input(
            "file_object_key",
            "independent physical-file count is outside the member count",
        ));
    }
    let logical_reclaimable_bytes = common
        .size_bytes
        .checked_mul(independent_file_count.checked_sub(1).ok_or_else(|| {
            StoreError::invalid_input("independent_file_count", "count underflow")
        })?)
        .ok_or_else(|| {
            StoreError::invalid_input("logical_reclaimable_bytes", "byte count overflow")
        })?;
    let run_key: String = connection.query_row(
        "SELECT run_key FROM scan_runs WHERE id = ?1",
        [build.scan_run_id],
        |row| row.get(0),
    )?;
    let group_key = compute_exact_group_key(&run_key, &common, manifest_digest)?;
    Ok(RecomputedExactGroup {
        member_count,
        edge_count,
        manifest_digest,
        group_key,
        independent_file_count,
        logical_reclaimable_bytes,
    })
}

pub fn compute_exact_group_member_leaf(
    member: &ExactGroupManifestMember,
) -> Result<ManifestDigest> {
    require_bounded_nonempty("algorithm", &member.algorithm, MAX_IDENTIFIER_BYTES)?;
    if member.digest.is_empty() || member.digest.len() > 1_024 {
        return Err(StoreError::invalid_input(
            "digest",
            "fingerprint digest must contain between 1 and 1024 bytes",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.exact-group-member.v1\0");
    hasher.update(&member.ordinal.to_le_bytes());
    hasher.update(&member.observation_id.to_le_bytes());
    hasher.update(&member.fingerprint_id.to_le_bytes());
    hasher.update(&member.sort_rank.to_le_bytes());
    hasher.update(member.stable_path_key.as_bytes());
    hasher.update(member.source_signature.as_bytes());
    hasher.update(&member.size_bytes.to_le_bytes());
    hash_length_prefixed(&mut hasher, member.algorithm.as_bytes())?;
    hasher.update(&member.algorithm_version.to_le_bytes());
    hasher.update(member.parameters_hash.as_bytes());
    hash_length_prefixed(&mut hasher, &member.digest)?;
    match member.file_object_key {
        Some(key) => {
            hasher.update(&[1]);
            hasher.update(key.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    Ok(ManifestDigest::from_runtime_evidence(
        *hasher.finalize().as_bytes(),
    ))
}

pub fn compute_exact_group_manifest(member_leaves: &[ManifestDigest]) -> Result<ManifestDigest> {
    if member_leaves.len() < 2 {
        return Err(StoreError::invalid_input(
            "member_leaves",
            "an exact duplicate manifest requires at least two members",
        ));
    }
    let member_count = u64::try_from(member_leaves.len())
        .map_err(|_| StoreError::invalid_input("member_leaves", "member count overflow"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.exact-group-manifest.v1\0");
    hasher.update(&member_count.to_le_bytes());
    for leaf in member_leaves {
        hasher.update(leaf.as_bytes());
    }
    Ok(ManifestDigest::from_runtime_evidence(
        *hasher.finalize().as_bytes(),
    ))
}

fn compute_exact_group_key(
    run_key: &str,
    common: &ExactFingerprintCommon,
    manifest: ManifestDigest,
) -> Result<ExactGroupKey> {
    require_bounded_nonempty("run_key", run_key, MAX_IDENTIFIER_BYTES)?;
    require_bounded_nonempty("algorithm", &common.algorithm, MAX_IDENTIFIER_BYTES)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.exact-group.v1\0");
    hash_length_prefixed(&mut hasher, run_key.as_bytes())?;
    hash_length_prefixed(&mut hasher, common.algorithm.as_bytes())?;
    hasher.update(&checked_u32("algorithm_version", common.algorithm_version)?.to_le_bytes());
    hasher.update(common.parameters_hash.as_bytes());
    hash_length_prefixed(&mut hasher, &common.digest)?;
    hasher.update(&checked_u64("size_bytes", common.size_bytes)?.to_le_bytes());
    hasher.update(manifest.as_bytes());
    Ok(ExactGroupKey::from_runtime_evidence(
        *hasher.finalize().as_bytes(),
    ))
}

fn hash_length_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) -> Result<()> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| StoreError::invalid_input("manifest", "byte length overflow"))?;
    hasher.update(&length.to_le_bytes());
    hasher.update(bytes);
    Ok(())
}

pub(crate) fn recompute_time_session_scope_manifest(
    connection: &Connection,
    scan_run_id: i64,
) -> Result<(i64, TimeEvidenceManifestDigest)> {
    require_positive("scan_run_id", scan_run_id)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.time-session-exact-scope.v1\0");
    hasher.update(&scan_run_id.to_le_bytes());
    let mut count = 0_i64;
    let mut statement = connection.prepare(
        "SELECT id, group_key, expected_member_count, expected_manifest_digest \
         FROM exact_group_builds \
         WHERE scan_run_id = ?1 AND state = 'verified' ORDER BY id",
    )?;
    let mut rows = statement.query([scan_run_id])?;
    while let Some(row) = rows.next()? {
        let build_id = row.get::<_, i64>(0)?;
        let group_key = row.get::<_, Vec<u8>>(1)?;
        let member_count = row.get::<_, i64>(2)?;
        let manifest = row.get::<_, Vec<u8>>(3)?;
        if group_key.len() != 32 || manifest.len() != 32 || member_count < 2 {
            return Err(StoreError::invalid_input(
                "time_session_manifest",
                "stored verified exact group is malformed",
            ));
        }
        hasher.update(&build_id.to_le_bytes());
        hasher.update(&group_key);
        hasher.update(&member_count.to_le_bytes());
        hasher.update(&manifest);
        count = count.checked_add(1).ok_or_else(|| {
            StoreError::invalid_input("expected_group_count", "group count overflow")
        })?;
    }
    hasher.update(&count.to_le_bytes());
    Ok((
        count,
        TimeEvidenceManifestDigest::from_runtime_evidence(*hasher.finalize().as_bytes()),
    ))
}

pub(crate) fn recompute_time_session_outcome_manifest(
    connection: &Connection,
    time_session_id: i64,
) -> Result<TimeEvidenceManifestDigest> {
    require_positive("time_session_id", time_session_id)?;
    let terminal = connection
        .query_row(
            "SELECT state, finalized_at_ms FROM scan_time_sessions WHERE id = ?1",
            [time_session_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => StoreError::ConcurrencyConflict {
                entity: "time_session_outcome_manifest",
                id: time_session_id,
            },
            other => StoreError::from(other),
        })?;
    let Some(finalized_at_ms) = terminal.1 else {
        return Err(StoreError::invalid_input(
            "time_session_outcome_manifest",
            "outcome manifest requires a complete or partial terminal session",
        ));
    };
    if !matches!(terminal.0.as_str(), "complete" | "partial") {
        return Err(StoreError::invalid_input(
            "time_session_outcome_manifest",
            "outcome manifest requires a complete or partial terminal session",
        ));
    }
    recompute_time_session_outcome_manifest_for_terminal(
        connection,
        time_session_id,
        &terminal.0,
        finalized_at_ms,
    )
}

fn recompute_time_session_outcome_manifest_for_terminal(
    connection: &Connection,
    time_session_id: i64,
    terminal_state: &str,
    finalized_at_ms: i64,
) -> Result<TimeEvidenceManifestDigest> {
    require_positive("time_session_id", time_session_id)?;
    require_nonnegative("finalized_at_ms", finalized_at_ms)?;
    if !matches!(terminal_state, "complete" | "partial") {
        return Err(StoreError::invalid_input(
            "time_session_state",
            "outcome manifest requires complete or partial terminal state",
        ));
    }
    let (scan_run_id, expected_group_count, expected_scope_manifest) = connection
        .query_row(
            "SELECT scan_run_id, expected_group_count, expected_manifest_digest \
             FROM scan_time_sessions WHERE id = ?1",
            [time_session_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => StoreError::ConcurrencyConflict {
                entity: "time_session_outcome_manifest",
                id: time_session_id,
            },
            other => StoreError::from(other),
        })?;
    if expected_scope_manifest.len() != 32 {
        return Err(StoreError::invalid_input(
            "time_session_outcome_manifest",
            "frozen exact-scope digest is malformed",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.time-session-outcomes.v2\0");
    hasher.update(&time_session_id.to_le_bytes());
    hasher.update(&scan_run_id.to_le_bytes());
    let mut evidence_count = 0_i64;
    let mut unavailable_count = 0_i64;
    let mut failed_count = 0_i64;
    let mut statement = connection.prepare(
        "SELECT outcome.exact_group_build_id, outcome.outcome, outcome.analysis_build_id, \
                outcome.reason_code, outcome.created_at_ms, build.sealed_manifest_digest, \
                build.decision, build.selected_candidate_ordinal, build.finalized_at_ms, \
                build.time_session_id, build.exact_group_build_id, build.state \
         FROM capture_time_group_outcomes AS outcome \
         LEFT JOIN capture_time_analysis_builds AS build ON build.id = outcome.analysis_build_id \
         WHERE outcome.time_session_id = ?1 ORDER BY outcome.exact_group_build_id",
    )?;
    let mut rows = statement.query([time_session_id])?;
    while let Some(row) = rows.next()? {
        let group_id = row.get::<_, i64>(0)?;
        let outcome = row.get::<_, String>(1)?;
        let analysis_id = row.get::<_, Option<i64>>(2)?;
        let reason_code = row.get::<_, String>(3)?;
        let created_at_ms = row.get::<_, i64>(4)?;
        let analysis_manifest = row.get::<_, Option<Vec<u8>>>(5)?;
        let analysis_decision = row.get::<_, Option<String>>(6)?;
        let selected_candidate_ordinal = row.get::<_, Option<i64>>(7)?;
        let analysis_finalized_at_ms = row.get::<_, Option<i64>>(8)?;
        let analysis_time_session_id = row.get::<_, Option<i64>>(9)?;
        let analysis_group_id = row.get::<_, Option<i64>>(10)?;
        let analysis_state = row.get::<_, Option<String>>(11)?;
        match outcome.as_str() {
            "evidence" => {
                evidence_count = evidence_count.checked_add(1).ok_or_else(|| {
                    StoreError::invalid_input("evidence_group_count", "count overflow")
                })?;
                if analysis_id.is_none()
                    || !matches!(analysis_manifest.as_deref(), Some(value) if value.len() == 32)
                    || !matches!(
                        analysis_decision.as_deref(),
                        Some(
                            "no_usable_evidence"
                                | "review_required"
                                | "evidence_eligible"
                                | "conflict"
                        )
                    )
                    || analysis_finalized_at_ms.is_none()
                    || analysis_time_session_id != Some(time_session_id)
                    || analysis_group_id != Some(group_id)
                    || analysis_state.as_deref() != Some("sealed")
                {
                    return Err(StoreError::invalid_input(
                        "time_session_outcome_manifest",
                        "evidence outcome lacks its complete sealed analysis decision",
                    ));
                }
            }
            "unavailable" => {
                unavailable_count = unavailable_count.checked_add(1).ok_or_else(|| {
                    StoreError::invalid_input("unavailable_group_count", "count overflow")
                })?;
                if analysis_id.is_some() {
                    return Err(StoreError::invalid_input(
                        "time_session_outcome_manifest",
                        "unavailable outcome must not reference an analysis",
                    ));
                }
            }
            "failed" => {
                failed_count = failed_count.checked_add(1).ok_or_else(|| {
                    StoreError::invalid_input("failed_group_count", "count overflow")
                })?;
                if analysis_id.is_some() {
                    return Err(StoreError::invalid_input(
                        "time_session_outcome_manifest",
                        "failed outcome must not reference an analysis",
                    ));
                }
            }
            _ => {
                return Err(StoreError::invalid_input(
                    "time_session_outcome_manifest",
                    "stored group outcome is not a v7 value",
                ));
            }
        }
        hasher.update(&group_id.to_le_bytes());
        hash_length_prefixed(&mut hasher, outcome.as_bytes())?;
        match analysis_id {
            Some(value) => {
                hasher.update(&[1]);
                hasher.update(&value.to_le_bytes());
                hasher.update(analysis_manifest.as_deref().ok_or_else(|| {
                    StoreError::invalid_input(
                        "time_session_outcome_manifest",
                        "evidence analysis manifest is absent",
                    )
                })?);
                hash_length_prefixed(
                    &mut hasher,
                    analysis_decision
                        .as_deref()
                        .ok_or_else(|| {
                            StoreError::invalid_input(
                                "time_session_outcome_manifest",
                                "evidence analysis decision is absent",
                            )
                        })?
                        .as_bytes(),
                )?;
                match selected_candidate_ordinal {
                    Some(ordinal) => {
                        hasher.update(&[1]);
                        hasher.update(&ordinal.to_le_bytes());
                    }
                    None => {
                        hasher.update(&[0]);
                    }
                }
                hasher.update(
                    &analysis_finalized_at_ms
                        .ok_or_else(|| {
                            StoreError::invalid_input(
                                "time_session_outcome_manifest",
                                "evidence analysis terminal time is absent",
                            )
                        })?
                        .to_le_bytes(),
                );
                hash_length_prefixed(&mut hasher, b"member_filesystem_times")?;
                let mut member_count = 0_i64;
                let mut member_statement = connection.prepare(
                    "SELECT member.member_ordinal, member.media_observation_snapshot_id, \
                            observation.birth_time_seconds, observation.birth_time_nanoseconds, \
                            observation.modified_time_seconds, \
                            observation.modified_time_nanoseconds, \
                            observation.timestamp_granularity_ns \
                     FROM capture_time_member_assessments AS member \
                     JOIN media_observation_snapshots AS observation \
                       ON observation.id = member.media_observation_snapshot_id \
                      AND observation.scan_run_id = member.scan_run_id \
                      AND observation.volume_id = member.volume_id \
                     WHERE member.analysis_build_id = ?1 ORDER BY member.member_ordinal",
                )?;
                let mut member_rows = member_statement.query([value])?;
                while let Some(member_row) = member_rows.next()? {
                    hasher.update(&[0xa7]);
                    hasher.update(&member_row.get::<_, i64>(0)?.to_le_bytes());
                    hasher.update(&member_row.get::<_, i64>(1)?.to_le_bytes());
                    hash_optional_i64(&mut hasher, member_row.get(2)?);
                    hash_optional_i64(&mut hasher, member_row.get(3)?);
                    hasher.update(&member_row.get::<_, i64>(4)?.to_le_bytes());
                    hasher.update(&member_row.get::<_, i64>(5)?.to_le_bytes());
                    hash_optional_i64(&mut hasher, member_row.get(6)?);
                    member_count = member_count.checked_add(1).ok_or_else(|| {
                        StoreError::invalid_input(
                            "time_session_outcome_manifest",
                            "analysis member count overflow",
                        )
                    })?;
                    if member_count > 8_192 {
                        return Err(StoreError::invalid_input(
                            "time_session_outcome_manifest",
                            "analysis member count exceeds the v7 hard bound",
                        ));
                    }
                }
                hasher.update(&member_count.to_le_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hash_length_prefixed(&mut hasher, reason_code.as_bytes())?;
        hasher.update(&created_at_ms.to_le_bytes());
    }
    hasher.update(&evidence_count.to_le_bytes());
    hasher.update(&unavailable_count.to_le_bytes());
    hasher.update(&failed_count.to_le_bytes());
    hash_length_prefixed(&mut hasher, terminal_state.as_bytes())?;
    hasher.update(&expected_group_count.to_le_bytes());
    hasher.update(&expected_scope_manifest);
    hasher.update(&finalized_at_ms.to_le_bytes());
    Ok(TimeEvidenceManifestDigest::from_runtime_evidence(
        *hasher.finalize().as_bytes(),
    ))
}

fn hash_optional_i64(hasher: &mut blake3::Hasher, value: Option<i64>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hasher.update(&value.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn hash_sqlite_query_by_id(
    connection: &Connection,
    hasher: &mut blake3::Hasher,
    label: &[u8],
    sql: &str,
    id: i64,
) -> Result<i64> {
    hash_length_prefixed(hasher, label)?;
    let mut statement = connection.prepare(sql)?;
    let column_count = statement.column_count();
    let mut rows = statement.query([id])?;
    let mut count = 0_i64;
    while let Some(row) = rows.next()? {
        hasher.update(&[0xa5]);
        for column in 0..column_count {
            use rusqlite::types::ValueRef;
            match row.get_ref(column)? {
                ValueRef::Null => {
                    hasher.update(&[0]);
                }
                ValueRef::Integer(value) => {
                    hasher.update(&[1]);
                    hasher.update(&value.to_le_bytes());
                }
                ValueRef::Real(_) => {
                    return Err(StoreError::invalid_input(
                        "time_evidence_manifest",
                        "REAL values are forbidden in evidence manifests",
                    ));
                }
                ValueRef::Text(value) => {
                    hasher.update(&[3]);
                    hash_length_prefixed(hasher, value)?;
                }
                ValueRef::Blob(value) => {
                    hasher.update(&[4]);
                    hash_length_prefixed(hasher, value)?;
                }
            }
        }
        count = count.checked_add(1).ok_or_else(|| {
            StoreError::invalid_input("time_evidence_manifest", "row count overflow")
        })?;
    }
    hasher.update(&[0x5a]);
    hasher.update(&count.to_le_bytes());
    Ok(count)
}

pub(crate) fn recompute_metadata_report_manifest(
    connection: &Connection,
    report_id: i64,
) -> Result<TimeEvidenceManifestDigest> {
    require_positive("report_id", report_id)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.metadata-report-manifest.v1\0");
    let header_count = hash_sqlite_query_by_id(
        connection,
        &mut hasher,
        b"header",
        "SELECT time_session_id, scan_run_id, core_session_id, \
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
                created_at_ms \
         FROM metadata_extraction_reports WHERE id = ?1",
        report_id,
    )?;
    if header_count != 1 {
        return Err(StoreError::ConcurrencyConflict {
            entity: "metadata_report_manifest",
            id: report_id,
        });
    }
    hash_sqlite_query_by_id(
        connection,
        &mut hasher,
        b"fields",
        "SELECT ordinal, parser_name, parser_version, field_kind, encoding, absolute_offset, \
                byte_len, raw_bytes, raw_digest, container_kind, tiff_header_offset, \
                tiff_ifd_offset, tiff_tag, tiff_byte_order, jpeg_app1_offset, bmff_box_offset, \
                bmff_box_path, created_at_ms \
         FROM metadata_extraction_fields WHERE report_id = ?1 ORDER BY ordinal, id",
        report_id,
    )?;
    hash_sqlite_query_by_id(
        connection,
        &mut hasher,
        b"issues",
        "SELECT ordinal, parser_name, parser_version, issue_code, source_offset, context, \
                created_at_ms \
         FROM metadata_extraction_issues WHERE report_id = ?1 ORDER BY ordinal, id",
        report_id,
    )?;
    hash_sqlite_query_by_id(
        connection,
        &mut hasher,
        b"revalidation",
        "SELECT time_session_id, scan_run_id, core_session_id, exact_group_build_id, \
                metadata_probe_observation_id, source_key, source_key_version, lineage_key, \
                lineage_key_version, source_signature_before, source_signature_after, \
                first_report_digest, second_report_digest, outcome, \
                descriptor_revalidated, path_revalidated, session_revalidated, trust_scope, \
                revalidated_at_ms \
         FROM metadata_source_revalidations WHERE report_id = ?1 ORDER BY id",
        report_id,
    )?;
    Ok(TimeEvidenceManifestDigest::from_runtime_evidence(
        *hasher.finalize().as_bytes(),
    ))
}

pub(crate) fn recompute_capture_time_analysis_manifest(
    connection: &Connection,
    analysis_build_id: i64,
) -> Result<TimeEvidenceManifestDigest> {
    require_positive("analysis_build_id", analysis_build_id)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.capture-time-analysis-manifest.v1\0");
    let header_count = hash_sqlite_query_by_id(
        connection,
        &mut hasher,
        b"header",
        "SELECT time_session_id, scan_run_id, exact_group_build_id, policy_name, \
                policy_version, policy_context_json, policy_context_digest, \
                expected_source_count, expected_observation_count, expected_candidate_count, \
                expected_issue_count, expected_member_count, expected_recommendation_count, \
                created_at_ms \
         FROM capture_time_analysis_builds WHERE id = ?1",
        analysis_build_id,
    )?;
    if header_count != 1 {
        return Err(StoreError::ConcurrencyConflict {
            entity: "capture_time_analysis_manifest",
            id: analysis_build_id,
        });
    }
    hash_sqlite_query_by_id(
        connection,
        &mut hasher,
        b"sources",
        "SELECT ordinal, report_id, source_key, lineage_key, binding_status, created_at_ms \
         FROM capture_time_analysis_sources WHERE analysis_build_id = ?1 \
         ORDER BY ordinal, report_id",
        analysis_build_id,
    )?;
    hash_sqlite_query_by_id(
        connection,
        &mut hasher,
        b"observations",
        "SELECT ordinal, source_ordinal, report_id, metadata_field_id, interpretation_kind, \
                wall_year, wall_month, wall_day, wall_hour, wall_minute, wall_second, \
                wall_nanosecond, semantic_kind, offset_kind, utc_offset_minutes, \
                utc_seconds_decimal, utc_nanoseconds, normalized_precision_ns, \
                parsed_offset_minutes, subsecond_nanosecond, subsecond_digits, \
                subsecond_precision_ns, rejection_code, created_at_ms \
         FROM capture_time_observations WHERE analysis_build_id = ?1 ORDER BY ordinal, id",
        analysis_build_id,
    )?;
    hash_sqlite_query_by_id(
        connection,
        &mut hasher,
        b"candidates",
        "SELECT ordinal, wall_year, wall_month, wall_day, wall_hour, wall_minute, wall_second, \
                wall_nanosecond, semantic_kind, offset_kind, utc_offset_minutes, \
                utc_seconds_decimal, utc_nanoseconds, precision_ns, confidence, evidence_gate, \
                evidence_kinds_json, source_keys_json, lineage_keys_json, \
                observation_ordinals_json, anomalies_json, blockers_json, created_at_ms \
         FROM capture_time_candidates WHERE analysis_build_id = ?1 ORDER BY ordinal, id",
        analysis_build_id,
    )?;
    hash_sqlite_query_by_id(
        connection,
        &mut hasher,
        b"policy-issues",
        "SELECT ordinal, issue_code, field_kind, observation_ordinals_json, source_keys_json, \
                lineage_keys_json, context, created_at_ms \
         FROM capture_time_policy_issues WHERE analysis_build_id = ?1 ORDER BY ordinal, id",
        analysis_build_id,
    )?;
    hash_sqlite_query_by_id(
        connection,
        &mut hasher,
        b"members",
        "SELECT member.member_ordinal, member.media_observation_snapshot_id, candidate.ordinal, \
                member.birth_time_relation, member.modified_time_relation, \
                member.donor_eligibility, member.reason_code, member.created_at_ms \
         FROM capture_time_member_assessments AS member \
         LEFT JOIN capture_time_candidates AS candidate \
           ON candidate.analysis_build_id = member.analysis_build_id \
          AND candidate.id = member.candidate_id \
         WHERE member.analysis_build_id = ?1 ORDER BY member.member_ordinal",
        analysis_build_id,
    )?;
    hash_sqlite_query_by_id(
        connection,
        &mut hasher,
        b"recommendation",
        "SELECT recommendation.keeper_observation_id, \
                recommendation.time_donor_observation_id, candidate.ordinal, \
                recommendation.keeper_policy_name, recommendation.keeper_policy_version, \
                recommendation.time_donor_policy_name, \
                recommendation.time_donor_policy_version, recommendation.evidence_only, \
                recommendation.write_authorized, recommendation.reason_code, \
                recommendation.created_at_ms \
         FROM capture_time_recommendations AS recommendation \
         LEFT JOIN capture_time_candidates AS candidate \
           ON candidate.analysis_build_id = recommendation.analysis_build_id \
          AND candidate.id = recommendation.candidate_id \
         WHERE recommendation.analysis_build_id = ?1 ORDER BY recommendation.analysis_build_id",
        analysis_build_id,
    )?;
    Ok(TimeEvidenceManifestDigest::from_runtime_evidence(
        *hasher.finalize().as_bytes(),
    ))
}

/// Rebuilds the v2 source key and v1 copy-lineage key exclusively from the
/// immutable persisted run/core/root/group/member/fingerprint graph.
pub(crate) fn recompute_metadata_source_keys(
    connection: &Connection,
    report_id: i64,
) -> Result<(TimeSourceKey, TimeLineageKey)> {
    require_positive("report_id", report_id)?;
    let raw = connection
        .query_row(
            "SELECT report.scan_run_id, report.core_session_id, \
                    run_session.mount_session_key, run_session.root_scope_key, \
                    run_session.stable_root_path_key, run_session.root_object_signature, \
                    namespace_path.stable_path_key, observation.source_signature, \
                    observation.id, fingerprint.id, exact_build.group_key, \
                    exact_build.expected_manifest_digest, fingerprint.algorithm, \
                    fingerprint.algorithm_version, fingerprint.parameters_hash, \
                    fingerprint.observed_size_bytes, fingerprint.digest \
             FROM metadata_extraction_reports AS report \
             JOIN exact_group_builds AS exact_build \
               ON exact_build.id = report.exact_group_build_id \
              AND exact_build.volume_id = report.volume_id \
              AND exact_build.scan_run_id = report.scan_run_id \
              AND exact_build.state = 'verified' \
             JOIN exact_group_build_members AS member \
               ON member.exact_group_build_id = exact_build.id \
              AND member.volume_id = exact_build.volume_id \
              AND member.scan_run_id = exact_build.scan_run_id \
              AND member.media_observation_snapshot_id = report.metadata_probe_observation_id \
              AND member.observation_fingerprint_id = report.metadata_probe_fingerprint_id \
             JOIN media_observation_snapshots AS observation \
               ON observation.id = member.media_observation_snapshot_id \
              AND observation.volume_id = member.volume_id \
              AND observation.scan_run_id = member.scan_run_id \
             JOIN media_namespace_paths AS namespace_path \
               ON namespace_path.id = observation.media_namespace_path_id \
              AND namespace_path.volume_id = observation.volume_id \
              AND namespace_path.media_file_id = observation.media_file_id \
              AND namespace_path.namespace_profile_id = observation.namespace_profile_id \
             JOIN observation_fingerprints AS fingerprint \
               ON fingerprint.id = member.observation_fingerprint_id \
              AND fingerprint.media_observation_snapshot_id = observation.id \
              AND fingerprint.volume_id = observation.volume_id \
              AND fingerprint.scan_run_id = observation.scan_run_id \
              AND fingerprint.fingerprint_kind = 'exact_bytes' \
              AND fingerprint.read_origin = 'full_hash_read' \
              AND fingerprint.source_signature_before = observation.source_signature \
              AND fingerprint.source_signature_after = observation.source_signature \
             JOIN scan_run_sessions AS run_session \
               ON run_session.scan_run_id = report.scan_run_id \
              AND run_session.volume_id = report.volume_id \
             JOIN scan_core_sessions AS core \
               ON core.scan_run_id = report.scan_run_id \
              AND core.volume_id = report.volume_id \
              AND core.core_session_id = report.core_session_id \
              AND core.root_object_signature = run_session.root_object_signature \
             WHERE report.id = ?1",
            [report_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, Vec<u8>>(16)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => StoreError::ConcurrencyConflict {
                entity: "metadata_report_source_identity",
                id: report_id,
            },
            other => StoreError::from(other),
        })?;
    let exact_fingerprint = TimeExactFingerprintMaterial::new(
        raw.12,
        raw.13,
        crate::model::ParametersHash::from_runtime_evidence(fixed_32_from_sql(raw.14, 14)?),
        raw.15,
        raw.16,
    )?;
    let source_material = TimeSourceKeyMaterial::new(
        1,
        raw.0,
        crate::model::CoreSessionId::from_runtime_evidence(fixed_32_from_sql(raw.1, 1)?),
        MountSessionKey::from_runtime_evidence(parse_lower_hex_32("mount_session_key", &raw.2)?),
        crate::model::RootScopeKey::from_volume_adapter(fixed_32_from_sql(raw.3, 3)?),
        crate::model::StablePathKey::from_volume_adapter(fixed_32_from_sql(raw.4, 4)?),
        crate::model::RootObjectSignature::from_volume_adapter(fixed_32_from_sql(raw.5, 5)?),
        crate::model::StablePathKey::from_volume_adapter(fixed_32_from_sql(raw.6, 6)?),
        SourceSignature::from_runtime_evidence(fixed_32_from_sql(raw.7, 7)?),
        raw.8,
        raw.9,
        ExactGroupKey::from_runtime_evidence(fixed_32_from_sql(raw.10, 10)?),
        ManifestDigest::from_runtime_evidence(fixed_32_from_sql(raw.11, 11)?),
        exact_fingerprint,
    )?;
    Ok((
        compute_time_source_key(&source_material),
        compute_time_lineage_key(source_material.exact_fingerprint()),
    ))
}

fn parse_lower_hex_32(field: &'static str, value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(StoreError::invalid_input(
            field,
            "expected exactly 64 lowercase hexadecimal characters",
        ));
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] =
            (decode_lower_hex_nibble(pair[0])? << 4) | decode_lower_hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn decode_lower_hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(StoreError::invalid_input(
            "hex",
            "invalid lowercase hexadecimal digit",
        )),
    }
}

fn fixed_32_from_sql(bytes: Vec<u8>, column: usize) -> rusqlite::Result<[u8; 32]> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("expected 32-byte evidence, observed {} bytes", bytes.len()),
            )),
        )
    })
}

fn checked_u64(field: &'static str, value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| StoreError::invalid_input(field, "value is negative"))
}

fn checked_u32(field: &'static str, value: i64) -> Result<u32> {
    u32::try_from(value).map_err(|_| StoreError::invalid_input(field, "value exceeds u32"))
}

struct StoredLocatorColumns<'a> {
    kind: &'static str,
    tiff_header_offset: Option<i64>,
    tiff_ifd_offset: Option<i64>,
    tiff_tag: Option<i64>,
    tiff_byte_order: Option<&'static str>,
    jpeg_app1_offset: Option<i64>,
    bmff_box_offset: Option<i64>,
    bmff_box_path: Option<&'a [u8]>,
}

struct StoredInterpretationColumns<'a> {
    kind: &'static str,
    wall_year: Option<i64>,
    wall_month: Option<i64>,
    wall_day: Option<i64>,
    wall_hour: Option<i64>,
    wall_minute: Option<i64>,
    wall_second: Option<i64>,
    wall_nanosecond: Option<i64>,
    semantic_kind: Option<&'static str>,
    offset_kind: Option<&'static str>,
    utc_offset_minutes: Option<i64>,
    utc_seconds_decimal: Option<&'a str>,
    utc_nanoseconds: Option<i64>,
    normalized_precision_ns: Option<i64>,
    parsed_offset_minutes: Option<i64>,
    subsecond_nanosecond: Option<i64>,
    subsecond_digits: Option<i64>,
    subsecond_precision_ns: Option<i64>,
    rejection_code: Option<&'a str>,
}

impl<'a> From<&'a CaptureTimeObservationInterpretationInput> for StoredInterpretationColumns<'a> {
    fn from(value: &'a CaptureTimeObservationInterpretationInput) -> Self {
        let mut columns = Self {
            kind: value.as_storage_str(),
            wall_year: None,
            wall_month: None,
            wall_day: None,
            wall_hour: None,
            wall_minute: None,
            wall_second: None,
            wall_nanosecond: None,
            semantic_kind: None,
            offset_kind: None,
            utc_offset_minutes: None,
            utc_seconds_decimal: None,
            utc_nanoseconds: None,
            normalized_precision_ns: None,
            parsed_offset_minutes: None,
            subsecond_nanosecond: None,
            subsecond_digits: None,
            subsecond_precision_ns: None,
            rejection_code: None,
        };
        match value {
            CaptureTimeObservationInterpretationInput::Timestamp(timestamp) => {
                let wall = timestamp.wall_time();
                columns.wall_year = Some(i64::from(wall.year()));
                columns.wall_month = Some(i64::from(wall.month()));
                columns.wall_day = Some(i64::from(wall.day()));
                columns.wall_hour = Some(i64::from(wall.hour()));
                columns.wall_minute = Some(i64::from(wall.minute()));
                columns.wall_second = Some(i64::from(wall.second()));
                columns.wall_nanosecond = Some(i64::from(wall.nanosecond()));
                columns.semantic_kind = Some(timestamp.semantic_kind().as_storage_str());
                columns.offset_kind = Some(timestamp.offset_kind().as_storage_str());
                columns.utc_offset_minutes = timestamp.utc_offset_minutes().map(i64::from);
                columns.utc_seconds_decimal = timestamp.utc_seconds_decimal();
                columns.utc_nanoseconds = timestamp.utc_nanoseconds().map(i64::from);
                columns.normalized_precision_ns = Some(i64::from(timestamp.precision_ns()));
            }
            CaptureTimeObservationInterpretationInput::Offset { minutes } => {
                columns.parsed_offset_minutes = Some(i64::from(*minutes));
            }
            CaptureTimeObservationInterpretationInput::Subsecond {
                nanosecond,
                digits,
                precision_ns,
            } => {
                columns.subsecond_nanosecond = Some(i64::from(*nanosecond));
                columns.subsecond_digits = Some(i64::from(*digits));
                columns.subsecond_precision_ns = Some(i64::from(*precision_ns));
            }
            CaptureTimeObservationInterpretationInput::Rejected { code } => {
                columns.rejection_code = Some(code);
            }
        }
        columns
    }
}

impl<'a> From<&'a MetadataContainerLocator> for StoredLocatorColumns<'a> {
    fn from(value: &'a MetadataContainerLocator) -> Self {
        match value {
            MetadataContainerLocator::Tiff {
                header_offset,
                ifd_offset,
                tag,
                byte_order,
            } => Self {
                kind: "tiff",
                tiff_header_offset: Some(*header_offset),
                tiff_ifd_offset: Some(*ifd_offset),
                tiff_tag: Some(*tag),
                tiff_byte_order: Some(byte_order.as_storage_str()),
                jpeg_app1_offset: None,
                bmff_box_offset: None,
                bmff_box_path: None,
            },
            MetadataContainerLocator::JpegExif {
                app1_offset,
                header_offset,
                ifd_offset,
                tag,
                byte_order,
            } => Self {
                kind: "jpeg_exif",
                tiff_header_offset: Some(*header_offset),
                tiff_ifd_offset: Some(*ifd_offset),
                tiff_tag: Some(*tag),
                tiff_byte_order: Some(byte_order.as_storage_str()),
                jpeg_app1_offset: Some(*app1_offset),
                bmff_box_offset: None,
                bmff_box_path: None,
            },
            MetadataContainerLocator::IsoBmff {
                box_offset,
                box_path,
            } => Self {
                kind: "iso_bmff",
                tiff_header_offset: None,
                tiff_ifd_offset: None,
                tiff_tag: None,
                tiff_byte_order: None,
                jpeg_app1_offset: None,
                bmff_box_offset: Some(*box_offset),
                bmff_box_path: Some(box_path),
            },
        }
    }
}

fn validate_time_batch(field: &'static str, count: usize) -> Result<()> {
    if !(1..=MAX_TIME_EVIDENCE_BATCH).contains(&count) {
        return Err(StoreError::invalid_input(
            field,
            format!("batch must contain between 1 and {MAX_TIME_EVIDENCE_BATCH} records"),
        ));
    }
    Ok(())
}

fn validate_metadata_report_input(input: &BeginMetadataReportInput) -> Result<()> {
    let limits = input.limits;
    let usage = input.usage;
    if usage.bytes_read > limits.total_bytes_read
        || usage.read_operations > limits.read_operations
        || usage.retained_field_bytes > limits.retained_field_bytes
        || usage.fields_emitted > limits.fields
        || usage.jpeg_segments_visited > limits.jpeg_segments
        || usage.ifd_entries_visited > limits.ifd_entries
        || usage.bmff_boxes_visited > limits.bmff_boxes
        || usage.max_depth_observed > limits.ifd_depth.max(limits.bmff_depth)
        || input.expected_field_count != usage.fields_emitted
        || input.expected_retained_field_bytes != usage.retained_field_bytes
    {
        return Err(StoreError::invalid_input(
            "metadata_report_usage",
            "usage or expected counts contradict the effective extraction limits",
        ));
    }
    Ok(())
}

fn validate_metadata_field_input(input: &MetadataFieldInput) -> Result<()> {
    if input.raw_bytes.len() > MAX_OPAQUE_BLOB_BYTES
        || input.locator.byte_len != input.raw_bytes.len() as i64
        || blake3::hash(&input.raw_bytes).as_bytes() != input.raw_digest.as_bytes()
    {
        return Err(StoreError::invalid_input(
            "metadata_field",
            "retained bytes, byte length, or raw digest are inconsistent",
        ));
    }
    input
        .locator
        .absolute_offset
        .checked_add(input.locator.byte_len)
        .ok_or_else(|| StoreError::invalid_input("metadata_locator", "locator range overflow"))?;
    Ok(())
}

fn require_draft_report_for_guard(
    connection: &Connection,
    guard: &TimeEvidenceGuard,
    report_id: i64,
) -> Result<()> {
    require_positive("report_id", report_id)?;
    let matches = connection.query_row(
        "SELECT EXISTS( \
             SELECT 1 FROM metadata_extraction_reports \
             WHERE id = ?1 AND scan_run_id = ?2 AND core_session_id = ?3 AND state = 'draft' \
         )",
        params![
            report_id,
            guard.run().scan_run_id,
            guard.core_session_id().as_bytes().as_slice(),
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !matches {
        return Err(StoreError::ConcurrencyConflict {
            entity: "draft_metadata_report_guard",
            id: report_id,
        });
    }
    Ok(())
}

fn require_draft_analysis_for_guard(
    connection: &Connection,
    guard: &TimeEvidenceGuard,
    analysis_build_id: i64,
) -> Result<()> {
    require_positive("analysis_build_id", analysis_build_id)?;
    let matches = connection.query_row(
        "SELECT EXISTS( \
             SELECT 1 FROM capture_time_analysis_builds AS build \
             JOIN scan_time_sessions AS time_session ON time_session.id = build.time_session_id \
             WHERE build.id = ?1 AND build.scan_run_id = ?2 AND build.state = 'draft' \
               AND time_session.core_session_id = ?3 AND time_session.state = 'draft' \
         )",
        params![
            analysis_build_id,
            guard.run().scan_run_id,
            guard.core_session_id().as_bytes().as_slice(),
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !matches {
        return Err(StoreError::ConcurrencyConflict {
            entity: "draft_capture_time_analysis_guard",
            id: analysis_build_id,
        });
    }
    Ok(())
}

fn latest_metadata_report_extraction_ms(connection: &Connection, report_id: i64) -> Result<i64> {
    connection
        .query_row(
            "SELECT max(value) FROM ( \
                 SELECT created_at_ms AS value FROM metadata_extraction_reports WHERE id = ?1 \
                 UNION ALL SELECT created_at_ms FROM metadata_extraction_fields \
                     WHERE report_id = ?1 \
                 UNION ALL SELECT created_at_ms FROM metadata_extraction_issues \
                     WHERE report_id = ?1 \
             )",
            [report_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(StoreError::from)
}

fn latest_capture_time_analysis_child_ms(
    connection: &Connection,
    analysis_build_id: i64,
) -> Result<i64> {
    connection
        .query_row(
            "SELECT max(value) FROM ( \
                 SELECT created_at_ms AS value FROM capture_time_analysis_builds WHERE id = ?1 \
                 UNION ALL SELECT created_at_ms FROM capture_time_analysis_sources \
                     WHERE analysis_build_id = ?1 \
                 UNION ALL SELECT created_at_ms FROM capture_time_observations \
                     WHERE analysis_build_id = ?1 \
                 UNION ALL SELECT created_at_ms FROM capture_time_candidates \
                     WHERE analysis_build_id = ?1 \
                 UNION ALL SELECT created_at_ms FROM capture_time_policy_issues \
                     WHERE analysis_build_id = ?1 \
                 UNION ALL SELECT created_at_ms FROM capture_time_member_assessments \
                     WHERE analysis_build_id = ?1 \
                 UNION ALL SELECT created_at_ms FROM capture_time_recommendations \
                     WHERE analysis_build_id = ?1 \
             )",
            [analysis_build_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(StoreError::from)
}

fn latest_time_group_terminal_evidence_ms(
    connection: &Connection,
    time_session_id: i64,
    exact_group_build_id: i64,
) -> Result<i64> {
    connection
        .query_row(
            "SELECT max(value) FROM ( \
                 SELECT created_at_ms AS value FROM scan_time_sessions WHERE id = ?1 \
                 UNION ALL SELECT finalized_at_ms FROM metadata_extraction_reports \
                     WHERE time_session_id = ?1 AND exact_group_build_id = ?2 \
                       AND finalized_at_ms IS NOT NULL \
                 UNION ALL SELECT finalized_at_ms FROM capture_time_analysis_builds \
                     WHERE time_session_id = ?1 AND exact_group_build_id = ?2 \
                       AND finalized_at_ms IS NOT NULL \
             )",
            params![time_session_id, exact_group_build_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(StoreError::from)
}

fn validate_candidate_references(
    connection: &Connection,
    analysis_build_id: i64,
    input: &CaptureTimeCandidateInput,
) -> Result<()> {
    for source_key in &input.source_keys {
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_time_analysis_sources \
                           WHERE analysis_build_id = ?1 AND source_key = ?2)",
            params![analysis_build_id, source_key.as_bytes().as_slice()],
            |row| row.get::<_, bool>(0),
        )?;
        if !exists {
            return Err(StoreError::invalid_input(
                "candidate_source_keys",
                "candidate references a source outside its analysis",
            ));
        }
    }
    for lineage_key in &input.lineage_keys {
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_time_analysis_sources \
                           WHERE analysis_build_id = ?1 AND lineage_key = ?2)",
            params![analysis_build_id, lineage_key.as_bytes().as_slice()],
            |row| row.get::<_, bool>(0),
        )?;
        if !exists {
            return Err(StoreError::invalid_input(
                "candidate_lineage_keys",
                "candidate references a lineage outside its analysis",
            ));
        }
    }
    for ordinal in &input.observation_ordinals {
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_time_observations \
                           WHERE analysis_build_id = ?1 AND ordinal = ?2)",
            params![analysis_build_id, ordinal],
            |row| row.get::<_, bool>(0),
        )?;
        if !exists {
            return Err(StoreError::invalid_input(
                "candidate_observation_ordinals",
                "candidate references an observation outside its analysis",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct CandidateSupportClaim {
    analysis_build_id: i64,
    wall_year: i64,
    wall_month: i64,
    wall_day: i64,
    wall_hour: i64,
    wall_minute: i64,
    wall_second: i64,
    wall_nanosecond: i64,
    semantic_kind: String,
    offset_kind: String,
    utc_offset_minutes: Option<i64>,
    utc_seconds_decimal: Option<String>,
    utc_nanoseconds: Option<i64>,
    precision_ns: i64,
    evidence_kinds: Vec<String>,
    source_keys: Vec<[u8; 32]>,
    lineage_keys: Vec<[u8; 32]>,
    observation_ordinals: Vec<i64>,
}

impl CandidateSupportClaim {
    fn from_input(analysis_build_id: i64, input: &CaptureTimeCandidateInput) -> Self {
        let wall = input.timestamp.wall_time();
        Self {
            analysis_build_id,
            wall_year: i64::from(wall.year()),
            wall_month: i64::from(wall.month()),
            wall_day: i64::from(wall.day()),
            wall_hour: i64::from(wall.hour()),
            wall_minute: i64::from(wall.minute()),
            wall_second: i64::from(wall.second()),
            wall_nanosecond: i64::from(wall.nanosecond()),
            semantic_kind: input.timestamp.semantic_kind().as_storage_str().to_owned(),
            offset_kind: input.timestamp.offset_kind().as_storage_str().to_owned(),
            utc_offset_minutes: input.timestamp.utc_offset_minutes().map(i64::from),
            utc_seconds_decimal: input.timestamp.utc_seconds_decimal().map(str::to_owned),
            utc_nanoseconds: input.timestamp.utc_nanoseconds().map(i64::from),
            precision_ns: i64::from(input.timestamp.precision_ns()),
            evidence_kinds: input
                .evidence_kinds
                .iter()
                .map(|value| value.as_storage_str().to_owned())
                .collect(),
            source_keys: input
                .source_keys
                .iter()
                .map(|value| *value.as_bytes())
                .collect(),
            lineage_keys: input
                .lineage_keys
                .iter()
                .map(|value| *value.as_bytes())
                .collect(),
            observation_ordinals: input.observation_ordinals.clone(),
        }
    }
}

struct StoredCandidateSupportObservation {
    source_ordinal: i64,
    report_id: i64,
    interpretation_kind: String,
    wall_year: Option<i64>,
    wall_month: Option<i64>,
    wall_day: Option<i64>,
    wall_hour: Option<i64>,
    wall_minute: Option<i64>,
    wall_second: Option<i64>,
    wall_nanosecond: Option<i64>,
    semantic_kind: Option<String>,
    offset_kind: Option<String>,
    utc_offset_minutes: Option<i64>,
    utc_seconds_decimal: Option<String>,
    utc_nanoseconds: Option<i64>,
    normalized_precision_ns: Option<i64>,
    parsed_offset_minutes: Option<i64>,
    subsecond_nanosecond: Option<i64>,
    subsecond_digits: Option<i64>,
    subsecond_precision_ns: Option<i64>,
    source_key: Vec<u8>,
    lineage_key: Vec<u8>,
    field_kind: String,
    container_kind: String,
    tiff_header_offset: Option<i64>,
    tiff_ifd_offset: Option<i64>,
    jpeg_app1_offset: Option<i64>,
}

struct CandidateSourceComposition {
    exif_original_atoms: BTreeMap<StoredExifScope, CandidateExifOriginalAtom>,
    independent_timestamps: Vec<StoredCandidateTimestamp>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum StoredExifScope {
    Tiff {
        header_offset: i64,
        ifd_offset: i64,
    },
    JpegExif {
        app1_offset: i64,
        header_offset: i64,
        ifd_offset: i64,
    },
}

struct CandidateExifOriginalAtom {
    timestamp: Option<StoredCandidateTimestamp>,
    offset_minutes: Option<i64>,
    subsecond: Option<(i64, i64, i64)>,
}

struct StoredCandidateTimestamp {
    wall_year: i64,
    wall_month: i64,
    wall_day: i64,
    wall_hour: i64,
    wall_minute: i64,
    wall_second: i64,
    wall_nanosecond: i64,
    semantic_kind: String,
    offset_kind: String,
    utc_offset_minutes: Option<i64>,
    utc_seconds_decimal: Option<String>,
    utc_nanoseconds: Option<i64>,
    precision_ns: i64,
}

fn validate_eligible_candidate_support(
    connection: &Connection,
    claim: &CandidateSupportClaim,
) -> Result<()> {
    if claim.observation_ordinals.is_empty()
        || claim.source_keys.is_empty()
        || claim.lineage_keys.is_empty()
        || claim.evidence_kinds.is_empty()
    {
        return Err(StoreError::invalid_input(
            "capture_time_candidate_support",
            "eligible candidate support must not be empty",
        ));
    }

    let mut statement = connection.prepare(
        "SELECT observation.source_ordinal, observation.report_id, \
                observation.interpretation_kind, observation.wall_year, \
                observation.wall_month, observation.wall_day, observation.wall_hour, \
                observation.wall_minute, observation.wall_second, \
                observation.wall_nanosecond, observation.semantic_kind, \
                observation.offset_kind, observation.utc_offset_minutes, \
                observation.utc_seconds_decimal, observation.utc_nanoseconds, \
                observation.normalized_precision_ns, observation.parsed_offset_minutes, \
                observation.subsecond_nanosecond, observation.subsecond_digits, \
                observation.subsecond_precision_ns, source.source_key, source.lineage_key, \
                field.field_kind, field.container_kind, field.tiff_header_offset, \
                field.tiff_ifd_offset, field.jpeg_app1_offset \
         FROM capture_time_observations AS observation \
         JOIN capture_time_analysis_builds AS build \
           ON build.id = observation.analysis_build_id \
         JOIN capture_time_analysis_sources AS source \
           ON source.analysis_build_id = observation.analysis_build_id \
          AND source.ordinal = observation.source_ordinal \
          AND source.report_id = observation.report_id \
         JOIN metadata_extraction_reports AS report \
           ON report.id = source.report_id \
          AND report.time_session_id = build.time_session_id \
          AND report.exact_group_build_id = build.exact_group_build_id \
          AND report.volume_id = build.volume_id \
          AND report.scan_run_id = build.scan_run_id \
          AND report.state = 'sealed' \
          AND report.extraction_status = 'extracted_unvalidated' \
          AND report.expected_issue_count = 0 \
          AND NOT EXISTS ( \
              SELECT 1 FROM metadata_extraction_issues AS issue \
              WHERE issue.report_id = report.id \
          ) \
         JOIN metadata_source_revalidations AS revalidation \
           ON revalidation.report_id = report.id \
          AND revalidation.time_session_id = report.time_session_id \
          AND revalidation.exact_group_build_id = report.exact_group_build_id \
          AND revalidation.metadata_probe_observation_id = \
              report.metadata_probe_observation_id \
          AND revalidation.source_key = source.source_key \
          AND revalidation.lineage_key = source.lineage_key \
          AND revalidation.outcome = 'reextracted_pinned_exact' \
          AND revalidation.descriptor_revalidated = 1 \
          AND revalidation.path_revalidated = 1 \
          AND revalidation.session_revalidated = 1 \
         JOIN metadata_extraction_fields AS field \
           ON field.id = observation.metadata_field_id \
          AND field.report_id = observation.report_id \
         WHERE observation.analysis_build_id = ?1 AND observation.ordinal = ?2",
    )?;

    let mut derived_source_keys = Vec::with_capacity(claim.observation_ordinals.len());
    let mut derived_lineage_keys = Vec::with_capacity(claim.observation_ordinals.len());
    let mut derived_evidence_kinds = Vec::new();
    let mut source_compositions: BTreeMap<(i64, i64, [u8; 32]), CandidateSourceComposition> =
        BTreeMap::new();
    for ordinal in &claim.observation_ordinals {
        let observation = statement
            .query_row(params![claim.analysis_build_id, ordinal], |row| {
                Ok(StoredCandidateSupportObservation {
                    source_ordinal: row.get(0)?,
                    report_id: row.get(1)?,
                    interpretation_kind: row.get(2)?,
                    wall_year: row.get(3)?,
                    wall_month: row.get(4)?,
                    wall_day: row.get(5)?,
                    wall_hour: row.get(6)?,
                    wall_minute: row.get(7)?,
                    wall_second: row.get(8)?,
                    wall_nanosecond: row.get(9)?,
                    semantic_kind: row.get(10)?,
                    offset_kind: row.get(11)?,
                    utc_offset_minutes: row.get(12)?,
                    utc_seconds_decimal: row.get(13)?,
                    utc_nanoseconds: row.get(14)?,
                    normalized_precision_ns: row.get(15)?,
                    parsed_offset_minutes: row.get(16)?,
                    subsecond_nanosecond: row.get(17)?,
                    subsecond_digits: row.get(18)?,
                    subsecond_precision_ns: row.get(19)?,
                    source_key: row.get(20)?,
                    lineage_key: row.get(21)?,
                    field_kind: row.get(22)?,
                    container_kind: row.get(23)?,
                    tiff_header_offset: row.get(24)?,
                    tiff_ifd_offset: row.get(25)?,
                    jpeg_app1_offset: row.get(26)?,
                })
            })
            .optional()?
            .ok_or_else(|| {
                StoreError::invalid_input(
                    "capture_time_candidate_support",
                    "eligible candidate references evidence without a complete sealed double-extraction proof",
                )
            })?;
        let exif_scope = matches!(
            observation.field_kind.as_str(),
            "exif_date_time_original" | "exif_offset_time_original" | "exif_subsec_time_original"
        )
        .then(|| required_candidate_exif_scope(&observation))
        .transpose()?;
        let source_key = fixed_32_from_sql(observation.source_key, 20)?;
        let lineage_key = fixed_32_from_sql(observation.lineage_key, 21)?;
        derived_source_keys.push(source_key);
        derived_lineage_keys.push(lineage_key);
        let composition = source_compositions
            .entry((
                observation.source_ordinal,
                observation.report_id,
                source_key,
            ))
            .or_insert_with(|| CandidateSourceComposition {
                exif_original_atoms: BTreeMap::new(),
                independent_timestamps: Vec::new(),
            });

        match observation.interpretation_kind.as_str() {
            "timestamp" => {
                let evidence_kind = timestamp_field_evidence_kind(&observation.field_kind)
                    .ok_or_else(|| {
                        StoreError::invalid_input(
                            "capture_time_candidate_support",
                            "timestamp observation uses a non-timestamp metadata field",
                        )
                    })?;
                derived_evidence_kinds.push(evidence_kind.to_owned());
                let timestamp = StoredCandidateTimestamp {
                    wall_year: required_candidate_timestamp_value(
                        "wall_year",
                        observation.wall_year,
                    )?,
                    wall_month: required_candidate_timestamp_value(
                        "wall_month",
                        observation.wall_month,
                    )?,
                    wall_day: required_candidate_timestamp_value("wall_day", observation.wall_day)?,
                    wall_hour: required_candidate_timestamp_value(
                        "wall_hour",
                        observation.wall_hour,
                    )?,
                    wall_minute: required_candidate_timestamp_value(
                        "wall_minute",
                        observation.wall_minute,
                    )?,
                    wall_second: required_candidate_timestamp_value(
                        "wall_second",
                        observation.wall_second,
                    )?,
                    wall_nanosecond: required_candidate_timestamp_value(
                        "wall_nanosecond",
                        observation.wall_nanosecond,
                    )?,
                    semantic_kind: observation.semantic_kind.ok_or_else(|| {
                        StoreError::invalid_input(
                            "capture_time_candidate_support",
                            "timestamp observation has no semantic kind",
                        )
                    })?,
                    offset_kind: observation.offset_kind.ok_or_else(|| {
                        StoreError::invalid_input(
                            "capture_time_candidate_support",
                            "timestamp observation has no offset kind",
                        )
                    })?,
                    utc_offset_minutes: observation.utc_offset_minutes,
                    utc_seconds_decimal: observation.utc_seconds_decimal,
                    utc_nanoseconds: observation.utc_nanoseconds,
                    precision_ns: required_candidate_timestamp_value(
                        "normalized_precision_ns",
                        observation.normalized_precision_ns,
                    )?,
                };
                if observation.field_kind == "exif_date_time_original" {
                    let scope = exif_scope.ok_or_else(|| {
                        StoreError::invalid_input(
                            "capture_time_candidate_support",
                            "DateTimeOriginal is missing an exact Exif scope",
                        )
                    })?;
                    let atom = composition
                        .exif_original_atoms
                        .entry(scope)
                        .or_insert_with(empty_candidate_exif_original_atom);
                    if atom.timestamp.replace(timestamp).is_some() {
                        return Err(StoreError::invalid_input(
                            "capture_time_candidate_support",
                            "eligible candidate contains duplicate DateTimeOriginal observations in one Exif scope",
                        ));
                    }
                } else {
                    composition.independent_timestamps.push(timestamp);
                }
            }
            "offset" if observation.field_kind == "exif_offset_time_original" => {
                let scope = exif_scope.ok_or_else(|| {
                    StoreError::invalid_input(
                        "capture_time_candidate_support",
                        "OffsetTimeOriginal is missing an exact Exif scope",
                    )
                })?;
                let minutes = observation.parsed_offset_minutes.ok_or_else(|| {
                    StoreError::invalid_input(
                        "capture_time_candidate_support",
                        "offset companion has no parsed offset",
                    )
                })?;
                let atom = composition
                    .exif_original_atoms
                    .entry(scope)
                    .or_insert_with(empty_candidate_exif_original_atom);
                if atom.offset_minutes.replace(minutes).is_some() {
                    return Err(StoreError::invalid_input(
                        "capture_time_candidate_support",
                        "eligible candidate contains duplicate offset companions in one Exif scope",
                    ));
                }
            }
            "subsecond" if observation.field_kind == "exif_subsec_time_original" => {
                let scope = exif_scope.ok_or_else(|| {
                    StoreError::invalid_input(
                        "capture_time_candidate_support",
                        "SubSecTimeOriginal is missing an exact Exif scope",
                    )
                })?;
                let subsecond = (
                    observation.subsecond_nanosecond.ok_or_else(|| {
                        StoreError::invalid_input(
                            "capture_time_candidate_support",
                            "subsecond companion has no normalized nanosecond",
                        )
                    })?,
                    observation.subsecond_digits.ok_or_else(|| {
                        StoreError::invalid_input(
                            "capture_time_candidate_support",
                            "subsecond companion has no digit count",
                        )
                    })?,
                    observation.subsecond_precision_ns.ok_or_else(|| {
                        StoreError::invalid_input(
                            "capture_time_candidate_support",
                            "subsecond companion has no precision",
                        )
                    })?,
                );
                let atom = composition
                    .exif_original_atoms
                    .entry(scope)
                    .or_insert_with(empty_candidate_exif_original_atom);
                if atom.subsecond.replace(subsecond).is_some() {
                    return Err(StoreError::invalid_input(
                        "capture_time_candidate_support",
                        "eligible candidate contains duplicate subsecond companions in one Exif scope",
                    ));
                }
            }
            _ => {
                return Err(StoreError::invalid_input(
                    "capture_time_candidate_support",
                    "eligible candidate contains a rejected or unrelated observation",
                ));
            }
        }
    }

    sort_dedup(&mut derived_source_keys);
    sort_dedup(&mut derived_lineage_keys);
    sort_dedup(&mut derived_evidence_kinds);
    let mut declared_source_keys = claim.source_keys.clone();
    let mut declared_lineage_keys = claim.lineage_keys.clone();
    let mut declared_evidence_kinds = claim.evidence_kinds.clone();
    sort_dedup(&mut declared_source_keys);
    sort_dedup(&mut declared_lineage_keys);
    sort_dedup(&mut declared_evidence_kinds);
    let has_eligible_exif_original_atom = source_compositions.values().any(|composition| {
        composition
            .exif_original_atoms
            .values()
            .any(|atom| exif_original_atom_matches_candidate(atom, claim))
    });
    if claim.semantic_kind != "utc"
        || claim.offset_kind != "explicit"
        || derived_source_keys != declared_source_keys
        || derived_lineage_keys != declared_lineage_keys
        || derived_evidence_kinds != declared_evidence_kinds
        || source_compositions.is_empty()
        || !has_eligible_exif_original_atom
        || !source_compositions
            .values()
            .all(|composition| source_composition_matches_candidate(composition, claim))
    {
        return Err(StoreError::invalid_input(
            "capture_time_candidate_support",
            "eligible candidate declarations do not exactly match their timestamp evidence",
        ));
    }
    Ok(())
}

fn empty_candidate_exif_original_atom() -> CandidateExifOriginalAtom {
    CandidateExifOriginalAtom {
        timestamp: None,
        offset_minutes: None,
        subsecond: None,
    }
}

fn required_candidate_exif_scope(
    observation: &StoredCandidateSupportObservation,
) -> Result<StoredExifScope> {
    let invalid = || {
        StoreError::invalid_input(
            "capture_time_candidate_support",
            "Exif DateTimeOriginal and its companions require a TIFF or JPEG Exif locator",
        )
    };
    match observation.container_kind.as_str() {
        "tiff" if observation.jpeg_app1_offset.is_none() => Ok(StoredExifScope::Tiff {
            header_offset: observation.tiff_header_offset.ok_or_else(invalid)?,
            ifd_offset: observation.tiff_ifd_offset.ok_or_else(invalid)?,
        }),
        "jpeg_exif" => Ok(StoredExifScope::JpegExif {
            app1_offset: observation.jpeg_app1_offset.ok_or_else(invalid)?,
            header_offset: observation.tiff_header_offset.ok_or_else(invalid)?,
            ifd_offset: observation.tiff_ifd_offset.ok_or_else(invalid)?,
        }),
        _ => Err(invalid()),
    }
}

fn required_candidate_timestamp_value(field: &'static str, value: Option<i64>) -> Result<i64> {
    value.ok_or_else(|| {
        StoreError::invalid_input(
            "capture_time_candidate_support",
            format!("timestamp observation has no {field}"),
        )
    })
}

fn source_composition_matches_candidate(
    composition: &CandidateSourceComposition,
    claim: &CandidateSupportClaim,
) -> bool {
    composition
        .exif_original_atoms
        .values()
        .all(|atom| exif_original_atom_matches_candidate(atom, claim))
        && composition
            .independent_timestamps
            .iter()
            .all(|timestamp| timestamp_exactly_matches_candidate(timestamp, claim))
}

fn timestamp_exactly_matches_candidate(
    timestamp: &StoredCandidateTimestamp,
    claim: &CandidateSupportClaim,
) -> bool {
    timestamp.wall_year == claim.wall_year
        && timestamp.wall_month == claim.wall_month
        && timestamp.wall_day == claim.wall_day
        && timestamp.wall_hour == claim.wall_hour
        && timestamp.wall_minute == claim.wall_minute
        && timestamp.wall_second == claim.wall_second
        && timestamp.wall_nanosecond == claim.wall_nanosecond
        && timestamp.semantic_kind == claim.semantic_kind
        && timestamp.offset_kind == claim.offset_kind
        && timestamp.utc_offset_minutes == claim.utc_offset_minutes
        && timestamp.utc_seconds_decimal == claim.utc_seconds_decimal
        && timestamp.utc_nanoseconds == claim.utc_nanoseconds
        && timestamp.precision_ns == claim.precision_ns
}

fn exif_original_atom_matches_candidate(
    atom: &CandidateExifOriginalAtom,
    claim: &CandidateSupportClaim,
) -> bool {
    let Some(timestamp) = atom.timestamp.as_ref() else {
        return false;
    };
    if claim.semantic_kind != "utc"
        || claim.offset_kind != "explicit"
        || timestamp.semantic_kind != "floating"
        || timestamp.offset_kind != "missing"
        || timestamp.utc_offset_minutes.is_some()
        || timestamp.utc_seconds_decimal.is_some()
        || timestamp.utc_nanoseconds.is_some()
        || atom.offset_minutes != claim.utc_offset_minutes
        || timestamp.wall_year != claim.wall_year
        || timestamp.wall_month != claim.wall_month
        || timestamp.wall_day != claim.wall_day
        || timestamp.wall_hour != claim.wall_hour
        || timestamp.wall_minute != claim.wall_minute
        || timestamp.wall_second != claim.wall_second
    {
        return false;
    }
    match atom.subsecond {
        Some((nanosecond, _digits, precision)) => {
            (timestamp.wall_nanosecond == 0 || timestamp.wall_nanosecond == nanosecond)
                && nanosecond == claim.wall_nanosecond
                && precision == claim.precision_ns
        }
        None => {
            timestamp.wall_nanosecond == claim.wall_nanosecond
                && timestamp.precision_ns == claim.precision_ns
        }
    }
}

fn timestamp_field_evidence_kind(field_kind: &str) -> Option<&'static str> {
    match field_kind {
        "exif_date_time_original" => Some("exif_date_time_original"),
        "exif_create_date" => Some("exif_create_date"),
        "exif_modify_date" => Some("exif_modify_date"),
        "quicktime_metadata_creation_date" => Some("quicktime_metadata_creation_date"),
        "quicktime_movie_header_creation_time" => Some("quicktime_movie_header_creation_time"),
        _ => None,
    }
}

fn sort_dedup<T: Ord>(values: &mut Vec<T>) {
    values.sort_unstable();
    values.dedup();
}

pub(crate) fn validate_capture_time_candidate_supports(connection: &Connection) -> Result<()> {
    validate_capture_time_candidate_supports_for_analysis(connection, None)
}

fn validate_capture_time_candidate_supports_for_analysis(
    connection: &Connection,
    analysis_build_id: Option<i64>,
) -> Result<()> {
    let mut last_id = 0_i64;
    loop {
        let stored = connection
            .query_row(
                "SELECT id, analysis_build_id, wall_year, wall_month, wall_day, wall_hour, \
                        wall_minute, wall_second, wall_nanosecond, semantic_kind, offset_kind, \
                        utc_offset_minutes, utc_seconds_decimal, utc_nanoseconds, precision_ns, \
                        evidence_kinds_json, source_keys_json, lineage_keys_json, \
                        observation_ordinals_json \
                 FROM capture_time_candidates \
                 WHERE evidence_gate = 'eligible' AND id > ?1 \
                   AND (?2 IS NULL OR analysis_build_id = ?2) \
                 ORDER BY id LIMIT 1",
                params![last_id, analysis_build_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, Option<i64>>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, Option<i64>>(13)?,
                        row.get::<_, i64>(14)?,
                        row.get::<_, String>(15)?,
                        row.get::<_, String>(16)?,
                        row.get::<_, String>(17)?,
                        row.get::<_, String>(18)?,
                    ))
                },
            )
            .optional()?;
        let Some(stored) = stored else {
            return Ok(());
        };
        last_id = stored.0;
        let evidence_kinds: Vec<String> = serde_json::from_str(&stored.15).map_err(|error| {
            StoreError::MigrationHistoryMismatch(format!(
                "eligible candidate id {} has invalid evidence-kind JSON: {error}",
                stored.0
            ))
        })?;
        let source_key_hex: Vec<String> = serde_json::from_str(&stored.16).map_err(|error| {
            StoreError::MigrationHistoryMismatch(format!(
                "eligible candidate id {} has invalid source-key JSON: {error}",
                stored.0
            ))
        })?;
        let lineage_key_hex: Vec<String> = serde_json::from_str(&stored.17).map_err(|error| {
            StoreError::MigrationHistoryMismatch(format!(
                "eligible candidate id {} has invalid lineage-key JSON: {error}",
                stored.0
            ))
        })?;
        let observation_ordinals: Vec<i64> = serde_json::from_str(&stored.18).map_err(|error| {
            StoreError::MigrationHistoryMismatch(format!(
                "eligible candidate id {} has invalid observation JSON: {error}",
                stored.0
            ))
        })?;
        let source_keys = source_key_hex
            .iter()
            .map(|value| parse_lower_hex_32("candidate_source_keys", value))
            .collect::<Result<Vec<_>>>()?;
        let lineage_keys = lineage_key_hex
            .iter()
            .map(|value| parse_lower_hex_32("candidate_lineage_keys", value))
            .collect::<Result<Vec<_>>>()?;
        let claim = CandidateSupportClaim {
            analysis_build_id: stored.1,
            wall_year: stored.2,
            wall_month: stored.3,
            wall_day: stored.4,
            wall_hour: stored.5,
            wall_minute: stored.6,
            wall_second: stored.7,
            wall_nanosecond: stored.8,
            semantic_kind: stored.9,
            offset_kind: stored.10,
            utc_offset_minutes: stored.11,
            utc_seconds_decimal: stored.12,
            utc_nanoseconds: stored.13,
            precision_ns: stored.14,
            evidence_kinds,
            source_keys,
            lineage_keys,
            observation_ordinals,
        };
        validate_eligible_candidate_support(connection, &claim).map_err(|error| {
            StoreError::MigrationHistoryMismatch(format!(
                "eligible candidate id {} has invalid evidence support: {error}",
                stored.0
            ))
        })?;
    }
}

fn validate_policy_issue_references(
    connection: &Connection,
    analysis_build_id: i64,
    input: &CaptureTimePolicyIssueInput,
) -> Result<()> {
    for source_key in &input.source_keys {
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_time_analysis_sources \
                           WHERE analysis_build_id = ?1 AND source_key = ?2)",
            params![analysis_build_id, source_key.as_bytes().as_slice()],
            |row| row.get::<_, bool>(0),
        )?;
        if !exists {
            return Err(StoreError::invalid_input(
                "policy_issue_source_keys",
                "policy issue references a source outside its analysis",
            ));
        }
    }
    for lineage_key in &input.lineage_keys {
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_time_analysis_sources \
                           WHERE analysis_build_id = ?1 AND lineage_key = ?2)",
            params![analysis_build_id, lineage_key.as_bytes().as_slice()],
            |row| row.get::<_, bool>(0),
        )?;
        if !exists {
            return Err(StoreError::invalid_input(
                "policy_issue_lineage_keys",
                "policy issue references a lineage outside its analysis",
            ));
        }
    }
    for ordinal in &input.observation_ordinals {
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_time_observations \
                           WHERE analysis_build_id = ?1 AND ordinal = ?2)",
            params![analysis_build_id, ordinal],
            |row| row.get::<_, bool>(0),
        )?;
        if !exists {
            return Err(StoreError::invalid_input(
                "policy_issue_observation_ordinals",
                "policy issue references an observation outside its analysis",
            ));
        }
    }
    Ok(())
}

struct StoredMemberCandidate {
    id: i64,
    utc_seconds_decimal: String,
    utc_nanoseconds: i64,
    precision_ns: i64,
}

struct StoredMemberObservation {
    birth_time_seconds: Option<i64>,
    birth_time_nanoseconds: Option<i64>,
    modified_time_seconds: i64,
    modified_time_nanoseconds: i64,
    timestamp_granularity_ns: Option<i64>,
}

fn validate_member_assessment_policy(
    input: &CaptureTimeMemberAssessmentInput,
    candidate: Option<&StoredMemberCandidate>,
    observation: &StoredMemberObservation,
) -> Result<()> {
    let expected = expected_member_assessment(candidate, observation)?;
    if input.birth_time_relation != expected.0
        || input.modified_time_relation != expected.1
        || input.donor_eligibility != crate::model::TimeDonorEligibility::Ineligible
        || input.reason_code != expected.2
    {
        return Err(StoreError::invalid_input(
            "capture_time_member",
            "member filesystem-time relations or reason do not match persisted UTC evidence and precision",
        ));
    }
    Ok(())
}

fn expected_member_assessment(
    candidate: Option<&StoredMemberCandidate>,
    observation: &StoredMemberObservation,
) -> Result<(
    crate::model::FileTimeRelation,
    crate::model::FileTimeRelation,
    &'static str,
)> {
    let birth_time = match (
        observation.birth_time_seconds,
        observation.birth_time_nanoseconds,
    ) {
        (Some(seconds), Some(nanoseconds)) if (0..1_000_000_000).contains(&nanoseconds) => {
            Some((seconds, nanoseconds))
        }
        (None, None) => None,
        _ => {
            return Err(StoreError::invalid_input(
                "capture_time_member",
                "stored birth timestamp components are inconsistent",
            ));
        }
    };
    if !(0..1_000_000_000).contains(&observation.modified_time_nanoseconds) {
        return Err(StoreError::invalid_input(
            "capture_time_member",
            "stored modified timestamp nanoseconds are invalid",
        ));
    }
    let Some(candidate) = candidate else {
        return Ok((
            if birth_time.is_some() {
                crate::model::FileTimeRelation::NotCompared
            } else {
                crate::model::FileTimeRelation::Unavailable
            },
            crate::model::FileTimeRelation::NotCompared,
            "no_strong_embedded_candidate",
        ));
    };
    let Some(granularity_ns) = observation.timestamp_granularity_ns else {
        return Ok((
            if birth_time.is_some() {
                crate::model::FileTimeRelation::ReviewFsPrecisionUnknown
            } else {
                crate::model::FileTimeRelation::Unavailable
            },
            crate::model::FileTimeRelation::ReviewFsPrecisionUnknown,
            "fs_precision_unknown",
        ));
    };
    if granularity_ns <= 0 || !(1..=1_000_000_000).contains(&candidate.precision_ns) {
        return Err(StoreError::invalid_input(
            "capture_time_member",
            "stored filesystem or candidate precision is invalid",
        ));
    }
    let candidate_seconds = parse_stored_utc_seconds(&candidate.utc_seconds_decimal)?;
    let tolerance_ns = granularity_ns.max(candidate.precision_ns);
    let birth_relation = match birth_time {
        Some((seconds, nanoseconds)) => relation_for_timestamp(
            candidate_seconds,
            candidate.utc_nanoseconds,
            seconds,
            nanoseconds,
            tolerance_ns,
        )?,
        None => crate::model::FileTimeRelation::Unavailable,
    };
    let modified_relation = relation_for_timestamp(
        candidate_seconds,
        candidate.utc_nanoseconds,
        observation.modified_time_seconds,
        observation.modified_time_nanoseconds,
        tolerance_ns,
    )?;
    let reason = if birth_relation == crate::model::FileTimeRelation::Matches
        || modified_relation == crate::model::FileTimeRelation::Matches
    {
        "embedded_time_matches_fs"
    } else {
        "embedded_time_differs_fs"
    };
    Ok((birth_relation, modified_relation, reason))
}

fn relation_for_timestamp(
    candidate_seconds: i128,
    candidate_nanoseconds: i64,
    filesystem_seconds: i64,
    filesystem_nanoseconds: i64,
    tolerance_ns: i64,
) -> Result<crate::model::FileTimeRelation> {
    if !(0..1_000_000_000).contains(&candidate_nanoseconds)
        || !(0..1_000_000_000).contains(&filesystem_nanoseconds)
        || tolerance_ns <= 0
    {
        return Err(StoreError::invalid_input(
            "capture_time_member",
            "timestamp components or comparison tolerance are invalid",
        ));
    }
    let candidate_total = candidate_seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(i128::from(candidate_nanoseconds)))
        .ok_or_else(|| {
            StoreError::invalid_input("capture_time_member", "candidate timestamp overflow")
        })?;
    let filesystem_total =
        i128::from(filesystem_seconds) * 1_000_000_000 + i128::from(filesystem_nanoseconds);
    let difference = candidate_total
        .checked_sub(filesystem_total)
        .and_then(i128::checked_abs)
        .ok_or_else(|| {
            StoreError::invalid_input("capture_time_member", "timestamp difference overflow")
        })?;
    Ok(if difference <= i128::from(tolerance_ns) {
        crate::model::FileTimeRelation::Matches
    } else {
        crate::model::FileTimeRelation::Differs
    })
}

fn parse_stored_utc_seconds(value: &str) -> Result<i128> {
    if value.is_empty() || value.len() > 40 || value.trim() != value || value.starts_with('+') {
        return Err(StoreError::invalid_input(
            "capture_time_member",
            "stored UTC seconds are not bounded canonical decimal",
        ));
    }
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
        || value == "-0"
    {
        return Err(StoreError::invalid_input(
            "capture_time_member",
            "stored UTC seconds are not canonical decimal",
        ));
    }
    value.parse::<i128>().map_err(|_| {
        StoreError::invalid_input("capture_time_member", "stored UTC seconds exceed i128")
    })
}

pub(crate) fn validate_capture_time_member_relations(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT member.analysis_build_id, member.member_ordinal, \
                member.birth_time_relation, member.modified_time_relation, \
                member.donor_eligibility, member.reason_code, member.candidate_id, \
                candidate.id, candidate.utc_seconds_decimal, candidate.utc_nanoseconds, \
                candidate.precision_ns, candidate.evidence_gate, candidate.semantic_kind, \
                observation.id, observation.birth_time_seconds, \
                observation.birth_time_nanoseconds, observation.modified_time_seconds, \
                observation.modified_time_nanoseconds, observation.timestamp_granularity_ns \
         FROM capture_time_member_assessments AS member \
         LEFT JOIN capture_time_candidates AS candidate \
           ON candidate.analysis_build_id = member.analysis_build_id \
          AND candidate.id = member.candidate_id \
         LEFT JOIN media_observation_snapshots AS observation \
           ON observation.id = member.media_observation_snapshot_id \
          AND observation.scan_run_id = member.scan_run_id \
          AND observation.volume_id = member.volume_id \
         ORDER BY member.analysis_build_id, member.member_ordinal",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let analysis_build_id = row.get::<_, i64>(0)?;
        let member_ordinal = row.get::<_, i64>(1)?;
        let birth_relation = row.get::<_, String>(2)?;
        let modified_relation = row.get::<_, String>(3)?;
        let donor_eligibility = row.get::<_, String>(4)?;
        let reason_code = row.get::<_, String>(5)?;
        let candidate_id = row.get::<_, Option<i64>>(6)?;
        let joined_candidate_id = row.get::<_, Option<i64>>(7)?;
        let candidate_seconds = row.get::<_, Option<String>>(8)?;
        let candidate_nanoseconds = row.get::<_, Option<i64>>(9)?;
        let candidate_precision = row.get::<_, Option<i64>>(10)?;
        let candidate_gate = row.get::<_, Option<String>>(11)?;
        let candidate_semantic = row.get::<_, Option<String>>(12)?;
        let observation_id = row.get::<_, Option<i64>>(13)?;
        let observation = StoredMemberObservation {
            birth_time_seconds: row.get(14)?,
            birth_time_nanoseconds: row.get(15)?,
            modified_time_seconds: row.get::<_, Option<i64>>(16)?.ok_or_else(|| {
                StoreError::invalid_input(
                    "capture_time_member",
                    "member observation has no modified timestamp",
                )
            })?,
            modified_time_nanoseconds: row.get::<_, Option<i64>>(17)?.ok_or_else(|| {
                StoreError::invalid_input(
                    "capture_time_member",
                    "member observation has no modified timestamp",
                )
            })?,
            timestamp_granularity_ns: row.get(18)?,
        };
        if observation_id.is_none() || donor_eligibility != "ineligible" {
            return Err(StoreError::invalid_input(
                "capture_time_member",
                format!(
                    "analysis {analysis_build_id} member {member_ordinal} has detached observation or forbidden donor status"
                ),
            ));
        }
        let candidate = match candidate_id {
            Some(id)
                if joined_candidate_id == Some(id)
                    && candidate_gate.as_deref() == Some("eligible")
                    && candidate_semantic.as_deref() == Some("utc") =>
            {
                Some(StoredMemberCandidate {
                    id,
                    utc_seconds_decimal: candidate_seconds.ok_or_else(|| {
                        StoreError::invalid_input(
                            "capture_time_member",
                            "eligible member candidate has no UTC seconds",
                        )
                    })?,
                    utc_nanoseconds: candidate_nanoseconds.ok_or_else(|| {
                        StoreError::invalid_input(
                            "capture_time_member",
                            "eligible member candidate has no UTC nanoseconds",
                        )
                    })?,
                    precision_ns: candidate_precision.ok_or_else(|| {
                        StoreError::invalid_input(
                            "capture_time_member",
                            "eligible member candidate has no precision",
                        )
                    })?,
                })
            }
            Some(_) => {
                return Err(StoreError::invalid_input(
                    "capture_time_member",
                    "member candidate is detached or not eligible UTC evidence",
                ));
            }
            None => None,
        };
        let expected = expected_member_assessment(candidate.as_ref(), &observation)?;
        if birth_relation != expected.0.as_storage_str()
            || modified_relation != expected.1.as_storage_str()
            || reason_code != expected.2
        {
            return Err(StoreError::invalid_input(
                "capture_time_member",
                format!(
                    "analysis {analysis_build_id} member {member_ordinal} stores a false filesystem-time relation"
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod capture_time_relation_tests {
    use super::{
        lower_hex, relation_for_timestamp, validate_capture_time_candidate_supports,
        validate_capture_time_member_relations, validate_eligible_candidate_support,
        CandidateSupportClaim,
    };
    use crate::model::FileTimeRelation;
    use rusqlite::Connection;

    #[test]
    fn v7_member_relation_uses_an_inclusive_nanosecond_tolerance() -> crate::Result<()> {
        assert_eq!(
            relation_for_timestamp(10, 0, 9, 999_999_500, 500)?,
            FileTimeRelation::Matches
        );
        assert_eq!(
            relation_for_timestamp(10, 0, 9, 999_999_499, 500)?,
            FileTimeRelation::Differs
        );
        assert_eq!(
            relation_for_timestamp(10, 0, 9, 0, 1_000_000_000)?,
            FileTimeRelation::Matches
        );
        Ok(())
    }

    #[test]
    fn v7_reopen_relation_validator_rejects_a_forged_match() -> crate::Result<()> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE capture_time_member_assessments ( \
                 analysis_build_id INTEGER NOT NULL, member_ordinal INTEGER NOT NULL, \
                 birth_time_relation TEXT NOT NULL, modified_time_relation TEXT NOT NULL, \
                 donor_eligibility TEXT NOT NULL, reason_code TEXT NOT NULL, \
                 candidate_id INTEGER, media_observation_snapshot_id INTEGER NOT NULL, \
                 scan_run_id INTEGER NOT NULL, volume_id INTEGER NOT NULL \
             ); \
             CREATE TABLE capture_time_candidates ( \
                 id INTEGER NOT NULL, analysis_build_id INTEGER NOT NULL, \
                 utc_seconds_decimal TEXT, utc_nanoseconds INTEGER, precision_ns INTEGER, \
                 evidence_gate TEXT NOT NULL, semantic_kind TEXT NOT NULL \
             ); \
             CREATE TABLE media_observation_snapshots ( \
                 id INTEGER NOT NULL, scan_run_id INTEGER NOT NULL, volume_id INTEGER NOT NULL, \
                 birth_time_seconds INTEGER, birth_time_nanoseconds INTEGER, \
                 modified_time_seconds INTEGER, modified_time_nanoseconds INTEGER, \
                 timestamp_granularity_ns INTEGER \
             ); \
             INSERT INTO capture_time_candidates VALUES ( \
                 1, 1, '1577934245', 0, 1000000000, 'eligible', 'utc' \
             ); \
             INSERT INTO media_observation_snapshots VALUES ( \
                 1, 1, 1, NULL, NULL, 2000, 0, 1 \
             ); \
             INSERT INTO capture_time_member_assessments VALUES ( \
                 1, 0, 'unavailable', 'matches', 'ineligible', \
                 'embedded_time_matches_fs', 1, 1, 1, 1 \
             );",
        )?;
        assert!(validate_capture_time_member_relations(&connection).is_err());
        connection.execute(
            "UPDATE capture_time_member_assessments \
             SET modified_time_relation = 'differs', \
                 reason_code = 'embedded_time_differs_fs'",
            [],
        )?;
        validate_capture_time_member_relations(&connection)
    }

    #[test]
    fn v7_eligible_candidate_requires_same_source_exact_exif_companions() -> crate::Result<()> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE capture_time_analysis_builds ( \
                 id INTEGER PRIMARY KEY, time_session_id INTEGER NOT NULL, \
                 exact_group_build_id INTEGER NOT NULL, volume_id INTEGER NOT NULL, \
                 scan_run_id INTEGER NOT NULL \
             ); \
             CREATE TABLE capture_time_analysis_sources ( \
                 analysis_build_id INTEGER NOT NULL, ordinal INTEGER NOT NULL, \
                 report_id INTEGER NOT NULL, source_key BLOB NOT NULL, lineage_key BLOB NOT NULL \
             ); \
             CREATE TABLE metadata_extraction_reports ( \
                 id INTEGER PRIMARY KEY, time_session_id INTEGER NOT NULL, \
                 exact_group_build_id INTEGER NOT NULL, volume_id INTEGER NOT NULL, \
                 scan_run_id INTEGER NOT NULL, metadata_probe_observation_id INTEGER NOT NULL, \
                 state TEXT NOT NULL, extraction_status TEXT NOT NULL, \
                 expected_issue_count INTEGER NOT NULL \
             ); \
             CREATE TABLE metadata_extraction_issues (report_id INTEGER NOT NULL); \
             CREATE TABLE metadata_source_revalidations ( \
                 report_id INTEGER NOT NULL, time_session_id INTEGER NOT NULL, \
                 exact_group_build_id INTEGER NOT NULL, \
                 metadata_probe_observation_id INTEGER NOT NULL, source_key BLOB NOT NULL, \
                 lineage_key BLOB NOT NULL, outcome TEXT NOT NULL, \
                 descriptor_revalidated INTEGER NOT NULL, path_revalidated INTEGER NOT NULL, \
                 session_revalidated INTEGER NOT NULL \
             ); \
             CREATE TABLE metadata_extraction_fields ( \
                 id INTEGER PRIMARY KEY, report_id INTEGER NOT NULL, field_kind TEXT NOT NULL, \
                 container_kind TEXT NOT NULL, tiff_header_offset INTEGER, \
                 tiff_ifd_offset INTEGER, jpeg_app1_offset INTEGER \
             ); \
             CREATE TABLE capture_time_observations ( \
                 analysis_build_id INTEGER NOT NULL, ordinal INTEGER NOT NULL, \
                 source_ordinal INTEGER NOT NULL, report_id INTEGER NOT NULL, \
                 metadata_field_id INTEGER NOT NULL, interpretation_kind TEXT NOT NULL, \
                 wall_year INTEGER, wall_month INTEGER, wall_day INTEGER, wall_hour INTEGER, \
                 wall_minute INTEGER, wall_second INTEGER, wall_nanosecond INTEGER, \
                 semantic_kind TEXT, offset_kind TEXT, utc_offset_minutes INTEGER, \
                 utc_seconds_decimal TEXT, utc_nanoseconds INTEGER, \
                 normalized_precision_ns INTEGER, parsed_offset_minutes INTEGER, \
                 subsecond_nanosecond INTEGER, subsecond_digits INTEGER, \
                 subsecond_precision_ns INTEGER \
             ); \
             CREATE TABLE capture_time_candidates ( \
                 id INTEGER PRIMARY KEY, analysis_build_id INTEGER NOT NULL, \
                 wall_year INTEGER NOT NULL, wall_month INTEGER NOT NULL, \
                 wall_day INTEGER NOT NULL, wall_hour INTEGER NOT NULL, \
                 wall_minute INTEGER NOT NULL, wall_second INTEGER NOT NULL, \
                 wall_nanosecond INTEGER NOT NULL, semantic_kind TEXT NOT NULL, \
                 offset_kind TEXT NOT NULL, utc_offset_minutes INTEGER, \
                 utc_seconds_decimal TEXT, utc_nanoseconds INTEGER, precision_ns INTEGER NOT NULL, \
                 evidence_gate TEXT NOT NULL, evidence_kinds_json TEXT NOT NULL, \
                 source_keys_json TEXT NOT NULL, lineage_keys_json TEXT NOT NULL, \
                 observation_ordinals_json TEXT NOT NULL \
             ); \
             INSERT INTO capture_time_analysis_builds VALUES (1, 10, 20, 1, 1); \
             INSERT INTO metadata_extraction_reports VALUES ( \
                 1, 10, 20, 1, 1, 101, 'sealed', 'extracted_unvalidated', 0 \
             ); \
             INSERT INTO metadata_extraction_reports VALUES ( \
                 2, 10, 20, 1, 1, 102, 'sealed', 'extracted_unvalidated', 0 \
             ); \
             INSERT INTO metadata_extraction_fields VALUES ( \
                 1, 1, 'exif_date_time_original', 'tiff', 20, 30, NULL \
             ); \
             INSERT INTO metadata_extraction_fields VALUES ( \
                 2, 1, 'exif_offset_time_original', 'tiff', 20, 30, NULL \
             ); \
             INSERT INTO metadata_extraction_fields VALUES ( \
                 3, 1, 'exif_subsec_time_original', 'tiff', 20, 30, NULL \
             ); \
             INSERT INTO metadata_extraction_fields VALUES ( \
                 4, 2, 'exif_offset_time_original', 'tiff', 20, 30, NULL \
             ); \
             INSERT INTO metadata_extraction_fields VALUES ( \
                 5, 1, 'exif_offset_time_original', 'tiff', 20, 31, NULL \
             ); \
             INSERT INTO metadata_extraction_fields VALUES ( \
                 6, 1, 'exif_create_date', 'tiff', 20, 30, NULL \
             ); \
             INSERT INTO metadata_extraction_fields VALUES ( \
                 7, 1, 'quicktime_metadata_creation_date', 'iso_bmff', NULL, NULL, NULL \
             ); \
             INSERT INTO capture_time_observations VALUES ( \
                 1, 0, 0, 1, 1, 'timestamp', 2020, 1, 2, 3, 4, 5, 0, \
                 'floating', 'missing', NULL, NULL, NULL, 1000000000, \
                 NULL, NULL, NULL, NULL \
             ); \
             INSERT INTO capture_time_observations VALUES ( \
                 1, 1, 0, 1, 2, 'offset', NULL, NULL, NULL, NULL, NULL, NULL, NULL, \
                 NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL \
             ); \
             INSERT INTO capture_time_observations VALUES ( \
                 1, 2, 0, 1, 3, 'subsecond', NULL, NULL, NULL, NULL, NULL, NULL, NULL, \
                 NULL, NULL, NULL, NULL, NULL, NULL, NULL, 123000000, 3, 1000000 \
             ); \
             INSERT INTO capture_time_observations VALUES ( \
                 1, 3, 1, 2, 4, 'offset', NULL, NULL, NULL, NULL, NULL, NULL, NULL, \
                 NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL \
             ); \
             INSERT INTO capture_time_observations VALUES ( \
                 1, 4, 0, 1, 5, 'offset', NULL, NULL, NULL, NULL, NULL, NULL, NULL, \
                 NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL \
             ); \
             INSERT INTO capture_time_observations VALUES ( \
                 1, 5, 0, 1, 6, 'timestamp', 2020, 1, 2, 3, 4, 5, 0, \
                 'floating', 'missing', NULL, NULL, NULL, 1000000000, \
                 NULL, NULL, NULL, NULL \
             ); \
             INSERT INTO capture_time_observations VALUES ( \
                 1, 6, 0, 1, 7, 'timestamp', 2020, 1, 2, 3, 4, 5, 0, \
                 'floating', 'missing', NULL, NULL, NULL, 1000000000, \
                 NULL, NULL, NULL, NULL \
             );",
        )?;
        for (ordinal, report_id, source, lineage, probe) in [
            (0_i64, 1_i64, [1_u8; 32], [3_u8; 32], 101_i64),
            (1_i64, 2_i64, [2_u8; 32], [4_u8; 32], 102_i64),
        ] {
            connection.execute(
                "INSERT INTO capture_time_analysis_sources VALUES (1, ?1, ?2, ?3, ?4)",
                rusqlite::params![ordinal, report_id, source.as_slice(), lineage.as_slice()],
            )?;
            connection.execute(
                "INSERT INTO metadata_source_revalidations VALUES ( \
                     ?1, 10, 20, ?2, ?3, ?4, 'reextracted_pinned_exact', 1, 1, 1 \
                 )",
                rusqlite::params![report_id, probe, source.as_slice(), lineage.as_slice()],
            )?;
        }
        let claim = CandidateSupportClaim {
            analysis_build_id: 1,
            wall_year: 2020,
            wall_month: 1,
            wall_day: 2,
            wall_hour: 3,
            wall_minute: 4,
            wall_second: 5,
            wall_nanosecond: 123_000_000,
            semantic_kind: "utc".to_owned(),
            offset_kind: "explicit".to_owned(),
            utc_offset_minutes: Some(0),
            utc_seconds_decimal: Some("1577934245".to_owned()),
            utc_nanoseconds: Some(123_000_000),
            precision_ns: 1_000_000,
            evidence_kinds: vec!["exif_date_time_original".to_owned()],
            source_keys: vec![[1; 32]],
            lineage_keys: vec![[3; 32]],
            observation_ordinals: vec![0, 1, 2],
        };
        validate_eligible_candidate_support(&connection, &claim)?;

        let mut wrong_offset = claim.clone();
        wrong_offset.utc_offset_minutes = Some(60);
        wrong_offset.utc_seconds_decimal = Some("1577930645".to_owned());
        assert!(validate_eligible_candidate_support(&connection, &wrong_offset).is_err());

        let mut cross_source = claim;
        cross_source.source_keys.push([2; 32]);
        cross_source.lineage_keys.push([4; 32]);
        cross_source.observation_ordinals = vec![0, 2, 3];
        assert!(validate_eligible_candidate_support(&connection, &cross_source).is_err());

        let mut cross_ifd = complete_candidate_claim();
        cross_ifd.observation_ordinals = vec![0, 2, 4];
        assert!(validate_eligible_candidate_support(&connection, &cross_ifd).is_err());

        let mut borrowed_create_date = complete_candidate_claim();
        borrowed_create_date
            .evidence_kinds
            .push("exif_create_date".to_owned());
        borrowed_create_date.observation_ordinals = vec![0, 1, 2, 5];
        assert!(validate_eligible_candidate_support(&connection, &borrowed_create_date).is_err());

        let mut borrowed_quicktime = complete_candidate_claim();
        borrowed_quicktime
            .evidence_kinds
            .push("quicktime_metadata_creation_date".to_owned());
        borrowed_quicktime.observation_ordinals = vec![0, 1, 2, 6];
        assert!(validate_eligible_candidate_support(&connection, &borrowed_quicktime).is_err());

        let source_keys_json = serde_json::to_string(&[lower_hex(&[1; 32])])?;
        let lineage_keys_json = serde_json::to_string(&[lower_hex(&[3; 32])])?;
        connection.execute(
            "INSERT INTO capture_time_candidates VALUES ( \
                 1, 1, 2020, 1, 2, 3, 4, 5, 123000000, 'utc', 'explicit', 0, \
                 '1577934245', 123000000, 1000000, 'eligible', \
                 '[\"exif_date_time_original\"]', ?1, ?2, '[0,1,2]' \
             )",
            rusqlite::params![source_keys_json, lineage_keys_json],
        )?;
        validate_capture_time_candidate_supports(&connection)?;
        connection.execute(
            "UPDATE capture_time_candidates SET observation_ordinals_json = '[0,2,4]'",
            [],
        )?;
        assert!(validate_capture_time_candidate_supports(&connection).is_err());
        connection.execute(
            "UPDATE capture_time_candidates SET observation_ordinals_json = '[0,1,2]'",
            [],
        )?;

        connection.execute(
            "UPDATE metadata_extraction_reports SET extraction_status = 'partial' WHERE id = 1",
            [],
        )?;
        let mut complete_source = cross_source;
        complete_source.source_keys = vec![[1; 32]];
        complete_source.lineage_keys = vec![[3; 32]];
        complete_source.observation_ordinals = vec![0, 1, 2];
        assert!(validate_eligible_candidate_support(&connection, &complete_source).is_err());
        Ok(())
    }

    fn complete_candidate_claim() -> CandidateSupportClaim {
        CandidateSupportClaim {
            analysis_build_id: 1,
            wall_year: 2020,
            wall_month: 1,
            wall_day: 2,
            wall_hour: 3,
            wall_minute: 4,
            wall_second: 5,
            wall_nanosecond: 123_000_000,
            semantic_kind: "utc".to_owned(),
            offset_kind: "explicit".to_owned(),
            utc_offset_minutes: Some(0),
            utc_seconds_decimal: Some("1577934245".to_owned()),
            utc_nanoseconds: Some(123_000_000),
            precision_ns: 1_000_000,
            evidence_kinds: vec!["exif_date_time_original".to_owned()],
            source_keys: vec![[1; 32]],
            lineage_keys: vec![[3; 32]],
            observation_ordinals: vec![0, 1, 2],
        }
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn validate_v5_batch(field: &'static str, count: usize) -> Result<()> {
    if !(1..=MAX_V5_WRITE_BATCH).contains(&count) {
        return Err(StoreError::invalid_input(
            field,
            format!("batch must contain between 1 and {MAX_V5_WRITE_BATCH} records"),
        ));
    }
    Ok(())
}

fn validate_namespace_profile(input: &NamespaceProfileInput) -> Result<()> {
    require_positive("volume_id", input.volume_id)?;
    require_positive("profile_version", input.profile_version)?;
    if !matches!(
        input.native_path_encoding.as_str(),
        "unix_bytes" | "windows_utf16_le"
    ) {
        return Err(StoreError::invalid_input(
            "native_path_encoding",
            "expected unix_bytes or windows_utf16_le",
        ));
    }
    if !matches!(
        input.case_behavior.as_str(),
        "sensitive" | "insensitive_preserving" | "insensitive_nonpreserving" | "unknown"
    ) {
        return Err(StoreError::invalid_input(
            "case_behavior",
            "unsupported case behavior",
        ));
    }
    if !matches!(
        input.unicode_behavior.as_str(),
        "exact" | "nfc" | "nfd" | "normalizing_other" | "unknown"
    ) {
        return Err(StoreError::invalid_input(
            "unicode_behavior",
            "unsupported Unicode behavior",
        ));
    }
    if input.key_strategy != "exact_native_v1" {
        return Err(StoreError::invalid_input(
            "key_strategy",
            "only exact_native_v1 is supported",
        ));
    }
    require_positive("key_algorithm_version", input.key_algorithm_version)?;
    if !matches!(
        input.reuse_scope.as_str(),
        "cross_session" | "current_session_only"
    ) {
        return Err(StoreError::invalid_input(
            "reuse_scope",
            "observed namespaces must be cross_session or current_session_only",
        ));
    }
    if input.reuse_scope == "cross_session"
        && (input.case_behavior == "unknown" || input.unicode_behavior == "unknown")
    {
        return Err(StoreError::invalid_input(
            "reuse_scope",
            "cross-session reuse requires known case and Unicode behavior",
        ));
    }
    match input.reuse_scope.as_str() {
        "cross_session" if input.bound_mount_session_key.is_some() => {
            return Err(StoreError::invalid_input(
                "bound_mount_session_key",
                "cross-session namespaces must not be bound to one mount session",
            ));
        }
        "current_session_only" if input.bound_mount_session_key.is_none() => {
            return Err(StoreError::invalid_input(
                "bound_mount_session_key",
                "current-session namespaces must be bound to their authenticated mount session",
            ));
        }
        _ => {}
    }
    require_nonnegative("created_at_ms", input.created_at_ms)
}

fn validate_scoped_scan_job(input: &NewScopedScanJob) -> Result<()> {
    require_bounded_nonempty("job_key", &input.job_key, MAX_IDENTIFIER_BYTES)?;
    require_positive("volume_id", input.volume_id)?;
    require_positive("namespace_profile_id", input.namespace_profile_id)?;
    validate_relative_path("root_display", &input.root_display, true)?;
    validate_v5_raw_path(
        "mount_relative_root_raw",
        &input.mount_relative_root_raw,
        &input.path_encoding,
        true,
        Some(&input.root_display),
    )?;
    require_nonnegative("created_at_ms", input.created_at_ms)?;
    let _ = serialize_optional_json("config", &input.config, MAX_JSON_BYTES)?;
    Ok(())
}

fn validate_bound_scan_run(input: &NewBoundScanRun) -> Result<()> {
    require_bounded_nonempty("run_key", &input.run_key, MAX_IDENTIFIER_BYTES)?;
    require_positive("scan_job_id", input.scan_job_id)?;
    require_positive("volume_id", input.volume_id)?;
    require_positive("capability_profile_id", input.capability_profile_id)?;
    if input.parent_scan_run_id.is_some_and(|id| id <= 0) {
        return Err(StoreError::invalid_input(
            "parent_scan_run_id",
            "value must be positive",
        ));
    }
    validate_v5_raw_path(
        "mount_relative_root_raw",
        &input.mount_relative_root_raw,
        &input.path_encoding,
        true,
        None,
    )?;
    if !matches!(
        input.scan_mode.as_str(),
        "full" | "incremental" | "resume" | "verify"
    ) {
        return Err(StoreError::invalid_input(
            "scan_mode",
            "unsupported scan mode",
        ));
    }
    require_nonnegative("created_at_ms", input.created_at_ms)?;
    let _ = serialize_optional_json("config", &input.config, MAX_JSON_BYTES)?;
    Ok(())
}

fn validate_bound_run_parent(
    transaction: &Transaction<'_>,
    input: &NewBoundScanRun,
    namespace_profile_id: i64,
    root_scope_key: &[u8; 32],
) -> Result<()> {
    let Some(parent_id) = input.parent_scan_run_id else {
        return Ok(());
    };
    let valid = transaction.query_row(
        "SELECT EXISTS( \
             SELECT 1 FROM scan_runs AS parent \
             JOIN scan_run_sessions AS session ON session.scan_run_id = parent.id \
             WHERE parent.id = ?1 AND parent.volume_id = ?2 \
               AND parent.state IN ('completed', 'failed', 'cancelled', 'interrupted') \
               AND session.scan_job_id = ?3 AND session.namespace_profile_id = ?4 \
               AND session.root_scope_key = ?5 \
         )",
        params![
            parent_id,
            input.volume_id,
            input.scan_job_id,
            namespace_profile_id,
            root_scope_key.as_slice(),
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !valid {
        return Err(StoreError::IdempotencyConflict {
            entity: "bound_scan_run_parent",
            key: input.run_key.clone(),
        });
    }
    Ok(())
}

fn validate_observation(input: &ObservationInput, native_path_encoding: &str) -> Result<()> {
    let compatible = match native_path_encoding {
        "unix_bytes" => matches!(input.path_encoding.as_str(), "utf8" | "unix_bytes"),
        "windows_utf16_le" => input.path_encoding == "windows_utf16_le",
        _ => false,
    };
    if !compatible {
        return Err(StoreError::invalid_input(
            "path_encoding",
            "observation encoding does not match the bound namespace",
        ));
    }
    validate_relative_path("display_path", &input.display_path, false)?;
    validate_v5_raw_path(
        "mount_relative_path_raw",
        &input.mount_relative_path_raw,
        &input.path_encoding,
        false,
        None,
    )?;
    validate_v5_raw_path(
        "root_relative_path_raw",
        &input.root_relative_path_raw,
        &input.path_encoding,
        false,
        Some(&input.display_path),
    )?;
    if input.entry_type != "regular" {
        return Err(StoreError::invalid_input(
            "entry_type",
            "v5 media observations currently accept regular files only",
        ));
    }
    if !matches!(
        input.media_kind.as_str(),
        "photo" | "video" | "raw" | "sidecar" | "unknown"
    ) {
        return Err(StoreError::invalid_input(
            "media_kind",
            "unsupported media kind",
        ));
    }
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
    require_positive("stat_signature_version", input.stat_signature_version)?;
    if input
        .native_file_id
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > 1_024)
    {
        return Err(StoreError::invalid_input(
            "native_file_id",
            "native file id must contain between 1 and 1024 bytes",
        ));
    }
    validate_optional_nonnegative("native_file_generation", input.native_file_generation)?;
    require_nonnegative("file_mode", input.file_mode)?;
    require_nonnegative("size_bytes", input.size_bytes)?;
    validate_optional_nonnegative("allocated_bytes", input.allocated_bytes)?;
    validate_optional_positive("link_count", input.link_count)?;
    validate_timestamp("birth_time", input.birth_time)?;
    validate_timestamp("modified_time", Some(input.modified_time))?;
    validate_timestamp("changed_time", Some(input.changed_time))?;
    validate_timestamp("accessed_time", input.accessed_time)?;
    validate_optional_positive("timestamp_granularity_ns", input.timestamp_granularity_ns)?;
    require_nonnegative("observed_at_ms", input.observed_at_ms)
}

fn validate_observation_path_binding(
    context: &BoundRunContext,
    input: &ObservationInput,
) -> Result<()> {
    validate_v5_path_relation(
        &context.mount_relative_root_raw,
        &context.root_path_encoding,
        &input.mount_relative_path_raw,
        &input.path_encoding,
        &input.root_relative_path_raw,
        &input.path_encoding,
    )
}

pub(crate) fn validate_v5_path_relation(
    mount_relative_root_raw: &[u8],
    root_path_encoding: &str,
    mount_relative_path_raw: &[u8],
    mount_path_encoding: &str,
    root_relative_path_raw: &[u8],
    root_relative_path_encoding: &str,
) -> Result<()> {
    validate_v5_raw_path(
        "mount_relative_root_raw",
        mount_relative_root_raw,
        root_path_encoding,
        true,
        None,
    )?;
    validate_v5_raw_path(
        "mount_relative_path_raw",
        mount_relative_path_raw,
        mount_path_encoding,
        false,
        None,
    )?;
    validate_v5_raw_path(
        "root_relative_path_raw",
        root_relative_path_raw,
        root_relative_path_encoding,
        false,
        None,
    )?;

    let matches = match (root_path_encoding, mount_path_encoding) {
        ("utf8" | "unix_bytes", "utf8" | "unix_bytes") => {
            if mount_path_encoding != root_relative_path_encoding {
                false
            } else if mount_relative_root_raw.is_empty() {
                mount_relative_path_raw == root_relative_path_raw
            } else {
                let expected_len = mount_relative_root_raw
                    .len()
                    .checked_add(1)
                    .and_then(|length| length.checked_add(root_relative_path_raw.len()));
                expected_len == Some(mount_relative_path_raw.len())
                    && mount_relative_path_raw.starts_with(mount_relative_root_raw)
                    && mount_relative_path_raw.get(mount_relative_root_raw.len()) == Some(&b'/')
                    && mount_relative_path_raw[mount_relative_root_raw.len() + 1..]
                        == *root_relative_path_raw
            }
        }
        ("windows_utf16_le", "windows_utf16_le") => {
            if root_relative_path_encoding != "windows_utf16_le" {
                return Err(StoreError::invalid_input(
                    "path_encoding",
                    "mount-relative and root-relative path encodings must match",
                ));
            }
            let root_units = decode_windows_path_units(mount_relative_root_raw)?;
            let mount_units = decode_windows_path_units(mount_relative_path_raw)?;
            let relative_units = decode_windows_path_units(root_relative_path_raw)?;
            let mut expected_components = Vec::new();
            if !root_units.is_empty() {
                expected_components.extend(windows_path_components(&root_units));
            }
            expected_components.extend(windows_path_components(&relative_units));
            expected_components == windows_path_components(&mount_units)
        }
        _ => false,
    };
    if !matches {
        return Err(StoreError::invalid_input(
            "mount_relative_path_raw",
            "mount-relative path must be the bound scan root followed by the root-relative path",
        ));
    }
    Ok(())
}

fn join_display_path(root_display: &str, relative_display: &str) -> Result<String> {
    validate_relative_path("root_display", root_display, true)?;
    validate_relative_path("display_path", relative_display, false)?;
    if root_display.is_empty() {
        return Ok(relative_display.to_owned());
    }
    let length = root_display
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(relative_display.len()))
        .ok_or_else(|| StoreError::invalid_input("display_path", "display path length overflow"))?;
    if length > MAX_PATH_BYTES {
        return Err(StoreError::invalid_input(
            "display_path",
            format!("path exceeds {MAX_PATH_BYTES} bytes"),
        ));
    }
    let mut joined = String::with_capacity(length);
    joined.push_str(root_display);
    joined.push('/');
    joined.push_str(relative_display);
    Ok(joined)
}

fn decode_windows_path_units(value: &[u8]) -> Result<Vec<u16>> {
    let mut chunks = value.chunks_exact(2);
    let units = chunks
        .by_ref()
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    if !chunks.remainder().is_empty() {
        return Err(StoreError::invalid_input(
            "mount_relative_path_raw",
            "windows_utf16_le path must contain complete 16-bit code units",
        ));
    }
    Ok(units)
}

fn windows_path_components(value: &[u16]) -> Vec<&[u16]> {
    value
        .split(|unit| *unit == b'/' as u16 || *unit == b'\\' as u16)
        .collect()
}

fn validate_timestamp(field: &'static str, timestamp: Option<FileTimestampParts>) -> Result<()> {
    if timestamp.is_some_and(|value| value.nanoseconds > 999_999_999) {
        return Err(StoreError::invalid_input(
            field,
            "nanoseconds must be between 0 and 999999999",
        ));
    }
    Ok(())
}

fn validate_directory_observation(
    input: &CoreDirectoryObservationInput,
    native_path_encoding: &str,
) -> Result<()> {
    let compatible = match native_path_encoding {
        "unix_bytes" => matches!(input.path_encoding.as_str(), "utf8" | "unix_bytes"),
        "windows_utf16_le" => input.path_encoding == "windows_utf16_le",
        _ => false,
    };
    if !compatible {
        return Err(StoreError::invalid_input(
            "path_encoding",
            "directory encoding does not match the bound namespace",
        ));
    }
    validate_persisted_path_evidence(
        &input.display_path,
        &input.root_relative_path_raw,
        &input.path_encoding,
        true,
    )?;
    require_nonnegative("observed_at_ms", input.observed_at_ms)?;
    Ok(())
}

fn validate_opaque_ticket(ticket: &[u8]) -> Result<()> {
    if ticket.is_empty() || ticket.len() > MAX_PATH_BYTES {
        return Err(StoreError::invalid_input(
            "ticket_blob",
            "opaque core ticket must contain between 1 and 65536 bytes",
        ));
    }
    Ok(())
}

fn validate_coverage_outcome(input: &CoverageOutcomeInput) -> Result<()> {
    require_nonnegative("directory_count", input.directory_count)?;
    require_nonnegative("replayed_count", input.replayed_count)?;
    require_nonnegative("stable_count", input.stable_count)?;
    require_nonnegative("failed_count", input.failed_count)?;
    require_nonnegative("finalized_at_ms", input.finalized_at_ms)?;
    let replayed = input
        .stable_count
        .checked_add(input.failed_count)
        .ok_or_else(|| StoreError::invalid_input("coverage_count", "coverage count overflow"))?;
    if input.replayed_count != replayed || input.replayed_count > input.directory_count {
        return Err(StoreError::invalid_input(
            "coverage_count",
            "replayed directories must equal stable plus failed and not exceed total",
        ));
    }
    match input.status {
        CoverageStatus::Complete => {
            if input.replayed_count != input.directory_count
                || input.stable_count != input.directory_count
                || input.failed_count != 0
                || input.core_manifest_digest.is_none()
                || input.core_seal_digest.is_none()
                || input.volume_verification_manifest.is_none()
            {
                return Err(StoreError::invalid_input(
                    "coverage_status",
                    "complete coverage requires every directory stable and all three manifests",
                ));
            }
        }
        CoverageStatus::Partial | CoverageStatus::Interrupted => {
            if input.core_seal_digest.is_some() {
                return Err(StoreError::invalid_input(
                    "core_seal_digest",
                    "incomplete coverage cannot carry a complete core seal",
                ));
            }
        }
    }
    Ok(())
}

fn validate_fresh_fingerprint(input: &FreshFingerprintInput) -> Result<()> {
    require_positive("observation_id", input.observation_id)?;
    require_bounded_nonempty("algorithm", &input.algorithm, MAX_IDENTIFIER_BYTES)?;
    require_positive("algorithm_version", input.algorithm_version)?;
    if input.digest.is_empty() || input.digest.len() > 1_024 {
        return Err(StoreError::invalid_input(
            "digest",
            "fingerprint digest must contain between 1 and 1024 bytes",
        ));
    }
    require_nonnegative("observed_size_bytes", input.observed_size_bytes)?;
    require_nonnegative("bytes_read", input.bytes_read)?;
    if input.bytes_read > input.observed_size_bytes {
        return Err(StoreError::invalid_input(
            "bytes_read",
            "bytes read cannot exceed the observed file size",
        ));
    }
    if input.fingerprint_kind == FreshFingerprintKind::ExactBytes
        && (!input.reached_expected_eof || input.bytes_read != input.observed_size_bytes)
    {
        return Err(StoreError::invalid_input(
            "reached_expected_eof",
            "exact fingerprint must cover all observed bytes and expected EOF",
        ));
    }
    require_nonnegative("completed_at_ms", input.completed_at_ms)?;
    require_nonnegative("created_at_ms", input.created_at_ms)?;
    if input.completed_at_ms < input.created_at_ms {
        return Err(StoreError::invalid_input(
            "completed_at_ms",
            "fingerprint completion cannot predate creation",
        ));
    }
    Ok(())
}

fn validate_v5_raw_path(
    field: &'static str,
    raw: &[u8],
    encoding: &str,
    allow_empty: bool,
    expected_utf8_display: Option<&str>,
) -> Result<()> {
    if raw.len() > MAX_PATH_BYTES {
        return Err(StoreError::invalid_input(
            field,
            format!("path exceeds {MAX_PATH_BYTES} bytes"),
        ));
    }
    if raw.is_empty() {
        if !allow_empty {
            return Err(StoreError::invalid_input(field, "path must not be empty"));
        }
        return if matches!(encoding, "utf8" | "unix_bytes" | "windows_utf16_le") {
            Ok(())
        } else {
            Err(StoreError::invalid_input(
                field,
                "unsupported path encoding",
            ))
        };
    }
    let display = match (encoding, expected_utf8_display) {
        ("utf8", Some(display)) => display,
        ("utf8", None) => std::str::from_utf8(raw)
            .map_err(|_| StoreError::invalid_input(field, "utf8 path is not valid UTF-8"))?,
        (_, Some(display)) => display,
        (_, None) => "path",
    };
    validate_raw_relative_path(display, raw, encoding, allow_empty)
        .map(|_| ())
        .map_err(|error| match error {
            StoreError::InvalidInput { reason, .. } => StoreError::invalid_input(field, reason),
            other => other,
        })
}

fn timestamp_seconds(value: Option<FileTimestampParts>) -> Option<i64> {
    value.map(|timestamp| timestamp.seconds)
}

fn timestamp_nanoseconds(value: Option<FileTimestampParts>) -> Option<i64> {
    value.map(|timestamp| i64::from(timestamp.nanoseconds))
}

fn timestamp_total_ns(value: Option<FileTimestampParts>) -> Option<i64> {
    value.and_then(|timestamp| {
        timestamp
            .seconds
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(i64::from(timestamp.nanoseconds)))
    })
}

fn scoped_v5_storage_path_key(
    volume_id: i64,
    namespace_profile_id: i64,
    stable_path_key: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.v5-media-storage-path.v1\0");
    hasher.update(&volume_id.to_le_bytes());
    hasher.update(&namespace_profile_id.to_le_bytes());
    hasher.update(stable_path_key);
    *hasher.finalize().as_bytes()
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

#[allow(dead_code)]
fn validate_scan_job(input: &NewScanJob) -> Result<()> {
    require_bounded_nonempty("job_key", &input.job_key, MAX_IDENTIFIER_BYTES)?;
    require_positive("volume_id", input.volume_id)?;
    require_positive("capability_profile_id", input.capability_profile_id)?;
    require_positive("path_semantics_version", input.path_semantics_version)?;
    validate_relative_path("root_relative_path", &input.root_relative_path, true)?;
    require_nonnegative("created_at_ms", input.created_at_ms)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
            let mut component_count = 0_usize;
            for component in value.split(|byte| *byte == b'/') {
                if component.is_empty() || component == b"." || component == b".." {
                    return Err(StoreError::invalid_input(
                        "relative_path_raw",
                        "Unix path contains an empty, dot, or parent component",
                    ));
                }
                if component.len() > 16 * 1024 {
                    return Err(StoreError::invalid_input(
                        "relative_path_raw",
                        "Unix path component exceeds 16384 bytes",
                    ));
                }
                component_count = component_count.checked_add(1).ok_or_else(|| {
                    StoreError::invalid_input("relative_path_raw", "component count overflow")
                })?;
                if component_count > 1_024 {
                    return Err(StoreError::invalid_input(
                        "relative_path_raw",
                        "Unix path exceeds 1024 components",
                    ));
                }
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
    let mut component_count = 0_usize;
    for component in code_units.split(|unit| *unit == b'/' as u16 || *unit == b'\\' as u16) {
        if component.is_empty()
            || component == [b'.' as u16]
            || component == [b'.' as u16, b'.' as u16]
            || component
                .last()
                .is_some_and(|unit| *unit == b'.' as u16 || *unit == b' ' as u16)
        {
            return Err(StoreError::invalid_input(
                "relative_path_raw",
                "Windows path contains an empty, dot, parent, or ambiguous trailing component",
            ));
        }
        if component.len().saturating_mul(2) > 16 * 1024 {
            return Err(StoreError::invalid_input(
                "relative_path_raw",
                "Windows path component exceeds 16384 bytes",
            ));
        }
        if component.iter().any(|unit| {
            *unit < 0x20
                || matches!(
                    *unit,
                    value if value == b'<' as u16
                        || value == b'>' as u16
                        || value == b'"' as u16
                        || value == b'|' as u16
                        || value == b'?' as u16
                        || value == b'*' as u16
                )
        }) {
            return Err(StoreError::invalid_input(
                "relative_path_raw",
                "Windows path contains a control or forbidden character",
            ));
        }
        if is_windows_device_component(component) {
            return Err(StoreError::invalid_input(
                "relative_path_raw",
                "Windows path contains a reserved device component",
            ));
        }
        component_count = component_count.checked_add(1).ok_or_else(|| {
            StoreError::invalid_input("relative_path_raw", "component count overflow")
        })?;
        if component_count > 1_024 {
            return Err(StoreError::invalid_input(
                "relative_path_raw",
                "Windows path exceeds 1024 components",
            ));
        }
    }
    Ok(())
}

fn is_windows_device_component(component: &[u16]) -> bool {
    let stem_end = component
        .iter()
        .position(|unit| *unit == b'.' as u16)
        .unwrap_or(component.len());
    let stem = component[..stem_end]
        .iter()
        .map(|unit| ascii_uppercase_u16(*unit))
        .collect::<Vec<_>>();
    windows_units_match_ascii(&stem, b"CON")
        || windows_units_match_ascii(&stem, b"PRN")
        || windows_units_match_ascii(&stem, b"AUX")
        || windows_units_match_ascii(&stem, b"NUL")
        || windows_units_match_ascii(&stem, b"CLOCK$")
        || windows_units_match_ascii(&stem, b"CONIN$")
        || windows_units_match_ascii(&stem, b"CONOUT$")
        || numbered_windows_device_component(&stem, b"COM")
        || numbered_windows_device_component(&stem, b"LPT")
}

fn numbered_windows_device_component(stem: &[u16], prefix: &[u8; 3]) -> bool {
    if stem.len() != 4 || !windows_units_match_ascii(&stem[..3], prefix) {
        return false;
    }
    matches!(stem[3], value if (b'0' as u16..=b'9' as u16).contains(&value))
        || matches!(stem[3], 0x00b9 | 0x00b2 | 0x00b3)
}

fn windows_units_match_ascii(units: &[u16], ascii: &[u8]) -> bool {
    units.len() == ascii.len()
        && units
            .iter()
            .zip(ascii)
            .all(|(unit, byte)| *unit == *byte as u16)
}

fn ascii_uppercase_u16(value: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&value) {
        value - (b'a' - b'A') as u16
    } else {
        value
    }
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
            | ("completed", "running")
            | ("cancelled", "running")
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
        | ("failed", "queued", "running", "running")
        | ("completed", "queued", "running", "running")
        | ("cancelled", "queued", "running", "running") => TransitionOrder::JobThenRun,
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

/// Computes the feature-independent digest used by v7 policy-context rows.
pub fn compute_time_policy_context_digest(
    value: &serde_json::Value,
) -> Result<crate::model::TimePolicyContextDigest> {
    let bytes = canonical_json_bytes(value)?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(StoreError::invalid_input(
            "policy_context_json",
            "canonical policy context exceeds 1 MiB",
        ));
    }
    Ok(
        crate::model::TimePolicyContextDigest::from_runtime_evidence(
            *blake3::hash(&bytes).as_bytes(),
        ),
    )
}

/// Computes the copy-family key from exact content identity only.
///
/// Run, mount, path, observation, and exact-group identity are deliberately
/// excluded so independently copied bytes share one lineage key.
pub fn compute_time_lineage_key(material: &TimeExactFingerprintMaterial) -> TimeLineageKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.runtime.timestamp-lineage.v1\0");
    hash_unchecked_length_prefixed(&mut hasher, material.algorithm.as_bytes());
    hasher.update(&material.algorithm_version.to_le_bytes());
    hasher.update(material.parameters_hash.as_bytes());
    hasher.update(&material.observed_size_bytes.to_le_bytes());
    hash_unchecked_length_prefixed(&mut hasher, &material.digest);
    TimeLineageKey::from_runtime_evidence(*hasher.finalize().as_bytes())
}

/// Computes a descriptor/session/path/stat/group-bound v2 source identity.
pub fn compute_time_source_key(material: &TimeSourceKeyMaterial) -> TimeSourceKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.runtime.timestamp-source.v2\0");
    hasher.update(&material.runtime_contract_version.to_le_bytes());
    hasher.update(&material.scan_run_id.to_le_bytes());
    hasher.update(material.core_session_id.as_bytes());
    hasher.update(material.mount_session_key.as_bytes());
    hasher.update(material.root_scope_key.as_bytes());
    hasher.update(material.stable_root_path_key.as_bytes());
    hasher.update(material.root_object_signature.as_bytes());
    hasher.update(material.stable_path_key.as_bytes());
    hasher.update(material.source_signature.as_bytes());
    hasher.update(&material.observation_id.to_le_bytes());
    hasher.update(&material.fingerprint_id.to_le_bytes());
    hasher.update(material.group_key.as_bytes());
    hasher.update(material.group_manifest.as_bytes());
    hash_unchecked_length_prefixed(&mut hasher, material.exact_fingerprint.algorithm.as_bytes());
    hasher.update(&material.exact_fingerprint.algorithm_version.to_le_bytes());
    hasher.update(material.exact_fingerprint.parameters_hash.as_bytes());
    hasher.update(&material.exact_fingerprint.observed_size_bytes.to_le_bytes());
    hash_unchecked_length_prefixed(&mut hasher, &material.exact_fingerprint.digest);
    TimeSourceKey::from_runtime_evidence(*hasher.finalize().as_bytes())
}

enum ManifestValue<'a> {
    Null,
    Integer(i64),
    Text(&'a str),
    Blob(&'a [u8]),
}

fn begin_manifest_section(hasher: &mut blake3::Hasher, label: &[u8]) -> Result<()> {
    hash_length_prefixed(hasher, label)
}

fn hash_manifest_row(hasher: &mut blake3::Hasher, values: &[ManifestValue<'_>]) -> Result<()> {
    hasher.update(&[0xa5]);
    for value in values {
        match value {
            ManifestValue::Null => {
                hasher.update(&[0]);
            }
            ManifestValue::Integer(value) => {
                hasher.update(&[1]);
                hasher.update(&value.to_le_bytes());
            }
            ManifestValue::Text(value) => {
                hasher.update(&[3]);
                hash_length_prefixed(hasher, value.as_bytes())?;
            }
            ManifestValue::Blob(value) => {
                hasher.update(&[4]);
                hash_length_prefixed(hasher, value)?;
            }
        }
    }
    Ok(())
}

fn end_manifest_section(hasher: &mut blake3::Hasher, count: i64) {
    hasher.update(&[0x5a]);
    hasher.update(&count.to_le_bytes());
}

fn optional_text(value: Option<&str>) -> ManifestValue<'_> {
    value.map_or(ManifestValue::Null, ManifestValue::Text)
}

fn optional_integer(value: Option<i64>) -> ManifestValue<'static> {
    value.map_or(ManifestValue::Null, ManifestValue::Integer)
}

fn optional_blob(value: Option<&[u8]>) -> ManifestValue<'_> {
    value.map_or(ManifestValue::Null, ManifestValue::Blob)
}

/// Computes the exact expected digest for a complete typed metadata report.
/// The same row/column stream is recomputed from SQLite at seal and reopen.
pub fn compute_metadata_report_manifest(
    plan: &MetadataReportManifestPlan,
    fields: &[MetadataFieldInput],
    issues: &[MetadataExtractionIssueInput],
    revalidation: &MetadataSourceRevalidationInput,
) -> Result<TimeEvidenceManifestDigest> {
    let input = &plan.begin;
    validate_metadata_report_input(input)?;
    if fields.len() as i64 != input.expected_field_count
        || issues.len() as i64 != input.expected_issue_count
    {
        return Err(StoreError::invalid_input(
            "metadata_report_manifest",
            "typed field or issue count differs from the frozen report header",
        ));
    }
    let mut sorted_fields = fields.iter().collect::<Vec<_>>();
    sorted_fields.sort_unstable_by_key(|field| field.ordinal);
    if sorted_fields
        .windows(2)
        .any(|pair| pair[0].ordinal == pair[1].ordinal)
    {
        return Err(StoreError::invalid_input(
            "metadata_field_ordinal",
            "field ordinals must be unique",
        ));
    }
    let mut retained_bytes = 0_i64;
    for field in &sorted_fields {
        validate_metadata_field_input(field)?;
        retained_bytes = retained_bytes
            .checked_add(field.locator.byte_len)
            .ok_or_else(|| {
                StoreError::invalid_input("expected_retained_field_bytes", "byte sum overflow")
            })?;
    }
    if retained_bytes != input.expected_retained_field_bytes {
        return Err(StoreError::invalid_input(
            "expected_retained_field_bytes",
            "retained field byte sum differs from the frozen report header",
        ));
    }
    let mut sorted_issues = issues.iter().collect::<Vec<_>>();
    sorted_issues.sort_unstable_by_key(|issue| issue.ordinal);
    if sorted_issues
        .windows(2)
        .any(|pair| pair[0].ordinal == pair[1].ordinal)
    {
        return Err(StoreError::invalid_input(
            "metadata_issue_ordinal",
            "issue ordinals must be unique",
        ));
    }
    if revalidation.source_signature_before != revalidation.source_signature_after
        || revalidation.first_report_digest != revalidation.second_report_digest
        || revalidation.first_report_digest != input.retained_report_digest
    {
        return Err(StoreError::invalid_input(
            "metadata_revalidation",
            "typed revalidation does not reproduce the pinned report",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.metadata-report-manifest.v1\0");
    begin_manifest_section(&mut hasher, b"header")?;
    let detected_format = input.detected_format.map(|value| value.as_storage_str());
    hash_manifest_row(
        &mut hasher,
        &[
            ManifestValue::Integer(input.time_session_id),
            ManifestValue::Integer(plan.scan_run_id),
            ManifestValue::Blob(plan.core_session_id.as_bytes()),
            ManifestValue::Integer(input.exact_group_build_id),
            ManifestValue::Integer(input.metadata_probe_observation_id),
            ManifestValue::Integer(input.metadata_probe_fingerprint_id),
            ManifestValue::Integer(input.probe_ordinal),
            ManifestValue::Integer(input.source_size_bytes),
            ManifestValue::Text(&input.parser.name),
            ManifestValue::Text(&input.parser.version),
            optional_text(detected_format),
            ManifestValue::Text(input.extraction_status.as_storage_str()),
            ManifestValue::Integer(input.limits.total_bytes_read),
            ManifestValue::Integer(input.limits.read_operations),
            ManifestValue::Integer(input.limits.retained_field_bytes),
            ManifestValue::Integer(input.limits.field_bytes),
            ManifestValue::Integer(input.limits.fields),
            ManifestValue::Integer(input.limits.jpeg_segments),
            ManifestValue::Integer(input.limits.ifd_entries),
            ManifestValue::Integer(input.limits.ifd_depth),
            ManifestValue::Integer(input.limits.bmff_boxes),
            ManifestValue::Integer(input.limits.bmff_depth),
            ManifestValue::Integer(input.usage.bytes_read),
            ManifestValue::Integer(input.usage.read_operations),
            ManifestValue::Integer(input.usage.retained_field_bytes),
            ManifestValue::Integer(input.usage.fields_emitted),
            ManifestValue::Integer(input.usage.jpeg_segments_visited),
            ManifestValue::Integer(input.usage.ifd_entries_visited),
            ManifestValue::Integer(input.usage.bmff_boxes_visited),
            ManifestValue::Integer(input.usage.max_depth_observed),
            ManifestValue::Integer(input.expected_field_count),
            ManifestValue::Integer(input.expected_issue_count),
            ManifestValue::Integer(input.expected_retained_field_bytes),
            ManifestValue::Blob(input.retained_report_digest.as_bytes()),
            ManifestValue::Integer(input.created_at_ms),
        ],
    )?;
    end_manifest_section(&mut hasher, 1);
    begin_manifest_section(&mut hasher, b"fields")?;
    for field in sorted_fields {
        let locator = StoredLocatorColumns::from(&field.locator.container);
        hash_manifest_row(
            &mut hasher,
            &[
                ManifestValue::Integer(field.ordinal),
                ManifestValue::Text(&field.parser.name),
                ManifestValue::Text(&field.parser.version),
                ManifestValue::Text(field.field_kind.as_storage_str()),
                ManifestValue::Text(field.encoding.as_storage_str()),
                ManifestValue::Integer(field.locator.absolute_offset),
                ManifestValue::Integer(field.locator.byte_len),
                ManifestValue::Blob(&field.raw_bytes),
                ManifestValue::Blob(field.raw_digest.as_bytes()),
                ManifestValue::Text(locator.kind),
                optional_integer(locator.tiff_header_offset),
                optional_integer(locator.tiff_ifd_offset),
                optional_integer(locator.tiff_tag),
                optional_text(locator.tiff_byte_order),
                optional_integer(locator.jpeg_app1_offset),
                optional_integer(locator.bmff_box_offset),
                optional_blob(locator.bmff_box_path),
                ManifestValue::Integer(field.created_at_ms),
            ],
        )?;
    }
    end_manifest_section(&mut hasher, input.expected_field_count);
    begin_manifest_section(&mut hasher, b"issues")?;
    for issue in sorted_issues {
        hash_manifest_row(
            &mut hasher,
            &[
                ManifestValue::Integer(issue.ordinal),
                ManifestValue::Text(&issue.parser.name),
                ManifestValue::Text(&issue.parser.version),
                ManifestValue::Text(issue.issue_code.as_storage_str()),
                optional_integer(issue.source_offset),
                ManifestValue::Text(&issue.context),
                ManifestValue::Integer(issue.created_at_ms),
            ],
        )?;
    }
    end_manifest_section(&mut hasher, input.expected_issue_count);
    begin_manifest_section(&mut hasher, b"revalidation")?;
    hash_manifest_row(
        &mut hasher,
        &[
            ManifestValue::Integer(input.time_session_id),
            ManifestValue::Integer(plan.scan_run_id),
            ManifestValue::Blob(plan.core_session_id.as_bytes()),
            ManifestValue::Integer(input.exact_group_build_id),
            ManifestValue::Integer(input.metadata_probe_observation_id),
            ManifestValue::Blob(revalidation.source_key.as_bytes()),
            ManifestValue::Integer(2),
            ManifestValue::Blob(revalidation.lineage_key.as_bytes()),
            ManifestValue::Integer(1),
            ManifestValue::Blob(revalidation.source_signature_before.as_bytes()),
            ManifestValue::Blob(revalidation.source_signature_after.as_bytes()),
            ManifestValue::Blob(revalidation.first_report_digest.as_bytes()),
            ManifestValue::Blob(revalidation.second_report_digest.as_bytes()),
            ManifestValue::Text("reextracted_pinned_exact"),
            ManifestValue::Integer(1),
            ManifestValue::Integer(1),
            ManifestValue::Integer(1),
            ManifestValue::Text("historical_proof_only"),
            ManifestValue::Integer(revalidation.revalidated_at_ms),
        ],
    )?;
    end_manifest_section(&mut hasher, 1);
    Ok(TimeEvidenceManifestDigest::from_runtime_evidence(
        *hasher.finalize().as_bytes(),
    ))
}

/// Computes the complete expected analysis digest from typed, bounded rows.
/// Candidate/member references use stable ordinals rather than SQLite ids.
#[allow(clippy::too_many_arguments)]
pub fn compute_capture_time_analysis_manifest(
    plan: &CaptureTimeAnalysisManifestPlan,
    sources: &[CaptureTimeAnalysisSourceInput],
    observations: &[CaptureTimeObservationInput],
    candidates: &[CaptureTimeCandidateInput],
    issues: &[CaptureTimePolicyIssueInput],
    members: &[CaptureTimeMemberAssessmentInput],
    recommendation: &CaptureTimeRecommendationInput,
) -> Result<TimeEvidenceManifestDigest> {
    let input = &plan.begin;
    if sources.len() as i64 != input.expected_source_count
        || observations.len() as i64 != input.expected_observation_count
        || candidates.len() as i64 != input.expected_candidate_count
        || issues.len() as i64 != input.expected_issue_count
        || members.len() as i64 != input.expected_member_count
        || input.expected_recommendation_count != 1
    {
        return Err(StoreError::invalid_input(
            "capture_time_analysis_manifest",
            "typed evidence counts differ from the frozen analysis header",
        ));
    }
    if recommendation.keeper_observation_id.is_some()
        || recommendation.time_donor_observation_id.is_some()
        || recommendation.candidate_id.is_some()
        || recommendation.keeper_policy_name.is_some()
        || recommendation.keeper_policy_version.is_some()
        || recommendation.time_donor_policy_name.is_some()
        || recommendation.time_donor_policy_version.is_some()
    {
        return Err(StoreError::invalid_input(
            "capture_time_recommendation",
            "manifest builder cannot encode an unimplemented keeper policy",
        ));
    }
    let mut sorted_sources = sources.iter().collect::<Vec<_>>();
    sorted_sources.sort_unstable_by_key(|source| source.ordinal);
    let mut sorted_observations = observations.iter().collect::<Vec<_>>();
    sorted_observations.sort_unstable_by_key(|observation| observation.ordinal);
    let mut sorted_candidates = candidates.iter().collect::<Vec<_>>();
    sorted_candidates.sort_unstable_by_key(|candidate| candidate.ordinal);
    let mut sorted_issues = issues.iter().collect::<Vec<_>>();
    sorted_issues.sort_unstable_by_key(|issue| issue.ordinal);
    let mut sorted_members = members.iter().collect::<Vec<_>>();
    sorted_members.sort_unstable_by_key(|member| member.member_ordinal);
    for (field, has_duplicate) in [
        (
            "capture_time_source_ordinal",
            sorted_sources
                .windows(2)
                .any(|pair| pair[0].ordinal == pair[1].ordinal),
        ),
        (
            "capture_time_observation_ordinal",
            sorted_observations
                .windows(2)
                .any(|pair| pair[0].ordinal == pair[1].ordinal),
        ),
        (
            "capture_time_candidate_ordinal",
            sorted_candidates
                .windows(2)
                .any(|pair| pair[0].ordinal == pair[1].ordinal),
        ),
        (
            "capture_time_issue_ordinal",
            sorted_issues
                .windows(2)
                .any(|pair| pair[0].ordinal == pair[1].ordinal),
        ),
        (
            "capture_time_member_ordinal",
            sorted_members
                .windows(2)
                .any(|pair| pair[0].member_ordinal == pair[1].member_ordinal),
        ),
    ] {
        if has_duplicate {
            return Err(StoreError::invalid_input(field, "ordinals must be unique"));
        }
    }
    let policy_context_json = serialize_canonical_json(&input.policy_context_json)?;
    let mut retained_json_bytes = i64::try_from(policy_context_json.len()).map_err(|_| {
        StoreError::invalid_input(
            "capture_time_analysis_budget",
            "policy JSON length does not fit the evidence counter",
        )
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.capture-time-analysis-manifest.v1\0");
    begin_manifest_section(&mut hasher, b"header")?;
    hash_manifest_row(
        &mut hasher,
        &[
            ManifestValue::Integer(input.time_session_id),
            ManifestValue::Integer(plan.scan_run_id),
            ManifestValue::Integer(input.exact_group_build_id),
            ManifestValue::Text(&input.policy_name),
            ManifestValue::Text(&input.policy_version),
            ManifestValue::Text(&policy_context_json),
            ManifestValue::Blob(input.policy_context_digest.as_bytes()),
            ManifestValue::Integer(input.expected_source_count),
            ManifestValue::Integer(input.expected_observation_count),
            ManifestValue::Integer(input.expected_candidate_count),
            ManifestValue::Integer(input.expected_issue_count),
            ManifestValue::Integer(input.expected_member_count),
            ManifestValue::Integer(input.expected_recommendation_count),
            ManifestValue::Integer(input.created_at_ms),
        ],
    )?;
    end_manifest_section(&mut hasher, 1);

    begin_manifest_section(&mut hasher, b"sources")?;
    for source in sorted_sources {
        hash_manifest_row(
            &mut hasher,
            &[
                ManifestValue::Integer(source.ordinal),
                ManifestValue::Integer(source.report_id),
                ManifestValue::Blob(source.source_key.as_bytes()),
                ManifestValue::Blob(source.lineage_key.as_bytes()),
                ManifestValue::Text("reextracted_pinned_source"),
                ManifestValue::Integer(source.created_at_ms),
            ],
        )?;
    }
    end_manifest_section(&mut hasher, input.expected_source_count);

    begin_manifest_section(&mut hasher, b"observations")?;
    for observation in sorted_observations {
        let columns = StoredInterpretationColumns::from(&observation.interpretation);
        let report_id = sources
            .iter()
            .find(|source| source.ordinal == observation.source_ordinal)
            .map(|source| source.report_id)
            .ok_or_else(|| {
                StoreError::invalid_input(
                    "capture_time_observation_source",
                    "observation references a missing source ordinal",
                )
            })?;
        hash_manifest_row(
            &mut hasher,
            &[
                ManifestValue::Integer(observation.ordinal),
                ManifestValue::Integer(observation.source_ordinal),
                ManifestValue::Integer(report_id),
                ManifestValue::Integer(observation.metadata_field_id),
                ManifestValue::Text(columns.kind),
                optional_integer(columns.wall_year),
                optional_integer(columns.wall_month),
                optional_integer(columns.wall_day),
                optional_integer(columns.wall_hour),
                optional_integer(columns.wall_minute),
                optional_integer(columns.wall_second),
                optional_integer(columns.wall_nanosecond),
                optional_text(columns.semantic_kind),
                optional_text(columns.offset_kind),
                optional_integer(columns.utc_offset_minutes),
                optional_text(columns.utc_seconds_decimal),
                optional_integer(columns.utc_nanoseconds),
                optional_integer(columns.normalized_precision_ns),
                optional_integer(columns.parsed_offset_minutes),
                optional_integer(columns.subsecond_nanosecond),
                optional_integer(columns.subsecond_digits),
                optional_integer(columns.subsecond_precision_ns),
                optional_text(columns.rejection_code),
                ManifestValue::Integer(observation.created_at_ms),
            ],
        )?;
    }
    end_manifest_section(&mut hasher, input.expected_observation_count);

    begin_manifest_section(&mut hasher, b"candidates")?;
    for candidate in sorted_candidates {
        validate_candidate_references_in_memory(sources, observations, candidate)?;
        let evidence_kinds_json = serde_json::to_string(
            &candidate
                .evidence_kinds
                .iter()
                .map(|value| value.as_storage_str())
                .collect::<Vec<_>>(),
        )?;
        let source_keys_json = serde_json::to_string(
            &candidate
                .source_keys
                .iter()
                .map(|value| lower_hex(value.as_bytes()))
                .collect::<Vec<_>>(),
        )?;
        let lineage_keys_json = serde_json::to_string(
            &candidate
                .lineage_keys
                .iter()
                .map(|value| lower_hex(value.as_bytes()))
                .collect::<Vec<_>>(),
        )?;
        let observation_ordinals_json = serde_json::to_string(&candidate.observation_ordinals)?;
        let anomalies_json = serde_json::to_string(
            &candidate
                .anomalies
                .iter()
                .map(|value| value.as_storage_str())
                .collect::<Vec<_>>(),
        )?;
        let blockers_json = serde_json::to_string(
            &candidate
                .evidence_gate
                .blockers()
                .iter()
                .map(|value| value.as_storage_str())
                .collect::<Vec<_>>(),
        )?;
        for value in [
            evidence_kinds_json.as_str(),
            source_keys_json.as_str(),
            lineage_keys_json.as_str(),
            observation_ordinals_json.as_str(),
            anomalies_json.as_str(),
            blockers_json.as_str(),
        ] {
            retained_json_bytes = retained_json_bytes
                .checked_add(i64::try_from(value.len()).map_err(|_| {
                    StoreError::invalid_input(
                        "capture_time_analysis_budget",
                        "candidate JSON length does not fit the evidence counter",
                    )
                })?)
                .ok_or_else(|| {
                    StoreError::invalid_input(
                        "capture_time_analysis_budget",
                        "retained JSON byte sum overflow",
                    )
                })?;
        }
        let wall = candidate.timestamp.wall_time();
        hash_manifest_row(
            &mut hasher,
            &[
                ManifestValue::Integer(candidate.ordinal),
                ManifestValue::Integer(i64::from(wall.year())),
                ManifestValue::Integer(i64::from(wall.month())),
                ManifestValue::Integer(i64::from(wall.day())),
                ManifestValue::Integer(i64::from(wall.hour())),
                ManifestValue::Integer(i64::from(wall.minute())),
                ManifestValue::Integer(i64::from(wall.second())),
                ManifestValue::Integer(i64::from(wall.nanosecond())),
                ManifestValue::Text(candidate.timestamp.semantic_kind().as_storage_str()),
                ManifestValue::Text(candidate.timestamp.offset_kind().as_storage_str()),
                optional_integer(candidate.timestamp.utc_offset_minutes().map(i64::from)),
                optional_text(candidate.timestamp.utc_seconds_decimal()),
                optional_integer(candidate.timestamp.utc_nanoseconds().map(i64::from)),
                ManifestValue::Integer(i64::from(candidate.timestamp.precision_ns())),
                ManifestValue::Text(candidate.confidence.as_storage_str()),
                ManifestValue::Text(candidate.evidence_gate.as_storage_str()),
                ManifestValue::Text(&evidence_kinds_json),
                ManifestValue::Text(&source_keys_json),
                ManifestValue::Text(&lineage_keys_json),
                ManifestValue::Text(&observation_ordinals_json),
                ManifestValue::Text(&anomalies_json),
                ManifestValue::Text(&blockers_json),
                ManifestValue::Integer(candidate.created_at_ms),
            ],
        )?;
    }
    end_manifest_section(&mut hasher, input.expected_candidate_count);

    begin_manifest_section(&mut hasher, b"policy-issues")?;
    for issue in sorted_issues {
        validate_policy_issue_references_in_memory(sources, observations, issue)?;
        let observation_ordinals_json = serde_json::to_string(&issue.observation_ordinals)?;
        let source_keys_json = serde_json::to_string(
            &issue
                .source_keys
                .iter()
                .map(|value| lower_hex(value.as_bytes()))
                .collect::<Vec<_>>(),
        )?;
        let lineage_keys_json = serde_json::to_string(
            &issue
                .lineage_keys
                .iter()
                .map(|value| lower_hex(value.as_bytes()))
                .collect::<Vec<_>>(),
        )?;
        for value in [
            observation_ordinals_json.as_str(),
            source_keys_json.as_str(),
            lineage_keys_json.as_str(),
            issue.context.as_str(),
        ] {
            retained_json_bytes = retained_json_bytes
                .checked_add(i64::try_from(value.len()).map_err(|_| {
                    StoreError::invalid_input(
                        "capture_time_analysis_budget",
                        "policy issue text length does not fit the evidence counter",
                    )
                })?)
                .ok_or_else(|| {
                    StoreError::invalid_input(
                        "capture_time_analysis_budget",
                        "retained JSON/text byte sum overflow",
                    )
                })?;
        }
        hash_manifest_row(
            &mut hasher,
            &[
                ManifestValue::Integer(issue.ordinal),
                ManifestValue::Text(&issue.code),
                optional_text(issue.field_kind.map(|value| value.as_storage_str())),
                ManifestValue::Text(&observation_ordinals_json),
                ManifestValue::Text(&source_keys_json),
                ManifestValue::Text(&lineage_keys_json),
                ManifestValue::Text(&issue.context),
                ManifestValue::Integer(issue.created_at_ms),
            ],
        )?;
    }
    end_manifest_section(&mut hasher, input.expected_issue_count);
    if retained_json_bytes > MAX_TIME_EVIDENCE_PAGE_BYTES {
        return Err(StoreError::invalid_input(
            "capture_time_analysis_budget",
            "retained policy/candidate/issue JSON and text exceed 16 MiB",
        ));
    }

    begin_manifest_section(&mut hasher, b"members")?;
    for member in sorted_members {
        if member.candidate_ordinal.is_some_and(|ordinal| {
            !candidates
                .iter()
                .any(|candidate| candidate.ordinal == ordinal)
        }) {
            return Err(StoreError::invalid_input(
                "member_candidate_ordinal",
                "member references a candidate outside its analysis",
            ));
        }
        hash_manifest_row(
            &mut hasher,
            &[
                ManifestValue::Integer(member.member_ordinal),
                ManifestValue::Integer(member.media_observation_snapshot_id),
                optional_integer(member.candidate_ordinal),
                ManifestValue::Text(member.birth_time_relation.as_storage_str()),
                ManifestValue::Text(member.modified_time_relation.as_storage_str()),
                ManifestValue::Text(member.donor_eligibility.as_storage_str()),
                ManifestValue::Text(&member.reason_code),
                ManifestValue::Integer(member.created_at_ms),
            ],
        )?;
    }
    end_manifest_section(&mut hasher, input.expected_member_count);

    begin_manifest_section(&mut hasher, b"recommendation")?;
    hash_manifest_row(
        &mut hasher,
        &[
            ManifestValue::Null,
            ManifestValue::Null,
            ManifestValue::Null,
            ManifestValue::Null,
            ManifestValue::Null,
            ManifestValue::Null,
            ManifestValue::Null,
            ManifestValue::Integer(1),
            ManifestValue::Integer(0),
            ManifestValue::Text(&recommendation.reason_code),
            ManifestValue::Integer(recommendation.created_at_ms),
        ],
    )?;
    end_manifest_section(&mut hasher, 1);
    Ok(TimeEvidenceManifestDigest::from_runtime_evidence(
        *hasher.finalize().as_bytes(),
    ))
}

fn validate_candidate_references_in_memory(
    sources: &[CaptureTimeAnalysisSourceInput],
    observations: &[CaptureTimeObservationInput],
    candidate: &CaptureTimeCandidateInput,
) -> Result<()> {
    let mut derived_sources = Vec::with_capacity(candidate.observation_ordinals.len());
    let mut derived_lineages = Vec::with_capacity(candidate.observation_ordinals.len());
    for ordinal in &candidate.observation_ordinals {
        let observation = observations
            .iter()
            .find(|observation| observation.ordinal == *ordinal)
            .ok_or_else(|| {
                StoreError::invalid_input(
                    "capture_time_candidate_support",
                    "candidate references an observation outside its analysis manifest",
                )
            })?;
        let source = sources
            .iter()
            .find(|source| source.ordinal == observation.source_ordinal)
            .ok_or_else(|| {
                StoreError::invalid_input(
                    "capture_time_candidate_support",
                    "candidate observation references a missing analysis source",
                )
            })?;
        derived_sources.push(*source.source_key.as_bytes());
        derived_lineages.push(*source.lineage_key.as_bytes());
    }
    sort_dedup(&mut derived_sources);
    sort_dedup(&mut derived_lineages);
    let mut declared_sources = candidate
        .source_keys
        .iter()
        .map(|key| *key.as_bytes())
        .collect::<Vec<_>>();
    let mut declared_lineages = candidate
        .lineage_keys
        .iter()
        .map(|key| *key.as_bytes())
        .collect::<Vec<_>>();
    sort_dedup(&mut declared_sources);
    sort_dedup(&mut declared_lineages);
    if derived_sources != declared_sources || derived_lineages != declared_lineages {
        return Err(StoreError::invalid_input(
            "capture_time_candidate_support",
            "candidate source and lineage declarations do not exactly match its observations",
        ));
    }
    Ok(())
}

fn validate_policy_issue_references_in_memory(
    sources: &[CaptureTimeAnalysisSourceInput],
    observations: &[CaptureTimeObservationInput],
    issue: &CaptureTimePolicyIssueInput,
) -> Result<()> {
    if issue
        .source_keys
        .iter()
        .any(|key| !sources.iter().any(|source| source.source_key == *key))
        || issue
            .lineage_keys
            .iter()
            .any(|key| !sources.iter().any(|source| source.lineage_key == *key))
        || issue.observation_ordinals.iter().any(|ordinal| {
            !observations
                .iter()
                .any(|observation| observation.ordinal == *ordinal)
        })
    {
        return Err(StoreError::invalid_input(
            "capture_time_policy_issue",
            "policy issue references evidence outside its analysis manifest",
        ));
    }
    Ok(())
}

fn hash_unchecked_length_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Encodes JSON without relying on `serde_json::Map`'s feature-selected
/// iteration order. Type tags and fixed-width length domains keep adjacent
/// values unambiguous; object keys are ordered by their UTF-8 bytes.
pub(crate) fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
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

#[allow(dead_code)]
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
