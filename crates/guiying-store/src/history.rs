use std::path::Path;

use rusqlite::OptionalExtension;

use crate::error::{Result, StoreError};
use crate::model::{
    CaptureTimeCandidateCursor, CaptureTimeCandidateRecord, CaptureTimeGroupSummaryRecord,
    CaptureTimeIssueCursor, CaptureTimeIssueRecord, CaptureTimeMemberCursor,
    CaptureTimeMemberRecord, CaptureTimeMetadataFieldRawDetail, CaptureTimeMetadataFieldRecord,
    CaptureTimeMetadataReportRecord, CaptureTimeSummaryCursor, DuplicateGroupCursor,
    DuplicateGroupMemberCursor, DuplicateGroupMemberRecord, EvidenceDatabaseScope, KeysetPage,
    MetadataFieldCursor, MetadataReportCursor, ScanHistoryContext, ScanHistoryCursor,
    ScanHistoryGroupContext, ScanHistoryRecord, ScanHistoryTimeOutcomeRecord, ScanIssueCursor,
    ScanIssueRecord, VerifiedExactGroup,
};
use crate::store::{
    enforce_read_budget, keyset_page_from_items, validate_positive_read_id, Store,
    MAX_PAGE_RESULT_BYTES,
};

const HISTORY_CURSOR_VERSION: i64 = 1;
const MAX_HISTORY_PAGE_SIZE: u32 = 64;

const HISTORY_ELIGIBLE_CTE: &str = "\
WITH eligible AS ( \
    SELECT run.id AS scan_run_id, run.root_relative_path, run.scan_mode, \
           run.started_at_ms, run.finished_at_ms, run.discovered_count, \
           run.fingerprinted_count, run.error_count, run.logical_bytes_seen, \
           coverage.status AS coverage_status, \
           CASE WHEN session.state IN ('complete', 'partial') THEN session.id END \
               AS time_session_id, \
           CASE \
               WHEN session.state IN ('complete', 'partial') THEN session.state \
               WHEN session.state = 'abandoned' THEN 'failed' \
               WHEN session.state = 'draft' THEN 'unavailable' \
               ELSE 'not_run' \
           END AS time_session_state, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.expected_group_count END AS expected_group_count, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.evidence_group_count END AS evidence_group_count, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.unavailable_group_count END AS unavailable_group_count, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.failed_group_count END AS failed_group_count, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.max_total_read_bytes END AS max_total_read_bytes, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.max_probe_count_per_group END AS max_probe_count_per_group, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.max_report_total_bytes_read END AS max_report_total_bytes_read, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.max_report_read_operations END AS max_report_read_operations, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.max_report_retained_field_bytes END \
               AS max_report_retained_field_bytes, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.max_report_fields END AS max_report_fields, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.max_report_issues END AS max_report_issues, \
           CASE WHEN session.state IN ('complete', 'partial') \
                THEN session.finalized_at_ms END AS finalized_at_ms \
    FROM scan_runs AS run \
    JOIN scan_job_runs AS job_run ON job_run.scan_run_id = run.id \
                                AND job_run.volume_id = run.volume_id \
    JOIN scan_jobs AS job ON job.id = job_run.scan_job_id \
                         AND job.volume_id = job_run.volume_id \
                         AND job.active_scan_run_id = run.id \
                         AND job.state = 'completed' \
    JOIN scan_stage_seals AS exact_seal ON exact_seal.scan_run_id = run.id \
                                        AND exact_seal.volume_id = run.volume_id \
                                        AND exact_seal.stage = 'exact_verification' \
    JOIN scan_coverage_outcomes AS coverage ON coverage.scan_run_id = run.id \
                                            AND coverage.volume_id = run.volume_id \
                                            AND coverage.status IN ('complete', 'partial') \
    LEFT JOIN scan_time_sessions AS session ON session.scan_run_id = run.id \
                                            AND session.volume_id = run.volume_id \
    WHERE run.state = 'completed' \
      AND run.started_at_ms IS NOT NULL \
      AND run.finished_at_ms IS NOT NULL \
      AND (?1 IS NULL OR run.finished_at_ms < ?1 \
           OR (run.finished_at_ms = ?1 AND run.id < ?2)) \
      AND (?4 IS NULL OR run.id = ?4) \
    ORDER BY run.finished_at_ms DESC, run.id DESC \
    LIMIT ?3 \
), \
exact_totals AS ( \
    SELECT build.scan_run_id, count(*) AS verified_group_count, \
           COALESCE(sum(build.expected_member_count), 0) AS verified_member_count, \
           COALESCE(sum(CASE WHEN build.independent_file_count > 1 \
                             THEN build.independent_file_count - 1 ELSE 0 END), 0) \
               AS redundant_copy_count, \
           COALESCE(sum(build.logical_reclaimable_bytes), 0) AS logical_reclaimable_bytes \
    FROM exact_group_builds AS build \
    JOIN eligible ON eligible.scan_run_id = build.scan_run_id \
    WHERE build.state = 'verified' \
    GROUP BY build.scan_run_id \
), \
observation_totals AS ( \
    SELECT observation.scan_run_id, count(*) AS observed_file_count \
    FROM media_observation_snapshots AS observation \
    JOIN eligible ON eligible.scan_run_id = observation.scan_run_id \
    GROUP BY observation.scan_run_id \
), \
issue_totals AS ( \
    SELECT issue.scan_run_id, count(*) AS issue_count, \
           sum(CASE WHEN issue.resolved_at_ms IS NULL THEN 1 ELSE 0 END) \
               AS unresolved_issue_count \
    FROM scan_issues AS issue \
    JOIN eligible ON eligible.scan_run_id = issue.scan_run_id \
    GROUP BY issue.scan_run_id \
), \
sealed_report_totals AS ( \
    SELECT report.time_session_id, \
           COALESCE(sum(report.usage_bytes_read * 2), 0) AS sealed_report_read_bytes, \
           COALESCE(sum(report.usage_read_operations * 2), 0) \
               AS sealed_report_read_operations \
    FROM metadata_extraction_reports AS report \
    JOIN eligible ON eligible.time_session_id = report.time_session_id \
    WHERE report.state = 'sealed' \
    GROUP BY report.time_session_id \
) ";

fn history_record_select_sql() -> String {
    format!(
        "{HISTORY_ELIGIBLE_CTE} \
         SELECT eligible.scan_run_id, eligible.root_relative_path, eligible.scan_mode, \
                eligible.started_at_ms, eligible.finished_at_ms, \
                eligible.coverage_status, eligible.discovered_count, \
                eligible.fingerprinted_count, eligible.error_count, \
                eligible.logical_bytes_seen, \
                COALESCE(observation_totals.observed_file_count, 0), \
                COALESCE(exact_totals.verified_group_count, 0), \
                COALESCE(exact_totals.verified_member_count, 0), \
                COALESCE(exact_totals.redundant_copy_count, 0), \
                COALESCE(exact_totals.logical_reclaimable_bytes, 0), \
                COALESCE(issue_totals.issue_count, 0), \
                COALESCE(issue_totals.unresolved_issue_count, 0), \
                eligible.time_session_state, eligible.expected_group_count, \
                eligible.evidence_group_count, eligible.unavailable_group_count, \
                eligible.failed_group_count, eligible.max_total_read_bytes, \
                eligible.max_probe_count_per_group, \
                eligible.max_report_total_bytes_read, \
                eligible.max_report_read_operations, \
                eligible.max_report_retained_field_bytes, \
                eligible.max_report_fields, eligible.max_report_issues, \
                CASE WHEN eligible.time_session_id IS NOT NULL THEN \
                    COALESCE(sealed_report_totals.sealed_report_read_bytes, 0) END, \
                CASE WHEN eligible.time_session_id IS NOT NULL THEN \
                    COALESCE(sealed_report_totals.sealed_report_read_operations, 0) END, \
                eligible.finalized_at_ms \
         FROM eligible \
         LEFT JOIN exact_totals ON exact_totals.scan_run_id = eligible.scan_run_id \
         LEFT JOIN observation_totals \
           ON observation_totals.scan_run_id = eligible.scan_run_id \
         LEFT JOIN issue_totals ON issue_totals.scan_run_id = eligible.scan_run_id \
         LEFT JOIN sealed_report_totals \
           ON sealed_report_totals.time_session_id = eligible.time_session_id \
         ORDER BY eligible.finished_at_ms DESC, eligible.scan_run_id DESC"
    )
}

fn scan_history_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanHistoryRecord> {
    let started_at_ms = row.get::<_, i64>(3)?;
    let finished_at_ms = row.get::<_, i64>(4)?;
    let duration_ms = finished_at_ms.checked_sub(started_at_ms).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Integer,
            "history finish precedes start".into(),
        )
    })?;
    Ok(ScanHistoryRecord {
        scan_run_id: row.get(0)?,
        root_display_path: row.get(1)?,
        scan_mode: row.get(2)?,
        started_at_ms,
        finished_at_ms,
        duration_ms,
        coverage_status: row.get(5)?,
        discovered_count: row.get(6)?,
        fingerprinted_count: row.get(7)?,
        error_count: row.get(8)?,
        logical_bytes_seen: row.get(9)?,
        observed_file_count: row.get(10)?,
        verified_group_count: row.get(11)?,
        verified_member_count: row.get(12)?,
        redundant_copy_count: row.get(13)?,
        logical_reclaimable_bytes: row.get(14)?,
        issue_count: row.get(15)?,
        unresolved_issue_count: row.get(16)?,
        time_outcome: ScanHistoryTimeOutcomeRecord {
            state: row.get(17)?,
            expected_group_count: row.get(18)?,
            evidence_group_count: row.get(19)?,
            unavailable_group_count: row.get(20)?,
            failed_group_count: row.get(21)?,
            max_total_read_bytes: row.get(22)?,
            max_probe_count_per_group: row.get(23)?,
            max_report_total_bytes_read: row.get(24)?,
            max_report_read_operations: row.get(25)?,
            max_report_retained_field_bytes: row.get(26)?,
            max_report_fields: row.get(27)?,
            max_report_issues: row.get(28)?,
            sealed_report_read_bytes: row.get(29)?,
            sealed_report_read_operations: row.get(30)?,
            finalized_at_ms: row.get(31)?,
        },
    })
}

/// A strictly read-only view over immutable, completed v7 scan evidence.
///
/// The wrapped writable `Store` type is never exposed. It is used only as a
/// private query facade so history reads share the already-audited group,
/// member, issue, capture-time, metadata, and raw-detail SQL implementations.
pub struct EvidenceReader {
    store: Store,
    database_scope: EvidenceDatabaseScope,
    reader_instance_key: [u8; 32],
}

impl EvidenceReader {
    /// Opens an existing v7 database without migration or reconciliation.
    pub fn open_existing_read_only(path: impl AsRef<Path>) -> Result<Self> {
        let store = Store::open_evidence_read_only(path.as_ref())?;
        let database_scope = EvidenceDatabaseScope::new(store.evidence_database_scope_digest());
        let reader_instance_key = store.evidence_reader_instance_key();
        Ok(Self {
            store,
            database_scope,
            reader_instance_key,
        })
    }

    #[must_use]
    pub fn database_path(&self) -> &Path {
        self.store.database_path()
    }

    #[must_use]
    pub const fn database_scope(&self) -> EvidenceDatabaseScope {
        self.database_scope
    }

    /// Rechecks the canonical source identity and current sidecar safety.
    ///
    /// This is intentionally cheap: it does not repeat schema, integrity, or
    /// evidence-manifest validation. A long-lived trusted result grant can
    /// call it before each command while reusing this already-validated reader.
    pub fn revalidate_source_identity(&self) -> Result<()> {
        self.store.verify_bound_database()
    }

    /// Lists completed jobs/runs with an exact-verification seal. Capture-time
    /// evidence is included only when its optional session is terminal.
    pub fn list_scan_history_page(
        &self,
        cursor: Option<&ScanHistoryCursor>,
        limit: u32,
    ) -> Result<KeysetPage<ScanHistoryRecord, ScanHistoryCursor>> {
        let (after_finished_at_ms, after_scan_run_id) = self.validate_history_cursor(cursor)?;
        let fetch_limit = validate_history_limit(limit)?;
        self.store.consistent_read(|connection| {
            let budget_sql = format!(
                "{HISTORY_ELIGIBLE_CTE} \
                 SELECT COALESCE(sum(4096 \
                     + length(CAST(root_relative_path AS BLOB)) \
                     + length(CAST(scan_mode AS BLOB)) \
                     + length(CAST(coverage_status AS BLOB)) \
                     + length(CAST(time_session_state AS BLOB))), 0) \
                 FROM eligible"
            );
            let page_bytes = connection.query_row(
                &budget_sql,
                rusqlite::params![
                    after_finished_at_ms,
                    after_scan_run_id,
                    fetch_limit,
                    Option::<i64>::None,
                ],
                |row| row.get::<_, i64>(0),
            )?;
            enforce_history_page_budget(page_bytes)?;

            let page_sql = history_record_select_sql();
            let mut statement = connection.prepare(&page_sql)?;
            let rows = statement.query_map(
                rusqlite::params![
                    after_finished_at_ms,
                    after_scan_run_id,
                    fetch_limit,
                    Option::<i64>::None,
                ],
                scan_history_record_from_row,
            )?;
            let items = rows
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(StoreError::from)?;
            keyset_page_from_items(items, limit, |record| ScanHistoryCursor {
                cursor_version: HISTORY_CURSOR_VERSION,
                database_scope_digest: self.database_scope.into_bytes(),
                last_finished_at_ms: record.finished_at_ms,
                last_scan_run_id: record.scan_run_id,
            })
        })
    }

    /// Resolves the display-safe summary for one catalog id without scanning
    /// or materializing unrelated history entries.
    pub fn get_scan_history_entry(&self, scan_run_id: i64) -> Result<Option<ScanHistoryRecord>> {
        validate_positive_read_id("scan_run_id", scan_run_id)?;
        self.store.consistent_read(|connection| {
            let budget_sql = format!(
                "{HISTORY_ELIGIBLE_CTE} \
                 SELECT COALESCE(sum(4096 \
                     + length(CAST(root_relative_path AS BLOB)) \
                     + length(CAST(scan_mode AS BLOB)) \
                     + length(CAST(coverage_status AS BLOB)) \
                     + length(CAST(time_session_state AS BLOB))), 0) \
                 FROM eligible"
            );
            let params =
                rusqlite::params![Option::<i64>::None, Option::<i64>::None, 1_i64, scan_run_id,];
            let bytes = connection.query_row(&budget_sql, params, |row| row.get::<_, i64>(0))?;
            enforce_history_page_budget(bytes)?;

            connection
                .query_row(
                    &history_record_select_sql(),
                    rusqlite::params![
                        Option::<i64>::None,
                        Option::<i64>::None,
                        1_i64,
                        scan_run_id,
                    ],
                    scan_history_record_from_row,
                )
                .optional()
                .map_err(StoreError::from)
        })
    }

    /// Resolves a visible catalog id to a process-local immutable read context.
    pub fn resolve_scan_history_entry(
        &self,
        scan_run_id: i64,
    ) -> Result<Option<ScanHistoryContext>> {
        validate_positive_read_id("scan_run_id", scan_run_id)?;
        self.store.consistent_read(|connection| {
            resolve_history_context_row(connection, scan_run_id)?.map_or(Ok(None), |row| {
                Ok(Some(ScanHistoryContext {
                    reader_instance_key: self.reader_instance_key,
                    database_scope: self.database_scope,
                    scan_job_id: row.0,
                    scan_run_id,
                    volume_id: row.1,
                    time_session_id: row.2,
                }))
            })
        })
    }

    /// Resolves any verified exact group in an eligible immutable scan.
    ///
    /// A partial terminal time session may not contain an outcome for every
    /// group. That never hides already sealed D1 duplicate evidence; it only
    /// prevents the capture-time methods from resolving an analysis context.
    pub fn resolve_scan_history_group(
        &self,
        context: &ScanHistoryContext,
        exact_group_build_id: i64,
    ) -> Result<Option<ScanHistoryGroupContext>> {
        validate_positive_read_id("exact_group_build_id", exact_group_build_id)?;
        self.store.consistent_read(|connection| {
            self.require_history_context(connection, context)?;
            connection
                .query_row(
                    "SELECT outcome.outcome, outcome.analysis_build_id \
                     FROM exact_group_builds AS build \
                     LEFT JOIN capture_time_group_outcomes AS outcome \
                       ON outcome.time_session_id = ?1 \
                      AND outcome.scan_run_id = build.scan_run_id \
                      AND outcome.volume_id = build.volume_id \
                      AND outcome.exact_group_build_id = build.id \
                     WHERE build.id = ?2 AND build.scan_run_id = ?3 \
                       AND build.volume_id = ?4 AND build.state = 'verified'",
                    rusqlite::params![
                        context.time_session_id,
                        exact_group_build_id,
                        context.scan_run_id,
                        context.volume_id,
                    ],
                    |row| {
                        Ok(ScanHistoryGroupContext {
                            history: context.clone(),
                            exact_group_build_id,
                            time_outcome: row.get(0)?,
                            analysis_build_id: row.get(1)?,
                        })
                    },
                )
                .optional()
                .map_err(StoreError::from)
        })
    }

    pub fn list_duplicate_groups_page(
        &self,
        context: &ScanHistoryContext,
        cursor: Option<&DuplicateGroupCursor>,
        limit: u32,
    ) -> Result<KeysetPage<VerifiedExactGroup, DuplicateGroupCursor>> {
        self.validate_history_context(context)?;
        self.store
            .list_duplicate_groups_page(context.scan_run_id, cursor, limit)
    }

    pub fn list_duplicate_group_members_page(
        &self,
        context: &ScanHistoryGroupContext,
        cursor: Option<&DuplicateGroupMemberCursor>,
        limit: u32,
    ) -> Result<KeysetPage<DuplicateGroupMemberRecord, DuplicateGroupMemberCursor>> {
        self.validate_history_group_context(context)?;
        self.store.list_duplicate_group_members_page(
            context.history.scan_run_id,
            context.exact_group_build_id,
            cursor,
            limit,
        )
    }

    pub fn list_scan_issues_page(
        &self,
        context: &ScanHistoryContext,
        cursor: Option<&ScanIssueCursor>,
        limit: u32,
    ) -> Result<KeysetPage<ScanIssueRecord, ScanIssueCursor>> {
        self.validate_history_context(context)?;
        self.store
            .list_scan_issues_page(context.scan_run_id, cursor, limit)
    }

    pub fn list_capture_time_group_summaries_page(
        &self,
        context: &ScanHistoryContext,
        cursor: Option<&CaptureTimeSummaryCursor>,
        limit: u32,
    ) -> Result<KeysetPage<CaptureTimeGroupSummaryRecord, CaptureTimeSummaryCursor>> {
        self.validate_history_context(context)?;
        self.require_terminal_time_session(context)?;
        self.store
            .list_capture_time_group_summaries_page(context.scan_run_id, cursor, limit)
    }

    pub fn get_capture_time_group_summary(
        &self,
        context: &ScanHistoryGroupContext,
    ) -> Result<Option<CaptureTimeGroupSummaryRecord>> {
        self.validate_history_group_context(context)?;
        let Some(analysis_build_id) = context.analysis_build_id else {
            return Ok(None);
        };
        if context.time_outcome.as_deref() != Some("evidence") {
            return Ok(None);
        }
        let record = self.store.get_capture_time_group_summary(
            context.history.scan_run_id,
            context.exact_group_build_id,
        )?;
        if record
            .as_ref()
            .is_some_and(|record| record.analysis_build_id != analysis_build_id)
        {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_history_time_analysis_context",
                id: context.exact_group_build_id,
            });
        }
        Ok(record)
    }

    pub fn list_capture_time_candidates_page(
        &self,
        context: &ScanHistoryGroupContext,
        cursor: Option<&CaptureTimeCandidateCursor>,
        limit: u32,
    ) -> Result<KeysetPage<CaptureTimeCandidateRecord, CaptureTimeCandidateCursor>> {
        let analysis_build_id = self.require_history_analysis_context(context)?;
        self.store.list_capture_time_candidates_page(
            context.history.scan_run_id,
            context.exact_group_build_id,
            analysis_build_id,
            cursor,
            limit,
        )
    }

    pub fn list_capture_time_members_page(
        &self,
        context: &ScanHistoryGroupContext,
        cursor: Option<&CaptureTimeMemberCursor>,
        limit: u32,
    ) -> Result<KeysetPage<CaptureTimeMemberRecord, CaptureTimeMemberCursor>> {
        let analysis_build_id = self.require_history_analysis_context(context)?;
        self.store.list_capture_time_members_page(
            context.history.scan_run_id,
            context.exact_group_build_id,
            analysis_build_id,
            cursor,
            limit,
        )
    }

    pub fn list_capture_time_issues_page(
        &self,
        context: &ScanHistoryGroupContext,
        cursor: Option<&CaptureTimeIssueCursor>,
        limit: u32,
    ) -> Result<KeysetPage<CaptureTimeIssueRecord, CaptureTimeIssueCursor>> {
        let analysis_build_id = self.require_history_analysis_context(context)?;
        self.store.list_capture_time_issues_page(
            context.history.scan_run_id,
            context.exact_group_build_id,
            analysis_build_id,
            cursor,
            limit,
        )
    }

    pub fn list_capture_time_metadata_reports_page(
        &self,
        context: &ScanHistoryGroupContext,
        cursor: Option<&MetadataReportCursor>,
        limit: u32,
    ) -> Result<KeysetPage<CaptureTimeMetadataReportRecord, MetadataReportCursor>> {
        let analysis_build_id = self.require_history_analysis_context(context)?;
        self.store.list_capture_time_metadata_reports_page(
            context.history.scan_run_id,
            context.exact_group_build_id,
            analysis_build_id,
            cursor,
            limit,
        )
    }

    pub fn list_capture_time_metadata_fields_page(
        &self,
        context: &ScanHistoryGroupContext,
        source_ordinal: i64,
        report_id: i64,
        cursor: Option<&MetadataFieldCursor>,
        limit: u32,
    ) -> Result<KeysetPage<CaptureTimeMetadataFieldRecord, MetadataFieldCursor>> {
        let analysis_build_id = self.require_history_analysis_context(context)?;
        self.store.list_capture_time_metadata_fields_page(
            context.history.scan_run_id,
            context.exact_group_build_id,
            analysis_build_id,
            source_ordinal,
            report_id,
            cursor,
            limit,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn get_capture_time_metadata_field_raw_detail(
        &self,
        context: &ScanHistoryGroupContext,
        source_ordinal: i64,
        report_id: i64,
        field_ordinal: i64,
        field_id: i64,
    ) -> Result<Option<CaptureTimeMetadataFieldRawDetail>> {
        let analysis_build_id = self.require_history_analysis_context(context)?;
        self.store.get_capture_time_metadata_field_raw_detail(
            context.history.scan_run_id,
            context.exact_group_build_id,
            analysis_build_id,
            source_ordinal,
            report_id,
            field_ordinal,
            field_id,
        )
    }

    pub fn close(self) -> Result<()> {
        self.store.close()
    }

    fn validate_history_cursor(
        &self,
        cursor: Option<&ScanHistoryCursor>,
    ) -> Result<(Option<i64>, Option<i64>)> {
        let Some(cursor) = cursor else {
            return Ok((None, None));
        };
        if cursor.cursor_version != HISTORY_CURSOR_VERSION
            || cursor.database_scope_digest != self.database_scope.into_bytes()
            || cursor.last_finished_at_ms < 0
            || cursor.last_scan_run_id <= 0
        {
            return Err(StoreError::invalid_input(
                "scan_history_cursor",
                "cursor version, database scope, or ordering key does not match",
            ));
        }
        Ok((
            Some(cursor.last_finished_at_ms),
            Some(cursor.last_scan_run_id),
        ))
    }

    fn validate_history_context(&self, context: &ScanHistoryContext) -> Result<()> {
        self.store
            .consistent_read(|connection| self.require_history_context(connection, context))
    }

    fn validate_history_group_context(&self, context: &ScanHistoryGroupContext) -> Result<()> {
        self.store.consistent_read(|connection| {
            self.require_history_context(connection, &context.history)?;
            let resolved = connection
                .query_row(
                    "SELECT outcome.outcome, outcome.analysis_build_id \
                     FROM exact_group_builds AS build \
                     LEFT JOIN capture_time_group_outcomes AS outcome \
                       ON outcome.time_session_id = ?1 \
                      AND outcome.scan_run_id = build.scan_run_id \
                      AND outcome.volume_id = build.volume_id \
                      AND outcome.exact_group_build_id = build.id \
                     WHERE build.id = ?2 AND build.scan_run_id = ?3 \
                       AND build.volume_id = ?4 AND build.state = 'verified'",
                    rusqlite::params![
                        context.history.time_session_id,
                        context.exact_group_build_id,
                        context.history.scan_run_id,
                        context.history.volume_id,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                        ))
                    },
                )
                .optional()?;
            if resolved.as_ref() != Some(&(context.time_outcome.clone(), context.analysis_build_id))
            {
                return Err(StoreError::ConcurrencyConflict {
                    entity: "scan_history_group_context",
                    id: context.exact_group_build_id,
                });
            }
            Ok(())
        })
    }

    fn require_history_analysis_context(&self, context: &ScanHistoryGroupContext) -> Result<i64> {
        self.validate_history_group_context(context)?;
        if context.time_outcome.as_deref() != Some("evidence") {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_history_time_evidence_context",
                id: context.exact_group_build_id,
            });
        }
        context
            .analysis_build_id
            .ok_or(StoreError::ConcurrencyConflict {
                entity: "scan_history_time_analysis_context",
                id: context.exact_group_build_id,
            })
    }

    fn require_terminal_time_session(&self, context: &ScanHistoryContext) -> Result<i64> {
        context
            .time_session_id
            .ok_or(StoreError::ConcurrencyConflict {
                entity: "scan_history_terminal_time_context",
                id: context.scan_run_id,
            })
    }

    fn require_history_context(
        &self,
        connection: &rusqlite::Connection,
        context: &ScanHistoryContext,
    ) -> Result<()> {
        if context.reader_instance_key != self.reader_instance_key
            || context.database_scope != self.database_scope
        {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_history_reader_context",
                id: context.scan_run_id,
            });
        }
        let resolved = resolve_history_context_row(connection, context.scan_run_id)?;
        if resolved
            != Some((
                context.scan_job_id,
                context.volume_id,
                context.time_session_id,
            ))
        {
            return Err(StoreError::ConcurrencyConflict {
                entity: "scan_history_context",
                id: context.scan_run_id,
            });
        }
        Ok(())
    }
}

fn validate_history_limit(limit: u32) -> Result<i64> {
    if limit == 0 || limit > MAX_HISTORY_PAGE_SIZE {
        return Err(StoreError::invalid_input(
            "limit",
            format!("scan history page size must be between 1 and {MAX_HISTORY_PAGE_SIZE}"),
        ));
    }
    i64::from(limit)
        .checked_add(1)
        .ok_or_else(|| StoreError::invalid_input("limit", "page size overflow"))
}

fn enforce_history_page_budget(bytes: i64) -> Result<()> {
    enforce_read_budget("scan history page", bytes, MAX_PAGE_RESULT_BYTES)
}

fn resolve_history_context_row(
    connection: &rusqlite::Connection,
    scan_run_id: i64,
) -> Result<Option<(i64, i64, Option<i64>)>> {
    connection
        .query_row(
            "SELECT job.id, run.volume_id, session.id \
             FROM scan_runs AS run \
             JOIN scan_job_runs AS job_run ON job_run.scan_run_id = run.id \
                                            AND job_run.volume_id = run.volume_id \
             JOIN scan_jobs AS job ON job.id = job_run.scan_job_id \
                                    AND job.volume_id = job_run.volume_id \
                                    AND job.active_scan_run_id = run.id \
                                    AND job.state = 'completed' \
             JOIN scan_stage_seals AS exact_seal \
               ON exact_seal.scan_run_id = run.id \
              AND exact_seal.volume_id = run.volume_id \
              AND exact_seal.stage = 'exact_verification' \
             JOIN scan_coverage_outcomes AS coverage \
               ON coverage.scan_run_id = run.id \
              AND coverage.volume_id = run.volume_id \
              AND coverage.status IN ('complete', 'partial') \
             LEFT JOIN scan_time_sessions AS session \
               ON session.scan_run_id = run.id \
              AND session.volume_id = run.volume_id \
              AND session.state IN ('complete', 'partial') \
              AND session.sealed_manifest_digest = session.expected_manifest_digest \
              AND session.sealed_outcome_manifest_digest IS NOT NULL \
              AND session.finalized_at_ms IS NOT NULL \
             WHERE run.id = ?1 AND run.state = 'completed' \
               AND run.started_at_ms IS NOT NULL AND run.finished_at_ms IS NOT NULL",
            [scan_run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(StoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MAX_READ_ONLY_DATABASE_FAMILY_BYTES;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn cursor_scope_is_stable_across_reopen_and_rejects_another_database(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let first_path = temporary.path().join("first.sqlite3");
        Store::open_or_create(&first_path)?.close()?;
        let first = EvidenceReader::open_existing_read_only(&first_path)?;
        let first_scope = first.database_scope();
        let cursor = ScanHistoryCursor {
            cursor_version: HISTORY_CURSOR_VERSION,
            database_scope_digest: first_scope.into_bytes(),
            last_finished_at_ms: 1,
            last_scan_run_id: 1,
        };
        first.close()?;

        let reopened = EvidenceReader::open_existing_read_only(&first_path)?;
        assert_eq!(reopened.database_scope(), first_scope);
        assert!(reopened
            .list_scan_history_page(Some(&cursor), 1)?
            .items
            .is_empty());
        reopened.close()?;

        let second_path = temporary.path().join("second.sqlite3");
        Store::open_or_create(&second_path)?.close()?;
        let second = EvidenceReader::open_existing_read_only(&second_path)?;
        assert_ne!(second.database_scope(), first_scope);
        assert!(matches!(
            second.list_scan_history_page(Some(&cursor), 1),
            Err(StoreError::InvalidInput { .. })
        ));
        second.close()?;
        Ok(())
    }

    #[test]
    fn evidence_reader_and_context_types_are_send() {
        fn assert_send<T: Send>() {}

        assert_send::<EvidenceReader>();
        assert_send::<ScanHistoryContext>();
        assert_send::<ScanHistoryGroupContext>();
        assert_send::<EvidenceDatabaseScope>();
    }

    #[test]
    fn history_cursor_denies_unknown_fields_and_page_budget_is_fail_closed(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert!(serde_json::from_value::<ScanHistoryCursor>(json!({
            "cursor_version": 1,
            "database_scope_digest": vec![0; 32],
            "last_finished_at_ms": 1,
            "last_scan_run_id": 1,
            "unexpected": true,
        }))
        .is_err());
        assert!(matches!(
            enforce_history_page_budget(MAX_PAGE_RESULT_BYTES + 1),
            Err(StoreError::ReadResultLimit {
                kind: "scan history page",
                ..
            })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn read_only_open_rejects_symlink_database_paths(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new()?;
        let database = temporary.path().join("database.sqlite3");
        let link = temporary.path().join("database-link.sqlite3");
        Store::open_or_create(&database)?.close()?;
        symlink(&database, &link)?;
        assert!(matches!(
            EvidenceReader::open_existing_read_only(&link),
            Err(StoreError::DatabaseIsNotRegularFile(_))
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn read_only_open_rejects_hot_journal_and_unpaired_wal_family(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TempDir::new()?;
        let journal_database = temporary.path().join("journal.sqlite3");
        Store::open_or_create(&journal_database)?.close()?;
        let journal = sidecar_path(&journal_database, "-journal");
        std::fs::write(&journal, b"not a recoverable journal")?;
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600))?;
        assert!(matches!(
            EvidenceReader::open_existing_read_only(&journal_database),
            Err(StoreError::ReadOnlyJournalPresent(_))
        ));

        let wal_database = temporary.path().join("wal.sqlite3");
        Store::open_or_create(&wal_database)?.close()?;
        let wal = sidecar_path(&wal_database, "-wal");
        std::fs::write(&wal, b"not a valid WAL")?;
        std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o600))?;
        assert!(matches!(
            EvidenceReader::open_existing_read_only(&wal_database),
            Err(StoreError::ReadOnlyWalSidecarMismatch(_))
        ));

        let shared_memory_database = temporary.path().join("shared-memory.sqlite3");
        Store::open_or_create(&shared_memory_database)?.close()?;
        let shared_memory = sidecar_path(&shared_memory_database, "-shm");
        std::fs::write(&shared_memory, [])?;
        std::fs::set_permissions(&shared_memory, std::fs::Permissions::from_mode(0o600))?;
        assert!(matches!(
            EvidenceReader::open_existing_read_only(&shared_memory_database),
            Err(StoreError::ReadOnlyWalSidecarMismatch(_))
        ));

        let empty_wal_database = temporary.path().join("empty-wal.sqlite3");
        Store::open_or_create(&empty_wal_database)?.close()?;
        let empty_wal = sidecar_path(&empty_wal_database, "-wal");
        std::fs::write(&empty_wal, [])?;
        std::fs::set_permissions(&empty_wal, std::fs::Permissions::from_mode(0o600))?;
        EvidenceReader::open_existing_read_only(&empty_wal_database)?.close()?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn read_only_open_rejects_oversized_sparse_database_before_sqlite(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let database = temporary.path().join("oversized.sqlite3");
        Store::open_or_create(&database)?.close()?;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&database)?
            .set_len(MAX_READ_ONLY_DATABASE_FAMILY_BYTES + 1)?;
        assert!(matches!(
            EvidenceReader::open_existing_read_only(&database),
            Err(StoreError::ReadOnlyDatabaseFamilyLimit { .. })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn cheap_revalidation_rejects_database_path_replacement(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let database = temporary.path().join("database.sqlite3");
        let replacement = temporary.path().join("replacement.sqlite3");
        let displaced = temporary.path().join("displaced.sqlite3");
        Store::open_or_create(&database)?.close()?;
        Store::open_or_create(&replacement)?.close()?;
        let reader = EvidenceReader::open_existing_read_only(&database)?;
        std::fs::rename(&database, displaced)?;
        std::fs::rename(replacement, &database)?;
        assert!(matches!(
            reader.revalidate_source_identity(),
            Err(StoreError::DatabaseIdentityChanged(_))
        ));
        drop(reader);
        Ok(())
    }

    #[cfg(unix)]
    fn sidecar_path(database: &Path, suffix: &str) -> std::path::PathBuf {
        let mut name = database.as_os_str().to_os_string();
        name.push(suffix);
        std::path::PathBuf::from(name)
    }

    #[cfg(windows)]
    #[test]
    fn windows_read_only_api_compiles_with_no_follow_identity_boundary() {
        fn assert_reader_result(_: Result<EvidenceReader>) {}
        let absolute = std::path::PathBuf::from(r"C:\guiying\missing.sqlite3");
        assert_reader_result(EvidenceReader::open_existing_read_only(absolute));
    }
}
