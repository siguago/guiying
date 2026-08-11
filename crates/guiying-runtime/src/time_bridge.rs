//! Current-session-only bridge from descriptor-bound media reads to timestamp policy.
//!
//! Nothing in this module authorizes or performs a media mutation. The opaque
//! result deliberately has private fields and no serialization implementation:
//! a future Store adapter must persist normalized evidence explicitly while the
//! live runtime session is still available.

use std::cell::RefCell;
use std::io::{self, Read, Seek, SeekFrom};

use guiying_core::ScanControl;
use guiying_metadata::{
    extract_timestamp_evidence, ExtractionLimits, ExtractionReport, MetadataIssueCode, ReadAtSource,
};
use guiying_store::{
    compute_time_lineage_key, compute_time_source_key, FingerprintBucketRecord,
    FingerprintFileTicketRecord, FreshFingerprintKind, RootScopeKey, StablePathKey, Store,
    TimeEvidenceGuard, TimeExactFingerprintMaterial, TimeSourceKeyMaterial, VerifiedExactGroup,
    VerifiedTimeProbeScopeRecord,
};
use guiying_time::{
    analyze_timestamp_evidence, EvidenceSource, LineageKey, PolicyContext, SourceKey,
    SourceVerifiedExtractionReport, TimeAnalysis,
};
use guiying_volume::ReadOnlyFile;
use serde_json::json;

use crate::{bind_file_ticket, root_object_signature, ActiveReadOnlyScan, BoundFileTicket};

/// At most four independent descriptors may be tried for one verified exact group.
pub(super) const MAX_TIMESTAMP_PROBES: u8 = 4;
/// Both extraction passes and every fallback fit under this aggregate reservation.
pub(super) const MAX_TIMESTAMP_PROBE_BYTES: u64 = 32 * 1024 * 1024;
/// Aggregate positional-read operation reservation for both extraction passes.
pub(super) const MAX_TIMESTAMP_PROBE_READ_OPERATIONS: u64 = 131_072;
/// Hard ceiling across every group in one post-D1 time-evidence session.
pub(super) const MAX_TIMESTAMP_SESSION_BYTES: u64 = 4_294_967_296;
/// Operation ceiling proportional to the maximum 4 GiB extraction reservation.
pub(super) const MAX_TIMESTAMP_SESSION_READ_OPERATIONS: u64 =
    (MAX_TIMESTAMP_SESSION_BYTES / BYTES_PER_EXTRACTION) * READ_OPERATIONS_PER_EXTRACTION;

const BYTES_PER_EXTRACTION: u64 = MAX_TIMESTAMP_PROBE_BYTES / (4 * 2);
const READ_OPERATIONS_PER_EXTRACTION: u64 = MAX_TIMESTAMP_PROBE_READ_OPERATIONS / (4 * 2);
const VERIFIED_SCOPE_PAGE_LIMIT: u32 = 64;
const STORE_TIME_BATCH_LIMIT: usize = 128;

/// Whether a descriptor-bound, twice-extracted report survived every later check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TimestampEvidenceStatus {
    Verified,
    Unavailable,
}

/// Bounded, path-free reason why one fallback could not become trusted evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TimestampProbeFailureCode {
    ExactGroupScopeRejected,
    SessionBindingChanged,
    TicketBindingRejected,
    ExtractionIoFailure,
    ReextractionMismatch,
    SourceChangedAfterRead,
    SessionChangedAfterRead,
    AggregateBudgetExhausted,
    SessionBudgetExhausted,
    Cancelled,
}

/// One failed probe. No operating-system message or source path is retained here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TimestampProbeFailure {
    ordinal: u8,
    code: TimestampProbeFailureCode,
}

/// Aggregate hard-budget accounting. Values are reservations, not filesystem byte counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TimestampProbeBudget {
    attempted_probes: u8,
    reserved_bytes: u64,
    reserved_read_operations: u64,
}

/// Checked reservations and actual descriptor reads across the whole time stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TimestampSessionBudget {
    max_bytes: u64,
    max_read_operations: u64,
    reserved_bytes: u64,
    reserved_read_operations: u64,
    actual_bytes: u64,
    actual_read_operations: u64,
    exhausted: bool,
}

impl TimestampSessionBudget {
    const fn hard_limit() -> Self {
        Self {
            max_bytes: MAX_TIMESTAMP_SESSION_BYTES,
            max_read_operations: MAX_TIMESTAMP_SESSION_READ_OPERATIONS,
            reserved_bytes: 0,
            reserved_read_operations: 0,
            actual_bytes: 0,
            actual_read_operations: 0,
            exhausted: false,
        }
    }

    #[cfg(test)]
    const fn with_limits(max_bytes: u64, max_read_operations: u64) -> Self {
        Self {
            max_bytes,
            max_read_operations,
            reserved_bytes: 0,
            reserved_read_operations: 0,
            actual_bytes: 0,
            actual_read_operations: 0,
            exhausted: false,
        }
    }
}

/// Opaque proof and analysis valid only for the live [`ActiveReadOnlyScan`].
///
/// Private session bindings and the source-verification proof intentionally
/// prevent callers from reconstructing this value from a database or IPC DTO.
/// This type does not implement `Serialize`, `Deserialize`, or `Clone`.
#[allow(dead_code)] // consumed only inside the in-process Store v7 adapter
pub(super) struct CurrentSessionTimestampEvidence {
    status: TimestampEvidenceStatus,
    scan_run_id: i64,
    source_key: Option<SourceKey>,
    lineage_key: Option<LineageKey>,
    probe_index: Option<u8>,
    verified: Option<SourceVerifiedExtractionReport>,
    analysis: TimeAnalysis,
    failures: Vec<TimestampProbeFailure>,
    budget: TimestampProbeBudget,
}

/// Internal authority that can only be created from a Store-sealed byte-exact group.
///
/// The retained records are capped at four and come from Store's guarded,
/// exact-stage-sealed probe page. A generic full-hash bucket cannot construct
/// this scope, so an abandoned collision bucket cannot reach the metadata
/// policy or share lineage with a verified group.
pub(super) struct VerifiedExactTimestampScope {
    scan_run_id: i64,
    core_session_id: [u8; 32],
    mount_session_key: [u8; 32],
    root_scope_key: [u8; 32],
    group: VerifiedExactGroup,
    bucket: FingerprintBucketRecord,
    records: Vec<FingerprintFileTicketRecord>,
}

impl VerifiedExactTimestampScope {
    fn from_store_record(
        runtime: &ActiveReadOnlyScan,
        record: VerifiedTimeProbeScopeRecord,
    ) -> Option<Self> {
        let VerifiedTimeProbeScopeRecord {
            scan_run_id,
            group,
            fingerprint_kind,
            algorithm,
            algorithm_version,
            parameters_hash,
            observed_size_bytes,
            digest,
            probes,
        } = record;
        let expected_record_count = usize::try_from(group.member_count)
            .ok()?
            .min(usize::from(MAX_TIMESTAMP_PROBES));
        let records_are_unique = probes.iter().enumerate().all(|(index, probe)| {
            probes.iter().skip(index + 1).all(|other| {
                probe.ticket.observation_id != other.ticket.observation_id
                    && probe.fingerprint_id != other.fingerprint_id
            })
        });
        let probes_are_canonical = probes.iter().enumerate().all(|(index, probe)| {
            let Ok(index) = i64::try_from(index) else {
                return false;
            };
            probe.ordinal == index && probe.sort_rank == index
        });
        let bucket = FingerprintBucketRecord {
            fingerprint_kind,
            algorithm,
            algorithm_version,
            parameters_hash,
            observed_size_bytes,
            digest,
            member_count: group.member_count,
        };
        let records = probes
            .into_iter()
            .map(|probe| FingerprintFileTicketRecord {
                fingerprint_id: probe.fingerprint_id,
                ticket: probe.ticket,
            })
            .collect::<Vec<_>>();
        (scan_run_id == runtime.ids.scan_run_id
            && bucket.fingerprint_kind == FreshFingerprintKind::ExactBytes
            && !bucket.algorithm.is_empty()
            && bucket.algorithm_version > 0
            && bucket.observed_size_bytes >= 0
            && !bucket.digest.is_empty()
            && group.build_id > 0
            && group.member_count >= 2
            && records.len() == expected_record_count
            && records_are_unique
            && probes_are_canonical
            && records
                .iter()
                .all(|record| record.ticket.size_bytes == bucket.observed_size_bytes))
        .then_some(Self {
            scan_run_id,
            core_session_id: *runtime.core_session_id.as_bytes(),
            mount_session_key: *runtime.guard.mount_session_key.as_bytes(),
            root_scope_key: *runtime.volume.observation().root_scope_key().as_bytes(),
            group,
            bucket,
            records,
        })
    }
}

/// Fail-closed status for the optional metadata/time stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampStageStatus {
    Completed,
    Partial,
    Unavailable,
}

/// Path-free stage failure classification. Exact duplicate evidence remains sealed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampStageFailureCode {
    EvidenceGuardRejected,
    ScopePageRejected,
    ScopeRecordRejected,
    AdapterWriteRejected,
    SessionBudgetExhausted,
    Cancelled,
}

/// Bounded accounting for a streamed time-evidence pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimestampStageSummary {
    status: TimestampStageStatus,
    groups_seen: u64,
    groups_written: u64,
    verified_groups: u64,
    unavailable_groups: u64,
    failed_groups: u64,
    failure: Option<TimestampStageFailureCode>,
    session_budget: TimestampSessionBudget,
}

/// Terminal outcome that the adapter actually committed for one group.
#[allow(dead_code)] // terminal outcomes remain internal to the durable adapter
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TimestampPersistedGroupOutcome {
    Evidence,
    Unavailable,
    Failed,
}

impl TimestampStageSummary {
    const fn unavailable(code: TimestampStageFailureCode) -> Self {
        Self {
            status: TimestampStageStatus::Unavailable,
            groups_seen: 0,
            groups_written: 0,
            verified_groups: 0,
            unavailable_groups: 0,
            failed_groups: 0,
            failure: Some(code),
            session_budget: TimestampSessionBudget::hard_limit(),
        }
    }

    const fn started() -> Self {
        Self {
            status: TimestampStageStatus::Completed,
            groups_seen: 0,
            groups_written: 0,
            verified_groups: 0,
            unavailable_groups: 0,
            failed_groups: 0,
            failure: None,
            session_budget: TimestampSessionBudget::hard_limit(),
        }
    }

    fn mark_partial(&mut self, code: TimestampStageFailureCode) {
        self.status = TimestampStageStatus::Partial;
        self.failure.get_or_insert(code);
    }

    fn record_group(&mut self, outcome: TimestampPersistedGroupOutcome) {
        self.groups_written = self.groups_written.saturating_add(1);
        match outcome {
            TimestampPersistedGroupOutcome::Evidence => {
                self.verified_groups = self.verified_groups.saturating_add(1);
            }
            TimestampPersistedGroupOutcome::Unavailable => {
                self.unavailable_groups = self.unavailable_groups.saturating_add(1);
            }
            TimestampPersistedGroupOutcome::Failed => {
                self.failed_groups = self.failed_groups.saturating_add(1);
            }
        }
    }

    /// Terminal state of the optional post-D1 evidence stage.
    #[must_use]
    pub const fn status(&self) -> TimestampStageStatus {
        self.status
    }

    /// Sealed exact groups visited before completion, cancellation, or failure.
    #[must_use]
    pub const fn groups_seen(&self) -> u64 {
        self.groups_seen
    }

    /// Groups for which Store committed exactly one terminal outcome.
    #[must_use]
    pub const fn groups_written(&self) -> u64 {
        self.groups_written
    }

    /// Groups with a source-revalidated, sealed capture-time analysis.
    #[must_use]
    pub const fn evidence_groups(&self) -> u64 {
        self.verified_groups
    }

    /// Groups for which no descriptor-bound timestamp source was available.
    #[must_use]
    pub const fn unavailable_groups(&self) -> u64 {
        self.unavailable_groups
    }

    /// Groups whose evidence conversion failed safely after D1 completed.
    #[must_use]
    pub const fn failed_groups(&self) -> u64 {
        self.failed_groups
    }

    /// First bounded, path-free reason why the optional stage became partial.
    #[must_use]
    pub const fn failure(&self) -> Option<TimestampStageFailureCode> {
        self.failure
    }

    /// Aggregate bytes reserved before descriptor probes began.
    #[must_use]
    pub const fn reserved_read_bytes(&self) -> u64 {
        self.session_budget.reserved_bytes
    }

    /// Aggregate descriptor bytes actually read across both extraction passes.
    #[must_use]
    pub const fn actual_read_bytes(&self) -> u64 {
        self.session_budget.actual_bytes
    }

    /// Aggregate positional-read operations reserved before probes began.
    #[must_use]
    pub const fn reserved_read_operations(&self) -> u64 {
        self.session_budget.reserved_read_operations
    }

    /// Aggregate positional-read operations actually performed.
    #[must_use]
    pub const fn actual_read_operations(&self) -> u64 {
        self.session_budget.actual_read_operations
    }

    /// Whether checked reservation or actual-read accounting reached its hard ceiling.
    #[must_use]
    pub const fn budget_exhausted(&self) -> bool {
        self.session_budget.exhausted
    }
}

/// In-process-only conversion boundary for durable Store v7 inputs.
///
/// The adapter receives the opaque second-extraction proof by reference while
/// its source descriptor, core session and mount session are still live. It
/// cannot manufacture a proof or retain a serializable runtime DTO.
#[allow(dead_code)] // implemented by the Store adapter and synthetic fault adapters
pub(super) trait TimestampEvidenceAdapter {
    /// Begin the bounded Store session after D1 has completed and the
    /// process-local time guard has been minted.
    fn begin_stage(
        &mut self,
        _store: &mut Store,
        _guard: &TimeEvidenceGuard,
    ) -> Result<(), crate::RuntimeError> {
        Ok(())
    }

    /// Persist one terminal group outcome or clean up every draft before
    /// returning an error. The control must be checked between Store batches.
    fn write_group(
        &mut self,
        store: &mut Store,
        guard: &TimeEvidenceGuard,
        scope: &VerifiedExactTimestampScope,
        evidence: &CurrentSessionTimestampEvidence,
        control: &dyn ScanControl,
    ) -> Result<TimestampPersistedGroupOutcome, crate::RuntimeError>;

    /// Seal the time session complete/partial after group processing ends.
    fn finish_stage(
        &mut self,
        _store: &mut Store,
        _guard: &TimeEvidenceGuard,
        _summary: &TimestampStageSummary,
    ) -> Result<(), crate::RuntimeError> {
        Ok(())
    }
}

/// Streams sealed verified groups through the descriptor bridge one page at a time.
///
/// Store/page/adapter failures are reported only through this optional-stage
/// summary and never propagated into the already sealed D1 result.
#[allow(dead_code)] // called by the explicit crate-private post-D1 persistence entry
pub(super) fn probe_sealed_exact_groups(
    runtime: &mut ActiveReadOnlyScan,
    context: &PolicyContext,
    control: &dyn ScanControl,
    adapter: &mut impl TimestampEvidenceAdapter,
) -> TimestampStageSummary {
    probe_sealed_exact_groups_with_page_limit(
        runtime,
        context,
        control,
        adapter,
        VERIFIED_SCOPE_PAGE_LIMIT,
    )
}

fn probe_sealed_exact_groups_with_page_limit(
    runtime: &mut ActiveReadOnlyScan,
    context: &PolicyContext,
    control: &dyn ScanControl,
    adapter: &mut impl TimestampEvidenceAdapter,
    page_limit: u32,
) -> TimestampStageSummary {
    if page_limit == 0 || page_limit > VERIFIED_SCOPE_PAGE_LIMIT {
        return TimestampStageSummary::unavailable(TimestampStageFailureCode::ScopePageRejected);
    }
    let time_guard = match runtime
        .store
        .time_evidence_guard(runtime.guard, runtime.core_session_id)
    {
        Ok(guard) => guard,
        Err(_) => {
            return TimestampStageSummary::unavailable(
                TimestampStageFailureCode::EvidenceGuardRejected,
            );
        }
    };
    let mut summary = TimestampStageSummary::started();
    if adapter
        .begin_stage(&mut runtime.store, &time_guard)
        .is_err()
    {
        summary.status = TimestampStageStatus::Unavailable;
        summary.failure = Some(TimestampStageFailureCode::AdapterWriteRejected);
        return summary;
    }
    if control.is_cancelled() {
        summary.status = TimestampStageStatus::Partial;
        summary.failure = Some(TimestampStageFailureCode::Cancelled);
        return finish_timestamp_stage(runtime, adapter, &time_guard, summary);
    }
    let mut cursor = None;
    'pages: loop {
        if control.is_cancelled() {
            summary.status = TimestampStageStatus::Partial;
            summary.failure = Some(TimestampStageFailureCode::Cancelled);
            break;
        }
        let page = match runtime.store.list_verified_time_probe_scopes_page(
            &time_guard,
            cursor.as_ref(),
            page_limit,
        ) {
            Ok(page) => page,
            Err(_) => {
                summary.status = TimestampStageStatus::Partial;
                summary.failure = Some(TimestampStageFailureCode::ScopePageRejected);
                break;
            }
        };
        if page.items.is_empty() && page.next_cursor.is_some() {
            summary.status = TimestampStageStatus::Partial;
            summary.failure = Some(TimestampStageFailureCode::ScopePageRejected);
            break;
        }
        for record in page.items {
            if control.is_cancelled() {
                summary.status = TimestampStageStatus::Partial;
                summary.failure = Some(TimestampStageFailureCode::Cancelled);
                break 'pages;
            }
            summary.groups_seen = summary.groups_seen.saturating_add(1);
            let Some(scope) = VerifiedExactTimestampScope::from_store_record(runtime, record)
            else {
                summary.mark_partial(TimestampStageFailureCode::ScopeRecordRejected);
                continue;
            };
            let evidence = probe_verified_exact_group(
                runtime,
                &scope,
                context,
                control,
                &mut summary.session_budget,
            );
            let cancelled = evidence_has_failure(&evidence, TimestampProbeFailureCode::Cancelled);
            let budget_exhausted =
                evidence_has_failure(&evidence, TimestampProbeFailureCode::SessionBudgetExhausted);
            let persisted_outcome =
                adapter.write_group(&mut runtime.store, &time_guard, &scope, &evidence, control);
            let persisted_outcome = match persisted_outcome {
                Ok(outcome) => outcome,
                Err(_) => {
                    summary.mark_partial(if control.is_cancelled() {
                        TimestampStageFailureCode::Cancelled
                    } else {
                        TimestampStageFailureCode::AdapterWriteRejected
                    });
                    break 'pages;
                }
            };
            summary.record_group(persisted_outcome);
            if cancelled || control.is_cancelled() {
                summary.status = TimestampStageStatus::Partial;
                summary.failure = Some(TimestampStageFailureCode::Cancelled);
                break 'pages;
            }
            if budget_exhausted || summary.session_budget.exhausted {
                summary.status = TimestampStageStatus::Partial;
                summary.failure = Some(TimestampStageFailureCode::SessionBudgetExhausted);
                break 'pages;
            }
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    finish_timestamp_stage(runtime, adapter, &time_guard, summary)
}

fn finish_timestamp_stage(
    runtime: &mut ActiveReadOnlyScan,
    adapter: &mut impl TimestampEvidenceAdapter,
    guard: &TimeEvidenceGuard,
    mut summary: TimestampStageSummary,
) -> TimestampStageSummary {
    if adapter
        .finish_stage(&mut runtime.store, guard, &summary)
        .is_err()
    {
        summary.status = TimestampStageStatus::Partial;
        summary
            .failure
            .get_or_insert(TimestampStageFailureCode::AdapterWriteRejected);
    }
    summary
}

fn evidence_has_failure(
    evidence: &CurrentSessionTimestampEvidence,
    code: TimestampProbeFailureCode,
) -> bool {
    evidence.failures.iter().any(|failure| failure.code == code)
}

fn probe_outcome_reason(evidence: &CurrentSessionTimestampEvidence) -> &'static str {
    evidence
        .failures
        .last()
        .map_or("no_descriptor_bound_source", |failure| match failure.code {
            TimestampProbeFailureCode::ExactGroupScopeRejected => "exact_group_scope_rejected",
            TimestampProbeFailureCode::SessionBindingChanged => "session_binding_changed",
            TimestampProbeFailureCode::TicketBindingRejected => "ticket_binding_rejected",
            TimestampProbeFailureCode::ExtractionIoFailure => "extraction_io_failure",
            TimestampProbeFailureCode::ReextractionMismatch => "reextraction_mismatch",
            TimestampProbeFailureCode::SourceChangedAfterRead => "source_changed_after_read",
            TimestampProbeFailureCode::SessionChangedAfterRead => "session_changed_after_read",
            TimestampProbeFailureCode::AggregateBudgetExhausted => "group_budget_exhausted",
            TimestampProbeFailureCode::SessionBudgetExhausted => "session_budget_exhausted",
            TimestampProbeFailureCode::Cancelled => "cancelled",
        })
}

fn policy_context_json(context: &PolicyContext) -> serde_json::Value {
    fn instant(value: guiying_time::UtcInstant) -> serde_json::Value {
        json!({
            "unix_seconds_decimal": value.unix_seconds().to_string(),
            "nanosecond": value.nanosecond(),
        })
    }

    fn wall(value: guiying_time::WallTime) -> serde_json::Value {
        json!({
            "year": value.year(),
            "month": value.month(),
            "day": value.day(),
            "hour": value.hour(),
            "minute": value.minute(),
            "second": value.second(),
            "nanosecond": value.nanosecond(),
        })
    }

    let sentinel_rules = context
        .sentinel_rules
        .iter()
        .map(|rule| match rule {
            guiying_time::SentinelRule::Year(year) => json!({
                "kind": "year",
                "year": year,
            }),
            guiying_time::SentinelRule::Date { year, month, day } => json!({
                "kind": "date",
                "year": year,
                "month": month,
                "day": day,
            }),
            guiying_time::SentinelRule::WallTime(value) => json!({
                "kind": "wall_time",
                "value": wall(*value),
            }),
            guiying_time::SentinelRule::UnixSecond(value) => json!({
                "kind": "unix_second",
                "unix_seconds_decimal": value.to_string(),
            }),
        })
        .collect::<Vec<_>>();

    json!({
        "contract": "guiying-time-policy-context-v1",
        "reference_utc": instant(context.reference_utc),
        "reference_wall_time": context.reference_wall_time.map(wall),
        "automatic_earliest_utc": context.automatic_earliest_utc.map(instant),
        "automatic_latest_utc": context.automatic_latest_utc.map(instant),
        "obvious_future_tolerance_seconds": context.obvious_future_tolerance_seconds,
        "strong_evidence_tolerance_seconds": context.strong_evidence_tolerance_seconds,
        "integer_hour_residual_tolerance_seconds":
            context.integer_hour_residual_tolerance_seconds,
        "maximum_suspected_offset_hours": context.maximum_suspected_offset_hours,
        "sentinel_rules": sentinel_rules,
        "system_timezone_applied": false,
    })
}

fn time_session_key(
    guard: &TimeEvidenceGuard,
    scope: &guiying_store::VerifiedTimeScopeSummary,
    policy_context_digest: &guiying_store::TimePolicyContextDigest,
    _budget: &guiying_store::TimeSessionBudget,
) -> guiying_store::TimeSessionKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.runtime.time-session.v1\0");
    hasher.update(&crate::RUNTIME_CONTRACT_VERSION.to_le_bytes());
    hasher.update(&guard.run().scan_run_id.to_le_bytes());
    hasher.update(&guard.run().capability_profile_id.to_le_bytes());
    hasher.update(guard.run().mount_session_key.as_bytes());
    hasher.update(guard.core_session_id().as_bytes());
    hasher.update(&scope.expected_group_count.to_le_bytes());
    hasher.update(scope.expected_manifest_digest.as_bytes());
    hasher.update(policy_context_digest.as_bytes());
    hasher.update(&MAX_TIMESTAMP_SESSION_BYTES.to_le_bytes());
    hasher.update(&[MAX_TIMESTAMP_PROBES]);
    hasher.update(&BYTES_PER_EXTRACTION.to_le_bytes());
    hasher.update(&READ_OPERATIONS_PER_EXTRACTION.to_le_bytes());
    hasher.update(
        &ExtractionLimits::default()
            .max_retained_field_bytes
            .to_le_bytes(),
    );
    hasher.update(&ExtractionLimits::default().max_fields.to_le_bytes());
    hasher.update(&128_u32.to_le_bytes());
    guiying_store::TimeSessionKey::from_runtime_evidence(*hasher.finalize().as_bytes())
}

fn checked_i64(value: u64, field: &'static str) -> Result<i64, crate::RuntimeError> {
    i64::try_from(value).map_err(|_| crate::RuntimeError::NumericRange(field))
}

fn checked_len(value: usize, field: &'static str) -> Result<i64, crate::RuntimeError> {
    i64::try_from(value).map_err(|_| crate::RuntimeError::NumericRange(field))
}

fn evidence_parser_identity(
    parser: guiying_metadata::ParserIdentity,
) -> Result<guiying_store::EvidenceParserIdentity, crate::RuntimeError> {
    Ok(guiying_store::EvidenceParserIdentity::new(
        parser.name,
        parser.version,
    )?)
}

fn stored_detected_format(
    format: guiying_metadata::DetectedFormat,
) -> guiying_store::MetadataDetectedFormat {
    match format {
        guiying_metadata::DetectedFormat::Jpeg => guiying_store::MetadataDetectedFormat::Jpeg,
        guiying_metadata::DetectedFormat::Tiff => guiying_store::MetadataDetectedFormat::Tiff,
        guiying_metadata::DetectedFormat::IsoBmff => guiying_store::MetadataDetectedFormat::IsoBmff,
    }
}

fn stored_extraction_status(
    status: guiying_metadata::ExtractionStatus,
) -> guiying_store::MetadataExtractionStatus {
    match status {
        guiying_metadata::ExtractionStatus::ExtractedUnvalidated => {
            guiying_store::MetadataExtractionStatus::ExtractedUnvalidated
        }
        guiying_metadata::ExtractionStatus::NoMetadata => {
            guiying_store::MetadataExtractionStatus::NoMetadata
        }
        guiying_metadata::ExtractionStatus::Partial => {
            guiying_store::MetadataExtractionStatus::Partial
        }
        guiying_metadata::ExtractionStatus::Failed => {
            guiying_store::MetadataExtractionStatus::Failed
        }
        guiying_metadata::ExtractionStatus::Unsupported => {
            guiying_store::MetadataExtractionStatus::Unsupported
        }
    }
}

fn stored_field_kind(
    kind: guiying_metadata::MetadataFieldKind,
) -> guiying_store::StoredMetadataFieldKind {
    match kind {
        guiying_metadata::MetadataFieldKind::ExifDateTimeOriginal => {
            guiying_store::StoredMetadataFieldKind::ExifDateTimeOriginal
        }
        guiying_metadata::MetadataFieldKind::ExifCreateDate => {
            guiying_store::StoredMetadataFieldKind::ExifCreateDate
        }
        guiying_metadata::MetadataFieldKind::ExifModifyDate => {
            guiying_store::StoredMetadataFieldKind::ExifModifyDate
        }
        guiying_metadata::MetadataFieldKind::ExifOffsetTimeOriginal => {
            guiying_store::StoredMetadataFieldKind::ExifOffsetTimeOriginal
        }
        guiying_metadata::MetadataFieldKind::ExifSubSecTimeOriginal => {
            guiying_store::StoredMetadataFieldKind::ExifSubSecTimeOriginal
        }
        guiying_metadata::MetadataFieldKind::QuickTimeMovieHeaderCreationTime => {
            guiying_store::StoredMetadataFieldKind::QuickTimeMovieHeaderCreationTime
        }
        guiying_metadata::MetadataFieldKind::QuickTimeMetadataCreationDate => {
            guiying_store::StoredMetadataFieldKind::QuickTimeMetadataCreationDate
        }
    }
}

fn stored_field_encoding(
    encoding: guiying_metadata::FieldEncoding,
) -> guiying_store::StoredMetadataEncoding {
    match encoding {
        guiying_metadata::FieldEncoding::DeclaredAscii => {
            guiying_store::StoredMetadataEncoding::DeclaredAscii
        }
        guiying_metadata::FieldEncoding::ValidatedUtf8 => {
            guiying_store::StoredMetadataEncoding::ValidatedUtf8
        }
        guiying_metadata::FieldEncoding::UnsignedBigEndian => {
            guiying_store::StoredMetadataEncoding::UnsignedBigEndian
        }
    }
}

fn stored_byte_order(
    byte_order: guiying_metadata::TiffByteOrder,
) -> guiying_store::StoredTiffByteOrder {
    match byte_order {
        guiying_metadata::TiffByteOrder::LittleEndian => {
            guiying_store::StoredTiffByteOrder::LittleEndian
        }
        guiying_metadata::TiffByteOrder::BigEndian => guiying_store::StoredTiffByteOrder::BigEndian,
    }
}

fn stored_locator(
    locator: &guiying_metadata::MetadataLocator,
) -> Result<guiying_store::MetadataLocatorInput, crate::RuntimeError> {
    let absolute_offset = checked_i64(locator.absolute_offset, "metadata locator offset")?;
    let byte_len = checked_i64(locator.byte_len, "metadata locator byte length")?;
    match &locator.container {
        guiying_metadata::MetadataContainer::Tiff {
            header_offset,
            ifd_offset,
            tag,
            byte_order,
        } => Ok(guiying_store::MetadataLocatorInput::tiff(
            absolute_offset,
            byte_len,
            checked_i64(*header_offset, "TIFF header offset")?,
            checked_i64(*ifd_offset, "TIFF IFD offset")?,
            *tag,
            stored_byte_order(*byte_order),
        )?),
        guiying_metadata::MetadataContainer::JpegExif {
            app1_offset,
            header_offset,
            ifd_offset,
            tag,
            byte_order,
        } => Ok(guiying_store::MetadataLocatorInput::jpeg_exif(
            absolute_offset,
            byte_len,
            checked_i64(*app1_offset, "JPEG APP1 offset")?,
            checked_i64(*header_offset, "Exif header offset")?,
            checked_i64(*ifd_offset, "Exif IFD offset")?,
            *tag,
            stored_byte_order(*byte_order),
        )?),
        guiying_metadata::MetadataContainer::IsoBmff {
            box_offset,
            box_path,
        } => Ok(guiying_store::MetadataLocatorInput::iso_bmff(
            absolute_offset,
            byte_len,
            checked_i64(*box_offset, "ISO BMFF box offset")?,
            box_path.clone(),
        )?),
    }
}

fn stored_metadata_issue_code(
    code: guiying_metadata::MetadataIssueCode,
) -> guiying_store::StoredMetadataIssueCode {
    match code {
        guiying_metadata::MetadataIssueCode::Io => guiying_store::StoredMetadataIssueCode::Io,
        guiying_metadata::MetadataIssueCode::UnexpectedEof => {
            guiying_store::StoredMetadataIssueCode::UnexpectedEof
        }
        guiying_metadata::MetadataIssueCode::ArithmeticOverflow => {
            guiying_store::StoredMetadataIssueCode::ArithmeticOverflow
        }
        guiying_metadata::MetadataIssueCode::OutOfBounds => {
            guiying_store::StoredMetadataIssueCode::OutOfBounds
        }
        guiying_metadata::MetadataIssueCode::InvalidStructure => {
            guiying_store::StoredMetadataIssueCode::InvalidStructure
        }
        guiying_metadata::MetadataIssueCode::CycleDetected => {
            guiying_store::StoredMetadataIssueCode::CycleDetected
        }
        guiying_metadata::MetadataIssueCode::LimitExceeded => {
            guiying_store::StoredMetadataIssueCode::LimitExceeded
        }
        guiying_metadata::MetadataIssueCode::UnsupportedVersion => {
            guiying_store::StoredMetadataIssueCode::UnsupportedVersion
        }
        guiying_metadata::MetadataIssueCode::InvalidSource => {
            guiying_store::StoredMetadataIssueCode::InvalidSource
        }
    }
}

fn extraction_limits_input(
    limits: guiying_metadata::ExtractionLimits,
) -> Result<guiying_store::MetadataExtractionLimitsInput, crate::RuntimeError> {
    Ok(guiying_store::MetadataExtractionLimitsInput::new(
        checked_i64(limits.max_total_bytes_read, "metadata total read limit")?,
        checked_i64(limits.max_read_operations, "metadata operation limit")?,
        checked_i64(
            limits.max_retained_field_bytes,
            "metadata retained field byte limit",
        )?,
        checked_i64(limits.max_field_bytes, "metadata field byte limit")?,
        i64::from(limits.max_fields),
        i64::from(limits.max_jpeg_segments),
        i64::from(limits.max_ifd_entries),
        i64::from(limits.max_ifd_depth),
        i64::from(limits.max_bmff_boxes),
        i64::from(limits.max_bmff_depth),
    )?)
}

fn extraction_usage_input(
    usage: guiying_metadata::ExtractionUsage,
) -> Result<guiying_store::MetadataExtractionUsageInput, crate::RuntimeError> {
    Ok(guiying_store::MetadataExtractionUsageInput::new(
        checked_i64(usage.bytes_read, "metadata bytes read")?,
        checked_i64(usage.read_operations, "metadata read operations")?,
        checked_i64(usage.retained_field_bytes, "metadata retained field bytes")?,
        i64::from(usage.fields_emitted),
        i64::from(usage.jpeg_segments_visited),
        i64::from(usage.ifd_entries_visited),
        i64::from(usage.bmff_boxes_visited),
        i64::from(usage.max_depth_observed),
    )?)
}

fn metadata_field_inputs(
    report: &ExtractionReport,
    created_at_ms: i64,
) -> Result<Vec<guiying_store::MetadataFieldInput>, crate::RuntimeError> {
    report
        .fields
        .iter()
        .enumerate()
        .map(|(ordinal, field)| {
            let raw_digest = guiying_store::MetadataReportDigest::from_runtime_evidence(
                *blake3::hash(&field.raw_bytes).as_bytes(),
            );
            Ok(guiying_store::MetadataFieldInput::new(
                checked_len(ordinal, "metadata field ordinal")?,
                evidence_parser_identity(field.parser)?,
                stored_field_kind(field.kind),
                stored_field_encoding(field.encoding),
                stored_locator(&field.locator)?,
                field.raw_bytes.clone(),
                raw_digest,
                created_at_ms,
            )?)
        })
        .collect()
}

fn metadata_issue_inputs(
    report: &ExtractionReport,
    created_at_ms: i64,
) -> Result<Vec<guiying_store::MetadataExtractionIssueInput>, crate::RuntimeError> {
    report
        .issues
        .iter()
        .enumerate()
        .map(|(ordinal, issue)| {
            Ok(guiying_store::MetadataExtractionIssueInput::new(
                checked_len(ordinal, "metadata issue ordinal")?,
                evidence_parser_identity(issue.parser)?,
                stored_metadata_issue_code(issue.code),
                issue
                    .offset
                    .map(|offset| checked_i64(offset, "metadata issue offset"))
                    .transpose()?,
                issue.context,
                created_at_ms,
            )?)
        })
        .collect()
}

fn hash_length_prefixed(
    hasher: &mut blake3::Hasher,
    bytes: &[u8],
) -> Result<(), crate::RuntimeError> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| crate::RuntimeError::NumericRange("timestamp report digest length"))?;
    hasher.update(&length.to_le_bytes());
    hasher.update(bytes);
    Ok(())
}

fn metadata_report_digest(
    report: &ExtractionReport,
) -> Result<guiying_store::MetadataReportDigest, crate::RuntimeError> {
    fn format_tag(value: Option<guiying_metadata::DetectedFormat>) -> u8 {
        match value {
            None => 0,
            Some(guiying_metadata::DetectedFormat::Jpeg) => 1,
            Some(guiying_metadata::DetectedFormat::Tiff) => 2,
            Some(guiying_metadata::DetectedFormat::IsoBmff) => 3,
        }
    }

    fn status_tag(value: guiying_metadata::ExtractionStatus) -> u8 {
        match value {
            guiying_metadata::ExtractionStatus::ExtractedUnvalidated => 1,
            guiying_metadata::ExtractionStatus::NoMetadata => 2,
            guiying_metadata::ExtractionStatus::Partial => 3,
            guiying_metadata::ExtractionStatus::Failed => 4,
            guiying_metadata::ExtractionStatus::Unsupported => 5,
        }
    }

    fn field_kind_tag(value: guiying_metadata::MetadataFieldKind) -> u8 {
        match value {
            guiying_metadata::MetadataFieldKind::ExifDateTimeOriginal => 1,
            guiying_metadata::MetadataFieldKind::ExifCreateDate => 2,
            guiying_metadata::MetadataFieldKind::ExifModifyDate => 3,
            guiying_metadata::MetadataFieldKind::ExifOffsetTimeOriginal => 4,
            guiying_metadata::MetadataFieldKind::ExifSubSecTimeOriginal => 5,
            guiying_metadata::MetadataFieldKind::QuickTimeMovieHeaderCreationTime => 6,
            guiying_metadata::MetadataFieldKind::QuickTimeMetadataCreationDate => 7,
        }
    }

    fn encoding_tag(value: guiying_metadata::FieldEncoding) -> u8 {
        match value {
            guiying_metadata::FieldEncoding::DeclaredAscii => 1,
            guiying_metadata::FieldEncoding::ValidatedUtf8 => 2,
            guiying_metadata::FieldEncoding::UnsignedBigEndian => 3,
        }
    }

    fn byte_order_tag(value: guiying_metadata::TiffByteOrder) -> u8 {
        match value {
            guiying_metadata::TiffByteOrder::LittleEndian => 1,
            guiying_metadata::TiffByteOrder::BigEndian => 2,
        }
    }

    fn issue_tag(value: guiying_metadata::MetadataIssueCode) -> u8 {
        match value {
            guiying_metadata::MetadataIssueCode::Io => 1,
            guiying_metadata::MetadataIssueCode::UnexpectedEof => 2,
            guiying_metadata::MetadataIssueCode::ArithmeticOverflow => 3,
            guiying_metadata::MetadataIssueCode::OutOfBounds => 4,
            guiying_metadata::MetadataIssueCode::InvalidStructure => 5,
            guiying_metadata::MetadataIssueCode::CycleDetected => 6,
            guiying_metadata::MetadataIssueCode::LimitExceeded => 7,
            guiying_metadata::MetadataIssueCode::UnsupportedVersion => 8,
            guiying_metadata::MetadataIssueCode::InvalidSource => 9,
        }
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"guiying.runtime.metadata-report.v1\0");
    hash_length_prefixed(&mut hasher, report.parser.name.as_bytes())?;
    hash_length_prefixed(&mut hasher, report.parser.version.as_bytes())?;
    for value in [
        report.limits.max_total_bytes_read,
        report.limits.max_read_operations,
        report.limits.max_retained_field_bytes,
        report.limits.max_field_bytes,
        u64::from(report.limits.max_fields),
        u64::from(report.limits.max_jpeg_segments),
        u64::from(report.limits.max_ifd_entries),
        u64::from(report.limits.max_ifd_depth),
        u64::from(report.limits.max_bmff_boxes),
        u64::from(report.limits.max_bmff_depth),
    ] {
        hasher.update(&value.to_le_bytes());
    }
    hasher.update(&[format_tag(report.format), status_tag(report.status)]);
    hash_length_prefixed(
        &mut hasher,
        &u64::try_from(report.fields.len())
            .map_err(|_| crate::RuntimeError::NumericRange("metadata field count"))?
            .to_le_bytes(),
    )?;
    for field in &report.fields {
        hash_length_prefixed(&mut hasher, field.parser.name.as_bytes())?;
        hash_length_prefixed(&mut hasher, field.parser.version.as_bytes())?;
        hasher.update(&[field_kind_tag(field.kind), encoding_tag(field.encoding)]);
        hasher.update(&field.locator.absolute_offset.to_le_bytes());
        hasher.update(&field.locator.byte_len.to_le_bytes());
        match &field.locator.container {
            guiying_metadata::MetadataContainer::Tiff {
                header_offset,
                ifd_offset,
                tag,
                byte_order,
            } => {
                hasher.update(&[1, byte_order_tag(*byte_order)]);
                hasher.update(&header_offset.to_le_bytes());
                hasher.update(&ifd_offset.to_le_bytes());
                hasher.update(&tag.to_le_bytes());
            }
            guiying_metadata::MetadataContainer::JpegExif {
                app1_offset,
                header_offset,
                ifd_offset,
                tag,
                byte_order,
            } => {
                hasher.update(&[2, byte_order_tag(*byte_order)]);
                hasher.update(&app1_offset.to_le_bytes());
                hasher.update(&header_offset.to_le_bytes());
                hasher.update(&ifd_offset.to_le_bytes());
                hasher.update(&tag.to_le_bytes());
            }
            guiying_metadata::MetadataContainer::IsoBmff {
                box_offset,
                box_path,
            } => {
                hasher.update(&[3]);
                hasher.update(&box_offset.to_le_bytes());
                let count = u64::try_from(box_path.len()).map_err(|_| {
                    crate::RuntimeError::NumericRange("metadata BMFF path component count")
                })?;
                hasher.update(&count.to_le_bytes());
                for component in box_path {
                    hasher.update(component);
                }
            }
        }
        hash_length_prefixed(&mut hasher, &field.raw_bytes)?;
    }
    let issue_count = u64::try_from(report.issues.len())
        .map_err(|_| crate::RuntimeError::NumericRange("metadata issue count"))?;
    hasher.update(&issue_count.to_le_bytes());
    for issue in &report.issues {
        hash_length_prefixed(&mut hasher, issue.parser.name.as_bytes())?;
        hash_length_prefixed(&mut hasher, issue.parser.version.as_bytes())?;
        hasher.update(&[issue_tag(issue.code)]);
        match issue.offset {
            Some(offset) => {
                hasher.update(&[1]);
                hasher.update(&offset.to_le_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hash_length_prefixed(&mut hasher, issue.context.as_bytes())?;
    }
    for value in [
        report.usage.bytes_read,
        report.usage.read_operations,
        report.usage.retained_field_bytes,
        u64::from(report.usage.fields_emitted),
        u64::from(report.usage.jpeg_segments_visited),
        u64::from(report.usage.ifd_entries_visited),
        u64::from(report.usage.bmff_boxes_visited),
        u64::from(report.usage.max_depth_observed),
    ] {
        hasher.update(&value.to_le_bytes());
    }
    Ok(guiying_store::MetadataReportDigest::from_runtime_evidence(
        *hasher.finalize().as_bytes(),
    ))
}

fn store_source_key(value: SourceKey) -> guiying_store::TimeSourceKey {
    guiying_store::TimeSourceKey::from_runtime_evidence(*value.as_bytes())
}

fn store_lineage_key(value: LineageKey) -> guiying_store::TimeLineageKey {
    guiying_store::TimeLineageKey::from_runtime_evidence(*value.as_bytes())
}

fn normalized_capture_time(
    timestamp: guiying_time::NormalizedTimestamp,
) -> Result<guiying_store::NormalizedCaptureTime, crate::RuntimeError> {
    let wall = timestamp.wall_time();
    let wall = guiying_store::CaptureWallTime::new(
        wall.year(),
        wall.month(),
        wall.day(),
        wall.hour(),
        wall.minute(),
        wall.second(),
        wall.nanosecond(),
    )?;
    let precision_ns = timestamp.precision().nanoseconds();
    match timestamp.offset_kind() {
        guiying_time::OffsetKind::Missing => {
            if timestamp.utc_offset().is_some() || timestamp.utc_instant().is_some() {
                return Err(crate::RuntimeError::UnsupportedEvidence(
                    "floating timestamp unexpectedly carries a UTC interpretation",
                ));
            }
            Ok(guiying_store::NormalizedCaptureTime::floating(
                wall,
                precision_ns,
            )?)
        }
        guiying_time::OffsetKind::Explicit => {
            let offset = timestamp
                .utc_offset()
                .ok_or(crate::RuntimeError::UnsupportedEvidence(
                    "explicit timestamp is missing its UTC offset",
                ))?;
            let instant =
                timestamp
                    .utc_instant()
                    .ok_or(crate::RuntimeError::UnsupportedEvidence(
                        "explicit timestamp is missing its UTC instant",
                    ))?;
            Ok(guiying_store::NormalizedCaptureTime::explicit_utc(
                wall,
                offset.minutes(),
                instant.unix_seconds().to_string(),
                instant.nanosecond(),
                precision_ns,
            )?)
        }
        guiying_time::OffsetKind::QuickTimeEpochAssumedUtc => {
            let offset = timestamp
                .utc_offset()
                .ok_or(crate::RuntimeError::UnsupportedEvidence(
                    "QuickTime timestamp is missing its assumed UTC offset",
                ))?;
            if offset.minutes() != 0 {
                return Err(crate::RuntimeError::UnsupportedEvidence(
                    "QuickTime epoch timestamp has a nonzero UTC offset",
                ));
            }
            let instant =
                timestamp
                    .utc_instant()
                    .ok_or(crate::RuntimeError::UnsupportedEvidence(
                        "QuickTime timestamp is missing its UTC instant",
                    ))?;
            Ok(
                guiying_store::NormalizedCaptureTime::quicktime_epoch_assumed_utc(
                    wall,
                    instant.unix_seconds().to_string(),
                    instant.nanosecond(),
                    precision_ns,
                )?,
            )
        }
    }
}

fn timestamp_parse_error_code(error: guiying_time::TimestampParseError) -> &'static str {
    match error {
        guiying_time::TimestampParseError::Empty => "empty",
        guiying_time::TimestampParseError::InvalidEncoding => "invalid_encoding",
        guiying_time::TimestampParseError::InvalidSyntax => "invalid_syntax",
        guiying_time::TimestampParseError::YearOutOfRange => "year_out_of_range",
        guiying_time::TimestampParseError::MonthOutOfRange => "month_out_of_range",
        guiying_time::TimestampParseError::DayOutOfRange => "day_out_of_range",
        guiying_time::TimestampParseError::HourOutOfRange => "hour_out_of_range",
        guiying_time::TimestampParseError::MinuteOutOfRange => "minute_out_of_range",
        guiying_time::TimestampParseError::SecondOutOfRange => "second_out_of_range",
        guiying_time::TimestampParseError::NanosecondOutOfRange => "nanosecond_out_of_range",
        guiying_time::TimestampParseError::SubsecondOutOfRange => "subsecond_out_of_range",
        guiying_time::TimestampParseError::OffsetOutOfRange => "offset_out_of_range",
        guiying_time::TimestampParseError::UnknownNegativeZeroOffset => {
            "unknown_negative_zero_offset"
        }
        guiying_time::TimestampParseError::PrecisionOutOfRange => "precision_out_of_range",
        guiying_time::TimestampParseError::UnsupportedBinaryLength => "unsupported_binary_length",
        guiying_time::TimestampParseError::ArithmeticOverflow => "arithmetic_overflow",
    }
}

fn observation_interpretation(
    interpretation: &guiying_time::ObservationInterpretation,
) -> Result<guiying_store::CaptureTimeObservationInterpretationInput, crate::RuntimeError> {
    match interpretation {
        guiying_time::ObservationInterpretation::Timestamp(timestamp) => Ok(
            guiying_store::CaptureTimeObservationInterpretationInput::Timestamp(
                normalized_capture_time(*timestamp)?,
            ),
        ),
        guiying_time::ObservationInterpretation::Offset(offset) => {
            Ok(guiying_store::CaptureTimeObservationInterpretationInput::offset(offset.minutes())?)
        }
        guiying_time::ObservationInterpretation::Subsecond {
            nanosecond,
            digits,
            precision,
        } => Ok(
            guiying_store::CaptureTimeObservationInterpretationInput::subsecond(
                *nanosecond,
                *digits,
                precision.nanoseconds(),
            )?,
        ),
        guiying_time::ObservationInterpretation::Rejected(error) => Ok(
            guiying_store::CaptureTimeObservationInterpretationInput::rejected(
                timestamp_parse_error_code(*error),
            )?,
        ),
    }
}

fn stored_confidence(value: guiying_time::Confidence) -> guiying_store::CaptureTimeConfidence {
    match value {
        guiying_time::Confidence::Conflict => guiying_store::CaptureTimeConfidence::Conflict,
        guiying_time::Confidence::Low => guiying_store::CaptureTimeConfidence::Low,
        guiying_time::Confidence::Medium => guiying_store::CaptureTimeConfidence::Medium,
        guiying_time::Confidence::High => guiying_store::CaptureTimeConfidence::High,
    }
}

fn stored_evidence_kind(
    value: guiying_time::TimeEvidenceKind,
) -> guiying_store::CaptureTimeEvidenceKind {
    match value {
        guiying_time::TimeEvidenceKind::ExifDateTimeOriginal => {
            guiying_store::CaptureTimeEvidenceKind::ExifDateTimeOriginal
        }
        guiying_time::TimeEvidenceKind::ExifCreateDate => {
            guiying_store::CaptureTimeEvidenceKind::ExifCreateDate
        }
        guiying_time::TimeEvidenceKind::ExifModifyDate => {
            guiying_store::CaptureTimeEvidenceKind::ExifModifyDate
        }
        guiying_time::TimeEvidenceKind::QuickTimeMetadataCreationDate => {
            guiying_store::CaptureTimeEvidenceKind::QuickTimeMetadataCreationDate
        }
        guiying_time::TimeEvidenceKind::QuickTimeMovieHeaderCreationTime => {
            guiying_store::CaptureTimeEvidenceKind::QuickTimeMovieHeaderCreationTime
        }
    }
}

fn stored_candidate_anomaly(
    value: guiying_time::CandidateAnomaly,
) -> guiying_store::CaptureTimeCandidateAnomaly {
    match value {
        guiying_time::CandidateAnomaly::MissingOffset => {
            guiying_store::CaptureTimeCandidateAnomaly::MissingOffset
        }
        guiying_time::CandidateAnomaly::SentinelValue => {
            guiying_store::CaptureTimeCandidateAnomaly::SentinelValue
        }
        guiying_time::CandidateAnomaly::ObviousFuture => {
            guiying_store::CaptureTimeCandidateAnomaly::ObviousFuture
        }
        guiying_time::CandidateAnomaly::OutsideAutomaticRange => {
            guiying_store::CaptureTimeCandidateAnomaly::OutsideAutomaticRange
        }
        guiying_time::CandidateAnomaly::QuickTimeEpochSemanticUncertainty => {
            guiying_store::CaptureTimeCandidateAnomaly::QuickTimeEpochSemanticUncertainty
        }
        guiying_time::CandidateAnomaly::InvalidCompanion => {
            guiying_store::CaptureTimeCandidateAnomaly::InvalidCompanion
        }
    }
}

fn stored_evidence_blocker(
    value: guiying_time::EvidenceGateBlocker,
) -> guiying_store::CaptureTimeEvidenceBlocker {
    match value {
        guiying_time::EvidenceGateBlocker::ConfidenceBelowHigh => {
            guiying_store::CaptureTimeEvidenceBlocker::ConfidenceBelowHigh
        }
        guiying_time::EvidenceGateBlocker::NoUtcInstant => {
            guiying_store::CaptureTimeEvidenceBlocker::NoUtcInstant
        }
        guiying_time::EvidenceGateBlocker::EvidenceConflict => {
            guiying_store::CaptureTimeEvidenceBlocker::EvidenceConflict
        }
        guiying_time::EvidenceGateBlocker::SentinelValue => {
            guiying_store::CaptureTimeEvidenceBlocker::SentinelValue
        }
        guiying_time::EvidenceGateBlocker::ObviousFuture => {
            guiying_store::CaptureTimeEvidenceBlocker::ObviousFuture
        }
        guiying_time::EvidenceGateBlocker::OutsideAutomaticRange => {
            guiying_store::CaptureTimeEvidenceBlocker::OutsideAutomaticRange
        }
        guiying_time::EvidenceGateBlocker::QuickTimeEpochSemanticUncertainty => {
            guiying_store::CaptureTimeEvidenceBlocker::QuickTimeEpochSemanticUncertainty
        }
        guiying_time::EvidenceGateBlocker::InvalidEvidencePresent => {
            guiying_store::CaptureTimeEvidenceBlocker::InvalidEvidencePresent
        }
        guiying_time::EvidenceGateBlocker::ExtractionReportUntrusted => {
            guiying_store::CaptureTimeEvidenceBlocker::ExtractionReportUntrusted
        }
        guiying_time::EvidenceGateBlocker::SourceNotRevalidated => {
            guiying_store::CaptureTimeEvidenceBlocker::SourceNotRevalidated
        }
        guiying_time::EvidenceGateBlocker::MultipleStrongValuesWithinTolerance => {
            guiying_store::CaptureTimeEvidenceBlocker::MultipleStrongValuesWithinTolerance
        }
    }
}

fn stored_evidence_gate(
    value: &guiying_time::EvidenceGateDecision,
) -> Result<guiying_store::CaptureTimeEvidenceGate, crate::RuntimeError> {
    match value {
        guiying_time::EvidenceGateDecision::Eligible => {
            Ok(guiying_store::CaptureTimeEvidenceGate::eligible())
        }
        guiying_time::EvidenceGateDecision::Blocked(blockers) => {
            Ok(guiying_store::CaptureTimeEvidenceGate::blocked(
                blockers
                    .iter()
                    .copied()
                    .map(stored_evidence_blocker)
                    .collect(),
            )?)
        }
    }
}

fn capture_time_candidate_inputs(
    analysis: &TimeAnalysis,
    created_at_ms: i64,
) -> Result<Vec<guiying_store::CaptureTimeCandidateInput>, crate::RuntimeError> {
    analysis
        .candidates
        .iter()
        .enumerate()
        .map(|(ordinal, candidate)| {
            Ok(guiying_store::CaptureTimeCandidateInput::new(
                checked_len(ordinal, "capture-time candidate ordinal")?,
                normalized_capture_time(candidate.timestamp)?,
                stored_confidence(candidate.confidence),
                stored_evidence_gate(&candidate.evidence_gate)?,
                candidate
                    .evidence_kinds
                    .iter()
                    .copied()
                    .map(stored_evidence_kind)
                    .collect(),
                candidate
                    .supporting_sources
                    .iter()
                    .copied()
                    .map(store_source_key)
                    .collect(),
                candidate
                    .supporting_lineages
                    .iter()
                    .copied()
                    .map(store_lineage_key)
                    .collect(),
                candidate
                    .observation_indices
                    .iter()
                    .map(|index| checked_len(*index, "candidate observation ordinal"))
                    .collect::<Result<Vec<_>, _>>()?,
                candidate
                    .anomalies
                    .iter()
                    .copied()
                    .map(stored_candidate_anomaly)
                    .collect(),
                created_at_ms,
            )?)
        })
        .collect()
}

fn policy_issue_code(value: guiying_time::PolicyIssueCode) -> &'static str {
    match value {
        guiying_time::PolicyIssueCode::InvalidField => "invalid_field",
        guiying_time::PolicyIssueCode::InvalidCompanion => "invalid_companion",
        guiying_time::PolicyIssueCode::OrphanExifCompanion => "orphan_exif_companion",
        guiying_time::PolicyIssueCode::RepeatedFieldConflict => "repeated_field_conflict",
        guiying_time::PolicyIssueCode::LineageConflict => "lineage_conflict",
        guiying_time::PolicyIssueCode::StrongEvidenceConflict => "strong_evidence_conflict",
        guiying_time::PolicyIssueCode::StrongEvidenceWithinToleranceAmbiguous => {
            "strong_evidence_within_tolerance_ambiguous"
        }
        guiying_time::PolicyIssueCode::PossibleTimezoneConflict => "possible_timezone_conflict",
        guiying_time::PolicyIssueCode::SentinelValue => "sentinel_value",
        guiying_time::PolicyIssueCode::ObviousFuture => "obvious_future",
        guiying_time::PolicyIssueCode::OutsideAutomaticRange => "outside_automatic_range",
        guiying_time::PolicyIssueCode::QuickTimeEpochSemanticUncertainty => {
            "quicktime_epoch_semantic_uncertainty"
        }
        guiying_time::PolicyIssueCode::ExtractionReportUntrusted => "extraction_report_untrusted",
        guiying_time::PolicyIssueCode::ExtractionReportContradiction => {
            "extraction_report_contradiction"
        }
        guiying_time::PolicyIssueCode::ParserIdentityMismatch => "parser_identity_mismatch",
        guiying_time::PolicyIssueCode::FieldEncodingMismatch => "field_encoding_mismatch",
        guiying_time::PolicyIssueCode::ContainerFormatMismatch => "container_format_mismatch",
        guiying_time::PolicyIssueCode::MetadataLocatorMismatch => "metadata_locator_mismatch",
        guiying_time::PolicyIssueCode::DuplicateSourceIdentity => "duplicate_source_identity",
        guiying_time::PolicyIssueCode::UnknownParserIdentity => "unknown_parser_identity",
        guiying_time::PolicyIssueCode::ExtractionBudgetContradiction => {
            "extraction_budget_contradiction"
        }
        guiying_time::PolicyIssueCode::AnalysisLimitExceeded => "analysis_limit_exceeded",
    }
}

fn capture_time_policy_issue_inputs(
    analysis: &TimeAnalysis,
    created_at_ms: i64,
) -> Result<Vec<guiying_store::CaptureTimePolicyIssueInput>, crate::RuntimeError> {
    analysis
        .issues
        .iter()
        .enumerate()
        .map(|(ordinal, issue)| {
            Ok(guiying_store::CaptureTimePolicyIssueInput::new(
                checked_len(ordinal, "capture-time issue ordinal")?,
                policy_issue_code(issue.code),
                issue.field_kind.map(stored_field_kind),
                issue
                    .observation_indices
                    .iter()
                    .map(|index| checked_len(*index, "policy issue observation ordinal"))
                    .collect::<Result<Vec<_>, _>>()?,
                issue
                    .source_keys
                    .iter()
                    .copied()
                    .map(store_source_key)
                    .collect(),
                issue
                    .lineage_keys
                    .iter()
                    .copied()
                    .map(store_lineage_key)
                    .collect(),
                issue.context,
                created_at_ms,
            )?)
        })
        .collect()
}

struct CaptureTimeDecisionMapping {
    decision: guiying_store::CaptureTimeDecision,
    selected_candidate_ordinal: Option<i64>,
    strong_candidate: Option<(i64, guiying_time::NormalizedTimestamp)>,
}

fn capture_time_decision(
    analysis: &TimeAnalysis,
) -> Result<CaptureTimeDecisionMapping, crate::RuntimeError> {
    match analysis.decision {
        guiying_time::AnalysisDecision::NoUsableEvidence => Ok(CaptureTimeDecisionMapping {
            decision: guiying_store::CaptureTimeDecision::NoUsableEvidence,
            selected_candidate_ordinal: None,
            strong_candidate: None,
        }),
        guiying_time::AnalysisDecision::ReviewRequired { candidate_index } => {
            let candidate = analysis.candidates.get(candidate_index).ok_or(
                crate::RuntimeError::UnsupportedEvidence(
                    "review decision references a missing capture-time candidate",
                ),
            )?;
            let ordinal = checked_len(candidate_index, "selected capture-time candidate")?;
            if matches!(
                candidate.evidence_gate,
                guiying_time::EvidenceGateDecision::Eligible
            ) {
                return Err(crate::RuntimeError::UnsupportedEvidence(
                    "review decision unexpectedly selected eligible evidence",
                ));
            }
            Ok(CaptureTimeDecisionMapping {
                decision: guiying_store::CaptureTimeDecision::ReviewRequired,
                selected_candidate_ordinal: Some(ordinal),
                strong_candidate: None,
            })
        }
        guiying_time::AnalysisDecision::EvidenceEligible { candidate_index } => {
            let candidate = analysis.candidates.get(candidate_index).ok_or(
                crate::RuntimeError::UnsupportedEvidence(
                    "eligible decision references a missing capture-time candidate",
                ),
            )?;
            if !matches!(
                candidate.evidence_gate,
                guiying_time::EvidenceGateDecision::Eligible
            ) || candidate.confidence != guiying_time::Confidence::High
                || candidate.timestamp.utc_instant().is_none()
            {
                return Err(crate::RuntimeError::UnsupportedEvidence(
                    "eligible decision is not backed by one high-confidence UTC candidate",
                ));
            }
            let ordinal = checked_len(candidate_index, "selected capture-time candidate")?;
            Ok(CaptureTimeDecisionMapping {
                decision: guiying_store::CaptureTimeDecision::EvidenceEligible,
                selected_candidate_ordinal: Some(ordinal),
                strong_candidate: Some((ordinal, candidate.timestamp)),
            })
        }
        guiying_time::AnalysisDecision::Conflict => Ok(CaptureTimeDecisionMapping {
            decision: guiying_store::CaptureTimeDecision::Conflict,
            selected_candidate_ordinal: None,
            strong_candidate: None,
        }),
    }
}

fn compare_file_timestamp(
    value: guiying_store::FileTimestampParts,
    granularity_ns: i64,
    candidate: guiying_time::NormalizedTimestamp,
) -> Result<guiying_store::FileTimeRelation, crate::RuntimeError> {
    if value.nanoseconds >= guiying_time::NANOS_PER_SECOND {
        return Err(crate::RuntimeError::UnsupportedEvidence(
            "filesystem timestamp nanoseconds are out of range",
        ));
    }
    if granularity_ns <= 0 {
        return Ok(guiying_store::FileTimeRelation::ReviewFsPrecisionUnknown);
    }
    let instant = candidate
        .utc_instant()
        .ok_or(crate::RuntimeError::UnsupportedEvidence(
            "filesystem comparison requires a UTC embedded candidate",
        ))?;
    let file_ns = i128::from(value.seconds)
        .checked_mul(i128::from(guiying_time::NANOS_PER_SECOND))
        .and_then(|seconds| seconds.checked_add(i128::from(value.nanoseconds)))
        .ok_or(crate::RuntimeError::NumericRange(
            "filesystem timestamp nanoseconds",
        ))?;
    let candidate_ns = instant
        .unix_seconds()
        .checked_mul(i128::from(guiying_time::NANOS_PER_SECOND))
        .and_then(|seconds| seconds.checked_add(i128::from(instant.nanosecond())))
        .ok_or(crate::RuntimeError::NumericRange(
            "embedded timestamp nanoseconds",
        ))?;
    let difference = if file_ns >= candidate_ns {
        file_ns - candidate_ns
    } else {
        candidate_ns - file_ns
    };
    let tolerance = i128::from(granularity_ns).max(i128::from(candidate.precision().nanoseconds()));
    Ok(if difference <= tolerance {
        guiying_store::FileTimeRelation::Matches
    } else {
        guiying_store::FileTimeRelation::Differs
    })
}

fn member_assessment(
    member: &guiying_store::DuplicateGroupMemberRecord,
    strong_candidate: Option<(i64, guiying_time::NormalizedTimestamp)>,
    created_at_ms: i64,
) -> Result<guiying_store::CaptureTimeMemberAssessmentInput, crate::RuntimeError> {
    let assessment = assess_member_filesystem_times(member, strong_candidate)?;
    Ok(guiying_store::CaptureTimeMemberAssessmentInput::new(
        member.ordinal,
        member.observation_id,
        assessment.candidate_ordinal,
        assessment.birth_relation,
        assessment.modified_relation,
        guiying_store::TimeDonorEligibility::Ineligible,
        assessment.reason_code,
        created_at_ms,
    )?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MemberFilesystemTimeAssessment {
    candidate_ordinal: Option<i64>,
    birth_relation: guiying_store::FileTimeRelation,
    modified_relation: guiying_store::FileTimeRelation,
    reason_code: &'static str,
}

fn assess_member_filesystem_times(
    member: &guiying_store::DuplicateGroupMemberRecord,
    strong_candidate: Option<(i64, guiying_time::NormalizedTimestamp)>,
) -> Result<MemberFilesystemTimeAssessment, crate::RuntimeError> {
    if let Some((candidate_ordinal, candidate)) = strong_candidate {
        if let Some(granularity_ns) = member.timestamp_granularity_ns {
            let birth_relation = member
                .birth_time
                .map(|value| compare_file_timestamp(value, granularity_ns, candidate))
                .transpose()?
                .unwrap_or(guiying_store::FileTimeRelation::Unavailable);
            let modified_relation =
                compare_file_timestamp(member.modified_time, granularity_ns, candidate)?;
            let reason_code = if matches!(
                birth_relation,
                guiying_store::FileTimeRelation::Matches
                    | guiying_store::FileTimeRelation::Unavailable
            ) && modified_relation == guiying_store::FileTimeRelation::Matches
            {
                "embedded_time_matches_fs"
            } else {
                "embedded_time_differs_fs"
            };
            Ok(MemberFilesystemTimeAssessment {
                candidate_ordinal: Some(candidate_ordinal),
                birth_relation,
                modified_relation,
                reason_code,
            })
        } else {
            Ok(MemberFilesystemTimeAssessment {
                candidate_ordinal: Some(candidate_ordinal),
                birth_relation: member
                    .birth_time
                    .map_or(guiying_store::FileTimeRelation::Unavailable, |_| {
                        guiying_store::FileTimeRelation::ReviewFsPrecisionUnknown
                    }),
                modified_relation: guiying_store::FileTimeRelation::ReviewFsPrecisionUnknown,
                reason_code: "fs_precision_unknown",
            })
        }
    } else {
        Ok(MemberFilesystemTimeAssessment {
            candidate_ordinal: None,
            birth_relation: member
                .birth_time
                .map_or(guiying_store::FileTimeRelation::Unavailable, |_| {
                    guiying_store::FileTimeRelation::NotCompared
                }),
            modified_relation: guiying_store::FileTimeRelation::NotCompared,
            reason_code: "no_strong_embedded_candidate",
        })
    }
}

fn load_member_assessments(
    store: &Store,
    scope: &VerifiedExactTimestampScope,
    strong_candidate: Option<(i64, guiying_time::NormalizedTimestamp)>,
    created_at_ms: i64,
    control: &dyn ScanControl,
) -> Result<Vec<guiying_store::CaptureTimeMemberAssessmentInput>, crate::RuntimeError> {
    let expected_count = usize::try_from(scope.group.member_count)
        .map_err(|_| crate::RuntimeError::NumericRange("exact group member count"))?;
    if !(2..=8_192).contains(&expected_count) {
        return Err(crate::RuntimeError::UnsupportedEvidence(
            "capture-time member count exceeds the bounded analysis contract",
        ));
    }
    let mut inputs = Vec::with_capacity(expected_count);
    let mut cursor = None;
    loop {
        if control.is_cancelled() {
            return Err(crate::RuntimeError::StageCancelled("capture-time evidence"));
        }
        let page = store.list_duplicate_group_members_page(
            scope.scan_run_id,
            scope.group.build_id,
            cursor.as_ref(),
            128,
        )?;
        if page.items.is_empty() && page.next_cursor.is_some() {
            return Err(crate::RuntimeError::UnsupportedEvidence(
                "duplicate-member page advanced without returning a member",
            ));
        }
        for member in page.items {
            if control.is_cancelled() {
                return Err(crate::RuntimeError::StageCancelled("capture-time evidence"));
            }
            let expected_ordinal = checked_len(inputs.len(), "capture-time member ordinal")?;
            if member.group_build_id != scope.group.build_id
                || member.ordinal != expected_ordinal
                || member.sort_rank != expected_ordinal
                || inputs.len() >= expected_count
            {
                return Err(crate::RuntimeError::UnsupportedEvidence(
                    "duplicate-member page is not the canonical sealed group order",
                ));
            }
            inputs.push(member_assessment(&member, strong_candidate, created_at_ms)?);
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    if inputs.len() != expected_count {
        return Err(crate::RuntimeError::UnsupportedEvidence(
            "duplicate-member page count differs from the sealed exact group",
        ));
    }
    Ok(inputs)
}

fn capture_time_observation_inputs(
    analysis: &TimeAnalysis,
    report: &ExtractionReport,
    metadata_field_ids: &[i64],
    source_key: SourceKey,
    lineage_key: LineageKey,
    created_at_ms: i64,
) -> Result<Vec<guiying_store::CaptureTimeObservationInput>, crate::RuntimeError> {
    if analysis.observations.len() != report.fields.len()
        || metadata_field_ids.len() != report.fields.len()
    {
        return Err(crate::RuntimeError::UnsupportedEvidence(
            "capture-time observations do not cover the retained report fields exactly",
        ));
    }
    analysis
        .observations
        .iter()
        .enumerate()
        .map(|(ordinal, observation)| {
            if observation.source_key != source_key
                || observation.lineage_key != lineage_key
                || observation.field != report.fields[ordinal]
            {
                return Err(crate::RuntimeError::UnsupportedEvidence(
                    "capture-time observation provenance differs from the sealed report",
                ));
            }
            Ok(guiying_store::CaptureTimeObservationInput::new(
                checked_len(ordinal, "capture-time observation ordinal")?,
                0,
                metadata_field_ids[ordinal],
                observation_interpretation(&observation.interpretation)?,
                created_at_ms,
            )?)
        })
        .collect()
}

fn require_not_cancelled(control: &dyn ScanControl) -> Result<(), crate::RuntimeError> {
    if control.is_cancelled() {
        Err(crate::RuntimeError::StageCancelled("capture-time evidence"))
    } else {
        Ok(())
    }
}

/// Durable adapter that consumes proofs only inside this live runtime process.
pub(super) struct StoreTimestampEvidenceAdapter {
    policy_context: PolicyContext,
    policy_context_json: serde_json::Value,
    policy_context_digest: guiying_store::TimePolicyContextDigest,
    time_session_id: Option<i64>,
    expected_group_count: i64,
    created_at_ms: Option<i64>,
    active_report_id: Option<i64>,
    active_analysis_id: Option<i64>,
}

impl StoreTimestampEvidenceAdapter {
    pub(super) fn new(policy_context: &PolicyContext) -> Result<Self, crate::RuntimeError> {
        let policy_context_json = policy_context_json(policy_context);
        let policy_context_digest =
            guiying_store::compute_time_policy_context_digest(&policy_context_json)?;
        Ok(Self {
            policy_context: policy_context.clone(),
            policy_context_json,
            policy_context_digest,
            time_session_id: None,
            expected_group_count: 0,
            created_at_ms: None,
            active_report_id: None,
            active_analysis_id: None,
        })
    }

    fn session_id(&self) -> Result<i64, crate::RuntimeError> {
        self.time_session_id
            .ok_or(crate::RuntimeError::UnsupportedEvidence(
                "time evidence session was not started",
            ))
    }

    fn created_at_ms(&self) -> Result<i64, crate::RuntimeError> {
        self.created_at_ms
            .ok_or(crate::RuntimeError::UnsupportedEvidence(
                "time evidence session timestamp disappeared",
            ))
    }

    fn persist_non_evidence_outcome(
        &self,
        store: &mut Store,
        guard: &TimeEvidenceGuard,
        group_build_id: i64,
        outcome: guiying_store::TimeGroupNonEvidenceOutcome,
        reason_code: &'static str,
    ) -> Result<(), crate::RuntimeError> {
        let input = guiying_store::RecordTimeGroupOutcomeInput::new(
            self.session_id()?,
            group_build_id,
            outcome,
            reason_code,
            self.created_at_ms()?,
        )?;
        store.write_transaction(|repository| {
            repository.record_time_group_non_evidence_outcome(guard, &input)
        })?;
        Ok(())
    }

    fn abandon_open_drafts(
        &mut self,
        store: &mut Store,
        guard: &TimeEvidenceGuard,
        reason_code: &'static str,
    ) -> Result<(), crate::RuntimeError> {
        let abandoned_at_ms = crate::now_ms()?;
        if let Some(analysis_id) = self.active_analysis_id {
            store.write_transaction(|repository| {
                repository.abandon_capture_time_analysis(
                    guard,
                    analysis_id,
                    abandoned_at_ms,
                    reason_code,
                    None,
                )
            })?;
            self.active_analysis_id = None;
        }
        if let Some(report_id) = self.active_report_id {
            store.write_transaction(|repository| {
                repository.abandon_metadata_report(
                    guard,
                    report_id,
                    abandoned_at_ms,
                    reason_code,
                    None,
                )
            })?;
            self.active_report_id = None;
        }
        Ok(())
    }

    fn persist_verified_group(
        &mut self,
        store: &mut Store,
        guard: &TimeEvidenceGuard,
        scope: &VerifiedExactTimestampScope,
        evidence: &CurrentSessionTimestampEvidence,
        control: &dyn ScanControl,
    ) -> Result<(), crate::RuntimeError> {
        self.persist_metadata_and_analysis(store, guard, scope, evidence, control)
    }

    fn persist_metadata_and_analysis(
        &mut self,
        store: &mut Store,
        guard: &TimeEvidenceGuard,
        scope: &VerifiedExactTimestampScope,
        evidence: &CurrentSessionTimestampEvidence,
        control: &dyn ScanControl,
    ) -> Result<(), crate::RuntimeError> {
        require_not_cancelled(control)?;
        if evidence.status != TimestampEvidenceStatus::Verified
            || evidence.scan_run_id != scope.scan_run_id
        {
            return Err(crate::RuntimeError::UnsupportedEvidence(
                "durable time evidence requires one verified current-run report",
            ));
        }
        let probe_index = evidence
            .probe_index
            .ok_or(crate::RuntimeError::UnsupportedEvidence(
                "verified time evidence is missing its sealed probe ordinal",
            ))?;
        let record = scope.records.get(usize::from(probe_index)).ok_or(
            crate::RuntimeError::UnsupportedEvidence(
                "verified time evidence references a probe outside the sealed group",
            ),
        )?;
        let verified =
            evidence
                .verified
                .as_ref()
                .ok_or(crate::RuntimeError::UnsupportedEvidence(
                    "verified time evidence is missing the pinned-source proof",
                ))?;
        let source_key = evidence
            .source_key
            .ok_or(crate::RuntimeError::UnsupportedEvidence(
                "verified time evidence is missing its source key",
            ))?;
        let lineage_key = evidence
            .lineage_key
            .ok_or(crate::RuntimeError::UnsupportedEvidence(
                "verified time evidence is missing its lineage key",
            ))?;
        if verified.source_key() != source_key {
            return Err(crate::RuntimeError::UnsupportedEvidence(
                "pinned-source proof and time evidence use different source keys",
            ));
        }
        let expected_analysis = analyze_timestamp_evidence(
            &[EvidenceSource::source_verified(lineage_key, verified)],
            &self.policy_context,
        );
        if expected_analysis != evidence.analysis {
            return Err(crate::RuntimeError::UnsupportedEvidence(
                "capture-time analysis differs from the adapter policy context",
            ));
        }
        let report = verified.report();
        if report_has_io_failure(report) {
            return Err(crate::RuntimeError::UnsupportedEvidence(
                "I/O-failed metadata reports cannot be sealed as verified evidence",
            ));
        }
        if evidence.analysis.source_reports.len() != 1 {
            return Err(crate::RuntimeError::UnsupportedEvidence(
                "one descriptor-bound probe must produce exactly one analysis source",
            ));
        }
        let source_report = evidence.analysis.source_reports[0];
        if source_report.source_key != source_key
            || source_report.lineage_key != lineage_key
            || source_report.parser != report.parser
            || source_report.status != report.status
            || source_report.binding
                != guiying_time::EvidenceBindingStatus::ReextractedFromPinnedSource
        {
            return Err(crate::RuntimeError::UnsupportedEvidence(
                "analysis source status differs from the pinned metadata report",
            ));
        }

        let created_at_ms = self.created_at_ms()?;
        let fields = metadata_field_inputs(report, created_at_ms)?;
        let metadata_issues = metadata_issue_inputs(report, created_at_ms)?;
        let report_digest = metadata_report_digest(report)?;
        let stored_source_key = store_source_key(source_key);
        let stored_lineage_key = store_lineage_key(lineage_key);
        let revalidated_at_ms = crate::now_ms()?;
        let revalidation =
            guiying_store::MetadataSourceRevalidationInput::reextracted_pinned_exact(
                stored_source_key,
                stored_lineage_key,
                record.ticket.source_signature,
                record.ticket.source_signature,
                report_digest,
                report_digest,
                revalidated_at_ms,
            )?;
        let report_plan = guiying_store::MetadataReportManifestPlan::new(
            guard,
            self.session_id()?,
            scope.group.build_id,
            record.ticket.observation_id,
            record.fingerprint_id,
            i64::from(probe_index),
            scope.bucket.observed_size_bytes,
            evidence_parser_identity(report.parser)?,
            report.format.map(stored_detected_format),
            stored_extraction_status(report.status),
            extraction_limits_input(report.limits)?,
            extraction_usage_input(report.usage)?,
            checked_len(fields.len(), "metadata report field count")?,
            checked_len(metadata_issues.len(), "metadata report issue count")?,
            checked_i64(
                report.usage.retained_field_bytes,
                "metadata retained field byte count",
            )?,
            report_digest,
            created_at_ms,
        )?;
        let report_manifest = guiying_store::compute_metadata_report_manifest(
            &report_plan,
            &fields,
            &metadata_issues,
            &revalidation,
        )?;
        let report_begin = report_plan.into_begin_input(report_manifest);
        require_not_cancelled(control)?;
        let report_id = store.write_transaction(|repository| {
            repository.begin_metadata_report(guard, &report_begin)
        })?;
        self.active_report_id = Some(report_id);

        let mut metadata_field_ids = Vec::with_capacity(fields.len());
        for chunk in fields.chunks(STORE_TIME_BATCH_LIMIT) {
            require_not_cancelled(control)?;
            let ids = store.write_transaction(|repository| {
                repository.append_metadata_fields_batch(guard, report_id, chunk)
            })?;
            if ids.len() != chunk.len() {
                return Err(crate::RuntimeError::UnsupportedEvidence(
                    "Store returned an incomplete metadata field id batch",
                ));
            }
            metadata_field_ids.extend(ids);
        }
        for chunk in metadata_issues.chunks(STORE_TIME_BATCH_LIMIT) {
            require_not_cancelled(control)?;
            let ids = store.write_transaction(|repository| {
                repository.append_metadata_issues_batch(guard, report_id, chunk)
            })?;
            if ids.len() != chunk.len() {
                return Err(crate::RuntimeError::UnsupportedEvidence(
                    "Store returned an incomplete metadata issue id batch",
                ));
            }
        }
        require_not_cancelled(control)?;
        store.write_transaction(|repository| {
            repository.seal_metadata_report(guard, report_id, &revalidation, revalidated_at_ms)
        })?;
        self.active_report_id = None;

        let analysis_created_at_ms = crate::now_ms()?;
        let sources = vec![
            guiying_store::CaptureTimeAnalysisSourceInput::reextracted_pinned_source(
                0,
                report_id,
                stored_source_key,
                stored_lineage_key,
                analysis_created_at_ms,
            )?,
        ];
        let observations = capture_time_observation_inputs(
            &evidence.analysis,
            report,
            &metadata_field_ids,
            source_key,
            lineage_key,
            analysis_created_at_ms,
        )?;
        let candidates = capture_time_candidate_inputs(&evidence.analysis, analysis_created_at_ms)?;
        let policy_issues =
            capture_time_policy_issue_inputs(&evidence.analysis, analysis_created_at_ms)?;
        let decision = capture_time_decision(&evidence.analysis)?;
        let members = load_member_assessments(
            store,
            scope,
            decision.strong_candidate,
            analysis_created_at_ms,
            control,
        )?;
        let recommendation = guiying_store::CaptureTimeRecommendationInput::without_keeper_policy(
            "keeper_policy_unavailable",
            analysis_created_at_ms,
        )?;
        let analysis_plan = guiying_store::CaptureTimeAnalysisManifestPlan::new(
            guard,
            self.session_id()?,
            scope.group.build_id,
            evidence.analysis.policy.name,
            evidence.analysis.policy.version,
            self.policy_context_json.clone(),
            self.policy_context_digest,
            checked_len(sources.len(), "capture-time source count")?,
            checked_len(observations.len(), "capture-time observation count")?,
            checked_len(candidates.len(), "capture-time candidate count")?,
            checked_len(policy_issues.len(), "capture-time policy issue count")?,
            checked_len(members.len(), "capture-time member count")?,
            1,
            analysis_created_at_ms,
        )?;
        let analysis_manifest = guiying_store::compute_capture_time_analysis_manifest(
            &analysis_plan,
            &sources,
            &observations,
            &candidates,
            &policy_issues,
            &members,
            &recommendation,
        )?;
        let analysis_begin = analysis_plan.into_begin_input(analysis_manifest);
        require_not_cancelled(control)?;
        let analysis_id = store.write_transaction(|repository| {
            repository.begin_capture_time_analysis(guard, &analysis_begin)
        })?;
        self.active_analysis_id = Some(analysis_id);

        for chunk in sources.chunks(STORE_TIME_BATCH_LIMIT) {
            require_not_cancelled(control)?;
            store.write_transaction(|repository| {
                repository.append_capture_time_sources_batch(guard, analysis_id, chunk)
            })?;
        }
        for chunk in observations.chunks(STORE_TIME_BATCH_LIMIT) {
            require_not_cancelled(control)?;
            let ids = store.write_transaction(|repository| {
                repository.append_capture_time_observations_batch(guard, analysis_id, chunk)
            })?;
            if ids.len() != chunk.len() {
                return Err(crate::RuntimeError::UnsupportedEvidence(
                    "Store returned an incomplete capture-time observation id batch",
                ));
            }
        }
        for chunk in candidates.chunks(STORE_TIME_BATCH_LIMIT) {
            require_not_cancelled(control)?;
            let ids = store.write_transaction(|repository| {
                repository.append_capture_time_candidates_batch(guard, analysis_id, chunk)
            })?;
            if ids.len() != chunk.len() {
                return Err(crate::RuntimeError::UnsupportedEvidence(
                    "Store returned an incomplete capture-time candidate id batch",
                ));
            }
        }
        for chunk in policy_issues.chunks(STORE_TIME_BATCH_LIMIT) {
            require_not_cancelled(control)?;
            let ids = store.write_transaction(|repository| {
                repository.append_capture_time_policy_issues_batch(guard, analysis_id, chunk)
            })?;
            if ids.len() != chunk.len() {
                return Err(crate::RuntimeError::UnsupportedEvidence(
                    "Store returned an incomplete capture-time issue id batch",
                ));
            }
        }
        for chunk in members.chunks(STORE_TIME_BATCH_LIMIT) {
            require_not_cancelled(control)?;
            store.write_transaction(|repository| {
                repository.append_capture_time_members_batch(guard, analysis_id, chunk)
            })?;
        }
        require_not_cancelled(control)?;
        store.write_transaction(|repository| {
            repository.append_capture_time_recommendation(guard, analysis_id, &recommendation)
        })?;
        require_not_cancelled(control)?;
        let finalized_at_ms = crate::now_ms()?;
        store.write_transaction(|repository| {
            repository.seal_capture_time_analysis(
                guard,
                analysis_id,
                decision.decision,
                decision.selected_candidate_ordinal,
                finalized_at_ms,
            )
        })?;
        self.active_analysis_id = None;
        Ok(())
    }
}

impl TimestampEvidenceAdapter for StoreTimestampEvidenceAdapter {
    fn begin_stage(
        &mut self,
        store: &mut Store,
        guard: &TimeEvidenceGuard,
    ) -> Result<(), crate::RuntimeError> {
        if self.time_session_id.is_some() {
            return Err(crate::RuntimeError::UnsupportedEvidence(
                "time evidence adapter may begin exactly once",
            ));
        }
        let scope = store.verified_time_scope_summary_for_time(guard)?;
        let created_at_ms = crate::now_ms()?;
        let budget = guiying_store::TimeSessionBudget::new(
            i64::try_from(MAX_TIMESTAMP_SESSION_BYTES)
                .map_err(|_| crate::RuntimeError::NumericRange("time session byte budget"))?,
            i64::from(MAX_TIMESTAMP_PROBES),
            i64::try_from(BYTES_PER_EXTRACTION)
                .map_err(|_| crate::RuntimeError::NumericRange("metadata report byte budget"))?,
            i64::try_from(READ_OPERATIONS_PER_EXTRACTION).map_err(|_| {
                crate::RuntimeError::NumericRange("metadata report operation budget")
            })?,
            i64::try_from(ExtractionLimits::default().max_retained_field_bytes).map_err(|_| {
                crate::RuntimeError::NumericRange("metadata retained field byte budget")
            })?,
            i64::from(ExtractionLimits::default().max_fields),
            128,
        )?;
        let time_session_key =
            time_session_key(guard, &scope, &self.policy_context_digest, &budget);
        let input = guiying_store::BeginTimeSessionInput::new(
            time_session_key,
            scope.expected_group_count,
            budget,
            scope.expected_manifest_digest,
            created_at_ms,
        )?;
        let time_session_id =
            store.write_transaction(|repository| repository.begin_time_session(guard, &input))?;
        self.time_session_id = Some(time_session_id);
        self.expected_group_count = scope.expected_group_count;
        self.created_at_ms = Some(created_at_ms);
        Ok(())
    }

    fn write_group(
        &mut self,
        store: &mut Store,
        guard: &TimeEvidenceGuard,
        scope: &VerifiedExactTimestampScope,
        evidence: &CurrentSessionTimestampEvidence,
        control: &dyn ScanControl,
    ) -> Result<TimestampPersistedGroupOutcome, crate::RuntimeError> {
        if control.is_cancelled()
            || evidence_has_failure(evidence, TimestampProbeFailureCode::Cancelled)
        {
            return Err(crate::RuntimeError::StageCancelled("capture-time evidence"));
        }
        if evidence.status == TimestampEvidenceStatus::Unavailable {
            self.persist_non_evidence_outcome(
                store,
                guard,
                scope.group.build_id,
                guiying_store::TimeGroupNonEvidenceOutcome::Unavailable,
                probe_outcome_reason(evidence),
            )?;
            return Ok(TimestampPersistedGroupOutcome::Unavailable);
        }
        match self.persist_verified_group(store, guard, scope, evidence, control) {
            Ok(()) => Ok(TimestampPersistedGroupOutcome::Evidence),
            Err(primary) => {
                let cleanup = self.abandon_open_drafts(store, guard, "runtime_time_adapter_failed");
                if control.is_cancelled() {
                    cleanup?;
                    return Err(primary);
                }
                cleanup?;
                self.persist_non_evidence_outcome(
                    store,
                    guard,
                    scope.group.build_id,
                    guiying_store::TimeGroupNonEvidenceOutcome::Failed,
                    "runtime_time_adapter_failed",
                )?;
                Ok(TimestampPersistedGroupOutcome::Failed)
            }
        }
    }

    fn finish_stage(
        &mut self,
        store: &mut Store,
        guard: &TimeEvidenceGuard,
        summary: &TimestampStageSummary,
    ) -> Result<(), crate::RuntimeError> {
        self.abandon_open_drafts(store, guard, "runtime_time_stage_stopped")?;
        let time_session_id = self.session_id()?;
        let outcome = if summary.status == TimestampStageStatus::Completed
            && i64::try_from(summary.groups_written).ok() == Some(self.expected_group_count)
        {
            guiying_store::TimeSessionOutcome::Complete
        } else {
            guiying_store::TimeSessionOutcome::Partial
        };
        let finalized_at_ms = crate::now_ms()?;
        let finalized = store.write_transaction(|repository| {
            repository.finalize_time_session(guard, time_session_id, outcome, finalized_at_ms)
        });
        if let Err(primary) = finalized {
            let abandoned_at_ms = crate::now_ms()?;
            let abandoned = store.write_transaction(|repository| {
                repository.abandon_time_session(
                    guard,
                    time_session_id,
                    abandoned_at_ms,
                    "runtime_time_finalize_failed",
                    None,
                )
            });
            return match abandoned {
                Ok(()) => Err(primary.into()),
                Err(abandon) => Err(crate::RuntimeError::Stream(format!(
                    "{primary}; additionally failed to abandon time session: {abandon}"
                ))),
            };
        }
        Ok(())
    }
}

/// Run the durable post-D1 metadata/time stage without exposing its proof DTO.
#[allow(dead_code)] // wired into the scan orchestrator after adapter QA completes
pub(super) fn persist_sealed_exact_group_times(
    runtime: &mut ActiveReadOnlyScan,
    context: &PolicyContext,
    control: &dyn ScanControl,
) -> Result<TimestampStageSummary, crate::RuntimeError> {
    let mut adapter = StoreTimestampEvidenceAdapter::new(context)?;
    Ok(probe_sealed_exact_groups(
        runtime,
        context,
        control,
        &mut adapter,
    ))
}

/// Descriptor bridge for one Store-sealed exact group.
///
/// This is intentionally crate-private: the post-D1 stage reconstructs scopes
/// only from Store's guarded sealed-group page, then the adapter persists and
/// discards this non-serializable output while the core and mount sessions are
/// still live. No generic digest-bucket or externally reconstructed DTO is
/// accepted.
#[allow(dead_code)]
pub(super) fn probe_verified_exact_group(
    runtime: &ActiveReadOnlyScan,
    scope: &VerifiedExactTimestampScope,
    context: &PolicyContext,
    control: &dyn ScanControl,
    session_budget: &mut TimestampSessionBudget,
) -> CurrentSessionTimestampEvidence {
    let mut result = unavailable_result(runtime.ids.scan_run_id, None, context);

    if scope.scan_run_id != runtime.ids.scan_run_id
        || scope.core_session_id != *runtime.core_session_id.as_bytes()
        || scope.mount_session_key != *runtime.guard.mount_session_key.as_bytes()
        || scope.root_scope_key != *runtime.volume.observation().root_scope_key().as_bytes()
    {
        result.failures.push(TimestampProbeFailure {
            ordinal: 0,
            code: TimestampProbeFailureCode::ExactGroupScopeRejected,
        });
        return result;
    }
    let Some(lineage_key) = exact_lineage_key(scope) else {
        result.failures.push(TimestampProbeFailure {
            ordinal: 0,
            code: TimestampProbeFailureCode::ExactGroupScopeRejected,
        });
        return result;
    };
    result.lineage_key = Some(lineage_key);

    if runtime.guard.mount_session_key.as_bytes()
        != runtime.volume.observation().mount_session_key().as_bytes()
        || runtime.volume.revalidate().is_err()
    {
        result.failures.push(TimestampProbeFailure {
            ordinal: 0,
            code: TimestampProbeFailureCode::SessionBindingChanged,
        });
        return result;
    }

    for (index, record) in scope.records.iter().enumerate() {
        let ordinal = u8::try_from(index + 1).unwrap_or(MAX_TIMESTAMP_PROBES);
        if control.is_cancelled() {
            result.failures.push(TimestampProbeFailure {
                ordinal,
                code: TimestampProbeFailureCode::Cancelled,
            });
            return result;
        }
        if !reserve_probe(&mut result.budget, session_budget) {
            result.failures.push(TimestampProbeFailure {
                ordinal,
                code: if session_budget.exhausted {
                    TimestampProbeFailureCode::SessionBudgetExhausted
                } else {
                    TimestampProbeFailureCode::AggregateBudgetExhausted
                },
            });
            break;
        }
        let bound = match bind_file_ticket(&runtime.volume, record.ticket.clone()) {
            Ok(bound) => bound,
            Err(_) => {
                result.failures.push(TimestampProbeFailure {
                    ordinal,
                    code: TimestampProbeFailureCode::TicketBindingRejected,
                });
                continue;
            }
        };
        let Some(source_key) = current_source_key(runtime, scope, record) else {
            result.failures.push(TimestampProbeFailure {
                ordinal,
                code: TimestampProbeFailureCode::ExactGroupScopeRejected,
            });
            return result;
        };
        match probe_bound_source(&runtime.volume, bound, source_key, control, session_budget) {
            Ok(verified) => {
                if control.is_cancelled() {
                    result.failures.push(TimestampProbeFailure {
                        ordinal,
                        code: TimestampProbeFailureCode::Cancelled,
                    });
                    return result;
                }
                if report_has_io_failure(verified.report()) {
                    result.failures.push(TimestampProbeFailure {
                        ordinal,
                        code: TimestampProbeFailureCode::ExtractionIoFailure,
                    });
                    continue;
                }
                let source = EvidenceSource::source_verified(lineage_key, &verified);
                result.analysis = analyze_timestamp_evidence(&[source], context);
                result.status = TimestampEvidenceStatus::Verified;
                result.source_key = Some(source_key);
                result.probe_index = u8::try_from(index).ok();
                result.verified = Some(verified);
                return result;
            }
            Err(code) => {
                result
                    .failures
                    .push(TimestampProbeFailure { ordinal, code });
                if matches!(
                    code,
                    TimestampProbeFailureCode::Cancelled
                        | TimestampProbeFailureCode::SessionBudgetExhausted
                ) {
                    return result;
                }
            }
        }
    }

    result
}

fn unavailable_result(
    scan_run_id: i64,
    lineage_key: Option<LineageKey>,
    context: &PolicyContext,
) -> CurrentSessionTimestampEvidence {
    CurrentSessionTimestampEvidence {
        status: TimestampEvidenceStatus::Unavailable,
        scan_run_id,
        source_key: None,
        lineage_key,
        probe_index: None,
        verified: None,
        analysis: analyze_timestamp_evidence(&[], context),
        failures: Vec::new(),
        budget: TimestampProbeBudget {
            attempted_probes: 0,
            reserved_bytes: 0,
            reserved_read_operations: 0,
        },
    }
}

fn reserve_probe(
    budget: &mut TimestampProbeBudget,
    session_budget: &mut TimestampSessionBudget,
) -> bool {
    let Some(attempted_probes) = budget.attempted_probes.checked_add(1) else {
        return false;
    };
    let reservation_bytes = BYTES_PER_EXTRACTION * 2;
    let reservation_operations = READ_OPERATIONS_PER_EXTRACTION * 2;
    let Some(reserved_bytes) = budget.reserved_bytes.checked_add(reservation_bytes) else {
        return false;
    };
    let Some(reserved_read_operations) = budget
        .reserved_read_operations
        .checked_add(reservation_operations)
    else {
        return false;
    };
    let Some(session_reserved_bytes) = session_budget.reserved_bytes.checked_add(reservation_bytes)
    else {
        session_budget.exhausted = true;
        return false;
    };
    let Some(session_reserved_read_operations) = session_budget
        .reserved_read_operations
        .checked_add(reservation_operations)
    else {
        session_budget.exhausted = true;
        return false;
    };
    if attempted_probes > MAX_TIMESTAMP_PROBES
        || reserved_bytes > MAX_TIMESTAMP_PROBE_BYTES
        || reserved_read_operations > MAX_TIMESTAMP_PROBE_READ_OPERATIONS
    {
        return false;
    }
    if session_reserved_bytes > session_budget.max_bytes
        || session_reserved_read_operations > session_budget.max_read_operations
    {
        session_budget.exhausted = true;
        return false;
    }
    budget.attempted_probes = attempted_probes;
    budget.reserved_bytes = reserved_bytes;
    budget.reserved_read_operations = reserved_read_operations;
    session_budget.reserved_bytes = session_reserved_bytes;
    session_budget.reserved_read_operations = session_reserved_read_operations;
    true
}

fn extraction_limits() -> ExtractionLimits {
    ExtractionLimits {
        max_total_bytes_read: BYTES_PER_EXTRACTION,
        max_read_operations: READ_OPERATIONS_PER_EXTRACTION,
        ..ExtractionLimits::default()
    }
    .effective()
}

fn probe_bound_source(
    volume: &guiying_volume::BoundVolumeSession,
    mut bound: BoundFileTicket,
    source_key: SourceKey,
    control: &dyn ScanControl,
    session_budget: &mut TimestampSessionBudget,
) -> Result<SourceVerifiedExtractionReport, TimestampProbeFailureCode> {
    if control.is_cancelled() {
        return Err(TimestampProbeFailureCode::Cancelled);
    }
    if session_budget.exhausted {
        return Err(TimestampProbeFailureCode::SessionBudgetExhausted);
    }
    let source_len = bound.file.initial_identity().size;
    let source = DescriptorReadAt::new(&mut bound.file, source_len, control, session_budget);
    let retained = extract_timestamp_evidence(&source, extraction_limits());
    let stopped_after_first = source.stop_code();
    let verified = stopped_after_first.map_or_else(
        || {
            Some(
                SourceVerifiedExtractionReport::revalidate_from_pinned_source(
                    source_key, &source, &retained,
                ),
            )
        },
        |_| None,
    );
    let stop_code = source.stop_code().or(stopped_after_first);
    match bound.file.verify_unchanged(volume, &bound.path) {
        Ok(true) => {}
        Ok(false) => return Err(TimestampProbeFailureCode::SourceChangedAfterRead),
        Err(_) => return Err(TimestampProbeFailureCode::SessionChangedAfterRead),
    }
    volume
        .revalidate()
        .map_err(|_| TimestampProbeFailureCode::SessionChangedAfterRead)?;
    if let Some(code) = stop_code {
        return Err(code);
    }
    verified
        .ok_or(TimestampProbeFailureCode::ReextractionMismatch)?
        .map_err(|_| TimestampProbeFailureCode::ReextractionMismatch)
}

fn report_has_io_failure(report: &ExtractionReport) -> bool {
    report.issues.iter().any(|issue| {
        matches!(
            issue.code,
            MetadataIssueCode::Io | MetadataIssueCode::UnexpectedEof
        )
    })
}

fn current_source_key(
    runtime: &ActiveReadOnlyScan,
    scope: &VerifiedExactTimestampScope,
    record: &FingerprintFileTicketRecord,
) -> Option<SourceKey> {
    let volume = runtime.volume.observation();
    let exact_fingerprint = exact_fingerprint_material(scope)?;
    let material = TimeSourceKeyMaterial::new(
        crate::RUNTIME_CONTRACT_VERSION,
        runtime.ids.scan_run_id,
        runtime.core_session_id,
        runtime.guard.mount_session_key,
        RootScopeKey::from_volume_adapter(*volume.root_scope_key().as_bytes()),
        StablePathKey::from_volume_adapter(*volume.stable_root_path_key().as_bytes()),
        root_object_signature(
            volume.root_identity(),
            runtime.guard.mount_session_key.as_bytes(),
        ),
        record.ticket.stable_path_key,
        record.ticket.source_signature,
        record.ticket.observation_id,
        record.fingerprint_id,
        scope.group.group_key,
        scope.group.manifest_digest,
        exact_fingerprint,
    )
    .ok()?;
    Some(SourceKey::new(
        *compute_time_source_key(&material).as_bytes(),
    ))
}

fn exact_lineage_key(scope: &VerifiedExactTimestampScope) -> Option<LineageKey> {
    let material = exact_fingerprint_material(scope)?;
    Some(LineageKey::new(
        *compute_time_lineage_key(&material).as_bytes(),
    ))
}

fn exact_fingerprint_material(
    scope: &VerifiedExactTimestampScope,
) -> Option<TimeExactFingerprintMaterial> {
    TimeExactFingerprintMaterial::new(
        scope.bucket.algorithm.clone(),
        scope.bucket.algorithm_version,
        scope.bucket.parameters_hash,
        scope.bucket.observed_size_bytes,
        scope.bucket.digest.clone(),
    )
    .ok()
}

/// A `ReadAtSource` view over one already-authorized volume descriptor.
/// Seeking is contained behind a private mutable borrow; no path is reopened.
struct DescriptorReadAt<'a> {
    file: RefCell<&'a mut ReadOnlyFile>,
    source_len: u64,
    control: &'a dyn ScanControl,
    session_budget: RefCell<&'a mut TimestampSessionBudget>,
}

impl<'a> DescriptorReadAt<'a> {
    fn new(
        file: &'a mut ReadOnlyFile,
        source_len: u64,
        control: &'a dyn ScanControl,
        session_budget: &'a mut TimestampSessionBudget,
    ) -> Self {
        Self {
            file: RefCell::new(file),
            source_len,
            control,
            session_budget: RefCell::new(session_budget),
        }
    }

    fn stop_code(&self) -> Option<TimestampProbeFailureCode> {
        if self.control.is_cancelled() {
            Some(TimestampProbeFailureCode::Cancelled)
        } else if self.session_budget.borrow().exhausted {
            Some(TimestampProbeFailureCode::SessionBudgetExhausted)
        } else {
            None
        }
    }
}

impl ReadAtSource for DescriptorReadAt<'_> {
    fn source_len(&self) -> io::Result<u64> {
        if self.control.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "timestamp extraction cancelled",
            ));
        }
        Ok(self.source_len)
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<usize> {
        if destination.is_empty() {
            return Ok(0);
        }
        if self.control.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "timestamp extraction cancelled",
            ));
        }
        let allowed = {
            let mut budget = self
                .session_budget
                .try_borrow_mut()
                .map_err(|_| io::Error::other("timestamp budget is already borrowed"))?;
            let Some(next_operations) = budget.actual_read_operations.checked_add(1) else {
                budget.exhausted = true;
                return Err(io::Error::other(
                    "timestamp read-operation budget exhausted",
                ));
            };
            if next_operations > budget.max_read_operations
                || budget.actual_bytes >= budget.max_bytes
            {
                budget.exhausted = true;
                return Err(io::Error::other("timestamp session read budget exhausted"));
            }
            let remaining = budget.max_bytes - budget.actual_bytes;
            let allowed = destination
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            if allowed == 0 {
                budget.exhausted = true;
                return Err(io::Error::other("timestamp session byte budget exhausted"));
            }
            budget.actual_read_operations = next_operations;
            allowed
        };
        let mut file = self
            .file
            .try_borrow_mut()
            .map_err(|_| io::Error::other("descriptor read is already borrowed"))?;
        file.seek(SeekFrom::Start(offset))?;
        if self.control.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "timestamp extraction cancelled",
            ));
        }
        let count = file.read(&mut destination[..allowed])?;
        drop(file);
        let mut budget = self
            .session_budget
            .try_borrow_mut()
            .map_err(|_| io::Error::other("timestamp budget is already borrowed"))?;
        let count = u64::try_from(count)
            .map_err(|_| io::Error::other("timestamp read count does not fit u64"))?;
        let Some(actual_bytes) = budget.actual_bytes.checked_add(count) else {
            budget.exhausted = true;
            return Err(io::Error::other("timestamp byte accounting overflow"));
        };
        if actual_bytes > budget.max_bytes {
            budget.exhausted = true;
            return Err(io::Error::other("timestamp session byte budget exhausted"));
        }
        budget.actual_bytes = actual_bytes;
        usize::try_from(count)
            .map_err(|_| io::Error::other("timestamp read count does not fit usize"))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use guiying_metadata::{DetectedFormat, ExtractionStatus, MetadataFieldKind};
    use guiying_time::{AnalysisDecision, OffsetKind, UtcInstant};

    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct RecordedGroup {
        build_id: i64,
        status: TimestampEvidenceStatus,
        metadata_fields: usize,
        analysis_candidates: usize,
    }

    #[derive(Default)]
    struct RecordingAdapter {
        calls: usize,
        reject_call: Option<usize>,
        groups: Vec<RecordedGroup>,
        finishes: Vec<TimestampStageStatus>,
    }

    impl TimestampEvidenceAdapter for RecordingAdapter {
        fn write_group(
            &mut self,
            _store: &mut Store,
            guard: &TimeEvidenceGuard,
            scope: &VerifiedExactTimestampScope,
            evidence: &CurrentSessionTimestampEvidence,
            _control: &dyn ScanControl,
        ) -> Result<TimestampPersistedGroupOutcome, crate::RuntimeError> {
            self.calls = self.calls.saturating_add(1);
            if self.reject_call == Some(self.calls) {
                return Err(crate::RuntimeError::Stream(
                    "synthetic time adapter rejection".to_owned(),
                ));
            }
            assert_eq!(guard.run().scan_run_id, scope.scan_run_id);
            assert_eq!(evidence.scan_run_id, scope.scan_run_id);
            self.groups.push(RecordedGroup {
                build_id: scope.group.build_id,
                status: evidence.status,
                metadata_fields: evidence
                    .verified
                    .as_ref()
                    .map_or(0, |verified| verified.report().fields.len()),
                analysis_candidates: evidence.analysis.candidates.len(),
            });
            Ok(match evidence.status {
                TimestampEvidenceStatus::Verified => TimestampPersistedGroupOutcome::Evidence,
                TimestampEvidenceStatus::Unavailable => TimestampPersistedGroupOutcome::Unavailable,
            })
        }

        fn finish_stage(
            &mut self,
            _store: &mut Store,
            _guard: &TimeEvidenceGuard,
            summary: &TimestampStageSummary,
        ) -> Result<(), crate::RuntimeError> {
            self.finishes.push(summary.status);
            Ok(())
        }
    }

    struct ShortReadSource {
        bytes: Vec<u8>,
        maximum_chunk: usize,
    }

    impl ReadAtSource for ShortReadSource {
        fn source_len(&self) -> io::Result<u64> {
            u64::try_from(self.bytes.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fixture too large"))
        }

        fn read_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<usize> {
            let start = usize::try_from(offset)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset too large"))?;
            if start >= self.bytes.len() || destination.is_empty() {
                return Ok(0);
            }
            let count = destination
                .len()
                .min(self.maximum_chunk)
                .min(self.bytes.len() - start);
            destination[..count].copy_from_slice(&self.bytes[start..start + count]);
            Ok(count)
        }
    }

    struct SwitchingSource {
        first: Vec<u8>,
        second: Vec<u8>,
        source_len_calls: Cell<u8>,
    }

    struct CancelAfterChecks {
        cancel_on_call: usize,
        calls: AtomicUsize,
    }

    impl CancelAfterChecks {
        const fn new(cancel_on_call: usize) -> Self {
            Self {
                cancel_on_call,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl ScanControl for CancelAfterChecks {
        fn is_cancelled(&self) -> bool {
            self.calls.fetch_add(1, Ordering::AcqRel).saturating_add(1) >= self.cancel_on_call
        }
    }

    impl ReadAtSource for SwitchingSource {
        fn source_len(&self) -> io::Result<u64> {
            let next = self.source_len_calls.get().saturating_add(1);
            self.source_len_calls.set(next);
            let bytes = if next <= 1 { &self.first } else { &self.second };
            u64::try_from(bytes.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fixture too large"))
        }

        fn read_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<usize> {
            let bytes = if self.source_len_calls.get() <= 1 {
                &self.first
            } else {
                &self.second
            };
            bytes.as_slice().read_at(offset, destination)
        }
    }

    #[test]
    fn short_reads_are_completed_and_offset_semantics_are_preserved() {
        let source = ShortReadSource {
            bytes: synthetic_tiff(b"2024:06:07 08:09:10\0", b"+08:00\0"),
            maximum_chunk: 1,
        };
        let retained = extract_timestamp_evidence(&source, extraction_limits());
        let source_key = SourceKey::new([7; 32]);
        let verified = SourceVerifiedExtractionReport::revalidate_from_pinned_source(
            source_key, &source, &retained,
        )
        .expect("one-byte short reads must reproduce exactly");
        let lineage = LineageKey::new([8; 32]);
        let context = PolicyContext::conservative(
            UtcInstant::new(1_800_000_000, 0).expect("fixture reference instant"),
        );
        let analysis = analyze_timestamp_evidence(
            &[EvidenceSource::source_verified(lineage, &verified)],
            &context,
        );
        let candidate = analysis.candidates.first().expect("Exif candidate");
        assert_eq!(
            candidate
                .timestamp
                .utc_offset()
                .expect("explicit offset")
                .minutes(),
            480
        );
        assert!(candidate.timestamp.utc_instant().is_some());
    }

    #[test]
    fn floating_exif_never_invents_the_system_timezone() {
        let source = synthetic_tiff(b"2024:06:07 08:09:10\0", b"\0\0\0\0\0\0\0");
        let retained = extract_timestamp_evidence(&source, extraction_limits());
        let verified = SourceVerifiedExtractionReport::revalidate_from_pinned_source(
            SourceKey::new([1; 32]),
            &source,
            &retained,
        )
        .expect("stable fixture reextracts");
        let context = PolicyContext::conservative(
            UtcInstant::new(1_800_000_000, 0).expect("fixture reference instant"),
        );
        let analysis = analyze_timestamp_evidence(
            &[EvidenceSource::source_verified(
                LineageKey::new([2; 32]),
                &verified,
            )],
            &context,
        );
        let timestamp = analysis
            .candidates
            .first()
            .expect("Exif candidate")
            .timestamp;
        assert_eq!(timestamp.offset_kind(), OffsetKind::Missing);
        assert!(timestamp.utc_offset().is_none());
        assert!(timestamp.utc_instant().is_none());
    }

    #[test]
    fn public_policy_clock_is_utc_only_and_never_supplies_a_local_wall_time() {
        let context = crate::conservative_policy_context_from_system_time()
            .expect("current UTC system clock");
        assert!(context.reference_wall_time.is_none());
        let json = policy_context_json(&context);
        assert_eq!(json["system_timezone_applied"], false);
        assert!(json["reference_wall_time"].is_null());
        assert!(json["reference_utc"]["unix_seconds_decimal"].is_string());
    }

    #[test]
    fn quicktime_mvhd_survives_double_extraction_but_remains_review_only() {
        let source = quicktime_movie(3_800_000_000);
        let retained = extract_timestamp_evidence(&source, extraction_limits());
        assert_eq!(retained.format, Some(DetectedFormat::IsoBmff));
        assert_eq!(retained.status, ExtractionStatus::ExtractedUnvalidated);
        assert_eq!(
            retained.fields[0].kind,
            MetadataFieldKind::QuickTimeMovieHeaderCreationTime
        );
        let verified = SourceVerifiedExtractionReport::revalidate_from_pinned_source(
            SourceKey::new([3; 32]),
            &source,
            &retained,
        )
        .expect("stable QuickTime fixture reextracts");
        let context = PolicyContext::conservative(
            UtcInstant::new(1_800_000_000, 0).expect("fixture reference instant"),
        );
        let analysis = analyze_timestamp_evidence(
            &[EvidenceSource::source_verified(
                LineageKey::new([4; 32]),
                &verified,
            )],
            &context,
        );
        assert_eq!(
            analysis.decision,
            AnalysisDecision::ReviewRequired { candidate_index: 0 }
        );
        assert_eq!(
            analysis.candidates[0].timestamp.offset_kind(),
            OffsetKind::QuickTimeEpochAssumedUtc
        );
    }

    #[test]
    fn a_change_between_extractions_cannot_produce_a_source_proof() {
        let source = SwitchingSource {
            first: synthetic_tiff(b"2024:06:07 08:09:10\0", b"+08:00\0"),
            second: synthetic_tiff(b"2025:06:07 08:09:10\0", b"+08:00\0"),
            source_len_calls: Cell::new(0),
        };
        let retained = extract_timestamp_evidence(&source, extraction_limits());
        let result = SourceVerifiedExtractionReport::revalidate_from_pinned_source(
            SourceKey::new([5; 32]),
            &source,
            &retained,
        );
        assert!(result.is_err());
    }

    #[test]
    fn aggregate_reservation_allows_exactly_four_two_pass_probes() {
        let mut budget = TimestampProbeBudget {
            attempted_probes: 0,
            reserved_bytes: 0,
            reserved_read_operations: 0,
        };
        let mut session_budget = TimestampSessionBudget::hard_limit();
        for _ in 0..MAX_TIMESTAMP_PROBES {
            assert!(reserve_probe(&mut budget, &mut session_budget));
        }
        assert!(!reserve_probe(&mut budget, &mut session_budget));
        assert_eq!(budget.attempted_probes, MAX_TIMESTAMP_PROBES);
        assert_eq!(budget.reserved_bytes, MAX_TIMESTAMP_PROBE_BYTES);
        assert_eq!(
            budget.reserved_read_operations,
            MAX_TIMESTAMP_PROBE_READ_OPERATIONS
        );
    }

    #[test]
    fn session_reservation_stops_before_starting_a_probe_beyond_the_global_limit() {
        let reservation_bytes = BYTES_PER_EXTRACTION * 2;
        let reservation_operations = READ_OPERATIONS_PER_EXTRACTION * 2;
        let mut session_budget =
            TimestampSessionBudget::with_limits(reservation_bytes, reservation_operations);
        let mut first_group = TimestampProbeBudget {
            attempted_probes: 0,
            reserved_bytes: 0,
            reserved_read_operations: 0,
        };
        assert!(reserve_probe(&mut first_group, &mut session_budget));

        let mut second_group = TimestampProbeBudget {
            attempted_probes: 0,
            reserved_bytes: 0,
            reserved_read_operations: 0,
        };
        assert!(!reserve_probe(&mut second_group, &mut session_budget));
        assert!(session_budget.exhausted);
        assert_eq!(session_budget.reserved_bytes, reservation_bytes);
        assert_eq!(
            session_budget.reserved_read_operations,
            reservation_operations
        );
        assert_eq!(second_group.attempted_probes, 0);
    }

    #[test]
    fn filesystem_time_assessment_never_promotes_missing_precision_or_missing_embedded_evidence() {
        use guiying_store::{DuplicateGroupMemberRecord, FileTimeRelation, FileTimestampParts};

        let candidate =
            guiying_time::parse_exif_timestamp(b"2024:06:07 08:09:10\0", None, Some(b"+08:00\0"))
                .expect("fixture timestamp");
        let instant = candidate.utc_instant().expect("explicit fixture offset");
        let member = DuplicateGroupMemberRecord {
            group_build_id: 1,
            ordinal: 0,
            observation_id: 2,
            fingerprint_id: 3,
            sort_rank: 0,
            stable_path_key: vec![1; 32],
            mount_relative_path_raw: b"a.tiff".to_vec(),
            root_relative_path_raw: b"a.tiff".to_vec(),
            path_encoding: "unix_bytes".to_owned(),
            display_path: "a.tiff".to_owned(),
            source_signature: vec![2; 32],
            size_bytes: 220,
            file_object_key: None,
            birth_time: Some(FileTimestampParts {
                seconds: i64::try_from(instant.unix_seconds()).expect("fixture instant fits i64"),
                nanoseconds: instant.nanosecond(),
            }),
            modified_time: FileTimestampParts {
                seconds: i64::try_from(instant.unix_seconds()).expect("fixture instant fits i64"),
                nanoseconds: instant.nanosecond(),
            },
            timestamp_granularity_ns: None,
        };
        let unknown = assess_member_filesystem_times(&member, Some((0, candidate)))
            .expect("missing FS precision remains review-only");
        assert_eq!(unknown.candidate_ordinal, Some(0));
        assert_eq!(
            unknown.birth_relation,
            FileTimeRelation::ReviewFsPrecisionUnknown
        );
        assert_eq!(
            unknown.modified_relation,
            FileTimeRelation::ReviewFsPrecisionUnknown
        );
        assert_eq!(unknown.reason_code, "fs_precision_unknown");

        let no_embedded = assess_member_filesystem_times(
            &DuplicateGroupMemberRecord {
                timestamp_granularity_ns: Some(1),
                ..member
            },
            None,
        )
        .expect("filesystem-only time remains non-candidate evidence");
        assert_eq!(no_embedded.candidate_ordinal, None);
        assert_eq!(no_embedded.birth_relation, FileTimeRelation::NotCompared);
        assert_eq!(no_embedded.modified_relation, FileTimeRelation::NotCompared);
        assert_eq!(no_embedded.reason_code, "no_strong_embedded_candidate");
    }

    #[test]
    fn lineage_depends_on_exact_content_not_copy_count_or_group_manifest() {
        use guiying_store::{ExactGroupKey, ManifestDigest, ParametersHash};

        let two_copy_bucket = FingerprintBucketRecord {
            fingerprint_kind: FreshFingerprintKind::ExactBytes,
            algorithm: "blake3".to_owned(),
            algorithm_version: 1,
            parameters_hash: ParametersHash::from_runtime_evidence([9; 32]),
            observed_size_bytes: 220,
            digest: vec![7; 32],
            member_count: 2,
        };
        let scope =
            |scan_run_id: i64,
             build_id: i64,
             manifest_byte: u8,
             bucket: FingerprintBucketRecord| VerifiedExactTimestampScope {
                scan_run_id,
                core_session_id: [u8::try_from(build_id).unwrap_or(u8::MAX); 32],
                mount_session_key: [3; 32],
                root_scope_key: [4; 32],
                group: VerifiedExactGroup {
                    build_id,
                    group_key: ExactGroupKey::from_runtime_evidence([manifest_byte ^ 0xff; 32]),
                    member_count: bucket.member_count,
                    edge_count: bucket.member_count - 1,
                    independent_file_count: bucket.member_count,
                    logical_reclaimable_bytes: bucket
                        .observed_size_bytes
                        .saturating_mul(bucket.member_count - 1),
                    manifest_digest: ManifestDigest::from_runtime_evidence([manifest_byte; 32]),
                    finalized_at_ms: build_id,
                },
                bucket,
                records: Vec::new(),
            };
        let two_copy_scope = scope(10, 1, 5, two_copy_bucket.clone());
        let mut three_copy_bucket = two_copy_bucket.clone();
        three_copy_bucket.member_count = 3;
        let three_copy_scope = scope(20, 2, 6, three_copy_bucket);
        assert_eq!(
            exact_lineage_key(&two_copy_scope),
            exact_lineage_key(&three_copy_scope),
            "run, group, manifest and copy count must not create another vote"
        );

        let mut different_content = two_copy_bucket;
        different_content.digest[0] ^= 0xff;
        let different_content_scope = scope(10, 1, 5, different_content);
        assert_ne!(
            exact_lineage_key(&two_copy_scope),
            exact_lineage_key(&different_content_scope)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn descriptor_bridge_rejects_path_replacement_then_uses_one_fallback_without_changing_d1(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::ffi::OsString;
        use std::fs;
        use std::os::unix::ffi::OsStringExt;

        use guiying_core::{NoopScanControl, ScanOptions};
        use tempfile::TempDir;

        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let payload = synthetic_tiff(b"2024:06:07 08:09:10\0", b"+08:00\0");
        let photos = media.path().join("photos");
        fs::create_dir(&photos)?;
        fs::write(photos.join("a.tiff"), &payload)?;
        fs::write(photos.join("b.tiff"), &payload)?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;
        let scope = finalize_only_exact_scope(&mut runtime)?;
        let exact_before = runtime
            .exact_duplicate_summary()
            .cloned()
            .ok_or("D1 summary disappeared after completion")?;
        let first = scope.records.first().ok_or("missing exact group probe")?;
        let replaced_path = media.path().join(OsString::from_vec(
            first.ticket.root_relative_path_raw.clone(),
        ));
        let backup_path = replaced_path
            .parent()
            .ok_or("replacement fixture lost its parent")?
            .join("replaced-source.backup");
        fs::rename(&replaced_path, backup_path)?;
        fs::write(&replaced_path, vec![0_u8; payload.len()])?;

        let context = PolicyContext::conservative(
            UtcInstant::new(1_800_000_000, 0).expect("fixture reference instant"),
        );
        let mut session_budget = TimestampSessionBudget::hard_limit();
        let evidence = probe_verified_exact_group(
            &runtime,
            &scope,
            &context,
            &guiying_core::NoopScanControl,
            &mut session_budget,
        );
        assert_eq!(evidence.status, TimestampEvidenceStatus::Verified);
        assert_eq!(evidence.scan_run_id, runtime.ids.scan_run_id);
        assert!(evidence.source_key.is_some());
        assert_eq!(evidence.lineage_key, exact_lineage_key(&scope));
        assert!(evidence.verified.is_some());
        assert!(!evidence.analysis.candidates.is_empty());
        assert_eq!(evidence.budget.attempted_probes, 2);
        assert_eq!(
            evidence.failures,
            &[TimestampProbeFailure {
                ordinal: 1,
                code: TimestampProbeFailureCode::TicketBindingRejected,
            }]
        );
        assert_eq!(scope.group.member_count, 2);
        assert_eq!(
            runtime.exact_duplicate_summary(),
            Some(&exact_before),
            "post-D1 metadata probing must not alter duplicate evidence"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn replacing_the_bound_volume_session_downgrades_without_reading_or_mutating_d1(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs;

        use guiying_core::{NoopScanControl, ScanOptions};
        use guiying_volume::BoundVolumeSession;
        use tempfile::TempDir;

        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let payload = quicktime_movie(3_800_000_000);
        fs::write(media.path().join("a.mov"), &payload)?;
        fs::write(media.path().join("b.mov"), &payload)?;
        let canonical_root = fs::canonicalize(media.path())?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            &canonical_root,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;
        let scope = finalize_only_exact_scope(&mut runtime)?;
        let exact_before = runtime
            .exact_duplicate_summary()
            .cloned()
            .ok_or("D1 summary disappeared after completion")?;
        runtime.volume = BoundVolumeSession::bind(&canonical_root)?;

        let context = PolicyContext::conservative(
            UtcInstant::new(1_800_000_000, 0).expect("fixture reference instant"),
        );
        let mut session_budget = TimestampSessionBudget::hard_limit();
        let evidence = probe_verified_exact_group(
            &runtime,
            &scope,
            &context,
            &guiying_core::NoopScanControl,
            &mut session_budget,
        );
        assert_eq!(evidence.status, TimestampEvidenceStatus::Unavailable);
        assert_eq!(evidence.budget.attempted_probes, 0);
        assert_eq!(
            evidence.failures,
            &[TimestampProbeFailure {
                ordinal: 0,
                code: TimestampProbeFailureCode::SessionBindingChanged,
            }]
        );
        assert_eq!(scope.group.member_count, 2);
        assert_eq!(
            runtime.exact_duplicate_summary(),
            Some(&exact_before),
            "session failure must not alter completed duplicate evidence"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cancellation_at_second_extraction_stops_before_another_descriptor_read(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs;

        use guiying_core::{NoopScanControl, ScanOptions};
        use tempfile::TempDir;

        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let payload = synthetic_tiff(b"2024:06:07 08:09:10\0", b"+08:00\0");
        fs::write(media.path().join("a.tiff"), &payload)?;
        fs::write(media.path().join("b.tiff"), &payload)?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;
        let scope = finalize_only_exact_scope(&mut runtime)?;
        let exact_before = runtime
            .exact_duplicate_summary()
            .cloned()
            .ok_or("D1 summary disappeared after completion")?;
        let record = scope
            .records
            .first()
            .ok_or("missing descriptor cancellation probe")?;
        let bound = bind_file_ticket(&runtime.volume, record.ticket.clone())?;
        let source_key = current_source_key(&runtime, &scope, record)
            .ok_or("sealed scope did not produce a Store-computed source key")?;

        let baseline = extract_timestamp_evidence(&payload, extraction_limits());
        let baseline_operations = usize::try_from(baseline.usage.read_operations)?;
        let cancel_on_call = baseline_operations
            .checked_mul(2)
            .and_then(|calls| calls.checked_add(5))
            .ok_or("cancellation check count overflow")?;
        let control = CancelAfterChecks::new(cancel_on_call);
        let mut group_budget = TimestampProbeBudget {
            attempted_probes: 0,
            reserved_bytes: 0,
            reserved_read_operations: 0,
        };
        let mut session_budget = TimestampSessionBudget::hard_limit();
        assert!(reserve_probe(&mut group_budget, &mut session_budget));

        let error = probe_bound_source(
            &runtime.volume,
            bound,
            source_key,
            &control,
            &mut session_budget,
        )
        .expect_err("cancellation during re-extraction produced a source proof");
        assert_eq!(error, TimestampProbeFailureCode::Cancelled);
        assert_eq!(
            session_budget.actual_read_operations, baseline.usage.read_operations,
            "the second pass must not perform another descriptor read after cancellation"
        );
        assert_eq!(session_budget.actual_bytes, baseline.usage.bytes_read);
        assert_eq!(
            runtime.exact_duplicate_summary(),
            Some(&exact_before),
            "cancellation must not alter completed duplicate evidence"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sealed_scope_pages_stream_each_group_and_adapter_failure_stays_post_d1(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs;

        use guiying_core::{CancellationToken, NoopScanControl, ScanOptions};
        use tempfile::TempDir;

        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let first = synthetic_tiff(b"2024:06:07 08:09:10\0", b"+08:00\0");
        let second = synthetic_tiff(b"2025:06:07 08:09:10\0", b"+08:00\0");
        for (name, payload) in [
            ("a-1.tiff", &first),
            ("a-2.tiff", &first),
            ("b-1.tiff", &second),
            ("b-2.tiff", &second),
        ] {
            fs::write(media.path().join(name), payload)?;
        }
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;
        let exact = runtime.verify_exact_duplicates(&NoopScanControl, &mut ())?;
        assert_eq!(exact.verified_groups, 2);

        let context = PolicyContext::conservative(
            UtcInstant::new(1_800_000_000, 0).expect("fixture reference instant"),
        );
        let mut adapter = RecordingAdapter::default();
        let summary = probe_sealed_exact_groups_with_page_limit(
            &mut runtime,
            &context,
            &NoopScanControl,
            &mut adapter,
            1,
        );
        assert_eq!(summary.status, TimestampStageStatus::Completed);
        assert_eq!(summary.groups_seen, 2);
        assert_eq!(summary.groups_written, 2);
        assert_eq!(summary.verified_groups, 2);
        assert_eq!(summary.unavailable_groups, 0);
        assert_eq!(summary.failed_groups, 0);
        assert_eq!(adapter.groups.len(), 2);
        assert_eq!(adapter.finishes, [TimestampStageStatus::Completed]);
        assert!(adapter
            .groups
            .iter()
            .all(|group| group.status == TimestampEvidenceStatus::Verified
                && group.metadata_fields >= 2
                && group.analysis_candidates == 1));

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut cancelled_adapter = RecordingAdapter::default();
        let cancelled = probe_sealed_exact_groups_with_page_limit(
            &mut runtime,
            &context,
            &cancellation,
            &mut cancelled_adapter,
            1,
        );
        assert_eq!(cancelled.status, TimestampStageStatus::Partial);
        assert_eq!(
            cancelled.failure,
            Some(TimestampStageFailureCode::Cancelled)
        );
        assert_eq!(cancelled.groups_seen, 0);
        assert_eq!(cancelled.session_budget.actual_bytes, 0);
        assert_eq!(cancelled.session_budget.actual_read_operations, 0);
        assert!(cancelled_adapter.groups.is_empty());
        assert_eq!(cancelled_adapter.finishes, [TimestampStageStatus::Partial]);

        let mut rejecting_adapter = RecordingAdapter {
            reject_call: Some(1),
            ..RecordingAdapter::default()
        };
        let partial = probe_sealed_exact_groups_with_page_limit(
            &mut runtime,
            &context,
            &NoopScanControl,
            &mut rejecting_adapter,
            1,
        );
        assert_eq!(partial.status, TimestampStageStatus::Partial);
        assert_eq!(partial.groups_seen, 1);
        assert_eq!(partial.groups_written, 0);
        assert_eq!(partial.verified_groups, 0);
        assert_eq!(partial.unavailable_groups, 0);
        assert_eq!(partial.failed_groups, 0);
        assert_eq!(rejecting_adapter.finishes, [TimestampStageStatus::Partial]);
        assert_eq!(
            partial.failure,
            Some(TimestampStageFailureCode::AdapterWriteRejected)
        );
        assert_eq!(runtime.exact_duplicate_summary(), Some(&exact));
        assert_eq!(exact.verified_groups, 2);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn durable_adapter_seals_verified_and_no_metadata_groups_without_touching_media(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::collections::BTreeMap;
        use std::fs;
        use std::time::SystemTime;

        use guiying_core::{NoopScanControl, ScanOptions};
        use guiying_store::{CaptureTimeDecision, FileTimeRelation, TimeDonorEligibility};
        use tempfile::TempDir;

        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let timestamped = synthetic_tiff(b"2024:06:07 08:09:10\0", b"+08:00\0");
        let unsupported = b"plain duplicate payload without a media container".to_vec();
        let fixtures = [
            ("timestamped-a.tiff", &timestamped),
            ("timestamped-b.tiff", &timestamped),
            ("unsupported-a.jpg", &unsupported),
            ("unsupported-b.jpg", &unsupported),
        ];
        for (name, payload) in fixtures {
            fs::write(media.path().join(name), payload)?;
        }
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;
        let exact = runtime.verify_exact_duplicates(&NoopScanControl, &mut ())?;
        assert_eq!(exact.verified_groups, 2);

        let before = fixtures
            .iter()
            .map(|(name, _)| {
                let path = media.path().join(name);
                let metadata = fs::metadata(&path)?;
                let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                Ok((name.to_string(), (fs::read(path)?, modified)))
            })
            .collect::<Result<BTreeMap<_, _>, io::Error>>()?;
        let context = PolicyContext::conservative(
            UtcInstant::new(1_800_000_000, 0).expect("fixture reference instant"),
        );
        let summary = persist_sealed_exact_group_times(&mut runtime, &context, &NoopScanControl)?;
        assert_eq!(summary.status, TimestampStageStatus::Completed);
        assert_eq!(summary.groups_seen, 2);
        assert_eq!(summary.groups_written, 2);
        assert_eq!(summary.verified_groups, 2);
        assert_eq!(summary.unavailable_groups, 0);
        assert_eq!(summary.failed_groups, 0);
        assert_eq!(runtime.exact_duplicate_summary(), Some(&exact));

        let page = runtime.store.list_capture_time_group_summaries_page(
            runtime.ids.scan_run_id,
            None,
            10,
        )?;
        assert!(page.next_cursor.is_none());
        assert_eq!(page.items.len(), 2);
        assert!(page.items.iter().all(|group| {
            group.source_count == 1
                && group.member_count == 2
                && group.evidence_only
                && !group.write_authorized
                && group.keeper_observation_id.is_none()
                && group.time_donor_observation_id.is_none()
        }));
        let eligible = page
            .items
            .iter()
            .find(|group| group.decision == CaptureTimeDecision::EvidenceEligible)
            .ok_or("timestamped group was not sealed evidence eligible")?;
        assert_eq!(eligible.observation_count, 2);
        assert_eq!(eligible.candidate_count, 1);
        assert_eq!(eligible.selected_candidate_ordinal, Some(0));
        let no_metadata = page
            .items
            .iter()
            .find(|group| group.decision == CaptureTimeDecision::NoUsableEvidence)
            .ok_or("unsupported group did not retain a no-usable-evidence analysis")?;
        assert_eq!(no_metadata.observation_count, 0);
        assert_eq!(no_metadata.candidate_count, 0);
        assert_eq!(no_metadata.selected_candidate_ordinal, None);

        for group in &page.items {
            let members = runtime.store.list_capture_time_members_page(
                runtime.ids.scan_run_id,
                group.exact_group_build_id,
                group.analysis_build_id,
                None,
                10,
            )?;
            assert!(members.next_cursor.is_none());
            assert_eq!(members.items.len(), 2);
            assert!(members
                .items
                .iter()
                .all(|member| member.donor_eligibility == TimeDonorEligibility::Ineligible));
            if group.decision == CaptureTimeDecision::NoUsableEvidence {
                assert!(members.items.iter().all(|member| {
                    member.candidate_ordinal.is_none()
                        && member.modified_time_relation == FileTimeRelation::NotCompared
                        && matches!(
                            member.birth_time_relation,
                            FileTimeRelation::Unavailable | FileTimeRelation::NotCompared
                        )
                        && member.reason_code == "no_strong_embedded_candidate"
                }));
            } else {
                assert!(members.items.iter().all(|member| {
                    member.candidate_ordinal == Some(0)
                        && if member.timestamp_granularity_ns.is_some() {
                            matches!(
                                member.modified_time_relation,
                                FileTimeRelation::Matches | FileTimeRelation::Differs
                            )
                        } else {
                            member.modified_time_relation
                                == FileTimeRelation::ReviewFsPrecisionUnknown
                                && member.reason_code == "fs_precision_unknown"
                        }
                }));
            }
        }

        for (name, _) in fixtures {
            let path = media.path().join(name);
            let expected = before.get(name).ok_or("missing pre-stage media snapshot")?;
            assert_eq!(
                fs::read(&path)?,
                expected.0,
                "media bytes changed for {name}"
            );
            assert_eq!(
                fs::metadata(path)?.modified()?,
                expected.1,
                "media mtime changed for {name}"
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn durable_adapter_cancellation_seals_partial_without_reading_or_changing_d1(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs;

        use guiying_core::{CancellationToken, NoopScanControl, ScanOptions};
        use tempfile::TempDir;

        let media = TempDir::new()?;
        let application = TempDir::new()?;
        let payload = synthetic_tiff(b"2024:06:07 08:09:10\0", b"+08:00\0");
        fs::write(media.path().join("a.tiff"), &payload)?;
        fs::write(media.path().join("b.tiff"), &payload)?;
        let mut runtime = ActiveReadOnlyScan::start(
            application.path().join("runtime.sqlite3"),
            fs::canonicalize(media.path())?,
            ScanOptions::default(),
        )?;
        runtime.enumerate(&NoopScanControl, &mut ())?;
        runtime.fingerprint_candidates(&NoopScanControl, &mut ())?;
        let exact = runtime.verify_exact_duplicates(&NoopScanControl, &mut ())?;
        assert_eq!(exact.verified_groups, 1);

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let summary = runtime.analyze_capture_times(&cancellation)?;
        assert_eq!(summary.status(), TimestampStageStatus::Partial);
        assert_eq!(
            summary.failure(),
            Some(TimestampStageFailureCode::Cancelled)
        );
        assert_eq!(summary.groups_seen(), 0);
        assert_eq!(summary.groups_written(), 0);
        assert_eq!(summary.actual_read_bytes(), 0);
        assert_eq!(summary.actual_read_operations(), 0);
        assert!(!summary.budget_exhausted());
        assert_eq!(runtime.exact_duplicate_summary(), Some(&exact));
        let page = runtime.store.list_capture_time_group_summaries_page(
            runtime.ids.scan_run_id,
            None,
            10,
        )?;
        assert!(page.items.is_empty());
        assert!(page.next_cursor.is_none());
        assert_eq!(fs::read(media.path().join("a.tiff"))?, payload);
        assert_eq!(fs::read(media.path().join("b.tiff"))?, payload);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn finalize_only_exact_scope(
        runtime: &mut ActiveReadOnlyScan,
    ) -> Result<VerifiedExactTimestampScope, Box<dyn std::error::Error>> {
        let summary = runtime.verify_exact_duplicates(&guiying_core::NoopScanControl, &mut ())?;
        if summary.verified_groups != 1 {
            return Err("expected exactly one sealed verified exact group".into());
        }
        let guard = runtime
            .store
            .time_evidence_guard(runtime.guard, runtime.core_session_id)?;
        let page = runtime
            .store
            .list_verified_time_probe_scopes_page(&guard, None, 10)?;
        if page.items.len() != 1 {
            return Err("expected exactly one sealed time probe scope".into());
        }
        if page.next_cursor.is_some() {
            return Err("one sealed group unexpectedly produced another page".into());
        }
        let record = page
            .items
            .into_iter()
            .next()
            .ok_or("sealed time probe scope disappeared")?;
        let mut wrong_run = record.clone();
        wrong_run.scan_run_id = wrong_run.scan_run_id.saturating_add(1);
        if VerifiedExactTimestampScope::from_store_record(runtime, wrong_run).is_some() {
            return Err("scope constructor accepted another scan run".into());
        }
        VerifiedExactTimestampScope::from_store_record(runtime, record)
            .ok_or_else(|| "sealed time probe scope failed runtime binding".into())
    }

    fn synthetic_tiff(original: &[u8], offset: &[u8]) -> Vec<u8> {
        assert_eq!(original.len(), 20);
        assert_eq!(offset.len(), 7);
        let mut bytes = vec![0_u8; 220];
        bytes[0..8].copy_from_slice(b"II\x2a\x00\x08\x00\x00\x00");
        put_u16_le(&mut bytes, 8, 1);
        put_ifd_entry_le(&mut bytes, 10, 0x8769, 4, 1, 64);
        put_u32_le(&mut bytes, 22, 0);
        put_u16_le(&mut bytes, 64, 2);
        put_ifd_entry_le(&mut bytes, 66, 0x9003, 2, 20, 150);
        put_ifd_entry_le(&mut bytes, 78, 0x9011, 2, 7, 180);
        put_u32_le(&mut bytes, 90, 0);
        bytes[150..170].copy_from_slice(original);
        bytes[180..187].copy_from_slice(offset);
        bytes
    }

    fn quicktime_movie(creation_time: u32) -> Vec<u8> {
        let mut payload = vec![0_u8; 20];
        payload[4..8].copy_from_slice(&creation_time.to_be_bytes());
        let mut movie = bmff_box(*b"ftyp", b"qt  \0\0\0\0".to_vec());
        movie.extend_from_slice(&bmff_box(*b"moov", bmff_box(*b"mvhd", payload)));
        movie
    }

    fn bmff_box(box_type: [u8; 4], payload: Vec<u8>) -> Vec<u8> {
        let size = u32::try_from(payload.len() + 8).expect("fixture box size");
        let mut bytes =
            Vec::with_capacity(usize::try_from(size).expect("u32 fixture size fits usize"));
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.extend_from_slice(&box_type);
        bytes.extend_from_slice(&payload);
        bytes
    }

    fn put_ifd_entry_le(
        bytes: &mut [u8],
        offset: usize,
        tag: u16,
        field_type: u16,
        count: u32,
        value: u32,
    ) {
        put_u16_le(bytes, offset, tag);
        put_u16_le(bytes, offset + 2, field_type);
        put_u32_le(bytes, offset + 4, count);
        put_u32_le(bytes, offset + 8, value);
    }

    fn put_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
