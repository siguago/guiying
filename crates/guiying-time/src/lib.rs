#![forbid(unsafe_code)]
//! Pure timestamp normalization and fail-closed evidence policy for Guiying.
//!
//! [`EvidenceGateDecision::Eligible`] is an evidence-policy result, not
//! authorization to mutate a file. The execution layer must independently
//! enforce volume capability, frozen-plan, read-back, content-integrity,
//! audit-log, user-confirmation, and donor-preservation gates.

mod calendar;
mod parse;
mod policy;

use guiying_metadata::{
    extract_timestamp_evidence, ExtractionReport, ExtractionStatus, MetadataField,
    MetadataFieldKind, MetadataIssue, ParserIdentity, ReadAtSource,
};

pub use parse::{
    parse_exif_timestamp, parse_quicktime_mvhd, parse_quicktime_timestamp, TimestampParseError,
};
pub use policy::analyze_timestamp_evidence;

/// Nanoseconds in one whole second.
pub const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// Parser-policy hard ceiling; caller configuration can only tighten it.
pub const MAX_STRONG_EVIDENCE_TOLERANCE_SECONDS: u64 = 5;
/// Integer-hour residual hard ceiling; caller configuration can only tighten it.
pub const MAX_INTEGER_HOUR_RESIDUAL_TOLERANCE_SECONDS: u64 = 5;
/// Future-clock tolerance hard ceiling; caller configuration can only tighten it.
pub const MAX_OBVIOUS_FUTURE_TOLERANCE_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Real-world offset suspicion is never extended beyond ±14 hours.
pub const MAX_SUSPECTED_OFFSET_HOURS: u8 = 14;

/// Maximum number of concrete sources accepted by one policy analysis.
pub const MAX_ANALYSIS_SOURCES: usize = 4_096;
/// Maximum number of retained metadata fields accepted across all sources.
pub const MAX_ANALYSIS_OBSERVATIONS: usize = 8_192;
/// Maximum number of extractor issues accepted across all sources.
pub const MAX_ANALYSIS_EXTRACTION_ISSUES: usize = 8_192;
/// Maximum number of raw metadata bytes retained across all sources.
pub const MAX_ANALYSIS_RAW_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum number of caller-supplied sentinel rules accepted by one analysis.
pub const MAX_ANALYSIS_SENTINEL_RULES: usize = 1_024;
/// Maximum aggregate number of retained ISO BMFF locator path components.
pub const MAX_ANALYSIS_BMFF_PATH_COMPONENTS: usize = 6 * MAX_ANALYSIS_OBSERVATIONS;
/// Conservative ceiling used to bound all generated policy diagnostics.
pub const MAX_ANALYSIS_POLICY_ISSUES: usize = 262_144;

const HARD_SENTINEL_YEARS: [u16; 3] = [1904, 1970, 1980];
const MIN_AUTOMATIC_UNIX_NANOSECONDS: i128 = i64::MIN as i128;
const MAX_AUTOMATIC_UNIX_NANOSECONDS: i128 = i64::MAX as i128;

/// Identity persisted with normalized candidates and policy decisions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PolicyIdentity {
    pub name: &'static str,
    pub version: &'static str,
}

pub const POLICY_IDENTITY: PolicyIdentity = PolicyIdentity {
    name: "guiying-time",
    version: env!("CARGO_PKG_VERSION"),
};

/// A calendar date and wall-clock time with no implicit timezone.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WallTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
}

impl WallTime {
    /// Construct a strictly valid proleptic-Gregorian wall time.
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
    ) -> Result<Self, TimestampParseError> {
        calendar::validate_components(year, month, day, hour, minute, second, nanosecond)?;
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
        })
    }

    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }

    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }

    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }

    #[must_use]
    pub const fn hour(self) -> u8 {
        self.hour
    }

    #[must_use]
    pub const fn minute(self) -> u8 {
        self.minute
    }

    #[must_use]
    pub const fn second(self) -> u8 {
        self.second
    }

    #[must_use]
    pub const fn nanosecond(self) -> u32 {
        self.nanosecond
    }

    pub(crate) fn with_nanosecond(self, nanosecond: u32) -> Result<Self, TimestampParseError> {
        Self::new(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            nanosecond,
        )
    }

    pub(crate) fn naive_unix_seconds(self) -> i128 {
        calendar::wall_time_to_unix_seconds(self)
    }
}

/// A UTC instant represented without the narrower database nanosecond range.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcInstant {
    unix_seconds: i128,
    nanosecond: u32,
}

impl UtcInstant {
    /// Construct an instant. Nanoseconds must be in `0..1_000_000_000`.
    pub fn new(unix_seconds: i128, nanosecond: u32) -> Result<Self, TimestampParseError> {
        if nanosecond >= NANOS_PER_SECOND {
            return Err(TimestampParseError::NanosecondOutOfRange);
        }
        Ok(Self {
            unix_seconds,
            nanosecond,
        })
    }

    #[must_use]
    pub const fn unix_seconds(self) -> i128 {
        self.unix_seconds
    }

    #[must_use]
    pub const fn nanosecond(self) -> u32 {
        self.nanosecond
    }

    pub(crate) fn total_nanoseconds(self) -> Option<i128> {
        self.unix_seconds
            .checked_mul(i128::from(NANOS_PER_SECOND))?
            .checked_add(i128::from(self.nanosecond))
    }
}

/// A validated UTC offset in whole minutes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcOffset {
    minutes: i16,
}

impl UtcOffset {
    /// Construct an offset in the conservative ISO-8601 range ±14:00.
    pub fn from_minutes(minutes: i16) -> Result<Self, TimestampParseError> {
        if !(-840..=840).contains(&minutes) {
            return Err(TimestampParseError::OffsetOutOfRange);
        }
        Ok(Self { minutes })
    }

    #[must_use]
    pub const fn minutes(self) -> i16 {
        self.minutes
    }
}

/// How the UTC offset was obtained.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OffsetKind {
    /// The media field explicitly carried `Z` or a signed offset.
    Explicit,
    /// ISO-BMFF `mvhd` is specified relative to 1904 UTC, but real-world
    /// writers have historically used inconsistent semantics.
    QuickTimeEpochAssumedUtc,
    /// No offset was present. The value remains a floating wall time.
    Missing,
}

/// Source resolution of a normalized timestamp.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TimePrecision {
    nanoseconds: u32,
}

impl TimePrecision {
    /// Construct a precision from 1 nanosecond through 1 second.
    pub fn from_nanoseconds(nanoseconds: u32) -> Result<Self, TimestampParseError> {
        if nanoseconds == 0 || nanoseconds > NANOS_PER_SECOND {
            return Err(TimestampParseError::PrecisionOutOfRange);
        }
        Ok(Self { nanoseconds })
    }

    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }

    pub(crate) const fn seconds() -> Self {
        Self {
            nanoseconds: NANOS_PER_SECOND,
        }
    }
}

/// Strictly normalized timestamp while retaining floating-time semantics.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedTimestamp {
    wall_time: WallTime,
    utc_offset: Option<UtcOffset>,
    utc_instant: Option<UtcInstant>,
    offset_kind: OffsetKind,
    precision: TimePrecision,
}

impl NormalizedTimestamp {
    #[must_use]
    pub const fn wall_time(self) -> WallTime {
        self.wall_time
    }

    #[must_use]
    pub const fn utc_offset(self) -> Option<UtcOffset> {
        self.utc_offset
    }

    /// Return `None` for a floating wall time. No system timezone is applied.
    #[must_use]
    pub const fn utc_instant(self) -> Option<UtcInstant> {
        self.utc_instant
    }

    #[must_use]
    pub const fn offset_kind(self) -> OffsetKind {
        self.offset_kind
    }

    #[must_use]
    pub const fn precision(self) -> TimePrecision {
        self.precision
    }

    pub(crate) fn floating(wall_time: WallTime, precision: TimePrecision) -> Self {
        Self {
            wall_time,
            utc_offset: None,
            utc_instant: None,
            offset_kind: OffsetKind::Missing,
            precision,
        }
    }

    pub(crate) fn explicit(
        wall_time: WallTime,
        offset: UtcOffset,
        precision: TimePrecision,
    ) -> Result<Self, TimestampParseError> {
        let utc_seconds = wall_time
            .naive_unix_seconds()
            .checked_sub(i128::from(offset.minutes()) * 60)
            .ok_or(TimestampParseError::ArithmeticOverflow)?;
        let instant = UtcInstant::new(utc_seconds, wall_time.nanosecond())?;
        Ok(Self {
            wall_time,
            utc_offset: Some(offset),
            utc_instant: Some(instant),
            offset_kind: OffsetKind::Explicit,
            precision,
        })
    }

    pub(crate) fn quicktime_epoch(
        wall_time: WallTime,
        instant: UtcInstant,
    ) -> Result<Self, TimestampParseError> {
        Ok(Self {
            wall_time,
            utc_offset: Some(UtcOffset::from_minutes(0)?),
            utc_instant: Some(instant),
            offset_kind: OffsetKind::QuickTimeEpochAssumedUtc,
            precision: TimePrecision::seconds(),
        })
    }
}

/// Caller-defined identity for one concrete input source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceKey([u8; 32]);

impl SourceKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Provenance family used to prevent copy-count voting.
///
/// Exact or copy-derived duplicates must receive the same key. A candidate's
/// support is deduplicated by this key, never by the number of file copies.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LineageKey([u8; 32]);

impl LineageKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Whether raw locators were re-extracted from the caller's pinned source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EvidenceBindingStatus {
    /// The report is retained for review, but its raw bytes have not been
    /// re-read from a pinned source in this process.
    Unverified,
    /// The opaque report was produced by a fresh bounded extraction from the
    /// pinned source supplied by the runtime.
    ReextractedFromPinnedSource,
}

/// Failure to reproduce a retained extraction report from a pinned source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SourceRevalidationError {
    /// The fresh extraction differed in any parser identity, limit, status,
    /// field, raw byte, locator, issue, format, or usage counter.
    ReportMismatch,
}

/// Opaque proof that a retained report was reproduced by a second extraction.
///
/// The runtime must pass a stable, already-authorized and identity-checked
/// [`ReadAtSource`] such as a pinned file handle. This wrapper proves only the
/// bounded re-extraction and byte re-read. It does not replace the execution
/// layer's later file-identity, full-content-hash, frozen-plan, volume,
/// read-back, audit-log, or user-confirmation gates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceVerifiedExtractionReport {
    source_key: SourceKey,
    report: ExtractionReport,
}

impl SourceVerifiedExtractionReport {
    /// Re-extract from a pinned source and require exact report equality.
    ///
    /// `source_key` must be the runtime's already-checked identity for that
    /// pinned handle. It is sealed into the returned proof and is the only
    /// concrete source identity later used by [`EvidenceSource::source_verified`].
    ///
    /// # Errors
    ///
    /// Returns [`SourceRevalidationError::ReportMismatch`] when any retained
    /// evidence or extraction-accounting value differs.
    pub fn revalidate_from_pinned_source(
        source_key: SourceKey,
        source: &dyn ReadAtSource,
        retained: &ExtractionReport,
    ) -> Result<Self, SourceRevalidationError> {
        let reextracted = extract_timestamp_evidence(source, retained.limits);
        if reextracted == *retained {
            Ok(Self {
                source_key,
                report: reextracted,
            })
        } else {
            Err(SourceRevalidationError::ReportMismatch)
        }
    }

    #[must_use]
    pub const fn report(&self) -> &ExtractionReport {
        &self.report
    }

    /// Return the concrete source identity bound during pinned re-extraction.
    #[must_use]
    pub const fn source_key(&self) -> SourceKey {
        self.source_key
    }
}

/// One metadata extraction report and its caller-proven source identities.
///
/// Construct unverified evidence with [`EvidenceSource::unverified`] for audit
/// and review. Only [`EvidenceSource::source_verified`] can contribute to an
/// eligible automatic evidence decision.
#[derive(Clone, Copy, Debug)]
pub struct EvidenceSource<'a> {
    source_key: SourceKey,
    pub lineage_key: LineageKey,
    report: &'a ExtractionReport,
    binding: EvidenceBindingStatus,
}

impl<'a> EvidenceSource<'a> {
    /// Retain an extraction report for parsing and review without claiming
    /// that its locators were re-read from the current source.
    #[must_use]
    pub const fn unverified(
        source_key: SourceKey,
        lineage_key: LineageKey,
        report: &'a ExtractionReport,
    ) -> Self {
        Self {
            source_key,
            lineage_key,
            report,
            binding: EvidenceBindingStatus::Unverified,
        }
    }

    /// Use an opaque fresh-extraction proof from a runtime-pinned source.
    ///
    /// The concrete [`SourceKey`] is taken from the proof and cannot be
    /// supplied or replaced at this stage. The lineage remains a separate
    /// caller assertion used only for copy-family conflict policy.
    #[must_use]
    pub const fn source_verified(
        lineage_key: LineageKey,
        verified: &'a SourceVerifiedExtractionReport,
    ) -> Self {
        Self {
            source_key: verified.source_key(),
            lineage_key,
            report: verified.report(),
            binding: EvidenceBindingStatus::ReextractedFromPinnedSource,
        }
    }

    /// Return the concrete source identity associated with this evidence.
    #[must_use]
    pub const fn source_key(self) -> SourceKey {
        self.source_key
    }

    #[must_use]
    pub const fn report(self) -> &'a ExtractionReport {
        self.report
    }

    #[must_use]
    pub const fn binding(self) -> EvidenceBindingStatus {
        self.binding
    }
}

/// An additional caller-controlled sentinel rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SentinelRule {
    Year(u16),
    Date { year: u16, month: u8, day: u8 },
    WallTime(WallTime),
    UnixSecond(i128),
}

/// Explicit inputs controlling plausibility and conflict policy.
///
/// This type never reads the clock or current timezone. Floating future checks
/// happen only when `reference_wall_time` is supplied by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyContext {
    pub reference_utc: UtcInstant,
    pub reference_wall_time: Option<WallTime>,
    /// Optional caller tightening of the hard signed-64-bit nanosecond floor.
    pub automatic_earliest_utc: Option<UtcInstant>,
    /// Optional caller tightening of the hard signed-64-bit nanosecond ceiling.
    pub automatic_latest_utc: Option<UtcInstant>,
    pub obvious_future_tolerance_seconds: u64,
    pub strong_evidence_tolerance_seconds: u64,
    pub integer_hour_residual_tolerance_seconds: u64,
    pub maximum_suspected_offset_hours: u8,
    pub sentinel_rules: Vec<SentinelRule>,
}

impl PolicyContext {
    /// Conservative defaults. Non-removable 1904, 1970, and 1980 year
    /// sentinels are enforced separately. The caller must supply the reference
    /// instant and may add stricter sentinel rules or automatic-time bounds.
    #[must_use]
    pub fn conservative(reference_utc: UtcInstant) -> Self {
        Self {
            reference_utc,
            reference_wall_time: None,
            automatic_earliest_utc: None,
            automatic_latest_utc: None,
            obvious_future_tolerance_seconds: 48 * 60 * 60,
            strong_evidence_tolerance_seconds: 2,
            integer_hour_residual_tolerance_seconds: 2,
            maximum_suspected_offset_hours: 14,
            sentinel_rules: Vec::new(),
        }
    }
}

/// Strict interpretation retained beside every raw metadata field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationInterpretation {
    Timestamp(NormalizedTimestamp),
    Offset(UtcOffset),
    Subsecond {
        nanosecond: u32,
        digits: u8,
        precision: TimePrecision,
    },
    Rejected(TimestampParseError),
}

/// Raw evidence, its source identity, and the strict parse result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceObservation {
    pub source_key: SourceKey,
    pub lineage_key: LineageKey,
    /// Exact raw bytes, parser identity, encoding, and byte locator.
    pub field: MetadataField,
    pub interpretation: ObservationInterpretation,
}

/// Timestamp evidence source semantics.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TimeEvidenceKind {
    ExifDateTimeOriginal,
    ExifCreateDate,
    ExifModifyDate,
    QuickTimeMetadataCreationDate,
    QuickTimeMovieHeaderCreationTime,
}

/// Candidate confidence from this evidence policy only.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Confidence {
    Conflict,
    Low,
    Medium,
    High,
}

/// Candidate anomaly retained for UI and audit explanations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CandidateAnomaly {
    MissingOffset,
    SentinelValue,
    ObviousFuture,
    OutsideAutomaticRange,
    QuickTimeEpochSemanticUncertainty,
    InvalidCompanion,
}

/// Why timestamp evidence cannot enter an automatic repair plan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EvidenceGateBlocker {
    ConfidenceBelowHigh,
    NoUtcInstant,
    EvidenceConflict,
    SentinelValue,
    ObviousFuture,
    OutsideAutomaticRange,
    QuickTimeEpochSemanticUncertainty,
    InvalidEvidencePresent,
    ExtractionReportUntrusted,
    SourceNotRevalidated,
    MultipleStrongValuesWithinTolerance,
}

/// Evidence-only action gate. This never authorizes a filesystem mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceGateDecision {
    /// The timestamp evidence may be passed to the independent execution
    /// safety gates. No write is authorized by this value.
    Eligible,
    Blocked(Vec<EvidenceGateBlocker>),
}

/// A normalized candidate with auditable, lineage-deduplicated support.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeCandidate {
    pub timestamp: NormalizedTimestamp,
    pub evidence_kinds: Vec<TimeEvidenceKind>,
    pub supporting_sources: Vec<SourceKey>,
    pub supporting_lineages: Vec<LineageKey>,
    pub observation_indices: Vec<usize>,
    pub confidence: Confidence,
    pub anomalies: Vec<CandidateAnomaly>,
    pub evidence_gate: EvidenceGateDecision,
}

/// Policy issue classification. Source bytes are referenced through
/// `observation_indices`, not copied into diagnostic strings.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PolicyIssueCode {
    InvalidField,
    InvalidCompanion,
    OrphanExifCompanion,
    RepeatedFieldConflict,
    LineageConflict,
    StrongEvidenceConflict,
    StrongEvidenceWithinToleranceAmbiguous,
    PossibleTimezoneConflict,
    SentinelValue,
    ObviousFuture,
    OutsideAutomaticRange,
    QuickTimeEpochSemanticUncertainty,
    ExtractionReportUntrusted,
    ExtractionReportContradiction,
    ParserIdentityMismatch,
    FieldEncodingMismatch,
    ContainerFormatMismatch,
    MetadataLocatorMismatch,
    DuplicateSourceIdentity,
    UnknownParserIdentity,
    ExtractionBudgetContradiction,
    AnalysisLimitExceeded,
}

/// Bounded, raw-byte-free policy diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyIssue {
    pub code: PolicyIssueCode,
    pub field_kind: Option<MetadataFieldKind>,
    pub observation_indices: Vec<usize>,
    pub source_keys: Vec<SourceKey>,
    pub lineage_keys: Vec<LineageKey>,
    pub context: &'static str,
}

/// Original extractor issue with caller-proven source identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceExtractionIssue {
    pub source_key: SourceKey,
    pub lineage_key: LineageKey,
    pub issue: MetadataIssue,
}

/// Extraction status retained even when a report emitted no field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceReportStatus {
    pub source_key: SourceKey,
    pub lineage_key: LineageKey,
    pub parser: ParserIdentity,
    pub status: ExtractionStatus,
    pub binding: EvidenceBindingStatus,
}

/// Final evidence-policy decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisDecision {
    NoUsableEvidence,
    ReviewRequired {
        candidate_index: usize,
    },
    /// Evidence-only recommendation; see [`EvidenceGateDecision`].
    EvidenceEligible {
        candidate_index: usize,
    },
    Conflict,
}

/// Complete, audit-friendly result of normalization and policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeAnalysis {
    pub policy: PolicyIdentity,
    pub source_reports: Vec<SourceReportStatus>,
    pub extraction_issues: Vec<SourceExtractionIssue>,
    pub observations: Vec<EvidenceObservation>,
    pub candidates: Vec<TimeCandidate>,
    pub issues: Vec<PolicyIssue>,
    pub decision: AnalysisDecision,
}
