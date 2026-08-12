use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use guiying_metadata::{
    DetectedFormat, ExtractionStatus, FieldEncoding, MetadataContainer, MetadataField,
    MetadataFieldKind, PARSER_IDENTITY,
};

use crate::parse::{parse_offset, parse_subsecond};
use crate::{
    parse_exif_timestamp, parse_quicktime_mvhd, parse_quicktime_timestamp, AnalysisDecision,
    CandidateAnomaly, Confidence, EvidenceBindingStatus, EvidenceGateBlocker, EvidenceGateDecision,
    EvidenceObservation, EvidenceSource, LineageKey, NormalizedTimestamp,
    ObservationInterpretation, PolicyContext, PolicyIssue, PolicyIssueCode, SourceExtractionIssue,
    SourceKey, SourceReportStatus, TimeAnalysis, TimeCandidate, TimeEvidenceKind, TimePrecision,
    UtcOffset, HARD_SENTINEL_YEARS, MAX_ANALYSIS_BMFF_PATH_COMPONENTS,
    MAX_ANALYSIS_EXTRACTION_ISSUES, MAX_ANALYSIS_OBSERVATIONS, MAX_ANALYSIS_POLICY_ISSUES,
    MAX_ANALYSIS_RAW_BYTES, MAX_ANALYSIS_SENTINEL_RULES, MAX_ANALYSIS_SOURCES,
    MAX_AUTOMATIC_UNIX_NANOSECONDS, MAX_INTEGER_HOUR_RESIDUAL_TOLERANCE_SECONDS,
    MAX_OBVIOUS_FUTURE_TOLERANCE_SECONDS, MAX_STRONG_EVIDENCE_TOLERANCE_SECONDS,
    MAX_SUSPECTED_OFFSET_HOURS, MIN_AUTOMATIC_UNIX_NANOSECONDS, NANOS_PER_SECOND, POLICY_IDENTITY,
};

const MAX_BMFF_PATH_COMPONENTS_PER_FIELD: usize = 6;

#[derive(Clone, Debug)]
struct Atom {
    timestamp: NormalizedTimestamp,
    kind: TimeEvidenceKind,
    source_key: SourceKey,
    lineage_key: LineageKey,
    observation_indices: Vec<usize>,
    base_confidence: Confidence,
    strong: bool,
    conflicted: bool,
    invalid_companion: bool,
    source_verified: bool,
}

#[derive(Clone, Debug)]
struct CandidateWork {
    timestamp: NormalizedTimestamp,
    kinds: Vec<TimeEvidenceKind>,
    sources: Vec<SourceKey>,
    lineages: Vec<LineageKey>,
    observations: Vec<usize>,
    base_confidence: Confidence,
    conflicted: bool,
    invalid_companion: bool,
    all_sources_verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ExifScope {
    Tiff {
        header_offset: u64,
        ifd_offset: u64,
    },
    JpegExif {
        app1_offset: u64,
        header_offset: u64,
        ifd_offset: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SemanticTimestamp {
    Utc(crate::UtcInstant),
    Floating(crate::WallTime, TimePrecision),
}

#[derive(Debug, Default)]
struct SentinelIndex {
    years: BTreeSet<u16>,
    dates: BTreeSet<(u16, u8, u8)>,
    wall_times: BTreeSet<crate::WallTime>,
    unix_seconds: BTreeSet<i128>,
}

impl SentinelIndex {
    fn from_rules(rules: &[crate::SentinelRule]) -> Self {
        let mut index = Self::default();
        for rule in rules {
            match *rule {
                crate::SentinelRule::Year(year) => {
                    index.years.insert(year);
                }
                crate::SentinelRule::Date { year, month, day } => {
                    index.dates.insert((year, month, day));
                }
                crate::SentinelRule::WallTime(value) => {
                    index.wall_times.insert(value);
                }
                crate::SentinelRule::UnixSecond(value) => {
                    index.unix_seconds.insert(value);
                }
            }
        }
        index
    }

    fn matches(&self, timestamp: NormalizedTimestamp) -> bool {
        let wall = timestamp.wall_time();
        self.years.contains(&wall.year())
            || self
                .dates
                .contains(&(wall.year(), wall.month(), wall.day()))
            || self.wall_times.contains(&wall)
            || timestamp
                .utc_instant()
                .is_some_and(|instant| self.unix_seconds.contains(&instant.unix_seconds()))
    }
}

/// Strictly normalize extractor reports and evaluate timestamp evidence.
///
/// The result never authorizes a filesystem mutation. In particular,
/// `ExtractedUnvalidated` merely permits this function to validate raw fields;
/// it is not mapped directly to confidence or action eligibility.
#[must_use]
pub fn analyze_timestamp_evidence(
    sources: &[EvidenceSource<'_>],
    context: &PolicyContext,
) -> TimeAnalysis {
    if !aggregate_within_limits(sources, context) {
        return analysis_limit_exceeded();
    }
    let sentinel_index = SentinelIndex::from_rules(&context.sentinel_rules);

    let mut source_reports = Vec::with_capacity(sources.len());
    let mut extraction_issues = Vec::new();
    let mut observations = Vec::new();
    let mut issues = Vec::new();
    let mut atoms = Vec::new();
    let mut extraction_untrusted = false;
    let mut invalid_evidence = false;
    let mut seen_source_keys = BTreeSet::new();

    for source in sources {
        if !seen_source_keys.insert(source.source_key) {
            extraction_untrusted = true;
            issues.push(source_issue(
                PolicyIssueCode::DuplicateSourceIdentity,
                source.source_key,
                source.lineage_key,
                "one concrete source identity was supplied more than once",
            ));
        }
        source_reports.push(SourceReportStatus {
            source_key: source.source_key,
            lineage_key: source.lineage_key,
            parser: source.report.parser,
            status: source.report.status,
            binding: source.binding(),
        });
        extraction_issues.extend(source.report.issues.iter().cloned().map(|issue| {
            SourceExtractionIssue {
                source_key: source.source_key,
                lineage_key: source.lineage_key,
                issue,
            }
        }));

        let range_start = observations.len();
        let mut source_contradiction = false;
        if source.report.parser != PARSER_IDENTITY {
            source_contradiction = true;
            issues.push(source_issue(
                PolicyIssueCode::UnknownParserIdentity,
                source.source_key,
                source.lineage_key,
                "extraction report was not produced by the parser version bound to this policy crate",
            ));
        }
        if !extraction_budget_matches(source.report) {
            source_contradiction = true;
            issues.push(source_issue(
                PolicyIssueCode::ExtractionBudgetContradiction,
                source.source_key,
                source.lineage_key,
                "extraction usage or limits contradict the retained fields",
            ));
        }
        for field in &source.report.fields {
            let interpretation = interpret_field(field);
            let observation_index = observations.len();
            if field.parser != source.report.parser {
                source_contradiction = true;
                issues.push(single_observation_issue(
                    PolicyIssueCode::ParserIdentityMismatch,
                    Some(field.kind),
                    observation_index,
                    source.source_key,
                    source.lineage_key,
                    "field parser identity differs from extraction report",
                ));
            }
            if !encoding_matches(field) {
                source_contradiction = true;
                issues.push(single_observation_issue(
                    PolicyIssueCode::FieldEncodingMismatch,
                    Some(field.kind),
                    observation_index,
                    source.source_key,
                    source.lineage_key,
                    "field encoding contradicts its metadata kind",
                ));
            }
            if !format_and_container_match(source.report.format, field) {
                source_contradiction = true;
                issues.push(single_observation_issue(
                    PolicyIssueCode::ContainerFormatMismatch,
                    Some(field.kind),
                    observation_index,
                    source.source_key,
                    source.lineage_key,
                    "metadata field kind contradicts the detected media format",
                ));
            }
            if !locator_matches(field) {
                source_contradiction = true;
                issues.push(single_observation_issue(
                    PolicyIssueCode::MetadataLocatorMismatch,
                    Some(field.kind),
                    observation_index,
                    source.source_key,
                    source.lineage_key,
                    "metadata field locator contradicts its raw bytes or field kind",
                ));
            }
            if matches!(interpretation, ObservationInterpretation::Rejected(_)) {
                invalid_evidence = true;
                issues.push(single_observation_issue(
                    PolicyIssueCode::InvalidField,
                    Some(field.kind),
                    observation_index,
                    source.source_key,
                    source.lineage_key,
                    "timestamp field failed strict syntax, calendar, or range validation",
                ));
            }
            observations.push(EvidenceObservation {
                source_key: source.source_key,
                lineage_key: source.lineage_key,
                field: field.clone(),
                interpretation,
            });
        }
        let range_end = observations.len();

        let status_trusted = source.report.status == ExtractionStatus::ExtractedUnvalidated;
        if matches!(
            source.report.status,
            ExtractionStatus::Partial | ExtractionStatus::Failed
        ) {
            extraction_untrusted = true;
            issues.push(source_issue(
                PolicyIssueCode::ExtractionReportUntrusted,
                source.source_key,
                source.lineage_key,
                "partial or failed extraction cannot supply repair evidence",
            ));
        }
        let status_contradiction = if status_trusted {
            source.report.fields.is_empty() || !source.report.issues.is_empty()
        } else if matches!(
            source.report.status,
            ExtractionStatus::Partial | ExtractionStatus::Failed
        ) {
            !source.report.fields.is_empty()
        } else {
            !source.report.fields.is_empty() || !source.report.issues.is_empty()
        };
        if status_contradiction {
            extraction_untrusted = true;
            source_contradiction = true;
            issues.push(source_issue(
                PolicyIssueCode::ExtractionReportContradiction,
                source.source_key,
                source.lineage_key,
                "extraction status, fields, and issues are self-contradictory",
            ));
        }

        if status_trusted && !source_contradiction {
            process_source_fields(
                source,
                range_start,
                range_end,
                &observations,
                &mut atoms,
                &mut issues,
            );
        }
    }

    mark_lineage_conflicts(&mut atoms, &mut issues);
    mark_strong_conflicts(&mut atoms, context, &mut issues);
    if issues.len() > MAX_ANALYSIS_POLICY_ISSUES {
        return analysis_limit_exceeded();
    }
    deduplicate_issues(&mut issues);
    invalid_evidence |= issues.iter().any(|issue| {
        matches!(
            issue.code,
            PolicyIssueCode::InvalidField
                | PolicyIssueCode::InvalidCompanion
                | PolicyIssueCode::OrphanExifCompanion
        )
    });

    let global_conflict = extraction_untrusted
        || issues.iter().any(|issue| {
            matches!(
                issue.code,
                PolicyIssueCode::InvalidCompanion
                    | PolicyIssueCode::RepeatedFieldConflict
                    | PolicyIssueCode::LineageConflict
                    | PolicyIssueCode::StrongEvidenceConflict
                    | PolicyIssueCode::PossibleTimezoneConflict
                    | PolicyIssueCode::ExtractionReportUntrusted
                    | PolicyIssueCode::ExtractionReportContradiction
                    | PolicyIssueCode::ParserIdentityMismatch
                    | PolicyIssueCode::FieldEncodingMismatch
                    | PolicyIssueCode::ContainerFormatMismatch
                    | PolicyIssueCode::MetadataLocatorMismatch
                    | PolicyIssueCode::DuplicateSourceIdentity
                    | PolicyIssueCode::UnknownParserIdentity
                    | PolicyIssueCode::ExtractionBudgetContradiction
            )
        });

    let mut candidates = build_candidates(
        &atoms,
        context,
        &sentinel_index,
        &mut issues,
        global_conflict,
        invalid_evidence,
        extraction_untrusted,
    );
    block_equal_rank_near_ambiguity(&mut candidates, context, &mut issues);
    if issues.len() > MAX_ANALYSIS_POLICY_ISSUES {
        return analysis_limit_exceeded();
    }
    candidates.sort_by(candidate_order);
    deduplicate_issues(&mut issues);
    source_reports.sort_by_key(|status| (status.lineage_key, status.source_key));

    let decision = decide(&candidates, global_conflict);
    TimeAnalysis {
        policy: POLICY_IDENTITY,
        source_reports,
        extraction_issues,
        observations,
        candidates,
        issues,
        decision,
    }
}

fn aggregate_within_limits(sources: &[EvidenceSource<'_>], context: &PolicyContext) -> bool {
    if sources.len() > MAX_ANALYSIS_SOURCES
        || context.sentinel_rules.len() > MAX_ANALYSIS_SENTINEL_RULES
    {
        return false;
    }
    let mut observations = 0_usize;
    let mut extraction_issues = 0_usize;
    let mut raw_bytes = 0_u64;
    let mut bmff_path_components = 0_usize;
    for source in sources {
        let report = source.report();
        let Some(next_observations) = observations.checked_add(report.fields.len()) else {
            return false;
        };
        let Some(next_extraction_issues) = extraction_issues.checked_add(report.issues.len())
        else {
            return false;
        };
        if next_observations > MAX_ANALYSIS_OBSERVATIONS
            || next_extraction_issues > MAX_ANALYSIS_EXTRACTION_ISSUES
        {
            return false;
        }
        for field in &report.fields {
            let Ok(field_bytes) = u64::try_from(field.raw_bytes.len()) else {
                return false;
            };
            let Some(next_raw_bytes) = raw_bytes.checked_add(field_bytes) else {
                return false;
            };
            if next_raw_bytes > MAX_ANALYSIS_RAW_BYTES {
                return false;
            }
            raw_bytes = next_raw_bytes;
            if let MetadataContainer::IsoBmff { box_path, .. } = &field.locator.container {
                if box_path.len() > MAX_BMFF_PATH_COMPONENTS_PER_FIELD {
                    return false;
                }
                let Some(next_components) = bmff_path_components.checked_add(box_path.len()) else {
                    return false;
                };
                if next_components > MAX_ANALYSIS_BMFF_PATH_COMPONENTS {
                    return false;
                }
                bmff_path_components = next_components;
            }
        }
        observations = next_observations;
        extraction_issues = next_extraction_issues;
    }
    aggregate_counts_within_limits(
        sources.len(),
        observations,
        extraction_issues,
        raw_bytes,
        bmff_path_components,
        context.sentinel_rules.len(),
    )
}

fn aggregate_counts_within_limits(
    sources: usize,
    observations: usize,
    extraction_issues: usize,
    raw_bytes: u64,
    bmff_path_components: usize,
    sentinel_rules: usize,
) -> bool {
    let estimated_policy_issues = observations
        .checked_mul(16)
        .and_then(|value| value.checked_add(sources.saturating_mul(8)))
        .and_then(|value| value.checked_add(extraction_issues));
    sources <= MAX_ANALYSIS_SOURCES
        && observations <= MAX_ANALYSIS_OBSERVATIONS
        && extraction_issues <= MAX_ANALYSIS_EXTRACTION_ISSUES
        && raw_bytes <= MAX_ANALYSIS_RAW_BYTES
        && bmff_path_components <= MAX_ANALYSIS_BMFF_PATH_COMPONENTS
        && sentinel_rules <= MAX_ANALYSIS_SENTINEL_RULES
        && estimated_policy_issues.is_some_and(|value| value <= MAX_ANALYSIS_POLICY_ISSUES)
}

fn analysis_limit_exceeded() -> TimeAnalysis {
    TimeAnalysis {
        policy: POLICY_IDENTITY,
        source_reports: Vec::new(),
        extraction_issues: Vec::new(),
        observations: Vec::new(),
        candidates: Vec::new(),
        issues: vec![PolicyIssue {
            code: PolicyIssueCode::AnalysisLimitExceeded,
            field_kind: None,
            observation_indices: Vec::new(),
            source_keys: Vec::new(),
            lineage_keys: Vec::new(),
            context: "aggregate timestamp evidence exceeded a parser-owned hard limit",
        }],
        decision: AnalysisDecision::Conflict,
    }
}

fn interpret_field(field: &MetadataField) -> ObservationInterpretation {
    let result = match field.kind {
        MetadataFieldKind::ExifDateTimeOriginal
        | MetadataFieldKind::ExifCreateDate
        | MetadataFieldKind::ExifModifyDate => parse_exif_timestamp(&field.raw_bytes, None, None)
            .map(ObservationInterpretation::Timestamp),
        MetadataFieldKind::ExifOffsetTimeOriginal => {
            parse_offset(&field.raw_bytes).map(ObservationInterpretation::Offset)
        }
        MetadataFieldKind::ExifSubSecTimeOriginal => {
            parse_subsecond(&field.raw_bytes).map(|(nanosecond, digits, precision)| {
                ObservationInterpretation::Subsecond {
                    nanosecond,
                    digits,
                    precision,
                }
            })
        }
        MetadataFieldKind::QuickTimeMetadataCreationDate => {
            parse_quicktime_timestamp(&field.raw_bytes).map(ObservationInterpretation::Timestamp)
        }
        MetadataFieldKind::QuickTimeMovieHeaderCreationTime => {
            parse_quicktime_mvhd(&field.raw_bytes).map(ObservationInterpretation::Timestamp)
        }
    };
    result.unwrap_or_else(ObservationInterpretation::Rejected)
}

fn encoding_matches(field: &MetadataField) -> bool {
    let expected = match field.kind {
        MetadataFieldKind::ExifDateTimeOriginal
        | MetadataFieldKind::ExifCreateDate
        | MetadataFieldKind::ExifModifyDate
        | MetadataFieldKind::ExifOffsetTimeOriginal
        | MetadataFieldKind::ExifSubSecTimeOriginal => FieldEncoding::DeclaredAscii,
        MetadataFieldKind::QuickTimeMetadataCreationDate => FieldEncoding::ValidatedUtf8,
        MetadataFieldKind::QuickTimeMovieHeaderCreationTime => FieldEncoding::UnsignedBigEndian,
    };
    field.encoding == expected
}

fn format_and_container_match(format: Option<DetectedFormat>, field: &MetadataField) -> bool {
    matches!(
        (format, &field.locator.container, field.kind),
        (
            Some(DetectedFormat::Jpeg),
            MetadataContainer::JpegExif { .. },
            MetadataFieldKind::ExifDateTimeOriginal
                | MetadataFieldKind::ExifCreateDate
                | MetadataFieldKind::ExifModifyDate
                | MetadataFieldKind::ExifOffsetTimeOriginal
                | MetadataFieldKind::ExifSubSecTimeOriginal,
        ) | (
            Some(DetectedFormat::Tiff),
            MetadataContainer::Tiff { .. },
            MetadataFieldKind::ExifDateTimeOriginal
                | MetadataFieldKind::ExifCreateDate
                | MetadataFieldKind::ExifModifyDate
                | MetadataFieldKind::ExifOffsetTimeOriginal
                | MetadataFieldKind::ExifSubSecTimeOriginal,
        ) | (
            Some(DetectedFormat::IsoBmff),
            MetadataContainer::IsoBmff { .. },
            MetadataFieldKind::QuickTimeMovieHeaderCreationTime
                | MetadataFieldKind::QuickTimeMetadataCreationDate,
        )
    )
}

fn locator_matches(field: &MetadataField) -> bool {
    if u64::try_from(field.raw_bytes.len()).ok() != Some(field.locator.byte_len)
        || field
            .locator
            .absolute_offset
            .checked_add(field.locator.byte_len)
            .is_none()
    {
        return false;
    }
    match (&field.locator.container, field.kind) {
        (
            MetadataContainer::Tiff {
                header_offset,
                ifd_offset,
                tag,
                ..
            },
            MetadataFieldKind::ExifDateTimeOriginal,
        ) => *header_offset == 0 && tiff_locator_matches(*header_offset, *ifd_offset, *tag, 0x9003),
        (
            MetadataContainer::Tiff {
                header_offset,
                ifd_offset,
                tag,
                ..
            },
            MetadataFieldKind::ExifCreateDate,
        ) => *header_offset == 0 && tiff_locator_matches(*header_offset, *ifd_offset, *tag, 0x9004),
        (
            MetadataContainer::Tiff {
                header_offset,
                ifd_offset,
                tag,
                ..
            },
            MetadataFieldKind::ExifModifyDate,
        ) => *header_offset == 0 && tiff_locator_matches(*header_offset, *ifd_offset, *tag, 0x0132),
        (
            MetadataContainer::Tiff {
                header_offset,
                ifd_offset,
                tag,
                ..
            },
            MetadataFieldKind::ExifOffsetTimeOriginal,
        ) => *header_offset == 0 && tiff_locator_matches(*header_offset, *ifd_offset, *tag, 0x9011),
        (
            MetadataContainer::Tiff {
                header_offset,
                ifd_offset,
                tag,
                ..
            },
            MetadataFieldKind::ExifSubSecTimeOriginal,
        ) => *header_offset == 0 && tiff_locator_matches(*header_offset, *ifd_offset, *tag, 0x9291),
        (
            MetadataContainer::JpegExif {
                app1_offset,
                header_offset,
                ifd_offset,
                tag,
                ..
            },
            kind @ (MetadataFieldKind::ExifDateTimeOriginal
            | MetadataFieldKind::ExifCreateDate
            | MetadataFieldKind::ExifModifyDate
            | MetadataFieldKind::ExifOffsetTimeOriginal
            | MetadataFieldKind::ExifSubSecTimeOriginal),
        ) => {
            let expected_tag = exif_tag(kind);
            app1_offset.checked_add(10) == Some(*header_offset)
                && tiff_locator_matches(*header_offset, *ifd_offset, *tag, expected_tag)
        }
        (
            MetadataContainer::IsoBmff {
                box_offset,
                box_path,
            },
            MetadataFieldKind::QuickTimeMovieHeaderCreationTime,
        ) => {
            box_path.as_slice() == [*b"moov", *b"mvhd"]
                && matches!(field.locator.byte_len, 4 | 8)
                && box_offset
                    .checked_add(12)
                    .is_some_and(|minimum| field.locator.absolute_offset >= minimum)
        }
        (
            MetadataContainer::IsoBmff {
                box_offset,
                box_path,
            },
            MetadataFieldKind::QuickTimeMetadataCreationDate,
        ) => quicktime_text_locator_matches(*box_offset, box_path, field.locator.absolute_offset),
        _ => false,
    }
}

fn exif_tag(kind: MetadataFieldKind) -> u16 {
    match kind {
        MetadataFieldKind::ExifDateTimeOriginal => 0x9003,
        MetadataFieldKind::ExifCreateDate => 0x9004,
        MetadataFieldKind::ExifModifyDate => 0x0132,
        MetadataFieldKind::ExifOffsetTimeOriginal => 0x9011,
        MetadataFieldKind::ExifSubSecTimeOriginal => 0x9291,
        MetadataFieldKind::QuickTimeMovieHeaderCreationTime
        | MetadataFieldKind::QuickTimeMetadataCreationDate => 0,
    }
}

fn tiff_locator_matches(
    header_offset: u64,
    ifd_offset: u64,
    actual_tag: u16,
    expected_tag: u16,
) -> bool {
    actual_tag == expected_tag
        && header_offset
            .checked_add(8)
            .is_some_and(|minimum| ifd_offset >= minimum)
}

fn quicktime_text_locator_matches(
    box_offset: u64,
    box_path: &[[u8; 4]],
    absolute_offset: u64,
) -> bool {
    const COPYRIGHT_DAY: [u8; 4] = [0xa9, b'd', b'a', b'y'];
    let legacy = box_path == [*b"moov", *b"udta", COPYRIGHT_DAY]
        && box_offset
            .checked_add(12)
            .is_some_and(|minimum| absolute_offset >= minimum);
    let modern_path = match box_path {
        [moov, meta, ilst, item, data]
            if moov == b"moov" && meta == b"meta" && ilst == b"ilst" && data == b"data" =>
        {
            *item == COPYRIGHT_DAY || u32::from_be_bytes(*item) != 0
        }
        [moov, udta, meta, ilst, item, data]
            if moov == b"moov"
                && udta == b"udta"
                && meta == b"meta"
                && ilst == b"ilst"
                && data == b"data" =>
        {
            *item == COPYRIGHT_DAY || u32::from_be_bytes(*item) != 0
        }
        _ => false,
    };
    legacy
        || (modern_path
            && box_offset
                .checked_add(16)
                .is_some_and(|minimum| absolute_offset >= minimum))
}

fn extraction_budget_matches(report: &guiying_metadata::ExtractionReport) -> bool {
    if report.limits != report.limits.effective()
        || report.usage.bytes_read > report.limits.max_total_bytes_read
        || report.usage.read_operations > report.limits.max_read_operations
        || report.usage.retained_field_bytes > report.limits.max_retained_field_bytes
        || report.usage.fields_emitted > report.limits.max_fields
        || report.usage.jpeg_segments_visited > report.limits.max_jpeg_segments
        || report.usage.ifd_entries_visited > report.limits.max_ifd_entries
        || report.usage.bmff_boxes_visited > report.limits.max_bmff_boxes
        || !format_depth_matches(report)
        || !format_usage_matches(report)
        || !locator_depth_matches(report)
        || (!report.fields.is_empty()
            && (report.usage.bytes_read == 0 || report.usage.read_operations == 0))
        || report.fields.iter().any(|field| {
            u64::try_from(field.raw_bytes.len())
                .map_or(true, |length| length > report.limits.max_field_bytes)
        })
    {
        return false;
    }
    let Ok(field_count) = u32::try_from(report.fields.len()) else {
        return false;
    };
    let retained = report.fields.iter().try_fold(0_u64, |total, field| {
        total.checked_add(field.locator.byte_len)
    });
    retained.is_some_and(|retained| {
        report.usage.fields_emitted == field_count
            && report.usage.retained_field_bytes == retained
            && report.usage.bytes_read >= retained
    })
}

fn format_depth_matches(report: &guiying_metadata::ExtractionReport) -> bool {
    let maximum = match report.format {
        Some(DetectedFormat::Jpeg | DetectedFormat::Tiff) => report.limits.max_ifd_depth,
        Some(DetectedFormat::IsoBmff) => report.limits.max_bmff_depth,
        None => 0,
    };
    report.usage.max_depth_observed <= maximum
}

fn format_usage_matches(report: &guiying_metadata::ExtractionReport) -> bool {
    let usage = report.usage;
    match report.format {
        None => {
            usage.jpeg_segments_visited == 0
                && usage.ifd_entries_visited == 0
                && usage.bmff_boxes_visited == 0
                && usage.max_depth_observed == 0
        }
        Some(DetectedFormat::Tiff) => {
            usage.jpeg_segments_visited == 0
                && usage.bmff_boxes_visited == 0
                && (report.fields.is_empty() || usage.ifd_entries_visited > 0)
        }
        Some(DetectedFormat::Jpeg) => {
            usage.bmff_boxes_visited == 0
                && (report.fields.is_empty()
                    || (usage.jpeg_segments_visited > 0 && usage.ifd_entries_visited > 0))
        }
        Some(DetectedFormat::IsoBmff) => {
            usage.jpeg_segments_visited == 0
                && usage.ifd_entries_visited == 0
                && (report.fields.is_empty() || usage.bmff_boxes_visited > 0)
        }
    }
}

fn locator_depth_matches(report: &guiying_metadata::ExtractionReport) -> bool {
    report.fields.iter().all(|field| {
        let required_depth = match &field.locator.container {
            MetadataContainer::Tiff { .. } | MetadataContainer::JpegExif { .. } => {
                if field.kind == MetadataFieldKind::ExifModifyDate {
                    1
                } else {
                    2
                }
            }
            MetadataContainer::IsoBmff { box_path, .. } => {
                let Ok(depth) = u16::try_from(box_path.len()) else {
                    return false;
                };
                depth
            }
        };
        report.usage.max_depth_observed >= required_depth
    })
}

fn process_source_fields(
    source: &EvidenceSource<'_>,
    range_start: usize,
    range_end: usize,
    observations: &[EvidenceObservation],
    atoms: &mut Vec<Atom>,
    issues: &mut Vec<PolicyIssue>,
) {
    let dto = indices_of_kind(
        observations,
        range_start,
        range_end,
        MetadataFieldKind::ExifDateTimeOriginal,
    );
    let offsets = indices_of_kind(
        observations,
        range_start,
        range_end,
        MetadataFieldKind::ExifOffsetTimeOriginal,
    );
    let subseconds = indices_of_kind(
        observations,
        range_start,
        range_end,
        MetadataFieldKind::ExifSubSecTimeOriginal,
    );

    let dto_by_scope = indices_by_exif_scope(&dto, observations);
    let offsets_by_scope = indices_by_exif_scope(&offsets, observations);
    let subseconds_by_scope = indices_by_exif_scope(&subseconds, observations);
    let orphan_companions = offsets_by_scope
        .iter()
        .chain(&subseconds_by_scope)
        .filter(|(scope, _)| !dto_by_scope.contains_key(scope))
        .flat_map(|(_, indices)| indices.iter().copied())
        .collect::<Vec<_>>();
    if !orphan_companions.is_empty() {
        issues.push(issue_for_indices(
            PolicyIssueCode::OrphanExifCompanion,
            None,
            orphan_companions,
            observations,
            "Exif companion is outside every DateTimeOriginal IFD scope",
        ));
    }

    for (scope, scoped_dto) in dto_by_scope {
        let scoped_offsets = offsets_by_scope.get(&scope).cloned().unwrap_or_default();
        let scoped_subseconds = subseconds_by_scope.get(&scope).cloned().unwrap_or_default();
        let dto_conflict = report_repeated_conflict(
            &scoped_dto,
            observations,
            MetadataFieldKind::ExifDateTimeOriginal,
            "repeated DateTimeOriginal values disagree inside one IFD scope",
            issues,
        );
        let offset_conflict = report_repeated_conflict(
            &scoped_offsets,
            observations,
            MetadataFieldKind::ExifOffsetTimeOriginal,
            "repeated OffsetTimeOriginal values disagree inside one IFD scope",
            issues,
        );
        let subsecond_conflict = report_repeated_conflict(
            &scoped_subseconds,
            observations,
            MetadataFieldKind::ExifSubSecTimeOriginal,
            "repeated SubSecTimeOriginal values disagree inside one IFD scope",
            issues,
        );
        let offset = unique_offset(&scoped_offsets, observations);
        let subsecond = unique_subsecond(&scoped_subseconds, observations);
        let companion_invalid = offset_conflict
            || subsecond_conflict
            || (offset.is_none() && !scoped_offsets.is_empty())
            || (subsecond.is_none() && !scoped_subseconds.is_empty());
        if companion_invalid {
            issues.push(issue_for_indices(
                PolicyIssueCode::InvalidCompanion,
                None,
                joined_indices(&scoped_offsets, &scoped_subseconds),
                observations,
                "Exif companion is malformed or conflicting; automatic evidence is blocked",
            ));
        }
        add_exif_original_atoms(
            source,
            &scoped_dto,
            &scoped_offsets,
            &scoped_subseconds,
            offset,
            subsecond,
            dto_conflict || companion_invalid,
            companion_invalid,
            observations,
            atoms,
        );
    }
    add_simple_exif_atoms(
        source,
        MetadataFieldKind::ExifCreateDate,
        TimeEvidenceKind::ExifCreateDate,
        Confidence::Medium,
        false,
        range_start,
        range_end,
        observations,
        atoms,
        issues,
    );
    add_simple_exif_atoms(
        source,
        MetadataFieldKind::ExifModifyDate,
        TimeEvidenceKind::ExifModifyDate,
        Confidence::Low,
        false,
        range_start,
        range_end,
        observations,
        atoms,
        issues,
    );
    add_simple_atoms(
        source,
        MetadataFieldKind::QuickTimeMetadataCreationDate,
        TimeEvidenceKind::QuickTimeMetadataCreationDate,
        Confidence::Medium,
        true,
        range_start,
        range_end,
        observations,
        atoms,
        issues,
    );
    add_simple_atoms(
        source,
        MetadataFieldKind::QuickTimeMovieHeaderCreationTime,
        TimeEvidenceKind::QuickTimeMovieHeaderCreationTime,
        Confidence::Low,
        false,
        range_start,
        range_end,
        observations,
        atoms,
        issues,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_exif_original_atoms(
    source: &EvidenceSource<'_>,
    dto: &[usize],
    offsets: &[usize],
    subseconds: &[usize],
    offset: Option<UtcOffset>,
    subsecond: Option<(u32, TimePrecision)>,
    evidence_conflict: bool,
    invalid_companion: bool,
    observations: &[EvidenceObservation],
    atoms: &mut Vec<Atom>,
) {
    for (base, matching_indices) in unique_timestamps(dto, observations) {
        let (nanosecond, precision) =
            subsecond.map_or((0, TimePrecision::seconds()), |value| value);
        let Ok(wall) = base.wall_time().with_nanosecond(nanosecond) else {
            continue;
        };
        let timestamp = offset.map_or_else(
            || Ok(NormalizedTimestamp::floating(wall, precision)),
            |value| NormalizedTimestamp::explicit(wall, value, precision),
        );
        let Ok(timestamp) = timestamp else {
            continue;
        };
        let mut all_indices = matching_indices;
        all_indices.extend_from_slice(offsets);
        all_indices.extend_from_slice(subseconds);
        sort_dedup(&mut all_indices);
        atoms.push(Atom {
            timestamp,
            kind: TimeEvidenceKind::ExifDateTimeOriginal,
            source_key: source.source_key,
            lineage_key: source.lineage_key,
            observation_indices: all_indices,
            base_confidence: if offset.is_some() {
                Confidence::High
            } else {
                Confidence::Medium
            },
            strong: true,
            conflicted: evidence_conflict,
            invalid_companion,
            source_verified: source.binding() == EvidenceBindingStatus::ReextractedFromPinnedSource,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn add_simple_exif_atoms(
    source: &EvidenceSource<'_>,
    field_kind: MetadataFieldKind,
    evidence_kind: TimeEvidenceKind,
    base_confidence: Confidence,
    strong: bool,
    range_start: usize,
    range_end: usize,
    observations: &[EvidenceObservation],
    atoms: &mut Vec<Atom>,
    issues: &mut Vec<PolicyIssue>,
) {
    let indices = indices_of_kind(observations, range_start, range_end, field_kind);
    let mut by_scope = BTreeMap::<ExifScope, Vec<usize>>::new();
    for index in indices {
        if let Some(scope) = exif_scope(&observations[index].field) {
            by_scope.entry(scope).or_default().push(index);
        }
    }
    for scoped_indices in by_scope.into_values() {
        add_simple_atom_indices(
            source,
            field_kind,
            evidence_kind,
            base_confidence,
            strong,
            scoped_indices,
            observations,
            atoms,
            issues,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_simple_atoms(
    source: &EvidenceSource<'_>,
    field_kind: MetadataFieldKind,
    evidence_kind: TimeEvidenceKind,
    base_confidence: Confidence,
    strong: bool,
    range_start: usize,
    range_end: usize,
    observations: &[EvidenceObservation],
    atoms: &mut Vec<Atom>,
    issues: &mut Vec<PolicyIssue>,
) {
    let indices = indices_of_kind(observations, range_start, range_end, field_kind);
    add_simple_atom_indices(
        source,
        field_kind,
        evidence_kind,
        base_confidence,
        strong,
        indices,
        observations,
        atoms,
        issues,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_simple_atom_indices(
    source: &EvidenceSource<'_>,
    field_kind: MetadataFieldKind,
    evidence_kind: TimeEvidenceKind,
    base_confidence: Confidence,
    strong: bool,
    indices: Vec<usize>,
    observations: &[EvidenceObservation],
    atoms: &mut Vec<Atom>,
    issues: &mut Vec<PolicyIssue>,
) {
    let repeated_conflict = report_repeated_conflict(
        &indices,
        observations,
        field_kind,
        "repeated timestamp values of one kind disagree inside one metadata scope",
        issues,
    );
    for (timestamp, matching_indices) in unique_timestamps(&indices, observations) {
        atoms.push(Atom {
            timestamp,
            kind: evidence_kind,
            source_key: source.source_key,
            lineage_key: source.lineage_key,
            observation_indices: matching_indices,
            base_confidence: if timestamp.utc_instant().is_some() {
                base_confidence
            } else {
                lower_confidence(base_confidence)
            },
            strong,
            conflicted: repeated_conflict,
            invalid_companion: false,
            source_verified: source.binding() == EvidenceBindingStatus::ReextractedFromPinnedSource,
        });
    }
}

fn report_repeated_conflict(
    indices: &[usize],
    observations: &[EvidenceObservation],
    field_kind: MetadataFieldKind,
    context: &'static str,
    issues: &mut Vec<PolicyIssue>,
) -> bool {
    let conflict = has_semantic_conflict(indices, observations);
    if conflict {
        issues.push(issue_for_indices(
            PolicyIssueCode::RepeatedFieldConflict,
            Some(field_kind),
            indices.to_vec(),
            observations,
            context,
        ));
    }
    conflict
}

fn mark_lineage_conflicts(atoms: &mut [Atom], issues: &mut Vec<PolicyIssue>) {
    let mut groups = BTreeMap::<(LineageKey, TimeEvidenceKind), Vec<usize>>::new();
    for (index, atom) in atoms.iter().enumerate() {
        groups
            .entry((atom.lineage_key, atom.kind))
            .or_default()
            .push(index);
    }
    for indices in groups.into_values() {
        let values = indices
            .iter()
            .map(|index| semantic_timestamp(atoms[*index].timestamp))
            .collect::<BTreeSet<_>>();
        if values.len() > 1 {
            for index in &indices {
                atoms[*index].conflicted = true;
            }
            issues.push(issue_for_atom_indices(
                PolicyIssueCode::LineageConflict,
                atoms,
                &indices,
                "copy-derived sources in one lineage disagree; copy count cannot vote",
            ));
        }
    }
}

fn semantic_timestamp(timestamp: NormalizedTimestamp) -> SemanticTimestamp {
    timestamp.utc_instant().map_or_else(
        || SemanticTimestamp::Floating(timestamp.wall_time(), timestamp.precision()),
        SemanticTimestamp::Utc,
    )
}

fn mark_strong_conflicts(
    atoms: &mut [Atom],
    context: &PolicyContext,
    issues: &mut Vec<PolicyIssue>,
) {
    let mut seen = BTreeSet::new();
    let representatives = atoms
        .iter()
        .enumerate()
        .filter_map(|(index, atom)| {
            (atom.strong && seen.insert((atom.lineage_key, atom.kind, atom.timestamp)))
                .then_some(index)
        })
        .collect::<Vec<_>>();
    let tolerance = seconds_to_nanoseconds(effective_strong_tolerance(context));

    let mut explicit = representatives
        .iter()
        .filter_map(|index| {
            atoms[*index]
                .timestamp
                .utc_instant()
                .and_then(|instant| instant.total_nanoseconds())
                .map(|value| (value, *index))
        })
        .collect::<Vec<_>>();
    explicit.sort_unstable();
    if let (Some((minimum, _)), Some((maximum, _))) =
        (explicit.first().copied(), explicit.last().copied())
    {
        let difference = maximum.saturating_sub(minimum);
        if difference > tolerance {
            mark_conflicted(atoms, &representatives);
            push_strong_conflict_issue(atoms, issues, &representatives, difference, context);
        }
    }

    let floating = representatives
        .iter()
        .copied()
        .filter(|index| atoms[*index].timestamp.utc_instant().is_none())
        .collect::<Vec<_>>();
    if floating.is_empty() {
        return;
    }
    let mut wall_values = representatives
        .iter()
        .filter_map(|index| {
            wall_total_nanoseconds(atoms[*index].timestamp).map(|value| (value, *index))
        })
        .collect::<Vec<_>>();
    wall_values.sort_unstable();
    let (Some((minimum, _)), Some((maximum, _))) =
        (wall_values.first().copied(), wall_values.last().copied())
    else {
        mark_conflicted(atoms, &representatives);
        return;
    };
    for floating_index in floating {
        let Some(value) = wall_total_nanoseconds(atoms[floating_index].timestamp) else {
            mark_conflicted(atoms, &representatives);
            return;
        };
        let difference = if value.saturating_sub(minimum) > tolerance {
            Some(value.saturating_sub(minimum))
        } else if maximum.saturating_sub(value) > tolerance {
            Some(maximum.saturating_sub(value))
        } else {
            None
        };
        if let Some(difference) = difference {
            mark_conflicted(atoms, &representatives);
            push_strong_conflict_issue(atoms, issues, &representatives, difference, context);
            break;
        }
    }
}

fn mark_conflicted(atoms: &mut [Atom], indices: &[usize]) {
    for index in indices {
        atoms[*index].conflicted = true;
    }
}

fn push_strong_conflict_issue(
    atoms: &[Atom],
    issues: &mut Vec<PolicyIssue>,
    representatives: &[usize],
    difference: i128,
    context: &PolicyContext,
) {
    let code = if is_suspected_integer_hour(difference, context) {
        PolicyIssueCode::PossibleTimezoneConflict
    } else {
        PolicyIssueCode::StrongEvidenceConflict
    };
    let message = if code == PolicyIssueCode::PossibleTimezoneConflict {
        "strong evidence differs by an integer hour; timezone inference is forbidden"
    } else {
        "strong evidence differs beyond the configured tolerance"
    };
    issues.push(issue_for_atom_indices(
        code,
        atoms,
        representatives,
        message,
    ));
}

fn build_candidates(
    atoms: &[Atom],
    context: &PolicyContext,
    sentinel_index: &SentinelIndex,
    issues: &mut Vec<PolicyIssue>,
    global_conflict: bool,
    invalid_evidence: bool,
    extraction_untrusted: bool,
) -> Vec<TimeCandidate> {
    let mut work = BTreeMap::<NormalizedTimestamp, CandidateWork>::new();
    for atom in atoms {
        if let Some(existing) = work.get_mut(&atom.timestamp) {
            existing.kinds.push(atom.kind);
            existing.sources.push(atom.source_key);
            existing.lineages.push(atom.lineage_key);
            existing
                .observations
                .extend_from_slice(&atom.observation_indices);
            existing.base_confidence =
                higher_confidence(existing.base_confidence, atom.base_confidence);
            existing.conflicted |= atom.conflicted;
            existing.invalid_companion |= atom.invalid_companion;
            existing.all_sources_verified &= atom.source_verified;
        } else {
            work.insert(
                atom.timestamp,
                CandidateWork {
                    timestamp: atom.timestamp,
                    kinds: vec![atom.kind],
                    sources: vec![atom.source_key],
                    lineages: vec![atom.lineage_key],
                    observations: atom.observation_indices.clone(),
                    base_confidence: atom.base_confidence,
                    conflicted: atom.conflicted,
                    invalid_companion: atom.invalid_companion,
                    all_sources_verified: atom.source_verified,
                },
            );
        }
    }

    work.into_values()
        .map(|mut candidate| {
            sort_dedup(&mut candidate.kinds);
            sort_dedup(&mut candidate.sources);
            sort_dedup(&mut candidate.lineages);
            sort_dedup(&mut candidate.observations);
            let mut anomalies = candidate_anomalies(&candidate, context, sentinel_index);
            if candidate.invalid_companion {
                anomalies.push(CandidateAnomaly::InvalidCompanion);
            }
            sort_dedup(&mut anomalies);

            for anomaly in &anomalies {
                let (code, message) = match anomaly {
                    CandidateAnomaly::SentinelValue => (
                        Some(PolicyIssueCode::SentinelValue),
                        "candidate matches a non-removable or caller-supplied sentinel rule",
                    ),
                    CandidateAnomaly::ObviousFuture => (
                        Some(PolicyIssueCode::ObviousFuture),
                        "candidate is beyond the caller-supplied future tolerance",
                    ),
                    CandidateAnomaly::OutsideAutomaticRange => (
                        Some(PolicyIssueCode::OutsideAutomaticRange),
                        "candidate is outside the non-widenable automatic timestamp range",
                    ),
                    CandidateAnomaly::QuickTimeEpochSemanticUncertainty => (
                        Some(PolicyIssueCode::QuickTimeEpochSemanticUncertainty),
                        "mvhd epoch semantics are uncertain and never sufficient alone",
                    ),
                    CandidateAnomaly::MissingOffset | CandidateAnomaly::InvalidCompanion => {
                        (None, "")
                    }
                };
                if let Some(code) = code {
                    issues.push(PolicyIssue {
                        code,
                        field_kind: None,
                        observation_indices: candidate.observations.clone(),
                        source_keys: candidate.sources.clone(),
                        lineage_keys: candidate.lineages.clone(),
                        context: message,
                    });
                }
            }

            let confidence = if candidate.conflicted || global_conflict {
                Confidence::Conflict
            } else if anomalies.iter().any(|anomaly| {
                matches!(
                    anomaly,
                    CandidateAnomaly::SentinelValue
                        | CandidateAnomaly::ObviousFuture
                        | CandidateAnomaly::OutsideAutomaticRange
                )
            }) {
                Confidence::Low
            } else {
                candidate.base_confidence
            };

            let evidence_gate = evidence_gate(
                confidence,
                candidate.timestamp,
                &anomalies,
                global_conflict,
                invalid_evidence,
                extraction_untrusted,
                candidate.all_sources_verified,
            );
            TimeCandidate {
                timestamp: candidate.timestamp,
                evidence_kinds: candidate.kinds,
                supporting_sources: candidate.sources,
                supporting_lineages: candidate.lineages,
                observation_indices: candidate.observations,
                confidence,
                anomalies,
                evidence_gate,
            }
        })
        .collect()
}

fn candidate_anomalies(
    candidate: &CandidateWork,
    context: &PolicyContext,
    sentinel_index: &SentinelIndex,
) -> Vec<CandidateAnomaly> {
    let mut anomalies = Vec::new();
    if candidate.timestamp.utc_instant().is_none() {
        anomalies.push(CandidateAnomaly::MissingOffset);
    }
    if candidate
        .kinds
        .contains(&TimeEvidenceKind::QuickTimeMovieHeaderCreationTime)
    {
        anomalies.push(CandidateAnomaly::QuickTimeEpochSemanticUncertainty);
    }
    if HARD_SENTINEL_YEARS.contains(&candidate.timestamp.wall_time().year())
        || sentinel_index.matches(candidate.timestamp)
    {
        anomalies.push(CandidateAnomaly::SentinelValue);
    }
    if is_obviously_future(candidate.timestamp, context) {
        anomalies.push(CandidateAnomaly::ObviousFuture);
    }
    if !is_inside_automatic_range(candidate.timestamp, context) {
        anomalies.push(CandidateAnomaly::OutsideAutomaticRange);
    }
    anomalies
}

fn evidence_gate(
    confidence: Confidence,
    timestamp: NormalizedTimestamp,
    anomalies: &[CandidateAnomaly],
    global_conflict: bool,
    invalid_evidence: bool,
    extraction_untrusted: bool,
    all_sources_verified: bool,
) -> EvidenceGateDecision {
    let mut blockers = Vec::new();
    if confidence != Confidence::High {
        blockers.push(EvidenceGateBlocker::ConfidenceBelowHigh);
    }
    if timestamp.utc_instant().is_none() {
        blockers.push(EvidenceGateBlocker::NoUtcInstant);
    }
    if global_conflict || confidence == Confidence::Conflict {
        blockers.push(EvidenceGateBlocker::EvidenceConflict);
    }
    if anomalies.contains(&CandidateAnomaly::SentinelValue) {
        blockers.push(EvidenceGateBlocker::SentinelValue);
    }
    if anomalies.contains(&CandidateAnomaly::ObviousFuture) {
        blockers.push(EvidenceGateBlocker::ObviousFuture);
    }
    if anomalies.contains(&CandidateAnomaly::OutsideAutomaticRange) {
        blockers.push(EvidenceGateBlocker::OutsideAutomaticRange);
    }
    if anomalies.contains(&CandidateAnomaly::QuickTimeEpochSemanticUncertainty) {
        blockers.push(EvidenceGateBlocker::QuickTimeEpochSemanticUncertainty);
    }
    if invalid_evidence || anomalies.contains(&CandidateAnomaly::InvalidCompanion) {
        blockers.push(EvidenceGateBlocker::InvalidEvidencePresent);
    }
    if extraction_untrusted {
        blockers.push(EvidenceGateBlocker::ExtractionReportUntrusted);
    }
    if !all_sources_verified {
        blockers.push(EvidenceGateBlocker::SourceNotRevalidated);
    }
    sort_dedup(&mut blockers);
    if blockers.is_empty() {
        EvidenceGateDecision::Eligible
    } else {
        EvidenceGateDecision::Blocked(blockers)
    }
}

fn decide(candidates: &[TimeCandidate], global_conflict: bool) -> AnalysisDecision {
    if global_conflict {
        return AnalysisDecision::Conflict;
    }
    if candidates.is_empty() {
        return AnalysisDecision::NoUsableEvidence;
    }
    if let Some(index) = best_candidate_index(candidates, true) {
        return AnalysisDecision::EvidenceEligible {
            candidate_index: index,
        };
    }
    let index = best_candidate_index(candidates, false).unwrap_or(0);
    AnalysisDecision::ReviewRequired {
        candidate_index: index,
    }
}

/// Blocks every equal-priority high-confidence candidate whose UTC instant is
/// near, but not identical to, another candidate's instant.
///
/// Grouping uses evidence priority only. Every instant is compared on the one
/// shared total-nanosecond scale regardless of its declared precision, so a
/// coarse and a fine reading of two different instants cannot silently bypass
/// review through the fine value's automatic preference. Candidates whose
/// instants are exactly equal share one entry and never block each other:
/// consistent with [`semantic_timestamp`] equality, differing precision or
/// offset representations of the same instant are a refinement, not an
/// ambiguity.
fn block_equal_rank_near_ambiguity(
    candidates: &mut [TimeCandidate],
    context: &PolicyContext,
    issues: &mut Vec<PolicyIssue>,
) {
    let mut groups = BTreeMap::<u8, BTreeMap<i128, Vec<usize>>>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.confidence != Confidence::High {
            continue;
        }
        let Some(value) = candidate
            .timestamp
            .utc_instant()
            .and_then(|instant| instant.total_nanoseconds())
        else {
            continue;
        };
        groups
            .entry(evidence_priority(&candidate.evidence_kinds))
            .or_default()
            .entry(value)
            .or_default()
            .push(index);
    }
    let tolerance = seconds_to_nanoseconds(effective_strong_tolerance(context));
    for instants in groups.into_values() {
        let mut previous: Option<(i128, Vec<usize>)> = None;
        for (value, indices) in instants {
            if let Some((previous_value, previous_indices)) = &previous {
                if value.saturating_sub(*previous_value) <= tolerance {
                    block_near_candidate_pair(candidates, previous_indices, &indices, issues);
                }
            }
            previous = Some((value, indices));
        }
    }
}

fn block_near_candidate_pair(
    candidates: &mut [TimeCandidate],
    left_indices: &[usize],
    right_indices: &[usize],
    issues: &mut Vec<PolicyIssue>,
) {
    for index in left_indices.iter().chain(right_indices) {
        add_gate_blocker(
            &mut candidates[*index].evidence_gate,
            EvidenceGateBlocker::MultipleStrongValuesWithinTolerance,
        );
    }
    let mut observations = Vec::new();
    let mut sources = Vec::new();
    let mut lineages = Vec::new();
    for index in left_indices.iter().chain(right_indices) {
        observations.extend_from_slice(&candidates[*index].observation_indices);
        sources.extend_from_slice(&candidates[*index].supporting_sources);
        lineages.extend_from_slice(&candidates[*index].supporting_lineages);
    }
    sort_dedup(&mut observations);
    sort_dedup(&mut sources);
    sort_dedup(&mut lineages);
    issues.push(PolicyIssue {
        code: PolicyIssueCode::StrongEvidenceWithinToleranceAmbiguous,
        field_kind: None,
        observation_indices: observations,
        source_keys: sources,
        lineage_keys: lineages,
        context:
            "equal-rank strong values are close but not identical; review chooses the exact value",
    });
}

fn add_gate_blocker(gate: &mut EvidenceGateDecision, blocker: EvidenceGateBlocker) {
    match gate {
        EvidenceGateDecision::Eligible => {
            *gate = EvidenceGateDecision::Blocked(vec![blocker]);
        }
        EvidenceGateDecision::Blocked(blockers) => {
            blockers.push(blocker);
            sort_dedup(blockers);
        }
    }
}

fn best_candidate_index(candidates: &[TimeCandidate], eligible_only: bool) -> Option<usize> {
    let mut best = None;
    for (index, candidate) in candidates.iter().enumerate() {
        if eligible_only && candidate.evidence_gate != EvidenceGateDecision::Eligible {
            continue;
        }
        if let Some(best_index) = best {
            if candidate_preference(candidate, &candidates[best_index]) == Ordering::Greater {
                best = Some(index);
            }
        } else {
            best = Some(index);
        }
    }
    best
}

fn candidate_preference(left: &TimeCandidate, right: &TimeCandidate) -> Ordering {
    confidence_rank(left.confidence)
        .cmp(&confidence_rank(right.confidence))
        .then_with(|| {
            left.timestamp
                .utc_instant()
                .is_some()
                .cmp(&right.timestamp.utc_instant().is_some())
        })
        .then_with(|| {
            evidence_priority(&left.evidence_kinds).cmp(&evidence_priority(&right.evidence_kinds))
        })
        .then_with(|| {
            right
                .timestamp
                .precision()
                .nanoseconds()
                .cmp(&left.timestamp.precision().nanoseconds())
        })
        .then_with(|| right.timestamp.cmp(&left.timestamp))
}

fn candidate_order(left: &TimeCandidate, right: &TimeCandidate) -> Ordering {
    left.timestamp
        .cmp(&right.timestamp)
        .then_with(|| left.evidence_kinds.cmp(&right.evidence_kinds))
}

fn evidence_priority(kinds: &[TimeEvidenceKind]) -> u8 {
    kinds
        .iter()
        .map(|kind| match kind {
            TimeEvidenceKind::ExifDateTimeOriginal => 5,
            TimeEvidenceKind::QuickTimeMetadataCreationDate => 4,
            TimeEvidenceKind::ExifCreateDate => 3,
            TimeEvidenceKind::ExifModifyDate => 2,
            TimeEvidenceKind::QuickTimeMovieHeaderCreationTime => 1,
        })
        .max()
        .unwrap_or(0)
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Conflict => 0,
        Confidence::Low => 1,
        Confidence::Medium => 2,
        Confidence::High => 3,
    }
}

fn higher_confidence(left: Confidence, right: Confidence) -> Confidence {
    if confidence_rank(left) >= confidence_rank(right) {
        left
    } else {
        right
    }
}

fn lower_confidence(confidence: Confidence) -> Confidence {
    match confidence {
        Confidence::High => Confidence::Medium,
        Confidence::Medium | Confidence::Low | Confidence::Conflict => Confidence::Low,
    }
}

fn unique_timestamps(
    indices: &[usize],
    observations: &[EvidenceObservation],
) -> Vec<(NormalizedTimestamp, Vec<usize>)> {
    let mut values = BTreeMap::<NormalizedTimestamp, Vec<usize>>::new();
    for index in indices {
        if let ObservationInterpretation::Timestamp(timestamp) = observations[*index].interpretation
        {
            values.entry(timestamp).or_default().push(*index);
        }
    }
    values.into_iter().collect()
}

fn unique_offset(indices: &[usize], observations: &[EvidenceObservation]) -> Option<UtcOffset> {
    let mut values = Vec::new();
    for index in indices {
        if let ObservationInterpretation::Offset(value) = observations[*index].interpretation {
            values.push(value);
        } else {
            return None;
        }
    }
    sort_dedup(&mut values);
    if values.len() == 1 {
        values.first().copied()
    } else {
        None
    }
}

fn unique_subsecond(
    indices: &[usize],
    observations: &[EvidenceObservation],
) -> Option<(u32, TimePrecision)> {
    let mut values = Vec::new();
    for index in indices {
        if let ObservationInterpretation::Subsecond {
            nanosecond,
            precision,
            ..
        } = observations[*index].interpretation
        {
            values.push((nanosecond, precision));
        } else {
            return None;
        }
    }
    sort_dedup(&mut values);
    if values.len() == 1 {
        values.first().copied()
    } else {
        None
    }
}

fn has_semantic_conflict(indices: &[usize], observations: &[EvidenceObservation]) -> bool {
    let Some(first_index) = indices.first() else {
        return false;
    };
    let first = &observations[*first_index];
    indices.iter().skip(1).any(|index| {
        let current = &observations[*index];
        match (&first.interpretation, &current.interpretation) {
            (
                ObservationInterpretation::Rejected(first_error),
                ObservationInterpretation::Rejected(current_error),
            ) => first_error != current_error || first.field.raw_bytes != current.field.raw_bytes,
            (first_value, current_value) => first_value != current_value,
        }
    })
}

fn indices_of_kind(
    observations: &[EvidenceObservation],
    start: usize,
    end: usize,
    kind: MetadataFieldKind,
) -> Vec<usize> {
    (start..end)
        .filter(|index| observations[*index].field.kind == kind)
        .collect()
}

fn indices_by_exif_scope(
    indices: &[usize],
    observations: &[EvidenceObservation],
) -> BTreeMap<ExifScope, Vec<usize>> {
    let mut grouped = BTreeMap::new();
    for index in indices {
        if let Some(scope) = exif_scope(&observations[*index].field) {
            grouped.entry(scope).or_insert_with(Vec::new).push(*index);
        }
    }
    grouped
}

fn exif_scope(field: &MetadataField) -> Option<ExifScope> {
    match field.locator.container {
        MetadataContainer::Tiff {
            header_offset,
            ifd_offset,
            ..
        } => Some(ExifScope::Tiff {
            header_offset,
            ifd_offset,
        }),
        MetadataContainer::JpegExif {
            app1_offset,
            header_offset,
            ifd_offset,
            ..
        } => Some(ExifScope::JpegExif {
            app1_offset,
            header_offset,
            ifd_offset,
        }),
        MetadataContainer::IsoBmff { .. } => None,
    }
}

fn wall_total_nanoseconds(timestamp: NormalizedTimestamp) -> Option<i128> {
    timestamp
        .wall_time()
        .naive_unix_seconds()
        .checked_mul(i128::from(NANOS_PER_SECOND))?
        .checked_add(i128::from(timestamp.wall_time().nanosecond()))
}

fn seconds_to_nanoseconds(seconds: u64) -> i128 {
    i128::from(seconds) * i128::from(NANOS_PER_SECOND)
}

fn is_suspected_integer_hour(difference: i128, context: &PolicyContext) -> bool {
    let residual_tolerance = seconds_to_nanoseconds(
        context
            .integer_hour_residual_tolerance_seconds
            .min(MAX_INTEGER_HOUR_RESIDUAL_TOLERANCE_SECONDS),
    );
    let hour = 3_600_i128 * i128::from(NANOS_PER_SECOND);
    (1..=context
        .maximum_suspected_offset_hours
        .min(MAX_SUSPECTED_OFFSET_HOURS))
        .any(|hours| difference.abs_diff(i128::from(hours) * hour) <= residual_tolerance as u128)
}

fn is_obviously_future(timestamp: NormalizedTimestamp, context: &PolicyContext) -> bool {
    let tolerance = seconds_to_nanoseconds(
        context
            .obvious_future_tolerance_seconds
            .min(MAX_OBVIOUS_FUTURE_TOLERANCE_SECONDS),
    );
    if let Some(instant) = timestamp.utc_instant() {
        return match (
            instant.total_nanoseconds(),
            context.reference_utc.total_nanoseconds(),
        ) {
            (Some(value), Some(reference)) => value > reference.saturating_add(tolerance),
            _ => true,
        };
    }
    context.reference_wall_time.is_some_and(|reference| {
        let reference_value = reference
            .naive_unix_seconds()
            .saturating_mul(i128::from(NANOS_PER_SECOND))
            .saturating_add(i128::from(reference.nanosecond()));
        wall_total_nanoseconds(timestamp).map_or(true, |value| {
            value > reference_value.saturating_add(tolerance)
        })
    })
}

fn is_inside_automatic_range(timestamp: NormalizedTimestamp, context: &PolicyContext) -> bool {
    let Some(instant) = timestamp.utc_instant() else {
        return true;
    };
    let Some(value) = instant.total_nanoseconds() else {
        return false;
    };
    let caller_earliest = context
        .automatic_earliest_utc
        .map_or(MIN_AUTOMATIC_UNIX_NANOSECONDS, instant_total_bound);
    let caller_latest = context
        .automatic_latest_utc
        .map_or(MAX_AUTOMATIC_UNIX_NANOSECONDS, instant_total_bound);
    let earliest = MIN_AUTOMATIC_UNIX_NANOSECONDS.max(caller_earliest);
    let latest = MAX_AUTOMATIC_UNIX_NANOSECONDS.min(caller_latest);
    earliest <= latest && (earliest..=latest).contains(&value)
}

fn instant_total_bound(instant: crate::UtcInstant) -> i128 {
    instant.total_nanoseconds().unwrap_or_else(|| {
        if instant.unix_seconds().is_negative() {
            i128::MIN
        } else {
            i128::MAX
        }
    })
}

fn effective_strong_tolerance(context: &PolicyContext) -> u64 {
    context
        .strong_evidence_tolerance_seconds
        .min(MAX_STRONG_EVIDENCE_TOLERANCE_SECONDS)
}

fn single_observation_issue(
    code: PolicyIssueCode,
    field_kind: Option<MetadataFieldKind>,
    observation_index: usize,
    source_key: SourceKey,
    lineage_key: LineageKey,
    context: &'static str,
) -> PolicyIssue {
    PolicyIssue {
        code,
        field_kind,
        observation_indices: vec![observation_index],
        source_keys: vec![source_key],
        lineage_keys: vec![lineage_key],
        context,
    }
}

fn source_issue(
    code: PolicyIssueCode,
    source_key: SourceKey,
    lineage_key: LineageKey,
    context: &'static str,
) -> PolicyIssue {
    PolicyIssue {
        code,
        field_kind: None,
        observation_indices: Vec::new(),
        source_keys: vec![source_key],
        lineage_keys: vec![lineage_key],
        context,
    }
}

fn issue_for_indices(
    code: PolicyIssueCode,
    field_kind: Option<MetadataFieldKind>,
    mut indices: Vec<usize>,
    observations: &[EvidenceObservation],
    context: &'static str,
) -> PolicyIssue {
    sort_dedup(&mut indices);
    let mut sources = indices
        .iter()
        .map(|index| observations[*index].source_key)
        .collect::<Vec<_>>();
    let mut lineages = indices
        .iter()
        .map(|index| observations[*index].lineage_key)
        .collect::<Vec<_>>();
    sort_dedup(&mut sources);
    sort_dedup(&mut lineages);
    PolicyIssue {
        code,
        field_kind,
        observation_indices: indices,
        source_keys: sources,
        lineage_keys: lineages,
        context,
    }
}

fn issue_for_atom_indices(
    code: PolicyIssueCode,
    atoms: &[Atom],
    indices: &[usize],
    context: &'static str,
) -> PolicyIssue {
    let mut observations = Vec::new();
    let mut sources = Vec::new();
    let mut lineages = Vec::new();
    for index in indices {
        observations.extend_from_slice(&atoms[*index].observation_indices);
        sources.push(atoms[*index].source_key);
        lineages.push(atoms[*index].lineage_key);
    }
    sort_dedup(&mut observations);
    sort_dedup(&mut sources);
    sort_dedup(&mut lineages);
    PolicyIssue {
        code,
        field_kind: None,
        observation_indices: observations,
        source_keys: sources,
        lineage_keys: lineages,
        context,
    }
}

fn deduplicate_issues(issues: &mut Vec<PolicyIssue>) {
    for issue in issues.iter_mut() {
        sort_dedup(&mut issue.observation_indices);
        sort_dedup(&mut issue.source_keys);
        sort_dedup(&mut issue.lineage_keys);
    }
    issues.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then_with(|| {
                metadata_kind_rank(left.field_kind).cmp(&metadata_kind_rank(right.field_kind))
            })
            .then_with(|| left.observation_indices.cmp(&right.observation_indices))
            .then_with(|| left.source_keys.cmp(&right.source_keys))
            .then_with(|| left.lineage_keys.cmp(&right.lineage_keys))
    });
    issues.dedup_by(|left, right| {
        left.code == right.code
            && left.field_kind == right.field_kind
            && left.observation_indices == right.observation_indices
            && left.source_keys == right.source_keys
            && left.lineage_keys == right.lineage_keys
    });
}

fn metadata_kind_rank(kind: Option<MetadataFieldKind>) -> u8 {
    match kind {
        None => 0,
        Some(MetadataFieldKind::ExifDateTimeOriginal) => 1,
        Some(MetadataFieldKind::ExifCreateDate) => 2,
        Some(MetadataFieldKind::ExifModifyDate) => 3,
        Some(MetadataFieldKind::ExifOffsetTimeOriginal) => 4,
        Some(MetadataFieldKind::ExifSubSecTimeOriginal) => 5,
        Some(MetadataFieldKind::QuickTimeMovieHeaderCreationTime) => 6,
        Some(MetadataFieldKind::QuickTimeMetadataCreationDate) => 7,
    }
}

fn joined_indices(left: &[usize], right: &[usize]) -> Vec<usize> {
    let mut values = left.to_vec();
    values.extend_from_slice(right);
    sort_dedup(&mut values);
    values
}

fn sort_dedup<T: Ord>(values: &mut Vec<T>) {
    values.sort_unstable();
    values.dedup();
}

#[cfg(test)]
mod tests {
    use super::aggregate_counts_within_limits;
    use crate::{
        MAX_ANALYSIS_BMFF_PATH_COMPONENTS, MAX_ANALYSIS_EXTRACTION_ISSUES,
        MAX_ANALYSIS_OBSERVATIONS, MAX_ANALYSIS_RAW_BYTES, MAX_ANALYSIS_SENTINEL_RULES,
        MAX_ANALYSIS_SOURCES,
    };

    #[test]
    fn every_aggregate_dimension_has_a_hard_ceiling() {
        assert!(aggregate_counts_within_limits(1, 1, 0, 32, 6, 1));
        assert!(!aggregate_counts_within_limits(
            MAX_ANALYSIS_SOURCES + 1,
            0,
            0,
            0,
            0,
            0,
        ));
        assert!(!aggregate_counts_within_limits(
            1,
            MAX_ANALYSIS_OBSERVATIONS + 1,
            0,
            0,
            0,
            0,
        ));
        assert!(!aggregate_counts_within_limits(
            1,
            0,
            MAX_ANALYSIS_EXTRACTION_ISSUES + 1,
            0,
            0,
            0,
        ));
        assert!(!aggregate_counts_within_limits(
            1,
            0,
            0,
            MAX_ANALYSIS_RAW_BYTES + 1,
            0,
            0,
        ));
        assert!(aggregate_counts_within_limits(
            1,
            MAX_ANALYSIS_OBSERVATIONS,
            0,
            0,
            MAX_ANALYSIS_BMFF_PATH_COMPONENTS,
            MAX_ANALYSIS_SENTINEL_RULES,
        ));
        assert!(!aggregate_counts_within_limits(
            1,
            MAX_ANALYSIS_OBSERVATIONS,
            0,
            0,
            MAX_ANALYSIS_BMFF_PATH_COMPONENTS + 1,
            0,
        ));
        assert!(!aggregate_counts_within_limits(
            1,
            0,
            0,
            0,
            0,
            MAX_ANALYSIS_SENTINEL_RULES + 1,
        ));
    }
}
