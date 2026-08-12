use guiying_metadata::{
    extract_timestamp_evidence, DetectedFormat, ExtractionLimits, ExtractionReport,
    ExtractionStatus, ExtractionUsage, FieldEncoding, MetadataContainer, MetadataField,
    MetadataFieldKind, MetadataLocator, ParserIdentity, ReadAtSource, TiffByteOrder,
    PARSER_IDENTITY,
};
use guiying_time::{
    analyze_timestamp_evidence, parse_exif_timestamp, parse_quicktime_mvhd,
    parse_quicktime_timestamp, AnalysisDecision, CandidateAnomaly, Confidence,
    EvidenceBindingStatus, EvidenceGateBlocker, EvidenceGateDecision, EvidenceSource, LineageKey,
    OffsetKind, PolicyContext, PolicyIssueCode, SentinelRule, SourceKey, SourceRevalidationError,
    SourceVerifiedExtractionReport, TimeAnalysis, TimeEvidenceKind, TimestampParseError,
    UtcInstant, WallTime, MAX_ANALYSIS_SENTINEL_RULES, MAX_ANALYSIS_SOURCES,
};

#[test]
fn exif_strictly_validates_leap_years_and_calendar_ranges() {
    let leap =
        parse_exif_timestamp(b"2024:02:29 23:59:59\0", None, None).expect("2024 is a leap year");
    assert_eq!(leap.wall_time().day(), 29);
    assert_eq!(leap.utc_instant(), None);

    assert_eq!(
        parse_exif_timestamp(b"2023:02:29 12:00:00", None, None),
        Err(TimestampParseError::DayOutOfRange)
    );
    assert_eq!(
        parse_exif_timestamp(b"2000:02:29 12:00:00", None, None)
            .expect("divisible by 400 is a leap year")
            .wall_time()
            .year(),
        2000
    );
    assert_eq!(
        parse_exif_timestamp(b"1900:02:29 12:00:00", None, None),
        Err(TimestampParseError::DayOutOfRange)
    );
    assert_eq!(
        parse_exif_timestamp(b"2024:13:01 00:00:00", None, None),
        Err(TimestampParseError::MonthOutOfRange)
    );
    assert_eq!(
        parse_exif_timestamp(b"2024:12:01 24:00:00", None, None),
        Err(TimestampParseError::HourOutOfRange)
    );
    assert_eq!(
        parse_exif_timestamp(b"2024:12:01 23:59:60", None, None),
        Err(TimestampParseError::SecondOutOfRange)
    );
}

#[test]
fn exif_combines_subseconds_and_explicit_offsets_without_system_timezone() {
    let timestamp =
        parse_exif_timestamp(b"2024:06:07 08:09:10\0", Some(b"123\0"), Some(b"+08:00\0"))
            .expect("valid Exif timestamp");
    assert_eq!(timestamp.wall_time().nanosecond(), 123_000_000);
    assert_eq!(timestamp.precision().nanoseconds(), 1_000_000);
    assert_eq!(timestamp.utc_offset().expect("offset").minutes(), 480);
    assert_eq!(timestamp.offset_kind(), OffsetKind::Explicit);

    let floating = parse_exif_timestamp(b"2024:06:07 08:09:10", None, None)
        .expect("valid floating Exif timestamp");
    assert_eq!(floating.offset_kind(), OffsetKind::Missing);
    assert_eq!(floating.utc_instant(), None);

    assert_eq!(
        parse_exif_timestamp(b"2024:06:07 08:09:10", Some(b"1234567890"), Some(b"+08:00")),
        Err(TimestampParseError::SubsecondOutOfRange)
    );
    assert!(parse_exif_timestamp(b"2024:06:07 08:09:10", None, Some(b"+14:00")).is_ok());
    assert!(parse_exif_timestamp(b"2024:06:07 08:09:10", None, Some(b"-14:00")).is_ok());
    assert_eq!(
        parse_exif_timestamp(b"2024:06:07 08:09:10", None, Some(b"+14:01")),
        Err(TimestampParseError::OffsetOutOfRange)
    );
    assert_eq!(
        parse_exif_timestamp(b"2024:06:07 08:09:10", None, Some(b"-14:01")),
        Err(TimestampParseError::OffsetOutOfRange)
    );
}

#[test]
fn quicktime_iso8601_requires_strict_structure_and_preserves_offset() {
    let value = parse_quicktime_timestamp(b"2024-06-07T08:09:10.123456789-05:30")
        .expect("valid QuickTime timestamp");
    assert_eq!(value.wall_time().nanosecond(), 123_456_789);
    assert_eq!(value.precision().nanoseconds(), 1);
    assert_eq!(value.utc_offset().expect("offset").minutes(), -330);

    let utc = parse_quicktime_timestamp(b"2024-06-07T08:09:10Z").expect("valid UTC timestamp");
    assert_eq!(utc.utc_offset().expect("offset").minutes(), 0);

    let floating = parse_quicktime_timestamp(b"2024-06-07T08:09:10")
        .expect("missing offset remains representable");
    assert_eq!(floating.utc_instant(), None);

    assert_eq!(
        parse_quicktime_timestamp(b"2024-06-07 08:09:10+08:00"),
        Err(TimestampParseError::InvalidSyntax)
    );
    assert_eq!(
        parse_quicktime_timestamp(b"2024-06-07T08:09:10+0800")
            .expect("ISO basic offset")
            .utc_offset()
            .expect("offset")
            .minutes(),
        480
    );
    assert_eq!(
        parse_quicktime_timestamp(b"2024-06-07T08:09:10-00:00"),
        Err(TimestampParseError::UnknownNegativeZeroOffset)
    );
}

#[test]
fn quicktime_mvhd_decodes_1904_epoch_but_marks_semantics() {
    let epoch = parse_quicktime_mvhd(&0_u32.to_be_bytes()).expect("mvhd epoch");
    assert_eq!(epoch.wall_time().year(), 1904);
    assert_eq!(epoch.wall_time().month(), 1);
    assert_eq!(epoch.wall_time().day(), 1);
    assert_eq!(epoch.offset_kind(), OffsetKind::QuickTimeEpochAssumedUtc);

    let unix_epoch = parse_quicktime_mvhd(&2_082_844_800_u32.to_be_bytes())
        .expect("QuickTime representation of Unix epoch");
    assert_eq!(unix_epoch.wall_time().year(), 1970);
    assert_eq!(unix_epoch.utc_instant().expect("instant").unix_seconds(), 0);

    assert_eq!(
        parse_quicktime_mvhd(&[0, 1, 2]),
        Err(TimestampParseError::UnsupportedBinaryLength)
    );
    assert_eq!(
        parse_quicktime_mvhd(&u64::MAX.to_be_bytes()),
        Err(TimestampParseError::YearOutOfRange)
    );
}

#[test]
fn validated_exif_original_can_pass_only_the_evidence_gate() {
    let bytes = synthetic_tiff();
    let retained = extract_timestamp_evidence(&bytes, ExtractionLimits::default());
    let verified = SourceVerifiedExtractionReport::revalidate_from_pinned_source(
        SourceKey::new([1; 32]),
        &bytes,
        &retained,
    )
    .expect("the pinned source reproduces its report");
    assert_eq!(verified.source_key(), SourceKey::new([1; 32]));
    assert_eq!(
        verified_source(1, &verified).source_key(),
        verified.source_key()
    );
    let report = verified.report();
    let analysis = analyze_timestamp_evidence(
        &[verified_source(1, &verified)],
        &context_at("2025-01-01T00:00:00Z"),
    );

    assert_eq!(analysis.candidates.len(), 1);
    let candidate = &analysis.candidates[0];
    assert_eq!(candidate.confidence, Confidence::High);
    assert_eq!(candidate.evidence_gate, EvidenceGateDecision::Eligible);
    assert_eq!(candidate.supporting_lineages.len(), 1);
    assert_eq!(candidate.observation_indices, vec![0, 1, 2]);
    assert_eq!(
        analysis.observations[0].field.raw_bytes,
        fields_raw(report, 0)
    );
    assert_eq!(
        analysis.observations[0].field.locator.absolute_offset,
        report.fields[0].locator.absolute_offset
    );
    assert_eq!(analysis.observations[0].field.parser, PARSER_IDENTITY);
    assert!(matches!(
        analysis.decision,
        AnalysisDecision::EvidenceEligible { .. }
    ));
}

#[test]
fn real_metadata_extraction_report_satisfies_policy_contract() {
    let bytes = synthetic_tiff();
    let report = extract_timestamp_evidence(&bytes, ExtractionLimits::default());
    let verified = SourceVerifiedExtractionReport::revalidate_from_pinned_source(
        SourceKey::new([1; 32]),
        &bytes,
        &report,
    )
    .expect("the pinned source reproduces its report");
    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    let analysis = analyze_timestamp_evidence(
        &[verified_source(1, &verified)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert_eq!(analysis.candidates.len(), 1);
    assert_eq!(analysis.candidates[0].confidence, Confidence::High);
    assert_eq!(
        analysis.candidates[0].evidence_gate,
        EvidenceGateDecision::Eligible
    );
    assert!(!analysis.issues.iter().any(|issue| {
        matches!(
            issue.code,
            PolicyIssueCode::ExtractionBudgetContradiction
                | PolicyIssueCode::MetadataLocatorMismatch
                | PolicyIssueCode::ContainerFormatMismatch
        )
    }));
}

#[test]
fn real_jpeg_exif_extraction_satisfies_container_contract() {
    let bytes = jpeg_with_exif(&synthetic_tiff());
    let retained = extract_timestamp_evidence(&bytes, ExtractionLimits::default());
    let verified = SourceVerifiedExtractionReport::revalidate_from_pinned_source(
        SourceKey::new([1; 32]),
        &bytes,
        &retained,
    )
    .expect("the pinned source reproduces its report");
    assert_eq!(
        verified.report().status,
        ExtractionStatus::ExtractedUnvalidated
    );
    let analysis = analyze_timestamp_evidence(
        &[verified_source(1, &verified)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert_eq!(analysis.candidates.len(), 1);
    assert_eq!(
        analysis.candidates[0].evidence_gate,
        EvidenceGateDecision::Eligible
    );
    assert!(!analysis.issues.iter().any(|issue| {
        matches!(
            issue.code,
            PolicyIssueCode::MetadataLocatorMismatch | PolicyIssueCode::ContainerFormatMismatch
        )
    }));
}

#[test]
fn real_bmff_extraction_satisfies_canonical_locator_contract() {
    let bytes = synthetic_quicktime_movie(b"2024-02-03T04:05:06+08:00");
    let retained = extract_timestamp_evidence(&bytes, ExtractionLimits::default());
    let verified = SourceVerifiedExtractionReport::revalidate_from_pinned_source(
        SourceKey::new([1; 32]),
        &bytes,
        &retained,
    )
    .expect("the pinned source reproduces its report");
    assert_eq!(
        verified.report().status,
        ExtractionStatus::ExtractedUnvalidated
    );
    let analysis = analyze_timestamp_evidence(
        &[verified_source(1, &verified)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert_eq!(analysis.candidates.len(), 1);
    assert_eq!(
        analysis.source_reports[0].binding,
        EvidenceBindingStatus::ReextractedFromPinnedSource
    );
    assert!(!analysis.issues.iter().any(|issue| {
        matches!(
            issue.code,
            PolicyIssueCode::MetadataLocatorMismatch
                | PolicyIssueCode::ContainerFormatMismatch
                | PolicyIssueCode::ExtractionBudgetContradiction
        )
    }));
}

#[test]
fn extracted_unvalidated_never_bypasses_field_validation() {
    let report = extracted_report(vec![exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        b"2023:02:29 12:00:00\0",
        10,
    )]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(analysis.candidates.is_empty());
    assert_eq!(analysis.decision, AnalysisDecision::NoUsableEvidence);
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::InvalidField));
}

#[test]
fn malformed_exif_companion_conflicts_instead_of_becoming_floating() {
    let report = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"2024:01:01 00:00:00",
            10,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+14:01", 40),
    ]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
    assert_eq!(analysis.candidates[0].confidence, Confidence::Conflict);
    assert!(analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::InvalidCompanion));
}

#[test]
fn exif_companion_is_never_borrowed_across_ifd_scopes() {
    let dto = exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        b"2024:01:01 00:00:00",
        10,
    );
    let mut foreign_offset = exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+08:00", 40);
    let MetadataContainer::Tiff { ifd_offset, .. } = &mut foreign_offset.locator.container else {
        panic!("fixture uses TIFF locator");
    };
    *ifd_offset = 99;
    let report = extracted_report(vec![dto, foreign_offset]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert_eq!(analysis.candidates.len(), 1);
    assert_eq!(analysis.candidates[0].timestamp.utc_instant(), None);
    assert_ne!(
        analysis.candidates[0].evidence_gate,
        EvidenceGateDecision::Eligible
    );
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::OrphanExifCompanion));
}

#[test]
fn no_offset_dst_wall_time_remains_floating_and_review_only() {
    // This local time is in the US spring-forward gap in many zones. Without
    // an explicit zone, this crate neither rejects it nor guesses a zone.
    let report = extracted_report(vec![exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        b"2024:03:10 02:30:00\0",
        10,
    )]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    let candidate = &analysis.candidates[0];
    assert_eq!(candidate.timestamp.utc_instant(), None);
    assert_eq!(candidate.confidence, Confidence::Medium);
    assert!(candidate
        .anomalies
        .contains(&CandidateAnomaly::MissingOffset));
    assert!(matches!(
        candidate.evidence_gate,
        EvidenceGateDecision::Blocked(ref blockers)
            if blockers.contains(&EvidenceGateBlocker::NoUtcInstant)
    ));
    assert!(matches!(
        analysis.decision,
        AnalysisDecision::ReviewRequired { .. }
    ));
}

#[test]
fn repeated_same_kind_conflict_never_selects_the_first_value() {
    let report = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"2024:01:01 10:00:00\0",
            10,
        ),
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"2024:01:02 10:00:00\0",
            40,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00\0", 70),
    ]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert_eq!(analysis.candidates.len(), 2);
    assert!(analysis
        .candidates
        .iter()
        .all(|candidate| candidate.confidence == Confidence::Conflict));
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
    assert!(analysis.issues.iter().any(|issue| {
        issue.code == PolicyIssueCode::RepeatedFieldConflict
            && issue.field_kind == Some(MetadataFieldKind::ExifDateTimeOriginal)
    }));
}

#[test]
fn identical_repeated_values_are_audited_without_becoming_a_conflict() {
    let report = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"2024:01:01 10:00:00\0",
            10,
        ),
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"2024:01:01 10:00:00",
            40,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00\0", 70),
    ]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert_eq!(analysis.candidates.len(), 1);
    assert_eq!(analysis.candidates[0].confidence, Confidence::High);
    assert!(!analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::RepeatedFieldConflict));
    assert_eq!(analysis.candidates[0].observation_indices, vec![0, 1, 2]);
}

#[test]
fn dst_fallback_offsets_are_reported_as_integer_hour_timezone_conflict() {
    let first = extracted_report(vec![quicktime_text_field(b"2024-11-03T01:30:00-04:00", 10)]);
    let second = extracted_report(vec![quicktime_text_field(b"2024-11-03T01:30:00-05:00", 10)]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &first), source(2, 2, &second)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::PossibleTimezoneConflict));
}

#[test]
fn integer_hour_timezone_suspicion_stops_at_the_hard_fourteen_hour_boundary() {
    let first = extracted_report(vec![quicktime_text_field(b"2024-01-01T00:00:00Z", 10)]);
    for (other, expected) in [
        (
            b"2024-01-01T14:00:00Z".as_slice(),
            PolicyIssueCode::PossibleTimezoneConflict,
        ),
        (
            b"2024-01-01T15:00:00Z".as_slice(),
            PolicyIssueCode::StrongEvidenceConflict,
        ),
    ] {
        let second = extracted_report(vec![quicktime_text_field(other, 10)]);
        let analysis = analyze_timestamp_evidence(
            &[source(1, 1, &first), source(2, 2, &second)],
            &context_at("2025-01-01T00:00:00Z"),
        );
        assert!(analysis.issues.iter().any(|issue| issue.code == expected));
    }
}

#[test]
fn non_hour_strong_evidence_difference_is_a_hard_conflict() {
    let first = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"2024:01:01 00:00:00",
            10,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00", 40),
    ]);
    let second = extracted_report(vec![quicktime_text_field(b"2024-01-03T00:01:00Z", 10)]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &first), source(2, 2, &second)],
        &context_at("2025-01-10T00:00:00Z"),
    );
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::StrongEvidenceConflict));
}

#[test]
fn equal_rank_values_inside_tolerance_require_review_of_exact_value() {
    let first = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"2024:01:01 00:00:00",
            10,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00", 40),
    ]);
    let second = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"2024:01:01 00:00:01",
            10,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00", 40),
    ]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &first), source(2, 2, &second)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(matches!(
        analysis.decision,
        AnalysisDecision::ReviewRequired { .. }
    ));
    assert!(analysis
        .issues
        .iter()
        .any(|issue| { issue.code == PolicyIssueCode::StrongEvidenceWithinToleranceAmbiguous }));
    assert!(analysis.candidates.iter().all(|candidate| {
        matches!(
            candidate.evidence_gate,
            EvidenceGateDecision::Blocked(ref blockers)
                if blockers.contains(
                    &EvidenceGateBlocker::MultipleStrongValuesWithinTolerance
                )
        )
    }));
}

#[test]
fn cross_precision_near_values_inside_tolerance_are_ambiguous_for_review() {
    // 08:09:10.123 at millisecond precision vs 08:09:10 at second precision:
    // two different instants 123 ms apart must not silently prefer the finer
    // reading; the exact value is a review decision.
    let fine =
        synthetic_tiff_with_exif_original(b"2024:06:07 08:09:10\0", b"+00:00\0", Some(*b"123\0"));
    let coarse = synthetic_tiff_with_exif_original(b"2024:06:07 08:09:10\0", b"+00:00\0", None);
    let fine_verified = pinned_verified_report(1, &fine);
    let coarse_verified = pinned_verified_report(2, &coarse);
    let analysis = analyze_timestamp_evidence(
        &[
            verified_source(1, &fine_verified),
            verified_source(2, &coarse_verified),
        ],
        &context_at("2025-01-01T00:00:00Z"),
    );

    assert_eq!(analysis.candidates.len(), 2);
    assert!(analysis
        .candidates
        .iter()
        .all(|candidate| candidate.confidence == Confidence::High));
    assert!(matches!(
        analysis.decision,
        AnalysisDecision::ReviewRequired { .. }
    ));
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::StrongEvidenceWithinToleranceAmbiguous));
    assert!(analysis.candidates.iter().all(|candidate| {
        matches!(
            candidate.evidence_gate,
            EvidenceGateDecision::Blocked(ref blockers)
                if blockers.contains(
                    &EvidenceGateBlocker::MultipleStrongValuesWithinTolerance
                )
        )
    }));
}

#[test]
fn same_instant_across_precisions_is_refinement_not_ambiguity() {
    // 08:09:10.000 at millisecond precision and 08:09:10 at second precision
    // are the same semantic instant; restating it more precisely is a
    // refinement and must not be misreported as near-value ambiguity.
    let fine =
        synthetic_tiff_with_exif_original(b"2024:06:07 08:09:10\0", b"+00:00\0", Some(*b"000\0"));
    let coarse = synthetic_tiff_with_exif_original(b"2024:06:07 08:09:10\0", b"+00:00\0", None);
    let fine_verified = pinned_verified_report(1, &fine);
    let coarse_verified = pinned_verified_report(2, &coarse);
    let analysis = analyze_timestamp_evidence(
        &[
            verified_source(1, &fine_verified),
            verified_source(2, &coarse_verified),
        ],
        &context_at("2025-01-01T00:00:00Z"),
    );

    assert_eq!(analysis.candidates.len(), 2);
    assert!(!analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::StrongEvidenceWithinToleranceAmbiguous));
    assert!(analysis.candidates.iter().all(|candidate| {
        candidate.confidence == Confidence::High
            && candidate.evidence_gate == EvidenceGateDecision::Eligible
    }));
    let AnalysisDecision::EvidenceEligible { candidate_index } = analysis.decision else {
        panic!(
            "same-instant refinement must stay eligible, observed {:?}",
            analysis.decision
        );
    };
    let selected = &analysis.candidates[candidate_index];
    let other = &analysis.candidates[1 - candidate_index];
    assert_eq!(selected.timestamp.precision().nanoseconds(), 1_000_000);
    assert_eq!(
        selected.timestamp.utc_instant(),
        other.timestamp.utc_instant()
    );
}

#[test]
fn duplicate_copy_count_does_not_outvote_an_independent_lineage() {
    let agreeing_reports = (0..8)
        .map(|index| {
            let report = extracted_report(vec![quicktime_text_field(b"2024-01-01T00:00:00Z", 10)]);
            (index, report)
        })
        .collect::<Vec<_>>();
    let conflict = extracted_report(vec![quicktime_text_field(b"2024-01-03T00:01:00Z", 10)]);
    let mut sources = agreeing_reports
        .iter()
        .map(|(index, report)| source(u8::try_from(*index + 1).expect("small index"), 1, report))
        .collect::<Vec<_>>();
    sources.push(source(99, 2, &conflict));

    let analysis = analyze_timestamp_evidence(&sources, &context_at("2025-01-01T00:00:00Z"));
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
    let popular = analysis
        .candidates
        .iter()
        .find(|candidate| candidate.timestamp.wall_time().day() == 1)
        .expect("popular candidate retained");
    assert_eq!(popular.supporting_sources.len(), 8);
    assert_eq!(popular.supporting_lineages.len(), 1);
    assert_eq!(popular.confidence, Confidence::Conflict);
}

#[test]
fn differing_copy_derived_sources_create_a_lineage_conflict() {
    let first = extracted_report(vec![quicktime_text_field(b"2024-01-01T00:00:00Z", 10)]);
    let second = extracted_report(vec![quicktime_text_field(b"2024-01-02T00:00:01Z", 10)]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 7, &first), source(2, 7, &second)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::LineageConflict));
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
}

#[test]
fn mvhd_alone_is_low_confidence_and_never_evidence_eligible() {
    let instant = parse_quicktime_timestamp(b"2024-01-02T03:04:05Z")
        .expect("fixture")
        .utc_instant()
        .expect("fixture instant");
    let report = extracted_report(vec![mvhd_field(mvhd_seconds(instant), 10)]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    let candidate = &analysis.candidates[0];
    assert_eq!(candidate.confidence, Confidence::Low);
    assert!(candidate
        .anomalies
        .contains(&CandidateAnomaly::QuickTimeEpochSemanticUncertainty));
    assert!(matches!(
        candidate.evidence_gate,
        EvidenceGateDecision::Blocked(ref blockers)
            if blockers.contains(&EvidenceGateBlocker::QuickTimeEpochSemanticUncertainty)
    ));
}

#[test]
fn quicktime_text_plus_matching_mvhd_remains_review_only_without_track_binding() {
    let text = b"2024-01-02T03:04:05Z";
    let instant = parse_quicktime_timestamp(text)
        .expect("fixture")
        .utc_instant()
        .expect("fixture instant");
    let report = extracted_report(vec![
        quicktime_text_field(text, 10),
        mvhd_field(mvhd_seconds(instant), 50),
    ]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    let text_candidate = analysis
        .candidates
        .iter()
        .find(|candidate| {
            candidate
                .evidence_kinds
                .contains(&TimeEvidenceKind::QuickTimeMetadataCreationDate)
        })
        .expect("text candidate");
    assert_eq!(text_candidate.confidence, Confidence::Medium);
    assert_ne!(text_candidate.evidence_gate, EvidenceGateDecision::Eligible);
    assert!(matches!(
        analysis.decision,
        AnalysisDecision::ReviewRequired { .. }
    ));
}

#[test]
fn quicktime_offset_and_source_boundaries_never_invent_high_confidence() {
    let floating_text = b"2024-01-02T03:04:05";
    let instant = parse_quicktime_timestamp(b"2024-01-02T03:04:05Z")
        .expect("fixture")
        .utc_instant()
        .expect("fixture instant");
    let floating_report = extracted_report(vec![
        quicktime_text_field(floating_text, 10),
        mvhd_field(mvhd_seconds(instant), 50),
    ]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &floating_report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    let text_candidate = analysis
        .candidates
        .iter()
        .find(|candidate| {
            candidate
                .evidence_kinds
                .contains(&TimeEvidenceKind::QuickTimeMetadataCreationDate)
        })
        .expect("text candidate");
    assert_ne!(text_candidate.confidence, Confidence::High);

    let text_report = extracted_report(vec![quicktime_text_field(b"2024-01-02T03:04:05Z", 10)]);
    let mvhd_report = extracted_report(vec![mvhd_field(mvhd_seconds(instant), 50)]);
    let analysis = analyze_timestamp_evidence(
        &[source(2, 7, &text_report), source(3, 7, &mvhd_report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    let text_candidate = analysis
        .candidates
        .iter()
        .find(|candidate| {
            candidate
                .evidence_kinds
                .contains(&TimeEvidenceKind::QuickTimeMetadataCreationDate)
        })
        .expect("text candidate");
    assert_eq!(text_candidate.confidence, Confidence::Medium);
}

#[test]
fn caller_context_marks_1904_1970_and_obvious_future() {
    let unix_epoch = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"1970:01:02 00:00:00",
            10,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00", 40),
    ]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &unix_epoch)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::SentinelValue));
    assert_eq!(analysis.candidates[0].confidence, Confidence::Low);

    let mvhd_epoch = extracted_report(vec![mvhd_field(0, 10)]);
    let analysis = analyze_timestamp_evidence(
        &[source(2, 2, &mvhd_epoch)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::SentinelValue));

    let future = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"2030:01:01 00:00:00",
            10,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00", 40),
    ]);
    let analysis = analyze_timestamp_evidence(
        &[source(3, 3, &future)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::ObviousFuture));
    assert_eq!(analysis.candidates[0].confidence, Confidence::Low);
}

#[test]
fn floating_future_is_checked_only_against_explicit_caller_wall_time() {
    let report = extracted_report(vec![exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        b"2030:01:01 00:00:00",
        10,
    )]);
    let mut without_wall = context_at("2025-01-01T00:00:00Z");
    without_wall.sentinel_rules.clear();
    let analysis = analyze_timestamp_evidence(&[source(1, 1, &report)], &without_wall);
    assert!(!analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::ObviousFuture));

    let mut with_wall = without_wall;
    with_wall.reference_wall_time =
        Some(WallTime::new(2025, 1, 1, 0, 0, 0, 0).expect("valid reference wall time"));
    let analysis = analyze_timestamp_evidence(&[source(1, 1, &report)], &with_wall);
    assert!(analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::ObviousFuture));
}

#[test]
fn partial_extraction_and_contract_contradictions_fail_closed() {
    let mut report = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"2024:01:01 00:00:00",
            10,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00", 40),
    ]);
    report.status = ExtractionStatus::Partial;
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(analysis.candidates.is_empty());
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::ExtractionReportUntrusted));
    assert_eq!(analysis.observations.len(), 2, "raw fields remain audited");
}

#[test]
fn parser_and_encoding_mismatch_are_not_trusted() {
    let mut wrong_parser = exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        b"2024:01:01 00:00:00",
        10,
    );
    wrong_parser.parser = ParserIdentity {
        name: "different-parser",
        version: "1",
    };
    wrong_parser.encoding = FieldEncoding::ValidatedUtf8;
    let report = extracted_report(vec![wrong_parser]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(analysis.candidates.is_empty());
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::ParserIdentityMismatch));
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::FieldEncodingMismatch));
}

#[test]
fn unknown_parser_and_impossible_usage_fail_closed() {
    let fields = vec![exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        b"2024:01:01 00:00:00",
        10,
    )];
    let mut report = extracted_report(fields);
    report.parser = ParserIdentity {
        name: "unapproved-parser",
        version: "1",
    };
    report.usage.fields_emitted = 0;
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
    assert!(analysis.candidates.is_empty());
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::UnknownParserIdentity));
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::ExtractionBudgetContradiction));
}

#[test]
fn format_locator_and_duplicate_source_contracts_fail_closed() {
    let mut field = exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        b"2024:01:01 00:00:00",
        10,
    );
    field.locator.byte_len += 1;
    let mut report = extracted_report(vec![field]);
    report.format = Some(DetectedFormat::IsoBmff);
    let duplicate = [source(1, 1, &report), source(1, 1, &report)];
    let analysis = analyze_timestamp_evidence(&duplicate, &context_at("2025-01-01T00:00:00Z"));
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
    assert!(analysis.candidates.is_empty());
    for code in [
        PolicyIssueCode::ContainerFormatMismatch,
        PolicyIssueCode::MetadataLocatorMismatch,
        PolicyIssueCode::DuplicateSourceIdentity,
    ] {
        assert!(analysis.issues.iter().any(|issue| issue.code == code));
    }
}

#[test]
fn hard_sentinels_cannot_be_removed_by_caller() {
    let report = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"1970:01:02 00:00:00",
            10,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00", 40),
    ]);
    let mut context = context_at("2025-01-01T00:00:00Z");
    context.sentinel_rules = vec![SentinelRule::Year(1904)];
    let analysis = analyze_timestamp_evidence(&[source(1, 1, &report)], &context);
    assert!(analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::SentinelValue));
    assert_eq!(analysis.candidates[0].confidence, Confidence::Low);
    assert!(matches!(
        analysis.candidates[0].evidence_gate,
        EvidenceGateDecision::Blocked(ref blockers)
            if blockers.contains(&EvidenceGateBlocker::SentinelValue)
    ));
}

#[test]
fn hard_1980_sentinel_is_reported_with_accurate_context() {
    let report = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"1980:07:01 12:00:00",
            10,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00", 40),
    ]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::SentinelValue));
    assert!(analysis.issues.iter().any(|issue| {
        issue.code == PolicyIssueCode::SentinelValue
            && issue.context == "candidate matches a non-removable or caller-supplied sentinel rule"
    }));
}

#[test]
fn indexed_sentinels_match_every_rule_kind() {
    let raw = b"2024-01-02T03:04:05Z";
    let timestamp = parse_quicktime_timestamp(raw).expect("valid fixture timestamp");
    let instant = timestamp.utc_instant().expect("fixture carries UTC");
    let rules = [
        SentinelRule::Year(2024),
        SentinelRule::Date {
            year: 2024,
            month: 1,
            day: 2,
        },
        SentinelRule::WallTime(timestamp.wall_time()),
        SentinelRule::UnixSecond(instant.unix_seconds()),
    ];
    let report = extracted_report(vec![quicktime_text_field(raw, 10)]);
    for rule in rules {
        let mut context = context_at("2025-01-01T00:00:00Z");
        context.sentinel_rules = vec![rule];
        let analysis = analyze_timestamp_evidence(&[source(1, 1, &report)], &context);
        assert!(analysis.candidates[0]
            .anomalies
            .contains(&CandidateAnomaly::SentinelValue));
    }
}

#[test]
fn sentinel_rule_limit_is_inclusive_and_matches_the_last_deduplicated_rule() {
    let raw = b"2024-01-02T03:04:05Z";
    let timestamp = parse_quicktime_timestamp(raw).expect("valid fixture timestamp");
    let matching_second = timestamp
        .utc_instant()
        .expect("fixture carries UTC")
        .unix_seconds();
    let report = extracted_report(vec![quicktime_text_field(raw, 10)]);
    let mut context = context_at("2025-01-01T00:00:00Z");
    context.sentinel_rules = vec![SentinelRule::Year(9999); MAX_ANALYSIS_SENTINEL_RULES - 1];
    context
        .sentinel_rules
        .push(SentinelRule::UnixSecond(matching_second));

    let analysis = analyze_timestamp_evidence(&[source(1, 1, &report)], &context);
    assert_ne!(analysis.decision, AnalysisDecision::Conflict);
    assert!(analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::SentinelValue));

    context.sentinel_rules.push(SentinelRule::Year(2024));
    let analysis = analyze_timestamp_evidence(&[source(1, 1, &report)], &context);
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
    assert!(analysis.candidates.is_empty());
    assert_eq!(analysis.issues.len(), 1);
    assert_eq!(
        analysis.issues[0].code,
        PolicyIssueCode::AnalysisLimitExceeded
    );
}

#[test]
fn automatic_range_retains_but_blocks_i64_nanosecond_outliers() {
    let context = context_at("2262-04-11T23:47:16.854775807Z");
    for (raw, outside) in [
        (b"0001:01:01 00:00:00\0".as_slice(), true),
        (b"1677:09:21 00:12:43\0".as_slice(), true),
        (b"1677:09:21 00:12:44\0".as_slice(), false),
        (b"2262:04:11 23:47:16\0".as_slice(), false),
        (b"2262:04:11 23:47:17\0".as_slice(), true),
    ] {
        let analysis = verified_exif_analysis(raw, &context);
        let candidate = &analysis.candidates[0];
        assert_eq!(
            candidate
                .anomalies
                .contains(&CandidateAnomaly::OutsideAutomaticRange),
            outside,
            "unexpected automatic-range result for {:?}",
            String::from_utf8_lossy(raw)
        );
        if outside {
            assert!(matches!(
                candidate.evidence_gate,
                EvidenceGateDecision::Blocked(ref blockers)
                    if blockers.contains(&EvidenceGateBlocker::OutsideAutomaticRange)
            ));
        } else {
            assert_eq!(candidate.evidence_gate, EvidenceGateDecision::Eligible);
        }
    }
}

#[test]
fn automatic_range_uses_exact_signed_i64_nanosecond_boundaries() {
    let context = context_at("2262-04-12T00:00:00Z");
    let minimum = i128::from(i64::MIN);
    let maximum = i128::from(i64::MAX);
    for (date, subsecond, expected_total, outside) in [
        (
            b"1677:09:21 00:12:43".as_slice(),
            b"145224191".as_slice(),
            minimum - 1,
            true,
        ),
        (
            b"1677:09:21 00:12:43".as_slice(),
            b"145224192".as_slice(),
            minimum,
            false,
        ),
        (
            b"1677:09:21 00:12:43".as_slice(),
            b"145224193".as_slice(),
            minimum + 1,
            false,
        ),
        (
            b"2262:04:11 23:47:16".as_slice(),
            b"854775806".as_slice(),
            maximum - 1,
            false,
        ),
        (
            b"2262:04:11 23:47:16".as_slice(),
            b"854775807".as_slice(),
            maximum,
            false,
        ),
        (
            b"2262:04:11 23:47:16".as_slice(),
            b"854775808".as_slice(),
            maximum + 1,
            true,
        ),
    ] {
        let report = extracted_report(vec![
            exif_field(MetadataFieldKind::ExifDateTimeOriginal, date, 10),
            exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00", 40),
            exif_field(MetadataFieldKind::ExifSubSecTimeOriginal, subsecond, 70),
        ]);
        let analysis = analyze_timestamp_evidence(&[source(1, 1, &report)], &context);
        let candidate = &analysis.candidates[0];
        let instant = candidate
            .timestamp
            .utc_instant()
            .expect("explicit offset produces UTC");
        let actual_total = instant
            .unix_seconds()
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(i128::from(instant.nanosecond())))
            .expect("fixture total fits i128");
        assert_eq!(actual_total, expected_total);
        assert_eq!(
            candidate
                .anomalies
                .contains(&CandidateAnomaly::OutsideAutomaticRange),
            outside
        );
    }
}

#[test]
fn caller_can_only_tighten_the_automatic_range() {
    let mut context = context_at("2025-01-01T00:00:00Z");
    context.automatic_earliest_utc = Some(
        parse_quicktime_timestamp(b"2024-06-08T00:00:00Z")
            .expect("valid lower bound")
            .utc_instant()
            .expect("bound has an offset"),
    );
    let analysis = verified_exif_analysis(b"2024:06:07 08:09:10\0", &context);
    assert!(analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::OutsideAutomaticRange));

    let mut attempted_widening = context_at("2025-01-01T00:00:00Z");
    attempted_widening.sentinel_rules.clear();
    attempted_widening.automatic_earliest_utc =
        Some(UtcInstant::new(i128::MIN, 0).expect("valid extreme instant"));
    attempted_widening.automatic_latest_utc =
        Some(UtcInstant::new(i128::MAX, 0).expect("valid extreme instant"));
    let analysis = verified_exif_analysis(b"0001:01:01 00:00:00\0", &attempted_widening);
    assert!(analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::OutsideAutomaticRange));
}

#[test]
fn extreme_reference_instants_fail_closed_without_overflow() {
    for reference in [
        UtcInstant::new(i128::MIN, 0).expect("valid extreme instant"),
        UtcInstant::new(i128::MAX, 0).expect("valid extreme instant"),
    ] {
        let mut context = PolicyContext::conservative(reference);
        context.sentinel_rules.clear();
        let analysis = verified_exif_analysis(b"0001:01:01 00:00:00\0", &context);
        assert!(matches!(
            analysis.candidates[0].evidence_gate,
            EvidenceGateDecision::Blocked(ref blockers)
                if blockers.contains(&EvidenceGateBlocker::OutsideAutomaticRange)
        ));
    }
}

#[test]
fn unverified_reports_are_review_only_and_source_changes_break_revalidation() {
    let bytes = synthetic_tiff();
    let report = extract_timestamp_evidence(&bytes, ExtractionLimits::default());
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(matches!(
        analysis.candidates[0].evidence_gate,
        EvidenceGateDecision::Blocked(ref blockers)
            if blockers.contains(&EvidenceGateBlocker::SourceNotRevalidated)
    ));
    assert!(matches!(
        analysis.decision,
        AnalysisDecision::ReviewRequired { .. }
    ));

    let changed = synthetic_tiff_with_date(b"2024:06:08 08:09:10\0");
    assert_eq!(
        SourceVerifiedExtractionReport::revalidate_from_pinned_source(
            SourceKey::new([1; 32]),
            &changed,
            &report,
        ),
        Err(SourceRevalidationError::ReportMismatch)
    );
}

#[test]
fn canonical_locators_and_per_field_budgets_fail_closed() {
    let mut wrong_container = extracted_report(vec![exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        b"2024:01:01 00:00:00",
        10,
    )]);
    wrong_container.format = Some(DetectedFormat::Jpeg);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &wrong_container)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::ContainerFormatMismatch));

    let mut bad_path = quicktime_text_field(b"2024-01-01T00:00:00Z", 10);
    let MetadataContainer::IsoBmff { box_path, .. } = &mut bad_path.locator.container else {
        panic!("fixture uses BMFF locator");
    };
    *box_path = vec![*b"moov", *b"free"];
    let report = extracted_report(vec![bad_path]);
    let analysis = analyze_timestamp_evidence(
        &[source(2, 2, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::MetadataLocatorMismatch));

    let maximum = usize::try_from(ExtractionLimits::default().max_field_bytes)
        .expect("test platform represents the field limit");
    let mut oversized = b"2024:01:01 00:00:00".to_vec();
    oversized.resize(maximum + 1, b' ');
    let report = extracted_report(vec![exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        &oversized,
        10,
    )]);
    let analysis = analyze_timestamp_evidence(
        &[source(3, 3, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert!(analysis
        .issues
        .iter()
        .any(|issue| issue.code == PolicyIssueCode::ExtractionBudgetContradiction));
}

#[test]
fn aggregate_rejects_oversized_bmff_paths_before_retaining_observations() {
    for component_count in [7, 1_000_000] {
        let mut report = extracted_report(vec![quicktime_text_field(b"2024-01-01T00:00:00Z", 10)]);
        let MetadataContainer::IsoBmff { box_path, .. } = &mut report.fields[0].locator.container
        else {
            panic!("fixture uses BMFF locator");
        };
        *box_path = vec![*b"free"; component_count];
        let analysis = analyze_timestamp_evidence(
            &[source(1, 1, &report)],
            &context_at("2025-01-01T00:00:00Z"),
        );
        assert_eq!(analysis.decision, AnalysisDecision::Conflict);
        assert!(analysis.source_reports.is_empty());
        assert!(analysis.observations.is_empty());
        assert_eq!(analysis.issues.len(), 1);
        assert_eq!(
            analysis.issues[0].code,
            PolicyIssueCode::AnalysisLimitExceeded
        );
    }
}

#[test]
fn impossible_read_format_counter_and_locator_depth_usage_fail_closed() {
    let base = extracted_report(vec![exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        b"2024:01:01 00:00:00",
        10,
    )]);
    let mut no_reads = base.clone();
    no_reads.usage.bytes_read = 0;
    no_reads.usage.read_operations = 0;
    let mut wrong_format_counter = base.clone();
    wrong_format_counter.usage.bmff_boxes_visited = 1;
    let mut insufficient_locator_depth = base;
    insufficient_locator_depth.usage.max_depth_observed = 1;

    for report in [no_reads, wrong_format_counter, insufficient_locator_depth] {
        let analysis = analyze_timestamp_evidence(
            &[source(1, 1, &report)],
            &context_at("2025-01-01T00:00:00Z"),
        );
        assert_eq!(analysis.decision, AnalysisDecision::Conflict);
        assert!(analysis.candidates.is_empty());
        assert!(analysis
            .issues
            .iter()
            .any(|issue| issue.code == PolicyIssueCode::ExtractionBudgetContradiction));
    }
}

#[test]
fn aggregate_source_limit_fails_closed_before_analysis() {
    let report = extracted_report(vec![quicktime_text_field(b"2024-01-01T00:00:00Z", 10)]);
    let repeated = source(1, 1, &report);
    let sources = vec![repeated; MAX_ANALYSIS_SOURCES + 1];
    let analysis = analyze_timestamp_evidence(&sources, &context_at("2025-01-01T00:00:00Z"));
    assert_eq!(analysis.decision, AnalysisDecision::Conflict);
    assert!(analysis.candidates.is_empty());
    assert_eq!(analysis.issues.len(), 1);
    assert_eq!(
        analysis.issues[0].code,
        PolicyIssueCode::AnalysisLimitExceeded
    );
}

#[test]
fn independent_exif_ifd_scopes_do_not_create_repeated_field_conflicts() {
    let first_date = exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        b"2024:01:01 10:00:00",
        10,
    );
    let first_offset = exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00", 40);
    let mut second_date = exif_field(
        MetadataFieldKind::ExifDateTimeOriginal,
        b"2024:01:01 11:00:00",
        70,
    );
    let mut second_offset = exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+01:00", 100);
    for field in [&mut second_date, &mut second_offset] {
        let MetadataContainer::Tiff { ifd_offset, .. } = &mut field.locator.container else {
            panic!("fixture uses TIFF locator");
        };
        *ifd_offset = 99;
    }
    let report = extracted_report(vec![first_date, first_offset, second_date, second_offset]);
    let analysis = analyze_timestamp_evidence(
        &[source(1, 1, &report)],
        &context_at("2025-01-01T00:00:00Z"),
    );
    assert_eq!(analysis.candidates.len(), 2);
    assert!(!analysis.issues.iter().any(|issue| {
        matches!(
            issue.code,
            PolicyIssueCode::RepeatedFieldConflict
                | PolicyIssueCode::LineageConflict
                | PolicyIssueCode::StrongEvidenceConflict
                | PolicyIssueCode::PossibleTimezoneConflict
        )
    }));
    assert!(matches!(
        analysis.decision,
        AnalysisDecision::ReviewRequired { .. }
    ));
}

#[test]
fn caller_cannot_expand_tolerances_past_hard_safety_ceilings() {
    let text = b"2024-01-01T00:00:00Z";
    let far_mvhd = parse_quicktime_timestamp(b"2024-02-01T00:00:00Z")
        .expect("fixture")
        .utc_instant()
        .expect("instant");
    let report = extracted_report(vec![
        quicktime_text_field(text, 10),
        mvhd_field(mvhd_seconds(far_mvhd), 50),
    ]);
    let mut context = context_at("2025-01-01T00:00:00Z");
    context.strong_evidence_tolerance_seconds = u64::MAX;
    let analysis = analyze_timestamp_evidence(&[source(1, 1, &report)], &context);
    let text_candidate = analysis
        .candidates
        .iter()
        .find(|candidate| {
            candidate
                .evidence_kinds
                .contains(&TimeEvidenceKind::QuickTimeMetadataCreationDate)
        })
        .expect("text candidate");
    assert_eq!(text_candidate.confidence, Confidence::Medium);

    let future = extracted_report(vec![
        exif_field(
            MetadataFieldKind::ExifDateTimeOriginal,
            b"2030:01:01 00:00:00",
            10,
        ),
        exif_field(MetadataFieldKind::ExifOffsetTimeOriginal, b"+00:00", 40),
    ]);
    context.obvious_future_tolerance_seconds = u64::MAX;
    let analysis = analyze_timestamp_evidence(&[source(2, 2, &future)], &context);
    assert!(analysis.candidates[0]
        .anomalies
        .contains(&CandidateAnomaly::ObviousFuture));
}

fn context_at(iso: impl AsRef<[u8]>) -> PolicyContext {
    let instant = parse_quicktime_timestamp(iso.as_ref())
        .expect("valid context fixture")
        .utc_instant()
        .expect("context fixture carries offset");
    PolicyContext::conservative(instant)
}

fn source(source: u8, lineage: u8, report: &ExtractionReport) -> EvidenceSource<'_> {
    EvidenceSource::unverified(
        SourceKey::new([source; 32]),
        LineageKey::new([lineage; 32]),
        report,
    )
}

fn verified_source(lineage: u8, report: &SourceVerifiedExtractionReport) -> EvidenceSource<'_> {
    EvidenceSource::source_verified(LineageKey::new([lineage; 32]), report)
}

fn pinned_verified_report(source: u8, bytes: &impl ReadAtSource) -> SourceVerifiedExtractionReport {
    let retained = extract_timestamp_evidence(bytes, ExtractionLimits::default());
    SourceVerifiedExtractionReport::revalidate_from_pinned_source(
        SourceKey::new([source; 32]),
        bytes,
        &retained,
    )
    .expect("the pinned source reproduces its report")
}

fn verified_exif_analysis(raw: &[u8], context: &PolicyContext) -> TimeAnalysis {
    let bytes = synthetic_tiff_with_date_and_offset(raw, b"+00:00\0");
    let retained = extract_timestamp_evidence(&bytes, ExtractionLimits::default());
    let verified = SourceVerifiedExtractionReport::revalidate_from_pinned_source(
        SourceKey::new([1; 32]),
        &bytes,
        &retained,
    )
    .expect("the pinned source reproduces its report");
    analyze_timestamp_evidence(&[verified_source(1, &verified)], context)
}

fn extracted_report(fields: Vec<MetadataField>) -> ExtractionReport {
    let format = if fields.iter().all(|field| {
        matches!(
            field.kind,
            MetadataFieldKind::QuickTimeMovieHeaderCreationTime
                | MetadataFieldKind::QuickTimeMetadataCreationDate
        )
    }) {
        DetectedFormat::IsoBmff
    } else {
        DetectedFormat::Tiff
    };
    let retained_field_bytes = fields
        .iter()
        .map(|field| field.locator.byte_len)
        .sum::<u64>();
    let fields_emitted = u32::try_from(fields.len()).expect("fixture field count");
    let (ifd_entries_visited, bmff_boxes_visited, max_depth_observed) = match format {
        DetectedFormat::Jpeg => unreachable!("fixture helper does not synthesize JPEG reports"),
        DetectedFormat::Tiff => {
            let depth = if fields.is_empty() {
                0
            } else if fields
                .iter()
                .all(|field| field.kind == MetadataFieldKind::ExifModifyDate)
            {
                1
            } else {
                2
            };
            (fields_emitted, 0, depth)
        }
        DetectedFormat::IsoBmff => {
            let depth = fields
                .iter()
                .filter_map(|field| match &field.locator.container {
                    MetadataContainer::IsoBmff { box_path, .. } => {
                        u16::try_from(box_path.len()).ok()
                    }
                    _ => None,
                })
                .max()
                .unwrap_or(0);
            (0, fields_emitted, depth)
        }
    };
    ExtractionReport {
        parser: PARSER_IDENTITY,
        limits: ExtractionLimits::default(),
        format: Some(format),
        status: ExtractionStatus::ExtractedUnvalidated,
        fields,
        issues: Vec::new(),
        usage: ExtractionUsage {
            bytes_read: retained_field_bytes,
            read_operations: u64::from(fields_emitted),
            retained_field_bytes,
            fields_emitted,
            ifd_entries_visited,
            bmff_boxes_visited,
            max_depth_observed,
            ..ExtractionUsage::default()
        },
    }
}

fn exif_field(kind: MetadataFieldKind, raw: &[u8], offset: u64) -> MetadataField {
    MetadataField {
        parser: PARSER_IDENTITY,
        kind,
        encoding: FieldEncoding::DeclaredAscii,
        locator: MetadataLocator {
            absolute_offset: offset,
            byte_len: u64::try_from(raw.len()).expect("fixture length"),
            container: MetadataContainer::Tiff {
                header_offset: 0,
                ifd_offset: 8,
                tag: exif_tag(kind),
                byte_order: TiffByteOrder::LittleEndian,
            },
        },
        raw_bytes: raw.to_vec(),
    }
}

fn quicktime_text_field(raw: &[u8], offset: u64) -> MetadataField {
    MetadataField {
        parser: PARSER_IDENTITY,
        kind: MetadataFieldKind::QuickTimeMetadataCreationDate,
        encoding: FieldEncoding::ValidatedUtf8,
        locator: MetadataLocator {
            absolute_offset: offset.saturating_add(16),
            byte_len: u64::try_from(raw.len()).expect("fixture length"),
            container: MetadataContainer::IsoBmff {
                box_offset: offset,
                box_path: vec![
                    *b"moov",
                    *b"udta",
                    *b"meta",
                    *b"ilst",
                    [0xa9, b'd', b'a', b'y'],
                    *b"data",
                ],
            },
        },
        raw_bytes: raw.to_vec(),
    }
}

fn mvhd_field(seconds: u64, offset: u64) -> MetadataField {
    MetadataField {
        parser: PARSER_IDENTITY,
        kind: MetadataFieldKind::QuickTimeMovieHeaderCreationTime,
        encoding: FieldEncoding::UnsignedBigEndian,
        locator: MetadataLocator {
            absolute_offset: offset.saturating_add(12),
            byte_len: 8,
            container: MetadataContainer::IsoBmff {
                box_offset: offset,
                box_path: vec![*b"moov", *b"mvhd"],
            },
        },
        raw_bytes: seconds.to_be_bytes().to_vec(),
    }
}

fn mvhd_seconds(instant: UtcInstant) -> u64 {
    u64::try_from(instant.unix_seconds() + 2_082_844_800).expect("fixture fits mvhd")
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

fn fields_raw(report: &ExtractionReport, index: usize) -> Vec<u8> {
    report.fields[index].raw_bytes.clone()
}

fn synthetic_tiff() -> Vec<u8> {
    synthetic_tiff_with_date_and_offset(b"2024:06:07 08:09:10\0", b"+08:00\0")
}

fn synthetic_tiff_with_date(original: &[u8]) -> Vec<u8> {
    synthetic_tiff_with_date_and_offset(original, b"+08:00\0")
}

fn synthetic_tiff_with_date_and_offset(original: &[u8], offset: &[u8]) -> Vec<u8> {
    synthetic_tiff_with_exif_original(original, offset, Some(*b"123\0"))
}

fn synthetic_tiff_with_exif_original(
    original: &[u8],
    offset: &[u8],
    subsecond: Option<[u8; 4]>,
) -> Vec<u8> {
    assert_eq!(original.len(), 20, "Exif fixture must be 19 bytes plus NUL");
    assert_eq!(
        offset.len(),
        7,
        "Exif offset fixture must be 6 bytes plus NUL"
    );
    let mut bytes = vec![0_u8; 220];
    bytes[0..8].copy_from_slice(b"II\x2a\x00\x08\x00\x00\x00");
    put_u16_le(&mut bytes, 8, 1);
    put_ifd_entry_le(&mut bytes, 10, 0x8769, 4, 1, 64);
    put_u32_le(&mut bytes, 22, 0);

    let entry_count = if subsecond.is_some() { 3 } else { 2 };
    put_u16_le(&mut bytes, 64, entry_count);
    put_ifd_entry_le(
        &mut bytes,
        66,
        0x9003,
        2,
        u32::try_from(original.len()).expect("fixture length"),
        150,
    );
    put_ifd_entry_le(
        &mut bytes,
        78,
        0x9011,
        2,
        u32::try_from(offset.len()).expect("fixture length"),
        180,
    );
    let next_ifd_offset = if let Some(subsecond) = subsecond {
        put_ifd_entry_le(&mut bytes, 90, 0x9291, 2, 4, u32::from_le_bytes(subsecond));
        102
    } else {
        90
    };
    put_u32_le(&mut bytes, next_ifd_offset, 0);
    bytes[150..150 + original.len()].copy_from_slice(original);
    bytes[180..180 + offset.len()].copy_from_slice(offset);
    bytes
}

fn synthetic_quicktime_movie(text: &[u8]) -> Vec<u8> {
    const COPYRIGHT_DAY: [u8; 4] = [0xa9, b'd', b'a', b'y'];
    let mut data_payload = Vec::new();
    data_payload.extend_from_slice(&1_u32.to_be_bytes());
    data_payload.extend_from_slice(&0_u32.to_be_bytes());
    data_payload.extend_from_slice(text);
    let item = bmff_box(COPYRIGHT_DAY, bmff_box(*b"data", data_payload));
    let ilst = bmff_box(*b"ilst", item);
    let mut meta_payload = vec![0_u8; 4];
    meta_payload.extend_from_slice(&ilst);
    let mut movie = bmff_box(*b"ftyp", b"qt  \0\0\0\0".to_vec());
    movie.extend_from_slice(&bmff_box(*b"moov", bmff_box(*b"meta", meta_payload)));
    movie
}

fn jpeg_with_exif(tiff: &[u8]) -> Vec<u8> {
    let segment_length = tiff
        .len()
        .checked_add(8)
        .and_then(|value| u16::try_from(value).ok())
        .expect("synthetic JPEG APP1 length fits u16");
    let mut bytes = vec![0xff, 0xd8, 0xff, 0xe1];
    bytes.extend_from_slice(&segment_length.to_be_bytes());
    bytes.extend_from_slice(b"Exif\0\0");
    bytes.extend_from_slice(tiff);
    bytes.extend_from_slice(&[0xff, 0xd9]);
    bytes
}

fn bmff_box(box_type: [u8; 4], payload: Vec<u8>) -> Vec<u8> {
    let size = payload
        .len()
        .checked_add(8)
        .and_then(|value| u32::try_from(value).ok())
        .expect("synthetic BMFF box size fits u32");
    let mut result = Vec::with_capacity(usize::try_from(size).expect("box size fits usize"));
    result.extend_from_slice(&size.to_be_bytes());
    result.extend_from_slice(&box_type);
    result.extend_from_slice(&payload);
    result
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
