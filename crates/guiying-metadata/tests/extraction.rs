use std::io;

use guiying_metadata::{
    extract_timestamp_evidence, DetectedFormat, ExtractionLimits, ExtractionStatus, FieldEncoding,
    MetadataFieldKind, MetadataIssueCode, ReadAtSource, TiffByteOrder,
};

const MODIFY_DATE: &[u8] = b"2020:01:02 03:04:05\0";
const ORIGINAL_DATE: &[u8] = b"2019:11:12 13:14:15\0";
const CREATE_DATE: &[u8] = b"2019:11:12 13:14:16\0";
const OFFSET_ORIGINAL: &[u8] = b"+08:00\0";

#[test]
fn extracts_little_endian_tiff_original_time_evidence() {
    let bytes = little_endian_tiff();
    let report = extract_timestamp_evidence(&bytes, ExtractionLimits::default());

    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    assert_eq!(report.format, Some(DetectedFormat::Tiff));
    assert!(report.issues.is_empty());
    assert_eq!(report.fields.len(), 5);
    assert_field(
        &report,
        MetadataFieldKind::ExifDateTimeOriginal,
        ORIGINAL_DATE,
    );
    assert_field(&report, MetadataFieldKind::ExifCreateDate, CREATE_DATE);
    assert_field(&report, MetadataFieldKind::ExifModifyDate, MODIFY_DATE);
    assert_field(
        &report,
        MetadataFieldKind::ExifOffsetTimeOriginal,
        OFFSET_ORIGINAL,
    );
    assert_field(&report, MetadataFieldKind::ExifSubSecTimeOriginal, b"123\0");
    assert_locators_resolve(&bytes, &report);
    assert_eq!(report.usage.fields_emitted, 5);
}

#[test]
fn extracts_big_endian_tiff_and_preserves_byte_order_locator() {
    let bytes = big_endian_tiff();
    let report = extract_timestamp_evidence(&bytes, ExtractionLimits::default());

    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    let field = report
        .fields
        .iter()
        .find(|field| field.kind == MetadataFieldKind::ExifModifyDate)
        .expect("synthetic TIFF has ModifyDate");
    assert_eq!(field.raw_bytes, MODIFY_DATE);
    match &field.locator.container {
        guiying_metadata::MetadataContainer::Tiff { byte_order, .. } => {
            assert_eq!(*byte_order, TiffByteOrder::BigEndian);
        }
        other => panic!("unexpected locator: {other:?}"),
    }
    assert_locators_resolve(&bytes, &report);
}

#[test]
fn extracts_jpeg_app1_without_reading_scan_data() {
    let bytes = jpeg_with_exif(&little_endian_tiff());
    let report = extract_timestamp_evidence(&bytes, ExtractionLimits::default());

    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    assert_eq!(report.format, Some(DetectedFormat::Jpeg));
    assert_field(
        &report,
        MetadataFieldKind::ExifDateTimeOriginal,
        ORIGINAL_DATE,
    );
    assert!(report.fields.iter().all(|field| matches!(
        field.locator.container,
        guiying_metadata::MetadataContainer::JpegExif { .. }
    )));
    assert_locators_resolve(&bytes, &report);
}

#[test]
fn handles_repeated_short_reads_exactly() {
    let bytes = little_endian_tiff();
    let source = ChunkedSource {
        data: bytes.clone(),
        advertised_len: len_u64(&bytes),
        max_chunk: 1,
        eof_after: bytes.len(),
    };
    let report = extract_timestamp_evidence(&source, ExtractionLimits::default());

    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    assert!(report.usage.read_operations > 100);
    assert_field(
        &report,
        MetadataFieldKind::ExifDateTimeOriginal,
        ORIGINAL_DATE,
    );
}

#[test]
fn premature_eof_is_a_failed_report_not_partial_evidence() {
    let bytes = little_endian_tiff();
    let source = ChunkedSource {
        data: bytes.clone(),
        advertised_len: len_u64(&bytes),
        max_chunk: 2,
        eof_after: 4,
    };
    let report = extract_timestamp_evidence(&source, ExtractionLimits::default());

    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::UnexpectedEof);
}

#[test]
fn total_read_budget_is_enforced_before_overread() {
    let bytes = little_endian_tiff();
    let limits = ExtractionLimits {
        max_total_bytes_read: 4,
        ..ExtractionLimits::default()
    };
    let report = extract_timestamp_evidence(&bytes, limits);

    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::LimitExceeded);
    assert_eq!(report.usage.bytes_read, 0);
}

#[test]
fn tiff_ifd_cycle_fails_closed() {
    let mut bytes = vec![0_u8; 32];
    bytes[0..8].copy_from_slice(b"II\x2a\x00\x08\x00\x00\x00");
    put_u16_le(&mut bytes, 8, 1);
    put_ifd_entry_le(&mut bytes, 10, 0x8769, 4, 1, 8);
    put_u32_le(&mut bytes, 22, 0);

    let report = extract_timestamp_evidence(&bytes, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::CycleDetected);
}

#[test]
fn tiff_out_of_bounds_value_fails_closed() {
    let mut bytes = vec![0_u8; 40];
    bytes[0..8].copy_from_slice(b"II\x2a\x00\x08\x00\x00\x00");
    put_u16_le(&mut bytes, 8, 1);
    put_ifd_entry_le(&mut bytes, 10, 0x0132, 2, 20, 0xffff_ff00);
    put_u32_le(&mut bytes, 22, 0);

    let report = extract_timestamp_evidence(&bytes, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::OutOfBounds);
}

#[test]
fn huge_ifd_count_hits_limit_before_allocation() {
    let mut bytes = vec![0_u8; 16];
    bytes[0..8].copy_from_slice(b"II\x2a\x00\x08\x00\x00\x00");
    put_u16_le(&mut bytes, 8, u16::MAX);

    let report = extract_timestamp_evidence(&bytes, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert_eq!(report.issues[0].code, MetadataIssueCode::LimitExceeded);
    assert!(report.usage.bytes_read < 100);
}

#[test]
fn extracts_quicktime_mvhd_version_zero_creation_time() {
    let mut mvhd_payload = vec![0_u8; 20];
    mvhd_payload[4..8].copy_from_slice(&3_800_000_000_u32.to_be_bytes());
    let movie = iso_movie(vec![bmff_box(*b"mvhd", mvhd_payload)]);

    let report = extract_timestamp_evidence(&movie, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    assert_eq!(report.format, Some(DetectedFormat::IsoBmff));
    let field = report
        .fields
        .iter()
        .find(|field| field.kind == MetadataFieldKind::QuickTimeMovieHeaderCreationTime)
        .expect("synthetic movie has mvhd");
    assert_eq!(field.raw_bytes, 3_800_000_000_u32.to_be_bytes());
    assert_eq!(field.encoding, FieldEncoding::UnsignedBigEndian);
    assert_locators_resolve(&movie, &report);
}

#[test]
fn extracts_quicktime_mvhd_version_one_creation_time() {
    let value = 4_500_000_000_u64;
    let mut mvhd_payload = vec![0_u8; 32];
    mvhd_payload[0] = 1;
    mvhd_payload[4..12].copy_from_slice(&value.to_be_bytes());
    let movie = iso_movie(vec![bmff_box(*b"mvhd", mvhd_payload)]);

    let report = extract_timestamp_evidence(&movie, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    assert_field(
        &report,
        MetadataFieldKind::QuickTimeMovieHeaderCreationTime,
        &value.to_be_bytes(),
    );
}

#[test]
fn ignores_mvhd_outside_direct_movie_header_position() {
    let mvhd = mvhd_v0(3_800_000_000);

    let mut root_level = bmff_box(*b"ftyp", b"qt  \0\0\0\0".to_vec());
    root_level.extend_from_slice(&mvhd);
    let root_report = extract_timestamp_evidence(&root_level, ExtractionLimits::default());
    assert_eq!(root_report.status, ExtractionStatus::NoMetadata);
    assert!(root_report.fields.is_empty());

    let under_user_data = iso_movie(vec![bmff_box(*b"udta", mvhd.clone())]);
    let user_data_report =
        extract_timestamp_evidence(&under_user_data, ExtractionLimits::default());
    assert_eq!(user_data_report.status, ExtractionStatus::NoMetadata);
    assert!(user_data_report.fields.is_empty());

    let nested_movie = iso_movie(vec![bmff_box(*b"moov", mvhd)]);
    let nested_report = extract_timestamp_evidence(&nested_movie, ExtractionLimits::default());
    assert_eq!(nested_report.status, ExtractionStatus::NoMetadata);
    assert!(nested_report.fields.is_empty());
}

#[test]
fn preserves_duplicate_movie_header_fields_for_policy_conflict_detection() {
    let movie = iso_movie(vec![mvhd_v0(3_800_000_000), mvhd_v0(3_800_000_001)]);
    let report = extract_timestamp_evidence(&movie, ExtractionLimits::default());

    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    let values = report
        .fields
        .iter()
        .filter(|field| field.kind == MetadataFieldKind::QuickTimeMovieHeaderCreationTime)
        .map(|field| field.raw_bytes.as_slice())
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 2);
    assert_ne!(values[0], values[1]);
}

#[test]
fn extracts_mdta_quicktime_creation_date_text() {
    let text = b"2024-02-03T04:05:06+08:00";
    let mut key_entry = Vec::new();
    let key_entry_size = 8_u32
        .checked_add(len_u32(CREATION_DATE_KEY))
        .expect("synthetic key entry size does not overflow");
    key_entry.extend_from_slice(&key_entry_size.to_be_bytes());
    key_entry.extend_from_slice(b"mdta");
    key_entry.extend_from_slice(CREATION_DATE_KEY);

    let mut keys_payload = vec![0_u8; 4];
    keys_payload.extend_from_slice(&1_u32.to_be_bytes());
    keys_payload.extend_from_slice(&key_entry);
    let keys = bmff_box(*b"keys", keys_payload);

    let mut data_payload = Vec::new();
    data_payload.extend_from_slice(&1_u32.to_be_bytes());
    data_payload.extend_from_slice(&0_u32.to_be_bytes());
    data_payload.extend_from_slice(text);
    let item = bmff_box(1_u32.to_be_bytes(), bmff_box(*b"data", data_payload));
    let ilst = bmff_box(*b"ilst", item);
    let mut meta_payload = vec![0_u8; 4];
    meta_payload.extend_from_slice(&keys);
    meta_payload.extend_from_slice(&ilst);
    let meta = bmff_box(*b"meta", meta_payload);
    let udta = bmff_box(*b"udta", meta);
    let movie = iso_movie(vec![udta]);

    let report = extract_timestamp_evidence(&movie, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    assert_field(
        &report,
        MetadataFieldKind::QuickTimeMetadataCreationDate,
        text,
    );
    assert_locators_resolve(&movie, &report);
}

#[test]
fn extracts_copyright_day_quicktime_creation_date_text() {
    let text = b"2023-08-09T10:11:12Z";
    let mut data_payload = Vec::new();
    data_payload.extend_from_slice(&1_u32.to_be_bytes());
    data_payload.extend_from_slice(&0_u32.to_be_bytes());
    data_payload.extend_from_slice(text);
    let item = bmff_box(COPYRIGHT_DAY, bmff_box(*b"data", data_payload));
    let ilst = bmff_box(*b"ilst", item);
    let mut meta_payload = vec![0_u8; 4];
    meta_payload.extend_from_slice(&ilst);
    let movie = iso_movie(vec![bmff_box(*b"meta", meta_payload)]);

    let report = extract_timestamp_evidence(&movie, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    assert_field(
        &report,
        MetadataFieldKind::QuickTimeMetadataCreationDate,
        text,
    );
    assert_locators_resolve(&movie, &report);
}

#[test]
fn extracts_legacy_udta_copyright_day_text() {
    let text = b"2022-07-08T09:10:11Z";
    let mut legacy_payload = Vec::new();
    legacy_payload.extend_from_slice(&len_u16(text).to_be_bytes());
    legacy_payload.extend_from_slice(&0_u16.to_be_bytes());
    legacy_payload.extend_from_slice(text);
    let copyright_day = bmff_box(COPYRIGHT_DAY, legacy_payload);
    let movie = iso_movie(vec![bmff_box(*b"udta", copyright_day)]);

    let report = extract_timestamp_evidence(&movie, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    assert_field(
        &report,
        MetadataFieldKind::QuickTimeMetadataCreationDate,
        text,
    );
    assert_locators_resolve(&movie, &report);
}

#[test]
fn ignores_legacy_copyright_day_outside_movie_user_data() {
    let text = b"2022-07-08T09:10:11Z";
    let mut legacy_payload = Vec::new();
    legacy_payload.extend_from_slice(&len_u16(text).to_be_bytes());
    legacy_payload.extend_from_slice(&0_u16.to_be_bytes());
    legacy_payload.extend_from_slice(text);
    let movie = iso_movie(vec![bmff_box(COPYRIGHT_DAY, legacy_payload)]);

    let report = extract_timestamp_evidence(&movie, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::NoMetadata);
    assert!(report.fields.is_empty());
}

#[test]
fn declared_quicktime_utf8_with_invalid_bytes_fails_closed() {
    let mut data_payload = Vec::new();
    data_payload.extend_from_slice(&1_u32.to_be_bytes());
    data_payload.extend_from_slice(&0_u32.to_be_bytes());
    data_payload.extend_from_slice(&[0xff, 0xfe]);
    let item = bmff_box(COPYRIGHT_DAY, bmff_box(*b"data", data_payload));
    let ilst = bmff_box(*b"ilst", item);
    let mut meta_payload = vec![0_u8; 4];
    meta_payload.extend_from_slice(&ilst);
    let movie = iso_movie(vec![bmff_box(*b"meta", meta_payload)]);

    let report = extract_timestamp_evidence(&movie, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::InvalidStructure);
}

#[test]
fn structurally_extracted_tiff_ascii_is_explicitly_not_date_validated() {
    for value in [b"X\0".as_slice(), b"\0".as_slice()] {
        let bytes = tiff_with_modify_date(value);
        let report = extract_timestamp_evidence(&bytes, ExtractionLimits::default());

        assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
        let field = report
            .fields
            .iter()
            .find(|field| field.kind == MetadataFieldKind::ExifModifyDate)
            .expect("synthetic TIFF exposes its raw ModifyDate field");
        assert_eq!(field.encoding, FieldEncoding::DeclaredAscii);
        assert_eq!(field.raw_bytes, value);
    }
}

#[test]
fn malformed_bmff_box_size_fails_closed() {
    let mut movie = bmff_box(*b"ftyp", b"qt  \0\0\0\0".to_vec());
    movie.extend_from_slice(&4_u32.to_be_bytes());
    movie.extend_from_slice(b"moov");

    let report = extract_timestamp_evidence(&movie, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::InvalidStructure);
}

#[test]
fn extended_bmff_size_overflow_is_reported_without_followup_read() {
    let mut bytes = bmff_box(*b"ftyp", Vec::new());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(b"free");
    bytes.extend_from_slice(&u64::MAX.to_be_bytes());
    let source = ChunkedSource {
        data: bytes.clone(),
        advertised_len: u64::MAX,
        max_chunk: bytes.len(),
        eof_after: bytes.len(),
    };

    let report = extract_timestamp_evidence(&source, permissive_limits());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::ArithmeticOverflow);
}

#[test]
fn hard_field_ceiling_cannot_be_disabled_by_caller() {
    let oversized_text = vec![b'7'; 1024 * 1024 + 1];
    let mut data_payload = Vec::with_capacity(8 + oversized_text.len());
    data_payload.extend_from_slice(&1_u32.to_be_bytes());
    data_payload.extend_from_slice(&0_u32.to_be_bytes());
    data_payload.extend_from_slice(&oversized_text);
    let item = bmff_box(COPYRIGHT_DAY, bmff_box(*b"data", data_payload));
    let ilst = bmff_box(*b"ilst", item);
    let mut meta_payload = vec![0_u8; 4];
    meta_payload.extend_from_slice(&ilst);
    let movie = iso_movie(vec![bmff_box(*b"meta", meta_payload)]);

    let report = extract_timestamp_evidence(&movie, permissive_limits());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::LimitExceeded);
    assert!(report.usage.bytes_read < 1024);
    assert_eq!(report.limits.max_field_bytes, 1024 * 1024);
}

#[test]
fn nesting_ceiling_is_clamped_and_configured_limit_is_enforced() {
    let effective = permissive_limits().effective();
    assert_eq!(effective.max_bmff_depth, 64);

    let mut meta_payload = vec![0_u8; 4];
    meta_payload.extend_from_slice(&bmff_box(*b"ilst", Vec::new()));
    let movie = iso_movie(vec![bmff_box(*b"udta", bmff_box(*b"meta", meta_payload))]);
    let limits = ExtractionLimits {
        max_bmff_depth: 2,
        ..ExtractionLimits::default()
    };
    let report = extract_timestamp_evidence(&movie, limits);
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::LimitExceeded);
    assert_eq!(report.usage.max_depth_observed, 2);
    assert_eq!(report.limits.max_bmff_depth, 2);
}

#[test]
fn source_cannot_claim_more_bytes_than_destination_capacity() {
    let report = extract_timestamp_evidence(&OverReportingSource, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::InvalidSource);
}

#[test]
fn unknown_bytes_are_unsupported_without_an_issue() {
    let bytes = b"not a supported media container".to_vec();
    let report = extract_timestamp_evidence(&bytes, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Unsupported);
    assert!(report.issues.is_empty());
    assert!(report.fields.is_empty());
}

#[test]
fn extracts_quicktime_style_meta_and_movie_header_together() {
    // Apple `.mov` layout: `meta` directly under `moov` with NO version/flags
    // and the mandatory `hdlr` as its first child. The pre-fix parser treated
    // this dialect as an ISO full box and failed the whole file, discarding
    // the already extracted `mvhd` creation time as well.
    let text = b"2024-02-03T04:05:06+08:00";
    let mut key_entry = Vec::new();
    let key_entry_size = 8_u32
        .checked_add(len_u32(CREATION_DATE_KEY))
        .expect("synthetic key entry size does not overflow");
    key_entry.extend_from_slice(&key_entry_size.to_be_bytes());
    key_entry.extend_from_slice(b"mdta");
    key_entry.extend_from_slice(CREATION_DATE_KEY);
    let mut keys_payload = vec![0_u8; 4];
    keys_payload.extend_from_slice(&1_u32.to_be_bytes());
    keys_payload.extend_from_slice(&key_entry);
    let keys = bmff_box(*b"keys", keys_payload);

    let mut data_payload = Vec::new();
    data_payload.extend_from_slice(&1_u32.to_be_bytes());
    data_payload.extend_from_slice(&0_u32.to_be_bytes());
    data_payload.extend_from_slice(text);
    let item = bmff_box(1_u32.to_be_bytes(), bmff_box(*b"data", data_payload));
    let ilst = bmff_box(*b"ilst", item);

    let mut meta_payload = Vec::new();
    meta_payload.extend_from_slice(&quicktime_hdlr(*b"mdta"));
    meta_payload.extend_from_slice(&keys);
    meta_payload.extend_from_slice(&ilst);
    let meta = bmff_box(*b"meta", meta_payload);
    let movie = iso_movie(vec![mvhd_v0(3_800_000_000), meta]);

    let report = extract_timestamp_evidence(&movie, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    assert!(report.issues.is_empty());
    assert_field(
        &report,
        MetadataFieldKind::QuickTimeMovieHeaderCreationTime,
        &3_800_000_000_u32.to_be_bytes(),
    );
    assert_field(
        &report,
        MetadataFieldKind::QuickTimeMetadataCreationDate,
        text,
    );
    assert_locators_resolve(&movie, &report);
}

#[test]
fn a_malformed_sibling_box_is_isolated_and_keeps_movie_header_evidence() {
    // Unsupported `meta` version: the box is rejected structurally, but the
    // valid sibling `mvhd` evidence must survive with a `Partial` status.
    let mut meta_payload = vec![9_u8, 0, 0, 0];
    meta_payload.extend_from_slice(&bmff_box(*b"ilst", Vec::new()));
    let movie = iso_movie(vec![
        mvhd_v0(3_800_000_000),
        bmff_box(*b"meta", meta_payload),
    ]);

    let report = extract_timestamp_evidence(&movie, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Partial);
    assert_field(
        &report,
        MetadataFieldKind::QuickTimeMovieHeaderCreationTime,
        &3_800_000_000_u32.to_be_bytes(),
    );
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].code, MetadataIssueCode::UnsupportedVersion);
}

#[test]
fn a_malformed_second_exif_segment_keeps_first_segment_evidence() {
    let mut bytes = vec![0xff, 0xd8];
    push_app1_exif(&mut bytes, &little_endian_tiff());
    push_app1_exif(&mut bytes, b"XXXXXXXX");
    bytes.extend_from_slice(&[0xff, 0xd9]);

    let report = extract_timestamp_evidence(&bytes, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Partial);
    assert_eq!(report.format, Some(DetectedFormat::Jpeg));
    assert_field(
        &report,
        MetadataFieldKind::ExifDateTimeOriginal,
        ORIGINAL_DATE,
    );
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].code, MetadataIssueCode::InvalidStructure);
}

#[test]
fn budget_failures_still_discard_partially_extracted_fields() {
    // Budget-class failures must stay whole-report failures so both passes of
    // the double-extraction sealing gate remain deterministic and comparable.
    let movie = iso_movie(vec![mvhd_v0(3_800_000_000), mvhd_v0(3_800_000_001)]);
    let limits = ExtractionLimits {
        max_fields: 1,
        ..ExtractionLimits::default()
    };

    let report = extract_timestamp_evidence(&movie, limits);
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::LimitExceeded);
}

#[test]
fn extracts_heif_exif_date_time_original() {
    let item_payload = exif_item_payload(&little_endian_tiff());
    let file = heif_file_with(
        |offset, length| {
            vec![
                heif_hdlr(*b"pict"),
                heif_iinf_with_items(vec![heif_infe_v2(1, *b"Exif")]),
                heif_iloc_v0(&[(1, vec![(offset, length)])]),
            ]
        },
        &item_payload,
    );

    let report = extract_timestamp_evidence(&file, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::ExtractedUnvalidated);
    assert_eq!(report.format, Some(DetectedFormat::IsoBmff));
    assert!(report.issues.is_empty());
    assert_field(
        &report,
        MetadataFieldKind::ExifDateTimeOriginal,
        ORIGINAL_DATE,
    );
    assert_field(&report, MetadataFieldKind::ExifModifyDate, MODIFY_DATE);
    assert!(report.fields.iter().all(|field| matches!(
        field.locator.container,
        guiying_metadata::MetadataContainer::Tiff { .. }
    )));
    assert_locators_resolve(&file, &report);
}

#[test]
fn heif_exif_extent_beyond_the_file_is_out_of_bounds() {
    let item_payload = exif_item_payload(&little_endian_tiff());
    let file = heif_file_with(
        |_offset, length| {
            vec![
                heif_hdlr(*b"pict"),
                heif_iinf_with_items(vec![heif_infe_v2(1, *b"Exif")]),
                heif_iloc_v0(&[(1, vec![(u32::MAX - 8, length)])]),
            ]
        },
        &item_payload,
    );

    let report = extract_timestamp_evidence(&file, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::OutOfBounds);
    assert!(report.usage.bytes_read < 4096);
}

#[test]
fn heif_exif_with_unsupported_construction_method_fails_closed() {
    let item_payload = exif_item_payload(&little_endian_tiff());
    let file = heif_file_with(
        |offset, length| {
            vec![
                heif_hdlr(*b"pict"),
                heif_iinf_with_items(vec![heif_infe_v2(1, *b"Exif")]),
                heif_iloc_v1_with_method(1, 1, &[(offset, length)]),
            ]
        },
        &item_payload,
    );

    let report = extract_timestamp_evidence(&file, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::InvalidStructure);
    assert!(report.usage.bytes_read < 4096);
}

#[test]
fn heif_exif_with_multiple_extents_fails_closed() {
    let item_payload = exif_item_payload(&little_endian_tiff());
    let file = heif_file_with(
        |offset, length| {
            vec![
                heif_hdlr(*b"pict"),
                heif_iinf_with_items(vec![heif_infe_v2(1, *b"Exif")]),
                heif_iloc_v0(&[(1, vec![(offset, 4), (offset + 4, length - 4)])]),
            ]
        },
        &item_payload,
    );

    let report = extract_timestamp_evidence(&file, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::InvalidStructure);
    assert!(report.usage.bytes_read < 4096);
}

#[test]
fn heif_declared_exif_item_without_location_fails_closed() {
    let item_payload = exif_item_payload(&little_endian_tiff());
    let file = heif_file_with(
        |offset, length| {
            vec![
                heif_hdlr(*b"pict"),
                heif_iinf_with_items(vec![heif_infe_v2(1, *b"Exif")]),
                heif_iloc_v0(&[(2, vec![(offset, length)])]),
            ]
        },
        &item_payload,
    );

    let report = extract_timestamp_evidence(&file, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::Failed);
    assert!(report.fields.is_empty());
    assert_eq!(report.issues[0].code, MetadataIssueCode::InvalidStructure);
    assert!(report.usage.bytes_read < 4096);
}

#[test]
fn heif_without_exif_item_is_no_metadata() {
    let item_payload = exif_item_payload(&little_endian_tiff());
    let file = heif_file_with(
        |offset, length| {
            vec![
                heif_hdlr(*b"pict"),
                heif_iinf_with_items(vec![heif_infe_v2(1, *b"mime")]),
                heif_iloc_v0(&[(1, vec![(offset, length)])]),
            ]
        },
        &item_payload,
    );

    let report = extract_timestamp_evidence(&file, ExtractionLimits::default());
    assert_eq!(report.status, ExtractionStatus::NoMetadata);
    assert!(report.fields.is_empty());
    assert!(report.issues.is_empty());
}

const CREATION_DATE_KEY: &[u8] = b"com.apple.quicktime.creationdate";
const COPYRIGHT_DAY: [u8; 4] = [0xa9, b'd', b'a', b'y'];

fn permissive_limits() -> ExtractionLimits {
    ExtractionLimits {
        max_total_bytes_read: u64::MAX,
        max_read_operations: u64::MAX,
        max_retained_field_bytes: u64::MAX,
        max_field_bytes: u64::MAX,
        max_fields: u32::MAX,
        max_jpeg_segments: u32::MAX,
        max_ifd_entries: u32::MAX,
        max_ifd_depth: u16::MAX,
        max_bmff_boxes: u32::MAX,
        max_bmff_depth: u16::MAX,
    }
}

fn assert_field(
    report: &guiying_metadata::ExtractionReport,
    kind: MetadataFieldKind,
    expected: &[u8],
) {
    let field = report
        .fields
        .iter()
        .find(|field| field.kind == kind)
        .unwrap_or_else(|| panic!("missing field {kind:?}"));
    assert_eq!(field.raw_bytes, expected);
    assert_eq!(field.locator.byte_len, len_u64(expected));
}

fn assert_locators_resolve(bytes: &[u8], report: &guiying_metadata::ExtractionReport) {
    for field in &report.fields {
        let start = usize::try_from(field.locator.absolute_offset)
            .expect("synthetic locator offset fits usize");
        let length =
            usize::try_from(field.locator.byte_len).expect("synthetic locator length fits usize");
        let end = start
            .checked_add(length)
            .expect("synthetic locator range does not overflow");
        assert_eq!(&bytes[start..end], field.raw_bytes);
    }
}

fn little_endian_tiff() -> Vec<u8> {
    let mut bytes = vec![0_u8; 320];
    bytes[0..8].copy_from_slice(b"II\x2a\x00\x08\x00\x00\x00");

    put_u16_le(&mut bytes, 8, 2);
    put_ifd_entry_le(&mut bytes, 10, 0x0132, 2, len_u32(MODIFY_DATE), 180);
    put_ifd_entry_le(&mut bytes, 22, 0x8769, 4, 1, 64);
    put_u32_le(&mut bytes, 34, 0);

    put_u16_le(&mut bytes, 64, 4);
    put_ifd_entry_le(&mut bytes, 66, 0x9003, 2, len_u32(ORIGINAL_DATE), 204);
    put_ifd_entry_le(&mut bytes, 78, 0x9004, 2, len_u32(CREATE_DATE), 228);
    put_ifd_entry_le(&mut bytes, 90, 0x9011, 2, len_u32(OFFSET_ORIGINAL), 252);
    put_ifd_entry_le(&mut bytes, 102, 0x9291, 2, 4, u32::from_le_bytes(*b"123\0"));
    put_u32_le(&mut bytes, 114, 0);

    bytes[180..180 + MODIFY_DATE.len()].copy_from_slice(MODIFY_DATE);
    bytes[204..204 + ORIGINAL_DATE.len()].copy_from_slice(ORIGINAL_DATE);
    bytes[228..228 + CREATE_DATE.len()].copy_from_slice(CREATE_DATE);
    bytes[252..252 + OFFSET_ORIGINAL.len()].copy_from_slice(OFFSET_ORIGINAL);
    bytes
}

fn big_endian_tiff() -> Vec<u8> {
    let mut bytes = vec![0_u8; 80];
    bytes[0..8].copy_from_slice(b"MM\x00\x2a\x00\x00\x00\x08");
    put_u16_be(&mut bytes, 8, 1);
    put_ifd_entry_be(&mut bytes, 10, 0x0132, 2, len_u32(MODIFY_DATE), 40);
    put_u32_be(&mut bytes, 22, 0);
    bytes[40..40 + MODIFY_DATE.len()].copy_from_slice(MODIFY_DATE);
    bytes
}

fn jpeg_with_exif(tiff: &[u8]) -> Vec<u8> {
    let segment_length = tiff
        .len()
        .checked_add(8)
        .expect("synthetic JPEG segment length does not overflow");
    let segment_length = u16::try_from(segment_length).expect("synthetic JPEG segment fits u16");
    let mut bytes = vec![0xff, 0xd8, 0xff, 0xe1];
    bytes.extend_from_slice(&segment_length.to_be_bytes());
    bytes.extend_from_slice(b"Exif\0\0");
    bytes.extend_from_slice(tiff);
    bytes.extend_from_slice(&[0xff, 0xd9]);
    bytes
}

fn iso_movie(children: Vec<Vec<u8>>) -> Vec<u8> {
    let mut file = bmff_box(*b"ftyp", b"qt  \0\0\0\0".to_vec());
    let moov_payload = children.into_iter().flatten().collect();
    file.extend_from_slice(&bmff_box(*b"moov", moov_payload));
    file
}

fn mvhd_v0(creation_time: u32) -> Vec<u8> {
    let mut payload = vec![0_u8; 20];
    payload[4..8].copy_from_slice(&creation_time.to_be_bytes());
    bmff_box(*b"mvhd", payload)
}

fn tiff_with_modify_date(value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 64];
    bytes[0..8].copy_from_slice(b"II\x2a\x00\x08\x00\x00\x00");
    put_u16_le(&mut bytes, 8, 1);
    let mut inline = [0_u8; 4];
    inline[..value.len()].copy_from_slice(value);
    put_ifd_entry_le(
        &mut bytes,
        10,
        0x0132,
        2,
        len_u32(value),
        u32::from_le_bytes(inline),
    );
    put_u32_le(&mut bytes, 22, 0);
    bytes
}

fn push_app1_exif(bytes: &mut Vec<u8>, tiff: &[u8]) {
    let segment_length = tiff
        .len()
        .checked_add(8)
        .expect("synthetic APP1 length does not overflow");
    let segment_length = u16::try_from(segment_length).expect("synthetic APP1 fits u16");
    bytes.extend_from_slice(&[0xff, 0xe1]);
    bytes.extend_from_slice(&segment_length.to_be_bytes());
    bytes.extend_from_slice(b"Exif\0\0");
    bytes.extend_from_slice(tiff);
}

/// QuickTime-style handler atom whose type field sits at payload offset 8.
fn quicktime_hdlr(handler: [u8; 4]) -> Vec<u8> {
    let mut payload = vec![0_u8; 8];
    payload.extend_from_slice(&handler);
    payload.extend_from_slice(&[0_u8; 12]);
    bmff_box(*b"hdlr", payload)
}

/// ISO full-box `hdlr` used inside a HEIF root `meta`; the handler type also
/// sits at payload offset 8.
fn heif_hdlr(handler: [u8; 4]) -> Vec<u8> {
    quicktime_hdlr(handler)
}

/// ISO full-box root-level `meta` (version 0) with the given children.
fn heif_meta(children: Vec<Vec<u8>>) -> Vec<u8> {
    let mut payload = vec![0_u8; 4];
    for child in children {
        payload.extend_from_slice(&child);
    }
    bmff_box(*b"meta", payload)
}

fn heif_iinf_with_items(entries: Vec<Vec<u8>>) -> Vec<u8> {
    let mut payload = vec![0_u8; 4];
    let count = u16::try_from(entries.len()).expect("synthetic iinf entry count fits u16");
    payload.extend_from_slice(&count.to_be_bytes());
    for entry in entries {
        payload.extend_from_slice(&entry);
    }
    bmff_box(*b"iinf", payload)
}

fn heif_infe_v2(item_id: u16, item_type: [u8; 4]) -> Vec<u8> {
    let mut payload = vec![2_u8, 0, 0, 0];
    payload.extend_from_slice(&item_id.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&item_type);
    payload.push(0);
    bmff_box(*b"infe", payload)
}

/// `iloc` version 0 with offset/length size 4 and no base offset.
fn heif_iloc_v0(items: &[(u16, Vec<(u32, u32)>)]) -> Vec<u8> {
    let mut payload = vec![0_u8, 0, 0, 0, 0x44, 0x00];
    let count = u16::try_from(items.len()).expect("synthetic iloc item count fits u16");
    payload.extend_from_slice(&count.to_be_bytes());
    for (item_id, extents) in items {
        payload.extend_from_slice(&item_id.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        let extent_count = u16::try_from(extents.len()).expect("synthetic extent count fits u16");
        payload.extend_from_slice(&extent_count.to_be_bytes());
        for (extent_offset, extent_length) in extents {
            payload.extend_from_slice(&extent_offset.to_be_bytes());
            payload.extend_from_slice(&extent_length.to_be_bytes());
        }
    }
    bmff_box(*b"iloc", payload)
}

/// `iloc` version 1 carrying an explicit construction method for one item.
fn heif_iloc_v1_with_method(item_id: u16, method: u16, extents: &[(u32, u32)]) -> Vec<u8> {
    let mut payload = vec![1_u8, 0, 0, 0, 0x44, 0x00];
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&item_id.to_be_bytes());
    payload.extend_from_slice(&method.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    let extent_count = u16::try_from(extents.len()).expect("synthetic extent count fits u16");
    payload.extend_from_slice(&extent_count.to_be_bytes());
    for (extent_offset, extent_length) in extents {
        payload.extend_from_slice(&extent_offset.to_be_bytes());
        payload.extend_from_slice(&extent_length.to_be_bytes());
    }
    bmff_box(*b"iloc", payload)
}

/// HEIF `ExifDataBlock`: four-byte TIFF header offset (zero) then the payload.
fn exif_item_payload(tiff: &[u8]) -> Vec<u8> {
    let mut payload = vec![0_u8; 4];
    payload.extend_from_slice(tiff);
    payload
}

/// Assemble `ftyp` + root `meta` + `mdat`, resolving the absolute item offset
/// with a two-pass build (`iloc` fields are fixed width, so sizes are stable).
fn heif_file_with(
    meta_children: impl Fn(u32, u32) -> Vec<Vec<u8>>,
    item_payload: &[u8],
) -> Vec<u8> {
    let ftyp = bmff_box(*b"ftyp", b"heic\0\0\0\0".to_vec());
    let item_length = len_u32(item_payload);
    let probe_meta = heif_meta(meta_children(0, item_length));
    let data_offset = ftyp
        .len()
        .checked_add(probe_meta.len())
        .and_then(|length| length.checked_add(8))
        .expect("synthetic HEIF prefix length does not overflow");
    let data_offset = u32::try_from(data_offset).expect("synthetic HEIF offset fits u32");
    let meta = heif_meta(meta_children(data_offset, item_length));
    assert_eq!(
        meta.len(),
        probe_meta.len(),
        "two-pass build must be stable"
    );
    let mut file = ftyp;
    file.extend_from_slice(&meta);
    file.extend_from_slice(&bmff_box(*b"mdat", item_payload.to_vec()));
    file
}

fn bmff_box(box_type: [u8; 4], payload: Vec<u8>) -> Vec<u8> {
    let size = payload
        .len()
        .checked_add(8)
        .expect("synthetic BMFF box size does not overflow");
    let encoded_size = u32::try_from(size).expect("synthetic BMFF box size fits u32");
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&encoded_size.to_be_bytes());
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

fn put_ifd_entry_be(
    bytes: &mut [u8],
    offset: usize,
    tag: u16,
    field_type: u16,
    count: u32,
    value: u32,
) {
    put_u16_be(bytes, offset, tag);
    put_u16_be(bytes, offset + 2, field_type);
    put_u32_be(bytes, offset + 4, count);
    put_u32_be(bytes, offset + 8, value);
}

fn put_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u16_be(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn len_u16(bytes: &[u8]) -> u16 {
    u16::try_from(bytes.len()).expect("synthetic byte length fits u16")
}

fn len_u32(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).expect("synthetic byte length fits u32")
}

fn len_u64(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).expect("synthetic byte length fits u64")
}

struct ChunkedSource {
    data: Vec<u8>,
    advertised_len: u64,
    max_chunk: usize,
    eof_after: usize,
}

impl ReadAtSource for ChunkedSource {
    fn source_len(&self) -> io::Result<u64> {
        Ok(self.advertised_len)
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset too large"))?;
        let available_end = self.data.len().min(self.eof_after);
        if start >= available_end || destination.is_empty() {
            return Ok(0);
        }
        let count = destination
            .len()
            .min(self.max_chunk)
            .min(available_end - start);
        destination[..count].copy_from_slice(&self.data[start..start + count]);
        Ok(count)
    }
}

struct OverReportingSource;

impl ReadAtSource for OverReportingSource {
    fn source_len(&self) -> io::Result<u64> {
        Ok(16)
    }

    fn read_at(&self, _offset: u64, destination: &mut [u8]) -> io::Result<usize> {
        Ok(destination.len().saturating_add(1))
    }
}
