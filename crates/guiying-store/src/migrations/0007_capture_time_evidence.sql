-- Version 7 persists read-only capture-time evidence derived from a freshly
-- revalidated metadata extraction.  It intentionally does not migrate the
-- legacy `time_candidates` table: those rows predate the current core,
-- volume-session, exact-group, source-revalidation, and lineage contracts.
--
-- Every recommendation in this schema is evidence only.  Nothing in these
-- tables is an operation plan, a filesystem capability, or write authority.

CREATE UNIQUE INDEX ux_exact_group_build_members_probe_binding_v7
    ON exact_group_build_members(
        volume_id,
        scan_run_id,
        exact_group_build_id,
        media_observation_snapshot_id,
        observation_fingerprint_id
    );

CREATE UNIQUE INDEX ux_exact_group_build_members_assessment_binding_v7
    ON exact_group_build_members(
        volume_id,
        scan_run_id,
        exact_group_build_id,
        ordinal,
        media_observation_snapshot_id
    );

CREATE TABLE scan_time_sessions (
    id INTEGER PRIMARY KEY,
    time_session_key BLOB NOT NULL CHECK (length(time_session_key) = 32),
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    core_session_id BLOB NOT NULL CHECK (length(core_session_id) = 32),
    schema_contract_version INTEGER NOT NULL CHECK (schema_contract_version = 1),
    scope_manifest_version INTEGER NOT NULL DEFAULT 1 CHECK (scope_manifest_version = 1),
    outcome_manifest_version INTEGER NOT NULL DEFAULT 2 CHECK (outcome_manifest_version = 2),
    state TEXT NOT NULL DEFAULT 'draft'
        CHECK (state IN ('draft', 'complete', 'partial', 'abandoned')),
    expected_group_count INTEGER NOT NULL CHECK (expected_group_count >= 0),
    evidence_group_count INTEGER CHECK (evidence_group_count IS NULL OR evidence_group_count >= 0),
    unavailable_group_count INTEGER
        CHECK (unavailable_group_count IS NULL OR unavailable_group_count >= 0),
    failed_group_count INTEGER CHECK (failed_group_count IS NULL OR failed_group_count >= 0),
    max_total_read_bytes INTEGER NOT NULL
        CHECK (max_total_read_bytes BETWEEN 1 AND 4294967296),
    max_probe_count_per_group INTEGER NOT NULL
        CHECK (max_probe_count_per_group BETWEEN 1 AND 4),
    max_report_total_bytes_read INTEGER NOT NULL
        CHECK (max_report_total_bytes_read BETWEEN 1 AND 8388608),
    max_report_read_operations INTEGER NOT NULL
        CHECK (max_report_read_operations BETWEEN 1 AND 32768),
    max_report_retained_field_bytes INTEGER NOT NULL
        CHECK (max_report_retained_field_bytes BETWEEN 1 AND 262144),
    max_report_fields INTEGER NOT NULL CHECK (max_report_fields BETWEEN 1 AND 128),
    max_report_issues INTEGER NOT NULL CHECK (max_report_issues BETWEEN 1 AND 128),
    expected_manifest_digest BLOB NOT NULL CHECK (length(expected_manifest_digest) = 32),
    sealed_manifest_digest BLOB
        CHECK (sealed_manifest_digest IS NULL OR length(sealed_manifest_digest) = 32),
    sealed_outcome_manifest_digest BLOB
        CHECK (
            sealed_outcome_manifest_digest IS NULL
            OR length(sealed_outcome_manifest_digest) = 32
        ),
    abandon_reason_code TEXT
        CHECK (
            abandon_reason_code IS NULL
            OR length(CAST(abandon_reason_code AS BLOB)) BETWEEN 1 AND 256
        ),
    abandon_reason_message TEXT
        CHECK (
            abandon_reason_message IS NULL
            OR length(CAST(abandon_reason_message AS BLOB)) BETWEEN 1 AND 65536
        ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    finalized_at_ms INTEGER
        CHECK (finalized_at_ms IS NULL OR finalized_at_ms >= created_at_ms),
    UNIQUE (scan_run_id),
    UNIQUE (time_session_key),
    UNIQUE (volume_id, scan_run_id, id),
    UNIQUE (volume_id, scan_run_id, id, core_session_id),
    CHECK (
        (state = 'draft'
         AND evidence_group_count IS NULL
         AND unavailable_group_count IS NULL
         AND failed_group_count IS NULL
         AND sealed_manifest_digest IS NULL
         AND sealed_outcome_manifest_digest IS NULL
         AND abandon_reason_code IS NULL
         AND abandon_reason_message IS NULL
         AND finalized_at_ms IS NULL)
        OR
        (state = 'complete'
         AND evidence_group_count IS NOT NULL
         AND unavailable_group_count IS NOT NULL
         AND failed_group_count IS NOT NULL
         AND evidence_group_count + unavailable_group_count + failed_group_count
             = expected_group_count
         AND sealed_manifest_digest = expected_manifest_digest
         AND sealed_outcome_manifest_digest IS NOT NULL
         AND abandon_reason_code IS NULL
         AND abandon_reason_message IS NULL
         AND finalized_at_ms IS NOT NULL)
        OR
        (state = 'partial'
         AND evidence_group_count IS NOT NULL
         AND unavailable_group_count IS NOT NULL
         AND failed_group_count IS NOT NULL
         AND evidence_group_count + unavailable_group_count + failed_group_count
             <= expected_group_count
         AND sealed_manifest_digest = expected_manifest_digest
         AND sealed_outcome_manifest_digest IS NOT NULL
         AND abandon_reason_code IS NULL
         AND abandon_reason_message IS NULL
         AND finalized_at_ms IS NOT NULL)
        OR
        (state = 'abandoned'
         AND evidence_group_count IS NULL
         AND unavailable_group_count IS NULL
         AND failed_group_count IS NULL
         AND sealed_manifest_digest IS NULL
         AND sealed_outcome_manifest_digest IS NULL
         AND abandon_reason_code IS NOT NULL
         AND finalized_at_ms IS NOT NULL)
    ),
    FOREIGN KEY (volume_id, scan_run_id, core_session_id)
        REFERENCES scan_core_sessions(volume_id, scan_run_id, core_session_id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_scan_time_sessions_state_v7
    ON scan_time_sessions(state, scan_run_id, id);

-- One immutable outcome per attempted exact group makes session coverage
-- counters independently auditable.  A missing row means "not attempted";
-- it is never silently classified as unavailable or failed.
CREATE TABLE capture_time_group_outcomes (
    time_session_id INTEGER NOT NULL,
    exact_group_build_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('evidence', 'unavailable', 'failed')),
    analysis_build_id INTEGER,
    reason_code TEXT NOT NULL CHECK (length(CAST(reason_code AS BLOB)) BETWEEN 1 AND 256),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (time_session_id, exact_group_build_id),
    UNIQUE (time_session_id, analysis_build_id),
    CHECK (
        (outcome = 'evidence' AND analysis_build_id IS NOT NULL)
        OR (outcome IN ('unavailable', 'failed') AND analysis_build_id IS NULL)
    ),
    FOREIGN KEY (volume_id, scan_run_id, time_session_id)
        REFERENCES scan_time_sessions(volume_id, scan_run_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id, exact_group_build_id)
        REFERENCES exact_group_builds(volume_id, scan_run_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (analysis_build_id, time_session_id)
        REFERENCES capture_time_analysis_builds(id, time_session_id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_capture_time_group_outcomes_page_v7
    ON capture_time_group_outcomes(time_session_id, outcome, exact_group_build_id);

CREATE TABLE metadata_extraction_reports (
    id INTEGER PRIMARY KEY,
    time_session_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    core_session_id BLOB NOT NULL CHECK (length(core_session_id) = 32),
    exact_group_build_id INTEGER NOT NULL,
    metadata_probe_observation_id INTEGER NOT NULL,
    metadata_probe_fingerprint_id INTEGER NOT NULL,
    probe_ordinal INTEGER NOT NULL CHECK (probe_ordinal BETWEEN 0 AND 3),
    source_size_bytes INTEGER NOT NULL CHECK (source_size_bytes >= 0),
    report_parser_name TEXT NOT NULL
        CHECK (length(CAST(report_parser_name AS BLOB)) BETWEEN 1 AND 128),
    report_parser_version TEXT NOT NULL
        CHECK (length(CAST(report_parser_version AS BLOB)) BETWEEN 1 AND 128),
    detected_format TEXT CHECK (detected_format IN ('jpeg', 'tiff', 'iso_bmff')),
    extraction_status TEXT NOT NULL CHECK (extraction_status IN (
        'extracted_unvalidated', 'no_metadata', 'partial', 'failed', 'unsupported'
    )),
    effective_max_total_bytes_read INTEGER NOT NULL
        CHECK (effective_max_total_bytes_read BETWEEN 1 AND 67108864),
    effective_max_read_operations INTEGER NOT NULL
        CHECK (effective_max_read_operations BETWEEN 1 AND 262144),
    effective_max_retained_field_bytes INTEGER NOT NULL
        CHECK (effective_max_retained_field_bytes BETWEEN 1 AND 16777216),
    effective_max_field_bytes INTEGER NOT NULL
        CHECK (effective_max_field_bytes BETWEEN 1 AND 1048576),
    effective_max_fields INTEGER NOT NULL CHECK (effective_max_fields BETWEEN 1 AND 4096),
    effective_max_jpeg_segments INTEGER NOT NULL
        CHECK (effective_max_jpeg_segments BETWEEN 1 AND 65536),
    effective_max_ifd_entries INTEGER NOT NULL
        CHECK (effective_max_ifd_entries BETWEEN 1 AND 65536),
    effective_max_ifd_depth INTEGER NOT NULL CHECK (effective_max_ifd_depth BETWEEN 1 AND 64),
    effective_max_bmff_boxes INTEGER NOT NULL
        CHECK (effective_max_bmff_boxes BETWEEN 1 AND 65536),
    effective_max_bmff_depth INTEGER NOT NULL CHECK (effective_max_bmff_depth BETWEEN 1 AND 64),
    usage_bytes_read INTEGER NOT NULL CHECK (usage_bytes_read >= 0),
    usage_read_operations INTEGER NOT NULL CHECK (usage_read_operations >= 0),
    usage_retained_field_bytes INTEGER NOT NULL CHECK (usage_retained_field_bytes >= 0),
    usage_fields_emitted INTEGER NOT NULL CHECK (usage_fields_emitted >= 0),
    usage_jpeg_segments_visited INTEGER NOT NULL CHECK (usage_jpeg_segments_visited >= 0),
    usage_ifd_entries_visited INTEGER NOT NULL CHECK (usage_ifd_entries_visited >= 0),
    usage_bmff_boxes_visited INTEGER NOT NULL CHECK (usage_bmff_boxes_visited >= 0),
    usage_max_depth_observed INTEGER NOT NULL CHECK (usage_max_depth_observed >= 0),
    expected_field_count INTEGER NOT NULL CHECK (expected_field_count BETWEEN 0 AND 4096),
    expected_issue_count INTEGER NOT NULL CHECK (expected_issue_count BETWEEN 0 AND 4096),
    expected_retained_field_bytes INTEGER NOT NULL
        CHECK (expected_retained_field_bytes BETWEEN 0 AND 16777216),
    manifest_version INTEGER NOT NULL DEFAULT 1 CHECK (manifest_version = 1),
    retained_report_digest BLOB NOT NULL CHECK (length(retained_report_digest) = 32),
    expected_manifest_digest BLOB NOT NULL CHECK (length(expected_manifest_digest) = 32),
    state TEXT NOT NULL DEFAULT 'draft'
        CHECK (state IN ('draft', 'sealed', 'abandoned')),
    sealed_manifest_digest BLOB
        CHECK (sealed_manifest_digest IS NULL OR length(sealed_manifest_digest) = 32),
    abandon_reason_code TEXT
        CHECK (
            abandon_reason_code IS NULL
            OR length(CAST(abandon_reason_code AS BLOB)) BETWEEN 1 AND 256
        ),
    abandon_reason_message TEXT
        CHECK (
            abandon_reason_message IS NULL
            OR length(CAST(abandon_reason_message AS BLOB)) BETWEEN 1 AND 65536
        ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    finalized_at_ms INTEGER
        CHECK (finalized_at_ms IS NULL OR finalized_at_ms >= created_at_ms),
    UNIQUE (time_session_id, exact_group_build_id, probe_ordinal),
    UNIQUE (id, time_session_id),
    UNIQUE (id, exact_group_build_id),
    CHECK (usage_bytes_read <= effective_max_total_bytes_read),
    CHECK (usage_read_operations <= effective_max_read_operations),
    CHECK (usage_retained_field_bytes <= effective_max_retained_field_bytes),
    CHECK (usage_fields_emitted <= effective_max_fields),
    CHECK (usage_jpeg_segments_visited <= effective_max_jpeg_segments),
    CHECK (usage_ifd_entries_visited <= effective_max_ifd_entries),
    CHECK (usage_bmff_boxes_visited <= effective_max_bmff_boxes),
    CHECK (usage_max_depth_observed <= MAX(effective_max_ifd_depth, effective_max_bmff_depth)),
    CHECK (effective_max_field_bytes <= effective_max_retained_field_bytes),
    CHECK (expected_field_count = usage_fields_emitted),
    CHECK (expected_retained_field_bytes = usage_retained_field_bytes),
    CHECK (
        (state = 'draft'
         AND sealed_manifest_digest IS NULL
         AND abandon_reason_code IS NULL
         AND abandon_reason_message IS NULL
         AND finalized_at_ms IS NULL)
        OR
        (state = 'sealed'
         AND sealed_manifest_digest = expected_manifest_digest
         AND abandon_reason_code IS NULL
         AND abandon_reason_message IS NULL
         AND finalized_at_ms IS NOT NULL)
        OR
        (state = 'abandoned'
         AND sealed_manifest_digest IS NULL
         AND abandon_reason_code IS NOT NULL
         AND finalized_at_ms IS NOT NULL)
    ),
    FOREIGN KEY (volume_id, scan_run_id, time_session_id, core_session_id)
        REFERENCES scan_time_sessions(volume_id, scan_run_id, id, core_session_id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        scan_run_id,
        exact_group_build_id,
        metadata_probe_observation_id,
        metadata_probe_fingerprint_id
    ) REFERENCES exact_group_build_members(
        volume_id,
        scan_run_id,
        exact_group_build_id,
        media_observation_snapshot_id,
        observation_fingerprint_id
    ) ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX ux_metadata_reports_sealed_group_v7
    ON metadata_extraction_reports(time_session_id, exact_group_build_id)
    WHERE state = 'sealed';

CREATE INDEX ix_metadata_reports_group_v7
    ON metadata_extraction_reports(time_session_id, exact_group_build_id, state, probe_ordinal, id);

CREATE TABLE metadata_extraction_fields (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    parser_name TEXT NOT NULL CHECK (length(CAST(parser_name AS BLOB)) BETWEEN 1 AND 128),
    parser_version TEXT NOT NULL CHECK (length(CAST(parser_version AS BLOB)) BETWEEN 1 AND 128),
    field_kind TEXT NOT NULL CHECK (field_kind IN (
        'exif_date_time_original',
        'exif_create_date',
        'exif_modify_date',
        'exif_offset_time_original',
        'exif_subsec_time_original',
        'quicktime_movie_header_creation_time',
        'quicktime_metadata_creation_date'
    )),
    encoding TEXT NOT NULL CHECK (encoding IN (
        'declared_ascii', 'validated_utf8', 'unsigned_big_endian'
    )),
    absolute_offset INTEGER NOT NULL CHECK (absolute_offset >= 0),
    byte_len INTEGER NOT NULL CHECK (byte_len BETWEEN 1 AND 1048576),
    raw_bytes BLOB NOT NULL CHECK (length(raw_bytes) BETWEEN 1 AND 1048576),
    raw_digest BLOB NOT NULL CHECK (length(raw_digest) = 32),
    container_kind TEXT NOT NULL CHECK (container_kind IN ('tiff', 'jpeg_exif', 'iso_bmff')),
    tiff_header_offset INTEGER CHECK (tiff_header_offset IS NULL OR tiff_header_offset >= 0),
    tiff_ifd_offset INTEGER CHECK (tiff_ifd_offset IS NULL OR tiff_ifd_offset >= 0),
    tiff_tag INTEGER CHECK (tiff_tag IS NULL OR tiff_tag BETWEEN 0 AND 65535),
    tiff_byte_order TEXT CHECK (tiff_byte_order IN ('little_endian', 'big_endian')),
    jpeg_app1_offset INTEGER CHECK (jpeg_app1_offset IS NULL OR jpeg_app1_offset >= 0),
    bmff_box_offset INTEGER CHECK (bmff_box_offset IS NULL OR bmff_box_offset >= 0),
    bmff_box_path BLOB
        CHECK (
            bmff_box_path IS NULL
            OR (length(bmff_box_path) BETWEEN 4 AND 256 AND length(bmff_box_path) % 4 = 0)
        ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (report_id, ordinal),
    UNIQUE (report_id, id),
    CHECK (byte_len = length(raw_bytes)),
    CHECK (
        (container_kind = 'tiff'
         AND tiff_header_offset IS NOT NULL
         AND tiff_ifd_offset IS NOT NULL
         AND tiff_tag IS NOT NULL
         AND tiff_byte_order IS NOT NULL
         AND jpeg_app1_offset IS NULL
         AND bmff_box_offset IS NULL
         AND bmff_box_path IS NULL)
        OR
        (container_kind = 'jpeg_exif'
         AND tiff_header_offset IS NOT NULL
         AND tiff_ifd_offset IS NOT NULL
         AND tiff_tag IS NOT NULL
         AND tiff_byte_order IS NOT NULL
         AND jpeg_app1_offset IS NOT NULL
         AND bmff_box_offset IS NULL
         AND bmff_box_path IS NULL)
        OR
        (container_kind = 'iso_bmff'
         AND tiff_header_offset IS NULL
         AND tiff_ifd_offset IS NULL
         AND tiff_tag IS NULL
         AND tiff_byte_order IS NULL
         AND jpeg_app1_offset IS NULL
         AND bmff_box_offset IS NOT NULL
         AND bmff_box_path IS NOT NULL)
    ),
    FOREIGN KEY (report_id) REFERENCES metadata_extraction_reports(id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_metadata_fields_page_v7
    ON metadata_extraction_fields(report_id, ordinal, id);

CREATE TABLE metadata_extraction_issues (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    parser_name TEXT NOT NULL CHECK (length(CAST(parser_name AS BLOB)) BETWEEN 1 AND 128),
    parser_version TEXT NOT NULL CHECK (length(CAST(parser_version AS BLOB)) BETWEEN 1 AND 128),
    issue_code TEXT NOT NULL CHECK (issue_code IN (
        'io', 'unexpected_eof', 'arithmetic_overflow', 'out_of_bounds',
        'invalid_structure', 'cycle_detected', 'limit_exceeded',
        'unsupported_version', 'invalid_source'
    )),
    source_offset INTEGER CHECK (source_offset IS NULL OR source_offset >= 0),
    context TEXT NOT NULL CHECK (length(CAST(context AS BLOB)) BETWEEN 1 AND 4096),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (report_id, ordinal),
    FOREIGN KEY (report_id) REFERENCES metadata_extraction_reports(id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_metadata_issues_page_v7
    ON metadata_extraction_issues(report_id, ordinal, id);

CREATE TABLE metadata_source_revalidations (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL UNIQUE,
    time_session_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    core_session_id BLOB NOT NULL CHECK (length(core_session_id) = 32),
    exact_group_build_id INTEGER NOT NULL,
    metadata_probe_observation_id INTEGER NOT NULL,
    source_key BLOB NOT NULL CHECK (length(source_key) = 32),
    source_key_version INTEGER NOT NULL DEFAULT 2 CHECK (source_key_version = 2),
    lineage_key BLOB NOT NULL CHECK (length(lineage_key) = 32),
    lineage_key_version INTEGER NOT NULL DEFAULT 1 CHECK (lineage_key_version = 1),
    source_signature_before BLOB NOT NULL CHECK (length(source_signature_before) = 32),
    source_signature_after BLOB NOT NULL CHECK (length(source_signature_after) = 32),
    first_report_digest BLOB NOT NULL CHECK (length(first_report_digest) = 32),
    second_report_digest BLOB NOT NULL CHECK (length(second_report_digest) = 32),
    outcome TEXT NOT NULL CHECK (outcome = 'reextracted_pinned_exact'),
    descriptor_revalidated INTEGER NOT NULL CHECK (descriptor_revalidated = 1),
    path_revalidated INTEGER NOT NULL CHECK (path_revalidated = 1),
    session_revalidated INTEGER NOT NULL CHECK (session_revalidated = 1),
    trust_scope TEXT NOT NULL CHECK (trust_scope = 'historical_proof_only'),
    revalidated_at_ms INTEGER NOT NULL CHECK (revalidated_at_ms >= 0),
    UNIQUE (report_id, source_key, lineage_key),
    UNIQUE (id, report_id),
    CHECK (source_signature_before = source_signature_after),
    CHECK (first_report_digest = second_report_digest),
    FOREIGN KEY (report_id, time_session_id)
        REFERENCES metadata_extraction_reports(id, time_session_id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id, core_session_id)
        REFERENCES scan_core_sessions(volume_id, scan_run_id, core_session_id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id, metadata_probe_observation_id, source_signature_before)
        REFERENCES media_observation_snapshots(volume_id, scan_run_id, id, source_signature)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_metadata_revalidations_group_v7
    ON metadata_source_revalidations(time_session_id, exact_group_build_id, report_id);

CREATE TABLE capture_time_analysis_builds (
    id INTEGER PRIMARY KEY,
    time_session_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    exact_group_build_id INTEGER NOT NULL,
    policy_name TEXT NOT NULL CHECK (length(CAST(policy_name AS BLOB)) BETWEEN 1 AND 128),
    policy_version TEXT NOT NULL CHECK (length(CAST(policy_version AS BLOB)) BETWEEN 1 AND 128),
    policy_context_json TEXT NOT NULL
        CHECK (
            length(CAST(policy_context_json AS BLOB)) BETWEEN 2 AND 1048576
            AND json_valid(policy_context_json)
            AND json_type(policy_context_json) = 'object'
            AND policy_context_json = json(policy_context_json)
            AND (
                json_type(policy_context_json, '$.sentinel_rules') IS NULL
                OR json_type(policy_context_json, '$.sentinel_rules') = 'array'
            )
            AND COALESCE(json_array_length(policy_context_json, '$.sentinel_rules'), 0) <= 1024
        ),
    policy_context_digest BLOB NOT NULL CHECK (length(policy_context_digest) = 32),
    state TEXT NOT NULL DEFAULT 'draft'
        CHECK (state IN ('draft', 'sealed', 'abandoned')),
    decision TEXT CHECK (decision IN (
        'no_usable_evidence', 'review_required', 'evidence_eligible', 'conflict'
    )),
    selected_candidate_ordinal INTEGER
        CHECK (selected_candidate_ordinal IS NULL OR selected_candidate_ordinal >= 0),
    expected_source_count INTEGER NOT NULL CHECK (expected_source_count BETWEEN 1 AND 4096),
    expected_observation_count INTEGER NOT NULL CHECK (expected_observation_count BETWEEN 0 AND 8192),
    expected_candidate_count INTEGER NOT NULL CHECK (expected_candidate_count BETWEEN 0 AND 8192),
    expected_issue_count INTEGER NOT NULL CHECK (expected_issue_count BETWEEN 0 AND 8192),
    expected_member_count INTEGER NOT NULL CHECK (expected_member_count BETWEEN 2 AND 8192),
    expected_recommendation_count INTEGER NOT NULL CHECK (expected_recommendation_count = 1),
    manifest_version INTEGER NOT NULL DEFAULT 1 CHECK (manifest_version = 1),
    expected_manifest_digest BLOB NOT NULL CHECK (length(expected_manifest_digest) = 32),
    sealed_manifest_digest BLOB
        CHECK (sealed_manifest_digest IS NULL OR length(sealed_manifest_digest) = 32),
    abandon_reason_code TEXT
        CHECK (
            abandon_reason_code IS NULL
            OR length(CAST(abandon_reason_code AS BLOB)) BETWEEN 1 AND 256
        ),
    abandon_reason_message TEXT
        CHECK (
            abandon_reason_message IS NULL
            OR length(CAST(abandon_reason_message AS BLOB)) BETWEEN 1 AND 65536
        ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    finalized_at_ms INTEGER
        CHECK (finalized_at_ms IS NULL OR finalized_at_ms >= created_at_ms),
    UNIQUE (time_session_id, exact_group_build_id),
    UNIQUE (volume_id, scan_run_id, exact_group_build_id),
    UNIQUE (id, time_session_id),
    CHECK (
        (state = 'draft'
         AND decision IS NULL
         AND selected_candidate_ordinal IS NULL
         AND sealed_manifest_digest IS NULL
         AND abandon_reason_code IS NULL
         AND abandon_reason_message IS NULL
         AND finalized_at_ms IS NULL)
        OR
        (state = 'sealed'
         AND decision IS NOT NULL
         AND ((decision IN ('review_required', 'evidence_eligible')
               AND selected_candidate_ordinal IS NOT NULL)
              OR
              (decision IN ('no_usable_evidence', 'conflict')
               AND selected_candidate_ordinal IS NULL))
         AND sealed_manifest_digest = expected_manifest_digest
         AND abandon_reason_code IS NULL
         AND abandon_reason_message IS NULL
         AND finalized_at_ms IS NOT NULL)
        OR
        (state = 'abandoned'
         AND decision IS NULL
         AND selected_candidate_ordinal IS NULL
         AND sealed_manifest_digest IS NULL
         AND abandon_reason_code IS NOT NULL
         AND finalized_at_ms IS NOT NULL)
    ),
    FOREIGN KEY (volume_id, scan_run_id, time_session_id)
        REFERENCES scan_time_sessions(volume_id, scan_run_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id, exact_group_build_id)
        REFERENCES exact_group_builds(volume_id, scan_run_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (id, selected_candidate_ordinal)
        REFERENCES capture_time_candidates(analysis_build_id, ordinal)
        ON UPDATE CASCADE ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE INDEX ix_capture_time_builds_page_v7
    ON capture_time_analysis_builds(time_session_id, state, exact_group_build_id, id);

CREATE TABLE capture_time_analysis_sources (
    analysis_build_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    report_id INTEGER NOT NULL,
    source_key BLOB NOT NULL CHECK (length(source_key) = 32),
    lineage_key BLOB NOT NULL CHECK (length(lineage_key) = 32),
    binding_status TEXT NOT NULL CHECK (binding_status = 'reextracted_pinned_source'),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (analysis_build_id, ordinal),
    UNIQUE (analysis_build_id, report_id),
    UNIQUE (analysis_build_id, ordinal, report_id),
    FOREIGN KEY (analysis_build_id) REFERENCES capture_time_analysis_builds(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (report_id, source_key, lineage_key)
        REFERENCES metadata_source_revalidations(report_id, source_key, lineage_key)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_capture_time_sources_report_v7
    ON capture_time_analysis_sources(report_id, analysis_build_id, ordinal);

CREATE TABLE capture_time_observations (
    id INTEGER PRIMARY KEY,
    analysis_build_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 8191),
    source_ordinal INTEGER NOT NULL CHECK (source_ordinal BETWEEN 0 AND 4095),
    report_id INTEGER NOT NULL,
    metadata_field_id INTEGER NOT NULL,
    interpretation_kind TEXT NOT NULL
        CHECK (interpretation_kind IN ('timestamp', 'offset', 'subsecond', 'rejected')),
    wall_year INTEGER CHECK (wall_year IS NULL OR wall_year BETWEEN 1 AND 9999),
    wall_month INTEGER CHECK (wall_month IS NULL OR wall_month BETWEEN 1 AND 12),
    wall_day INTEGER CHECK (wall_day IS NULL OR wall_day BETWEEN 1 AND 31),
    wall_hour INTEGER CHECK (wall_hour IS NULL OR wall_hour BETWEEN 0 AND 23),
    wall_minute INTEGER CHECK (wall_minute IS NULL OR wall_minute BETWEEN 0 AND 59),
    wall_second INTEGER CHECK (wall_second IS NULL OR wall_second BETWEEN 0 AND 59),
    wall_nanosecond INTEGER CHECK (wall_nanosecond IS NULL OR wall_nanosecond BETWEEN 0 AND 999999999),
    semantic_kind TEXT CHECK (semantic_kind IN ('floating', 'utc')),
    offset_kind TEXT CHECK (offset_kind IN ('missing', 'explicit', 'quicktime_epoch_assumed_utc')),
    utc_offset_minutes INTEGER
        CHECK (utc_offset_minutes IS NULL OR utc_offset_minutes BETWEEN -840 AND 840),
    utc_seconds_decimal TEXT
        CHECK (utc_seconds_decimal IS NULL OR length(CAST(utc_seconds_decimal AS BLOB)) BETWEEN 1 AND 40),
    utc_nanoseconds INTEGER CHECK (utc_nanoseconds IS NULL OR utc_nanoseconds BETWEEN 0 AND 999999999),
    normalized_precision_ns INTEGER
        CHECK (normalized_precision_ns IS NULL OR normalized_precision_ns BETWEEN 1 AND 1000000000),
    parsed_offset_minutes INTEGER
        CHECK (parsed_offset_minutes IS NULL OR parsed_offset_minutes BETWEEN -840 AND 840),
    subsecond_nanosecond INTEGER
        CHECK (subsecond_nanosecond IS NULL OR subsecond_nanosecond BETWEEN 0 AND 999999999),
    subsecond_digits INTEGER CHECK (subsecond_digits IS NULL OR subsecond_digits BETWEEN 1 AND 9),
    subsecond_precision_ns INTEGER
        CHECK (subsecond_precision_ns IS NULL OR subsecond_precision_ns BETWEEN 1 AND 1000000000),
    rejection_code TEXT CHECK (rejection_code IN (
        'empty', 'invalid_encoding', 'invalid_syntax', 'year_out_of_range',
        'month_out_of_range', 'day_out_of_range', 'hour_out_of_range',
        'minute_out_of_range', 'second_out_of_range', 'nanosecond_out_of_range',
        'subsecond_out_of_range', 'offset_out_of_range',
        'unknown_negative_zero_offset', 'precision_out_of_range',
        'unsupported_binary_length', 'arithmetic_overflow'
    )),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (analysis_build_id, ordinal),
    UNIQUE (analysis_build_id, id),
    CHECK (
        utc_seconds_decimal IS NULL
        OR utc_seconds_decimal = '0'
        OR (
            substr(utc_seconds_decimal, 1, 1) BETWEEN '1' AND '9'
            AND utc_seconds_decimal NOT GLOB '*[^0-9]*'
        )
        OR (
            substr(utc_seconds_decimal, 1, 1) = '-'
            AND length(utc_seconds_decimal) >= 2
            AND substr(utc_seconds_decimal, 2, 1) BETWEEN '1' AND '9'
            AND substr(utc_seconds_decimal, 2) NOT GLOB '*[^0-9]*'
        )
    ),
    CHECK (
        (interpretation_kind = 'timestamp'
         AND wall_year IS NOT NULL AND wall_month IS NOT NULL AND wall_day IS NOT NULL
         AND wall_hour IS NOT NULL AND wall_minute IS NOT NULL AND wall_second IS NOT NULL
         AND wall_nanosecond IS NOT NULL AND semantic_kind IS NOT NULL
         AND offset_kind IS NOT NULL AND normalized_precision_ns IS NOT NULL
         AND parsed_offset_minutes IS NULL AND subsecond_nanosecond IS NULL
         AND subsecond_digits IS NULL AND subsecond_precision_ns IS NULL
         AND rejection_code IS NULL
         AND ((semantic_kind = 'floating'
               AND offset_kind = 'missing'
               AND utc_offset_minutes IS NULL
               AND utc_seconds_decimal IS NULL
               AND utc_nanoseconds IS NULL)
              OR
              (semantic_kind = 'utc'
               AND offset_kind IN ('explicit', 'quicktime_epoch_assumed_utc')
               AND utc_offset_minutes IS NOT NULL
               AND utc_seconds_decimal IS NOT NULL
               AND utc_nanoseconds IS NOT NULL
               AND (offset_kind <> 'quicktime_epoch_assumed_utc' OR utc_offset_minutes = 0))))
        OR
        (interpretation_kind = 'offset'
         AND wall_year IS NULL AND wall_month IS NULL AND wall_day IS NULL
         AND wall_hour IS NULL AND wall_minute IS NULL AND wall_second IS NULL
         AND wall_nanosecond IS NULL AND semantic_kind IS NULL AND offset_kind IS NULL
         AND utc_offset_minutes IS NULL AND utc_seconds_decimal IS NULL
         AND utc_nanoseconds IS NULL AND normalized_precision_ns IS NULL
         AND parsed_offset_minutes IS NOT NULL
         AND subsecond_nanosecond IS NULL AND subsecond_digits IS NULL
         AND subsecond_precision_ns IS NULL AND rejection_code IS NULL)
        OR
        (interpretation_kind = 'subsecond'
         AND wall_year IS NULL AND wall_month IS NULL AND wall_day IS NULL
         AND wall_hour IS NULL AND wall_minute IS NULL AND wall_second IS NULL
         AND wall_nanosecond IS NULL AND semantic_kind IS NULL AND offset_kind IS NULL
         AND utc_offset_minutes IS NULL AND utc_seconds_decimal IS NULL
         AND utc_nanoseconds IS NULL AND normalized_precision_ns IS NULL
         AND parsed_offset_minutes IS NULL
         AND subsecond_nanosecond IS NOT NULL AND subsecond_digits IS NOT NULL
         AND subsecond_precision_ns IS NOT NULL AND rejection_code IS NULL)
        OR
        (interpretation_kind = 'rejected'
         AND wall_year IS NULL AND wall_month IS NULL AND wall_day IS NULL
         AND wall_hour IS NULL AND wall_minute IS NULL AND wall_second IS NULL
         AND wall_nanosecond IS NULL AND semantic_kind IS NULL AND offset_kind IS NULL
         AND utc_offset_minutes IS NULL AND utc_seconds_decimal IS NULL
         AND utc_nanoseconds IS NULL AND normalized_precision_ns IS NULL
         AND parsed_offset_minutes IS NULL AND subsecond_nanosecond IS NULL
         AND subsecond_digits IS NULL AND subsecond_precision_ns IS NULL
         AND rejection_code IS NOT NULL)
    ),
    FOREIGN KEY (analysis_build_id, source_ordinal, report_id)
        REFERENCES capture_time_analysis_sources(analysis_build_id, ordinal, report_id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (report_id, metadata_field_id)
        REFERENCES metadata_extraction_fields(report_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_capture_time_observations_page_v7
    ON capture_time_observations(analysis_build_id, ordinal, id);

CREATE TABLE capture_time_candidates (
    id INTEGER PRIMARY KEY,
    analysis_build_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 8191),
    wall_year INTEGER NOT NULL CHECK (wall_year BETWEEN 1 AND 9999),
    wall_month INTEGER NOT NULL CHECK (wall_month BETWEEN 1 AND 12),
    wall_day INTEGER NOT NULL CHECK (wall_day BETWEEN 1 AND 31),
    wall_hour INTEGER NOT NULL CHECK (wall_hour BETWEEN 0 AND 23),
    wall_minute INTEGER NOT NULL CHECK (wall_minute BETWEEN 0 AND 59),
    wall_second INTEGER NOT NULL CHECK (wall_second BETWEEN 0 AND 59),
    wall_nanosecond INTEGER NOT NULL CHECK (wall_nanosecond BETWEEN 0 AND 999999999),
    semantic_kind TEXT NOT NULL CHECK (semantic_kind IN ('floating', 'utc')),
    offset_kind TEXT NOT NULL
        CHECK (offset_kind IN ('missing', 'explicit', 'quicktime_epoch_assumed_utc')),
    utc_offset_minutes INTEGER
        CHECK (utc_offset_minutes IS NULL OR utc_offset_minutes BETWEEN -840 AND 840),
    utc_seconds_decimal TEXT
        CHECK (utc_seconds_decimal IS NULL OR length(CAST(utc_seconds_decimal AS BLOB)) BETWEEN 1 AND 40),
    utc_nanoseconds INTEGER CHECK (utc_nanoseconds IS NULL OR utc_nanoseconds BETWEEN 0 AND 999999999),
    precision_ns INTEGER NOT NULL CHECK (precision_ns BETWEEN 1 AND 1000000000),
    confidence TEXT NOT NULL CHECK (confidence IN ('conflict', 'low', 'medium', 'high')),
    evidence_gate TEXT NOT NULL CHECK (evidence_gate IN ('eligible', 'blocked')),
    evidence_kinds_json TEXT NOT NULL CHECK (
        length(CAST(evidence_kinds_json AS BLOB)) BETWEEN 2 AND 1048576
        AND json_valid(evidence_kinds_json) AND json_type(evidence_kinds_json) = 'array'
        AND evidence_kinds_json = json(evidence_kinds_json)
        AND json_array_length(evidence_kinds_json) BETWEEN 1 AND 8192
    ),
    source_keys_json TEXT NOT NULL CHECK (
        length(CAST(source_keys_json AS BLOB)) BETWEEN 2 AND 1048576
        AND json_valid(source_keys_json) AND json_type(source_keys_json) = 'array'
        AND source_keys_json = json(source_keys_json)
        AND json_array_length(source_keys_json) BETWEEN 1 AND 4096
    ),
    lineage_keys_json TEXT NOT NULL CHECK (
        length(CAST(lineage_keys_json AS BLOB)) BETWEEN 2 AND 1048576
        AND json_valid(lineage_keys_json) AND json_type(lineage_keys_json) = 'array'
        AND lineage_keys_json = json(lineage_keys_json)
        AND json_array_length(lineage_keys_json) BETWEEN 1 AND 4096
    ),
    observation_ordinals_json TEXT NOT NULL CHECK (
        length(CAST(observation_ordinals_json AS BLOB)) BETWEEN 2 AND 1048576
        AND json_valid(observation_ordinals_json) AND json_type(observation_ordinals_json) = 'array'
        AND observation_ordinals_json = json(observation_ordinals_json)
        AND json_array_length(observation_ordinals_json) BETWEEN 1 AND 8192
    ),
    anomalies_json TEXT NOT NULL CHECK (
        length(CAST(anomalies_json AS BLOB)) BETWEEN 2 AND 1048576
        AND json_valid(anomalies_json) AND json_type(anomalies_json) = 'array'
        AND anomalies_json = json(anomalies_json)
        AND json_array_length(anomalies_json) <= 8192
    ),
    blockers_json TEXT NOT NULL CHECK (
        length(CAST(blockers_json AS BLOB)) BETWEEN 2 AND 1048576
        AND json_valid(blockers_json) AND json_type(blockers_json) = 'array'
        AND blockers_json = json(blockers_json)
        AND json_array_length(blockers_json) <= 8192
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (analysis_build_id, ordinal),
    UNIQUE (analysis_build_id, id),
    CHECK (
        utc_seconds_decimal IS NULL
        OR utc_seconds_decimal = '0'
        OR (
            substr(utc_seconds_decimal, 1, 1) BETWEEN '1' AND '9'
            AND utc_seconds_decimal NOT GLOB '*[^0-9]*'
        )
        OR (
            substr(utc_seconds_decimal, 1, 1) = '-'
            AND length(utc_seconds_decimal) >= 2
            AND substr(utc_seconds_decimal, 2, 1) BETWEEN '1' AND '9'
            AND substr(utc_seconds_decimal, 2) NOT GLOB '*[^0-9]*'
        )
    ),
    CHECK (
        (semantic_kind = 'floating'
         AND offset_kind = 'missing'
         AND utc_offset_minutes IS NULL
         AND utc_seconds_decimal IS NULL
         AND utc_nanoseconds IS NULL)
        OR
        (semantic_kind = 'utc'
         AND offset_kind IN ('explicit', 'quicktime_epoch_assumed_utc')
         AND utc_offset_minutes IS NOT NULL
         AND utc_seconds_decimal IS NOT NULL
         AND utc_nanoseconds IS NOT NULL
         AND (offset_kind <> 'quicktime_epoch_assumed_utc' OR utc_offset_minutes = 0))
    ),
    CHECK (
        (evidence_gate = 'eligible'
         AND confidence = 'high'
         AND semantic_kind = 'utc'
         AND offset_kind = 'explicit'
         AND json_array_length(blockers_json) = 0)
        OR
        (evidence_gate = 'blocked' AND json_array_length(blockers_json) >= 1)
    ),
    FOREIGN KEY (analysis_build_id) REFERENCES capture_time_analysis_builds(id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_capture_time_candidates_page_v7
    ON capture_time_candidates(analysis_build_id, ordinal, id);

CREATE TABLE capture_time_policy_issues (
    id INTEGER PRIMARY KEY,
    analysis_build_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 8191),
    issue_code TEXT NOT NULL CHECK (issue_code IN (
        'invalid_field', 'invalid_companion', 'orphan_exif_companion',
        'repeated_field_conflict', 'lineage_conflict', 'strong_evidence_conflict',
        'strong_evidence_within_tolerance_ambiguous', 'possible_timezone_conflict',
        'sentinel_value', 'obvious_future', 'outside_automatic_range',
        'quicktime_epoch_semantic_uncertainty', 'extraction_report_untrusted',
        'extraction_report_contradiction', 'parser_identity_mismatch',
        'field_encoding_mismatch', 'container_format_mismatch',
        'metadata_locator_mismatch', 'duplicate_source_identity',
        'unknown_parser_identity', 'extraction_budget_contradiction',
        'analysis_limit_exceeded'
    )),
    field_kind TEXT CHECK (field_kind IN (
        'exif_date_time_original', 'exif_create_date', 'exif_modify_date',
        'exif_offset_time_original', 'exif_subsec_time_original',
        'quicktime_movie_header_creation_time', 'quicktime_metadata_creation_date'
    )),
    observation_ordinals_json TEXT NOT NULL CHECK (
        length(CAST(observation_ordinals_json AS BLOB)) BETWEEN 2 AND 1048576
        AND json_valid(observation_ordinals_json) AND json_type(observation_ordinals_json) = 'array'
        AND observation_ordinals_json = json(observation_ordinals_json)
        AND json_array_length(observation_ordinals_json) <= 8192
    ),
    source_keys_json TEXT NOT NULL CHECK (
        length(CAST(source_keys_json AS BLOB)) BETWEEN 2 AND 1048576
        AND json_valid(source_keys_json) AND json_type(source_keys_json) = 'array'
        AND source_keys_json = json(source_keys_json)
        AND json_array_length(source_keys_json) <= 4096
    ),
    lineage_keys_json TEXT NOT NULL CHECK (
        length(CAST(lineage_keys_json AS BLOB)) BETWEEN 2 AND 1048576
        AND json_valid(lineage_keys_json) AND json_type(lineage_keys_json) = 'array'
        AND lineage_keys_json = json(lineage_keys_json)
        AND json_array_length(lineage_keys_json) <= 4096
    ),
    context TEXT NOT NULL CHECK (length(CAST(context AS BLOB)) BETWEEN 1 AND 4096),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (analysis_build_id, ordinal),
    FOREIGN KEY (analysis_build_id) REFERENCES capture_time_analysis_builds(id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_capture_time_policy_issues_page_v7
    ON capture_time_policy_issues(analysis_build_id, ordinal, id);

CREATE TABLE capture_time_member_assessments (
    analysis_build_id INTEGER NOT NULL,
    member_ordinal INTEGER NOT NULL CHECK (member_ordinal BETWEEN 0 AND 8191),
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    exact_group_build_id INTEGER NOT NULL,
    media_observation_snapshot_id INTEGER NOT NULL,
    candidate_id INTEGER,
    birth_time_relation TEXT NOT NULL CHECK (birth_time_relation IN (
        'unavailable', 'not_compared', 'matches', 'differs', 'review_fs_precision_unknown'
    )),
    modified_time_relation TEXT NOT NULL CHECK (modified_time_relation IN (
        'not_compared', 'matches', 'differs', 'review_fs_precision_unknown'
    )),
    donor_eligibility TEXT NOT NULL
        CHECK (donor_eligibility IN ('eligible', 'ineligible', 'review_required')),
    reason_code TEXT NOT NULL CHECK (length(CAST(reason_code AS BLOB)) BETWEEN 1 AND 256),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (analysis_build_id, member_ordinal),
    UNIQUE (analysis_build_id, media_observation_snapshot_id),
    FOREIGN KEY (analysis_build_id, candidate_id)
        REFERENCES capture_time_candidates(analysis_build_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        scan_run_id,
        exact_group_build_id,
        member_ordinal,
        media_observation_snapshot_id
    ) REFERENCES exact_group_build_members(
        volume_id,
        scan_run_id,
        exact_group_build_id,
        ordinal,
        media_observation_snapshot_id
    ) ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_capture_time_member_assessments_candidate_v7
    ON capture_time_member_assessments(analysis_build_id, candidate_id, member_ordinal);

CREATE TABLE capture_time_recommendations (
    analysis_build_id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    exact_group_build_id INTEGER NOT NULL,
    keeper_observation_id INTEGER,
    time_donor_observation_id INTEGER,
    candidate_id INTEGER,
    keeper_policy_name TEXT
        CHECK (keeper_policy_name IS NULL OR length(CAST(keeper_policy_name AS BLOB)) BETWEEN 1 AND 128),
    keeper_policy_version TEXT
        CHECK (keeper_policy_version IS NULL OR length(CAST(keeper_policy_version AS BLOB)) BETWEEN 1 AND 128),
    time_donor_policy_name TEXT
        CHECK (time_donor_policy_name IS NULL OR length(CAST(time_donor_policy_name AS BLOB)) BETWEEN 1 AND 128),
    time_donor_policy_version TEXT
        CHECK (time_donor_policy_version IS NULL OR length(CAST(time_donor_policy_version AS BLOB)) BETWEEN 1 AND 128),
    evidence_only INTEGER NOT NULL DEFAULT 1 CHECK (evidence_only = 1),
    write_authorized INTEGER NOT NULL DEFAULT 0 CHECK (write_authorized = 0),
    reason_code TEXT NOT NULL CHECK (length(CAST(reason_code AS BLOB)) BETWEEN 1 AND 256),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (
        (keeper_observation_id IS NULL
         AND keeper_policy_name IS NULL
         AND keeper_policy_version IS NULL
         AND time_donor_observation_id IS NULL
         AND candidate_id IS NULL
         AND time_donor_policy_name IS NULL
         AND time_donor_policy_version IS NULL)
        OR
        (keeper_observation_id IS NOT NULL
         AND keeper_policy_name IS NOT NULL
         AND keeper_policy_version IS NOT NULL
         AND ((time_donor_observation_id IS NULL
               AND candidate_id IS NULL
               AND time_donor_policy_name IS NULL
               AND time_donor_policy_version IS NULL)
              OR
              (time_donor_observation_id IS NOT NULL
               AND candidate_id IS NOT NULL
               AND time_donor_policy_name IS NOT NULL
               AND time_donor_policy_version IS NOT NULL)))
    ),
    FOREIGN KEY (analysis_build_id, candidate_id)
        REFERENCES capture_time_candidates(analysis_build_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id, exact_group_build_id, keeper_observation_id)
        REFERENCES exact_group_build_members(
            volume_id, scan_run_id, exact_group_build_id, media_observation_snapshot_id
        ) ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id, exact_group_build_id, time_donor_observation_id)
        REFERENCES exact_group_build_members(
            volume_id, scan_run_id, exact_group_build_id, media_observation_snapshot_id
        ) ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

-- A time session may only start from current-session core evidence after the
-- exact verification stage has been sealed.  The expected group set is frozen.
CREATE TRIGGER trg_scan_time_sessions_insert_guard_v7
BEFORE INSERT ON scan_time_sessions
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_core_sessions AS core
    JOIN scan_run_sessions AS run_session
      ON run_session.scan_run_id = core.scan_run_id
     AND run_session.volume_id = core.volume_id
     AND run_session.capability_profile_id = core.capability_profile_id
     AND run_session.namespace_profile_id = core.namespace_profile_id
    JOIN scan_runs AS run
      ON run.id = run_session.scan_run_id
     AND run.volume_id = run_session.volume_id
    JOIN scan_jobs AS job
      ON job.id = run_session.scan_job_id
     AND job.volume_id = run_session.volume_id
     AND job.active_scan_run_id = run.id
    JOIN capability_profiles AS profile
      ON profile.id = run_session.capability_profile_id
     AND profile.volume_id = run_session.volume_id
    JOIN scan_stage_seals AS seal
      ON seal.scan_run_id = core.scan_run_id
     AND seal.volume_id = core.volume_id
     AND seal.stage = 'exact_verification'
    WHERE core.scan_run_id = NEW.scan_run_id
      AND core.volume_id = NEW.volume_id
      AND core.core_session_id = NEW.core_session_id
      AND run.state = 'completed'
      AND job.state = 'completed'
      AND profile.profile_hash_version = 2
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.is_current = 1
      AND profile.mount_session_key = run_session.mount_session_key COLLATE BINARY
      AND NEW.created_at_ms >= core.bound_at_ms
      AND NEW.created_at_ms >= seal.sealed_at_ms
      AND NEW.expected_group_count = (
          SELECT count(*) FROM exact_group_builds AS exact_build
          WHERE exact_build.scan_run_id = NEW.scan_run_id
            AND exact_build.volume_id = NEW.volume_id
            AND exact_build.state = 'verified'
      )
)
BEGIN
    SELECT RAISE(ABORT, 'time session requires sealed current-session exact evidence');
END;

CREATE TRIGGER trg_scan_time_sessions_immutable_v7
BEFORE UPDATE OF
    id, time_session_key, volume_id, scan_run_id, core_session_id,
    schema_contract_version, scope_manifest_version, outcome_manifest_version,
    expected_group_count, max_total_read_bytes,
    max_probe_count_per_group, max_report_total_bytes_read,
    max_report_read_operations, max_report_retained_field_bytes,
    max_report_fields, max_report_issues, expected_manifest_digest, created_at_ms
ON scan_time_sessions
BEGIN
    SELECT RAISE(ABORT, 'time session identity and budgets are immutable');
END;

CREATE TRIGGER trg_scan_time_sessions_transition_v7
BEFORE UPDATE ON scan_time_sessions
WHEN OLD.state <> 'draft' OR NEW.state NOT IN ('complete', 'partial', 'abandoned')
BEGIN
    SELECT RAISE(ABORT, 'time session only permits one draft-to-terminal transition');
END;

CREATE TRIGGER trg_scan_time_sessions_finalize_guard_v7
BEFORE UPDATE OF state ON scan_time_sessions
WHEN NEW.state IN ('complete', 'partial') AND (
    EXISTS (
        SELECT 1 FROM metadata_extraction_reports AS report
        WHERE report.time_session_id = NEW.id AND report.state = 'draft'
    )
    OR EXISTS (
        SELECT 1 FROM capture_time_analysis_builds AS build
        WHERE build.time_session_id = NEW.id AND build.state = 'draft'
    )
    OR NEW.evidence_group_count <> (
        SELECT count(*) FROM capture_time_group_outcomes AS outcome
        WHERE outcome.time_session_id = NEW.id AND outcome.outcome = 'evidence'
    )
    OR NEW.unavailable_group_count <> (
        SELECT count(*) FROM capture_time_group_outcomes AS outcome
        WHERE outcome.time_session_id = NEW.id AND outcome.outcome = 'unavailable'
    )
    OR NEW.failed_group_count <> (
        SELECT count(*) FROM capture_time_group_outcomes AS outcome
        WHERE outcome.time_session_id = NEW.id AND outcome.outcome = 'failed'
    )
    OR EXISTS (
        SELECT 1 FROM capture_time_analysis_builds AS build
        WHERE build.time_session_id = NEW.id
          AND build.state = 'sealed'
          AND NOT EXISTS (
              SELECT 1 FROM capture_time_group_outcomes AS outcome
              WHERE outcome.time_session_id = NEW.id
                AND outcome.exact_group_build_id = build.exact_group_build_id
                AND outcome.analysis_build_id = build.id
                AND outcome.outcome = 'evidence'
          )
    )
    OR (
        SELECT COALESCE(sum(report.usage_bytes_read), 0)
        FROM metadata_extraction_reports AS report
        WHERE report.time_session_id = NEW.id
    ) > NEW.max_total_read_bytes / 2
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(outcome.created_at_ms)
        FROM capture_time_group_outcomes AS outcome
        WHERE outcome.time_session_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(report.finalized_at_ms)
        FROM metadata_extraction_reports AS report
        WHERE report.time_session_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(build.finalized_at_ms)
        FROM capture_time_analysis_builds AS build
        WHERE build.time_session_id = NEW.id
    ), NEW.created_at_ms)
)
BEGIN
    SELECT RAISE(ABORT, 'time session terminal counts or read budget are stale');
END;

CREATE TRIGGER trg_scan_time_sessions_abandon_guard_v7
BEFORE UPDATE OF state ON scan_time_sessions
WHEN NEW.state = 'abandoned' AND (
    EXISTS (
        SELECT 1 FROM metadata_extraction_reports AS report
        WHERE report.time_session_id = NEW.id AND report.state = 'draft'
    )
    OR EXISTS (
        SELECT 1 FROM capture_time_analysis_builds AS build
        WHERE build.time_session_id = NEW.id AND build.state = 'draft'
    )
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(report.finalized_at_ms)
        FROM metadata_extraction_reports AS report
        WHERE report.time_session_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(build.finalized_at_ms)
        FROM capture_time_analysis_builds AS build
        WHERE build.time_session_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(outcome.created_at_ms)
        FROM capture_time_group_outcomes AS outcome
        WHERE outcome.time_session_id = NEW.id
    ), NEW.created_at_ms)
)
BEGIN
    SELECT RAISE(ABORT, 'time session abandonment predates retained terminal evidence');
END;

CREATE TRIGGER trg_scan_time_sessions_no_delete_v7
BEFORE DELETE ON scan_time_sessions
BEGIN
    SELECT RAISE(ABORT, 'time session evidence cannot be deleted');
END;

CREATE TRIGGER trg_capture_time_group_outcomes_insert_guard_v7
BEFORE INSERT ON capture_time_group_outcomes
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_time_sessions AS time_session
    JOIN exact_group_builds AS exact_build
      ON exact_build.id = NEW.exact_group_build_id
     AND exact_build.scan_run_id = NEW.scan_run_id
     AND exact_build.volume_id = NEW.volume_id
     AND exact_build.state = 'verified'
    WHERE time_session.id = NEW.time_session_id
      AND time_session.state = 'draft'
      AND time_session.scan_run_id = NEW.scan_run_id
      AND time_session.volume_id = NEW.volume_id
      AND NEW.created_at_ms >= time_session.created_at_ms
      AND NEW.created_at_ms >= COALESCE((
          SELECT max(report.finalized_at_ms)
          FROM metadata_extraction_reports AS report
          WHERE report.time_session_id = NEW.time_session_id
            AND report.exact_group_build_id = NEW.exact_group_build_id
      ), time_session.created_at_ms)
      AND NEW.created_at_ms >= COALESCE((
          SELECT max(build.finalized_at_ms)
          FROM capture_time_analysis_builds AS build
          WHERE build.time_session_id = NEW.time_session_id
            AND build.exact_group_build_id = NEW.exact_group_build_id
      ), time_session.created_at_ms)
      AND NOT EXISTS (
          SELECT 1 FROM metadata_extraction_reports AS report
          WHERE report.time_session_id = NEW.time_session_id
            AND report.exact_group_build_id = NEW.exact_group_build_id
            AND report.state = 'draft'
      )
      AND NOT EXISTS (
          SELECT 1 FROM capture_time_analysis_builds AS build
          WHERE build.time_session_id = NEW.time_session_id
            AND build.exact_group_build_id = NEW.exact_group_build_id
            AND build.state = 'draft'
      )
      AND (
          (NEW.outcome = 'evidence' AND EXISTS (
              SELECT 1 FROM capture_time_analysis_builds AS build
              WHERE build.id = NEW.analysis_build_id
                AND build.time_session_id = NEW.time_session_id
                AND build.exact_group_build_id = NEW.exact_group_build_id
                AND build.volume_id = NEW.volume_id
                AND build.scan_run_id = NEW.scan_run_id
                AND build.state = 'sealed'
                AND build.finalized_at_ms <= NEW.created_at_ms
          ))
          OR
          (NEW.outcome IN ('unavailable', 'failed') AND NOT EXISTS (
              SELECT 1 FROM capture_time_analysis_builds AS build
              WHERE build.time_session_id = NEW.time_session_id
                AND build.exact_group_build_id = NEW.exact_group_build_id
                AND build.state = 'sealed'
          ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'time group outcome is not supported by terminal group evidence');
END;

CREATE TRIGGER trg_capture_time_group_outcomes_no_update_v7
BEFORE UPDATE ON capture_time_group_outcomes
BEGIN
    SELECT RAISE(ABORT, 'time group outcome is immutable');
END;

CREATE TRIGGER trg_capture_time_group_outcomes_no_delete_v7
BEFORE DELETE ON capture_time_group_outcomes
BEGIN
    SELECT RAISE(ABORT, 'time group outcome cannot be deleted');
END;

CREATE TRIGGER trg_metadata_reports_insert_guard_v7
BEFORE INSERT ON metadata_extraction_reports
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_time_sessions AS time_session
    JOIN exact_group_builds AS exact_build
      ON exact_build.id = NEW.exact_group_build_id
     AND exact_build.scan_run_id = time_session.scan_run_id
     AND exact_build.volume_id = time_session.volume_id
     AND exact_build.state = 'verified'
    JOIN media_observation_snapshots AS observation
      ON observation.id = NEW.metadata_probe_observation_id
     AND observation.scan_run_id = NEW.scan_run_id
     AND observation.volume_id = NEW.volume_id
    JOIN observation_fingerprints AS fingerprint
      ON fingerprint.id = NEW.metadata_probe_fingerprint_id
     AND fingerprint.media_observation_snapshot_id = observation.id
     AND fingerprint.scan_run_id = observation.scan_run_id
     AND fingerprint.volume_id = observation.volume_id
    JOIN scan_run_sessions AS run_session
      ON run_session.scan_run_id = time_session.scan_run_id
     AND run_session.volume_id = time_session.volume_id
    JOIN capability_profiles AS profile
      ON profile.id = run_session.capability_profile_id
     AND profile.volume_id = run_session.volume_id
    WHERE time_session.id = NEW.time_session_id
      AND time_session.state = 'draft'
      AND time_session.scan_run_id = NEW.scan_run_id
      AND time_session.volume_id = NEW.volume_id
      AND time_session.core_session_id = NEW.core_session_id
      AND NEW.created_at_ms >= time_session.created_at_ms
      AND NOT EXISTS (
          SELECT 1 FROM capture_time_group_outcomes AS outcome
          WHERE outcome.time_session_id = NEW.time_session_id
            AND outcome.exact_group_build_id = NEW.exact_group_build_id
      )
      AND NEW.probe_ordinal < time_session.max_probe_count_per_group
      AND NEW.source_size_bytes = observation.size_bytes
      AND fingerprint.fingerprint_kind = 'exact_bytes'
      AND fingerprint.source_signature_before = observation.source_signature
      AND fingerprint.source_signature_after = observation.source_signature
      AND NEW.effective_max_total_bytes_read <= time_session.max_report_total_bytes_read
      AND NEW.effective_max_read_operations <= time_session.max_report_read_operations
      AND NEW.effective_max_retained_field_bytes <= time_session.max_report_retained_field_bytes
      AND NEW.effective_max_fields <= time_session.max_report_fields
      AND NEW.expected_issue_count <= time_session.max_report_issues
      AND profile.profile_hash_version = 2
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.is_current = 1
      AND profile.mount_session_key = run_session.mount_session_key COLLATE BINARY
      AND NEW.usage_bytes_read <= time_session.max_total_read_bytes / 2 - COALESCE((
          SELECT sum(existing.usage_bytes_read)
          FROM metadata_extraction_reports AS existing
          WHERE existing.time_session_id = NEW.time_session_id
      ), 0)
)
BEGIN
    SELECT RAISE(ABORT, 'metadata report is not bound to a draft time session and exact member');
END;

CREATE TRIGGER trg_metadata_reports_immutable_v7
BEFORE UPDATE OF
    id, time_session_id, volume_id, scan_run_id, core_session_id,
    exact_group_build_id, metadata_probe_observation_id,
    metadata_probe_fingerprint_id, probe_ordinal, source_size_bytes,
    report_parser_name, report_parser_version, detected_format, extraction_status,
    effective_max_total_bytes_read, effective_max_read_operations,
    effective_max_retained_field_bytes, effective_max_field_bytes,
    effective_max_fields, effective_max_jpeg_segments, effective_max_ifd_entries,
    effective_max_ifd_depth, effective_max_bmff_boxes, effective_max_bmff_depth,
    usage_bytes_read, usage_read_operations, usage_retained_field_bytes,
    usage_fields_emitted, usage_jpeg_segments_visited, usage_ifd_entries_visited,
    usage_bmff_boxes_visited, usage_max_depth_observed, expected_field_count,
    expected_issue_count, expected_retained_field_bytes, manifest_version,
    retained_report_digest, expected_manifest_digest, created_at_ms
ON metadata_extraction_reports
BEGIN
    SELECT RAISE(ABORT, 'metadata report identity, limits, usage, and manifest are immutable');
END;

CREATE TRIGGER trg_metadata_reports_transition_v7
BEFORE UPDATE ON metadata_extraction_reports
WHEN OLD.state <> 'draft' OR NEW.state NOT IN ('sealed', 'abandoned')
BEGIN
    SELECT RAISE(ABORT, 'metadata report only permits one draft-to-terminal transition');
END;

CREATE TRIGGER trg_metadata_reports_seal_guard_v7
BEFORE UPDATE OF state ON metadata_extraction_reports
WHEN NEW.state = 'sealed' AND (
    (SELECT count(*) FROM metadata_extraction_fields AS field
     WHERE field.report_id = NEW.id) <> NEW.expected_field_count
    OR (SELECT count(*) FROM metadata_extraction_issues AS issue
        WHERE issue.report_id = NEW.id) <> NEW.expected_issue_count
    OR COALESCE((SELECT sum(length(field.raw_bytes))
                 FROM metadata_extraction_fields AS field
                 WHERE field.report_id = NEW.id), 0) <> NEW.expected_retained_field_bytes
    OR NOT EXISTS (
        SELECT 1 FROM metadata_source_revalidations AS revalidation
        WHERE revalidation.report_id = NEW.id
          AND revalidation.time_session_id = NEW.time_session_id
          AND revalidation.volume_id = NEW.volume_id
          AND revalidation.scan_run_id = NEW.scan_run_id
          AND revalidation.core_session_id = NEW.core_session_id
          AND revalidation.exact_group_build_id = NEW.exact_group_build_id
          AND revalidation.metadata_probe_observation_id = NEW.metadata_probe_observation_id
          AND revalidation.first_report_digest = NEW.retained_report_digest
          AND revalidation.second_report_digest = NEW.retained_report_digest
          AND revalidation.outcome = 'reextracted_pinned_exact'
    )
    OR NEW.finalized_at_ms < (
        SELECT revalidation.revalidated_at_ms
        FROM metadata_source_revalidations AS revalidation
        WHERE revalidation.report_id = NEW.id
    )
)
BEGIN
    SELECT RAISE(ABORT, 'metadata report cannot seal without complete revalidated evidence');
END;

CREATE TRIGGER trg_metadata_reports_terminal_chronology_v7
BEFORE UPDATE OF state ON metadata_extraction_reports
WHEN NEW.state IN ('sealed', 'abandoned') AND (
    NEW.finalized_at_ms < COALESCE((
        SELECT max(field.created_at_ms)
        FROM metadata_extraction_fields AS field
        WHERE field.report_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(issue.created_at_ms)
        FROM metadata_extraction_issues AS issue
        WHERE issue.report_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(revalidation.revalidated_at_ms)
        FROM metadata_source_revalidations AS revalidation
        WHERE revalidation.report_id = NEW.id
    ), NEW.created_at_ms)
    OR EXISTS (
        SELECT 1 FROM metadata_source_revalidations AS revalidation
        WHERE revalidation.report_id = NEW.id
          AND revalidation.revalidated_at_ms < COALESCE((
              SELECT max(field.created_at_ms)
              FROM metadata_extraction_fields AS field
              WHERE field.report_id = NEW.id
          ), NEW.created_at_ms)
    )
    OR EXISTS (
        SELECT 1 FROM metadata_source_revalidations AS revalidation
        WHERE revalidation.report_id = NEW.id
          AND revalidation.revalidated_at_ms < COALESCE((
              SELECT max(issue.created_at_ms)
              FROM metadata_extraction_issues AS issue
              WHERE issue.report_id = NEW.id
          ), NEW.created_at_ms)
    )
)
BEGIN
    SELECT RAISE(ABORT, 'metadata report terminal time predates retained evidence');
END;

CREATE TRIGGER trg_metadata_reports_no_delete_v7
BEFORE DELETE ON metadata_extraction_reports
BEGIN
    SELECT RAISE(ABORT, 'metadata report evidence cannot be deleted');
END;

CREATE TRIGGER trg_metadata_fields_insert_guard_v7
BEFORE INSERT ON metadata_extraction_fields
WHEN NOT EXISTS (
    SELECT 1 FROM metadata_extraction_reports AS report
    WHERE report.id = NEW.report_id
      AND report.state = 'draft'
      AND NOT EXISTS (
          SELECT 1 FROM metadata_source_revalidations AS revalidation
          WHERE revalidation.report_id = report.id
      )
      AND NEW.ordinal < report.expected_field_count
      AND NEW.created_at_ms >= report.created_at_ms
      AND NEW.byte_len <= report.effective_max_field_bytes
      AND NEW.absolute_offset <= report.source_size_bytes
      AND NEW.byte_len <= report.source_size_bytes - NEW.absolute_offset
      AND COALESCE(NEW.tiff_header_offset, 0) <= report.source_size_bytes
      AND COALESCE(NEW.tiff_ifd_offset, 0) <= report.source_size_bytes
      AND COALESCE(NEW.jpeg_app1_offset, 0) <= report.source_size_bytes
      AND COALESCE(NEW.bmff_box_offset, 0) <= report.source_size_bytes
)
BEGIN
    SELECT RAISE(ABORT, 'metadata field exceeds report bounds or report is terminal');
END;

CREATE TRIGGER trg_metadata_fields_no_update_v7
BEFORE UPDATE ON metadata_extraction_fields
BEGIN
    SELECT RAISE(ABORT, 'metadata field evidence is immutable');
END;

CREATE TRIGGER trg_metadata_fields_no_delete_v7
BEFORE DELETE ON metadata_extraction_fields
BEGIN
    SELECT RAISE(ABORT, 'metadata field evidence cannot be deleted');
END;

CREATE TRIGGER trg_metadata_issues_insert_guard_v7
BEFORE INSERT ON metadata_extraction_issues
WHEN NOT EXISTS (
    SELECT 1 FROM metadata_extraction_reports AS report
    WHERE report.id = NEW.report_id
      AND report.state = 'draft'
      AND NOT EXISTS (
          SELECT 1 FROM metadata_source_revalidations AS revalidation
          WHERE revalidation.report_id = report.id
      )
      AND NEW.ordinal < report.expected_issue_count
      AND NEW.created_at_ms >= report.created_at_ms
      AND (NEW.source_offset IS NULL OR NEW.source_offset <= report.source_size_bytes)
)
BEGIN
    SELECT RAISE(ABORT, 'metadata issue exceeds report bounds or report is terminal');
END;

CREATE TRIGGER trg_metadata_issues_no_update_v7
BEFORE UPDATE ON metadata_extraction_issues
BEGIN
    SELECT RAISE(ABORT, 'metadata issue evidence is immutable');
END;

CREATE TRIGGER trg_metadata_issues_no_delete_v7
BEFORE DELETE ON metadata_extraction_issues
BEGIN
    SELECT RAISE(ABORT, 'metadata issue evidence cannot be deleted');
END;

CREATE TRIGGER trg_metadata_revalidations_insert_guard_v7
BEFORE INSERT ON metadata_source_revalidations
WHEN NOT EXISTS (
    SELECT 1
    FROM metadata_extraction_reports AS report
    JOIN media_observation_snapshots AS observation
      ON observation.id = report.metadata_probe_observation_id
     AND observation.scan_run_id = report.scan_run_id
     AND observation.volume_id = report.volume_id
    JOIN scan_run_sessions AS run_session
      ON run_session.scan_run_id = report.scan_run_id
     AND run_session.volume_id = report.volume_id
    JOIN capability_profiles AS profile
      ON profile.id = run_session.capability_profile_id
     AND profile.volume_id = run_session.volume_id
    WHERE report.id = NEW.report_id
      AND report.state = 'draft'
      AND report.time_session_id = NEW.time_session_id
      AND report.volume_id = NEW.volume_id
      AND report.scan_run_id = NEW.scan_run_id
      AND report.core_session_id = NEW.core_session_id
      AND report.exact_group_build_id = NEW.exact_group_build_id
      AND report.metadata_probe_observation_id = NEW.metadata_probe_observation_id
      AND NEW.source_signature_before = observation.source_signature
      AND NEW.source_signature_after = observation.source_signature
      AND NEW.first_report_digest = report.retained_report_digest
      AND NEW.second_report_digest = report.retained_report_digest
      AND NEW.revalidated_at_ms >= report.created_at_ms
      AND NEW.revalidated_at_ms >= COALESCE((
          SELECT max(field.created_at_ms)
          FROM metadata_extraction_fields AS field
          WHERE field.report_id = report.id
      ), report.created_at_ms)
      AND NEW.revalidated_at_ms >= COALESCE((
          SELECT max(issue.created_at_ms)
          FROM metadata_extraction_issues AS issue
          WHERE issue.report_id = report.id
      ), report.created_at_ms)
      AND (SELECT count(*) FROM metadata_extraction_fields AS field
           WHERE field.report_id = report.id) = report.expected_field_count
      AND (SELECT count(*) FROM metadata_extraction_issues AS issue
           WHERE issue.report_id = report.id) = report.expected_issue_count
      AND COALESCE((SELECT sum(length(field.raw_bytes))
                    FROM metadata_extraction_fields AS field
                    WHERE field.report_id = report.id), 0) =
          report.expected_retained_field_bytes
      AND profile.profile_hash_version = 2
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.is_current = 1
      AND profile.mount_session_key = run_session.mount_session_key COLLATE BINARY
)
BEGIN
    SELECT RAISE(ABORT, 'source revalidation does not reproduce the retained pinned report');
END;

CREATE TRIGGER trg_metadata_revalidations_no_update_v7
BEFORE UPDATE ON metadata_source_revalidations
BEGIN
    SELECT RAISE(ABORT, 'source revalidation proof is immutable');
END;

CREATE TRIGGER trg_metadata_revalidations_no_delete_v7
BEFORE DELETE ON metadata_source_revalidations
BEGIN
    SELECT RAISE(ABORT, 'source revalidation proof cannot be deleted');
END;

CREATE TRIGGER trg_capture_time_builds_insert_guard_v7
BEFORE INSERT ON capture_time_analysis_builds
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_time_sessions AS time_session
    JOIN exact_group_builds AS exact_build
      ON exact_build.id = NEW.exact_group_build_id
     AND exact_build.scan_run_id = NEW.scan_run_id
     AND exact_build.volume_id = NEW.volume_id
     AND exact_build.state = 'verified'
    WHERE time_session.id = NEW.time_session_id
      AND time_session.state = 'draft'
      AND time_session.scan_run_id = NEW.scan_run_id
      AND time_session.volume_id = NEW.volume_id
      AND NEW.expected_member_count = exact_build.expected_member_count
      AND NEW.created_at_ms >= time_session.created_at_ms
      AND NOT EXISTS (
          SELECT 1 FROM capture_time_group_outcomes AS outcome
          WHERE outcome.time_session_id = NEW.time_session_id
            AND outcome.exact_group_build_id = NEW.exact_group_build_id
      )
)
BEGIN
    SELECT RAISE(ABORT, 'time analysis requires a draft session and verified exact group');
END;

CREATE TRIGGER trg_capture_time_builds_immutable_v7
BEFORE UPDATE OF
    id, time_session_id, volume_id, scan_run_id, exact_group_build_id,
    policy_name, policy_version, policy_context_json, policy_context_digest,
    expected_source_count, expected_observation_count, expected_candidate_count,
    expected_issue_count, expected_member_count, expected_recommendation_count,
    manifest_version, expected_manifest_digest, created_at_ms
ON capture_time_analysis_builds
BEGIN
    SELECT RAISE(ABORT, 'time analysis identity, policy, counts, and manifest are immutable');
END;

CREATE TRIGGER trg_capture_time_builds_transition_v7
BEFORE UPDATE ON capture_time_analysis_builds
WHEN OLD.state <> 'draft' OR NEW.state NOT IN ('sealed', 'abandoned')
BEGIN
    SELECT RAISE(ABORT, 'time analysis only permits one draft-to-terminal transition');
END;

CREATE TRIGGER trg_capture_time_builds_seal_guard_v7
BEFORE UPDATE OF state ON capture_time_analysis_builds
WHEN NEW.state = 'sealed' AND (
    (SELECT count(*) FROM capture_time_analysis_sources AS source
     WHERE source.analysis_build_id = NEW.id) <> NEW.expected_source_count
    OR (SELECT count(*) FROM capture_time_observations AS observation
        WHERE observation.analysis_build_id = NEW.id) <> NEW.expected_observation_count
    OR (SELECT count(*) FROM capture_time_candidates AS candidate
        WHERE candidate.analysis_build_id = NEW.id) <> NEW.expected_candidate_count
    OR (SELECT count(*) FROM capture_time_policy_issues AS issue
        WHERE issue.analysis_build_id = NEW.id) <> NEW.expected_issue_count
    OR (SELECT count(*) FROM capture_time_member_assessments AS member
        WHERE member.analysis_build_id = NEW.id) <> NEW.expected_member_count
    OR (SELECT count(*) FROM capture_time_recommendations AS recommendation
        WHERE recommendation.analysis_build_id = NEW.id) <> NEW.expected_recommendation_count
    OR (NEW.selected_candidate_ordinal IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM capture_time_candidates AS candidate
        WHERE candidate.analysis_build_id = NEW.id
          AND candidate.ordinal = NEW.selected_candidate_ordinal
    ))
    OR (NEW.decision = 'evidence_eligible' AND NOT EXISTS (
        SELECT 1 FROM capture_time_candidates AS candidate
        WHERE candidate.analysis_build_id = NEW.id
          AND candidate.ordinal = NEW.selected_candidate_ordinal
          AND candidate.evidence_gate = 'eligible'
    ))
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(source.created_at_ms)
        FROM capture_time_analysis_sources AS source
        WHERE source.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(observation.created_at_ms)
        FROM capture_time_observations AS observation
        WHERE observation.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(candidate.created_at_ms)
        FROM capture_time_candidates AS candidate
        WHERE candidate.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(issue.created_at_ms)
        FROM capture_time_policy_issues AS issue
        WHERE issue.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(member.created_at_ms)
        FROM capture_time_member_assessments AS member
        WHERE member.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(recommendation.created_at_ms)
        FROM capture_time_recommendations AS recommendation
        WHERE recommendation.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
)
BEGIN
    SELECT RAISE(ABORT, 'time analysis cannot seal with incomplete or ineligible evidence');
END;

CREATE TRIGGER trg_capture_time_builds_terminal_chronology_v7
BEFORE UPDATE OF state ON capture_time_analysis_builds
WHEN NEW.state IN ('sealed', 'abandoned') AND (
    NEW.finalized_at_ms < COALESCE((
        SELECT max(source.created_at_ms)
        FROM capture_time_analysis_sources AS source
        WHERE source.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(observation.created_at_ms)
        FROM capture_time_observations AS observation
        WHERE observation.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(candidate.created_at_ms)
        FROM capture_time_candidates AS candidate
        WHERE candidate.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(issue.created_at_ms)
        FROM capture_time_policy_issues AS issue
        WHERE issue.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(member.created_at_ms)
        FROM capture_time_member_assessments AS member
        WHERE member.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
    OR NEW.finalized_at_ms < COALESCE((
        SELECT max(recommendation.created_at_ms)
        FROM capture_time_recommendations AS recommendation
        WHERE recommendation.analysis_build_id = NEW.id
    ), NEW.created_at_ms)
)
BEGIN
    SELECT RAISE(ABORT, 'time analysis terminal time predates retained child evidence');
END;

CREATE TRIGGER trg_capture_time_builds_no_delete_v7
BEFORE DELETE ON capture_time_analysis_builds
BEGIN
    SELECT RAISE(ABORT, 'time analysis evidence cannot be deleted');
END;

CREATE TRIGGER trg_capture_time_sources_insert_guard_v7
BEFORE INSERT ON capture_time_analysis_sources
WHEN NOT EXISTS (
    SELECT 1
    FROM capture_time_analysis_builds AS build
    JOIN metadata_extraction_reports AS report
      ON report.id = NEW.report_id
     AND report.time_session_id = build.time_session_id
     AND report.exact_group_build_id = build.exact_group_build_id
     AND report.state = 'sealed'
    JOIN metadata_source_revalidations AS revalidation
      ON revalidation.report_id = report.id
     AND revalidation.source_key = NEW.source_key
     AND revalidation.lineage_key = NEW.lineage_key
    WHERE build.id = NEW.analysis_build_id
      AND build.state = 'draft'
      AND NEW.ordinal < build.expected_source_count
      AND NEW.created_at_ms >= build.created_at_ms
      AND NEW.created_at_ms >= report.finalized_at_ms
      AND report.expected_retained_field_bytes <= 33554432 - COALESCE((
          SELECT sum(existing_report.expected_retained_field_bytes)
          FROM capture_time_analysis_sources AS existing_source
          JOIN metadata_extraction_reports AS existing_report
            ON existing_report.id = existing_source.report_id
          WHERE existing_source.analysis_build_id = NEW.analysis_build_id
      ), 0)
      AND report.expected_issue_count <= 8192 - COALESCE((
          SELECT sum(existing_report.expected_issue_count)
          FROM capture_time_analysis_sources AS existing_source
          JOIN metadata_extraction_reports AS existing_report
            ON existing_report.id = existing_source.report_id
          WHERE existing_source.analysis_build_id = NEW.analysis_build_id
      ), 0)
      AND COALESCE((
          SELECT sum(length(field.bmff_box_path) / 4)
          FROM metadata_extraction_fields AS field
          WHERE field.report_id = NEW.report_id
      ), 0) <= 49152 - COALESCE((
          SELECT sum(length(field.bmff_box_path) / 4)
          FROM capture_time_analysis_sources AS existing_source
          JOIN metadata_extraction_fields AS field
            ON field.report_id = existing_source.report_id
          WHERE existing_source.analysis_build_id = NEW.analysis_build_id
      ), 0)
)
BEGIN
    SELECT RAISE(ABORT, 'analysis source lacks a sealed source-revalidated report');
END;

CREATE TRIGGER trg_capture_time_sources_no_update_v7
BEFORE UPDATE ON capture_time_analysis_sources
BEGIN
    SELECT RAISE(ABORT, 'time analysis source is immutable');
END;

CREATE TRIGGER trg_capture_time_sources_no_delete_v7
BEFORE DELETE ON capture_time_analysis_sources
BEGIN
    SELECT RAISE(ABORT, 'time analysis source cannot be deleted');
END;

CREATE TRIGGER trg_capture_time_observations_insert_guard_v7
BEFORE INSERT ON capture_time_observations
WHEN NOT EXISTS (
    SELECT 1 FROM capture_time_analysis_builds AS build
    WHERE build.id = NEW.analysis_build_id
      AND build.state = 'draft'
      AND NEW.ordinal < build.expected_observation_count
      AND NEW.created_at_ms >= build.created_at_ms
)
BEGIN
    SELECT RAISE(ABORT, 'time observation exceeds its draft analysis');
END;

CREATE TRIGGER trg_capture_time_observations_no_update_v7
BEFORE UPDATE ON capture_time_observations
BEGIN
    SELECT RAISE(ABORT, 'time observation is immutable');
END;

CREATE TRIGGER trg_capture_time_observations_no_delete_v7
BEFORE DELETE ON capture_time_observations
BEGIN
    SELECT RAISE(ABORT, 'time observation cannot be deleted');
END;

CREATE TRIGGER trg_capture_time_candidates_insert_guard_v7
BEFORE INSERT ON capture_time_candidates
WHEN NOT EXISTS (
    SELECT 1 FROM capture_time_analysis_builds AS build
    WHERE build.id = NEW.analysis_build_id
      AND build.state = 'draft'
      AND NEW.ordinal < build.expected_candidate_count
      AND NEW.created_at_ms >= build.created_at_ms
      AND length(CAST(build.policy_context_json AS BLOB))
          + length(CAST(NEW.evidence_kinds_json AS BLOB))
          + length(CAST(NEW.source_keys_json AS BLOB))
          + length(CAST(NEW.lineage_keys_json AS BLOB))
          + length(CAST(NEW.observation_ordinals_json AS BLOB))
          + length(CAST(NEW.anomalies_json AS BLOB))
          + length(CAST(NEW.blockers_json AS BLOB))
          <= 16777216 - COALESCE((
              SELECT sum(
                  length(CAST(candidate.evidence_kinds_json AS BLOB))
                  + length(CAST(candidate.source_keys_json AS BLOB))
                  + length(CAST(candidate.lineage_keys_json AS BLOB))
                  + length(CAST(candidate.observation_ordinals_json AS BLOB))
                  + length(CAST(candidate.anomalies_json AS BLOB))
                  + length(CAST(candidate.blockers_json AS BLOB))
              )
              FROM capture_time_candidates AS candidate
              WHERE candidate.analysis_build_id = NEW.analysis_build_id
          ), 0) - COALESCE((
              SELECT sum(
                  length(CAST(issue.observation_ordinals_json AS BLOB))
                  + length(CAST(issue.source_keys_json AS BLOB))
                  + length(CAST(issue.lineage_keys_json AS BLOB))
                  + length(CAST(issue.context AS BLOB))
              )
              FROM capture_time_policy_issues AS issue
              WHERE issue.analysis_build_id = NEW.analysis_build_id
          ), 0)
      AND NOT EXISTS (
          SELECT 1 FROM json_each(NEW.evidence_kinds_json) AS item
          WHERE item.type <> 'text' OR item.value NOT IN (
              'exif_date_time_original', 'exif_create_date', 'exif_modify_date',
              'quicktime_metadata_creation_date',
              'quicktime_movie_header_creation_time'
          )
      )
      AND NOT EXISTS (
          SELECT 1 FROM json_each(NEW.anomalies_json) AS item
          WHERE item.type <> 'text' OR item.value NOT IN (
              'missing_offset', 'sentinel_value', 'obvious_future',
              'outside_automatic_range', 'quicktime_epoch_semantic_uncertainty',
              'invalid_companion'
          )
      )
      AND NOT EXISTS (
          SELECT 1 FROM json_each(NEW.blockers_json) AS item
          WHERE item.type <> 'text' OR item.value NOT IN (
              'confidence_below_high', 'no_utc_instant', 'evidence_conflict',
              'sentinel_value', 'obvious_future', 'outside_automatic_range',
              'quicktime_epoch_semantic_uncertainty', 'invalid_evidence_present',
              'extraction_report_untrusted', 'source_not_revalidated',
              'multiple_strong_values_within_tolerance'
          )
      )
      AND NOT EXISTS (
          SELECT 1 FROM json_each(NEW.source_keys_json) AS item
          WHERE item.type <> 'text'
             OR length(item.value) <> 64
             OR item.value GLOB '*[^0-9a-f]*'
             OR NOT EXISTS (
                 SELECT 1 FROM capture_time_analysis_sources AS source
                 WHERE source.analysis_build_id = NEW.analysis_build_id
                   AND lower(hex(source.source_key)) = item.value
             )
      )
      AND NOT EXISTS (
          SELECT 1 FROM json_each(NEW.lineage_keys_json) AS item
          WHERE item.type <> 'text'
             OR length(item.value) <> 64
             OR item.value GLOB '*[^0-9a-f]*'
             OR NOT EXISTS (
                 SELECT 1 FROM capture_time_analysis_sources AS source
                 WHERE source.analysis_build_id = NEW.analysis_build_id
                   AND lower(hex(source.lineage_key)) = item.value
             )
      )
      AND NOT EXISTS (
          SELECT 1 FROM json_each(NEW.observation_ordinals_json) AS item
          WHERE item.type <> 'integer'
             OR item.value < 0
             OR NOT EXISTS (
                 SELECT 1 FROM capture_time_observations AS observation
                 WHERE observation.analysis_build_id = NEW.analysis_build_id
                   AND observation.ordinal = item.value
             )
      )
      AND (
          NEW.evidence_gate <> 'eligible'
          OR (
              NEW.offset_kind = 'explicit'
              AND EXISTS (
                  SELECT 1 FROM json_each(NEW.evidence_kinds_json) AS evidence_kind
                  WHERE evidence_kind.type = 'text'
                    AND evidence_kind.value = 'exif_date_time_original'
              )
              AND NOT EXISTS (
                  SELECT 1 FROM json_each(NEW.observation_ordinals_json) AS item
                  WHERE NOT EXISTS (
                      SELECT 1
                      FROM capture_time_observations AS observation
                      JOIN capture_time_analysis_sources AS source
                        ON source.analysis_build_id = observation.analysis_build_id
                       AND source.ordinal = observation.source_ordinal
                       AND source.report_id = observation.report_id
                      JOIN capture_time_analysis_builds AS support_build
                        ON support_build.id = observation.analysis_build_id
                      JOIN metadata_extraction_reports AS report
                        ON report.id = source.report_id
                       AND report.time_session_id = support_build.time_session_id
                       AND report.exact_group_build_id = support_build.exact_group_build_id
                       AND report.volume_id = support_build.volume_id
                       AND report.scan_run_id = support_build.scan_run_id
                       AND report.state = 'sealed'
                       AND report.extraction_status = 'extracted_unvalidated'
                       AND report.expected_issue_count = 0
                      JOIN metadata_source_revalidations AS revalidation
                        ON revalidation.report_id = report.id
                       AND revalidation.time_session_id = report.time_session_id
                       AND revalidation.exact_group_build_id = report.exact_group_build_id
                       AND revalidation.metadata_probe_observation_id =
                           report.metadata_probe_observation_id
                       AND revalidation.source_key = source.source_key
                       AND revalidation.lineage_key = source.lineage_key
                       AND revalidation.outcome = 'reextracted_pinned_exact'
                       AND revalidation.descriptor_revalidated = 1
                       AND revalidation.path_revalidated = 1
                       AND revalidation.session_revalidated = 1
                      JOIN metadata_extraction_fields AS field
                        ON field.id = observation.metadata_field_id
                       AND field.report_id = observation.report_id
                      WHERE observation.analysis_build_id = NEW.analysis_build_id
                        AND observation.ordinal = item.value
                        AND NOT EXISTS (
                            SELECT 1 FROM metadata_extraction_issues AS issue
                            WHERE issue.report_id = report.id
                        )
                        AND (
                            (observation.interpretation_kind = 'timestamp'
                             AND field.field_kind IN (
                                 'exif_date_time_original', 'exif_create_date',
                                 'exif_modify_date', 'quicktime_metadata_creation_date',
                                 'quicktime_movie_header_creation_time'
                             ))
                            OR (observation.interpretation_kind = 'offset'
                                AND field.field_kind = 'exif_offset_time_original'
                                AND observation.parsed_offset_minutes IS
                                        NEW.utc_offset_minutes
                                AND EXISTS (
                                    SELECT 1
                                    FROM json_each(NEW.observation_ordinals_json) AS timestamp_item
                                    JOIN capture_time_observations AS timestamp_observation
                                      ON timestamp_observation.analysis_build_id =
                                             NEW.analysis_build_id
                                     AND timestamp_observation.ordinal = timestamp_item.value
                                     AND timestamp_observation.source_ordinal =
                                             observation.source_ordinal
                                     AND timestamp_observation.interpretation_kind = 'timestamp'
                                ))
                            OR (observation.interpretation_kind = 'subsecond'
                                AND field.field_kind = 'exif_subsec_time_original'
                                AND observation.subsecond_nanosecond = NEW.wall_nanosecond
                                AND observation.subsecond_precision_ns = NEW.precision_ns
                                AND EXISTS (
                                    SELECT 1
                                    FROM json_each(NEW.observation_ordinals_json) AS timestamp_item
                                    JOIN capture_time_observations AS timestamp_observation
                                      ON timestamp_observation.analysis_build_id =
                                             NEW.analysis_build_id
                                     AND timestamp_observation.ordinal = timestamp_item.value
                                     AND timestamp_observation.source_ordinal =
                                             observation.source_ordinal
                                     AND timestamp_observation.interpretation_kind = 'timestamp'
                                ))
                        )
                  )
              )
              AND EXISTS (
                  SELECT 1
                  FROM json_each(NEW.observation_ordinals_json) AS timestamp_item
                  JOIN capture_time_observations AS timestamp_observation
                    ON timestamp_observation.analysis_build_id = NEW.analysis_build_id
                   AND timestamp_observation.ordinal = timestamp_item.value
                  JOIN metadata_extraction_fields AS timestamp_field
                    ON timestamp_field.id = timestamp_observation.metadata_field_id
                   AND timestamp_field.report_id = timestamp_observation.report_id
                  JOIN json_each(NEW.observation_ordinals_json) AS offset_item
                  JOIN capture_time_observations AS offset_observation
                    ON offset_observation.analysis_build_id = NEW.analysis_build_id
                   AND offset_observation.ordinal = offset_item.value
                   AND offset_observation.source_ordinal =
                           timestamp_observation.source_ordinal
                   AND offset_observation.report_id = timestamp_observation.report_id
                  JOIN metadata_extraction_fields AS offset_field
                    ON offset_field.id = offset_observation.metadata_field_id
                   AND offset_field.report_id = offset_observation.report_id
                  WHERE timestamp_observation.interpretation_kind = 'timestamp'
                    AND timestamp_field.field_kind = 'exif_date_time_original'
                    AND timestamp_field.container_kind IN ('tiff', 'jpeg_exif')
                    AND timestamp_observation.semantic_kind = 'floating'
                    AND timestamp_observation.offset_kind = 'missing'
                    AND timestamp_observation.utc_offset_minutes IS NULL
                    AND timestamp_observation.utc_seconds_decimal IS NULL
                    AND timestamp_observation.utc_nanoseconds IS NULL
                    AND timestamp_observation.wall_year = NEW.wall_year
                    AND timestamp_observation.wall_month = NEW.wall_month
                    AND timestamp_observation.wall_day = NEW.wall_day
                    AND timestamp_observation.wall_hour = NEW.wall_hour
                    AND timestamp_observation.wall_minute = NEW.wall_minute
                    AND timestamp_observation.wall_second = NEW.wall_second
                    AND offset_observation.interpretation_kind = 'offset'
                    AND offset_observation.parsed_offset_minutes IS NEW.utc_offset_minutes
                    AND offset_field.field_kind = 'exif_offset_time_original'
                    AND offset_field.container_kind = timestamp_field.container_kind
                    AND offset_field.tiff_header_offset = timestamp_field.tiff_header_offset
                    AND offset_field.tiff_ifd_offset = timestamp_field.tiff_ifd_offset
                    AND offset_field.jpeg_app1_offset IS timestamp_field.jpeg_app1_offset
                    AND (
                        (timestamp_observation.wall_nanosecond = NEW.wall_nanosecond
                         AND timestamp_observation.normalized_precision_ns = NEW.precision_ns)
                        OR EXISTS (
                            SELECT 1
                            FROM json_each(NEW.observation_ordinals_json) AS subsecond_item
                            JOIN capture_time_observations AS subsecond_observation
                              ON subsecond_observation.analysis_build_id = NEW.analysis_build_id
                             AND subsecond_observation.ordinal = subsecond_item.value
                             AND subsecond_observation.source_ordinal =
                                     timestamp_observation.source_ordinal
                             AND subsecond_observation.report_id =
                                     timestamp_observation.report_id
                            JOIN metadata_extraction_fields AS subsecond_field
                              ON subsecond_field.id = subsecond_observation.metadata_field_id
                             AND subsecond_field.report_id = subsecond_observation.report_id
                            WHERE subsecond_observation.interpretation_kind = 'subsecond'
                              AND subsecond_observation.subsecond_nanosecond =
                                      NEW.wall_nanosecond
                              AND subsecond_observation.subsecond_precision_ns = NEW.precision_ns
                              AND subsecond_field.field_kind = 'exif_subsec_time_original'
                              AND subsecond_field.container_kind = timestamp_field.container_kind
                              AND subsecond_field.tiff_header_offset =
                                      timestamp_field.tiff_header_offset
                              AND subsecond_field.tiff_ifd_offset =
                                      timestamp_field.tiff_ifd_offset
                              AND subsecond_field.jpeg_app1_offset IS
                                      timestamp_field.jpeg_app1_offset
                        )
                    )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(NEW.observation_ordinals_json) AS timestamp_item
                  JOIN capture_time_observations AS timestamp_observation
                    ON timestamp_observation.analysis_build_id = NEW.analysis_build_id
                   AND timestamp_observation.ordinal = timestamp_item.value
                   AND timestamp_observation.interpretation_kind = 'timestamp'
                  JOIN metadata_extraction_fields AS timestamp_field
                    ON timestamp_field.id = timestamp_observation.metadata_field_id
                   AND timestamp_field.report_id = timestamp_observation.report_id
                  WHERE timestamp_field.field_kind = 'exif_date_time_original'
                    AND NOT (
                        timestamp_field.container_kind IN ('tiff', 'jpeg_exif')
                        AND timestamp_observation.semantic_kind = 'floating'
                        AND timestamp_observation.offset_kind = 'missing'
                        AND timestamp_observation.utc_offset_minutes IS NULL
                        AND timestamp_observation.utc_seconds_decimal IS NULL
                        AND timestamp_observation.utc_nanoseconds IS NULL
                        AND timestamp_observation.wall_year = NEW.wall_year
                        AND timestamp_observation.wall_month = NEW.wall_month
                        AND timestamp_observation.wall_day = NEW.wall_day
                        AND timestamp_observation.wall_hour = NEW.wall_hour
                        AND timestamp_observation.wall_minute = NEW.wall_minute
                        AND timestamp_observation.wall_second = NEW.wall_second
                        AND EXISTS (
                            SELECT 1
                            FROM json_each(NEW.observation_ordinals_json) AS offset_item
                            JOIN capture_time_observations AS offset_observation
                              ON offset_observation.analysis_build_id = NEW.analysis_build_id
                             AND offset_observation.ordinal = offset_item.value
                             AND offset_observation.source_ordinal =
                                     timestamp_observation.source_ordinal
                             AND offset_observation.report_id =
                                     timestamp_observation.report_id
                            JOIN metadata_extraction_fields AS offset_field
                              ON offset_field.id = offset_observation.metadata_field_id
                             AND offset_field.report_id = offset_observation.report_id
                            WHERE offset_observation.interpretation_kind = 'offset'
                              AND offset_observation.parsed_offset_minutes IS
                                      NEW.utc_offset_minutes
                              AND offset_field.field_kind = 'exif_offset_time_original'
                              AND offset_field.container_kind = timestamp_field.container_kind
                              AND offset_field.tiff_header_offset =
                                      timestamp_field.tiff_header_offset
                              AND offset_field.tiff_ifd_offset =
                                      timestamp_field.tiff_ifd_offset
                              AND offset_field.jpeg_app1_offset IS
                                      timestamp_field.jpeg_app1_offset
                        )
                        AND (
                            (timestamp_observation.wall_nanosecond = NEW.wall_nanosecond
                             AND timestamp_observation.normalized_precision_ns =
                                    NEW.precision_ns)
                            OR EXISTS (
                                SELECT 1
                                FROM json_each(NEW.observation_ordinals_json) AS subsecond_item
                                JOIN capture_time_observations AS subsecond_observation
                                  ON subsecond_observation.analysis_build_id =
                                         NEW.analysis_build_id
                                 AND subsecond_observation.ordinal = subsecond_item.value
                                 AND subsecond_observation.source_ordinal =
                                         timestamp_observation.source_ordinal
                                 AND subsecond_observation.report_id =
                                         timestamp_observation.report_id
                                JOIN metadata_extraction_fields AS subsecond_field
                                  ON subsecond_field.id =
                                         subsecond_observation.metadata_field_id
                                 AND subsecond_field.report_id =
                                         subsecond_observation.report_id
                                WHERE subsecond_observation.interpretation_kind = 'subsecond'
                                  AND subsecond_observation.subsecond_nanosecond =
                                          NEW.wall_nanosecond
                                  AND subsecond_observation.subsecond_precision_ns =
                                          NEW.precision_ns
                                  AND subsecond_field.field_kind =
                                          'exif_subsec_time_original'
                                  AND subsecond_field.container_kind =
                                          timestamp_field.container_kind
                                  AND subsecond_field.tiff_header_offset =
                                          timestamp_field.tiff_header_offset
                                  AND subsecond_field.tiff_ifd_offset =
                                          timestamp_field.tiff_ifd_offset
                                  AND subsecond_field.jpeg_app1_offset IS
                                          timestamp_field.jpeg_app1_offset
                            )
                        )
                    )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(NEW.observation_ordinals_json) AS item
                  JOIN capture_time_observations AS observation
                    ON observation.analysis_build_id = NEW.analysis_build_id
                   AND observation.ordinal = item.value
                   AND observation.interpretation_kind = 'timestamp'
                  JOIN metadata_extraction_fields AS field
                    ON field.id = observation.metadata_field_id
                   AND field.report_id = observation.report_id
                  WHERE field.field_kind <> 'exif_date_time_original'
                    AND NOT (
                        observation.wall_year = NEW.wall_year
                        AND observation.wall_month = NEW.wall_month
                        AND observation.wall_day = NEW.wall_day
                        AND observation.wall_hour = NEW.wall_hour
                        AND observation.wall_minute = NEW.wall_minute
                        AND observation.wall_second = NEW.wall_second
                        AND observation.wall_nanosecond = NEW.wall_nanosecond
                        AND observation.semantic_kind = NEW.semantic_kind
                        AND observation.offset_kind = NEW.offset_kind
                        AND observation.utc_offset_minutes IS NEW.utc_offset_minutes
                        AND observation.utc_seconds_decimal IS NEW.utc_seconds_decimal
                        AND observation.utc_nanoseconds IS NEW.utc_nanoseconds
                        AND observation.normalized_precision_ns = NEW.precision_ns
                    )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(NEW.observation_ordinals_json) AS companion_item
                  JOIN capture_time_observations AS companion_observation
                    ON companion_observation.analysis_build_id = NEW.analysis_build_id
                   AND companion_observation.ordinal = companion_item.value
                  JOIN metadata_extraction_fields AS companion_field
                    ON companion_field.id = companion_observation.metadata_field_id
                   AND companion_field.report_id = companion_observation.report_id
                  WHERE companion_observation.interpretation_kind IN ('offset', 'subsecond')
                    AND (
                        (companion_observation.interpretation_kind = 'offset'
                         AND (
                             companion_field.field_kind <> 'exif_offset_time_original'
                             OR companion_observation.parsed_offset_minutes IS NOT
                                    NEW.utc_offset_minutes
                         ))
                        OR
                        (companion_observation.interpretation_kind = 'subsecond'
                         AND (
                             companion_field.field_kind <> 'exif_subsec_time_original'
                             OR companion_observation.subsecond_nanosecond <>
                                    NEW.wall_nanosecond
                             OR companion_observation.subsecond_precision_ns <>
                                    NEW.precision_ns
                         ))
                        OR NOT EXISTS (
                            SELECT 1
                            FROM json_each(NEW.observation_ordinals_json) AS timestamp_item
                            JOIN capture_time_observations AS timestamp_observation
                              ON timestamp_observation.analysis_build_id = NEW.analysis_build_id
                             AND timestamp_observation.ordinal = timestamp_item.value
                             AND timestamp_observation.source_ordinal =
                                     companion_observation.source_ordinal
                             AND timestamp_observation.report_id =
                                     companion_observation.report_id
                            JOIN metadata_extraction_fields AS timestamp_field
                              ON timestamp_field.id = timestamp_observation.metadata_field_id
                             AND timestamp_field.report_id = timestamp_observation.report_id
                            WHERE timestamp_observation.interpretation_kind = 'timestamp'
                              AND timestamp_observation.semantic_kind = 'floating'
                              AND timestamp_observation.offset_kind = 'missing'
                              AND timestamp_field.field_kind = 'exif_date_time_original'
                              AND timestamp_field.container_kind IN ('tiff', 'jpeg_exif')
                              AND timestamp_field.container_kind = companion_field.container_kind
                              AND timestamp_field.tiff_header_offset =
                                      companion_field.tiff_header_offset
                              AND timestamp_field.tiff_ifd_offset =
                                      companion_field.tiff_ifd_offset
                              AND timestamp_field.jpeg_app1_offset IS
                                      companion_field.jpeg_app1_offset
                        )
                    )
              )
              AND NOT EXISTS (
                  SELECT 1 FROM json_each(NEW.source_keys_json) AS declared
                  WHERE NOT EXISTS (
                      SELECT 1
                      FROM json_each(NEW.observation_ordinals_json) AS item
                      JOIN capture_time_observations AS observation
                        ON observation.analysis_build_id = NEW.analysis_build_id
                       AND observation.ordinal = item.value
                      JOIN capture_time_analysis_sources AS source
                        ON source.analysis_build_id = observation.analysis_build_id
                       AND source.ordinal = observation.source_ordinal
                      WHERE lower(hex(source.source_key)) = declared.value
                  )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(NEW.observation_ordinals_json) AS item
                  JOIN capture_time_observations AS observation
                    ON observation.analysis_build_id = NEW.analysis_build_id
                   AND observation.ordinal = item.value
                  JOIN capture_time_analysis_sources AS source
                    ON source.analysis_build_id = observation.analysis_build_id
                   AND source.ordinal = observation.source_ordinal
                  WHERE NOT EXISTS (
                      SELECT 1 FROM json_each(NEW.source_keys_json) AS declared
                      WHERE declared.value = lower(hex(source.source_key))
                  )
              )
              AND NOT EXISTS (
                  SELECT 1 FROM json_each(NEW.lineage_keys_json) AS declared
                  WHERE NOT EXISTS (
                      SELECT 1
                      FROM json_each(NEW.observation_ordinals_json) AS item
                      JOIN capture_time_observations AS observation
                        ON observation.analysis_build_id = NEW.analysis_build_id
                       AND observation.ordinal = item.value
                      JOIN capture_time_analysis_sources AS source
                        ON source.analysis_build_id = observation.analysis_build_id
                       AND source.ordinal = observation.source_ordinal
                      WHERE lower(hex(source.lineage_key)) = declared.value
                  )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(NEW.observation_ordinals_json) AS item
                  JOIN capture_time_observations AS observation
                    ON observation.analysis_build_id = NEW.analysis_build_id
                   AND observation.ordinal = item.value
                  JOIN capture_time_analysis_sources AS source
                    ON source.analysis_build_id = observation.analysis_build_id
                   AND source.ordinal = observation.source_ordinal
                  WHERE NOT EXISTS (
                      SELECT 1 FROM json_each(NEW.lineage_keys_json) AS declared
                      WHERE declared.value = lower(hex(source.lineage_key))
                  )
              )
              AND NOT EXISTS (
                  SELECT 1 FROM json_each(NEW.evidence_kinds_json) AS declared
                  WHERE NOT EXISTS (
                      SELECT 1
                      FROM json_each(NEW.observation_ordinals_json) AS item
                      JOIN capture_time_observations AS observation
                        ON observation.analysis_build_id = NEW.analysis_build_id
                       AND observation.ordinal = item.value
                       AND observation.interpretation_kind = 'timestamp'
                      JOIN metadata_extraction_fields AS field
                        ON field.id = observation.metadata_field_id
                       AND field.report_id = observation.report_id
                      WHERE field.field_kind = declared.value
                  )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(NEW.observation_ordinals_json) AS item
                  JOIN capture_time_observations AS observation
                    ON observation.analysis_build_id = NEW.analysis_build_id
                   AND observation.ordinal = item.value
                   AND observation.interpretation_kind = 'timestamp'
                  JOIN metadata_extraction_fields AS field
                    ON field.id = observation.metadata_field_id
                   AND field.report_id = observation.report_id
                  WHERE NOT EXISTS (
                      SELECT 1 FROM json_each(NEW.evidence_kinds_json) AS declared
                      WHERE declared.value = field.field_kind
                  )
              )
              AND EXISTS (
                  SELECT 1
                  FROM json_each(NEW.observation_ordinals_json) AS item
                  JOIN capture_time_observations AS observation
                    ON observation.analysis_build_id = NEW.analysis_build_id
                   AND observation.ordinal = item.value
                   AND observation.interpretation_kind = 'timestamp'
                  WHERE observation.wall_year = NEW.wall_year
                    AND observation.wall_month = NEW.wall_month
                    AND observation.wall_day = NEW.wall_day
                    AND observation.wall_hour = NEW.wall_hour
                    AND observation.wall_minute = NEW.wall_minute
                    AND observation.wall_second = NEW.wall_second
                    AND (
                        (
                            observation.wall_nanosecond = NEW.wall_nanosecond
                            AND observation.semantic_kind = NEW.semantic_kind
                            AND observation.offset_kind = NEW.offset_kind
                            AND observation.utc_offset_minutes IS NEW.utc_offset_minutes
                            AND observation.utc_seconds_decimal IS NEW.utc_seconds_decimal
                            AND observation.utc_nanoseconds IS NEW.utc_nanoseconds
                            AND observation.normalized_precision_ns = NEW.precision_ns
                        )
                        OR (
                            NEW.semantic_kind = 'utc'
                            AND NEW.offset_kind = 'explicit'
                            AND observation.semantic_kind = 'floating'
                            AND observation.offset_kind = 'missing'
                            AND observation.utc_offset_minutes IS NULL
                            AND observation.utc_seconds_decimal IS NULL
                            AND observation.utc_nanoseconds IS NULL
                            AND EXISTS (
                                SELECT 1
                                FROM json_each(NEW.observation_ordinals_json) AS offset_item
                                JOIN capture_time_observations AS offset_observation
                                  ON offset_observation.analysis_build_id =
                                         NEW.analysis_build_id
                                 AND offset_observation.ordinal = offset_item.value
                                 AND offset_observation.source_ordinal =
                                         observation.source_ordinal
                                 AND offset_observation.interpretation_kind = 'offset'
                                 AND offset_observation.parsed_offset_minutes IS
                                         NEW.utc_offset_minutes
                            )
                            AND (
                                (
                                    observation.wall_nanosecond = NEW.wall_nanosecond
                                    AND observation.normalized_precision_ns = NEW.precision_ns
                                )
                                OR EXISTS (
                                    SELECT 1
                                    FROM json_each(NEW.observation_ordinals_json) AS subsecond_item
                                    JOIN capture_time_observations AS subsecond_observation
                                      ON subsecond_observation.analysis_build_id =
                                             NEW.analysis_build_id
                                     AND subsecond_observation.ordinal = subsecond_item.value
                                     AND subsecond_observation.source_ordinal =
                                             observation.source_ordinal
                                     AND subsecond_observation.interpretation_kind = 'subsecond'
                                     AND subsecond_observation.subsecond_nanosecond =
                                             NEW.wall_nanosecond
                                     AND subsecond_observation.subsecond_precision_ns =
                                             NEW.precision_ns
                                )
                            )
                        )
                    )
              )
          )
      )
      AND NOT EXISTS (
          SELECT 1 FROM (
              SELECT item.value FROM json_each(NEW.evidence_kinds_json) AS item
              GROUP BY item.value HAVING count(*) > 1
              UNION ALL
              SELECT item.value FROM json_each(NEW.source_keys_json) AS item
              GROUP BY item.value HAVING count(*) > 1
              UNION ALL
              SELECT item.value FROM json_each(NEW.lineage_keys_json) AS item
              GROUP BY item.value HAVING count(*) > 1
              UNION ALL
              SELECT item.value FROM json_each(NEW.observation_ordinals_json) AS item
              GROUP BY item.value HAVING count(*) > 1
              UNION ALL
              SELECT item.value FROM json_each(NEW.anomalies_json) AS item
              GROUP BY item.value HAVING count(*) > 1
              UNION ALL
              SELECT item.value FROM json_each(NEW.blockers_json) AS item
              GROUP BY item.value HAVING count(*) > 1
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'time candidate exceeds its draft analysis or references invalid support');
END;

CREATE TRIGGER trg_capture_time_candidates_no_update_v7
BEFORE UPDATE ON capture_time_candidates
BEGIN
    SELECT RAISE(ABORT, 'time candidate evidence is immutable');
END;

CREATE TRIGGER trg_capture_time_candidates_no_delete_v7
BEFORE DELETE ON capture_time_candidates
BEGIN
    SELECT RAISE(ABORT, 'time candidate evidence cannot be deleted');
END;

CREATE TRIGGER trg_capture_time_policy_issues_insert_guard_v7
BEFORE INSERT ON capture_time_policy_issues
WHEN NOT EXISTS (
    SELECT 1 FROM capture_time_analysis_builds AS build
    WHERE build.id = NEW.analysis_build_id
      AND build.state = 'draft'
      AND NEW.ordinal < build.expected_issue_count
      AND NEW.created_at_ms >= build.created_at_ms
      AND length(CAST(build.policy_context_json AS BLOB))
          + length(CAST(NEW.observation_ordinals_json AS BLOB))
          + length(CAST(NEW.source_keys_json AS BLOB))
          + length(CAST(NEW.lineage_keys_json AS BLOB))
          + length(CAST(NEW.context AS BLOB))
          <= 16777216 - COALESCE((
              SELECT sum(
                  length(CAST(candidate.evidence_kinds_json AS BLOB))
                  + length(CAST(candidate.source_keys_json AS BLOB))
                  + length(CAST(candidate.lineage_keys_json AS BLOB))
                  + length(CAST(candidate.observation_ordinals_json AS BLOB))
                  + length(CAST(candidate.anomalies_json AS BLOB))
                  + length(CAST(candidate.blockers_json AS BLOB))
              )
              FROM capture_time_candidates AS candidate
              WHERE candidate.analysis_build_id = NEW.analysis_build_id
          ), 0) - COALESCE((
              SELECT sum(
                  length(CAST(issue.observation_ordinals_json AS BLOB))
                  + length(CAST(issue.source_keys_json AS BLOB))
                  + length(CAST(issue.lineage_keys_json AS BLOB))
                  + length(CAST(issue.context AS BLOB))
              )
              FROM capture_time_policy_issues AS issue
              WHERE issue.analysis_build_id = NEW.analysis_build_id
          ), 0)
      AND NOT EXISTS (
          SELECT 1 FROM json_each(NEW.source_keys_json) AS item
          WHERE item.type <> 'text'
             OR length(item.value) <> 64
             OR item.value GLOB '*[^0-9a-f]*'
             OR NOT EXISTS (
                 SELECT 1 FROM capture_time_analysis_sources AS source
                 WHERE source.analysis_build_id = NEW.analysis_build_id
                   AND lower(hex(source.source_key)) = item.value
             )
      )
      AND NOT EXISTS (
          SELECT 1 FROM json_each(NEW.lineage_keys_json) AS item
          WHERE item.type <> 'text'
             OR length(item.value) <> 64
             OR item.value GLOB '*[^0-9a-f]*'
             OR NOT EXISTS (
                 SELECT 1 FROM capture_time_analysis_sources AS source
                 WHERE source.analysis_build_id = NEW.analysis_build_id
                   AND lower(hex(source.lineage_key)) = item.value
             )
      )
      AND NOT EXISTS (
          SELECT 1 FROM json_each(NEW.observation_ordinals_json) AS item
          WHERE item.type <> 'integer'
             OR item.value < 0
             OR NOT EXISTS (
                 SELECT 1 FROM capture_time_observations AS observation
                 WHERE observation.analysis_build_id = NEW.analysis_build_id
                   AND observation.ordinal = item.value
             )
      )
      AND NOT EXISTS (
          SELECT 1 FROM (
              SELECT item.value FROM json_each(NEW.source_keys_json) AS item
              GROUP BY item.value HAVING count(*) > 1
              UNION ALL
              SELECT item.value FROM json_each(NEW.lineage_keys_json) AS item
              GROUP BY item.value HAVING count(*) > 1
              UNION ALL
              SELECT item.value FROM json_each(NEW.observation_ordinals_json) AS item
              GROUP BY item.value HAVING count(*) > 1
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'time policy issue exceeds its draft analysis or references invalid evidence');
END;

CREATE TRIGGER trg_capture_time_policy_issues_no_update_v7
BEFORE UPDATE ON capture_time_policy_issues
BEGIN
    SELECT RAISE(ABORT, 'time policy issue is immutable');
END;

CREATE TRIGGER trg_capture_time_policy_issues_no_delete_v7
BEFORE DELETE ON capture_time_policy_issues
BEGIN
    SELECT RAISE(ABORT, 'time policy issue cannot be deleted');
END;

CREATE TRIGGER trg_capture_time_members_insert_guard_v7
BEFORE INSERT ON capture_time_member_assessments
WHEN NOT EXISTS (
    SELECT 1
    FROM capture_time_analysis_builds AS build
    JOIN media_observation_snapshots AS observation
      ON observation.id = NEW.media_observation_snapshot_id
     AND observation.scan_run_id = NEW.scan_run_id
     AND observation.volume_id = NEW.volume_id
    LEFT JOIN capture_time_candidates AS candidate
      ON candidate.analysis_build_id = build.id
     AND candidate.id = NEW.candidate_id
    WHERE build.id = NEW.analysis_build_id
      AND build.state = 'draft'
      AND build.scan_run_id = NEW.scan_run_id
      AND build.volume_id = NEW.volume_id
      AND build.exact_group_build_id = NEW.exact_group_build_id
      AND NEW.member_ordinal < build.expected_member_count
      AND NEW.created_at_ms >= build.created_at_ms
      AND (NEW.birth_time_relation <> 'unavailable' OR observation.birth_time_seconds IS NULL)
      AND (NEW.birth_time_relation = 'unavailable' OR observation.birth_time_seconds IS NOT NULL)
      AND NEW.donor_eligibility = 'ineligible'
      AND (
          (NEW.candidate_id IS NULL
           AND NEW.birth_time_relation IN ('unavailable', 'not_compared')
           AND NEW.modified_time_relation = 'not_compared'
           AND NEW.reason_code = 'no_strong_embedded_candidate')
          OR (
              NEW.candidate_id IS NOT NULL
              AND candidate.id = NEW.candidate_id
              AND candidate.evidence_gate = 'eligible'
              AND candidate.semantic_kind = 'utc'
              AND (
                  (observation.timestamp_granularity_ns IS NULL
                   AND NEW.birth_time_relation = CASE
                       WHEN observation.birth_time_seconds IS NULL
                       THEN 'unavailable'
                       ELSE 'review_fs_precision_unknown'
                   END
                   AND NEW.modified_time_relation = 'review_fs_precision_unknown'
                   AND NEW.reason_code = 'fs_precision_unknown')
                  OR
                  (observation.timestamp_granularity_ns IS NOT NULL
                   AND (NEW.birth_time_relation = 'unavailable'
                        OR NEW.birth_time_relation IN ('matches', 'differs'))
                   AND NEW.modified_time_relation IN ('matches', 'differs')
                   AND NEW.modified_time_relation = CASE
                       WHEN CASE
                           WHEN abs(
                               CAST(candidate.utc_seconds_decimal AS INTEGER)
                               - observation.modified_time_seconds
                           ) > (
                               max(observation.timestamp_granularity_ns,
                                   candidate.precision_ns) / 1000000000
                           ) + 1
                           THEN 0
                           ELSE abs(
                               (CAST(candidate.utc_seconds_decimal AS INTEGER)
                                - observation.modified_time_seconds) * 1000000000
                               + candidate.utc_nanoseconds
                               - observation.modified_time_nanoseconds
                           ) <= max(observation.timestamp_granularity_ns,
                                    candidate.precision_ns)
                       END
                       THEN 'matches'
                       ELSE 'differs'
                   END
                   AND NEW.birth_time_relation = CASE
                       WHEN observation.birth_time_seconds IS NULL
                       THEN 'unavailable'
                       WHEN CASE
                           WHEN abs(
                               CAST(candidate.utc_seconds_decimal AS INTEGER)
                               - observation.birth_time_seconds
                           ) > (
                               max(observation.timestamp_granularity_ns,
                                   candidate.precision_ns) / 1000000000
                           ) + 1
                           THEN 0
                           ELSE abs(
                               (CAST(candidate.utc_seconds_decimal AS INTEGER)
                                - observation.birth_time_seconds) * 1000000000
                               + candidate.utc_nanoseconds
                               - observation.birth_time_nanoseconds
                           ) <= max(observation.timestamp_granularity_ns,
                                    candidate.precision_ns)
                       END
                       THEN 'matches'
                       ELSE 'differs'
                   END
                   AND NEW.reason_code = CASE
                       WHEN NEW.birth_time_relation = 'matches'
                         OR NEW.modified_time_relation = 'matches'
                       THEN 'embedded_time_matches_fs'
                       ELSE 'embedded_time_differs_fs'
                   END)
              )
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'member assessment is not bounded to its exact member and evidence');
END;

CREATE TRIGGER trg_capture_time_members_no_update_v7
BEFORE UPDATE ON capture_time_member_assessments
BEGIN
    SELECT RAISE(ABORT, 'time member assessment is immutable');
END;

CREATE TRIGGER trg_capture_time_members_no_delete_v7
BEFORE DELETE ON capture_time_member_assessments
BEGIN
    SELECT RAISE(ABORT, 'time member assessment cannot be deleted');
END;

CREATE TRIGGER trg_capture_time_recommendations_insert_guard_v7
BEFORE INSERT ON capture_time_recommendations
WHEN NOT EXISTS (
    SELECT 1 FROM capture_time_analysis_builds AS build
    WHERE build.id = NEW.analysis_build_id
      AND build.state = 'draft'
      AND build.scan_run_id = NEW.scan_run_id
      AND build.volume_id = NEW.volume_id
      AND build.exact_group_build_id = NEW.exact_group_build_id
      AND NEW.created_at_ms >= build.created_at_ms
      AND (
          NEW.time_donor_observation_id IS NULL
          OR EXISTS (
              SELECT 1 FROM capture_time_member_assessments AS member
              WHERE member.analysis_build_id = NEW.analysis_build_id
                AND member.media_observation_snapshot_id = NEW.time_donor_observation_id
                AND member.candidate_id = NEW.candidate_id
                AND member.donor_eligibility = 'eligible'
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'time recommendation lacks independent keeper/donor evidence');
END;

CREATE TRIGGER trg_capture_time_recommendations_no_update_v7
BEFORE UPDATE ON capture_time_recommendations
BEGIN
    SELECT RAISE(ABORT, 'time recommendation is immutable');
END;

CREATE TRIGGER trg_capture_time_recommendations_no_delete_v7
BEFORE DELETE ON capture_time_recommendations
BEGIN
    SELECT RAISE(ABORT, 'time recommendation cannot be deleted');
END;

PRAGMA user_version = 7;
