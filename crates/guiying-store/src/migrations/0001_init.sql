-- Guiying initial data model.
--
-- Runtime connections must also apply the PRAGMAs documented in
-- docs/engineering/DATA_MODEL.md. foreign_keys is repeated here so direct
-- sqlite3 execution validates the migration with FK enforcement enabled.

PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE volumes (
    id INTEGER PRIMARY KEY,
    identity_key TEXT NOT NULL UNIQUE,
    identity_strength TEXT NOT NULL
        CHECK (identity_strength IN ('strong', 'medium', 'weak')),
    marker_uuid TEXT UNIQUE,
    native_uuid TEXT,
    filesystem_type TEXT NOT NULL,
    display_name TEXT,
    mount_source TEXT,
    last_mount_path TEXT,
    transport TEXT,
    is_network INTEGER NOT NULL DEFAULT 0
        CHECK (is_network IN (0, 1)),
    is_read_only INTEGER NOT NULL DEFAULT 1
        CHECK (is_read_only IN (0, 1)),
    case_behavior TEXT NOT NULL DEFAULT 'unknown'
        CHECK (case_behavior IN (
            'sensitive',
            'insensitive_preserving',
            'insensitive_nonpreserving',
            'unknown'
        )),
    total_bytes INTEGER
        CHECK (total_bytes IS NULL OR total_bytes >= 0),
    first_seen_at_ms INTEGER NOT NULL
        CHECK (first_seen_at_ms >= 0),
    last_seen_at_ms INTEGER NOT NULL
        CHECK (last_seen_at_ms >= first_seen_at_ms),
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL
        CHECK (updated_at_ms >= created_at_ms),
    UNIQUE (id, identity_key),
    CHECK (length(identity_key) > 0),
    CHECK (length(filesystem_type) > 0)
) STRICT;

CREATE TABLE capability_profiles (
    id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    profile_hash BLOB NOT NULL
        CHECK (length(profile_hash) = 32),
    probe_mode TEXT NOT NULL
        CHECK (probe_mode IN ('passive', 'active')),
    probe_status TEXT NOT NULL
        CHECK (probe_status IN ('complete', 'partial', 'failed')),
    observed_at_ms INTEGER NOT NULL
        CHECK (observed_at_ms >= 0),
    os_build TEXT NOT NULL,
    driver_name TEXT,
    driver_version TEXT,
    mount_flags INTEGER,
    can_read INTEGER
        CHECK (can_read IS NULL OR can_read IN (0, 1)),
    can_write INTEGER
        CHECK (can_write IS NULL OR can_write IN (0, 1)),
    can_rename_same_volume INTEGER
        CHECK (can_rename_same_volume IS NULL OR can_rename_same_volume IN (0, 1)),
    can_rename_exclusive INTEGER
        CHECK (can_rename_exclusive IS NULL OR can_rename_exclusive IN (0, 1)),
    can_set_birth_time INTEGER
        CHECK (can_set_birth_time IS NULL OR can_set_birth_time IN (0, 1)),
    can_set_modified_time INTEGER
        CHECK (can_set_modified_time IS NULL OR can_set_modified_time IN (0, 1)),
    can_use_xattrs INTEGER
        CHECK (can_use_xattrs IS NULL OR can_use_xattrs IN (0, 1)),
    can_use_hard_links INTEGER
        CHECK (can_use_hard_links IS NULL OR can_use_hard_links IN (0, 1)),
    can_use_clones INTEGER
        CHECK (can_use_clones IS NULL OR can_use_clones IN (0, 1)),
    has_persistent_file_ids INTEGER
        CHECK (has_persistent_file_ids IS NULL OR has_persistent_file_ids IN (0, 1)),
    timestamp_granularity_ns INTEGER
        CHECK (timestamp_granularity_ns IS NULL OR timestamp_granularity_ns > 0),
    maximum_name_bytes INTEGER
        CHECK (maximum_name_bytes IS NULL OR maximum_name_bytes > 0),
    maximum_file_bytes INTEGER
        CHECK (maximum_file_bytes IS NULL OR maximum_file_bytes >= 0),
    raw_capabilities_json TEXT,
    is_current INTEGER NOT NULL DEFAULT 1
        CHECK (is_current IN (0, 1)),
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    UNIQUE (volume_id, profile_hash),
    UNIQUE (volume_id, id),
    FOREIGN KEY (volume_id) REFERENCES volumes(id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX ux_capability_profiles_current
    ON capability_profiles(volume_id)
    WHERE is_current = 1;

CREATE TABLE scan_runs (
    id INTEGER PRIMARY KEY,
    run_key TEXT NOT NULL UNIQUE,
    volume_id INTEGER NOT NULL,
    capability_profile_id INTEGER NOT NULL,
    parent_scan_run_id INTEGER,
    root_relative_path TEXT NOT NULL,
    root_path_key BLOB NOT NULL,
    scan_mode TEXT NOT NULL
        CHECK (scan_mode IN ('full', 'incremental', 'resume', 'verify')),
    state TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN (
            'queued',
            'running',
            'paused',
            'completed',
            'failed',
            'cancelled',
            'interrupted'
        )),
    config_json TEXT,
    discovered_count INTEGER NOT NULL DEFAULT 0
        CHECK (discovered_count >= 0),
    fingerprinted_count INTEGER NOT NULL DEFAULT 0
        CHECK (fingerprinted_count >= 0),
    error_count INTEGER NOT NULL DEFAULT 0
        CHECK (error_count >= 0),
    logical_bytes_seen INTEGER NOT NULL DEFAULT 0
        CHECK (logical_bytes_seen >= 0),
    started_at_ms INTEGER
        CHECK (started_at_ms IS NULL OR started_at_ms >= 0),
    heartbeat_at_ms INTEGER
        CHECK (heartbeat_at_ms IS NULL OR heartbeat_at_ms >= 0),
    finished_at_ms INTEGER
        CHECK (finished_at_ms IS NULL OR finished_at_ms >= 0),
    last_error_code TEXT,
    last_error_message TEXT,
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL
        CHECK (updated_at_ms >= created_at_ms),
    UNIQUE (volume_id, id),
    CHECK (length(run_key) > 0),
    CHECK (root_relative_path = '' OR root_relative_path NOT LIKE '/%'),
    CHECK (finished_at_ms IS NULL OR started_at_ms IS NOT NULL),
    FOREIGN KEY (volume_id) REFERENCES volumes(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, capability_profile_id)
        REFERENCES capability_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, parent_scan_run_id)
        REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_scan_runs_volume_state
    ON scan_runs(volume_id, state, created_at_ms DESC);

CREATE INDEX ix_scan_runs_capability_profile
    ON scan_runs(capability_profile_id);

CREATE INDEX ix_scan_runs_volume_capability_profile
    ON scan_runs(volume_id, capability_profile_id);

CREATE INDEX ix_scan_runs_parent
    ON scan_runs(parent_scan_run_id)
    WHERE parent_scan_run_id IS NOT NULL;

CREATE INDEX ix_scan_runs_volume_parent
    ON scan_runs(volume_id, parent_scan_run_id)
    WHERE parent_scan_run_id IS NOT NULL;

CREATE TABLE media_files (
    id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    first_seen_scan_run_id INTEGER NOT NULL,
    last_seen_scan_run_id INTEGER NOT NULL,
    relative_path TEXT NOT NULL,
    path_key BLOB NOT NULL,
    entry_type TEXT NOT NULL DEFAULT 'regular'
        CHECK (entry_type IN (
            'regular',
            'symlink',
            'directory',
            'other'
        )),
    media_kind TEXT NOT NULL DEFAULT 'unknown'
        CHECK (media_kind IN (
            'photo',
            'video',
            'raw',
            'sidecar',
            'unknown'
        )),
    mime_type TEXT,
    file_extension TEXT,
    lifecycle_state TEXT NOT NULL DEFAULT 'present'
        CHECK (lifecycle_state IN (
            'present',
            'missing',
            'quarantined',
            'excluded',
            'unreadable',
            'io_error'
        )),
    size_bytes INTEGER
        CHECK (size_bytes IS NULL OR size_bytes >= 0),
    allocated_bytes INTEGER
        CHECK (allocated_bytes IS NULL OR allocated_bytes >= 0),
    native_file_id BLOB,
    native_file_generation INTEGER,
    link_count INTEGER
        CHECK (link_count IS NULL OR link_count >= 1),
    is_sparse INTEGER
        CHECK (is_sparse IS NULL OR is_sparse IN (0, 1)),
    may_share_content INTEGER
        CHECK (may_share_content IS NULL OR may_share_content IN (0, 1)),
    birth_time_ns INTEGER,
    modified_time_ns INTEGER,
    changed_time_ns INTEGER,
    accessed_time_ns INTEGER,
    timestamp_granularity_ns INTEGER
        CHECK (timestamp_granularity_ns IS NULL OR timestamp_granularity_ns > 0),
    stat_signature BLOB,
    metadata_json TEXT,
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL
        CHECK (updated_at_ms >= created_at_ms),
    UNIQUE (volume_id, path_key),
    UNIQUE (volume_id, id),
    CHECK (length(relative_path) > 0),
    CHECK (relative_path NOT LIKE '/%'),
    FOREIGN KEY (volume_id) REFERENCES volumes(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, first_seen_scan_run_id)
        REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, last_seen_scan_run_id)
        REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_media_files_last_seen_scan
    ON media_files(last_seen_scan_run_id);

CREATE INDEX ix_media_files_volume_last_seen_scan
    ON media_files(volume_id, last_seen_scan_run_id);

CREATE INDEX ix_media_files_first_seen_scan
    ON media_files(first_seen_scan_run_id);

CREATE INDEX ix_media_files_volume_first_seen_scan
    ON media_files(volume_id, first_seen_scan_run_id);

CREATE INDEX ix_media_files_volume_lifecycle
    ON media_files(volume_id, lifecycle_state, media_kind);

CREATE INDEX ix_media_files_size_candidates
    ON media_files(volume_id, size_bytes)
    WHERE entry_type = 'regular'
      AND lifecycle_state = 'present'
      AND size_bytes IS NOT NULL;

CREATE TABLE fingerprints (
    id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    media_file_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    fingerprint_kind TEXT NOT NULL
        CHECK (fingerprint_kind IN (
            'sample',
            'exact_bytes',
            'decoded_pixels',
            'perceptual',
            'metadata'
        )),
    algorithm TEXT NOT NULL,
    algorithm_version INTEGER NOT NULL
        CHECK (algorithm_version >= 1),
    parameters_hash BLOB NOT NULL
        CHECK (length(parameters_hash) = 32),
    source_signature BLOB NOT NULL
        CHECK (length(source_signature) = 32),
    digest BLOB NOT NULL
        CHECK (length(digest) > 0),
    observed_size_bytes INTEGER NOT NULL
        CHECK (observed_size_bytes >= 0),
    observed_modified_time_ns INTEGER,
    bytes_read INTEGER NOT NULL
        CHECK (bytes_read >= 0),
    completed_at_ms INTEGER NOT NULL
        CHECK (completed_at_ms >= 0),
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    UNIQUE (
        media_file_id,
        fingerprint_kind,
        algorithm,
        algorithm_version,
        parameters_hash,
        source_signature
    ),
    UNIQUE (volume_id, id),
    UNIQUE (volume_id, media_file_id, id),
    UNIQUE (volume_id, media_file_id, id, fingerprint_kind),
    UNIQUE (
        volume_id,
        media_file_id,
        id,
        fingerprint_kind,
        observed_size_bytes,
        digest
    ),
    CHECK (fingerprint_kind <> 'exact_bytes' OR bytes_read = observed_size_bytes),
    FOREIGN KEY (volume_id, media_file_id)
        REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id)
        REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_fingerprints_digest_lookup
    ON fingerprints(
        fingerprint_kind,
        algorithm,
        algorithm_version,
        parameters_hash,
        digest
    );

CREATE INDEX ix_fingerprints_scan_run
    ON fingerprints(volume_id, scan_run_id);

CREATE TABLE duplicate_groups (
    id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    group_key BLOB NOT NULL
        CHECK (length(group_key) = 32),
    match_kind TEXT NOT NULL
        CHECK (match_kind IN (
            'exact_bytes',
            'exact_pixels',
            'visual_similarity'
        )),
    algorithm TEXT NOT NULL,
    algorithm_version INTEGER NOT NULL
        CHECK (algorithm_version >= 1),
    similarity_basis_points INTEGER NOT NULL
        CHECK (similarity_basis_points BETWEEN 0 AND 10000),
    confidence_basis_points INTEGER NOT NULL
        CHECK (confidence_basis_points BETWEEN 0 AND 10000),
    review_state TEXT NOT NULL DEFAULT 'unreviewed'
        CHECK (review_state IN (
            'unreviewed',
            'approved',
            'rejected',
            'conflict'
        )),
    logical_reclaimable_bytes INTEGER
        CHECK (logical_reclaimable_bytes IS NULL OR logical_reclaimable_bytes >= 0),
    notes TEXT,
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL
        CHECK (updated_at_ms >= created_at_ms),
    UNIQUE (volume_id, scan_run_id, group_key),
    UNIQUE (volume_id, id),
    FOREIGN KEY (volume_id, scan_run_id)
        REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_duplicate_groups_review
    ON duplicate_groups(volume_id, scan_run_id, review_state, match_kind);

CREATE TABLE duplicate_group_members (
    id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    duplicate_group_id INTEGER NOT NULL,
    media_file_id INTEGER NOT NULL,
    evidence_fingerprint_id INTEGER NOT NULL,
    evidence_fingerprint_kind TEXT NOT NULL
        CHECK (evidence_fingerprint_kind IN (
            'exact_bytes',
            'decoded_pixels',
            'perceptual'
        )),
    member_role TEXT NOT NULL DEFAULT 'candidate'
        CHECK (member_role IN ('candidate', 'keeper', 'excluded')),
    recommended_action TEXT NOT NULL DEFAULT 'review'
        CHECK (recommended_action IN ('keep', 'quarantine', 'review', 'ignore')),
    metadata_relation TEXT NOT NULL DEFAULT 'unknown'
        CHECK (metadata_relation IN (
            'equal',
            'keeper_superset',
            'member_superset',
            'divergent',
            'unknown'
        )),
    sort_rank INTEGER NOT NULL DEFAULT 0
        CHECK (sort_rank >= 0),
    reason_json TEXT,
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    UNIQUE (volume_id, duplicate_group_id, media_file_id),
    UNIQUE (volume_id, id),
    UNIQUE (volume_id, media_file_id, id),
    FOREIGN KEY (volume_id, duplicate_group_id)
        REFERENCES duplicate_groups(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, media_file_id)
        REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        media_file_id,
        evidence_fingerprint_id,
        evidence_fingerprint_kind
    ) REFERENCES fingerprints(
        volume_id,
        media_file_id,
        id,
        fingerprint_kind
    )
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX ux_duplicate_group_members_keeper
    ON duplicate_group_members(duplicate_group_id)
    WHERE member_role = 'keeper';

CREATE INDEX ix_duplicate_group_members_media
    ON duplicate_group_members(volume_id, media_file_id);

CREATE INDEX ix_duplicate_group_members_fingerprint
    ON duplicate_group_members(volume_id, evidence_fingerprint_id);

CREATE INDEX ix_duplicate_group_members_evidence_binding
    ON duplicate_group_members(
        volume_id,
        media_file_id,
        evidence_fingerprint_id,
        evidence_fingerprint_kind
    );

CREATE TABLE time_candidates (
    id INTEGER PRIMARY KEY,
    candidate_key BLOB NOT NULL
        CHECK (length(candidate_key) = 32),
    volume_id INTEGER NOT NULL,
    media_file_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    source_media_file_id INTEGER,
    source_duplicate_group_id INTEGER,
    source_asset_link_id INTEGER,
    source_kind TEXT NOT NULL
        CHECK (source_kind IN (
            'exif',
            'quicktime',
            'filesystem_birth',
            'filesystem_modified',
            'xmp_sidecar',
            'json_sidecar',
            'filename',
            'directory_name',
            'duplicate_peer',
            'manual'
        )),
    source_locator TEXT,
    raw_value BLOB NOT NULL,
    raw_text TEXT,
    raw_encoding TEXT NOT NULL,
    parse_status TEXT NOT NULL
        CHECK (parse_status IN (
            'parsed',
            'partial',
            'unparseable',
            'out_of_range'
        )),
    wall_time TEXT,
    utc_offset_minutes INTEGER
        CHECK (utc_offset_minutes IS NULL
            OR utc_offset_minutes BETWEEN -1440 AND 1440),
    offset_kind TEXT NOT NULL DEFAULT 'absent'
        CHECK (offset_kind IN (
            'embedded',
            'sidecar',
            'inferred',
            'absent',
            'invalid'
        )),
    timezone_name TEXT,
    utc_instant_ns INTEGER,
    precision_ns INTEGER
        CHECK (precision_ns IS NULL OR precision_ns > 0),
    precision_kind TEXT NOT NULL
        CHECK (precision_kind IN ('exact', 'bounded', 'estimated', 'unknown')),
    confidence_basis_points INTEGER NOT NULL
        CHECK (confidence_basis_points BETWEEN 0 AND 10000),
    ambiguity TEXT NOT NULL DEFAULT 'none'
        CHECK (ambiguity IN (
            'none',
            'missing_offset',
            'dst_fold',
            'timezone_conflict',
            'source_conflict',
            'invalid_value',
            'range_overflow'
        )),
    is_selected INTEGER NOT NULL DEFAULT 0
        CHECK (is_selected IN (0, 1)),
    selection_reason TEXT,
    normalized_at_ms INTEGER NOT NULL
        CHECK (normalized_at_ms >= 0),
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    UNIQUE (volume_id, media_file_id, candidate_key),
    UNIQUE (volume_id, id),
    UNIQUE (volume_id, media_file_id, id),
    CHECK (
        (precision_kind = 'unknown' AND precision_ns IS NULL)
        OR (precision_kind <> 'unknown' AND precision_ns IS NOT NULL)
    ),
    CHECK (
        utc_instant_ns IS NULL
        OR (
            parse_status = 'parsed'
            AND wall_time IS NOT NULL
            AND utc_offset_minutes IS NOT NULL
            AND offset_kind IN ('embedded', 'sidecar', 'inferred')
        )
    ),
    CHECK (
        is_selected = 0
        OR (parse_status = 'parsed' AND wall_time IS NOT NULL)
    ),
    CHECK (
        (
            source_kind = 'duplicate_peer'
            AND source_media_file_id IS NOT NULL
            AND source_media_file_id <> media_file_id
            AND source_duplicate_group_id IS NOT NULL
            AND source_asset_link_id IS NULL
        )
        OR (
            source_kind IN ('xmp_sidecar', 'json_sidecar')
            AND source_media_file_id IS NOT NULL
            AND source_media_file_id <> media_file_id
            AND source_duplicate_group_id IS NULL
            AND source_asset_link_id IS NOT NULL
        )
        OR (
            source_kind NOT IN (
                'duplicate_peer', 'xmp_sidecar', 'json_sidecar'
            )
            AND source_media_file_id IS NULL
            AND source_duplicate_group_id IS NULL
            AND source_asset_link_id IS NULL
        )
    ),
    FOREIGN KEY (volume_id, media_file_id)
        REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id)
        REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, source_media_file_id)
        REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, source_duplicate_group_id)
        REFERENCES duplicate_groups(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        source_media_file_id,
        media_file_id,
        source_asset_link_id
    ) REFERENCES asset_links(
        volume_id,
        from_media_file_id,
        to_media_file_id,
        id
    )
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX ux_time_candidates_selected
    ON time_candidates(media_file_id)
    WHERE is_selected = 1;

CREATE INDEX ix_time_candidates_scan_run
    ON time_candidates(volume_id, scan_run_id);

CREATE INDEX ix_time_candidates_source_media
    ON time_candidates(volume_id, source_media_file_id)
    WHERE source_media_file_id IS NOT NULL;

CREATE INDEX ix_time_candidates_duplicate_group_source
    ON time_candidates(volume_id, source_duplicate_group_id)
    WHERE source_duplicate_group_id IS NOT NULL;

CREATE INDEX ix_time_candidates_asset_link_source
    ON time_candidates(
        volume_id,
        source_media_file_id,
        media_file_id,
        source_asset_link_id
    )
    WHERE source_asset_link_id IS NOT NULL;

CREATE INDEX ix_time_candidates_ranking
    ON time_candidates(
        media_file_id,
        confidence_basis_points DESC,
        ambiguity,
        source_kind
    );

CREATE TABLE asset_links (
    id INTEGER PRIMARY KEY,
    link_key BLOB NOT NULL
        CHECK (length(link_key) = 32),
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    from_media_file_id INTEGER NOT NULL,
    to_media_file_id INTEGER NOT NULL,
    link_kind TEXT NOT NULL
        CHECK (link_kind IN (
            'live_photo_pair',
            'raw_render_pair',
            'sidecar_for',
            'edit_directive_for',
            'burst_member',
            'derived_from'
        )),
    relation_state TEXT NOT NULL DEFAULT 'inferred'
        CHECK (relation_state IN ('inferred', 'confirmed', 'rejected', 'conflict')),
    confidence_basis_points INTEGER NOT NULL
        CHECK (confidence_basis_points BETWEEN 0 AND 10000),
    evidence_json TEXT,
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL
        CHECK (updated_at_ms >= created_at_ms),
    UNIQUE (volume_id, link_key),
    UNIQUE (volume_id, id),
    UNIQUE (volume_id, from_media_file_id, to_media_file_id, id),
    CHECK (from_media_file_id <> to_media_file_id),
    FOREIGN KEY (volume_id, scan_run_id)
        REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, from_media_file_id)
        REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, to_media_file_id)
        REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_asset_links_from
    ON asset_links(volume_id, from_media_file_id, link_kind, relation_state);

CREATE INDEX ix_asset_links_to
    ON asset_links(volume_id, to_media_file_id, link_kind, relation_state);

CREATE INDEX ix_asset_links_scan_run
    ON asset_links(volume_id, scan_run_id);

CREATE TABLE operation_batches (
    id INTEGER PRIMARY KEY,
    batch_key TEXT NOT NULL UNIQUE,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER,
    capability_profile_id INTEGER NOT NULL,
    operation_kind TEXT NOT NULL
        CHECK (operation_kind IN (
            'quarantine',
            'restore',
            'repair_time',
            'purge',
            'merge_metadata',
            'mixed'
        )),
    state TEXT NOT NULL DEFAULT 'planned'
        CHECK (state IN (
            'planned',
            'running',
            'paused',
            'completed',
            'failed',
            'cancelled',
            'needs_reconciliation'
        )),
    state_version INTEGER NOT NULL DEFAULT 0
        CHECK (state_version >= 0),
    is_dry_run INTEGER NOT NULL DEFAULT 0
        CHECK (is_dry_run IN (0, 1)),
    requires_confirmation INTEGER NOT NULL DEFAULT 1
        CHECK (requires_confirmation IN (0, 1)),
    confirmed_at_ms INTEGER
        CHECK (confirmed_at_ms IS NULL OR confirmed_at_ms >= 0),
    sealed_at_ms INTEGER
        CHECK (sealed_at_ms IS NULL OR sealed_at_ms >= 0),
    manifest_digest BLOB
        CHECK (manifest_digest IS NULL OR length(manifest_digest) = 32),
    volume_manifest_outbox_id INTEGER,
    policy_json TEXT NOT NULL DEFAULT '{}',
    started_at_ms INTEGER
        CHECK (started_at_ms IS NULL OR started_at_ms >= 0),
    finished_at_ms INTEGER
        CHECK (finished_at_ms IS NULL OR finished_at_ms >= 0),
    last_error_code TEXT,
    last_error_message TEXT,
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL
        CHECK (updated_at_ms >= created_at_ms),
    UNIQUE (id, volume_id),
    UNIQUE (volume_id, id),
    CHECK (length(batch_key) > 0),
    CHECK (is_dry_run = 0 OR state IN ('planned', 'cancelled')),
    CHECK (
        requires_confirmation = 0
        OR state IN ('planned', 'cancelled')
        OR confirmed_at_ms IS NOT NULL
    ),
    CHECK (
        (sealed_at_ms IS NULL AND manifest_digest IS NULL)
        OR (sealed_at_ms IS NOT NULL AND manifest_digest IS NOT NULL)
    ),
    CHECK (
        state IN ('planned', 'cancelled')
        OR volume_manifest_outbox_id IS NOT NULL
    ),
    CHECK (
        (state IN ('completed', 'failed', 'cancelled') AND finished_at_ms IS NOT NULL)
        OR (state NOT IN ('completed', 'failed', 'cancelled') AND finished_at_ms IS NULL)
    ),
    FOREIGN KEY (volume_id) REFERENCES volumes(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id)
        REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, capability_profile_id)
        REFERENCES capability_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, id, volume_manifest_outbox_id)
        REFERENCES volume_manifest_outbox(
            volume_id,
            operation_batch_id,
            id
        )
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_operation_batches_volume_state
    ON operation_batches(volume_id, state, created_at_ms DESC);

CREATE INDEX ix_operation_batches_scan_run
    ON operation_batches(scan_run_id)
    WHERE scan_run_id IS NOT NULL;

CREATE INDEX ix_operation_batches_volume_scan_run
    ON operation_batches(volume_id, scan_run_id)
    WHERE scan_run_id IS NOT NULL;

CREATE INDEX ix_operation_batches_capability
    ON operation_batches(capability_profile_id);

CREATE INDEX ix_operation_batches_volume_capability
    ON operation_batches(volume_id, capability_profile_id);

CREATE TABLE operation_items (
    id INTEGER PRIMARY KEY,
    operation_batch_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    item_key TEXT NOT NULL,
    media_file_id INTEGER NOT NULL,
    keeper_media_file_id INTEGER,
    duplicate_group_member_id INTEGER,
    time_candidate_id INTEGER,
    precondition_fingerprint_id INTEGER NOT NULL,
    precondition_fingerprint_kind TEXT NOT NULL DEFAULT 'exact_bytes'
        CHECK (precondition_fingerprint_kind = 'exact_bytes'),
    volume_intent_outbox_id INTEGER,
    operation_kind TEXT NOT NULL
        CHECK (operation_kind IN (
            'quarantine',
            'restore',
            'repair_time',
            'purge',
            'merge_metadata'
        )),
    state TEXT NOT NULL DEFAULT 'planned'
        CHECK (state IN (
            'planned',
            'in_progress',
            'applied',
            'verifying',
            'succeeded',
            'failed',
            'skipped',
            'cancelled',
            'needs_reconciliation',
            'rolled_back'
        )),
    state_version INTEGER NOT NULL DEFAULT 0
        CHECK (state_version >= 0),
    source_relative_path_snapshot TEXT NOT NULL,
    source_relative_path_raw BLOB NOT NULL,
    source_path_encoding TEXT NOT NULL
        CHECK (source_path_encoding IN ('unix_bytes', 'windows_utf16le')),
    destination_relative_path TEXT,
    destination_relative_path_raw BLOB,
    destination_path_encoding TEXT
        CHECK (
            destination_path_encoding IS NULL
            OR destination_path_encoding IN ('unix_bytes', 'windows_utf16le')
        ),
    expected_size_bytes INTEGER NOT NULL
        CHECK (expected_size_bytes >= 0),
    expected_modified_time_ns INTEGER,
    expected_digest BLOB NOT NULL
        CHECK (length(expected_digest) > 0),
    before_metadata_json TEXT NOT NULL DEFAULT '{}',
    requested_change_json TEXT NOT NULL DEFAULT '{}',
    observed_result_json TEXT,
    verification_digest BLOB,
    attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK (attempt_count >= 0),
    last_error_code TEXT,
    last_error_message TEXT,
    applied_at_ms INTEGER
        CHECK (applied_at_ms IS NULL OR applied_at_ms >= 0),
    verified_at_ms INTEGER
        CHECK (verified_at_ms IS NULL OR verified_at_ms >= 0),
    finished_at_ms INTEGER
        CHECK (finished_at_ms IS NULL OR finished_at_ms >= 0),
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL
        CHECK (updated_at_ms >= created_at_ms),
    UNIQUE (operation_batch_id, item_key),
    UNIQUE (operation_batch_id, id),
    UNIQUE (volume_id, id),
    CHECK (length(item_key) > 0),
    CHECK (length(source_relative_path_snapshot) > 0),
    CHECK (length(source_relative_path_raw) > 0),
    CHECK (source_relative_path_snapshot NOT LIKE '/%'),
    CHECK (instr(source_relative_path_snapshot, char(0)) = 0),
    CHECK (instr('/' || source_relative_path_snapshot || '/', '/../') = 0),
    CHECK (instr('/' || source_relative_path_snapshot || '/', '/./') = 0),
    CHECK (instr('/' || source_relative_path_snapshot || '/', '//') = 0),
    CHECK (
        source_path_encoding <> 'unix_bytes'
        OR (
            substr(source_relative_path_raw, 1, 1) <> x'2F'
            AND instr(source_relative_path_raw, x'00') = 0
            AND source_relative_path_raw NOT IN (x'2E', x'2E2E')
            AND substr(source_relative_path_raw, 1, 2) <> x'2E2F'
            AND substr(source_relative_path_raw, 1, 3) <> x'2E2E2F'
            AND substr(source_relative_path_raw, -2) <> x'2F2E'
            AND substr(source_relative_path_raw, -3) <> x'2F2E2E'
            AND substr(source_relative_path_raw, -1) <> x'2F'
            AND instr(source_relative_path_raw, x'2F2E2F') = 0
            AND instr(source_relative_path_raw, x'2F2E2E2F') = 0
            AND instr(source_relative_path_raw, x'2F2F') = 0
        )
    ),
    CHECK (
        (destination_relative_path IS NULL
            AND destination_relative_path_raw IS NULL
            AND destination_path_encoding IS NULL)
        OR (destination_relative_path IS NOT NULL
            AND destination_relative_path_raw IS NOT NULL
            AND destination_path_encoding IS NOT NULL
            AND length(destination_relative_path) > 0
            AND length(destination_relative_path_raw) > 0
            AND destination_relative_path NOT LIKE '/%'
            AND instr(destination_relative_path, char(0)) = 0
            AND instr('/' || destination_relative_path || '/', '/../') = 0
            AND instr('/' || destination_relative_path || '/', '/./') = 0
            AND instr('/' || destination_relative_path || '/', '//') = 0
            AND (
                destination_path_encoding <> 'unix_bytes'
                OR (
                    substr(destination_relative_path_raw, 1, 1) <> x'2F'
                    AND instr(destination_relative_path_raw, x'00') = 0
                    AND destination_relative_path_raw NOT IN (x'2E', x'2E2E')
                    AND substr(destination_relative_path_raw, 1, 2) <> x'2E2F'
                    AND substr(destination_relative_path_raw, 1, 3) <> x'2E2E2F'
                    AND substr(destination_relative_path_raw, -2) <> x'2F2E'
                    AND substr(destination_relative_path_raw, -3) <> x'2F2E2E'
                    AND substr(destination_relative_path_raw, -1) <> x'2F'
                    AND instr(destination_relative_path_raw, x'2F2E2F') = 0
                    AND instr(destination_relative_path_raw, x'2F2E2E2F') = 0
                    AND instr(destination_relative_path_raw, x'2F2F') = 0
                )
            ))
    ),
    CHECK (
        (operation_kind = 'repair_time' AND time_candidate_id IS NOT NULL)
        OR (operation_kind <> 'repair_time' AND time_candidate_id IS NULL)
    ),
    CHECK (keeper_media_file_id IS NULL OR duplicate_group_member_id IS NOT NULL),
    CHECK (
        operation_kind NOT IN ('quarantine', 'purge')
        OR (
            duplicate_group_member_id IS NOT NULL
            AND keeper_media_file_id IS NOT NULL
            AND media_file_id <> keeper_media_file_id
        )
    ),
    CHECK (
        (operation_kind IN ('quarantine', 'restore')
            AND destination_relative_path IS NOT NULL)
        OR (operation_kind NOT IN ('quarantine', 'restore')
            AND destination_relative_path IS NULL)
    ),
    CHECK (
        state IN ('planned', 'skipped', 'cancelled')
        OR volume_intent_outbox_id IS NOT NULL
    ),
    CHECK (state NOT IN ('applied', 'verifying', 'succeeded') OR applied_at_ms IS NOT NULL),
    CHECK (state <> 'succeeded' OR verified_at_ms IS NOT NULL),
    CHECK (
        (
            state IN ('succeeded', 'failed', 'skipped', 'cancelled', 'rolled_back')
            AND finished_at_ms IS NOT NULL
        )
        OR (
            state NOT IN ('succeeded', 'failed', 'skipped', 'cancelled', 'rolled_back')
            AND finished_at_ms IS NULL
        )
    ),
    FOREIGN KEY (operation_batch_id, volume_id)
        REFERENCES operation_batches(id, volume_id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, media_file_id)
        REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, keeper_media_file_id)
        REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, media_file_id, duplicate_group_member_id)
        REFERENCES duplicate_group_members(volume_id, media_file_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, media_file_id, time_candidate_id)
        REFERENCES time_candidates(volume_id, media_file_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        media_file_id,
        precondition_fingerprint_id,
        precondition_fingerprint_kind,
        expected_size_bytes,
        expected_digest
    ) REFERENCES fingerprints(
        volume_id,
        media_file_id,
        id,
        fingerprint_kind,
        observed_size_bytes,
        digest
    )
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        operation_batch_id,
        id,
        volume_intent_outbox_id
    ) REFERENCES volume_manifest_outbox(
        operation_batch_id,
        operation_item_id,
        id
    )
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_operation_items_batch_state
    ON operation_items(operation_batch_id, state, id);

CREATE INDEX ix_operation_items_media
    ON operation_items(media_file_id);

CREATE INDEX ix_operation_items_batch_volume
    ON operation_items(operation_batch_id, volume_id);

CREATE INDEX ix_operation_items_volume_media
    ON operation_items(volume_id, media_file_id);

CREATE INDEX ix_operation_items_keeper
    ON operation_items(keeper_media_file_id)
    WHERE keeper_media_file_id IS NOT NULL;

CREATE INDEX ix_operation_items_volume_keeper
    ON operation_items(volume_id, keeper_media_file_id)
    WHERE keeper_media_file_id IS NOT NULL;

CREATE INDEX ix_operation_items_group_member
    ON operation_items(duplicate_group_member_id)
    WHERE duplicate_group_member_id IS NOT NULL;

CREATE INDEX ix_operation_items_group_member_binding
    ON operation_items(volume_id, media_file_id, duplicate_group_member_id)
    WHERE duplicate_group_member_id IS NOT NULL;

CREATE INDEX ix_operation_items_time_candidate
    ON operation_items(time_candidate_id)
    WHERE time_candidate_id IS NOT NULL;

CREATE INDEX ix_operation_items_time_candidate_binding
    ON operation_items(volume_id, media_file_id, time_candidate_id)
    WHERE time_candidate_id IS NOT NULL;

CREATE INDEX ix_operation_items_precondition_fingerprint
    ON operation_items(precondition_fingerprint_id);

CREATE INDEX ix_operation_items_precondition_binding
    ON operation_items(
        volume_id,
        media_file_id,
        precondition_fingerprint_id,
        precondition_fingerprint_kind,
        expected_size_bytes,
        expected_digest
    );

-- Explicit cross-operation dependencies preserve a time donor until every
-- selected transfer that depends on it has completed and been dual-logged.
CREATE TABLE operation_item_dependencies (
    id INTEGER PRIMARY KEY,
    dependency_key TEXT NOT NULL UNIQUE,
    volume_id INTEGER NOT NULL,
    dependent_operation_item_id INTEGER NOT NULL,
    prerequisite_operation_item_id INTEGER NOT NULL,
    time_candidate_id INTEGER NOT NULL,
    dependency_kind TEXT NOT NULL
        CHECK (dependency_kind = 'donor_time_preservation'),
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    UNIQUE (
        volume_id,
        dependent_operation_item_id,
        prerequisite_operation_item_id,
        time_candidate_id
    ),
    CHECK (length(dependency_key) > 0),
    CHECK (dependent_operation_item_id <> prerequisite_operation_item_id),
    FOREIGN KEY (volume_id, dependent_operation_item_id)
        REFERENCES operation_items(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, prerequisite_operation_item_id)
        REFERENCES operation_items(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, time_candidate_id)
        REFERENCES time_candidates(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_operation_item_dependencies_prerequisite
    ON operation_item_dependencies(
        volume_id,
        prerequisite_operation_item_id,
        dependent_operation_item_id
    );

CREATE INDEX ix_operation_item_dependencies_candidate
    ON operation_item_dependencies(volume_id, time_candidate_id);

CREATE TABLE operation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key TEXT NOT NULL UNIQUE,
    operation_batch_id INTEGER NOT NULL,
    operation_item_id INTEGER,
    event_scope TEXT NOT NULL
        CHECK (event_scope IN ('batch', 'item')),
    event_kind TEXT NOT NULL
        CHECK (event_kind IN (
            'created',
            'state_transition',
            'attempt',
            'verification',
            'reconciliation',
            'volume_manifest',
            'note'
        )),
    from_state TEXT,
    to_state TEXT,
    state_version INTEGER
        CHECK (state_version IS NULL OR state_version >= 0),
    actor TEXT NOT NULL,
    occurred_at_ms INTEGER NOT NULL
        CHECK (occurred_at_ms >= 0),
    details_json TEXT,
    CHECK (
        (event_scope = 'batch' AND operation_item_id IS NULL)
        OR (event_scope = 'item' AND operation_item_id IS NOT NULL)
    ),
    FOREIGN KEY (operation_batch_id) REFERENCES operation_batches(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (operation_batch_id, operation_item_id)
        REFERENCES operation_items(operation_batch_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_operation_events_batch
    ON operation_events(operation_batch_id, id);

CREATE INDEX ix_operation_events_item
    ON operation_events(operation_batch_id, operation_item_id, id)
    WHERE operation_item_id IS NOT NULL;

CREATE INDEX ix_operation_events_occurred
    ON operation_events(occurred_at_ms, id);

-- The SQLite database is the durable local half of the write-ahead protocol.
-- Each row contains the exact canonical bytes that must also be appended to an
-- append-only manifest on the target volume. Filesystem actions are gated on a
-- verified target-volume batch manifest and item intent below.
CREATE TABLE volume_manifest_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    outbox_key TEXT NOT NULL UNIQUE,
    volume_id INTEGER NOT NULL,
    operation_batch_id INTEGER NOT NULL,
    operation_item_id INTEGER,
    record_kind TEXT NOT NULL
        CHECK (record_kind IN (
            'batch_manifest',
            'item_intent',
            'item_applied',
            'item_verified',
            'item_reconciliation'
        )),
    sequence_number INTEGER NOT NULL
        CHECK (sequence_number >= 0),
    target_volume_identity_key TEXT NOT NULL,
    target_mount_session_key TEXT NOT NULL,
    target_relative_path TEXT NOT NULL,
    sealed_plan_digest BLOB NOT NULL
        CHECK (length(sealed_plan_digest) = 32),
    serialization_version INTEGER NOT NULL DEFAULT 1
        CHECK (serialization_version >= 1),
    hash_algorithm TEXT NOT NULL DEFAULT 'blake3-256'
        CHECK (hash_algorithm = 'blake3-256'),
    record_payload BLOB NOT NULL
        CHECK (length(record_payload) > 0),
    payload_digest BLOB NOT NULL
        CHECK (length(payload_digest) = 32),
    previous_record_digest BLOB
        CHECK (
            previous_record_digest IS NULL
            OR length(previous_record_digest) = 32
        ),
    record_digest BLOB NOT NULL
        CHECK (length(record_digest) = 32),
    delivery_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (delivery_state IN (
            'pending',
            'written',
            'fsynced',
            'verified',
            'needs_reconciliation'
        )),
    state_version INTEGER NOT NULL DEFAULT 0
        CHECK (state_version >= 0),
    local_recorded_at_ms INTEGER NOT NULL
        CHECK (local_recorded_at_ms >= 0),
    target_offset_bytes INTEGER
        CHECK (target_offset_bytes IS NULL OR target_offset_bytes >= 0),
    target_length_bytes INTEGER
        CHECK (target_length_bytes IS NULL OR target_length_bytes > 0),
    written_at_ms INTEGER
        CHECK (written_at_ms IS NULL OR written_at_ms >= 0),
    fsynced_at_ms INTEGER
        CHECK (fsynced_at_ms IS NULL OR fsynced_at_ms >= 0),
    verified_at_ms INTEGER
        CHECK (verified_at_ms IS NULL OR verified_at_ms >= 0),
    readback_digest BLOB
        CHECK (readback_digest IS NULL OR length(readback_digest) = 32),
    last_error_code TEXT,
    last_error_message TEXT,
    created_at_ms INTEGER NOT NULL
        CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL
        CHECK (updated_at_ms >= created_at_ms),
    UNIQUE (volume_id, operation_batch_id, id),
    UNIQUE (operation_batch_id, operation_item_id, id),
    UNIQUE (operation_batch_id, sequence_number),
    CHECK (length(outbox_key) > 0),
    CHECK (length(target_mount_session_key) > 0),
    CHECK (length(target_relative_path) > 0),
    CHECK (target_relative_path NOT LIKE '/%'),
    CHECK (substr(target_relative_path, 1, 9) = '.guiying/'),
    CHECK (instr('/' || target_relative_path || '/', '/../') = 0),
    CHECK (instr('/' || target_relative_path || '/', '/./') = 0),
    CHECK (instr(target_relative_path, char(0)) = 0),
    CHECK (
        (
            record_kind = 'batch_manifest'
            AND operation_item_id IS NULL
            AND sequence_number = 0
            AND previous_record_digest IS NULL
        )
        OR (
            record_kind <> 'batch_manifest'
            AND operation_item_id IS NOT NULL
            AND sequence_number > 0
            AND previous_record_digest IS NOT NULL
        )
    ),
    CHECK (
        (target_offset_bytes IS NULL AND target_length_bytes IS NULL)
        OR (
            target_offset_bytes IS NOT NULL
            AND target_length_bytes = length(record_payload)
        )
    ),
    CHECK (written_at_ms IS NULL OR written_at_ms >= local_recorded_at_ms),
    CHECK (fsynced_at_ms IS NULL OR (
        written_at_ms IS NOT NULL AND fsynced_at_ms >= written_at_ms
    )),
    CHECK (verified_at_ms IS NULL OR (
        fsynced_at_ms IS NOT NULL AND verified_at_ms >= fsynced_at_ms
    )),
    CHECK (
        delivery_state NOT IN ('written', 'fsynced', 'verified')
        OR (
            target_offset_bytes IS NOT NULL
            AND target_length_bytes IS NOT NULL
            AND written_at_ms IS NOT NULL
        )
    ),
    CHECK (
        delivery_state NOT IN ('fsynced', 'verified')
        OR fsynced_at_ms IS NOT NULL
    ),
    CHECK (
        delivery_state <> 'verified'
        OR (
            verified_at_ms IS NOT NULL
            AND readback_digest = record_digest
        )
    ),
    CHECK (
        delivery_state <> 'needs_reconciliation'
        OR last_error_code IS NOT NULL
    ),
    CHECK (
        delivery_state = 'needs_reconciliation'
        OR (
            delivery_state = 'pending'
            AND target_offset_bytes IS NULL
            AND target_length_bytes IS NULL
            AND written_at_ms IS NULL
            AND fsynced_at_ms IS NULL
            AND verified_at_ms IS NULL
            AND readback_digest IS NULL
        )
        OR (
            delivery_state = 'written'
            AND written_at_ms IS NOT NULL
            AND fsynced_at_ms IS NULL
            AND verified_at_ms IS NULL
            AND readback_digest IS NULL
        )
        OR (
            delivery_state = 'fsynced'
            AND fsynced_at_ms IS NOT NULL
            AND verified_at_ms IS NULL
            AND readback_digest IS NULL
        )
        OR (
            delivery_state = 'verified'
            AND verified_at_ms IS NOT NULL
            AND readback_digest = record_digest
        )
    ),
    FOREIGN KEY (volume_id, target_volume_identity_key)
        REFERENCES volumes(id, identity_key)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, operation_batch_id)
        REFERENCES operation_batches(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (operation_batch_id, operation_item_id)
        REFERENCES operation_items(operation_batch_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_volume_manifest_outbox_delivery
    ON volume_manifest_outbox(
        volume_id,
        delivery_state,
        operation_batch_id,
        sequence_number
    );

CREATE INDEX ix_volume_manifest_outbox_item
    ON volume_manifest_outbox(operation_batch_id, operation_item_id, sequence_number)
    WHERE operation_item_id IS NOT NULL;

CREATE INDEX ix_volume_manifest_outbox_volume_identity
    ON volume_manifest_outbox(volume_id, target_volume_identity_key);

CREATE UNIQUE INDEX ux_volume_manifest_outbox_batch_manifest
    ON volume_manifest_outbox(operation_batch_id)
    WHERE record_kind = 'batch_manifest';

CREATE UNIQUE INDEX ux_volume_manifest_outbox_item_milestone
    ON volume_manifest_outbox(operation_batch_id, operation_item_id, record_kind)
    WHERE record_kind IN ('item_intent', 'item_applied', 'item_verified');

-- Cross-entity provenance is deliberately fail-closed. Composite foreign keys
-- keep ids on the same volume/file; these triggers cover semantic relationships
-- that cannot be expressed as a static key.
CREATE TRIGGER trg_fingerprints_no_update
BEFORE UPDATE ON fingerprints
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'fingerprint evidence is immutable');
END;

CREATE TRIGGER trg_fingerprints_no_delete
BEFORE DELETE ON fingerprints
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'fingerprint evidence is immutable');
END;

CREATE TRIGGER trg_duplicate_groups_evidence_identity_immutable
BEFORE UPDATE OF
    id,
    volume_id,
    scan_run_id,
    group_key,
    match_kind,
    algorithm,
    algorithm_version
ON duplicate_groups
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM duplicate_group_members AS member
    WHERE member.volume_id = OLD.volume_id
      AND member.duplicate_group_id = OLD.id
)
 AND (
    OLD.id IS NOT NEW.id
    OR OLD.volume_id IS NOT NEW.volume_id
    OR OLD.scan_run_id IS NOT NEW.scan_run_id
    OR OLD.group_key IS NOT NEW.group_key
    OR OLD.match_kind IS NOT NEW.match_kind
    OR OLD.algorithm IS NOT NEW.algorithm
    OR OLD.algorithm_version IS NOT NEW.algorithm_version
 )
BEGIN
    SELECT RAISE(ABORT, 'duplicate group evidence identity is immutable');
END;

CREATE TRIGGER trg_duplicate_group_members_evidence_insert
BEFORE INSERT ON duplicate_group_members
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM duplicate_groups AS duplicate_group
    JOIN fingerprints AS evidence
      ON evidence.volume_id = NEW.volume_id
     AND evidence.media_file_id = NEW.media_file_id
     AND evidence.id = NEW.evidence_fingerprint_id
     AND evidence.fingerprint_kind = NEW.evidence_fingerprint_kind
     AND evidence.scan_run_id = duplicate_group.scan_run_id
     AND evidence.algorithm = duplicate_group.algorithm
     AND evidence.algorithm_version = duplicate_group.algorithm_version
    WHERE duplicate_group.volume_id = NEW.volume_id
      AND duplicate_group.id = NEW.duplicate_group_id
      AND (
          (duplicate_group.match_kind = 'exact_bytes'
              AND NEW.evidence_fingerprint_kind = 'exact_bytes')
          OR (duplicate_group.match_kind = 'exact_pixels'
              AND NEW.evidence_fingerprint_kind = 'decoded_pixels')
          OR (duplicate_group.match_kind = 'visual_similarity'
              AND NEW.evidence_fingerprint_kind = 'perceptual')
      )
)
BEGIN
    SELECT RAISE(ABORT, 'duplicate member evidence does not match its group');
END;

CREATE TRIGGER trg_duplicate_group_members_evidence_update
BEFORE UPDATE OF
    volume_id,
    duplicate_group_id,
    media_file_id,
    evidence_fingerprint_id,
    evidence_fingerprint_kind
ON duplicate_group_members
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM duplicate_groups AS duplicate_group
    JOIN fingerprints AS evidence
      ON evidence.volume_id = NEW.volume_id
     AND evidence.media_file_id = NEW.media_file_id
     AND evidence.id = NEW.evidence_fingerprint_id
     AND evidence.fingerprint_kind = NEW.evidence_fingerprint_kind
     AND evidence.scan_run_id = duplicate_group.scan_run_id
     AND evidence.algorithm = duplicate_group.algorithm
     AND evidence.algorithm_version = duplicate_group.algorithm_version
    WHERE duplicate_group.volume_id = NEW.volume_id
      AND duplicate_group.id = NEW.duplicate_group_id
      AND (
          (duplicate_group.match_kind = 'exact_bytes'
              AND NEW.evidence_fingerprint_kind = 'exact_bytes')
          OR (duplicate_group.match_kind = 'exact_pixels'
              AND NEW.evidence_fingerprint_kind = 'decoded_pixels')
          OR (duplicate_group.match_kind = 'visual_similarity'
              AND NEW.evidence_fingerprint_kind = 'perceptual')
      )
)
BEGIN
    SELECT RAISE(ABORT, 'duplicate member evidence does not match its group');
END;

CREATE TRIGGER trg_time_candidates_provenance_insert
BEFORE INSERT ON time_candidates
FOR EACH ROW
WHEN (
    NEW.source_kind = 'duplicate_peer'
    AND NOT EXISTS (
        SELECT 1
        FROM duplicate_groups AS duplicate_group
        JOIN duplicate_group_members AS target_member
          ON target_member.volume_id = duplicate_group.volume_id
         AND target_member.duplicate_group_id = duplicate_group.id
         AND target_member.media_file_id = NEW.media_file_id
        JOIN duplicate_group_members AS source_member
          ON source_member.volume_id = duplicate_group.volume_id
         AND source_member.duplicate_group_id = duplicate_group.id
         AND source_member.media_file_id = NEW.source_media_file_id
        WHERE duplicate_group.volume_id = NEW.volume_id
          AND duplicate_group.id = NEW.source_duplicate_group_id
          AND duplicate_group.scan_run_id = NEW.scan_run_id
          AND duplicate_group.match_kind = 'exact_bytes'
          AND target_member.member_role <> 'excluded'
          AND source_member.member_role <> 'excluded'
    )
) OR (
    NEW.source_kind IN ('xmp_sidecar', 'json_sidecar')
    AND NOT EXISTS (
        SELECT 1
        FROM asset_links AS link
        WHERE link.volume_id = NEW.volume_id
          AND link.id = NEW.source_asset_link_id
          AND link.scan_run_id = NEW.scan_run_id
          AND link.from_media_file_id = NEW.source_media_file_id
          AND link.to_media_file_id = NEW.media_file_id
          AND link.link_kind = 'sidecar_for'
          AND link.relation_state IN ('inferred', 'confirmed')
    )
)
BEGIN
    SELECT RAISE(ABORT, 'time candidate provenance is not actionable');
END;

CREATE TRIGGER trg_time_candidates_provenance_update
BEFORE UPDATE OF
    volume_id,
    media_file_id,
    scan_run_id,
    source_media_file_id,
    source_duplicate_group_id,
    source_asset_link_id,
    source_kind
ON time_candidates
FOR EACH ROW
WHEN (
    NEW.source_kind = 'duplicate_peer'
    AND NOT EXISTS (
        SELECT 1
        FROM duplicate_groups AS duplicate_group
        JOIN duplicate_group_members AS target_member
          ON target_member.volume_id = duplicate_group.volume_id
         AND target_member.duplicate_group_id = duplicate_group.id
         AND target_member.media_file_id = NEW.media_file_id
        JOIN duplicate_group_members AS source_member
          ON source_member.volume_id = duplicate_group.volume_id
         AND source_member.duplicate_group_id = duplicate_group.id
         AND source_member.media_file_id = NEW.source_media_file_id
        WHERE duplicate_group.volume_id = NEW.volume_id
          AND duplicate_group.id = NEW.source_duplicate_group_id
          AND duplicate_group.scan_run_id = NEW.scan_run_id
          AND duplicate_group.match_kind = 'exact_bytes'
          AND target_member.member_role <> 'excluded'
          AND source_member.member_role <> 'excluded'
    )
) OR (
    NEW.source_kind IN ('xmp_sidecar', 'json_sidecar')
    AND NOT EXISTS (
        SELECT 1
        FROM asset_links AS link
        WHERE link.volume_id = NEW.volume_id
          AND link.id = NEW.source_asset_link_id
          AND link.scan_run_id = NEW.scan_run_id
          AND link.from_media_file_id = NEW.source_media_file_id
          AND link.to_media_file_id = NEW.media_file_id
          AND link.link_kind = 'sidecar_for'
          AND link.relation_state IN ('inferred', 'confirmed')
    )
)
BEGIN
    SELECT RAISE(ABORT, 'time candidate provenance is not actionable');
END;

CREATE TRIGGER trg_time_candidates_evidence_immutable
BEFORE UPDATE ON time_candidates
FOR EACH ROW
WHEN OLD.id IS NOT NEW.id
 OR OLD.candidate_key IS NOT NEW.candidate_key
 OR OLD.volume_id IS NOT NEW.volume_id
 OR OLD.media_file_id IS NOT NEW.media_file_id
 OR OLD.scan_run_id IS NOT NEW.scan_run_id
 OR OLD.source_media_file_id IS NOT NEW.source_media_file_id
 OR OLD.source_duplicate_group_id IS NOT NEW.source_duplicate_group_id
 OR OLD.source_asset_link_id IS NOT NEW.source_asset_link_id
 OR OLD.source_kind IS NOT NEW.source_kind
 OR OLD.source_locator IS NOT NEW.source_locator
 OR OLD.raw_value IS NOT NEW.raw_value
 OR OLD.raw_text IS NOT NEW.raw_text
 OR OLD.raw_encoding IS NOT NEW.raw_encoding
 OR OLD.parse_status IS NOT NEW.parse_status
 OR OLD.wall_time IS NOT NEW.wall_time
 OR OLD.utc_offset_minutes IS NOT NEW.utc_offset_minutes
 OR OLD.offset_kind IS NOT NEW.offset_kind
 OR OLD.timezone_name IS NOT NEW.timezone_name
 OR OLD.utc_instant_ns IS NOT NEW.utc_instant_ns
 OR OLD.precision_ns IS NOT NEW.precision_ns
 OR OLD.precision_kind IS NOT NEW.precision_kind
 OR OLD.confidence_basis_points IS NOT NEW.confidence_basis_points
 OR OLD.ambiguity IS NOT NEW.ambiguity
 OR OLD.normalized_at_ms IS NOT NEW.normalized_at_ms
 OR OLD.created_at_ms IS NOT NEW.created_at_ms
BEGIN
    SELECT RAISE(ABORT, 'time candidate evidence is immutable');
END;

CREATE TRIGGER trg_time_candidates_no_delete
BEFORE DELETE ON time_candidates
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'time candidate evidence is immutable');
END;

CREATE TRIGGER trg_operation_items_relationship_insert
BEFORE INSERT ON operation_items
FOR EACH ROW
WHEN NEW.keeper_media_file_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1
    FROM duplicate_group_members AS source_member
    JOIN duplicate_group_members AS keeper_member
      ON keeper_member.volume_id = source_member.volume_id
     AND keeper_member.duplicate_group_id = source_member.duplicate_group_id
     AND keeper_member.media_file_id = NEW.keeper_media_file_id
     AND keeper_member.member_role = 'keeper'
    JOIN duplicate_groups AS duplicate_group
      ON duplicate_group.volume_id = source_member.volume_id
     AND duplicate_group.id = source_member.duplicate_group_id
    JOIN operation_batches AS batch
      ON batch.id = NEW.operation_batch_id
     AND batch.volume_id = NEW.volume_id
    WHERE source_member.volume_id = NEW.volume_id
      AND source_member.id = NEW.duplicate_group_member_id
      AND source_member.media_file_id = NEW.media_file_id
      AND source_member.member_role = 'candidate'
      AND NEW.media_file_id <> NEW.keeper_media_file_id
      AND (
          batch.scan_run_id IS NULL
          OR batch.scan_run_id = duplicate_group.scan_run_id
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'keeper is not the keeper of the source duplicate group');
END;

CREATE TRIGGER trg_operation_items_relationship_update
BEFORE UPDATE OF
    operation_batch_id,
    volume_id,
    media_file_id,
    keeper_media_file_id,
    duplicate_group_member_id
ON operation_items
FOR EACH ROW
WHEN NEW.keeper_media_file_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1
    FROM duplicate_group_members AS source_member
    JOIN duplicate_group_members AS keeper_member
      ON keeper_member.volume_id = source_member.volume_id
     AND keeper_member.duplicate_group_id = source_member.duplicate_group_id
     AND keeper_member.media_file_id = NEW.keeper_media_file_id
     AND keeper_member.member_role = 'keeper'
    JOIN duplicate_groups AS duplicate_group
      ON duplicate_group.volume_id = source_member.volume_id
     AND duplicate_group.id = source_member.duplicate_group_id
    JOIN operation_batches AS batch
      ON batch.id = NEW.operation_batch_id
     AND batch.volume_id = NEW.volume_id
    WHERE source_member.volume_id = NEW.volume_id
      AND source_member.id = NEW.duplicate_group_member_id
      AND source_member.media_file_id = NEW.media_file_id
      AND source_member.member_role = 'candidate'
      AND NEW.media_file_id <> NEW.keeper_media_file_id
      AND (
          batch.scan_run_id IS NULL
          OR batch.scan_run_id = duplicate_group.scan_run_id
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'keeper is not the keeper of the source duplicate group');
END;

CREATE TRIGGER trg_operation_item_dependencies_insert_guard
BEFORE INSERT ON operation_item_dependencies
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM operation_items AS dependent
    JOIN operation_batches AS dependent_batch
      ON dependent_batch.id = dependent.operation_batch_id
    JOIN operation_items AS prerequisite
      ON prerequisite.volume_id = dependent.volume_id
     AND prerequisite.id = NEW.prerequisite_operation_item_id
    JOIN time_candidates AS candidate
      ON candidate.volume_id = dependent.volume_id
     AND candidate.id = NEW.time_candidate_id
    WHERE dependent.volume_id = NEW.volume_id
      AND dependent.id = NEW.dependent_operation_item_id
      AND dependent.operation_kind IN ('quarantine', 'purge')
      AND dependent.media_file_id = candidate.source_media_file_id
      AND prerequisite.operation_kind = 'repair_time'
      AND prerequisite.time_candidate_id = candidate.id
      AND prerequisite.media_file_id = candidate.media_file_id
      AND candidate.is_selected = 1
      AND dependent_batch.sealed_at_ms IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'invalid donor preservation dependency');
END;

CREATE TRIGGER trg_operation_item_dependencies_no_update
BEFORE UPDATE ON operation_item_dependencies
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'operation item dependency is immutable');
END;

CREATE TRIGGER trg_operation_item_dependencies_no_delete
BEFORE DELETE ON operation_item_dependencies
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'operation item dependency is immutable');
END;

CREATE TRIGGER trg_operation_items_dependency_binding_immutable
BEFORE UPDATE OF
    volume_id,
    media_file_id,
    time_candidate_id,
    operation_kind
ON operation_items
FOR EACH ROW
WHEN (
    EXISTS (
        SELECT 1
        FROM operation_item_dependencies AS dependency
        WHERE dependency.volume_id = OLD.volume_id
          AND dependency.dependent_operation_item_id = OLD.id
    )
    AND (
        OLD.volume_id IS NOT NEW.volume_id
        OR OLD.media_file_id IS NOT NEW.media_file_id
        OR OLD.operation_kind IS NOT NEW.operation_kind
    )
) OR (
    EXISTS (
        SELECT 1
        FROM operation_item_dependencies AS dependency
        WHERE dependency.volume_id = OLD.volume_id
          AND dependency.prerequisite_operation_item_id = OLD.id
    )
    AND (
        OLD.volume_id IS NOT NEW.volume_id
        OR OLD.media_file_id IS NOT NEW.media_file_id
        OR OLD.time_candidate_id IS NOT NEW.time_candidate_id
        OR OLD.operation_kind IS NOT NEW.operation_kind
    )
)
BEGIN
    SELECT RAISE(ABORT, 'operation item fields are bound by a donor dependency');
END;

CREATE TRIGGER trg_volume_manifest_outbox_initial_state
BEFORE INSERT ON volume_manifest_outbox
FOR EACH ROW
WHEN NEW.delivery_state <> 'pending' OR NEW.state_version <> 0
BEGIN
    SELECT RAISE(ABORT, 'volume manifest record must start pending at version 0');
END;

CREATE TRIGGER trg_volume_manifest_outbox_plan_guard
BEFORE INSERT ON volume_manifest_outbox
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM operation_batches AS batch
    WHERE batch.id = NEW.operation_batch_id
      AND batch.volume_id = NEW.volume_id
      AND batch.sealed_at_ms IS NOT NULL
      AND batch.manifest_digest IS NOT NULL
      AND batch.manifest_digest = NEW.sealed_plan_digest
) OR (
    NEW.operation_item_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1
        FROM operation_items AS item
        WHERE item.operation_batch_id = NEW.operation_batch_id
          AND item.id = NEW.operation_item_id
          AND item.volume_id = NEW.volume_id
    )
) OR (
    NEW.record_kind = 'item_intent'
    AND NOT EXISTS (
        SELECT 1
        FROM operation_items AS item
        WHERE item.operation_batch_id = NEW.operation_batch_id
          AND item.id = NEW.operation_item_id
          AND item.state = 'planned'
    )
) OR (
    NEW.record_kind = 'item_applied'
    AND NOT EXISTS (
        SELECT 1
        FROM operation_items AS item
        WHERE item.operation_batch_id = NEW.operation_batch_id
          AND item.id = NEW.operation_item_id
          AND item.state = 'in_progress'
    )
) OR (
    NEW.record_kind = 'item_verified'
    AND NOT EXISTS (
        SELECT 1
        FROM operation_items AS item
        WHERE item.operation_batch_id = NEW.operation_batch_id
          AND item.id = NEW.operation_item_id
          AND item.state = 'verifying'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'volume manifest record is not bound to a sealed plan');
END;

CREATE TRIGGER trg_volume_manifest_outbox_chain
BEFORE INSERT ON volume_manifest_outbox
FOR EACH ROW
WHEN (
    NEW.sequence_number = 0
    AND EXISTS (
        SELECT 1
        FROM volume_manifest_outbox AS existing
        WHERE existing.operation_batch_id = NEW.operation_batch_id
    )
) OR (
    NEW.sequence_number > 0
    AND NOT EXISTS (
        SELECT 1
        FROM volume_manifest_outbox AS previous
        WHERE previous.operation_batch_id = NEW.operation_batch_id
          AND previous.sequence_number = NEW.sequence_number - 1
          AND previous.record_digest = NEW.previous_record_digest
          AND previous.volume_id = NEW.volume_id
          AND previous.target_volume_identity_key =
              NEW.target_volume_identity_key
          AND previous.target_mount_session_key =
              NEW.target_mount_session_key
          AND previous.target_relative_path = NEW.target_relative_path
          AND previous.sealed_plan_digest = NEW.sealed_plan_digest
          AND previous.serialization_version = NEW.serialization_version
          AND previous.hash_algorithm = NEW.hash_algorithm
    )
)
BEGIN
    SELECT RAISE(ABORT, 'volume manifest hash chain is not contiguous');
END;

CREATE TRIGGER trg_volume_manifest_outbox_record_immutable
BEFORE UPDATE ON volume_manifest_outbox
FOR EACH ROW
WHEN OLD.outbox_key IS NOT NEW.outbox_key
 OR OLD.volume_id IS NOT NEW.volume_id
 OR OLD.operation_batch_id IS NOT NEW.operation_batch_id
 OR OLD.operation_item_id IS NOT NEW.operation_item_id
 OR OLD.record_kind IS NOT NEW.record_kind
 OR OLD.sequence_number IS NOT NEW.sequence_number
 OR OLD.target_volume_identity_key IS NOT NEW.target_volume_identity_key
 OR OLD.target_mount_session_key IS NOT NEW.target_mount_session_key
 OR OLD.target_relative_path IS NOT NEW.target_relative_path
 OR OLD.sealed_plan_digest IS NOT NEW.sealed_plan_digest
 OR OLD.serialization_version IS NOT NEW.serialization_version
 OR OLD.hash_algorithm IS NOT NEW.hash_algorithm
 OR OLD.record_payload IS NOT NEW.record_payload
 OR OLD.payload_digest IS NOT NEW.payload_digest
 OR OLD.previous_record_digest IS NOT NEW.previous_record_digest
 OR OLD.record_digest IS NOT NEW.record_digest
 OR OLD.local_recorded_at_ms IS NOT NEW.local_recorded_at_ms
 OR OLD.created_at_ms IS NOT NEW.created_at_ms
BEGIN
    SELECT RAISE(ABORT, 'volume manifest record payload is immutable');
END;

CREATE TRIGGER trg_volume_manifest_outbox_evidence_immutable
BEFORE UPDATE ON volume_manifest_outbox
FOR EACH ROW
WHEN (
    OLD.target_offset_bytes IS NOT NULL
    AND OLD.target_offset_bytes IS NOT NEW.target_offset_bytes
) OR (
    OLD.target_length_bytes IS NOT NULL
    AND OLD.target_length_bytes IS NOT NEW.target_length_bytes
) OR (
    OLD.written_at_ms IS NOT NULL
    AND OLD.written_at_ms IS NOT NEW.written_at_ms
) OR (
    OLD.fsynced_at_ms IS NOT NULL
    AND OLD.fsynced_at_ms IS NOT NEW.fsynced_at_ms
) OR (
    OLD.verified_at_ms IS NOT NULL
    AND OLD.verified_at_ms IS NOT NEW.verified_at_ms
) OR (
    OLD.readback_digest IS NOT NULL
    AND OLD.readback_digest IS NOT NEW.readback_digest
)
BEGIN
    SELECT RAISE(ABORT, 'volume manifest delivery evidence is immutable');
END;

CREATE TRIGGER trg_volume_manifest_outbox_state_version
BEFORE UPDATE ON volume_manifest_outbox
FOR EACH ROW
WHEN (
    OLD.delivery_state = NEW.delivery_state
    AND OLD.state_version <> NEW.state_version
) OR (
    OLD.delivery_state <> NEW.delivery_state
    AND NEW.state_version <> OLD.state_version + 1
)
BEGIN
    SELECT RAISE(ABORT, 'invalid volume manifest state_version');
END;

CREATE TRIGGER trg_volume_manifest_outbox_state_transition
BEFORE UPDATE OF delivery_state ON volume_manifest_outbox
FOR EACH ROW
WHEN OLD.delivery_state <> NEW.delivery_state
 AND NOT (
    (OLD.delivery_state = 'pending'
        AND NEW.delivery_state IN ('written', 'needs_reconciliation'))
    OR (OLD.delivery_state = 'written'
        AND NEW.delivery_state IN ('fsynced', 'needs_reconciliation'))
    OR (OLD.delivery_state = 'fsynced'
        AND NEW.delivery_state IN ('verified', 'needs_reconciliation'))
    OR (OLD.delivery_state = 'verified'
        AND NEW.delivery_state = 'needs_reconciliation')
    OR (OLD.delivery_state = 'needs_reconciliation'
        AND NEW.delivery_state IN ('pending', 'written', 'fsynced', 'verified'))
 )
BEGIN
    SELECT RAISE(ABORT, 'invalid volume manifest state transition');
END;

CREATE TRIGGER trg_volume_manifest_outbox_delivery_order
BEFORE UPDATE OF delivery_state ON volume_manifest_outbox
FOR EACH ROW
WHEN NEW.delivery_state = 'written'
 AND OLD.delivery_state <> NEW.delivery_state
 AND (
    (NEW.sequence_number = 0 AND NEW.target_offset_bytes <> 0)
    OR (
        NEW.sequence_number > 0
        AND NOT EXISTS (
            SELECT 1
            FROM volume_manifest_outbox AS previous
            WHERE previous.operation_batch_id = NEW.operation_batch_id
              AND previous.sequence_number = NEW.sequence_number - 1
              AND previous.delivery_state = 'verified'
              AND NEW.target_offset_bytes =
                  previous.target_offset_bytes + previous.target_length_bytes
        )
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'volume manifest predecessor is not durably verified');
END;

CREATE TRIGGER trg_volume_manifest_outbox_event_created
AFTER INSERT ON volume_manifest_outbox
FOR EACH ROW
BEGIN
    INSERT INTO operation_events (
        event_key,
        operation_batch_id,
        operation_item_id,
        event_scope,
        event_kind,
        from_state,
        to_state,
        state_version,
        actor,
        occurred_at_ms,
        details_json
    ) VALUES (
        'outbox:' || NEW.id || ':state:0',
        NEW.operation_batch_id,
        NEW.operation_item_id,
        CASE WHEN NEW.operation_item_id IS NULL THEN 'batch' ELSE 'item' END,
        'volume_manifest',
        NULL,
        NEW.delivery_state,
        NEW.state_version,
        'volume_manifest_outbox',
        NEW.created_at_ms,
        '{"outbox_id":' || NEW.id || ',"sequence_number":'
            || NEW.sequence_number || '}'
    );
END;

CREATE TRIGGER trg_volume_manifest_outbox_event_transition
AFTER UPDATE OF delivery_state ON volume_manifest_outbox
FOR EACH ROW
WHEN OLD.delivery_state <> NEW.delivery_state
BEGIN
    INSERT INTO operation_events (
        event_key,
        operation_batch_id,
        operation_item_id,
        event_scope,
        event_kind,
        from_state,
        to_state,
        state_version,
        actor,
        occurred_at_ms,
        details_json
    ) VALUES (
        'outbox:' || NEW.id || ':state:' || NEW.state_version,
        NEW.operation_batch_id,
        NEW.operation_item_id,
        CASE WHEN NEW.operation_item_id IS NULL THEN 'batch' ELSE 'item' END,
        'volume_manifest',
        OLD.delivery_state,
        NEW.delivery_state,
        NEW.state_version,
        'volume_manifest_outbox',
        NEW.updated_at_ms,
        '{"outbox_id":' || NEW.id || ',"sequence_number":'
            || NEW.sequence_number || '}'
    );
END;

CREATE TRIGGER trg_volume_manifest_outbox_no_delete
BEFORE DELETE ON volume_manifest_outbox
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'volume_manifest_outbox is append-only');
END;

-- State versions provide optimistic concurrency. Repeating an update that leaves
-- the state unchanged must leave the version unchanged, making retries idempotent.
CREATE TRIGGER trg_operation_batches_initial_state
BEFORE INSERT ON operation_batches
FOR EACH ROW
WHEN NEW.state <> 'planned'
 OR NEW.state_version <> 0
 OR NEW.volume_manifest_outbox_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'operation batch must start planned, unbound, at version 0');
END;

CREATE TRIGGER trg_operation_batches_dry_run_cannot_start
BEFORE UPDATE OF state ON operation_batches
FOR EACH ROW
WHEN NEW.state = 'running'
 AND OLD.state <> NEW.state
 AND NEW.is_dry_run = 1
BEGIN
    SELECT RAISE(ABORT, 'dry-run batches cannot enter an execution state');
END;

CREATE TRIGGER trg_operation_batches_sealed_plan
BEFORE UPDATE ON operation_batches
FOR EACH ROW
WHEN OLD.sealed_at_ms IS NOT NULL
 AND (
    OLD.batch_key IS NOT NEW.batch_key
    OR OLD.volume_id IS NOT NEW.volume_id
    OR OLD.scan_run_id IS NOT NEW.scan_run_id
    OR OLD.capability_profile_id IS NOT NEW.capability_profile_id
    OR OLD.operation_kind IS NOT NEW.operation_kind
    OR OLD.is_dry_run IS NOT NEW.is_dry_run
    OR OLD.requires_confirmation IS NOT NEW.requires_confirmation
    OR OLD.sealed_at_ms IS NOT NEW.sealed_at_ms
    OR OLD.manifest_digest IS NOT NEW.manifest_digest
    OR OLD.policy_json IS NOT NEW.policy_json
 )
BEGIN
    SELECT RAISE(ABORT, 'sealed operation batch plan is immutable');
END;

CREATE TRIGGER trg_operation_batches_donor_dependency_seal_guard
BEFORE UPDATE OF sealed_at_ms ON operation_batches
FOR EACH ROW
WHEN OLD.sealed_at_ms IS NULL
 AND NEW.sealed_at_ms IS NOT NULL
 AND EXISTS (
    SELECT 1
    FROM operation_items AS dependent
    JOIN time_candidates AS candidate
      ON candidate.volume_id = dependent.volume_id
     AND candidate.source_media_file_id = dependent.media_file_id
     AND candidate.is_selected = 1
    WHERE dependent.operation_batch_id = NEW.id
      AND dependent.operation_kind IN ('quarantine', 'purge')
      AND NOT EXISTS (
          SELECT 1
          FROM operation_item_dependencies AS dependency
          JOIN operation_items AS prerequisite
            ON prerequisite.volume_id = dependency.volume_id
           AND prerequisite.id = dependency.prerequisite_operation_item_id
          WHERE dependency.volume_id = dependent.volume_id
            AND dependency.dependent_operation_item_id = dependent.id
            AND dependency.time_candidate_id = candidate.id
            AND prerequisite.operation_kind = 'repair_time'
            AND prerequisite.time_candidate_id = candidate.id
            AND prerequisite.media_file_id = candidate.media_file_id
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'cannot seal destructive donor without repair dependency');
END;

CREATE TRIGGER trg_operation_batches_item_provenance_seal_guard
BEFORE UPDATE OF sealed_at_ms ON operation_batches
FOR EACH ROW
WHEN OLD.sealed_at_ms IS NULL
 AND NEW.sealed_at_ms IS NOT NULL
 AND NEW.scan_run_id IS NOT NULL
 AND EXISTS (
    SELECT 1
    FROM operation_items AS item
    WHERE item.operation_batch_id = NEW.id
      AND (
          (
              item.duplicate_group_member_id IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM duplicate_group_members AS member
                  JOIN duplicate_groups AS duplicate_group
                    ON duplicate_group.volume_id = member.volume_id
                   AND duplicate_group.id = member.duplicate_group_id
                  WHERE member.volume_id = item.volume_id
                    AND member.id = item.duplicate_group_member_id
                    AND duplicate_group.scan_run_id = NEW.scan_run_id
              )
          )
          OR (
              item.time_candidate_id IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM time_candidates AS candidate
                  WHERE candidate.volume_id = item.volume_id
                    AND candidate.id = item.time_candidate_id
                    AND candidate.scan_run_id = NEW.scan_run_id
              )
          )
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'cannot seal batch with cross-scan item provenance');
END;

CREATE TRIGGER trg_operation_batches_confirmation_immutable
BEFORE UPDATE OF confirmed_at_ms ON operation_batches
FOR EACH ROW
WHEN OLD.confirmed_at_ms IS NOT NULL
 AND OLD.confirmed_at_ms IS NOT NEW.confirmed_at_ms
BEGIN
    SELECT RAISE(ABORT, 'operation batch confirmation is immutable');
END;

CREATE TRIGGER trg_operation_batches_manifest_binding
BEFORE UPDATE OF volume_manifest_outbox_id ON operation_batches
FOR EACH ROW
WHEN (
    OLD.volume_manifest_outbox_id IS NOT NULL
    AND OLD.volume_manifest_outbox_id IS NOT NEW.volume_manifest_outbox_id
) OR (
    NEW.volume_manifest_outbox_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1
        FROM volume_manifest_outbox AS outbox
        WHERE outbox.id = NEW.volume_manifest_outbox_id
          AND outbox.volume_id = NEW.volume_id
          AND outbox.operation_batch_id = NEW.id
          AND outbox.operation_item_id IS NULL
          AND outbox.record_kind = 'batch_manifest'
          AND outbox.sequence_number = 0
          AND outbox.sealed_plan_digest = NEW.manifest_digest
          AND outbox.delivery_state = 'verified'
          AND outbox.readback_digest = outbox.record_digest
    )
)
BEGIN
    SELECT RAISE(ABORT, 'batch manifest binding must reference verified volume record');
END;

CREATE TRIGGER trg_operation_batches_state_version
BEFORE UPDATE ON operation_batches
FOR EACH ROW
WHEN (
    OLD.state = NEW.state
    AND OLD.state_version <> NEW.state_version
) OR (
    OLD.state <> NEW.state
    AND NEW.state_version <> OLD.state_version + 1
)
BEGIN
    SELECT RAISE(ABORT, 'invalid operation batch state_version');
END;

CREATE TRIGGER trg_operation_batches_state_transition
BEFORE UPDATE OF state ON operation_batches
FOR EACH ROW
WHEN OLD.state <> NEW.state
 AND NOT (
    (OLD.state = 'planned' AND NEW.state IN ('running', 'cancelled'))
    OR (OLD.state = 'running' AND NEW.state IN (
        'paused', 'completed', 'failed', 'cancelled', 'needs_reconciliation'
    ))
    OR (OLD.state = 'paused' AND NEW.state IN (
        'running', 'cancelled', 'needs_reconciliation'
    ))
    OR (OLD.state = 'failed' AND NEW.state IN (
        'running', 'cancelled', 'needs_reconciliation'
    ))
    OR (OLD.state = 'needs_reconciliation' AND NEW.state IN (
        'running', 'completed', 'failed'
    ))
    OR (OLD.state = 'completed' AND NEW.state = 'needs_reconciliation')
 )
BEGIN
    SELECT RAISE(ABORT, 'invalid operation batch state transition');
END;

CREATE TRIGGER trg_operation_batches_start_guard
BEFORE UPDATE OF state ON operation_batches
FOR EACH ROW
WHEN NEW.state = 'running'
 AND OLD.state <> NEW.state
 AND (
    NEW.sealed_at_ms IS NULL
    OR NEW.manifest_digest IS NULL
    OR (NEW.requires_confirmation = 1 AND NEW.confirmed_at_ms IS NULL)
    OR NOT EXISTS (
        SELECT 1
        FROM volume_manifest_outbox AS outbox
        WHERE outbox.id = NEW.volume_manifest_outbox_id
          AND outbox.volume_id = NEW.volume_id
          AND outbox.operation_batch_id = NEW.id
          AND outbox.operation_item_id IS NULL
          AND outbox.record_kind = 'batch_manifest'
          AND outbox.sealed_plan_digest = NEW.manifest_digest
          AND outbox.delivery_state = 'verified'
          AND outbox.readback_digest = outbox.record_digest
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'operation batch lacks sealed, confirmed, dual-durable manifest');
END;

CREATE TRIGGER trg_operation_batches_complete_guard
BEFORE UPDATE OF state ON operation_batches
FOR EACH ROW
WHEN NEW.state = 'completed'
 AND OLD.state <> NEW.state
 AND EXISTS (
    SELECT 1
    FROM operation_items AS item
    WHERE item.operation_batch_id = NEW.id
      AND item.state NOT IN ('succeeded', 'skipped', 'rolled_back')
 )
BEGIN
    SELECT RAISE(ABORT, 'operation batch has non-terminal items');
END;

CREATE TRIGGER trg_operation_batches_cancel_guard
BEFORE UPDATE OF state ON operation_batches
FOR EACH ROW
WHEN NEW.state = 'cancelled'
 AND OLD.state <> NEW.state
 AND EXISTS (
    SELECT 1
    FROM operation_items AS item
    WHERE item.operation_batch_id = NEW.id
      AND item.state NOT IN (
          'succeeded', 'failed', 'skipped', 'cancelled', 'rolled_back'
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'operation batch has active or uncertain items');
END;

CREATE TRIGGER trg_operation_items_initial_state
BEFORE INSERT ON operation_items
FOR EACH ROW
WHEN NEW.state <> 'planned'
 OR NEW.state_version <> 0
 OR NEW.volume_intent_outbox_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'operation item must start planned, unbound, at version 0');
END;

CREATE TRIGGER trg_operation_items_no_insert_after_seal
BEFORE INSERT ON operation_items
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM operation_batches AS batch
    WHERE batch.id = NEW.operation_batch_id
      AND batch.sealed_at_ms IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'cannot add an item to a sealed operation batch');
END;

CREATE TRIGGER trg_operation_items_sealed_plan
BEFORE UPDATE ON operation_items
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM operation_batches AS batch
    WHERE batch.id = OLD.operation_batch_id
      AND batch.sealed_at_ms IS NOT NULL
)
 AND (
    OLD.operation_batch_id IS NOT NEW.operation_batch_id
    OR OLD.volume_id IS NOT NEW.volume_id
    OR OLD.item_key IS NOT NEW.item_key
    OR OLD.media_file_id IS NOT NEW.media_file_id
    OR OLD.keeper_media_file_id IS NOT NEW.keeper_media_file_id
    OR OLD.duplicate_group_member_id IS NOT NEW.duplicate_group_member_id
    OR OLD.time_candidate_id IS NOT NEW.time_candidate_id
    OR OLD.precondition_fingerprint_id IS NOT NEW.precondition_fingerprint_id
    OR OLD.precondition_fingerprint_kind IS NOT NEW.precondition_fingerprint_kind
    OR OLD.operation_kind IS NOT NEW.operation_kind
    OR OLD.source_relative_path_snapshot IS NOT NEW.source_relative_path_snapshot
    OR OLD.source_relative_path_raw IS NOT NEW.source_relative_path_raw
    OR OLD.source_path_encoding IS NOT NEW.source_path_encoding
    OR OLD.destination_relative_path IS NOT NEW.destination_relative_path
    OR OLD.destination_relative_path_raw IS NOT NEW.destination_relative_path_raw
    OR OLD.destination_path_encoding IS NOT NEW.destination_path_encoding
    OR OLD.expected_size_bytes IS NOT NEW.expected_size_bytes
    OR OLD.expected_modified_time_ns IS NOT NEW.expected_modified_time_ns
    OR OLD.expected_digest IS NOT NEW.expected_digest
    OR OLD.before_metadata_json IS NOT NEW.before_metadata_json
    OR OLD.requested_change_json IS NOT NEW.requested_change_json
 )
BEGIN
    SELECT RAISE(ABORT, 'sealed operation item plan is immutable');
END;

CREATE TRIGGER trg_operation_items_batch_kind_insert
BEFORE INSERT ON operation_items
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM operation_batches AS batch
    WHERE batch.id = NEW.operation_batch_id
      AND batch.volume_id = NEW.volume_id
      AND (
          batch.operation_kind = 'mixed'
          OR batch.operation_kind = NEW.operation_kind
      )
)
BEGIN
    SELECT RAISE(ABORT, 'operation item kind does not match its batch');
END;

CREATE TRIGGER trg_operation_items_batch_kind_update
BEFORE UPDATE OF operation_batch_id, volume_id, operation_kind ON operation_items
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM operation_batches AS batch
    WHERE batch.id = NEW.operation_batch_id
      AND batch.volume_id = NEW.volume_id
      AND (
          batch.operation_kind = 'mixed'
          OR batch.operation_kind = NEW.operation_kind
      )
)
BEGIN
    SELECT RAISE(ABORT, 'operation item kind does not match its batch');
END;

CREATE TRIGGER trg_operation_items_intent_binding
BEFORE UPDATE OF volume_intent_outbox_id ON operation_items
FOR EACH ROW
WHEN (
    OLD.volume_intent_outbox_id IS NOT NULL
    AND OLD.volume_intent_outbox_id IS NOT NEW.volume_intent_outbox_id
) OR (
    NEW.volume_intent_outbox_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1
        FROM volume_manifest_outbox AS outbox
        WHERE outbox.id = NEW.volume_intent_outbox_id
          AND outbox.volume_id = NEW.volume_id
          AND outbox.operation_batch_id = NEW.operation_batch_id
          AND outbox.operation_item_id = NEW.id
          AND outbox.record_kind = 'item_intent'
          AND outbox.sealed_plan_digest = (
              SELECT batch.manifest_digest
              FROM operation_batches AS batch
              WHERE batch.id = NEW.operation_batch_id
          )
          AND outbox.delivery_state = 'verified'
          AND outbox.readback_digest = outbox.record_digest
    )
)
BEGIN
    SELECT RAISE(ABORT, 'item intent binding must reference verified volume record');
END;

CREATE TRIGGER trg_operation_items_start_guard
BEFORE UPDATE OF state ON operation_items
FOR EACH ROW
WHEN NEW.state = 'in_progress'
 AND OLD.state <> NEW.state
 AND NOT EXISTS (
    SELECT 1
    FROM operation_batches AS batch
    WHERE batch.id = NEW.operation_batch_id
      AND batch.state = 'running'
      AND batch.sealed_at_ms IS NOT NULL
      AND batch.manifest_digest IS NOT NULL
      AND EXISTS (
          SELECT 1
          FROM volume_manifest_outbox AS batch_outbox
          WHERE batch_outbox.id = batch.volume_manifest_outbox_id
            AND batch_outbox.volume_id = batch.volume_id
            AND batch_outbox.operation_batch_id = batch.id
            AND batch_outbox.operation_item_id IS NULL
            AND batch_outbox.record_kind = 'batch_manifest'
            AND batch_outbox.sealed_plan_digest = batch.manifest_digest
            AND batch_outbox.delivery_state = 'verified'
            AND batch_outbox.readback_digest = batch_outbox.record_digest
      )
      AND (
          batch.requires_confirmation = 0
          OR batch.confirmed_at_ms IS NOT NULL
      )
      AND EXISTS (
          SELECT 1
          FROM volume_manifest_outbox AS item_outbox
          WHERE item_outbox.id = NEW.volume_intent_outbox_id
            AND item_outbox.volume_id = NEW.volume_id
            AND item_outbox.operation_batch_id = NEW.operation_batch_id
            AND item_outbox.operation_item_id = NEW.id
            AND item_outbox.record_kind = 'item_intent'
            AND item_outbox.sealed_plan_digest = batch.manifest_digest
            AND item_outbox.delivery_state = 'verified'
            AND item_outbox.readback_digest = item_outbox.record_digest
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'operation item lacks a running dual-durable intent');
END;

CREATE TRIGGER trg_operation_items_destructive_start_guard
BEFORE UPDATE OF state ON operation_items
FOR EACH ROW
WHEN NEW.state = 'in_progress'
 AND OLD.state <> NEW.state
 AND NEW.operation_kind IN ('quarantine', 'purge')
 AND NOT EXISTS (
    SELECT 1
    FROM duplicate_group_members AS source_member
    JOIN duplicate_groups AS duplicate_group
      ON duplicate_group.volume_id = source_member.volume_id
     AND duplicate_group.id = source_member.duplicate_group_id
    JOIN fingerprints AS source_evidence
      ON source_evidence.volume_id = source_member.volume_id
     AND source_evidence.media_file_id = source_member.media_file_id
     AND source_evidence.id = source_member.evidence_fingerprint_id
     AND source_evidence.fingerprint_kind = 'exact_bytes'
    JOIN duplicate_group_members AS keeper_member
      ON keeper_member.volume_id = source_member.volume_id
     AND keeper_member.duplicate_group_id = source_member.duplicate_group_id
     AND keeper_member.media_file_id = NEW.keeper_media_file_id
     AND keeper_member.member_role = 'keeper'
    JOIN fingerprints AS keeper_evidence
      ON keeper_evidence.volume_id = keeper_member.volume_id
     AND keeper_evidence.media_file_id = keeper_member.media_file_id
     AND keeper_evidence.id = keeper_member.evidence_fingerprint_id
     AND keeper_evidence.fingerprint_kind = 'exact_bytes'
    WHERE source_member.volume_id = NEW.volume_id
      AND source_member.id = NEW.duplicate_group_member_id
      AND source_member.media_file_id = NEW.media_file_id
      AND source_member.member_role = 'candidate'
      AND NEW.media_file_id <> NEW.keeper_media_file_id
      AND duplicate_group.match_kind = 'exact_bytes'
      AND duplicate_group.algorithm = 'blake3'
      AND duplicate_group.review_state = 'approved'
      AND source_evidence.id = NEW.precondition_fingerprint_id
      AND source_evidence.algorithm = duplicate_group.algorithm
      AND source_evidence.algorithm_version =
          duplicate_group.algorithm_version
      AND source_evidence.observed_size_bytes = NEW.expected_size_bytes
      AND source_evidence.digest = NEW.expected_digest
      AND keeper_evidence.algorithm = source_evidence.algorithm
      AND keeper_evidence.algorithm_version = source_evidence.algorithm_version
      AND keeper_evidence.parameters_hash = source_evidence.parameters_hash
      AND keeper_evidence.observed_size_bytes = NEW.expected_size_bytes
      AND keeper_evidence.digest = NEW.expected_digest
 )
BEGIN
    SELECT RAISE(ABORT, 'destructive item lacks approved equal-byte keeper evidence');
END;

CREATE TRIGGER trg_operation_items_donor_dependency_start_guard
BEFORE UPDATE OF state ON operation_items
FOR EACH ROW
WHEN NEW.state = 'in_progress'
 AND OLD.state <> NEW.state
 AND NEW.operation_kind IN ('quarantine', 'purge')
 AND (
    EXISTS (
        SELECT 1
        FROM operation_item_dependencies AS dependency
        WHERE dependency.volume_id = NEW.volume_id
          AND dependency.dependent_operation_item_id = NEW.id
          AND NOT EXISTS (
              SELECT 1
              FROM operation_items AS prerequisite
              JOIN time_candidates AS candidate
                ON candidate.volume_id = prerequisite.volume_id
               AND candidate.id = dependency.time_candidate_id
              WHERE prerequisite.volume_id = dependency.volume_id
                AND prerequisite.id =
                    dependency.prerequisite_operation_item_id
                AND prerequisite.operation_kind = 'repair_time'
                AND prerequisite.time_candidate_id = candidate.id
                AND prerequisite.media_file_id = candidate.media_file_id
                AND candidate.source_media_file_id = NEW.media_file_id
                AND prerequisite.state = 'succeeded'
          )
    )
    OR EXISTS (
        SELECT 1
        FROM time_candidates AS candidate
        WHERE candidate.volume_id = NEW.volume_id
          AND candidate.source_media_file_id = NEW.media_file_id
          AND candidate.is_selected = 1
          AND NOT EXISTS (
              SELECT 1
              FROM operation_item_dependencies AS dependency
              JOIN operation_items AS prerequisite
                ON prerequisite.volume_id = dependency.volume_id
               AND prerequisite.id =
                   dependency.prerequisite_operation_item_id
              WHERE dependency.volume_id = NEW.volume_id
                AND dependency.dependent_operation_item_id = NEW.id
                AND dependency.time_candidate_id = candidate.id
                AND prerequisite.operation_kind = 'repair_time'
                AND prerequisite.time_candidate_id = candidate.id
                AND prerequisite.media_file_id = candidate.media_file_id
                AND prerequisite.state = 'succeeded'
          )
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'time donor repair dependency is not satisfied');
END;

CREATE TRIGGER trg_operation_items_repair_time_start_guard
BEFORE UPDATE OF state ON operation_items
FOR EACH ROW
WHEN NEW.state = 'in_progress'
 AND OLD.state <> NEW.state
 AND NEW.operation_kind = 'repair_time'
 AND NOT EXISTS (
    SELECT 1
    FROM time_candidates AS candidate
    JOIN operation_batches AS batch
      ON batch.id = NEW.operation_batch_id
     AND batch.volume_id = NEW.volume_id
    WHERE candidate.volume_id = NEW.volume_id
      AND candidate.media_file_id = NEW.media_file_id
      AND candidate.id = NEW.time_candidate_id
      AND (
          batch.scan_run_id IS NULL
          OR batch.scan_run_id = candidate.scan_run_id
      )
      AND candidate.is_selected = 1
      AND candidate.parse_status = 'parsed'
      AND candidate.wall_time IS NOT NULL
      AND candidate.utc_instant_ns IS NOT NULL
      AND (
          candidate.source_kind NOT IN (
              'duplicate_peer', 'xmp_sidecar', 'json_sidecar'
          )
          OR (
              candidate.source_kind = 'duplicate_peer'
              AND EXISTS (
                  SELECT 1
                  FROM duplicate_groups AS duplicate_group
                  JOIN duplicate_group_members AS target_member
                    ON target_member.volume_id = duplicate_group.volume_id
                   AND target_member.duplicate_group_id = duplicate_group.id
                   AND target_member.media_file_id = candidate.media_file_id
                  JOIN duplicate_group_members AS source_member
                    ON source_member.volume_id = duplicate_group.volume_id
                   AND source_member.duplicate_group_id = duplicate_group.id
                   AND source_member.media_file_id =
                       candidate.source_media_file_id
                  WHERE duplicate_group.volume_id = candidate.volume_id
                    AND duplicate_group.id =
                        candidate.source_duplicate_group_id
                    AND duplicate_group.scan_run_id = candidate.scan_run_id
                    AND duplicate_group.match_kind = 'exact_bytes'
                    AND duplicate_group.review_state = 'approved'
                    AND target_member.member_role <> 'excluded'
                    AND source_member.member_role <> 'excluded'
              )
          )
          OR (
              candidate.source_kind IN ('xmp_sidecar', 'json_sidecar')
              AND EXISTS (
                  SELECT 1
                  FROM asset_links AS link
                  WHERE link.volume_id = candidate.volume_id
                    AND link.id = candidate.source_asset_link_id
                    AND link.scan_run_id = candidate.scan_run_id
                    AND link.from_media_file_id =
                        candidate.source_media_file_id
                    AND link.to_media_file_id = candidate.media_file_id
                    AND link.link_kind = 'sidecar_for'
                    AND link.relation_state = 'confirmed'
              )
          )
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'repair-time item lacks a selected unambiguous instant');
END;

CREATE TRIGGER trg_operation_items_applied_manifest_guard
BEFORE UPDATE OF state ON operation_items
FOR EACH ROW
WHEN NEW.state = 'applied'
 AND OLD.state <> NEW.state
 AND NOT EXISTS (
    SELECT 1
    FROM volume_manifest_outbox AS outbox
    JOIN operation_batches AS batch
      ON batch.id = NEW.operation_batch_id
     AND batch.volume_id = NEW.volume_id
    WHERE outbox.volume_id = NEW.volume_id
      AND outbox.operation_batch_id = NEW.operation_batch_id
      AND outbox.operation_item_id = NEW.id
      AND outbox.record_kind = 'item_applied'
      AND outbox.sealed_plan_digest = batch.manifest_digest
      AND outbox.delivery_state = 'verified'
      AND outbox.readback_digest = outbox.record_digest
 )
BEGIN
    SELECT RAISE(ABORT, 'applied item lacks dual-durable result record');
END;

CREATE TRIGGER trg_operation_items_succeeded_manifest_guard
BEFORE UPDATE OF state ON operation_items
FOR EACH ROW
WHEN NEW.state = 'succeeded'
 AND OLD.state <> NEW.state
 AND NOT EXISTS (
    SELECT 1
    FROM volume_manifest_outbox AS outbox
    JOIN operation_batches AS batch
      ON batch.id = NEW.operation_batch_id
     AND batch.volume_id = NEW.volume_id
    WHERE outbox.volume_id = NEW.volume_id
      AND outbox.operation_batch_id = NEW.operation_batch_id
      AND outbox.operation_item_id = NEW.id
      AND outbox.record_kind = 'item_verified'
      AND outbox.sealed_plan_digest = batch.manifest_digest
      AND outbox.delivery_state = 'verified'
      AND outbox.readback_digest = outbox.record_digest
 )
BEGIN
    SELECT RAISE(ABORT, 'succeeded item lacks dual-durable verification record');
END;

CREATE TRIGGER trg_operation_items_state_version
BEFORE UPDATE ON operation_items
FOR EACH ROW
WHEN (
    OLD.state = NEW.state
    AND OLD.state_version <> NEW.state_version
) OR (
    OLD.state <> NEW.state
    AND NEW.state_version <> OLD.state_version + 1
)
BEGIN
    SELECT RAISE(ABORT, 'invalid operation item state_version');
END;

CREATE TRIGGER trg_operation_items_state_transition
BEFORE UPDATE OF state ON operation_items
FOR EACH ROW
WHEN OLD.state <> NEW.state
 AND NOT (
    (OLD.state = 'planned' AND NEW.state IN (
        'in_progress', 'skipped', 'cancelled'
    ))
    OR (OLD.state = 'in_progress' AND NEW.state IN (
        'applied', 'failed', 'needs_reconciliation'
    ))
    OR (OLD.state = 'applied' AND NEW.state IN (
        'verifying', 'failed', 'rolled_back', 'needs_reconciliation'
    ))
    OR (OLD.state = 'verifying' AND NEW.state IN (
        'succeeded', 'failed', 'rolled_back', 'needs_reconciliation'
    ))
    OR (OLD.state = 'failed' AND NEW.state IN (
        'in_progress', 'cancelled', 'needs_reconciliation'
    ))
    OR (OLD.state = 'needs_reconciliation' AND NEW.state IN (
        'in_progress', 'succeeded', 'failed', 'rolled_back'
    ))
    OR (OLD.state = 'succeeded' AND NEW.state = 'needs_reconciliation')
    OR (OLD.state = 'rolled_back' AND NEW.state = 'needs_reconciliation')
 )
BEGIN
    SELECT RAISE(ABORT, 'invalid operation item state transition');
END;

-- Trigger-generated events are naturally idempotent: only a real state change
-- creates an event, and the event key includes the monotonically increasing
-- state_version.
CREATE TRIGGER trg_operation_batches_event_created
AFTER INSERT ON operation_batches
FOR EACH ROW
BEGIN
    INSERT INTO operation_events (
        event_key,
        operation_batch_id,
        operation_item_id,
        event_scope,
        event_kind,
        from_state,
        to_state,
        state_version,
        actor,
        occurred_at_ms
    ) VALUES (
        'batch:' || NEW.id || ':state:0',
        NEW.id,
        NULL,
        'batch',
        'created',
        NULL,
        NEW.state,
        NEW.state_version,
        'state_machine',
        NEW.created_at_ms
    );
END;

CREATE TRIGGER trg_operation_batches_event_transition
AFTER UPDATE OF state ON operation_batches
FOR EACH ROW
WHEN OLD.state <> NEW.state
BEGIN
    INSERT INTO operation_events (
        event_key,
        operation_batch_id,
        operation_item_id,
        event_scope,
        event_kind,
        from_state,
        to_state,
        state_version,
        actor,
        occurred_at_ms
    ) VALUES (
        'batch:' || NEW.id || ':state:' || NEW.state_version,
        NEW.id,
        NULL,
        'batch',
        'state_transition',
        OLD.state,
        NEW.state,
        NEW.state_version,
        'state_machine',
        NEW.updated_at_ms
    );
END;

CREATE TRIGGER trg_operation_items_event_created
AFTER INSERT ON operation_items
FOR EACH ROW
BEGIN
    INSERT INTO operation_events (
        event_key,
        operation_batch_id,
        operation_item_id,
        event_scope,
        event_kind,
        from_state,
        to_state,
        state_version,
        actor,
        occurred_at_ms
    ) VALUES (
        'item:' || NEW.id || ':state:0',
        NEW.operation_batch_id,
        NEW.id,
        'item',
        'created',
        NULL,
        NEW.state,
        NEW.state_version,
        'state_machine',
        NEW.created_at_ms
    );
END;

CREATE TRIGGER trg_operation_items_event_transition
AFTER UPDATE OF state ON operation_items
FOR EACH ROW
WHEN OLD.state <> NEW.state
BEGIN
    INSERT INTO operation_events (
        event_key,
        operation_batch_id,
        operation_item_id,
        event_scope,
        event_kind,
        from_state,
        to_state,
        state_version,
        actor,
        occurred_at_ms
    ) VALUES (
        'item:' || NEW.id || ':state:' || NEW.state_version,
        NEW.operation_batch_id,
        NEW.id,
        'item',
        'state_transition',
        OLD.state,
        NEW.state,
        NEW.state_version,
        'state_machine',
        NEW.updated_at_ms
    );
END;

CREATE TRIGGER trg_operation_events_no_update
BEFORE UPDATE ON operation_events
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'operation_events is append-only');
END;

CREATE TRIGGER trg_operation_events_no_delete
BEFORE DELETE ON operation_events
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'operation_events is append-only');
END;

COMMIT;
