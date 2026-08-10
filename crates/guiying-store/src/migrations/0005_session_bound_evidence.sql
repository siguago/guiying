-- Version 5 separates stable namespace/scope evidence from the ephemeral
-- capability and mount session that authorizes one live read-only attempt.
--
-- This migration deliberately creates companion tables. Version-4
-- fingerprints, observations, and duplicate groups are retained as legacy
-- history but are never copied into the version-5 evidence graph.

CREATE TABLE namespace_profiles (
    id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    profile_key BLOB
        CHECK (profile_key IS NULL OR length(profile_key) = 32),
    profile_version INTEGER NOT NULL CHECK (profile_version >= 1),
    origin TEXT NOT NULL
        CHECK (origin IN ('observed_v5', 'legacy_session_v4')),
    native_path_encoding TEXT
        CHECK (native_path_encoding IS NULL OR native_path_encoding IN (
            'unix_bytes', 'windows_utf16_le'
        )),
    case_behavior TEXT
        CHECK (case_behavior IS NULL OR case_behavior IN (
            'sensitive',
            'insensitive_preserving',
            'insensitive_nonpreserving',
            'unknown'
        )),
    unicode_behavior TEXT
        CHECK (unicode_behavior IS NULL OR unicode_behavior IN (
            'exact', 'nfc', 'nfd', 'normalizing_other', 'unknown'
        )),
    key_strategy TEXT
        CHECK (key_strategy IS NULL OR key_strategy = 'exact_native_v1'),
    key_algorithm_version INTEGER
        CHECK (key_algorithm_version IS NULL OR key_algorithm_version >= 1),
    reuse_scope TEXT NOT NULL
        CHECK (reuse_scope IN (
            'cross_session', 'current_session_only', 'history_only'
        )),
    bound_mount_session_key TEXT
        CHECK (
            bound_mount_session_key IS NULL
            OR (
                length(bound_mount_session_key) = 64
                AND bound_mount_session_key = lower(bound_mount_session_key)
                AND bound_mount_session_key NOT GLOB '*[^0-9a-f]*'
            )
        ),
    legacy_capability_profile_id INTEGER,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (volume_id, id),
    UNIQUE (volume_id, legacy_capability_profile_id),
    CHECK (
        (origin = 'observed_v5'
         AND profile_key IS NOT NULL
         AND native_path_encoding IS NOT NULL
         AND case_behavior IS NOT NULL
         AND unicode_behavior IS NOT NULL
         AND key_strategy = 'exact_native_v1'
         AND key_algorithm_version IS NOT NULL
         AND reuse_scope IN ('cross_session', 'current_session_only')
         AND (
             (reuse_scope = 'cross_session'
              AND bound_mount_session_key IS NULL)
             OR
             (reuse_scope = 'current_session_only'
              AND bound_mount_session_key IS NOT NULL)
         )
         AND legacy_capability_profile_id IS NULL)
        OR
        (origin = 'legacy_session_v4'
         AND profile_key IS NULL
         AND key_strategy IS NULL
         AND key_algorithm_version IS NULL
         AND reuse_scope = 'history_only'
         AND bound_mount_session_key IS NULL)
    ),
    FOREIGN KEY (volume_id) REFERENCES volumes(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, legacy_capability_profile_id)
        REFERENCES capability_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX ux_namespace_profiles_cross_session_v5
    ON namespace_profiles(volume_id, profile_key)
    WHERE origin = 'observed_v5' AND reuse_scope = 'cross_session';

CREATE UNIQUE INDEX ux_namespace_profiles_current_session_v5
    ON namespace_profiles(volume_id, profile_key, bound_mount_session_key)
    WHERE origin = 'observed_v5' AND reuse_scope = 'current_session_only';

CREATE UNIQUE INDEX ux_namespace_profiles_legacy_unbound_v5
    ON namespace_profiles(volume_id)
    WHERE origin = 'legacy_session_v4'
      AND legacy_capability_profile_id IS NULL;

CREATE INDEX ix_namespace_profiles_volume_origin_v5
    ON namespace_profiles(volume_id, origin, id);

CREATE TABLE scan_job_scopes (
    scan_job_id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    namespace_profile_id INTEGER NOT NULL,
    origin TEXT NOT NULL
        CHECK (origin IN ('observed_v5', 'legacy_session_v4')),
    root_display TEXT NOT NULL
        CHECK (length(CAST(root_display AS BLOB)) <= 65536),
    mount_relative_root_raw BLOB NOT NULL
        CHECK (length(mount_relative_root_raw) <= 65536),
    path_encoding TEXT NOT NULL
        CHECK (path_encoding IN ('utf8', 'unix_bytes', 'windows_utf16_le')),
    stable_root_path_key BLOB
        CHECK (stable_root_path_key IS NULL OR length(stable_root_path_key) = 32),
    root_scope_key BLOB
        CHECK (root_scope_key IS NULL OR length(root_scope_key) = 32),
    legacy_semantic_path_key BLOB
        CHECK (
            legacy_semantic_path_key IS NULL
            OR length(legacy_semantic_path_key) BETWEEN 1 AND 4096
        ),
    recoverable INTEGER NOT NULL CHECK (recoverable IN (0, 1)),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (volume_id, scan_job_id),
    UNIQUE (
        volume_id,
        scan_job_id,
        namespace_profile_id,
        stable_root_path_key,
        root_scope_key
    ),
    CHECK (
        (origin = 'observed_v5'
         AND stable_root_path_key IS NOT NULL
         AND root_scope_key IS NOT NULL
         AND legacy_semantic_path_key IS NULL)
        OR
        (origin = 'legacy_session_v4'
         AND stable_root_path_key IS NULL
         AND root_scope_key IS NULL
         AND legacy_semantic_path_key IS NOT NULL
         AND recoverable = 0)
    ),
    CHECK (
        path_encoding <> 'utf8'
        OR mount_relative_root_raw = CAST(root_display AS BLOB)
    ),
    FOREIGN KEY (volume_id, scan_job_id) REFERENCES scan_jobs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, namespace_profile_id)
        REFERENCES namespace_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_scan_job_scopes_namespace_v5
    ON scan_job_scopes(volume_id, namespace_profile_id, scan_job_id);

CREATE TABLE scan_run_sessions (
    scan_run_id INTEGER PRIMARY KEY,
    scan_job_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    capability_profile_id INTEGER NOT NULL,
    namespace_profile_id INTEGER NOT NULL,
    mount_session_key TEXT NOT NULL
        CHECK (
            length(mount_session_key) = 64
            AND mount_session_key NOT GLOB '*[^0-9a-f]*'
        ),
    mount_relative_root_raw BLOB NOT NULL
        CHECK (length(mount_relative_root_raw) <= 65536),
    path_encoding TEXT NOT NULL
        CHECK (path_encoding IN ('utf8', 'unix_bytes', 'windows_utf16_le')),
    stable_root_path_key BLOB NOT NULL
        CHECK (length(stable_root_path_key) = 32),
    root_scope_key BLOB NOT NULL
        CHECK (length(root_scope_key) = 32),
    root_object_signature BLOB NOT NULL
        CHECK (length(root_object_signature) = 32),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (volume_id, scan_run_id),
    UNIQUE (
        volume_id,
        scan_run_id,
        capability_profile_id,
        namespace_profile_id
    ),
    FOREIGN KEY (volume_id, scan_run_id) REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_job_id) REFERENCES scan_jobs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (scan_job_id, scan_run_id)
        REFERENCES scan_job_runs(scan_job_id, scan_run_id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, capability_profile_id)
        REFERENCES capability_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, namespace_profile_id)
        REFERENCES namespace_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        scan_job_id,
        namespace_profile_id,
        stable_root_path_key,
        root_scope_key
    ) REFERENCES scan_job_scopes(
        volume_id,
        scan_job_id,
        namespace_profile_id,
        stable_root_path_key,
        root_scope_key
    ) ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_scan_run_sessions_job_v5
    ON scan_run_sessions(volume_id, scan_job_id, scan_run_id);

CREATE INDEX ix_scan_run_sessions_capability_v5
    ON scan_run_sessions(volume_id, capability_profile_id, scan_run_id);

CREATE TABLE scan_stage_seals (
    scan_run_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    stage TEXT NOT NULL
        CHECK (stage IN (
            'enumeration', 'sampling', 'full_hash', 'exact_verification'
        )),
    item_count INTEGER NOT NULL CHECK (item_count >= 0),
    logical_bytes INTEGER NOT NULL CHECK (logical_bytes >= 0),
    sealed_at_ms INTEGER NOT NULL CHECK (sealed_at_ms >= 0),
    PRIMARY KEY (scan_run_id, stage),
    UNIQUE (volume_id, scan_run_id, stage),
    FOREIGN KEY (volume_id, scan_run_id) REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_scan_stage_seals_run_v5
    ON scan_stage_seals(volume_id, scan_run_id, stage);

CREATE TABLE media_namespace_paths (
    id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    media_file_id INTEGER NOT NULL,
    namespace_profile_id INTEGER NOT NULL,
    stable_path_key BLOB NOT NULL CHECK (length(stable_path_key) = 32),
    mount_relative_path_raw BLOB NOT NULL
        CHECK (length(mount_relative_path_raw) BETWEEN 1 AND 65536),
    path_encoding TEXT NOT NULL
        CHECK (path_encoding IN ('utf8', 'unix_bytes', 'windows_utf16_le')),
    display_path TEXT NOT NULL
        CHECK (length(CAST(display_path AS BLOB)) BETWEEN 1 AND 65536),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (namespace_profile_id, stable_path_key),
    UNIQUE (volume_id, id),
    UNIQUE (volume_id, media_file_id),
    UNIQUE (volume_id, id, media_file_id, namespace_profile_id),
    CHECK (
        path_encoding <> 'utf8'
        OR mount_relative_path_raw = CAST(display_path AS BLOB)
    ),
    FOREIGN KEY (volume_id, media_file_id) REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, namespace_profile_id)
        REFERENCES namespace_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_media_namespace_paths_media_v5
    ON media_namespace_paths(volume_id, media_file_id, id);

CREATE TABLE media_observation_snapshots (
    id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    media_namespace_path_id INTEGER NOT NULL,
    media_file_id INTEGER NOT NULL,
    namespace_profile_id INTEGER NOT NULL,
    capability_profile_id INTEGER NOT NULL,
    root_relative_path_raw BLOB NOT NULL
        CHECK (length(root_relative_path_raw) BETWEEN 1 AND 65536),
    path_encoding TEXT NOT NULL
        CHECK (path_encoding IN ('utf8', 'unix_bytes', 'windows_utf16_le')),
    display_path TEXT NOT NULL
        CHECK (length(CAST(display_path AS BLOB)) BETWEEN 1 AND 65536),
    source_signature BLOB NOT NULL CHECK (length(source_signature) = 32),
    stat_signature_version INTEGER NOT NULL CHECK (stat_signature_version >= 1),
    file_object_key BLOB
        CHECK (file_object_key IS NULL OR length(file_object_key) = 32),
    native_file_id BLOB
        CHECK (native_file_id IS NULL OR length(native_file_id) BETWEEN 1 AND 1024),
    native_file_generation INTEGER
        CHECK (native_file_generation IS NULL OR native_file_generation >= 0),
    file_mode INTEGER NOT NULL CHECK (file_mode >= 0),
    entry_type TEXT NOT NULL CHECK (entry_type = 'regular'),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    allocated_bytes INTEGER CHECK (allocated_bytes IS NULL OR allocated_bytes >= 0),
    link_count INTEGER CHECK (link_count IS NULL OR link_count >= 1),
    is_sparse INTEGER CHECK (is_sparse IS NULL OR is_sparse IN (0, 1)),
    may_share_content INTEGER
        CHECK (may_share_content IS NULL OR may_share_content IN (0, 1)),
    birth_time_seconds INTEGER,
    birth_time_nanoseconds INTEGER
        CHECK (
            birth_time_nanoseconds IS NULL
            OR birth_time_nanoseconds BETWEEN 0 AND 999999999
        ),
    modified_time_seconds INTEGER NOT NULL,
    modified_time_nanoseconds INTEGER NOT NULL
        CHECK (modified_time_nanoseconds BETWEEN 0 AND 999999999),
    changed_time_seconds INTEGER NOT NULL,
    changed_time_nanoseconds INTEGER NOT NULL
        CHECK (changed_time_nanoseconds BETWEEN 0 AND 999999999),
    accessed_time_seconds INTEGER,
    accessed_time_nanoseconds INTEGER
        CHECK (
            accessed_time_nanoseconds IS NULL
            OR accessed_time_nanoseconds BETWEEN 0 AND 999999999
        ),
    timestamp_granularity_ns INTEGER NOT NULL
        CHECK (timestamp_granularity_ns > 0),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
    UNIQUE (scan_run_id, media_file_id),
    UNIQUE (volume_id, scan_run_id, id),
    UNIQUE (volume_id, scan_run_id, id, source_signature),
    CHECK (
        (birth_time_seconds IS NULL) = (birth_time_nanoseconds IS NULL)
    ),
    CHECK (
        (modified_time_seconds IS NULL) = (modified_time_nanoseconds IS NULL)
    ),
    CHECK (
        (changed_time_seconds IS NULL) = (changed_time_nanoseconds IS NULL)
    ),
    CHECK (
        (accessed_time_seconds IS NULL) = (accessed_time_nanoseconds IS NULL)
    ),
    CHECK (
        path_encoding <> 'utf8'
        OR root_relative_path_raw = CAST(display_path AS BLOB)
    ),
    FOREIGN KEY (volume_id, scan_run_id) REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, media_file_id) REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        media_namespace_path_id,
        media_file_id,
        namespace_profile_id
    ) REFERENCES media_namespace_paths(
        volume_id,
        id,
        media_file_id,
        namespace_profile_id
    ) ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        scan_run_id,
        capability_profile_id,
        namespace_profile_id
    ) REFERENCES scan_run_sessions(
        volume_id,
        scan_run_id,
        capability_profile_id,
        namespace_profile_id
    ) ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_media_observation_snapshots_run_page_v5
    ON media_observation_snapshots(scan_run_id, id);

CREATE INDEX ix_media_observation_snapshots_size_v5
    ON media_observation_snapshots(scan_run_id, size_bytes, id);

CREATE INDEX ix_media_observation_snapshots_file_object_v5
    ON media_observation_snapshots(scan_run_id, file_object_key, id)
    WHERE file_object_key IS NOT NULL;

CREATE TABLE observation_fingerprints (
    id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    media_observation_snapshot_id INTEGER NOT NULL,
    fingerprint_kind TEXT NOT NULL
        CHECK (fingerprint_kind IN ('sample', 'exact_bytes')),
    algorithm TEXT NOT NULL
        CHECK (length(CAST(algorithm AS BLOB)) BETWEEN 1 AND 1024),
    algorithm_version INTEGER NOT NULL CHECK (algorithm_version >= 1),
    parameters_hash BLOB NOT NULL CHECK (length(parameters_hash) = 32),
    read_origin TEXT NOT NULL
        CHECK (read_origin IN (
            'sample_read', 'full_hash_read', 'exact_compare_read'
        )),
    source_signature_before BLOB NOT NULL
        CHECK (length(source_signature_before) = 32),
    source_signature_after BLOB NOT NULL
        CHECK (length(source_signature_after) = 32),
    digest BLOB NOT NULL CHECK (length(digest) BETWEEN 1 AND 1024),
    observed_size_bytes INTEGER NOT NULL CHECK (observed_size_bytes >= 0),
    bytes_read INTEGER NOT NULL CHECK (bytes_read >= 0),
    reached_expected_eof INTEGER NOT NULL
        CHECK (reached_expected_eof IN (0, 1)),
    completed_at_ms INTEGER NOT NULL CHECK (completed_at_ms >= 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (volume_id, scan_run_id, id),
    UNIQUE (
        volume_id,
        scan_run_id,
        media_observation_snapshot_id,
        id
    ),
    UNIQUE (
        scan_run_id,
        media_observation_snapshot_id,
        fingerprint_kind,
        algorithm,
        algorithm_version,
        parameters_hash
    ),
    CHECK (
        (fingerprint_kind = 'sample' AND read_origin = 'sample_read')
        OR
        (fingerprint_kind = 'exact_bytes'
         AND read_origin IN ('full_hash_read', 'exact_compare_read'))
    ),
    CHECK (bytes_read <= observed_size_bytes),
    CHECK (completed_at_ms >= created_at_ms),
    CHECK (
        fingerprint_kind <> 'exact_bytes'
        OR (bytes_read = observed_size_bytes AND reached_expected_eof = 1)
    ),
    FOREIGN KEY (
        volume_id,
        scan_run_id,
        media_observation_snapshot_id
    ) REFERENCES media_observation_snapshots(volume_id, scan_run_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_observation_fingerprints_observation_v5
    ON observation_fingerprints(
        scan_run_id, media_observation_snapshot_id, fingerprint_kind, id
    );

CREATE INDEX ix_observation_fingerprints_bucket_v5
    ON observation_fingerprints(
        scan_run_id,
        fingerprint_kind,
        algorithm,
        algorithm_version,
        parameters_hash,
        observed_size_bytes,
        digest,
        id
    );

CREATE TABLE exact_group_builds (
    id INTEGER PRIMARY KEY,
    build_key BLOB NOT NULL CHECK (length(build_key) = 32),
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    representative_observation_id INTEGER NOT NULL,
    representative_fingerprint_id INTEGER NOT NULL,
    expected_member_count INTEGER NOT NULL CHECK (expected_member_count >= 2),
    expected_edge_count INTEGER NOT NULL CHECK (expected_edge_count >= 1),
    expected_manifest_digest BLOB NOT NULL
        CHECK (length(expected_manifest_digest) = 32),
    state TEXT NOT NULL DEFAULT 'draft'
        CHECK (state IN ('draft', 'verified', 'abandoned')),
    group_key BLOB CHECK (group_key IS NULL OR length(group_key) = 32),
    independent_file_count INTEGER
        CHECK (independent_file_count IS NULL OR independent_file_count >= 1),
    logical_reclaimable_bytes INTEGER
        CHECK (
            logical_reclaimable_bytes IS NULL
            OR logical_reclaimable_bytes >= 0
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
    UNIQUE (volume_id, scan_run_id, build_key),
    UNIQUE (volume_id, scan_run_id, id),
    CHECK (expected_edge_count = expected_member_count - 1),
    CHECK (
        (state = 'draft'
         AND group_key IS NULL
         AND independent_file_count IS NULL
         AND logical_reclaimable_bytes IS NULL
         AND abandon_reason_code IS NULL
         AND abandon_reason_message IS NULL
         AND finalized_at_ms IS NULL)
        OR
        (state = 'verified'
         AND group_key IS NOT NULL
         AND independent_file_count BETWEEN 1 AND expected_member_count
         AND logical_reclaimable_bytes IS NOT NULL
         AND abandon_reason_code IS NULL
         AND abandon_reason_message IS NULL
         AND finalized_at_ms IS NOT NULL)
        OR
        (state = 'abandoned'
         AND group_key IS NULL
         AND independent_file_count IS NULL
         AND logical_reclaimable_bytes IS NULL
         AND abandon_reason_code IS NOT NULL
         AND finalized_at_ms IS NOT NULL)
    ),
    FOREIGN KEY (
        volume_id,
        scan_run_id,
        representative_observation_id
    ) REFERENCES media_observation_snapshots(volume_id, scan_run_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        scan_run_id,
        representative_observation_id,
        representative_fingerprint_id
    ) REFERENCES observation_fingerprints(
        volume_id,
        scan_run_id,
        media_observation_snapshot_id,
        id
    ) ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX ux_exact_group_builds_verified_group_v5
    ON exact_group_builds(scan_run_id, group_key)
    WHERE state = 'verified';

CREATE INDEX ix_exact_group_builds_verified_page_v5
    ON exact_group_builds(
        scan_run_id, logical_reclaimable_bytes DESC, id
    ) WHERE state = 'verified';

CREATE TABLE exact_group_build_members (
    exact_group_build_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    media_observation_snapshot_id INTEGER NOT NULL,
    observation_fingerprint_id INTEGER NOT NULL,
    sort_rank INTEGER NOT NULL CHECK (sort_rank >= 0),
    manifest_leaf BLOB NOT NULL CHECK (length(manifest_leaf) = 32),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (exact_group_build_id, ordinal),
    UNIQUE (exact_group_build_id, media_observation_snapshot_id),
    UNIQUE (
        volume_id,
        scan_run_id,
        exact_group_build_id,
        media_observation_snapshot_id
    ),
    FOREIGN KEY (volume_id, scan_run_id, exact_group_build_id)
        REFERENCES exact_group_builds(volume_id, scan_run_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        scan_run_id,
        media_observation_snapshot_id,
        observation_fingerprint_id
    ) REFERENCES observation_fingerprints(
        volume_id,
        scan_run_id,
        media_observation_snapshot_id,
        id
    ) ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_exact_group_build_members_page_v5
    ON exact_group_build_members(exact_group_build_id, sort_rank, ordinal);

CREATE INDEX ix_exact_group_build_members_observation_v5
    ON exact_group_build_members(
        scan_run_id, media_observation_snapshot_id, exact_group_build_id
    );

CREATE TABLE exact_verification_edges (
    exact_group_build_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    representative_observation_id INTEGER NOT NULL,
    representative_fingerprint_id INTEGER NOT NULL,
    member_observation_id INTEGER NOT NULL,
    member_fingerprint_id INTEGER NOT NULL,
    representative_source_signature BLOB NOT NULL
        CHECK (length(representative_source_signature) = 32),
    member_source_signature BLOB NOT NULL
        CHECK (length(member_source_signature) = 32),
    compared_bytes INTEGER NOT NULL CHECK (compared_bytes >= 0),
    verified_at_ms INTEGER NOT NULL CHECK (verified_at_ms >= 0),
    PRIMARY KEY (exact_group_build_id, member_observation_id),
    UNIQUE (
        volume_id,
        scan_run_id,
        exact_group_build_id,
        member_observation_id
    ),
    CHECK (representative_observation_id <> member_observation_id),
    FOREIGN KEY (volume_id, scan_run_id, exact_group_build_id)
        REFERENCES exact_group_builds(volume_id, scan_run_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        scan_run_id,
        exact_group_build_id,
        member_observation_id
    ) REFERENCES exact_group_build_members(
        volume_id,
        scan_run_id,
        exact_group_build_id,
        media_observation_snapshot_id
    ) ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        scan_run_id,
        representative_observation_id,
        representative_fingerprint_id
    ) REFERENCES observation_fingerprints(
        volume_id,
        scan_run_id,
        media_observation_snapshot_id,
        id
    ) ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        scan_run_id,
        member_observation_id,
        member_fingerprint_id
    ) REFERENCES observation_fingerprints(
        volume_id,
        scan_run_id,
        media_observation_snapshot_id,
        id
    ) ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- A v4 capability profile contains a session-specific path profile. Preserve
-- it as history only; it must never become a stable namespace by migration.
INSERT INTO namespace_profiles (
    volume_id,
    profile_key,
    profile_version,
    origin,
    native_path_encoding,
    case_behavior,
    unicode_behavior,
    key_strategy,
    key_algorithm_version,
    reuse_scope,
    legacy_capability_profile_id,
    created_at_ms
)
SELECT
    profile.volume_id,
    NULL,
    profile.path_semantics_version,
    'legacy_session_v4',
    CASE profile.path_encoding_family
        WHEN 'unix' THEN 'unix_bytes'
        WHEN 'windows' THEN 'windows_utf16_le'
        ELSE NULL
    END,
    profile.case_behavior,
    profile.unicode_behavior,
    NULL,
    NULL,
    'history_only',
    profile.id,
    profile.created_at_ms
FROM capability_profiles AS profile
ORDER BY profile.id;

-- A legacy job can be capability-unbound. Keep exactly one explicit unbound
-- namespace per affected volume instead of guessing which profile produced
-- its old path key.
INSERT INTO namespace_profiles (
    volume_id,
    profile_key,
    profile_version,
    origin,
    native_path_encoding,
    case_behavior,
    unicode_behavior,
    key_strategy,
    key_algorithm_version,
    reuse_scope,
    legacy_capability_profile_id,
    created_at_ms
)
SELECT
    volume.id,
    NULL,
    1,
    'legacy_session_v4',
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    'history_only',
    NULL,
    volume.created_at_ms
FROM volumes AS volume
WHERE NOT EXISTS (
        SELECT 1 FROM capability_profiles AS profile
        WHERE profile.volume_id = volume.id
    )
   OR EXISTS (
        SELECT 1 FROM scan_job_roots AS root
        WHERE root.volume_id = volume.id
          AND root.capability_profile_id IS NULL
    )
ORDER BY volume.id;

INSERT INTO scan_job_scopes (
    scan_job_id,
    volume_id,
    namespace_profile_id,
    origin,
    root_display,
    mount_relative_root_raw,
    path_encoding,
    stable_root_path_key,
    root_scope_key,
    legacy_semantic_path_key,
    recoverable,
    created_at_ms
)
SELECT
    job.id,
    job.volume_id,
    namespace.id,
    'legacy_session_v4',
    job.root_relative_path,
    root.relative_path_raw,
    root.path_encoding,
    NULL,
    NULL,
    root.semantic_path_key,
    0,
    job.created_at_ms
FROM scan_jobs AS job
JOIN scan_job_roots AS root
  ON root.scan_job_id = job.id
 AND root.volume_id = job.volume_id
JOIN namespace_profiles AS namespace
  ON namespace.volume_id = job.volume_id
 AND namespace.origin = 'legacy_session_v4'
 AND namespace.legacy_capability_profile_id IS root.capability_profile_id
ORDER BY job.id;

-- Triggers validate future writes, not rows copied during the migration. Fail
-- the transaction if any legacy job could not be represented exactly.
CREATE TABLE guiying_v5_invariant_guard (
    violation INTEGER NOT NULL CHECK (violation = 0)
) STRICT;

INSERT INTO guiying_v5_invariant_guard (violation)
SELECT 1
FROM scan_jobs AS job
LEFT JOIN scan_job_scopes AS scope ON scope.scan_job_id = job.id
WHERE scope.scan_job_id IS NULL
   OR scope.volume_id <> job.volume_id
LIMIT 1;

INSERT INTO guiying_v5_invariant_guard (violation)
SELECT 1
FROM scan_job_scopes AS scope
JOIN namespace_profiles AS namespace
  ON namespace.id = scope.namespace_profile_id
 AND namespace.volume_id = scope.volume_id
WHERE scope.origin <> 'legacy_session_v4'
   OR scope.recoverable <> 0
   OR scope.stable_root_path_key IS NOT NULL
   OR scope.root_scope_key IS NOT NULL
   OR namespace.origin <> 'legacy_session_v4'
   OR namespace.reuse_scope <> 'history_only'
LIMIT 1;

DROP TABLE guiying_v5_invariant_guard;

-- The process-local descriptors behind an active v4 run cannot survive an
-- upgrade. Explicitly terminate each active attempt before installing the v5
-- state machine. Do not pretend that it completed or can resume in place.
DROP TRIGGER trg_scan_jobs_state_binding;
DROP TRIGGER trg_scan_runs_state_binding;
DROP TRIGGER trg_scan_jobs_state_edge_v4;
DROP TRIGGER trg_scan_runs_state_edge_v4;
DROP TRIGGER trg_scan_job_runs_root_evidence_insert_v4;
DROP TRIGGER trg_scan_job_roots_insert_guard_v4;
DROP TRIGGER trg_scan_run_roots_insert_guard_v4;
DROP TRIGGER trg_scan_jobs_active_run_replace_guard;
DROP TRIGGER trg_scan_jobs_active_run_binding;

UPDATE scan_jobs
SET state = 'failed',
    state_version = state_version + 1
WHERE state IN ('queued', 'running', 'paused');

UPDATE scan_runs
SET state = 'interrupted',
    state_version = state_version + 1,
    started_at_ms = COALESCE(started_at_ms, created_at_ms),
    finished_at_ms = COALESCE(finished_at_ms, updated_at_ms),
    last_error_code = 'PROCESS_UPGRADED_WITH_ACTIVE_RUN',
    last_error_message =
        'The active v4 scan lost its process-local filesystem binding during the v5 upgrade.'
WHERE state IN ('queued', 'running', 'paused');

CREATE TRIGGER trg_namespace_profiles_insert_guard_v5
BEFORE INSERT ON namespace_profiles
WHEN (NEW.origin = 'observed_v5' AND NOT EXISTS (
          SELECT 1 FROM volumes AS volume
          WHERE volume.id = NEW.volume_id
            AND (
                NEW.reuse_scope <> 'cross_session'
                OR (
                    volume.identity_strength = 'strong'
                    AND NEW.case_behavior <> 'unknown'
                    AND NEW.unicode_behavior <> 'unknown'
                )
            )
      ))
   OR (NEW.origin = 'observed_v5' AND NOT (
          (NEW.reuse_scope = 'cross_session'
           AND NEW.bound_mount_session_key IS NULL)
          OR
          (NEW.reuse_scope = 'current_session_only'
           AND length(NEW.bound_mount_session_key) = 64
           AND NEW.bound_mount_session_key = lower(NEW.bound_mount_session_key)
           AND NEW.bound_mount_session_key NOT GLOB '*[^0-9a-f]*')
      ))
   OR (NEW.reuse_scope = 'cross_session' AND NOT EXISTS (
          SELECT 1 FROM volumes AS volume
          WHERE volume.id = NEW.volume_id
            AND volume.identity_strength = 'strong'
            AND NEW.origin = 'observed_v5'
            AND NEW.case_behavior <> 'unknown'
            AND NEW.unicode_behavior <> 'unknown'
      ))
   OR (NEW.legacy_capability_profile_id IS NOT NULL AND NOT EXISTS (
          SELECT 1 FROM capability_profiles AS profile
          WHERE profile.id = NEW.legacy_capability_profile_id
            AND profile.volume_id = NEW.volume_id
      ))
BEGIN
    SELECT RAISE(ABORT, 'namespace profile evidence is incomplete or not reusable');
END;

CREATE TRIGGER trg_namespace_profiles_no_update_v5
BEFORE UPDATE ON namespace_profiles
BEGIN
    SELECT RAISE(ABORT, 'namespace profile evidence is immutable');
END;

CREATE TRIGGER trg_namespace_profiles_no_delete_v5
BEFORE DELETE ON namespace_profiles
BEGIN
    SELECT RAISE(ABORT, 'namespace profile evidence cannot be deleted');
END;

-- Re-probing a mount must not silently detach a queued, running, or paused
-- attempt from the capability snapshot that guards its descriptors. The
-- caller must first end/interrupt that attempt through the guarded state API.
CREATE TRIGGER trg_capability_profiles_keep_active_current_v5
BEFORE UPDATE OF is_current ON capability_profiles
WHEN OLD.is_current = 1
 AND NEW.is_current = 0
 AND EXISTS (
     SELECT 1
     FROM scan_run_sessions AS session
     JOIN scan_runs AS run
       ON run.id = session.scan_run_id
      AND run.volume_id = session.volume_id
     WHERE session.capability_profile_id = OLD.id
       AND session.volume_id = OLD.volume_id
       AND run.state IN ('queued', 'running', 'paused')
 )
BEGIN
    SELECT RAISE(ABORT, 'active scan session must end before capability replacement');
END;

CREATE TRIGGER trg_scan_job_scopes_insert_guard_v5
BEFORE INSERT ON scan_job_scopes
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_jobs AS job
    JOIN namespace_profiles AS namespace
      ON namespace.id = NEW.namespace_profile_id
     AND namespace.volume_id = NEW.volume_id
    JOIN volumes AS volume ON volume.id = NEW.volume_id
    WHERE job.id = NEW.scan_job_id
      AND job.volume_id = NEW.volume_id
      AND job.root_relative_path = NEW.root_display
      AND namespace.origin = NEW.origin
      AND (
          (NEW.origin = 'legacy_session_v4'
           AND job.root_path_key = NEW.legacy_semantic_path_key
           AND NEW.recoverable = 0)
          OR
          (NEW.origin = 'observed_v5'
           AND job.root_path_key = NEW.stable_root_path_key
           AND namespace.native_path_encoding = CASE NEW.path_encoding
               WHEN 'windows_utf16_le' THEN 'windows_utf16_le'
               ELSE 'unix_bytes'
           END
           AND (
               NEW.recoverable = 0
               OR (
                   NEW.recoverable = 1
                   AND namespace.reuse_scope = 'cross_session'
                   AND volume.identity_strength = 'strong'
               )
           ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'scan job scope does not match its stable namespace');
END;

CREATE TRIGGER trg_scan_job_roots_insert_guard_v5
BEFORE INSERT ON scan_job_roots
WHEN NEW.capability_profile_id IS NOT NULL
  OR NOT EXISTS (
      SELECT 1 FROM scan_jobs AS job
      WHERE job.id = NEW.scan_job_id
        AND job.volume_id = NEW.volume_id
        AND job.root_path_key = NEW.semantic_path_key
        AND (NEW.path_encoding <> 'utf8'
             OR CAST(job.root_relative_path AS BLOB) = NEW.relative_path_raw)
  )
BEGIN
    SELECT RAISE(ABORT, 'v5 scan job root must be capability-independent');
END;

CREATE TRIGGER trg_scan_run_roots_insert_guard_v5
BEFORE INSERT ON scan_run_roots
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_runs AS run
    JOIN capability_profiles AS profile
      ON profile.id = run.capability_profile_id
     AND profile.volume_id = run.volume_id
    WHERE run.id = NEW.scan_run_id
      AND run.volume_id = NEW.volume_id
      AND run.capability_profile_id = NEW.capability_profile_id
      AND run.root_path_key = NEW.semantic_path_key
      AND profile.path_semantics_version = NEW.path_semantics_version
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND length(profile.mount_session_key) = 64
      AND profile.mount_session_key NOT GLOB '*[^0-9a-f]*'
      AND profile.path_encoding_family = CASE NEW.path_encoding
          WHEN 'windows_utf16_le' THEN 'windows'
          ELSE 'unix'
      END
      AND (NEW.path_encoding <> 'utf8'
           OR CAST(run.root_relative_path AS BLOB) = NEW.relative_path_raw)
)
BEGIN
    SELECT RAISE(ABORT, 'scan run root lacks current capability evidence');
END;

CREATE TRIGGER trg_scan_job_scopes_no_update_v5
BEFORE UPDATE ON scan_job_scopes
BEGIN
    SELECT RAISE(ABORT, 'scan job scope evidence is immutable');
END;

CREATE TRIGGER trg_scan_job_scopes_no_delete_v5
BEFORE DELETE ON scan_job_scopes
BEGIN
    SELECT RAISE(ABORT, 'scan job scope evidence cannot be deleted');
END;

CREATE TRIGGER trg_scan_job_runs_observed_scope_insert_v5
BEFORE INSERT ON scan_job_runs
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_job_scopes AS scope
    JOIN namespace_profiles AS namespace
      ON namespace.id = scope.namespace_profile_id
     AND namespace.volume_id = scope.volume_id
    JOIN volumes AS volume ON volume.id = scope.volume_id
    WHERE scope.scan_job_id = NEW.scan_job_id
      AND scope.volume_id = NEW.volume_id
      AND scope.origin = 'observed_v5'
      AND namespace.origin = 'observed_v5'
      AND NEW.attempt_number = COALESCE((
          SELECT max(existing.attempt_number) + 1
          FROM scan_job_runs AS existing
          WHERE existing.scan_job_id = NEW.scan_job_id
      ), 1)
      AND EXISTS (
          SELECT 1
          FROM scan_runs AS candidate_run
          JOIN scan_jobs AS candidate_job
            ON candidate_job.id = NEW.scan_job_id
           AND candidate_job.volume_id = NEW.volume_id
          WHERE candidate_run.id = NEW.scan_run_id
            AND candidate_run.volume_id = NEW.volume_id
            AND (
                (NEW.attempt_number = 1
                 AND candidate_run.parent_scan_run_id IS NULL)
                OR
                (NEW.attempt_number > 1
                 AND candidate_run.parent_scan_run_id =
                     candidate_job.active_scan_run_id)
            )
      )
      AND (
          NEW.attempt_number = 1
          OR (
              NEW.attempt_number > 1
              AND scope.recoverable = 1
              AND namespace.reuse_scope = 'cross_session'
              AND volume.identity_strength = 'strong'
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'legacy or unscoped scan job cannot add an attempt');
END;

CREATE TRIGGER trg_scan_jobs_active_run_replace_guard_v5
BEFORE UPDATE OF active_scan_run_id ON scan_jobs
WHEN OLD.active_scan_run_id IS NOT NULL
 AND NEW.active_scan_run_id IS NOT NULL
 AND OLD.active_scan_run_id <> NEW.active_scan_run_id
 AND NOT (
    OLD.state IN ('failed', 'completed', 'cancelled')
    AND NEW.state = OLD.state
    AND EXISTS (
        SELECT 1 FROM scan_runs AS previous
        WHERE previous.id = OLD.active_scan_run_id
          AND previous.volume_id = OLD.volume_id
          AND previous.state IN ('failed', 'interrupted', 'completed', 'cancelled')
    )
    AND EXISTS (
        SELECT 1 FROM scan_runs AS replacement
        WHERE replacement.id = NEW.active_scan_run_id
          AND replacement.volume_id = NEW.volume_id
          AND replacement.state = 'queued'
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'active scan run replacement is not a valid new attempt');
END;

CREATE TRIGGER trg_scan_jobs_active_run_binding_v5
BEFORE UPDATE OF active_scan_run_id ON scan_jobs
WHEN NEW.active_scan_run_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1
    FROM scan_job_runs AS binding
    JOIN scan_runs AS run
      ON run.id = binding.scan_run_id
     AND run.volume_id = binding.volume_id
    WHERE binding.scan_job_id = NEW.id
      AND binding.scan_run_id = NEW.active_scan_run_id
      AND binding.volume_id = NEW.volume_id
      AND run.root_relative_path = NEW.root_relative_path
      AND run.root_path_key = NEW.root_path_key
      AND (
          (NEW.state = 'queued' AND run.state = 'queued')
          OR (NEW.state = 'running' AND run.state IN ('queued', 'running', 'paused'))
          OR (NEW.state = 'paused' AND run.state = 'paused')
          OR (NEW.state = 'completed' AND run.state IN ('completed', 'queued'))
          OR (NEW.state = 'failed' AND run.state IN ('failed', 'interrupted', 'queued'))
          OR (NEW.state = 'cancelled' AND run.state IN (
              'cancelled', 'failed', 'interrupted', 'queued'
          ))
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'active scan run is not bound to this job scope');
END;

CREATE TRIGGER trg_scan_run_sessions_insert_guard_v5
BEFORE INSERT ON scan_run_sessions
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_job_runs AS binding
    JOIN scan_jobs AS job
      ON job.id = binding.scan_job_id
     AND job.volume_id = binding.volume_id
    JOIN scan_runs AS run
      ON run.id = binding.scan_run_id
     AND run.volume_id = binding.volume_id
    JOIN scan_job_scopes AS scope
      ON scope.scan_job_id = binding.scan_job_id
     AND scope.volume_id = binding.volume_id
    JOIN namespace_profiles AS namespace
      ON namespace.id = scope.namespace_profile_id
     AND namespace.volume_id = scope.volume_id
    JOIN capability_profiles AS profile
      ON profile.id = NEW.capability_profile_id
     AND profile.volume_id = NEW.volume_id
    JOIN volumes AS volume ON volume.id = NEW.volume_id
    JOIN scan_run_roots AS run_root
      ON run_root.scan_run_id = run.id
     AND run_root.volume_id = run.volume_id
    WHERE binding.scan_job_id = NEW.scan_job_id
      AND binding.scan_run_id = NEW.scan_run_id
      AND binding.volume_id = NEW.volume_id
      AND run.capability_profile_id = NEW.capability_profile_id
      AND run.root_path_key = NEW.stable_root_path_key
      AND run.root_relative_path = job.root_relative_path
      AND run_root.capability_profile_id = NEW.capability_profile_id
      AND run_root.relative_path_raw = NEW.mount_relative_root_raw
      AND run_root.path_encoding = NEW.path_encoding
      AND run_root.semantic_path_key = NEW.stable_root_path_key
      AND scope.origin = 'observed_v5'
      AND namespace.origin = 'observed_v5'
      AND namespace.id = NEW.namespace_profile_id
      AND namespace.native_path_encoding = CASE NEW.path_encoding
          WHEN 'windows_utf16_le' THEN 'windows_utf16_le'
          ELSE 'unix_bytes'
      END
      AND (
          (namespace.reuse_scope = 'cross_session'
           AND namespace.bound_mount_session_key IS NULL)
          OR
          (namespace.reuse_scope = 'current_session_only'
           AND namespace.bound_mount_session_key = NEW.mount_session_key COLLATE BINARY)
      )
      AND scope.mount_relative_root_raw = NEW.mount_relative_root_raw
      AND scope.path_encoding = NEW.path_encoding
      AND scope.stable_root_path_key = NEW.stable_root_path_key
      AND scope.root_scope_key = NEW.root_scope_key
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key = NEW.mount_session_key COLLATE BINARY
      AND length(profile.mount_session_key) = 64
      AND profile.mount_session_key NOT GLOB '*[^0-9a-f]*'
      AND profile.probe_protocol_version IS NOT NULL
      AND profile.path_encoding_family IS NOT NULL
      AND profile.path_encoding_family = CASE NEW.path_encoding
          WHEN 'windows_utf16_le' THEN 'windows'
          ELSE 'unix'
      END
      AND (
          binding.attempt_number = 1
          OR (
              binding.attempt_number > 1
              AND scope.recoverable = 1
              AND namespace.reuse_scope = 'cross_session'
              AND volume.identity_strength = 'strong'
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'scan run session is not bound to current capability and scope evidence');
END;

CREATE TRIGGER trg_scan_run_sessions_no_update_v5
BEFORE UPDATE ON scan_run_sessions
BEGIN
    SELECT RAISE(ABORT, 'scan run session evidence is immutable');
END;

CREATE TRIGGER trg_scan_run_sessions_no_delete_v5
BEFORE DELETE ON scan_run_sessions
BEGIN
    SELECT RAISE(ABORT, 'scan run session evidence cannot be deleted');
END;

CREATE TRIGGER trg_scan_runs_enter_running_session_gate_v5
BEFORE UPDATE OF state ON scan_runs
WHEN OLD.state IS NOT NEW.state
 AND NEW.state = 'running'
 AND NOT EXISTS (
    SELECT 1
    FROM scan_run_sessions AS session
    JOIN scan_job_scopes AS scope
      ON scope.scan_job_id = session.scan_job_id
     AND scope.volume_id = session.volume_id
    JOIN namespace_profiles AS namespace
      ON namespace.id = session.namespace_profile_id
     AND namespace.volume_id = session.volume_id
    JOIN capability_profiles AS profile
      ON profile.id = session.capability_profile_id
     AND profile.volume_id = session.volume_id
    WHERE session.scan_run_id = NEW.id
      AND session.volume_id = NEW.volume_id
      AND session.capability_profile_id = NEW.capability_profile_id
      AND scope.origin = 'observed_v5'
      AND namespace.origin = 'observed_v5'
      AND (
          (namespace.reuse_scope = 'cross_session'
           AND namespace.bound_mount_session_key IS NULL)
          OR
          (namespace.reuse_scope = 'current_session_only'
           AND namespace.bound_mount_session_key = session.mount_session_key COLLATE BINARY)
      )
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key = session.mount_session_key COLLATE BINARY
      AND length(profile.mount_session_key) = 64
      AND profile.mount_session_key NOT GLOB '*[^0-9a-f]*'
 )
BEGIN
    SELECT RAISE(ABORT, 'scan run cannot start without a current bound session');
END;

CREATE TRIGGER trg_scan_runs_complete_seal_gate_v5
BEFORE UPDATE OF state ON scan_runs
WHEN OLD.state IS NOT NEW.state
 AND NEW.state = 'completed'
 AND NOT EXISTS (
     SELECT 1 FROM scan_stage_seals AS seal
     WHERE seal.scan_run_id = NEW.id
       AND seal.volume_id = NEW.volume_id
       AND seal.stage = 'exact_verification'
 )
BEGIN
    SELECT RAISE(ABORT, 'scan run cannot complete before exact verification is sealed');
END;

CREATE TRIGGER trg_scan_jobs_initial_state_v5
BEFORE INSERT ON scan_jobs
WHEN NEW.state <> 'queued'
BEGIN
    SELECT RAISE(ABORT, 'new scan job must start queued');
END;

CREATE TRIGGER trg_scan_runs_initial_state_v5
BEFORE INSERT ON scan_runs
WHEN NEW.state <> 'queued'
BEGIN
    SELECT RAISE(ABORT, 'new scan run must start queued');
END;

CREATE TRIGGER trg_scan_jobs_state_edge_v5
BEFORE UPDATE OF state ON scan_jobs
WHEN OLD.state IS NOT NEW.state
 AND NOT (
      (OLD.state = 'queued' AND NEW.state IN ('running', 'failed', 'cancelled'))
   OR (OLD.state = 'running' AND NEW.state IN (
          'paused', 'completed', 'failed', 'cancelled'
      ))
   OR (OLD.state = 'paused' AND NEW.state IN ('running', 'failed', 'cancelled'))
   OR (OLD.state = 'failed' AND NEW.state IN ('running', 'cancelled'))
   OR (OLD.state = 'completed' AND NEW.state = 'running')
   OR (OLD.state = 'cancelled' AND NEW.state = 'running')
 )
BEGIN
    SELECT RAISE(ABORT, 'invalid scan job state edge');
END;

CREATE TRIGGER trg_scan_runs_state_edge_v5
BEFORE UPDATE OF state ON scan_runs
WHEN OLD.state IS NOT NEW.state
 AND NOT (
      (OLD.state = 'queued' AND NEW.state IN ('running', 'cancelled', 'interrupted'))
   OR (OLD.state = 'running' AND NEW.state IN (
          'paused', 'completed', 'failed', 'cancelled', 'interrupted'
      ))
   OR (OLD.state = 'paused' AND NEW.state IN (
          'running', 'failed', 'cancelled', 'interrupted'
      ))
 )
BEGIN
    SELECT RAISE(ABORT, 'invalid scan run state edge');
END;

CREATE TRIGGER trg_scan_jobs_state_binding_v5
BEFORE UPDATE OF state ON scan_jobs
WHEN NOT (NEW.active_scan_run_id IS NULL AND NEW.state IN ('failed', 'cancelled'))
 AND (
    NEW.active_scan_run_id IS NULL
    OR NOT EXISTS (
        SELECT 1 FROM scan_runs AS run
        WHERE run.id = NEW.active_scan_run_id
          AND run.volume_id = NEW.volume_id
          AND (
              (NEW.state = 'queued' AND run.state = 'queued')
              OR (NEW.state = 'running' AND run.state IN ('queued', 'running', 'paused'))
              OR (NEW.state = 'paused' AND run.state = 'paused')
              OR (NEW.state = 'completed' AND run.state IN ('completed', 'queued'))
              OR (NEW.state = 'failed' AND run.state IN (
                  'queued', 'failed', 'interrupted'
              ))
              OR (NEW.state = 'cancelled' AND run.state IN (
                  'cancelled', 'failed', 'interrupted', 'queued'
              ))
          )
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'scan job state is inconsistent with active run');
END;

CREATE TRIGGER trg_scan_runs_state_binding_v5
BEFORE UPDATE OF state ON scan_runs
WHEN EXISTS (
    SELECT 1
    FROM scan_jobs AS job
    WHERE job.active_scan_run_id = NEW.id
      AND job.volume_id = NEW.volume_id
      AND NOT (
          (NEW.state = 'queued' AND job.state IN ('queued', 'running', 'failed'))
          OR (NEW.state = 'running' AND job.state = 'running')
          OR (NEW.state = 'paused' AND job.state IN ('running', 'paused'))
          OR (NEW.state = 'completed' AND job.state IN ('running', 'completed'))
          OR (NEW.state = 'failed' AND job.state IN ('running', 'paused', 'failed'))
          OR (NEW.state = 'interrupted' AND job.state IN (
              'queued', 'running', 'paused', 'failed'
          ))
          OR (NEW.state = 'cancelled' AND job.state IN (
              'queued', 'running', 'paused', 'cancelled'
          ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'scan run state is inconsistent with active job');
END;

CREATE TRIGGER trg_scan_stage_seals_insert_guard_v5
BEFORE INSERT ON scan_stage_seals
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_runs AS run
    JOIN scan_run_sessions AS session
      ON session.scan_run_id = run.id
     AND session.volume_id = run.volume_id
    JOIN capability_profiles AS profile
      ON profile.id = session.capability_profile_id
     AND profile.volume_id = session.volume_id
    WHERE run.id = NEW.scan_run_id
      AND run.volume_id = NEW.volume_id
      AND run.state = 'running'
      AND run.capability_profile_id = session.capability_profile_id
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key = session.mount_session_key COLLATE BINARY
      AND (
          (NEW.stage = 'enumeration'
           AND NOT EXISTS (
               SELECT 1 FROM scan_stage_seals AS previous
               WHERE previous.scan_run_id = NEW.scan_run_id
           )
           AND NEW.item_count = (
               SELECT count(*) FROM media_observation_snapshots AS observation
               WHERE observation.scan_run_id = NEW.scan_run_id
           )
           AND NEW.logical_bytes = COALESCE((
               SELECT sum(observation.size_bytes)
               FROM media_observation_snapshots AS observation
               WHERE observation.scan_run_id = NEW.scan_run_id
           ), 0))
          OR
          (NEW.stage = 'sampling'
           AND EXISTS (
               SELECT 1 FROM scan_stage_seals AS previous
               WHERE previous.scan_run_id = NEW.scan_run_id
                 AND previous.stage = 'enumeration'
                 AND previous.sealed_at_ms <= NEW.sealed_at_ms
           )
           AND NOT EXISTS (
               SELECT 1 FROM scan_stage_seals AS later
               WHERE later.scan_run_id = NEW.scan_run_id
                 AND later.stage IN ('sampling', 'full_hash', 'exact_verification')
           )
           AND NEW.item_count = (
               SELECT count(*) FROM observation_fingerprints AS fingerprint
               WHERE fingerprint.scan_run_id = NEW.scan_run_id
                 AND fingerprint.fingerprint_kind = 'sample'
           )
           AND NEW.logical_bytes = COALESCE((
               SELECT sum(fingerprint.bytes_read)
               FROM observation_fingerprints AS fingerprint
               WHERE fingerprint.scan_run_id = NEW.scan_run_id
                 AND fingerprint.fingerprint_kind = 'sample'
           ), 0))
          OR
          (NEW.stage = 'full_hash'
           AND EXISTS (
               SELECT 1 FROM scan_stage_seals AS enumeration
               WHERE enumeration.scan_run_id = NEW.scan_run_id
                 AND enumeration.stage = 'enumeration'
                 AND enumeration.sealed_at_ms <= NEW.sealed_at_ms
           )
           AND EXISTS (
               SELECT 1 FROM scan_stage_seals AS sampling
               WHERE sampling.scan_run_id = NEW.scan_run_id
                 AND sampling.stage = 'sampling'
                 AND sampling.sealed_at_ms <= NEW.sealed_at_ms
           )
           AND NOT EXISTS (
               SELECT 1 FROM scan_stage_seals AS later
               WHERE later.scan_run_id = NEW.scan_run_id
                 AND later.stage IN ('full_hash', 'exact_verification')
           )
           AND NEW.item_count = (
               SELECT count(*) FROM observation_fingerprints AS fingerprint
               WHERE fingerprint.scan_run_id = NEW.scan_run_id
                 AND fingerprint.fingerprint_kind = 'exact_bytes'
                 AND fingerprint.read_origin = 'full_hash_read'
           )
           AND NEW.logical_bytes = COALESCE((
               SELECT sum(fingerprint.bytes_read)
               FROM observation_fingerprints AS fingerprint
               WHERE fingerprint.scan_run_id = NEW.scan_run_id
                 AND fingerprint.fingerprint_kind = 'exact_bytes'
                 AND fingerprint.read_origin = 'full_hash_read'
           ), 0))
          OR
          (NEW.stage = 'exact_verification'
           AND EXISTS (
               SELECT 1 FROM scan_stage_seals AS full_hash
               WHERE full_hash.scan_run_id = NEW.scan_run_id
                 AND full_hash.stage = 'full_hash'
                 AND full_hash.sealed_at_ms <= NEW.sealed_at_ms
           )
           AND NOT EXISTS (
               SELECT 1 FROM scan_stage_seals AS later
               WHERE later.scan_run_id = NEW.scan_run_id
                 AND later.stage = 'exact_verification'
           )
           AND NOT EXISTS (
               SELECT 1 FROM exact_group_builds AS build
               WHERE build.scan_run_id = NEW.scan_run_id
                 AND build.state = 'draft'
           )
           AND NEW.item_count = (
               SELECT count(*) FROM exact_verification_edges AS edge
               WHERE edge.scan_run_id = NEW.scan_run_id
           )
           AND NEW.logical_bytes = COALESCE((
               SELECT sum(edge.compared_bytes)
               FROM exact_verification_edges AS edge
               WHERE edge.scan_run_id = NEW.scan_run_id
           ), 0))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'scan stage cannot be sealed out of order or with stale totals');
END;

CREATE TRIGGER trg_scan_stage_seals_no_update_v5
BEFORE UPDATE ON scan_stage_seals
BEGIN
    SELECT RAISE(ABORT, 'scan stage seal is immutable');
END;

CREATE TRIGGER trg_scan_stage_seals_no_delete_v5
BEFORE DELETE ON scan_stage_seals
BEGIN
    SELECT RAISE(ABORT, 'scan stage seal cannot be deleted');
END;

CREATE TRIGGER trg_media_namespace_paths_insert_guard_v5
BEFORE INSERT ON media_namespace_paths
WHEN NOT EXISTS (
    SELECT 1
    FROM media_files AS media
    JOIN namespace_profiles AS namespace
      ON namespace.id = NEW.namespace_profile_id
     AND namespace.volume_id = NEW.volume_id
    WHERE media.id = NEW.media_file_id
      AND media.volume_id = NEW.volume_id
      AND media.relative_path = NEW.display_path
      AND namespace.origin = 'observed_v5'
      AND namespace.native_path_encoding = CASE NEW.path_encoding
          WHEN 'windows_utf16_le' THEN 'windows_utf16_le'
          ELSE 'unix_bytes'
      END
)
BEGIN
    SELECT RAISE(ABORT, 'media namespace path does not match stable media evidence');
END;

CREATE TRIGGER trg_media_namespace_paths_no_update_v5
BEFORE UPDATE ON media_namespace_paths
BEGIN
    SELECT RAISE(ABORT, 'media namespace path is immutable');
END;

CREATE TRIGGER trg_media_namespace_paths_no_delete_v5
BEFORE DELETE ON media_namespace_paths
BEGIN
    SELECT RAISE(ABORT, 'media namespace path cannot be deleted');
END;

CREATE TRIGGER trg_media_observation_snapshots_insert_guard_v5
BEFORE INSERT ON media_observation_snapshots
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_runs AS run
    JOIN scan_run_sessions AS session
      ON session.scan_run_id = run.id
     AND session.volume_id = run.volume_id
    JOIN capability_profiles AS profile
      ON profile.id = session.capability_profile_id
     AND profile.volume_id = session.volume_id
    JOIN namespace_profiles AS namespace
      ON namespace.id = session.namespace_profile_id
     AND namespace.volume_id = session.volume_id
    JOIN media_namespace_paths AS path
      ON path.id = NEW.media_namespace_path_id
     AND path.volume_id = NEW.volume_id
     AND path.media_file_id = NEW.media_file_id
     AND path.namespace_profile_id = NEW.namespace_profile_id
    WHERE run.id = NEW.scan_run_id
      AND run.volume_id = NEW.volume_id
      AND run.state = 'running'
      AND session.capability_profile_id = NEW.capability_profile_id
      AND session.namespace_profile_id = NEW.namespace_profile_id
      AND path.path_encoding = NEW.path_encoding
      AND namespace.origin = 'observed_v5'
      AND namespace.native_path_encoding = CASE NEW.path_encoding
          WHEN 'windows_utf16_le' THEN 'windows_utf16_le'
          ELSE 'unix_bytes'
      END
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key = session.mount_session_key COLLATE BINARY
      AND (
          (length(session.mount_relative_root_raw) = 0
           AND hex(path.mount_relative_path_raw) =
               hex(NEW.root_relative_path_raw))
          OR
          (length(session.mount_relative_root_raw) > 0
           AND NEW.path_encoding IN ('utf8', 'unix_bytes')
           AND hex(path.mount_relative_path_raw) =
               hex(session.mount_relative_root_raw)
               || '2F' || hex(NEW.root_relative_path_raw))
          OR
          (length(session.mount_relative_root_raw) > 0
           AND NEW.path_encoding = 'windows_utf16_le'
           AND hex(path.mount_relative_path_raw) IN (
               hex(session.mount_relative_root_raw)
                   || '2F00' || hex(NEW.root_relative_path_raw),
               hex(session.mount_relative_root_raw)
                   || '5C00' || hex(NEW.root_relative_path_raw)
           ))
      )
      AND NEW.observed_at_ms >= session.created_at_ms
      AND NOT EXISTS (
          SELECT 1 FROM scan_stage_seals AS seal
          WHERE seal.scan_run_id = NEW.scan_run_id
            AND seal.stage = 'enumeration'
      )
)
BEGIN
    SELECT RAISE(ABORT, 'media observation is not current enumeration evidence');
END;

CREATE TRIGGER trg_media_observation_snapshots_no_update_v5
BEFORE UPDATE ON media_observation_snapshots
BEGIN
    SELECT RAISE(ABORT, 'media observation snapshot is immutable');
END;

CREATE TRIGGER trg_media_observation_snapshots_no_delete_v5
BEFORE DELETE ON media_observation_snapshots
BEGIN
    SELECT RAISE(ABORT, 'media observation snapshot cannot be deleted');
END;

CREATE TRIGGER trg_observation_fingerprints_insert_guard_v5
BEFORE INSERT ON observation_fingerprints
WHEN NOT EXISTS (
    SELECT 1
    FROM media_observation_snapshots AS observation
    JOIN scan_runs AS run
      ON run.id = observation.scan_run_id
     AND run.volume_id = observation.volume_id
    JOIN scan_run_sessions AS session
      ON session.scan_run_id = run.id
     AND session.volume_id = run.volume_id
    JOIN capability_profiles AS profile
      ON profile.id = session.capability_profile_id
     AND profile.volume_id = session.volume_id
    WHERE observation.id = NEW.media_observation_snapshot_id
      AND observation.scan_run_id = NEW.scan_run_id
      AND observation.volume_id = NEW.volume_id
      AND run.state = 'running'
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key = session.mount_session_key COLLATE BINARY
      AND observation.source_signature = NEW.source_signature_before
      AND observation.source_signature = NEW.source_signature_after
      AND observation.size_bytes = NEW.observed_size_bytes
      AND NEW.completed_at_ms >= observation.observed_at_ms
      AND (
          (NEW.fingerprint_kind = 'sample'
           AND EXISTS (
               SELECT 1 FROM scan_stage_seals AS enumeration
               WHERE enumeration.scan_run_id = NEW.scan_run_id
                 AND enumeration.stage = 'enumeration'
           )
           AND NOT EXISTS (
               SELECT 1 FROM scan_stage_seals AS sampling
               WHERE sampling.scan_run_id = NEW.scan_run_id
                 AND sampling.stage = 'sampling'
           ))
          OR
          (NEW.fingerprint_kind = 'exact_bytes'
           AND NEW.read_origin = 'full_hash_read'
           AND EXISTS (
               SELECT 1 FROM scan_stage_seals AS sampling
               WHERE sampling.scan_run_id = NEW.scan_run_id
                 AND sampling.stage = 'sampling'
           )
           AND NOT EXISTS (
               SELECT 1 FROM scan_stage_seals AS full_hash
               WHERE full_hash.scan_run_id = NEW.scan_run_id
                 AND full_hash.stage = 'full_hash'
           ))
          OR
          (NEW.fingerprint_kind = 'exact_bytes'
           AND NEW.read_origin = 'exact_compare_read'
           AND EXISTS (
               SELECT 1 FROM scan_stage_seals AS full_hash
               WHERE full_hash.scan_run_id = NEW.scan_run_id
                 AND full_hash.stage = 'full_hash'
           )
           AND NOT EXISTS (
               SELECT 1 FROM scan_stage_seals AS exact_stage
               WHERE exact_stage.scan_run_id = NEW.scan_run_id
                 AND exact_stage.stage = 'exact_verification'
           ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'fingerprint is not fresh evidence for the current scan stage');
END;

CREATE TRIGGER trg_observation_fingerprints_no_update_v5
BEFORE UPDATE ON observation_fingerprints
BEGIN
    SELECT RAISE(ABORT, 'observation fingerprint is immutable');
END;

CREATE TRIGGER trg_observation_fingerprints_no_delete_v5
BEFORE DELETE ON observation_fingerprints
BEGIN
    SELECT RAISE(ABORT, 'observation fingerprint cannot be deleted');
END;

CREATE TRIGGER trg_exact_group_builds_insert_guard_v5
BEFORE INSERT ON exact_group_builds
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_runs AS run
    JOIN scan_run_sessions AS session
      ON session.scan_run_id = run.id
     AND session.volume_id = run.volume_id
    JOIN capability_profiles AS profile
      ON profile.id = session.capability_profile_id
     AND profile.volume_id = session.volume_id
    JOIN media_observation_snapshots AS observation
      ON observation.id = NEW.representative_observation_id
     AND observation.scan_run_id = NEW.scan_run_id
     AND observation.volume_id = NEW.volume_id
    JOIN observation_fingerprints AS fingerprint
      ON fingerprint.id = NEW.representative_fingerprint_id
     AND fingerprint.media_observation_snapshot_id = observation.id
     AND fingerprint.scan_run_id = observation.scan_run_id
     AND fingerprint.volume_id = observation.volume_id
    WHERE run.id = NEW.scan_run_id
      AND run.volume_id = NEW.volume_id
      AND run.state = 'running'
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key = session.mount_session_key COLLATE BINARY
      AND fingerprint.fingerprint_kind = 'exact_bytes'
      AND fingerprint.source_signature_before = observation.source_signature
      AND fingerprint.source_signature_after = observation.source_signature
      AND fingerprint.bytes_read = observation.size_bytes
      AND fingerprint.observed_size_bytes = observation.size_bytes
      AND fingerprint.reached_expected_eof = 1
      AND NEW.state = 'draft'
      AND NEW.created_at_ms >= fingerprint.completed_at_ms
      AND EXISTS (
          SELECT 1 FROM scan_stage_seals AS full_hash
          WHERE full_hash.scan_run_id = NEW.scan_run_id
            AND full_hash.stage = 'full_hash'
      )
      AND NOT EXISTS (
          SELECT 1 FROM scan_stage_seals AS exact_stage
          WHERE exact_stage.scan_run_id = NEW.scan_run_id
            AND exact_stage.stage = 'exact_verification'
      )
)
BEGIN
    SELECT RAISE(ABORT, 'exact group draft lacks current exact representative evidence');
END;

CREATE TRIGGER trg_exact_group_build_members_insert_guard_v5
BEFORE INSERT ON exact_group_build_members
WHEN NOT EXISTS (
    SELECT 1
    FROM exact_group_builds AS build
    JOIN scan_runs AS run
      ON run.id = build.scan_run_id
     AND run.volume_id = build.volume_id
    JOIN scan_run_sessions AS session
      ON session.scan_run_id = run.id
     AND session.volume_id = run.volume_id
    JOIN capability_profiles AS profile
      ON profile.id = session.capability_profile_id
     AND profile.volume_id = session.volume_id
    JOIN media_observation_snapshots AS observation
      ON observation.id = NEW.media_observation_snapshot_id
     AND observation.scan_run_id = NEW.scan_run_id
     AND observation.volume_id = NEW.volume_id
    JOIN observation_fingerprints AS fingerprint
      ON fingerprint.id = NEW.observation_fingerprint_id
     AND fingerprint.media_observation_snapshot_id = observation.id
     AND fingerprint.scan_run_id = observation.scan_run_id
     AND fingerprint.volume_id = observation.volume_id
    JOIN observation_fingerprints AS representative
      ON representative.id = build.representative_fingerprint_id
     AND representative.media_observation_snapshot_id =
         build.representative_observation_id
     AND representative.scan_run_id = build.scan_run_id
     AND representative.volume_id = build.volume_id
    WHERE build.id = NEW.exact_group_build_id
      AND build.scan_run_id = NEW.scan_run_id
      AND build.volume_id = NEW.volume_id
      AND build.state = 'draft'
      AND run.state = 'running'
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key = session.mount_session_key COLLATE BINARY
      AND NEW.ordinal < build.expected_member_count
      AND (
          (NEW.ordinal = 0
           AND NEW.media_observation_snapshot_id = build.representative_observation_id
           AND NEW.observation_fingerprint_id = build.representative_fingerprint_id)
          OR
          (NEW.ordinal > 0
           AND NEW.media_observation_snapshot_id <> build.representative_observation_id)
      )
      AND fingerprint.fingerprint_kind = 'exact_bytes'
      AND fingerprint.algorithm = representative.algorithm
      AND fingerprint.algorithm_version = representative.algorithm_version
      AND fingerprint.parameters_hash = representative.parameters_hash
      AND fingerprint.digest = representative.digest
      AND fingerprint.observed_size_bytes = representative.observed_size_bytes
      AND fingerprint.source_signature_before = observation.source_signature
      AND fingerprint.source_signature_after = observation.source_signature
      AND fingerprint.bytes_read = observation.size_bytes
      AND fingerprint.reached_expected_eof = 1
      AND NEW.created_at_ms >= build.created_at_ms
      AND NOT EXISTS (
          SELECT 1 FROM exact_group_build_members AS existing
          WHERE existing.exact_group_build_id = NEW.exact_group_build_id
            AND existing.manifest_leaf = NEW.manifest_leaf
      )
      AND (
          SELECT count(*) FROM exact_group_build_members AS existing
          WHERE existing.exact_group_build_id = NEW.exact_group_build_id
      ) < build.expected_member_count
      AND NOT EXISTS (
          SELECT 1 FROM scan_stage_seals AS exact_stage
          WHERE exact_stage.scan_run_id = NEW.scan_run_id
            AND exact_stage.stage = 'exact_verification'
      )
)
BEGIN
    SELECT RAISE(ABORT, 'exact group member is not compatible fresh evidence');
END;

CREATE TRIGGER trg_exact_group_build_members_no_update_v5
BEFORE UPDATE ON exact_group_build_members
BEGIN
    SELECT RAISE(ABORT, 'exact group member is immutable');
END;

CREATE TRIGGER trg_exact_group_build_members_no_delete_v5
BEFORE DELETE ON exact_group_build_members
BEGIN
    SELECT RAISE(ABORT, 'exact group member cannot be deleted');
END;

CREATE TRIGGER trg_exact_verification_edges_insert_guard_v5
BEFORE INSERT ON exact_verification_edges
WHEN NOT EXISTS (
    SELECT 1
    FROM exact_group_builds AS build
    JOIN scan_runs AS run
      ON run.id = build.scan_run_id
     AND run.volume_id = build.volume_id
    JOIN scan_run_sessions AS session
      ON session.scan_run_id = run.id
     AND session.volume_id = run.volume_id
    JOIN capability_profiles AS profile
      ON profile.id = session.capability_profile_id
     AND profile.volume_id = session.volume_id
    JOIN exact_group_build_members AS member
      ON member.exact_group_build_id = build.id
     AND member.media_observation_snapshot_id = NEW.member_observation_id
     AND member.scan_run_id = build.scan_run_id
     AND member.volume_id = build.volume_id
    JOIN media_observation_snapshots AS representative_observation
      ON representative_observation.id = NEW.representative_observation_id
     AND representative_observation.scan_run_id = build.scan_run_id
     AND representative_observation.volume_id = build.volume_id
    JOIN media_observation_snapshots AS member_observation
      ON member_observation.id = NEW.member_observation_id
     AND member_observation.scan_run_id = build.scan_run_id
     AND member_observation.volume_id = build.volume_id
    JOIN observation_fingerprints AS representative_fingerprint
      ON representative_fingerprint.id = NEW.representative_fingerprint_id
     AND representative_fingerprint.media_observation_snapshot_id =
         representative_observation.id
     AND representative_fingerprint.scan_run_id = build.scan_run_id
     AND representative_fingerprint.volume_id = build.volume_id
    JOIN observation_fingerprints AS member_fingerprint
      ON member_fingerprint.id = NEW.member_fingerprint_id
     AND member_fingerprint.media_observation_snapshot_id = member_observation.id
     AND member_fingerprint.scan_run_id = build.scan_run_id
     AND member_fingerprint.volume_id = build.volume_id
    WHERE build.id = NEW.exact_group_build_id
      AND build.scan_run_id = NEW.scan_run_id
      AND build.volume_id = NEW.volume_id
      AND build.state = 'draft'
      AND run.state = 'running'
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key = session.mount_session_key COLLATE BINARY
      AND NEW.representative_observation_id = build.representative_observation_id
      AND NEW.representative_fingerprint_id = build.representative_fingerprint_id
      AND NEW.member_fingerprint_id = member.observation_fingerprint_id
      AND representative_fingerprint.fingerprint_kind = 'exact_bytes'
      AND member_fingerprint.fingerprint_kind = 'exact_bytes'
      AND representative_fingerprint.algorithm = member_fingerprint.algorithm
      AND representative_fingerprint.algorithm_version = member_fingerprint.algorithm_version
      AND representative_fingerprint.parameters_hash = member_fingerprint.parameters_hash
      AND representative_fingerprint.digest = member_fingerprint.digest
      AND representative_fingerprint.observed_size_bytes =
          member_fingerprint.observed_size_bytes
      AND representative_fingerprint.source_signature_before =
          representative_observation.source_signature
      AND representative_fingerprint.source_signature_after =
          representative_observation.source_signature
      AND member_fingerprint.source_signature_before =
          member_observation.source_signature
      AND member_fingerprint.source_signature_after =
          member_observation.source_signature
      AND NEW.representative_source_signature =
          representative_observation.source_signature
      AND NEW.member_source_signature = member_observation.source_signature
      AND NEW.compared_bytes = representative_observation.size_bytes
      AND NEW.compared_bytes = member_observation.size_bytes
      AND NEW.verified_at_ms >= build.created_at_ms
      AND NEW.verified_at_ms >= representative_fingerprint.completed_at_ms
      AND NEW.verified_at_ms >= member_fingerprint.completed_at_ms
      AND (
          SELECT count(*) FROM exact_verification_edges AS existing
          WHERE existing.exact_group_build_id = NEW.exact_group_build_id
      ) < build.expected_edge_count
      AND NOT EXISTS (
          SELECT 1 FROM scan_stage_seals AS exact_stage
          WHERE exact_stage.scan_run_id = NEW.scan_run_id
            AND exact_stage.stage = 'exact_verification'
      )
)
BEGIN
    SELECT RAISE(ABORT, 'exact verification edge does not prove current equal bytes');
END;

CREATE TRIGGER trg_exact_verification_edges_no_update_v5
BEFORE UPDATE ON exact_verification_edges
BEGIN
    SELECT RAISE(ABORT, 'exact verification edge is immutable');
END;

CREATE TRIGGER trg_exact_verification_edges_no_delete_v5
BEFORE DELETE ON exact_verification_edges
BEGIN
    SELECT RAISE(ABORT, 'exact verification edge cannot be deleted');
END;

CREATE TRIGGER trg_exact_group_builds_update_guard_v5
BEFORE UPDATE ON exact_group_builds
WHEN OLD.build_key IS NOT NEW.build_key
  OR OLD.volume_id IS NOT NEW.volume_id
  OR OLD.scan_run_id IS NOT NEW.scan_run_id
  OR OLD.representative_observation_id IS NOT NEW.representative_observation_id
  OR OLD.representative_fingerprint_id IS NOT NEW.representative_fingerprint_id
  OR OLD.expected_member_count IS NOT NEW.expected_member_count
  OR OLD.expected_edge_count IS NOT NEW.expected_edge_count
  OR OLD.expected_manifest_digest IS NOT NEW.expected_manifest_digest
  OR OLD.created_at_ms IS NOT NEW.created_at_ms
  OR OLD.state <> 'draft'
  OR NEW.state NOT IN ('verified', 'abandoned')
  OR (NEW.state = 'verified' AND NOT EXISTS (
      SELECT 1
      FROM scan_runs AS run
      JOIN scan_run_sessions AS session
        ON session.scan_run_id = run.id
       AND session.volume_id = run.volume_id
      JOIN capability_profiles AS profile
        ON profile.id = session.capability_profile_id
       AND profile.volume_id = session.volume_id
      JOIN media_observation_snapshots AS representative_observation
        ON representative_observation.id = NEW.representative_observation_id
       AND representative_observation.scan_run_id = NEW.scan_run_id
       AND representative_observation.volume_id = NEW.volume_id
      WHERE run.id = NEW.scan_run_id
        AND run.volume_id = NEW.volume_id
        AND run.state = 'running'
        AND profile.profile_hash_version = 2
        AND profile.is_current = 1
        AND profile.probe_status = 'complete'
        AND profile.can_read = 1
        AND profile.mount_session_key = session.mount_session_key COLLATE BINARY
        AND NEW.finalized_at_ms >= NEW.created_at_ms
        AND NEW.independent_file_count = (
            SELECT count(DISTINCT CASE
                WHEN observation.file_object_key IS NULL
                    THEN 'unknown:' || CAST(observation.id AS TEXT)
                ELSE 'known:' || hex(observation.file_object_key)
            END)
            FROM exact_group_build_members AS member
            JOIN media_observation_snapshots AS observation
              ON observation.id = member.media_observation_snapshot_id
             AND observation.scan_run_id = member.scan_run_id
             AND observation.volume_id = member.volume_id
            WHERE member.exact_group_build_id = NEW.id
        )
        AND (
            representative_observation.size_bytes = 0
            OR NEW.independent_file_count - 1
                <= 9223372036854775807 / representative_observation.size_bytes
        )
        AND NEW.logical_reclaimable_bytes =
            (NEW.independent_file_count - 1) * representative_observation.size_bytes
        AND NOT EXISTS (
            SELECT 1 FROM scan_stage_seals AS exact_stage
            WHERE exact_stage.scan_run_id = NEW.scan_run_id
              AND exact_stage.stage = 'exact_verification'
        )
        AND (
            SELECT count(*) FROM exact_group_build_members AS member
            WHERE member.exact_group_build_id = NEW.id
        ) = NEW.expected_member_count
        AND (
            SELECT count(DISTINCT member.manifest_leaf)
            FROM exact_group_build_members AS member
            WHERE member.exact_group_build_id = NEW.id
        ) = NEW.expected_member_count
        AND (
            SELECT min(member.ordinal) FROM exact_group_build_members AS member
            WHERE member.exact_group_build_id = NEW.id
        ) = 0
        AND (
            SELECT max(member.ordinal) FROM exact_group_build_members AS member
            WHERE member.exact_group_build_id = NEW.id
        ) = NEW.expected_member_count - 1
        AND EXISTS (
            SELECT 1 FROM exact_group_build_members AS representative_member
            WHERE representative_member.exact_group_build_id = NEW.id
              AND representative_member.ordinal = 0
              AND representative_member.media_observation_snapshot_id =
                  NEW.representative_observation_id
              AND representative_member.observation_fingerprint_id =
                  NEW.representative_fingerprint_id
        )
        AND (
            SELECT count(*) FROM exact_verification_edges AS edge
            WHERE edge.exact_group_build_id = NEW.id
        ) = NEW.expected_edge_count
        AND NOT EXISTS (
            SELECT 1
            FROM exact_group_build_members AS member
            WHERE member.exact_group_build_id = NEW.id
              AND member.media_observation_snapshot_id <>
                  NEW.representative_observation_id
              AND NOT EXISTS (
                  SELECT 1 FROM exact_verification_edges AS edge
                  WHERE edge.exact_group_build_id = member.exact_group_build_id
                    AND edge.member_observation_id =
                        member.media_observation_snapshot_id
                  )
        )
        AND NOT EXISTS (
            SELECT 1
            FROM exact_group_build_members AS candidate
            JOIN media_observation_snapshots AS candidate_observation
              ON candidate_observation.id =
                 candidate.media_observation_snapshot_id
             AND candidate_observation.scan_run_id = candidate.scan_run_id
             AND candidate_observation.volume_id = candidate.volume_id
            JOIN exact_group_build_members AS existing
              ON existing.scan_run_id = candidate.scan_run_id
             AND existing.exact_group_build_id <> candidate.exact_group_build_id
            JOIN media_observation_snapshots AS existing_observation
              ON existing_observation.id =
                 existing.media_observation_snapshot_id
             AND existing_observation.scan_run_id = existing.scan_run_id
             AND existing_observation.volume_id = existing.volume_id
            JOIN exact_group_builds AS existing_build
              ON existing_build.id = existing.exact_group_build_id
             AND existing_build.scan_run_id = existing.scan_run_id
             AND existing_build.volume_id = existing.volume_id
             AND existing_build.state = 'verified'
            WHERE candidate.exact_group_build_id = NEW.id
              AND (
                  existing.media_observation_snapshot_id =
                      candidate.media_observation_snapshot_id
                  OR (
                      candidate_observation.file_object_key IS NOT NULL
                      AND existing_observation.file_object_key =
                          candidate_observation.file_object_key
                  )
              )
        )
  ))
  OR (NEW.state = 'abandoned' AND NOT EXISTS (
      SELECT 1
      FROM scan_runs AS run
      LEFT JOIN scan_run_sessions AS session
        ON session.scan_run_id = run.id
       AND session.volume_id = run.volume_id
      LEFT JOIN capability_profiles AS profile
        ON profile.id = session.capability_profile_id
       AND profile.volume_id = session.volume_id
      WHERE run.id = NEW.scan_run_id
        AND run.volume_id = NEW.volume_id
        AND NEW.finalized_at_ms >= NEW.created_at_ms
        AND NEW.abandon_reason_code IS NOT NULL
        AND (
            run.state IN ('failed', 'interrupted', 'cancelled')
            OR (
                run.state = 'running'
                AND profile.profile_hash_version = 2
                AND profile.is_current = 1
                AND profile.probe_status = 'complete'
                AND profile.can_read = 1
                AND profile.mount_session_key =
                    session.mount_session_key COLLATE BINARY
                AND NOT EXISTS (
                    SELECT 1 FROM scan_stage_seals AS exact_stage
                    WHERE exact_stage.scan_run_id = NEW.scan_run_id
                      AND exact_stage.stage = 'exact_verification'
                )
            )
        )
  ))
BEGIN
    SELECT RAISE(ABORT, 'exact group state transition lacks a complete manifest and edge set');
END;

CREATE TRIGGER trg_exact_group_builds_no_delete_v5
BEFORE DELETE ON exact_group_builds
BEGIN
    SELECT RAISE(ABORT, 'exact group build cannot be deleted');
END;
