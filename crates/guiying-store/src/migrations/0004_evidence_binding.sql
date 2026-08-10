-- Version 4 binds every newly persisted path key to the capability snapshot
-- and path-semantics version that produced it. Legacy rows are retained, but
-- missing historical evidence is represented as NULL rather than invented.

ALTER TABLE capability_profiles
    ADD COLUMN profile_hash_version INTEGER NOT NULL DEFAULT 1
        CHECK (profile_hash_version IN (1, 2));
ALTER TABLE capability_profiles
    ADD COLUMN mount_session_key TEXT;
ALTER TABLE capability_profiles
    ADD COLUMN probe_protocol_version INTEGER
        CHECK (probe_protocol_version IS NULL OR probe_protocol_version >= 1);
ALTER TABLE capability_profiles
    ADD COLUMN case_behavior TEXT
        CHECK (case_behavior IS NULL OR case_behavior IN (
            'sensitive',
            'insensitive_preserving',
            'insensitive_nonpreserving'
        ));
ALTER TABLE capability_profiles
    ADD COLUMN unicode_behavior TEXT
        CHECK (unicode_behavior IS NULL OR unicode_behavior IN (
            'exact', 'nfc', 'nfd', 'normalizing_other'
        ));
ALTER TABLE capability_profiles
    ADD COLUMN path_encoding_family TEXT
        CHECK (path_encoding_family IS NULL OR path_encoding_family IN ('unix', 'windows'));
ALTER TABLE capability_profiles
    ADD COLUMN path_semantics_version INTEGER NOT NULL DEFAULT 1
        CHECK (path_semantics_version >= 1);
ALTER TABLE capability_profiles
    ADD COLUMN can_no_replace INTEGER
        CHECK (can_no_replace IS NULL OR can_no_replace IN (0, 1));
ALTER TABLE capability_profiles
    ADD COLUMN can_sync_directory INTEGER
        CHECK (can_sync_directory IS NULL OR can_sync_directory IN (0, 1));
ALTER TABLE capability_profiles
    ADD COLUMN can_append_durable INTEGER
        CHECK (can_append_durable IS NULL OR can_append_durable IN (0, 1));
ALTER TABLE capability_profiles
    ADD COLUMN single_writer INTEGER
        CHECK (single_writer IS NULL OR single_writer IN (0, 1));

-- Rust computes the version-2 digest inside the same migration transaction
-- before this SQL body runs. Only then is the format marker advanced.
-- Values that the legacy v1 digest never authenticated must not be laundered
-- into a trusted v2 snapshot. They remain honestly unknown until a fresh
-- probe records a new profile.
UPDATE capability_profiles SET
    mount_flags = NULL,
    can_use_hard_links = NULL,
    can_use_clones = NULL,
    maximum_name_bytes = NULL,
    maximum_file_bytes = NULL;
UPDATE capability_profiles SET profile_hash_version = 2;

CREATE UNIQUE INDEX ux_volumes_native_uuid_v4
    ON volumes(native_uuid)
    WHERE native_uuid IS NOT NULL;
CREATE UNIQUE INDEX ux_volumes_marker_uuid_v4
    ON volumes(marker_uuid)
    WHERE marker_uuid IS NOT NULL;

ALTER TABLE scan_runs
    ADD COLUMN state_version INTEGER NOT NULL DEFAULT 0
        CHECK (state_version >= 0);

CREATE TABLE scan_job_roots (
    scan_job_id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    capability_profile_id INTEGER,
    path_semantics_version INTEGER NOT NULL CHECK (path_semantics_version >= 1),
    relative_path_raw BLOB NOT NULL
        CHECK (length(relative_path_raw) <= 65536),
    path_encoding TEXT NOT NULL
        CHECK (path_encoding IN ('utf8', 'unix_bytes', 'windows_utf16_le')),
    semantic_path_key BLOB NOT NULL
        CHECK (length(semantic_path_key) BETWEEN 1 AND 4096),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (volume_id, scan_job_id),
    FOREIGN KEY (volume_id, scan_job_id) REFERENCES scan_jobs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, capability_profile_id)
        REFERENCES capability_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE TABLE scan_run_roots (
    scan_run_id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    capability_profile_id INTEGER NOT NULL,
    path_semantics_version INTEGER NOT NULL CHECK (path_semantics_version >= 1),
    relative_path_raw BLOB NOT NULL
        CHECK (length(relative_path_raw) <= 65536),
    path_encoding TEXT NOT NULL
        CHECK (path_encoding IN ('utf8', 'unix_bytes', 'windows_utf16_le')),
    semantic_path_key BLOB NOT NULL
        CHECK (length(semantic_path_key) BETWEEN 1 AND 4096),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (volume_id, scan_run_id),
    FOREIGN KEY (volume_id, scan_run_id) REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, capability_profile_id)
        REFERENCES capability_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE TABLE media_path_keys (
    volume_id INTEGER NOT NULL,
    media_file_id INTEGER NOT NULL,
    capability_profile_id INTEGER NOT NULL,
    path_semantics_version INTEGER NOT NULL CHECK (path_semantics_version >= 1),
    semantic_path_key BLOB NOT NULL
        CHECK (length(semantic_path_key) BETWEEN 1 AND 4096),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (volume_id, media_file_id),
    UNIQUE (
        volume_id,
        capability_profile_id,
        path_semantics_version,
        semantic_path_key
    ),
    FOREIGN KEY (volume_id, media_file_id) REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, capability_profile_id)
        REFERENCES capability_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE media_file_observations (
    id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    media_file_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    capability_profile_id INTEGER NOT NULL,
    path_semantics_version INTEGER NOT NULL CHECK (path_semantics_version >= 1),
    relative_path TEXT NOT NULL
        CHECK (length(CAST(relative_path AS BLOB)) BETWEEN 1 AND 65536),
    relative_path_raw BLOB NOT NULL
        CHECK (length(relative_path_raw) BETWEEN 1 AND 65536),
    path_encoding TEXT NOT NULL
        CHECK (path_encoding IN ('utf8', 'unix_bytes', 'windows_utf16_le')),
    semantic_path_key BLOB NOT NULL
        CHECK (length(semantic_path_key) BETWEEN 1 AND 4096),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
    UNIQUE (scan_run_id, media_file_id),
    UNIQUE (
        volume_id,
        scan_run_id,
        capability_profile_id,
        path_semantics_version,
        semantic_path_key
    ),
    UNIQUE (volume_id, id),
    FOREIGN KEY (volume_id, media_file_id) REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id) REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, capability_profile_id)
        REFERENCES capability_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_media_file_observations_run_page
    ON media_file_observations(scan_run_id, id);

-- Existing v3 evidence did not preserve raw root bytes. UTF-8 is the only
-- lossless reconstruction possible; it is recorded explicitly. A job with no
-- historical run/current profile remains capability-unbound and cannot be
-- used by the v4 repository as a new execution root.
INSERT INTO scan_run_roots (
    scan_run_id,
    volume_id,
    capability_profile_id,
    path_semantics_version,
    relative_path_raw,
    path_encoding,
    semantic_path_key,
    created_at_ms
)
SELECT
    run.id,
    run.volume_id,
    run.capability_profile_id,
    profile.path_semantics_version,
    CAST(run.root_relative_path AS BLOB),
    'utf8',
    run.root_path_key,
    run.created_at_ms
FROM scan_runs AS run
JOIN capability_profiles AS profile
  ON profile.id = run.capability_profile_id
 AND profile.volume_id = run.volume_id;

INSERT INTO scan_job_roots (
    scan_job_id,
    volume_id,
    capability_profile_id,
    path_semantics_version,
    relative_path_raw,
    path_encoding,
    semantic_path_key,
    created_at_ms
)
SELECT
    job.id,
    job.volume_id,
    COALESCE(
        active.capability_profile_id,
        (
            SELECT run.capability_profile_id
            FROM scan_job_runs AS binding
            JOIN scan_runs AS run ON run.id = binding.scan_run_id
            WHERE binding.scan_job_id = job.id
              AND binding.volume_id = job.volume_id
            ORDER BY binding.attempt_number
            LIMIT 1
        )
    ),
    COALESCE(
        active_profile.path_semantics_version,
        (
            SELECT profile.path_semantics_version
            FROM scan_job_runs AS binding
            JOIN scan_runs AS run ON run.id = binding.scan_run_id
            JOIN capability_profiles AS profile
              ON profile.id = run.capability_profile_id
             AND profile.volume_id = run.volume_id
            WHERE binding.scan_job_id = job.id
              AND binding.volume_id = job.volume_id
            ORDER BY binding.attempt_number
            LIMIT 1
        ),
        1
    ),
    CAST(job.root_relative_path AS BLOB),
    'utf8',
    job.root_path_key,
    job.created_at_ms
FROM scan_jobs AS job
LEFT JOIN scan_runs AS active
  ON active.id = job.active_scan_run_id
 AND active.volume_id = job.volume_id
LEFT JOIN capability_profiles AS active_profile
  ON active_profile.id = active.capability_profile_id
 AND active_profile.volume_id = active.volume_id;

INSERT INTO media_path_keys (
    volume_id,
    media_file_id,
    capability_profile_id,
    path_semantics_version,
    semantic_path_key,
    created_at_ms
)
SELECT
    media.volume_id,
    media.id,
    run.capability_profile_id,
    profile.path_semantics_version,
    media.path_key,
    media.created_at_ms
FROM media_files AS media
JOIN scan_runs AS run
  ON run.id = media.last_seen_scan_run_id
 AND run.volume_id = media.volume_id
JOIN capability_profiles AS profile
  ON profile.id = run.capability_profile_id
 AND profile.volume_id = run.volume_id;

INSERT INTO media_file_observations (
    volume_id,
    media_file_id,
    scan_run_id,
    capability_profile_id,
    path_semantics_version,
    relative_path,
    relative_path_raw,
    path_encoding,
    semantic_path_key,
    observed_at_ms
)
SELECT
    media.volume_id,
    media.id,
    media.last_seen_scan_run_id,
    run.capability_profile_id,
    profile.path_semantics_version,
    media.relative_path,
    COALESCE(path.relative_path_raw, CAST(media.relative_path AS BLOB)),
    COALESCE(path.path_encoding, 'utf8'),
    media.path_key,
    media.updated_at_ms
FROM media_files AS media
JOIN scan_runs AS run
  ON run.id = media.last_seen_scan_run_id
 AND run.volume_id = media.volume_id
JOIN capability_profiles AS profile
  ON profile.id = run.capability_profile_id
 AND profile.volume_id = run.volume_id
LEFT JOIN media_file_paths AS path
  ON path.volume_id = media.volume_id
 AND path.media_file_id = media.id;

CREATE TRIGGER trg_volumes_identity_immutable_v4
BEFORE UPDATE ON volumes
WHEN OLD.identity_key IS NOT NEW.identity_key
  OR (OLD.marker_uuid IS NOT NEW.marker_uuid AND NOT (
       OLD.identity_strength = 'weak'
       AND NEW.identity_strength = 'strong'
       AND OLD.marker_uuid IS NULL
       AND NEW.marker_uuid IS NOT NULL
     ))
  OR (OLD.native_uuid IS NOT NEW.native_uuid AND NOT (
       OLD.identity_strength = 'weak'
       AND NEW.identity_strength = 'strong'
       AND OLD.native_uuid IS NULL
       AND NEW.native_uuid IS NOT NULL
     ))
  OR (OLD.identity_strength IS NOT NEW.identity_strength AND NOT (
       OLD.identity_strength = 'weak'
       AND NEW.identity_strength = 'strong'
       AND (
         (OLD.marker_uuid IS NULL AND NEW.marker_uuid IS NOT NULL)
         OR (OLD.native_uuid IS NULL AND NEW.native_uuid IS NOT NULL)
       )
     ))
  OR (NEW.identity_strength = 'strong'
      AND (NEW.marker_uuid IS NULL OR length(CAST(NEW.marker_uuid AS BLOB)) = 0)
      AND (NEW.native_uuid IS NULL OR length(CAST(NEW.native_uuid AS BLOB)) = 0))
  OR (NEW.marker_uuid IS NOT NULL AND length(CAST(NEW.marker_uuid AS BLOB)) = 0)
  OR (NEW.native_uuid IS NOT NULL AND length(CAST(NEW.native_uuid AS BLOB)) = 0)
BEGIN
    SELECT RAISE(ABORT, 'volume identity is immutable or invalid');
END;

CREATE TRIGGER trg_volumes_identity_insert_guard_v4
BEFORE INSERT ON volumes
WHEN (NEW.identity_strength = 'strong'
      AND (NEW.marker_uuid IS NULL OR length(CAST(NEW.marker_uuid AS BLOB)) = 0)
      AND (NEW.native_uuid IS NULL OR length(CAST(NEW.native_uuid AS BLOB)) = 0))
  OR (NEW.marker_uuid IS NOT NULL AND length(CAST(NEW.marker_uuid AS BLOB)) = 0)
  OR (NEW.native_uuid IS NOT NULL AND length(CAST(NEW.native_uuid AS BLOB)) = 0)
  OR EXISTS (
      SELECT 1 FROM volumes AS existing
      WHERE existing.identity_key <> NEW.identity_key
        AND ((NEW.marker_uuid IS NOT NULL AND existing.marker_uuid = NEW.marker_uuid)
          OR (NEW.native_uuid IS NOT NULL AND existing.native_uuid = NEW.native_uuid))
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid or aliased volume identity evidence');
END;

CREATE TRIGGER trg_volumes_no_delete_v4
BEFORE DELETE ON volumes
BEGIN
    SELECT RAISE(ABORT, 'volume evidence cannot be deleted');
END;

CREATE TRIGGER trg_capability_profiles_evidence_immutable_v4
BEFORE UPDATE ON capability_profiles
WHEN OLD.volume_id IS NOT NEW.volume_id
  OR OLD.profile_hash IS NOT NEW.profile_hash
  OR OLD.profile_hash_version IS NOT NEW.profile_hash_version
  OR OLD.probe_mode IS NOT NEW.probe_mode
  OR OLD.probe_status IS NOT NEW.probe_status
  OR OLD.observed_at_ms IS NOT NEW.observed_at_ms
  OR OLD.os_build IS NOT NEW.os_build
  OR OLD.mount_session_key IS NOT NEW.mount_session_key
  OR OLD.probe_protocol_version IS NOT NEW.probe_protocol_version
  OR OLD.driver_name IS NOT NEW.driver_name
  OR OLD.driver_version IS NOT NEW.driver_version
  OR OLD.mount_flags IS NOT NEW.mount_flags
  OR OLD.case_behavior IS NOT NEW.case_behavior
  OR OLD.unicode_behavior IS NOT NEW.unicode_behavior
  OR OLD.path_encoding_family IS NOT NEW.path_encoding_family
  OR OLD.path_semantics_version IS NOT NEW.path_semantics_version
  OR OLD.can_read IS NOT NEW.can_read
  OR OLD.can_write IS NOT NEW.can_write
  OR OLD.can_rename_same_volume IS NOT NEW.can_rename_same_volume
  OR OLD.can_rename_exclusive IS NOT NEW.can_rename_exclusive
  OR OLD.can_no_replace IS NOT NEW.can_no_replace
  OR OLD.can_sync_directory IS NOT NEW.can_sync_directory
  OR OLD.can_append_durable IS NOT NEW.can_append_durable
  OR OLD.single_writer IS NOT NEW.single_writer
  OR OLD.can_set_birth_time IS NOT NEW.can_set_birth_time
  OR OLD.can_set_modified_time IS NOT NEW.can_set_modified_time
  OR OLD.can_use_xattrs IS NOT NEW.can_use_xattrs
  OR OLD.can_use_hard_links IS NOT NEW.can_use_hard_links
  OR OLD.can_use_clones IS NOT NEW.can_use_clones
  OR OLD.has_persistent_file_ids IS NOT NEW.has_persistent_file_ids
  OR OLD.timestamp_granularity_ns IS NOT NEW.timestamp_granularity_ns
  OR OLD.maximum_name_bytes IS NOT NEW.maximum_name_bytes
  OR OLD.maximum_file_bytes IS NOT NEW.maximum_file_bytes
  OR OLD.raw_capabilities_json IS NOT NEW.raw_capabilities_json
  OR OLD.created_at_ms IS NOT NEW.created_at_ms
BEGIN
    SELECT RAISE(ABORT, 'capability profile evidence is immutable');
END;

CREATE TRIGGER trg_capability_profiles_no_delete_v4
BEFORE DELETE ON capability_profiles
BEGIN
    SELECT RAISE(ABORT, 'capability profile evidence cannot be deleted');
END;

CREATE TRIGGER trg_scan_job_roots_insert_guard_v4
BEFORE INSERT ON scan_job_roots
WHEN NOT EXISTS (
    SELECT 1 FROM scan_jobs AS job
    WHERE job.id = NEW.scan_job_id
      AND job.volume_id = NEW.volume_id
      AND job.root_path_key = NEW.semantic_path_key
      AND (NEW.path_encoding <> 'utf8'
           OR CAST(job.root_relative_path AS BLOB) = NEW.relative_path_raw)
)
 OR (NEW.capability_profile_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM capability_profiles AS profile
    WHERE profile.id = NEW.capability_profile_id
      AND profile.volume_id = NEW.volume_id
      AND profile.path_semantics_version = NEW.path_semantics_version
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key IS NOT NULL
      AND profile.probe_protocol_version IS NOT NULL
      AND profile.case_behavior IS NOT NULL
      AND profile.unicode_behavior IS NOT NULL
      AND profile.path_encoding_family IS NOT NULL
      AND ((profile.path_encoding_family = 'unix'
            AND NEW.path_encoding IN ('utf8', 'unix_bytes'))
        OR (profile.path_encoding_family = 'windows'
            AND NEW.path_encoding = 'windows_utf16_le'))
))
BEGIN
    SELECT RAISE(ABORT, 'scan job root evidence mismatch');
END;

CREATE TRIGGER trg_scan_run_roots_insert_guard_v4
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
      AND profile.mount_session_key IS NOT NULL
      AND profile.probe_protocol_version IS NOT NULL
      AND profile.case_behavior IS NOT NULL
      AND profile.unicode_behavior IS NOT NULL
      AND profile.path_encoding_family IS NOT NULL
      AND ((profile.path_encoding_family = 'unix'
            AND NEW.path_encoding IN ('utf8', 'unix_bytes'))
        OR (profile.path_encoding_family = 'windows'
            AND NEW.path_encoding = 'windows_utf16_le'))
      AND (NEW.path_encoding <> 'utf8'
           OR CAST(run.root_relative_path AS BLOB) = NEW.relative_path_raw)
)
BEGIN
    SELECT RAISE(ABORT, 'scan run root evidence mismatch');
END;

CREATE TRIGGER trg_scan_job_roots_no_update_v4
BEFORE UPDATE ON scan_job_roots BEGIN
    SELECT RAISE(ABORT, 'scan job root evidence is immutable');
END;
CREATE TRIGGER trg_scan_job_roots_no_delete_v4
BEFORE DELETE ON scan_job_roots BEGIN
    SELECT RAISE(ABORT, 'scan job root evidence cannot be deleted');
END;
CREATE TRIGGER trg_scan_run_roots_no_update_v4
BEFORE UPDATE ON scan_run_roots BEGIN
    SELECT RAISE(ABORT, 'scan run root evidence is immutable');
END;
CREATE TRIGGER trg_scan_run_roots_no_delete_v4
BEFORE DELETE ON scan_run_roots BEGIN
    SELECT RAISE(ABORT, 'scan run root evidence cannot be deleted');
END;

CREATE TRIGGER trg_scan_job_runs_no_update_v4
BEFORE UPDATE ON scan_job_runs BEGIN
    SELECT RAISE(ABORT, 'scan job/run binding is immutable');
END;

CREATE TRIGGER trg_scan_job_runs_root_evidence_insert_v4
BEFORE INSERT ON scan_job_runs
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_job_roots AS job_root
    JOIN scan_run_roots AS run_root
      ON run_root.scan_run_id = NEW.scan_run_id
     AND run_root.volume_id = NEW.volume_id
    WHERE job_root.scan_job_id = NEW.scan_job_id
      AND job_root.volume_id = NEW.volume_id
      AND job_root.capability_profile_id = run_root.capability_profile_id
      AND job_root.path_semantics_version = run_root.path_semantics_version
      AND job_root.relative_path_raw = run_root.relative_path_raw
      AND job_root.path_encoding = run_root.path_encoding
      AND job_root.semantic_path_key = run_root.semantic_path_key
)
BEGIN
    SELECT RAISE(ABORT, 'scan job/run raw root evidence mismatch');
END;
CREATE TRIGGER trg_scan_job_runs_no_delete_v4
BEFORE DELETE ON scan_job_runs BEGIN
    SELECT RAISE(ABORT, 'scan job/run binding cannot be deleted');
END;

CREATE TRIGGER trg_scan_jobs_active_run_not_cleared_v4
BEFORE UPDATE OF active_scan_run_id ON scan_jobs
WHEN OLD.active_scan_run_id IS NOT NULL
 AND NEW.active_scan_run_id IS NULL
 AND NEW.state <> 'cancelled'
BEGIN
    SELECT RAISE(ABORT, 'active scan run cannot be cleared');
END;

CREATE TRIGGER trg_scan_jobs_state_version_v4
BEFORE UPDATE ON scan_jobs
WHEN (OLD.state IS NOT NEW.state AND NEW.state_version <> OLD.state_version + 1)
  OR (OLD.state IS NEW.state AND NEW.state_version <> OLD.state_version)
BEGIN
    SELECT RAISE(ABORT, 'invalid scan job state version');
END;

CREATE TRIGGER trg_scan_runs_state_version_v4
BEFORE UPDATE ON scan_runs
WHEN (OLD.state IS NOT NEW.state AND NEW.state_version <> OLD.state_version + 1)
  OR (OLD.state IS NEW.state AND NEW.state_version <> OLD.state_version)
BEGIN
    SELECT RAISE(ABORT, 'invalid scan run state version');
END;

CREATE TRIGGER trg_scan_jobs_state_edge_v4
BEFORE UPDATE OF state ON scan_jobs
WHEN OLD.state IS NOT NEW.state
 AND NOT (
      (OLD.state = 'queued' AND NEW.state IN ('running', 'cancelled'))
   OR (OLD.state = 'running' AND NEW.state IN ('paused', 'completed', 'failed', 'cancelled'))
   OR (OLD.state = 'paused' AND NEW.state IN ('running', 'failed', 'cancelled'))
   OR (OLD.state = 'failed' AND NEW.state = 'running')
 )
BEGIN
    SELECT RAISE(ABORT, 'invalid scan job state edge');
END;

CREATE TRIGGER trg_scan_runs_state_edge_v4
BEFORE UPDATE OF state ON scan_runs
WHEN OLD.state IS NOT NEW.state
 AND NOT (
      (OLD.state = 'queued' AND NEW.state IN ('running', 'cancelled'))
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

CREATE TRIGGER trg_scan_runs_last_error_v4
BEFORE UPDATE OF state, last_error_code, last_error_message ON scan_runs
WHEN (NEW.state IN ('failed', 'interrupted') AND (
          NEW.last_error_code IS NULL
          OR NEW.last_error_message IS NULL
          OR length(CAST(NEW.last_error_code AS BLOB)) NOT BETWEEN 1 AND 1024
          OR length(CAST(NEW.last_error_message AS BLOB)) NOT BETWEEN 1 AND 65536
      ))
   OR (NEW.state NOT IN ('failed', 'interrupted') AND (
          NEW.last_error_code IS NOT NULL OR NEW.last_error_message IS NOT NULL
      ))
BEGIN
    SELECT RAISE(ABORT, 'scan run last-error evidence does not match state');
END;

CREATE TRIGGER trg_scan_runs_last_error_insert_v4
BEFORE INSERT ON scan_runs
WHEN (NEW.state IN ('failed', 'interrupted') AND (
          NEW.last_error_code IS NULL
          OR NEW.last_error_message IS NULL
          OR length(CAST(NEW.last_error_code AS BLOB)) NOT BETWEEN 1 AND 1024
          OR length(CAST(NEW.last_error_message AS BLOB)) NOT BETWEEN 1 AND 65536
      ))
   OR (NEW.state NOT IN ('failed', 'interrupted') AND (
          NEW.last_error_code IS NOT NULL OR NEW.last_error_message IS NOT NULL
      ))
BEGIN
    SELECT RAISE(ABORT, 'scan run last-error evidence does not match state');
END;

CREATE TRIGGER trg_media_path_keys_no_update_v4
BEFORE UPDATE ON media_path_keys BEGIN
    SELECT RAISE(ABORT, 'media path semantics binding is immutable');
END;
CREATE TRIGGER trg_media_path_keys_insert_guard_v4
BEFORE INSERT ON media_path_keys
WHEN NOT EXISTS (
    SELECT 1 FROM capability_profiles AS profile
    WHERE profile.id = NEW.capability_profile_id
      AND profile.volume_id = NEW.volume_id
      AND profile.path_semantics_version = NEW.path_semantics_version
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key IS NOT NULL
      AND profile.probe_protocol_version IS NOT NULL
      AND profile.case_behavior IS NOT NULL
      AND profile.unicode_behavior IS NOT NULL
      AND profile.path_encoding_family IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'media path key capability mismatch');
END;
CREATE TRIGGER trg_media_path_keys_no_delete_v4
BEFORE DELETE ON media_path_keys BEGIN
    SELECT RAISE(ABORT, 'media path semantics binding cannot be deleted');
END;
CREATE TRIGGER trg_media_file_observations_no_update_v4
BEFORE UPDATE ON media_file_observations BEGIN
    SELECT RAISE(ABORT, 'media file observation is immutable');
END;
CREATE TRIGGER trg_media_file_observations_insert_guard_v4
BEFORE INSERT ON media_file_observations
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_runs AS run
    JOIN media_path_keys AS path
      ON path.volume_id = NEW.volume_id
     AND path.media_file_id = NEW.media_file_id
    JOIN capability_profiles AS profile
      ON profile.id = NEW.capability_profile_id
     AND profile.volume_id = NEW.volume_id
    WHERE run.id = NEW.scan_run_id
      AND run.volume_id = NEW.volume_id
      AND run.state = 'running'
      AND run.capability_profile_id = NEW.capability_profile_id
      AND path.capability_profile_id = NEW.capability_profile_id
      AND path.path_semantics_version = NEW.path_semantics_version
      AND path.semantic_path_key = NEW.semantic_path_key
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key IS NOT NULL
      AND profile.probe_protocol_version IS NOT NULL
      AND profile.case_behavior IS NOT NULL
      AND profile.unicode_behavior IS NOT NULL
      AND profile.path_encoding_family IS NOT NULL
      AND ((profile.path_encoding_family = 'unix'
            AND NEW.path_encoding IN ('utf8', 'unix_bytes'))
        OR (profile.path_encoding_family = 'windows'
            AND NEW.path_encoding = 'windows_utf16_le'))
      AND (NEW.path_encoding <> 'utf8'
           OR NEW.relative_path_raw = CAST(NEW.relative_path AS BLOB))
)
BEGIN
    SELECT RAISE(ABORT, 'media observation capability or path mismatch');
END;
CREATE TRIGGER trg_media_file_observations_no_delete_v4
BEFORE DELETE ON media_file_observations BEGIN
    SELECT RAISE(ABORT, 'media file observation cannot be deleted');
END;

-- The operation executor has not yet bound plans to an explicit Windows
-- namespace/capability profile. Reject such plans instead of treating WTF-16
-- bytes as if the older slash-only checks were sufficient.
CREATE TRIGGER trg_operation_items_windows_path_unsupported_insert_v4
BEFORE INSERT ON operation_items
WHEN NEW.source_path_encoding = 'windows_utf16le'
  OR NEW.destination_path_encoding = 'windows_utf16le'
BEGIN
    SELECT RAISE(ABORT, 'Windows operation paths require a bound namespace profile');
END;

CREATE TRIGGER trg_operation_items_windows_path_unsupported_update_v4
BEFORE UPDATE OF source_relative_path_raw, source_path_encoding,
                 destination_relative_path_raw, destination_path_encoding
ON operation_items
WHEN NEW.source_path_encoding = 'windows_utf16le'
  OR NEW.destination_path_encoding = 'windows_utf16le'
BEGIN
    SELECT RAISE(ABORT, 'Windows operation paths require a bound namespace profile');
END;
