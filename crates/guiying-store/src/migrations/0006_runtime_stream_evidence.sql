-- Version 6 persists the bounded, process-local evidence needed to bridge the
-- authenticated streaming scanner to the normalized version-5 evidence graph.
-- These rows are metadata only.  Opaque tickets are never filesystem paths or
-- durable authority: a new process must interrupt the run and start a new
-- core/volume session before reading media again.

-- Version 5 used the nanosecond representation unit as if it were the actual
-- timestamp granularity of the mounted filesystem.  Keep that legacy value as
-- a storage-unit fact and add a genuinely nullable observed precision field.
ALTER TABLE media_observation_snapshots
    RENAME COLUMN timestamp_granularity_ns TO timestamp_storage_unit_ns;

ALTER TABLE media_observation_snapshots
    ADD COLUMN timestamp_granularity_ns INTEGER
        CHECK (timestamp_granularity_ns IS NULL OR timestamp_granularity_ns > 0);

CREATE TRIGGER trg_media_observation_precision_no_update_v6
BEFORE UPDATE OF timestamp_granularity_ns ON media_observation_snapshots
BEGIN
    SELECT RAISE(ABORT, 'media observation timestamp precision is immutable');
END;

CREATE TABLE scan_core_sessions (
    scan_run_id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    capability_profile_id INTEGER NOT NULL,
    namespace_profile_id INTEGER NOT NULL,
    core_session_id BLOB NOT NULL CHECK (length(core_session_id) = 32),
    trust_scope TEXT NOT NULL CHECK (trust_scope = 'current_core_session_only'),
    engine_contract_version INTEGER NOT NULL CHECK (engine_contract_version = 1),
    root_index INTEGER NOT NULL CHECK (root_index = 0),
    root_kind TEXT NOT NULL CHECK (root_kind = 'directory'),
    root_object_signature BLOB NOT NULL CHECK (length(root_object_signature) = 32),
    root_source_signature BLOB NOT NULL CHECK (length(root_source_signature) = 32),
    bound_at_ms INTEGER NOT NULL CHECK (bound_at_ms >= 0),
    UNIQUE (volume_id, scan_run_id),
    UNIQUE (volume_id, scan_run_id, core_session_id),
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

CREATE INDEX ix_scan_core_sessions_capability_v6
    ON scan_core_sessions(volume_id, capability_profile_id, scan_run_id);

CREATE TABLE scan_file_tickets (
    media_observation_snapshot_id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    core_session_id BLOB NOT NULL CHECK (length(core_session_id) = 32),
    source_signature BLOB NOT NULL CHECK (length(source_signature) = 32),
    ticket_format_version INTEGER NOT NULL CHECK (ticket_format_version = 1),
    ticket_blob BLOB NOT NULL CHECK (length(ticket_blob) BETWEEN 1 AND 65536),
    ticket_sort_key BLOB NOT NULL CHECK (length(ticket_sort_key) = 32),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (volume_id, scan_run_id, ticket_sort_key),
    UNIQUE (
        volume_id,
        scan_run_id,
        media_observation_snapshot_id,
        source_signature
    ),
    FOREIGN KEY (volume_id, scan_run_id, core_session_id)
        REFERENCES scan_core_sessions(volume_id, scan_run_id, core_session_id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id,
        scan_run_id,
        media_observation_snapshot_id,
        source_signature
    ) REFERENCES media_observation_snapshots(
        volume_id,
        scan_run_id,
        id,
        source_signature
    ) ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_scan_file_tickets_page_v6
    ON scan_file_tickets(scan_run_id, ticket_sort_key, media_observation_snapshot_id);

CREATE TABLE scan_directory_observations (
    id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    core_session_id BLOB NOT NULL CHECK (length(core_session_id) = 32),
    root_index INTEGER NOT NULL CHECK (root_index = 0),
    root_relative_path_raw BLOB NOT NULL
        CHECK (length(root_relative_path_raw) <= 65536),
    path_encoding TEXT NOT NULL
        CHECK (path_encoding IN ('utf8', 'unix_bytes', 'windows_utf16_le')),
    display_path TEXT NOT NULL
        CHECK (length(CAST(display_path AS BLOB)) <= 65536),
    source_signature BLOB NOT NULL CHECK (length(source_signature) = 32),
    directory_object_signature BLOB NOT NULL
        CHECK (length(directory_object_signature) = 32),
    ticket_format_version INTEGER NOT NULL CHECK (ticket_format_version = 1),
    ticket_blob BLOB NOT NULL CHECK (length(ticket_blob) BETWEEN 1 AND 65536),
    ticket_sort_key BLOB NOT NULL CHECK (length(ticket_sort_key) = 32),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
    UNIQUE (volume_id, scan_run_id, id),
    UNIQUE (scan_run_id, root_index, path_encoding, root_relative_path_raw),
    UNIQUE (volume_id, scan_run_id, ticket_sort_key),
    CHECK (
        path_encoding <> 'utf8'
        OR root_relative_path_raw = CAST(display_path AS BLOB)
    ),
    FOREIGN KEY (volume_id, scan_run_id, core_session_id)
        REFERENCES scan_core_sessions(volume_id, scan_run_id, core_session_id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_scan_directory_observations_page_v6
    ON scan_directory_observations(scan_run_id, ticket_sort_key, id);

CREATE TABLE scan_coverage_outcomes (
    scan_run_id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    core_session_id BLOB NOT NULL CHECK (length(core_session_id) = 32),
    status TEXT NOT NULL CHECK (status IN ('complete', 'partial', 'interrupted')),
    directory_count INTEGER NOT NULL CHECK (directory_count >= 0),
    replayed_count INTEGER NOT NULL CHECK (replayed_count >= 0),
    stable_count INTEGER NOT NULL CHECK (stable_count >= 0),
    failed_count INTEGER NOT NULL CHECK (failed_count >= 0),
    core_manifest_digest BLOB
        CHECK (core_manifest_digest IS NULL OR length(core_manifest_digest) = 32),
    core_seal_digest BLOB
        CHECK (core_seal_digest IS NULL OR length(core_seal_digest) = 32),
    volume_verification_manifest BLOB
        CHECK (
            volume_verification_manifest IS NULL
            OR length(volume_verification_manifest) = 32
        ),
    finalized_at_ms INTEGER NOT NULL CHECK (finalized_at_ms >= 0),
    UNIQUE (volume_id, scan_run_id),
    CHECK (replayed_count = stable_count + failed_count),
    CHECK (replayed_count <= directory_count),
    CHECK (
        (status = 'complete'
         AND replayed_count = directory_count
         AND stable_count = directory_count
         AND failed_count = 0
         AND core_manifest_digest IS NOT NULL
         AND core_seal_digest IS NOT NULL
         AND volume_verification_manifest IS NOT NULL)
        OR
        (status IN ('partial', 'interrupted')
         AND core_seal_digest IS NULL)
    ),
    FOREIGN KEY (volume_id, scan_run_id, core_session_id)
        REFERENCES scan_core_sessions(volume_id, scan_run_id, core_session_id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER trg_scan_core_sessions_insert_guard_v6
BEFORE INSERT ON scan_core_sessions
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
      AND session.capability_profile_id = NEW.capability_profile_id
      AND session.namespace_profile_id = NEW.namespace_profile_id
      AND session.root_object_signature = NEW.root_object_signature
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key = session.mount_session_key COLLATE BINARY
      AND NEW.bound_at_ms >= session.created_at_ms
      AND NOT EXISTS (
          SELECT 1 FROM scan_stage_seals AS seal
          WHERE seal.scan_run_id = NEW.scan_run_id
            AND seal.stage = 'enumeration'
      )
)
BEGIN
    SELECT RAISE(ABORT, 'core session is not bound to the current scan session');
END;

CREATE TRIGGER trg_scan_core_sessions_no_update_v6
BEFORE UPDATE ON scan_core_sessions
BEGIN
    SELECT RAISE(ABORT, 'core scan session evidence is immutable');
END;

CREATE TRIGGER trg_scan_core_sessions_no_delete_v6
BEFORE DELETE ON scan_core_sessions
BEGIN
    SELECT RAISE(ABORT, 'core scan session evidence cannot be deleted');
END;

CREATE TRIGGER trg_scan_file_tickets_insert_guard_v6
BEFORE INSERT ON scan_file_tickets
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_core_sessions AS core
    JOIN scan_runs AS run
      ON run.id = core.scan_run_id
     AND run.volume_id = core.volume_id
    JOIN media_observation_snapshots AS observation
      ON observation.id = NEW.media_observation_snapshot_id
     AND observation.scan_run_id = NEW.scan_run_id
     AND observation.volume_id = NEW.volume_id
    WHERE core.scan_run_id = NEW.scan_run_id
      AND core.volume_id = NEW.volume_id
      AND core.core_session_id = NEW.core_session_id
      AND run.state = 'running'
      AND observation.source_signature = NEW.source_signature
      AND NEW.created_at_ms >= observation.observed_at_ms
      AND NEW.created_at_ms >= core.bound_at_ms
      AND NOT EXISTS (
          SELECT 1 FROM scan_stage_seals AS seal
          WHERE seal.scan_run_id = NEW.scan_run_id
            AND seal.stage = 'enumeration'
      )
)
BEGIN
    SELECT RAISE(ABORT, 'file ticket is not current authenticated enumeration evidence');
END;

CREATE TRIGGER trg_scan_file_tickets_no_update_v6
BEFORE UPDATE ON scan_file_tickets
BEGIN
    SELECT RAISE(ABORT, 'file ticket evidence is immutable');
END;

CREATE TRIGGER trg_scan_file_tickets_no_delete_v6
BEFORE DELETE ON scan_file_tickets
BEGIN
    SELECT RAISE(ABORT, 'file ticket evidence cannot be deleted');
END;

CREATE TRIGGER trg_scan_directory_observations_insert_guard_v6
BEFORE INSERT ON scan_directory_observations
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_core_sessions AS core
    JOIN scan_run_sessions AS session
      ON session.scan_run_id = core.scan_run_id
     AND session.volume_id = core.volume_id
    JOIN scan_runs AS run
      ON run.id = core.scan_run_id
     AND run.volume_id = core.volume_id
    WHERE core.scan_run_id = NEW.scan_run_id
      AND core.volume_id = NEW.volume_id
      AND core.core_session_id = NEW.core_session_id
      AND core.root_index = NEW.root_index
      AND run.state = 'running'
      AND session.path_encoding = NEW.path_encoding
      AND NEW.observed_at_ms >= core.bound_at_ms
      AND NOT EXISTS (
          SELECT 1 FROM scan_stage_seals AS seal
          WHERE seal.scan_run_id = NEW.scan_run_id
            AND seal.stage = 'enumeration'
      )
)
BEGIN
    SELECT RAISE(ABORT, 'directory ticket is not current authenticated enumeration evidence');
END;

CREATE TRIGGER trg_scan_directory_observations_no_update_v6
BEFORE UPDATE ON scan_directory_observations
BEGIN
    SELECT RAISE(ABORT, 'directory observation evidence is immutable');
END;

CREATE TRIGGER trg_scan_directory_observations_no_delete_v6
BEFORE DELETE ON scan_directory_observations
BEGIN
    SELECT RAISE(ABORT, 'directory observation evidence cannot be deleted');
END;

CREATE TRIGGER trg_scan_coverage_outcomes_insert_guard_v6
BEFORE INSERT ON scan_coverage_outcomes
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_core_sessions AS core
    JOIN scan_runs AS run
      ON run.id = core.scan_run_id
     AND run.volume_id = core.volume_id
    JOIN scan_run_sessions AS session
      ON session.scan_run_id = core.scan_run_id
     AND session.volume_id = core.volume_id
    JOIN capability_profiles AS profile
      ON profile.id = session.capability_profile_id
     AND profile.volume_id = session.volume_id
    WHERE core.scan_run_id = NEW.scan_run_id
      AND core.volume_id = NEW.volume_id
      AND core.core_session_id = NEW.core_session_id
      AND run.state = 'running'
      AND profile.profile_hash_version = 2
      AND profile.is_current = 1
      AND profile.probe_status = 'complete'
      AND profile.can_read = 1
      AND profile.mount_session_key = session.mount_session_key COLLATE BINARY
      AND NEW.directory_count = (
          SELECT count(*) FROM scan_directory_observations AS directory
          WHERE directory.scan_run_id = NEW.scan_run_id
      )
      AND (
          NEW.status <> 'complete'
          OR (
              NEW.finalized_at_ms >= COALESCE((
                  SELECT max(directory.observed_at_ms)
                  FROM scan_directory_observations AS directory
                  WHERE directory.scan_run_id = NEW.scan_run_id
              ), core.bound_at_ms)
              AND (SELECT count(*) FROM scan_file_tickets AS ticket
                   WHERE ticket.scan_run_id = NEW.scan_run_id) =
                  (SELECT count(*) FROM media_observation_snapshots AS observation
                   WHERE observation.scan_run_id = NEW.scan_run_id)
          )
      )
      AND EXISTS (
          SELECT 1 FROM scan_stage_seals AS seal
          WHERE seal.scan_run_id = NEW.scan_run_id
            AND seal.stage = 'full_hash'
            AND seal.sealed_at_ms <= NEW.finalized_at_ms
      )
      AND NOT EXISTS (
          SELECT 1 FROM scan_stage_seals AS seal
          WHERE seal.scan_run_id = NEW.scan_run_id
            AND seal.stage = 'exact_verification'
      )
)
BEGIN
    SELECT RAISE(ABORT, 'coverage outcome lacks current core and volume evidence');
END;

CREATE TRIGGER trg_scan_coverage_outcomes_no_update_v6
BEFORE UPDATE ON scan_coverage_outcomes
BEGIN
    SELECT RAISE(ABORT, 'coverage outcome evidence is immutable');
END;

CREATE TRIGGER trg_scan_coverage_outcomes_no_delete_v6
BEFORE DELETE ON scan_coverage_outcomes
BEGIN
    SELECT RAISE(ABORT, 'coverage outcome evidence cannot be deleted');
END;

-- When a run opts into authenticated streaming, enumeration cannot close until
-- every immutable media observation has its matching opaque ticket.
CREATE TRIGGER trg_scan_stage_enumeration_core_ticket_gate_v6
BEFORE INSERT ON scan_stage_seals
WHEN NEW.stage = 'enumeration'
 AND EXISTS (
     SELECT 1 FROM scan_core_sessions AS core
     WHERE core.scan_run_id = NEW.scan_run_id
       AND core.volume_id = NEW.volume_id
 )
 AND (
     (SELECT count(*) FROM scan_file_tickets AS ticket
      WHERE ticket.scan_run_id = NEW.scan_run_id) <>
     (SELECT count(*) FROM media_observation_snapshots AS observation
      WHERE observation.scan_run_id = NEW.scan_run_id)
     OR EXISTS (
         SELECT 1 FROM media_observation_snapshots AS observation
         WHERE observation.scan_run_id = NEW.scan_run_id
           AND NOT EXISTS (
               SELECT 1 FROM scan_file_tickets AS ticket
               WHERE ticket.scan_run_id = observation.scan_run_id
                 AND ticket.media_observation_snapshot_id = observation.id
                 AND ticket.source_signature = observation.source_signature
           )
     )
 )
BEGIN
    SELECT RAISE(ABORT, 'enumeration cannot seal before every observation has a core ticket');
END;

CREATE TRIGGER trg_scan_stage_exact_coverage_gate_v6
BEFORE INSERT ON scan_stage_seals
WHEN NEW.stage = 'exact_verification'
 AND EXISTS (
     SELECT 1 FROM scan_core_sessions AS core
     WHERE core.scan_run_id = NEW.scan_run_id
       AND core.volume_id = NEW.volume_id
 )
 AND NOT EXISTS (
     SELECT 1 FROM scan_coverage_outcomes AS coverage
     WHERE coverage.scan_run_id = NEW.scan_run_id
       AND coverage.volume_id = NEW.volume_id
       AND coverage.status = 'complete'
       AND coverage.finalized_at_ms <= NEW.sealed_at_ms
 )
BEGIN
    SELECT RAISE(ABORT, 'exact verification requires complete core and volume coverage');
END;

CREATE TRIGGER trg_scan_stage_chronology_guard_v6
BEFORE INSERT ON scan_stage_seals
WHEN (NEW.stage = 'enumeration' AND NEW.sealed_at_ms < COALESCE((
          SELECT max(observation.observed_at_ms)
          FROM media_observation_snapshots AS observation
          WHERE observation.scan_run_id = NEW.scan_run_id
      ), 0))
  OR (NEW.stage = 'sampling' AND NEW.sealed_at_ms < COALESCE((
          SELECT max(fingerprint.completed_at_ms)
          FROM observation_fingerprints AS fingerprint
          WHERE fingerprint.scan_run_id = NEW.scan_run_id
            AND fingerprint.fingerprint_kind = 'sample'
      ), 0))
  OR (NEW.stage = 'full_hash' AND NEW.sealed_at_ms < COALESCE((
          SELECT max(fingerprint.completed_at_ms)
          FROM observation_fingerprints AS fingerprint
          WHERE fingerprint.scan_run_id = NEW.scan_run_id
            AND fingerprint.fingerprint_kind = 'exact_bytes'
            AND fingerprint.read_origin = 'full_hash_read'
      ), 0))
  OR (NEW.stage = 'exact_verification' AND NEW.sealed_at_ms < MAX(
          COALESCE((
              SELECT max(edge.verified_at_ms)
              FROM exact_verification_edges AS edge
              WHERE edge.scan_run_id = NEW.scan_run_id
          ), 0),
          COALESCE((
              SELECT max(build.finalized_at_ms)
              FROM exact_group_builds AS build
              WHERE build.scan_run_id = NEW.scan_run_id
                AND build.state = 'verified'
          ), 0),
          COALESCE((
              SELECT coverage.finalized_at_ms
              FROM scan_coverage_outcomes AS coverage
              WHERE coverage.scan_run_id = NEW.scan_run_id
          ), 0)
      ))
BEGIN
    SELECT RAISE(ABORT, 'scan stage seal predates the evidence it seals');
END;

CREATE TRIGGER trg_exact_group_finalize_chronology_v6
BEFORE UPDATE OF state ON exact_group_builds
WHEN OLD.state = 'draft'
 AND NEW.state = 'verified'
 AND NEW.finalized_at_ms < COALESCE((
     SELECT max(edge.verified_at_ms)
     FROM exact_verification_edges AS edge
     WHERE edge.exact_group_build_id = NEW.id
 ), 0)
BEGIN
    SELECT RAISE(ABORT, 'exact group finalization predates its verification edges');
END;

CREATE TRIGGER trg_bound_scan_issue_media_guard_v6
BEFORE INSERT ON scan_issues
WHEN NEW.media_file_id IS NOT NULL
 AND EXISTS (
     SELECT 1 FROM scan_run_sessions AS session
     WHERE session.scan_run_id = NEW.scan_run_id
       AND session.volume_id = NEW.volume_id
 )
 AND NOT EXISTS (
     SELECT 1 FROM media_observation_snapshots AS observation
     WHERE observation.scan_run_id = NEW.scan_run_id
       AND observation.volume_id = NEW.volume_id
       AND observation.media_file_id = NEW.media_file_id
 )
BEGIN
    SELECT RAISE(ABORT, 'scan issue media file was not observed by this run');
END;

PRAGMA user_version = 6;
