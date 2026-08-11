-- Version 8 adds process-local runtime leases and durable control intent.
-- A lease row is audit evidence only: RuntimeLeaseGuard remains process-local
-- and a reopened process must interrupt or honour an already durable cancel.
-- Evidence chain heads are maintained at write time for same-process pause
-- audit commitments. They are not cross-process resume authority and reopen
-- intentionally does not replay the raw evidence chain.

CREATE UNIQUE INDEX ux_scan_run_sessions_mount_binding_v8
    ON scan_run_sessions(volume_id, scan_run_id, mount_session_key);

CREATE TABLE scan_runtime_leases (
    scan_run_id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    scan_job_id INTEGER NOT NULL,
    capability_profile_id INTEGER NOT NULL,
    namespace_profile_id INTEGER NOT NULL,
    runtime_lease_key BLOB NOT NULL UNIQUE CHECK (length(runtime_lease_key) = 32),
    core_session_id BLOB NOT NULL CHECK (length(core_session_id) = 32),
    mount_session_key TEXT NOT NULL CHECK (
        length(mount_session_key) = 64
        AND mount_session_key = lower(mount_session_key)
        AND mount_session_key NOT GLOB '*[^0-9a-f]*'
    ),
    work_plan_digest BLOB NOT NULL CHECK (length(work_plan_digest) = 32),
    directory_evidence_count INTEGER NOT NULL DEFAULT 0
        CHECK (directory_evidence_count >= 0),
    file_evidence_count INTEGER NOT NULL DEFAULT 0 CHECK (file_evidence_count >= 0),
    directory_evidence_digest BLOB NOT NULL CHECK (length(directory_evidence_digest) = 32),
    file_evidence_digest BLOB NOT NULL CHECK (length(file_evidence_digest) = 32),
    evidence_chain_digest BLOB NOT NULL CHECK (length(evidence_chain_digest) = 32),
    lease_contract_version INTEGER NOT NULL CHECK (lease_contract_version = 1),
    state TEXT NOT NULL CHECK (state IN ('active', 'releasing', 'released')),
    acquired_at_ms INTEGER NOT NULL CHECK (acquired_at_ms >= 0),
    last_heartbeat_at_ms INTEGER NOT NULL CHECK (last_heartbeat_at_ms >= acquired_at_ms),
    release_reason TEXT CHECK (release_reason IN (
        'completed', 'failed', 'cancelled', 'interrupted', 'process_restart'
    )),
    release_started_at_ms INTEGER CHECK (
        release_started_at_ms IS NULL OR release_started_at_ms >= last_heartbeat_at_ms
    ),
    released_at_ms INTEGER CHECK (
        released_at_ms IS NULL OR released_at_ms >= release_started_at_ms
    ),
    UNIQUE (volume_id, scan_run_id, runtime_lease_key),
    UNIQUE (volume_id, scan_run_id, runtime_lease_key, core_session_id, mount_session_key),
    CHECK (
        (state = 'active' AND release_reason IS NULL
         AND release_started_at_ms IS NULL AND released_at_ms IS NULL)
        OR
        (state = 'releasing' AND release_reason IS NOT NULL
         AND release_started_at_ms IS NOT NULL AND released_at_ms IS NULL)
        OR
        (state = 'released' AND release_reason IS NOT NULL
         AND release_started_at_ms IS NOT NULL AND released_at_ms IS NOT NULL)
    ),
    FOREIGN KEY (volume_id, scan_run_id, mount_session_key)
        REFERENCES scan_run_sessions(volume_id, scan_run_id, mount_session_key)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        volume_id, scan_run_id, capability_profile_id, namespace_profile_id
    ) REFERENCES scan_run_sessions(
        volume_id, scan_run_id, capability_profile_id, namespace_profile_id
    ) ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id, core_session_id)
        REFERENCES scan_core_sessions(volume_id, scan_run_id, core_session_id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_job_id) REFERENCES scan_jobs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (scan_job_id, scan_run_id)
        REFERENCES scan_job_runs(scan_job_id, scan_run_id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_scan_runtime_leases_state_v8
    ON scan_runtime_leases(state, scan_run_id);

CREATE TABLE scan_control_requests (
    id INTEGER PRIMARY KEY,
    request_key BLOB NOT NULL UNIQUE CHECK (length(request_key) = 32),
    scan_run_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    runtime_lease_key BLOB NOT NULL CHECK (length(runtime_lease_key) = 32),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    kind TEXT NOT NULL CHECK (kind IN ('pause', 'resume', 'cancel')),
    expected_job_state_version INTEGER NOT NULL CHECK (expected_job_state_version >= 0),
    expected_run_state_version INTEGER NOT NULL CHECK (expected_run_state_version >= 0),
    expected_checkpoint_generation INTEGER CHECK (
        expected_checkpoint_generation IS NULL OR expected_checkpoint_generation >= 1
    ),
    disposition TEXT NOT NULL DEFAULT 'pending'
        CHECK (disposition IN ('pending', 'acknowledged', 'superseded', 'interrupted')),
    requested_at_ms INTEGER NOT NULL CHECK (requested_at_ms >= 0),
    acknowledged_at_ms INTEGER CHECK (
        acknowledged_at_ms IS NULL OR acknowledged_at_ms >= requested_at_ms
    ),
    ack_job_state_version INTEGER CHECK (
        ack_job_state_version IS NULL OR ack_job_state_version >= 1
    ),
    ack_run_state_version INTEGER CHECK (
        ack_run_state_version IS NULL OR ack_run_state_version >= 1
    ),
    ack_checkpoint_generation INTEGER CHECK (
        ack_checkpoint_generation IS NULL OR ack_checkpoint_generation >= 1
    ),
    ack_reason_code TEXT CHECK (
        ack_reason_code IS NULL
        OR length(CAST(ack_reason_code AS BLOB)) BETWEEN 1 AND 256
    ),
    pause_checkpoint_write_key BLOB UNIQUE CHECK (
        pause_checkpoint_write_key IS NULL OR length(pause_checkpoint_write_key) = 32
    ),
    pause_checkpoint_payload_digest BLOB CHECK (
        pause_checkpoint_payload_digest IS NULL
        OR length(pause_checkpoint_payload_digest) = 32
    ),
    superseded_by_request_id INTEGER,
    UNIQUE (scan_run_id, sequence),
    UNIQUE (id, scan_run_id, volume_id, runtime_lease_key, request_key),
    CHECK (
        (disposition = 'pending' AND acknowledged_at_ms IS NULL
         AND ack_job_state_version IS NULL AND ack_run_state_version IS NULL
         AND ack_checkpoint_generation IS NULL AND ack_reason_code IS NULL
         AND pause_checkpoint_write_key IS NULL
         AND pause_checkpoint_payload_digest IS NULL
         AND superseded_by_request_id IS NULL)
        OR
        (disposition = 'acknowledged' AND acknowledged_at_ms IS NOT NULL
         AND ack_job_state_version IS NOT NULL AND ack_run_state_version IS NOT NULL
         AND ((kind = 'pause' AND ack_checkpoint_generation IS NOT NULL
               AND pause_checkpoint_write_key IS NOT NULL
               AND pause_checkpoint_payload_digest IS NOT NULL)
              OR (kind = 'resume' AND ack_checkpoint_generation IS NOT NULL
                  AND pause_checkpoint_write_key IS NULL
                  AND pause_checkpoint_payload_digest IS NULL)
              OR (kind = 'cancel' AND pause_checkpoint_write_key IS NULL
                  AND pause_checkpoint_payload_digest IS NULL))
         AND ack_reason_code IS NOT NULL AND superseded_by_request_id IS NULL)
        OR
        (disposition = 'superseded' AND acknowledged_at_ms IS NOT NULL
         AND ack_job_state_version IS NULL AND ack_run_state_version IS NULL
         AND ack_checkpoint_generation IS NULL AND ack_reason_code IS NOT NULL
         AND pause_checkpoint_write_key IS NULL
         AND pause_checkpoint_payload_digest IS NULL
         AND superseded_by_request_id IS NOT NULL)
        OR
        (disposition = 'interrupted' AND acknowledged_at_ms IS NOT NULL
         AND ack_job_state_version IS NULL AND ack_run_state_version IS NULL
         AND ack_checkpoint_generation IS NULL AND ack_reason_code IS NOT NULL
         AND pause_checkpoint_write_key IS NULL
         AND pause_checkpoint_payload_digest IS NULL
         AND superseded_by_request_id IS NULL)
    ),
    CHECK (
        (kind = 'resume' AND expected_checkpoint_generation IS NOT NULL)
        OR (kind IN ('pause', 'cancel') AND expected_checkpoint_generation IS NULL)
    ),
    FOREIGN KEY (volume_id, scan_run_id, runtime_lease_key)
        REFERENCES scan_runtime_leases(volume_id, scan_run_id, runtime_lease_key)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (superseded_by_request_id) REFERENCES scan_control_requests(id)
        ON UPDATE CASCADE ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE INDEX ix_scan_control_requests_pending_v8
    ON scan_control_requests(scan_run_id, disposition, sequence);

CREATE UNIQUE INDEX ux_scan_control_requests_one_pending_v8
    ON scan_control_requests(scan_run_id) WHERE disposition = 'pending';

CREATE TABLE scan_pause_checkpoints (
    scan_run_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    runtime_lease_key BLOB NOT NULL CHECK (length(runtime_lease_key) = 32),
    core_session_id BLOB NOT NULL CHECK (length(core_session_id) = 32),
    mount_session_key TEXT NOT NULL CHECK (
        length(mount_session_key) = 64
        AND mount_session_key = lower(mount_session_key)
        AND mount_session_key NOT GLOB '*[^0-9a-f]*'
    ),
    pause_request_id INTEGER NOT NULL,
    pause_request_key BLOB NOT NULL CHECK (length(pause_request_key) = 32),
    generation INTEGER NOT NULL CHECK (generation >= 1),
    write_key BLOB NOT NULL UNIQUE CHECK (length(write_key) = 32),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    cursor_contract_version INTEGER NOT NULL CHECK (cursor_contract_version = 1),
    stage TEXT NOT NULL CHECK (stage = 'enumeration'),
    cursor_json TEXT NOT NULL CHECK (
        length(CAST(cursor_json AS BLOB)) BETWEEN 2 AND 16384
        AND CASE WHEN json_valid(cursor_json) THEN (
            json_type(cursor_json) = 'object'
            AND cursor_json = json(cursor_json)
            AND json_type(cursor_json, '$.stage') IS 'text'
            AND json_extract(cursor_json, '$.stage') IS 'enumeration'
            AND json_type(cursor_json, '$.next_directory_ordinal') IS 'integer'
            AND json_extract(cursor_json, '$.next_directory_ordinal')
                BETWEEN 0 AND 9223372036854775807
            AND json_type(cursor_json, '$.next_file_ordinal') IS 'integer'
            AND json_extract(cursor_json, '$.next_file_ordinal')
                BETWEEN 0 AND 9223372036854775807
        ) ELSE 0 END
    ),
    work_plan_digest BLOB NOT NULL CHECK (length(work_plan_digest) = 32),
    evidence_manifest_digest BLOB NOT NULL CHECK (length(evidence_manifest_digest) = 32),
    job_state_version INTEGER NOT NULL CHECK (job_state_version >= 1),
    run_state_version INTEGER NOT NULL CHECK (run_state_version >= 1),
    discovered_count INTEGER NOT NULL CHECK (discovered_count >= 0),
    fingerprinted_count INTEGER NOT NULL CHECK (fingerprinted_count >= 0),
    error_count INTEGER NOT NULL CHECK (error_count >= 0),
    logical_bytes_seen INTEGER NOT NULL CHECK (logical_bytes_seen >= 0),
    saved_at_ms INTEGER NOT NULL CHECK (saved_at_ms >= 0),
    PRIMARY KEY (scan_run_id, generation),
    UNIQUE (pause_request_id),
    CHECK (fingerprinted_count <= discovered_count),
    FOREIGN KEY (
        volume_id, scan_run_id, runtime_lease_key, core_session_id, mount_session_key
    ) REFERENCES scan_runtime_leases(
        volume_id, scan_run_id, runtime_lease_key, core_session_id, mount_session_key
    ) ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (
        pause_request_id, scan_run_id, volume_id, runtime_lease_key, pause_request_key
    ) REFERENCES scan_control_requests(
        id, scan_run_id, volume_id, runtime_lease_key, request_key
    ) ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER trg_scan_runtime_leases_insert_guard_v8
BEFORE INSERT ON scan_runtime_leases
WHEN NEW.state <> 'active'
 OR NEW.acquired_at_ms <> NEW.last_heartbeat_at_ms
 OR NOT EXISTS (
    SELECT 1 FROM scan_runs AS run
    JOIN scan_jobs AS job
      ON job.id = NEW.scan_job_id AND job.volume_id = NEW.volume_id
     AND job.active_scan_run_id = run.id
    JOIN scan_run_sessions AS session
      ON session.scan_run_id = run.id AND session.volume_id = run.volume_id
    JOIN scan_core_sessions AS core
      ON core.scan_run_id = run.id AND core.volume_id = run.volume_id
    WHERE run.id = NEW.scan_run_id AND run.volume_id = NEW.volume_id
      AND run.state = 'running' AND job.state = 'running'
      AND session.mount_session_key = NEW.mount_session_key
      AND session.capability_profile_id = NEW.capability_profile_id
      AND session.namespace_profile_id = NEW.namespace_profile_id
      AND core.core_session_id = NEW.core_session_id
      AND core.capability_profile_id = NEW.capability_profile_id
      AND core.namespace_profile_id = NEW.namespace_profile_id
      AND NEW.acquired_at_ms >= core.bound_at_ms
 )
BEGIN
    SELECT RAISE(ABORT, 'runtime lease is not bound to the live run/core/mount session');
END;

CREATE TRIGGER trg_scan_runtime_leases_update_guard_v8
BEFORE UPDATE ON scan_runtime_leases
WHEN NEW.scan_run_id <> OLD.scan_run_id
 OR NEW.volume_id <> OLD.volume_id
 OR NEW.scan_job_id <> OLD.scan_job_id
 OR NEW.capability_profile_id <> OLD.capability_profile_id
 OR NEW.namespace_profile_id <> OLD.namespace_profile_id
 OR NEW.runtime_lease_key <> OLD.runtime_lease_key
 OR NEW.core_session_id <> OLD.core_session_id
 OR NEW.mount_session_key <> OLD.mount_session_key
 OR NEW.work_plan_digest <> OLD.work_plan_digest
 OR NEW.lease_contract_version <> OLD.lease_contract_version
 OR NEW.acquired_at_ms <> OLD.acquired_at_ms
 OR OLD.state = 'released'
 OR NOT (
      (OLD.state = 'active' AND NEW.state = 'active'
       AND NEW.release_reason IS NULL
       AND ((NEW.directory_evidence_count = OLD.directory_evidence_count
             AND NEW.file_evidence_count = OLD.file_evidence_count
             AND NEW.directory_evidence_digest = OLD.directory_evidence_digest
             AND NEW.file_evidence_digest = OLD.file_evidence_digest
             AND NEW.evidence_chain_digest = OLD.evidence_chain_digest
             AND NEW.last_heartbeat_at_ms >= OLD.last_heartbeat_at_ms)
         OR (NEW.last_heartbeat_at_ms = OLD.last_heartbeat_at_ms
             AND NEW.evidence_chain_digest <> OLD.evidence_chain_digest
             AND ((NEW.directory_evidence_count = OLD.directory_evidence_count + 1
                   AND NEW.file_evidence_count = OLD.file_evidence_count
                   AND NEW.directory_evidence_digest <> OLD.directory_evidence_digest
                   AND NEW.file_evidence_digest = OLD.file_evidence_digest)
               OR (NEW.directory_evidence_count = OLD.directory_evidence_count
                   AND NEW.file_evidence_count = OLD.file_evidence_count + 1
                   AND NEW.directory_evidence_digest = OLD.directory_evidence_digest
                   AND NEW.file_evidence_digest <> OLD.file_evidence_digest)))))
   OR (OLD.state = 'active' AND NEW.state = 'releasing'
       AND NEW.last_heartbeat_at_ms = OLD.last_heartbeat_at_ms
       AND NEW.directory_evidence_count = OLD.directory_evidence_count
       AND NEW.file_evidence_count = OLD.file_evidence_count
       AND NEW.directory_evidence_digest = OLD.directory_evidence_digest
       AND NEW.file_evidence_digest = OLD.file_evidence_digest
       AND NEW.evidence_chain_digest = OLD.evidence_chain_digest
       AND NEW.release_reason IS NOT NULL
       AND NEW.release_started_at_ms >= OLD.last_heartbeat_at_ms)
   OR (OLD.state = 'releasing' AND NEW.state = 'released'
       AND NEW.last_heartbeat_at_ms = OLD.last_heartbeat_at_ms
       AND NEW.directory_evidence_count = OLD.directory_evidence_count
       AND NEW.file_evidence_count = OLD.file_evidence_count
       AND NEW.directory_evidence_digest = OLD.directory_evidence_digest
       AND NEW.file_evidence_digest = OLD.file_evidence_digest
       AND NEW.evidence_chain_digest = OLD.evidence_chain_digest
       AND NEW.release_reason = OLD.release_reason
       AND NEW.release_started_at_ms = OLD.release_started_at_ms
       AND NEW.released_at_ms >= OLD.release_started_at_ms
       AND EXISTS (
          SELECT 1 FROM scan_runs AS run
          JOIN scan_jobs AS job ON job.id = OLD.scan_job_id
          WHERE run.id = OLD.scan_run_id
            AND ((OLD.release_reason = 'completed' AND run.state = 'completed' AND job.state = 'completed')
              OR (OLD.release_reason = 'failed' AND run.state = 'failed' AND job.state = 'failed')
              OR (OLD.release_reason = 'cancelled' AND run.state = 'cancelled' AND job.state = 'cancelled')
              OR (OLD.release_reason IN ('interrupted', 'process_restart')
                  AND ((run.state = 'interrupted' AND job.state = 'failed')
                    OR (run.state = 'cancelled' AND job.state = 'cancelled'))))
       ))
 )
BEGIN
    SELECT RAISE(ABORT, 'runtime lease identity or one-way lifecycle is invalid');
END;

CREATE TRIGGER trg_scan_runtime_leases_no_delete_v8
BEFORE DELETE ON scan_runtime_leases
BEGIN
    SELECT RAISE(ABORT, 'runtime lease cannot be deleted');
END;

CREATE TRIGGER trg_scan_control_requests_insert_guard_v8
BEFORE INSERT ON scan_control_requests
WHEN NEW.disposition <> 'pending'
 OR NEW.sequence <> COALESCE((
      SELECT max(sequence) + 1 FROM scan_control_requests
      WHERE scan_run_id = NEW.scan_run_id
    ), 1)
 OR EXISTS (
      SELECT 1 FROM scan_control_requests
      WHERE scan_run_id = NEW.scan_run_id AND kind = 'cancel'
    )
 OR EXISTS (
      SELECT 1 FROM scan_control_requests
      WHERE scan_run_id = NEW.scan_run_id AND disposition = 'pending'
    )
 OR NOT EXISTS (
      SELECT 1 FROM scan_runtime_leases AS lease
      JOIN scan_runs AS run ON run.id = lease.scan_run_id
      JOIN scan_jobs AS job ON job.id = lease.scan_job_id
      WHERE lease.scan_run_id = NEW.scan_run_id
        AND lease.volume_id = NEW.volume_id
        AND lease.runtime_lease_key = NEW.runtime_lease_key
        AND lease.state = 'active'
        AND run.state_version = NEW.expected_run_state_version
        AND job.state_version = NEW.expected_job_state_version
        AND NEW.requested_at_ms >= lease.last_heartbeat_at_ms
        AND ((NEW.kind = 'pause' AND run.state = 'running' AND job.state = 'running')
          OR (NEW.kind = 'resume' AND run.state = 'paused' AND job.state = 'paused')
          OR (NEW.kind = 'cancel' AND run.state IN ('running', 'paused')
              AND job.state IN ('running', 'paused')))
    )
 OR (NEW.kind = 'resume' AND NOT EXISTS (
      SELECT 1 FROM scan_pause_checkpoints AS checkpoint
      WHERE checkpoint.scan_run_id = NEW.scan_run_id
        AND checkpoint.generation = NEW.expected_checkpoint_generation
        AND checkpoint.runtime_lease_key = NEW.runtime_lease_key
        AND checkpoint.generation = (
            SELECT max(latest.generation) FROM scan_pause_checkpoints AS latest
            WHERE latest.scan_run_id = NEW.scan_run_id
        )
        AND checkpoint.pause_request_id = (
            SELECT latest_request.id FROM scan_control_requests AS latest_request
            WHERE latest_request.scan_run_id = NEW.scan_run_id
              AND latest_request.disposition = 'acknowledged'
            ORDER BY latest_request.sequence DESC LIMIT 1
        )
    ))
BEGIN
    SELECT RAISE(ABORT, 'control request is stale, dominated, or not lease-bound');
END;

CREATE TRIGGER trg_scan_control_requests_update_guard_v8
BEFORE UPDATE ON scan_control_requests
WHEN NEW.id <> OLD.id OR NEW.request_key <> OLD.request_key
 OR NEW.scan_run_id <> OLD.scan_run_id OR NEW.volume_id <> OLD.volume_id
 OR NEW.runtime_lease_key <> OLD.runtime_lease_key OR NEW.sequence <> OLD.sequence
 OR NEW.kind <> OLD.kind
 OR NEW.expected_job_state_version <> OLD.expected_job_state_version
 OR NEW.expected_run_state_version <> OLD.expected_run_state_version
 OR NEW.expected_checkpoint_generation IS NOT OLD.expected_checkpoint_generation
 OR NEW.requested_at_ms <> OLD.requested_at_ms
 OR OLD.disposition <> 'pending'
 OR NOT (
      (NEW.disposition = 'acknowledged' AND NEW.acknowledged_at_ms >= OLD.requested_at_ms
       AND NEW.ack_job_state_version IS NOT NULL AND NEW.ack_run_state_version IS NOT NULL
       AND NEW.ack_job_state_version = OLD.expected_job_state_version + 1
       AND NEW.ack_run_state_version = OLD.expected_run_state_version + 1
       AND NEW.ack_reason_code IS NOT NULL AND NEW.superseded_by_request_id IS NULL
       AND EXISTS (
          SELECT 1 FROM scan_runtime_leases AS lease
          JOIN scan_runs AS run ON run.id = lease.scan_run_id
          JOIN scan_jobs AS job ON job.id = lease.scan_job_id
          LEFT JOIN scan_pause_checkpoints AS checkpoint
            ON checkpoint.scan_run_id = lease.scan_run_id
          WHERE lease.scan_run_id = OLD.scan_run_id
            AND lease.volume_id = OLD.volume_id
            AND lease.runtime_lease_key = OLD.runtime_lease_key
            AND NEW.ack_job_state_version = job.state_version
            AND NEW.ack_run_state_version = run.state_version
            AND (
                (OLD.kind = 'pause' AND lease.state = 'active'
                 AND job.state = 'paused' AND run.state = 'paused'
                 AND checkpoint.pause_request_id = OLD.id
                 AND checkpoint.generation = NEW.ack_checkpoint_generation
                 AND checkpoint.write_key = NEW.pause_checkpoint_write_key
                 AND checkpoint.payload_digest = NEW.pause_checkpoint_payload_digest
                 AND checkpoint.job_state_version = NEW.ack_job_state_version
                 AND checkpoint.run_state_version = NEW.ack_run_state_version)
             OR (OLD.kind = 'resume' AND lease.state = 'active'
                 AND job.state = 'running' AND run.state = 'running'
                 AND checkpoint.generation = OLD.expected_checkpoint_generation
                 AND checkpoint.generation = NEW.ack_checkpoint_generation)
             OR (OLD.kind = 'cancel' AND lease.state = 'releasing'
                 AND lease.release_reason IN ('cancelled', 'process_restart')
                 AND job.state = 'cancelled' AND run.state = 'cancelled'
                 AND NEW.ack_checkpoint_generation IS (
                     SELECT max(cancel_checkpoint.generation)
                     FROM scan_pause_checkpoints AS cancel_checkpoint
                     JOIN scan_control_requests AS cancel_pause
                       ON cancel_pause.id = cancel_checkpoint.pause_request_id
                     WHERE cancel_checkpoint.scan_run_id = OLD.scan_run_id
                       AND cancel_pause.sequence < OLD.sequence
                 ))
            )
       ))
   OR (NEW.disposition = 'interrupted' AND NEW.acknowledged_at_ms >= OLD.requested_at_ms
       AND OLD.kind IN ('pause', 'resume')
       AND NEW.ack_reason_code = 'PROCESS_RESTART'
       AND NEW.superseded_by_request_id IS NULL
       AND EXISTS (
           SELECT 1 FROM scan_runtime_leases AS lease
           WHERE lease.scan_run_id = OLD.scan_run_id
             AND lease.runtime_lease_key = OLD.runtime_lease_key
             AND lease.state = 'releasing'
             AND lease.release_reason = 'process_restart'
       ))
   OR (NEW.disposition = 'superseded' AND NEW.acknowledged_at_ms >= OLD.requested_at_ms
       AND NEW.ack_reason_code = 'CANCEL_DOMINATED'
       AND NEW.superseded_by_request_id IS NOT NULL)
 )
BEGIN
    SELECT RAISE(ABORT, 'control request identity or terminal disposition is invalid');
END;

CREATE TRIGGER trg_scan_control_requests_no_delete_v8
BEFORE DELETE ON scan_control_requests
BEGIN
    SELECT RAISE(ABORT, 'control request cannot be deleted');
END;

CREATE TRIGGER trg_scan_pause_checkpoints_insert_guard_v8
BEFORE INSERT ON scan_pause_checkpoints
WHEN NEW.generation <> COALESCE((
      SELECT max(generation) + 1 FROM scan_pause_checkpoints
      WHERE scan_run_id = NEW.scan_run_id
    ), 1)
 OR (SELECT count(*) FROM json_each(NEW.cursor_json)) <> 3
 OR (SELECT count(*) FROM json_each(NEW.cursor_json)
     WHERE key = 'stage' AND type = 'text' AND value = 'enumeration') <> 1
 OR (SELECT count(*) FROM json_each(NEW.cursor_json)
     WHERE key = 'next_directory_ordinal' AND type = 'integer'
       AND atom BETWEEN 0 AND 9223372036854775807) <> 1
 OR (SELECT count(*) FROM json_each(NEW.cursor_json)
     WHERE key = 'next_file_ordinal' AND type = 'integer'
       AND atom BETWEEN 0 AND 9223372036854775807) <> 1
 OR (NEW.generation > 1 AND NOT EXISTS (
      SELECT 1
      FROM scan_pause_checkpoints AS previous
      JOIN scan_control_requests AS previous_request
        ON previous_request.id = previous.pause_request_id
      JOIN scan_control_requests AS request ON request.id = NEW.pause_request_id
      WHERE previous.scan_run_id = NEW.scan_run_id
        AND previous.generation = NEW.generation - 1
        AND previous.volume_id = NEW.volume_id
        AND previous.runtime_lease_key = NEW.runtime_lease_key
        AND previous.core_session_id = NEW.core_session_id
        AND previous.mount_session_key = NEW.mount_session_key
        AND previous.cursor_contract_version = NEW.cursor_contract_version
        AND previous.stage = NEW.stage
        AND previous.work_plan_digest = NEW.work_plan_digest
        AND request.sequence > previous_request.sequence
        AND NEW.discovered_count >= previous.discovered_count
        AND NEW.fingerprinted_count >= previous.fingerprinted_count
        AND NEW.error_count >= previous.error_count
        AND NEW.logical_bytes_seen >= previous.logical_bytes_seen
        AND NEW.saved_at_ms >= previous.saved_at_ms
        AND json_extract(NEW.cursor_json, '$.next_directory_ordinal')
            >= json_extract(previous.cursor_json, '$.next_directory_ordinal')
        AND json_extract(NEW.cursor_json, '$.next_file_ordinal')
            >= json_extract(previous.cursor_json, '$.next_file_ordinal')
    ))
 OR NOT EXISTS (
      SELECT 1 FROM scan_runtime_leases AS lease
      JOIN scan_control_requests AS request ON request.id = NEW.pause_request_id
      JOIN scan_runs AS run ON run.id = NEW.scan_run_id
      JOIN scan_jobs AS job ON job.id = lease.scan_job_id
      WHERE lease.scan_run_id = NEW.scan_run_id AND lease.volume_id = NEW.volume_id
        AND lease.runtime_lease_key = NEW.runtime_lease_key
        AND lease.core_session_id = NEW.core_session_id
        AND lease.mount_session_key = NEW.mount_session_key AND lease.state = 'active'
        AND request.request_key = NEW.pause_request_key AND request.kind = 'pause'
        AND request.disposition = 'pending'
        AND request.scan_run_id = NEW.scan_run_id
        AND request.volume_id = NEW.volume_id
        AND request.runtime_lease_key = NEW.runtime_lease_key
        AND run.state = 'running' AND job.state = 'running'
        AND NEW.run_state_version = run.state_version + 1
        AND NEW.job_state_version = job.state_version + 1
        AND NEW.discovered_count = run.discovered_count
        AND NEW.fingerprinted_count = run.fingerprinted_count
        AND NEW.error_count = run.error_count
        AND NEW.logical_bytes_seen = run.logical_bytes_seen
        AND json_extract(NEW.cursor_json, '$.next_directory_ordinal')
            = lease.directory_evidence_count
        AND json_extract(NEW.cursor_json, '$.next_file_ordinal')
            = lease.file_evidence_count
        AND NEW.work_plan_digest = lease.work_plan_digest
        AND NEW.evidence_manifest_digest = lease.evidence_chain_digest
        AND NEW.saved_at_ms >= request.requested_at_ms
    )
BEGIN
    SELECT RAISE(ABORT, 'pause checkpoint is not bound to pending pause and live evidence');
END;

CREATE TRIGGER trg_scan_pause_checkpoints_update_guard_v8
BEFORE UPDATE ON scan_pause_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'pause checkpoint history is append-only');
END;

CREATE TRIGGER trg_scan_pause_checkpoints_no_delete_v8
BEFORE DELETE ON scan_pause_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'pause checkpoint cannot be deleted');
END;

CREATE TRIGGER trg_scan_runs_runtime_control_gate_v8
BEFORE UPDATE OF state ON scan_runs
WHEN OLD.state IS NOT NEW.state
 AND EXISTS (SELECT 1 FROM scan_runtime_leases WHERE scan_run_id = OLD.id)
 AND NOT (
      (OLD.state = 'running' AND NEW.state = 'paused' AND EXISTS (
          SELECT 1 FROM scan_runtime_leases AS lease
          JOIN scan_control_requests AS request
            ON request.scan_run_id = lease.scan_run_id AND request.kind = 'pause'
           AND request.disposition = 'pending'
          JOIN scan_pause_checkpoints AS checkpoint
            ON checkpoint.pause_request_id = request.id
          WHERE lease.scan_run_id = OLD.id AND lease.state = 'active'
            AND checkpoint.run_state_version = NEW.state_version
      ))
   OR (OLD.state = 'paused' AND NEW.state = 'running' AND EXISTS (
          SELECT 1 FROM scan_runtime_leases AS lease
          JOIN scan_control_requests AS request
            ON request.scan_run_id = lease.scan_run_id AND request.kind = 'resume'
           AND request.disposition = 'pending'
          WHERE lease.scan_run_id = OLD.id AND lease.state = 'active'
      ))
   OR (NEW.state IN ('completed', 'failed', 'cancelled', 'interrupted') AND EXISTS (
          SELECT 1 FROM scan_runtime_leases AS lease
          WHERE lease.scan_run_id = OLD.id AND lease.state = 'releasing'
            AND ((NEW.state = 'completed' AND lease.release_reason = 'completed')
              OR (NEW.state = 'failed' AND lease.release_reason = 'failed')
              OR (NEW.state = 'cancelled' AND lease.release_reason IN ('cancelled', 'process_restart'))
              OR (NEW.state = 'interrupted' AND lease.release_reason IN ('interrupted', 'process_restart')))
      ) AND (
          (NEW.state = 'cancelled' AND EXISTS (
              SELECT 1 FROM scan_control_requests AS request
              WHERE request.scan_run_id = OLD.id AND request.kind = 'cancel'
                AND request.disposition = 'pending'
          ))
          OR (NEW.state <> 'cancelled' AND NOT EXISTS (
              SELECT 1 FROM scan_control_requests AS request
              WHERE request.scan_run_id = OLD.id AND request.disposition = 'pending'
          ))
      ))
 )
BEGIN
    SELECT RAISE(ABORT, 'leased scan run transition lacks control acknowledgement or release intent');
END;

CREATE TRIGGER trg_scan_jobs_runtime_control_gate_v8
BEFORE UPDATE OF state ON scan_jobs
WHEN OLD.state IS NOT NEW.state
 AND EXISTS (
    SELECT 1 FROM scan_runtime_leases WHERE scan_job_id = OLD.id AND scan_run_id = OLD.active_scan_run_id
 )
 AND NOT (
      (OLD.state = 'running' AND NEW.state = 'paused' AND EXISTS (
          SELECT 1 FROM scan_runtime_leases AS lease
          JOIN scan_control_requests AS request
            ON request.scan_run_id = lease.scan_run_id AND request.kind = 'pause'
           AND request.disposition = 'pending'
          JOIN scan_pause_checkpoints AS checkpoint ON checkpoint.pause_request_id = request.id
          WHERE lease.scan_job_id = OLD.id AND lease.state = 'active'
            AND checkpoint.job_state_version = NEW.state_version
      ))
   OR (OLD.state = 'paused' AND NEW.state = 'running' AND EXISTS (
          SELECT 1 FROM scan_runtime_leases AS lease
          JOIN scan_control_requests AS request
            ON request.scan_run_id = lease.scan_run_id AND request.kind = 'resume'
           AND request.disposition = 'pending'
          WHERE lease.scan_job_id = OLD.id AND lease.state = 'active'
      ))
   OR (NEW.state IN ('completed', 'failed', 'cancelled') AND EXISTS (
          SELECT 1 FROM scan_runtime_leases AS lease
          JOIN scan_runs AS run ON run.id = lease.scan_run_id
          WHERE lease.scan_job_id = OLD.id AND lease.state = 'releasing'
            AND ((NEW.state = 'completed' AND lease.release_reason = 'completed')
              OR (NEW.state = 'failed' AND lease.release_reason = 'failed')
              OR (NEW.state = 'failed' AND run.state = 'interrupted'
                  AND lease.release_reason IN ('interrupted', 'process_restart'))
              OR (NEW.state = 'cancelled' AND run.state = 'cancelled'
                  AND lease.release_reason IN ('cancelled', 'process_restart')))
      ))
 )
BEGIN
    SELECT RAISE(ABORT, 'leased scan job transition lacks control acknowledgement or release intent');
END;

PRAGMA user_version = 8;
