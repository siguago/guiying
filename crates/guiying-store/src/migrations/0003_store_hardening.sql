-- Version 2 predates the state/root guards below. Triggers do not validate
-- rows that already exist, so fail the whole migration before changing any
-- schema object when historical data violates a version 3 invariant. The
-- guard table is transaction-local in effect: it is dropped on success and
-- the surrounding migration transaction rolls it back on any failed insert.
CREATE TABLE guiying_v3_invariant_guard (
    violation INTEGER NOT NULL CHECK (violation = 0)
) STRICT;

INSERT INTO guiying_v3_invariant_guard (violation)
SELECT 1
FROM scan_runs
WHERE fingerprinted_count > discovered_count
LIMIT 1;

INSERT INTO guiying_v3_invariant_guard (violation)
SELECT 1
FROM scan_job_runs AS binding
JOIN scan_jobs AS job
  ON job.id = binding.scan_job_id
 AND job.volume_id = binding.volume_id
JOIN scan_runs AS run
  ON run.id = binding.scan_run_id
 AND run.volume_id = binding.volume_id
WHERE job.root_relative_path <> run.root_relative_path
   OR job.root_path_key <> run.root_path_key
LIMIT 1;

INSERT INTO guiying_v3_invariant_guard (violation)
SELECT 1
FROM scan_jobs AS job
WHERE job.active_scan_run_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM scan_job_runs AS binding
    JOIN scan_runs AS run
      ON run.id = binding.scan_run_id
     AND run.volume_id = binding.volume_id
    WHERE binding.scan_job_id = job.id
      AND binding.scan_run_id = job.active_scan_run_id
      AND binding.volume_id = job.volume_id
      AND run.root_relative_path = job.root_relative_path
      AND run.root_path_key = job.root_path_key
  )
LIMIT 1;

INSERT INTO guiying_v3_invariant_guard (violation)
SELECT 1
FROM scan_jobs
WHERE active_scan_run_id IS NULL
  AND state NOT IN ('queued', 'cancelled')
LIMIT 1;

-- Accept only the adjacent job/run states required inside one coordinated
-- transition. Callers still commit both halves in the same SQLite transaction.
INSERT INTO guiying_v3_invariant_guard (violation)
SELECT 1
FROM scan_jobs AS job
JOIN scan_runs AS run
  ON run.id = job.active_scan_run_id
 AND run.volume_id = job.volume_id
WHERE NOT (
    (job.state = 'queued' AND run.state IN ('queued', 'cancelled'))
 OR (job.state = 'running' AND run.state IN (
        'queued', 'running', 'paused', 'completed', 'failed', 'interrupted', 'cancelled'
    ))
 OR (job.state = 'paused' AND run.state IN ('paused', 'failed', 'interrupted', 'cancelled'))
 OR (job.state = 'completed' AND run.state = 'completed')
 OR (job.state = 'failed' AND run.state IN ('queued', 'failed', 'interrupted'))
 OR (job.state = 'cancelled' AND run.state = 'cancelled')
)
LIMIT 1;

DROP TABLE guiying_v3_invariant_guard;

-- Canonicalize the Windows encoding spelling used by guiying-core. Version 2
-- used `windows_wtf16le`; the conversion is lossless because only the label
-- changes. Rebuilding the child table also makes the accepted spelling an
-- enforceable schema property instead of an application convention.
CREATE TABLE media_file_paths_v3 (
    volume_id INTEGER NOT NULL,
    media_file_id INTEGER NOT NULL,
    relative_path_raw BLOB NOT NULL CHECK (length(relative_path_raw) > 0),
    path_encoding TEXT NOT NULL
        CHECK (path_encoding IN ('utf8', 'unix_bytes', 'windows_utf16_le')),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    PRIMARY KEY (volume_id, media_file_id),
    FOREIGN KEY (volume_id, media_file_id) REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO media_file_paths_v3 (
    volume_id,
    media_file_id,
    relative_path_raw,
    path_encoding,
    created_at_ms,
    updated_at_ms
)
SELECT
    volume_id,
    media_file_id,
    relative_path_raw,
    CASE path_encoding
        WHEN 'windows_wtf16le' THEN 'windows_utf16_le'
        ELSE path_encoding
    END,
    created_at_ms,
    updated_at_ms
FROM media_file_paths;

DROP TABLE media_file_paths;
ALTER TABLE media_file_paths_v3 RENAME TO media_file_paths;

-- A checkpoint is deliberately opaque to SQLite, but its envelope is strict,
-- monotonic, volume-bound, and count-safe. The scanner owns the cursor schema.
CREATE TABLE scan_checkpoints (
    scan_run_id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    checkpoint_version INTEGER NOT NULL CHECK (checkpoint_version >= 1),
    cursor_version INTEGER NOT NULL CHECK (cursor_version >= 1),
    cursor_json TEXT NOT NULL CHECK (json_valid(cursor_json)),
    discovered_count INTEGER NOT NULL CHECK (discovered_count >= 0),
    fingerprinted_count INTEGER NOT NULL
        CHECK (fingerprinted_count >= 0 AND fingerprinted_count <= discovered_count),
    error_count INTEGER NOT NULL CHECK (error_count >= 0),
    logical_bytes_seen INTEGER NOT NULL CHECK (logical_bytes_seen >= 0),
    saved_at_ms INTEGER NOT NULL CHECK (saved_at_ms >= 0),
    UNIQUE (volume_id, scan_run_id),
    FOREIGN KEY (volume_id, scan_run_id) REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_media_files_run_page
    ON media_files(last_seen_scan_run_id, id);

CREATE INDEX ix_scan_issues_run_page
    ON scan_issues(scan_run_id, id);

CREATE INDEX ix_scan_jobs_active_page
    ON scan_jobs(id)
    WHERE state IN ('queued', 'running', 'paused');

-- Job/run roots are immutable evidence and every binding must describe the
-- same volume-relative root. Foreign keys already enforce the volume half.
CREATE TRIGGER trg_scan_jobs_root_immutable
BEFORE UPDATE OF volume_id, root_relative_path, root_path_key ON scan_jobs
BEGIN
    SELECT RAISE(ABORT, 'scan job root is immutable');
END;

CREATE TRIGGER trg_scan_runs_root_immutable
BEFORE UPDATE OF volume_id, root_relative_path, root_path_key ON scan_runs
BEGIN
    SELECT RAISE(ABORT, 'scan run root is immutable');
END;

CREATE TRIGGER trg_scan_job_runs_root_insert
BEFORE INSERT ON scan_job_runs
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_jobs AS job
    JOIN scan_runs AS run
      ON run.id = NEW.scan_run_id
     AND run.volume_id = NEW.volume_id
    WHERE job.id = NEW.scan_job_id
      AND job.volume_id = NEW.volume_id
      AND job.root_relative_path = run.root_relative_path
      AND job.root_path_key = run.root_path_key
)
BEGIN
    SELECT RAISE(ABORT, 'scan job/run root mismatch');
END;

-- A job/run binding is historical evidence. Retrying creates a new binding;
-- it never edits or removes the old attempt.
CREATE TRIGGER trg_scan_job_runs_immutable_update
BEFORE UPDATE ON scan_job_runs
BEGIN
    SELECT RAISE(ABORT, 'scan job/run binding is immutable');
END;

CREATE TRIGGER trg_scan_job_runs_immutable_delete
BEFORE DELETE ON scan_job_runs
BEGIN
    SELECT RAISE(ABORT, 'scan job/run binding cannot be deleted');
END;

-- A bound active run remains part of the audit trail, including after
-- cancellation. The only supported replacement is a new queued retry after
-- the previous active attempt failed or was interrupted.
CREATE TRIGGER trg_scan_jobs_active_run_not_clear
BEFORE UPDATE OF active_scan_run_id ON scan_jobs
WHEN OLD.active_scan_run_id IS NOT NULL
 AND NEW.active_scan_run_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'active scan run cannot be cleared');
END;

CREATE TRIGGER trg_scan_jobs_active_run_replace_guard
BEFORE UPDATE OF active_scan_run_id ON scan_jobs
WHEN OLD.active_scan_run_id IS NOT NULL
 AND NEW.active_scan_run_id IS NOT NULL
 AND OLD.active_scan_run_id <> NEW.active_scan_run_id
 AND NOT (
    OLD.state = 'failed'
    AND NEW.state = 'failed'
    AND EXISTS (
        SELECT 1 FROM scan_runs AS previous
        WHERE previous.id = OLD.active_scan_run_id
          AND previous.volume_id = OLD.volume_id
          AND previous.state IN ('failed', 'interrupted')
    )
    AND EXISTS (
        SELECT 1 FROM scan_runs AS replacement
        WHERE replacement.id = NEW.active_scan_run_id
          AND replacement.volume_id = NEW.volume_id
          AND replacement.state = 'queued'
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'active scan run replacement is not a valid retry');
END;

CREATE TRIGGER trg_scan_jobs_active_run_binding
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
        OR (NEW.state = 'completed' AND run.state = 'completed')
        OR (NEW.state = 'failed' AND run.state IN ('failed', 'interrupted', 'queued'))
        OR (NEW.state = 'cancelled' AND run.state = 'cancelled')
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'active scan run is not bound to this job root');
END;

-- Progress is mutable only while actively running. This trigger protects the
-- invariant even if a future repository path bypasses update_scan_progress.
CREATE TRIGGER trg_scan_runs_progress_guard
BEFORE UPDATE OF discovered_count, fingerprinted_count, error_count, logical_bytes_seen
ON scan_runs
WHEN OLD.state <> 'running'
  OR NEW.fingerprinted_count > NEW.discovered_count
  OR NEW.discovered_count < OLD.discovered_count
  OR NEW.fingerprinted_count < OLD.fingerprinted_count
  OR NEW.error_count < OLD.error_count
  OR NEW.logical_bytes_seen < OLD.logical_bytes_seen
BEGIN
    SELECT RAISE(ABORT, 'invalid scan progress update');
END;

-- The active job and run briefly occupy adjacent states because SQLite
-- triggers are immediate. A coordinated transition uses job then run when
-- starting/resuming, and run then job when pausing or entering a terminal
-- state; both halves must remain in the same transaction.
CREATE TRIGGER trg_scan_jobs_state_binding
BEFORE UPDATE OF state ON scan_jobs
WHEN NOT (NEW.active_scan_run_id IS NULL AND NEW.state = 'cancelled')
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
        OR (NEW.state = 'completed' AND run.state = 'completed')
        OR (NEW.state = 'failed' AND run.state IN ('failed', 'interrupted'))
        OR (NEW.state = 'cancelled' AND run.state = 'cancelled')
      )
  ))
BEGIN
    SELECT RAISE(ABORT, 'scan job state is inconsistent with active run');
END;

CREATE TRIGGER trg_scan_runs_state_binding
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
        OR (NEW.state = 'interrupted' AND job.state IN ('running', 'paused', 'failed'))
        OR (NEW.state = 'cancelled' AND job.state IN ('queued', 'running', 'paused', 'cancelled'))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'scan run state is inconsistent with active job');
END;
