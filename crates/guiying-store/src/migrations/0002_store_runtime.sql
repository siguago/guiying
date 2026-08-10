CREATE TABLE scan_jobs (
    id INTEGER PRIMARY KEY,
    job_key TEXT NOT NULL UNIQUE,
    volume_id INTEGER NOT NULL,
    root_relative_path TEXT NOT NULL,
    root_path_key BLOB NOT NULL CHECK (length(root_path_key) > 0),
    state TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'paused', 'completed', 'failed', 'cancelled')),
    config_json TEXT CHECK (config_json IS NULL OR json_valid(config_json)),
    active_scan_run_id INTEGER,
    state_version INTEGER NOT NULL DEFAULT 0 CHECK (state_version >= 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    UNIQUE (volume_id, id),
    CHECK (length(job_key) > 0),
    CHECK (root_relative_path = '' OR root_relative_path NOT LIKE '/%'),
    FOREIGN KEY (volume_id) REFERENCES volumes(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, active_scan_run_id) REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_scan_jobs_volume_state
    ON scan_jobs(volume_id, state, updated_at_ms DESC);

CREATE INDEX ix_scan_jobs_active_run
    ON scan_jobs(volume_id, active_scan_run_id)
    WHERE active_scan_run_id IS NOT NULL;

CREATE TABLE scan_job_runs (
    scan_job_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    volume_id INTEGER NOT NULL,
    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (scan_job_id, scan_run_id),
    UNIQUE (scan_job_id, attempt_number),
    UNIQUE (scan_run_id),
    FOREIGN KEY (volume_id, scan_job_id) REFERENCES scan_jobs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, scan_run_id) REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_scan_job_runs_run
    ON scan_job_runs(volume_id, scan_run_id);

-- `media_files.relative_path` is display text. This companion table preserves
-- the exact path representation used by the filesystem adapter so non-UTF-8
-- Unix names and Windows WTF-16 names never round-trip through lossy text.
CREATE TABLE media_file_paths (
    volume_id INTEGER NOT NULL,
    media_file_id INTEGER NOT NULL,
    relative_path_raw BLOB NOT NULL CHECK (length(relative_path_raw) > 0),
    path_encoding TEXT NOT NULL
        CHECK (path_encoding IN ('utf8', 'unix_bytes', 'windows_wtf16le')),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    PRIMARY KEY (volume_id, media_file_id),
    FOREIGN KEY (volume_id, media_file_id) REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE scan_issues (
    id INTEGER PRIMARY KEY,
    issue_key TEXT NOT NULL UNIQUE,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    media_file_id INTEGER,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'error', 'fatal')),
    stage TEXT NOT NULL CHECK (length(stage) > 0),
    code TEXT NOT NULL CHECK (length(code) > 0),
    message TEXT NOT NULL CHECK (length(message) > 0),
    details_json TEXT CHECK (details_json IS NULL OR json_valid(details_json)),
    occurred_at_ms INTEGER NOT NULL CHECK (occurred_at_ms >= 0),
    resolved_at_ms INTEGER CHECK (resolved_at_ms IS NULL OR resolved_at_ms >= occurred_at_ms),
    UNIQUE (volume_id, id),
    FOREIGN KEY (volume_id, scan_run_id) REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (volume_id, media_file_id) REFERENCES media_files(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_scan_issues_run_severity
    ON scan_issues(volume_id, scan_run_id, severity, occurred_at_ms);

CREATE INDEX ix_scan_issues_media
    ON scan_issues(volume_id, media_file_id)
    WHERE media_file_id IS NOT NULL;

CREATE TABLE scan_reports (
    id INTEGER PRIMARY KEY,
    report_key TEXT NOT NULL UNIQUE,
    volume_id INTEGER NOT NULL,
    scan_run_id INTEGER NOT NULL,
    report_version INTEGER NOT NULL CHECK (report_version >= 1),
    report_json TEXT NOT NULL CHECK (json_valid(report_json)),
    generated_at_ms INTEGER NOT NULL CHECK (generated_at_ms >= 0),
    UNIQUE (scan_run_id, report_version),
    UNIQUE (volume_id, id),
    FOREIGN KEY (volume_id, scan_run_id) REFERENCES scan_runs(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

CREATE INDEX ix_scan_reports_run
    ON scan_reports(volume_id, scan_run_id, generated_at_ms DESC);
