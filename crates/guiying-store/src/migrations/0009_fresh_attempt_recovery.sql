-- Version 9 separates fresh-attempt lineage from historical evidence reuse.
-- A missing policy is deliberately inert: neither a recoverable scope nor a
-- fingerprint hint may infer authority from namespace_profiles.reuse_scope.

CREATE TABLE namespace_reuse_policies (
    namespace_profile_id INTEGER PRIMARY KEY,
    volume_id INTEGER NOT NULL,
    policy TEXT NOT NULL CHECK (policy IN (
        'fresh_attempt_only', 'evidence_reuse_eligible'
    )),
    policy_version INTEGER NOT NULL CHECK (policy_version = 1),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (volume_id, namespace_profile_id),
    FOREIGN KEY (volume_id, namespace_profile_id)
        REFERENCES namespace_profiles(volume_id, id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT;

-- Every valid v8 cross-session profile had strong identity plus known case and
-- Unicode behavior. Preserve that narrower evidence-reuse eligibility exactly.
INSERT INTO namespace_reuse_policies (
    namespace_profile_id, volume_id, policy, policy_version, created_at_ms
)
SELECT namespace.id, namespace.volume_id, 'evidence_reuse_eligible', 1,
       namespace.created_at_ms
FROM namespace_profiles AS namespace
JOIN volumes AS volume ON volume.id = namespace.volume_id
WHERE namespace.origin = 'observed_v5'
  AND namespace.reuse_scope = 'cross_session'
  AND namespace.bound_mount_session_key IS NULL
  AND namespace.key_strategy = 'exact_native_v1'
  AND namespace.case_behavior <> 'unknown'
  AND namespace.unicode_behavior <> 'unknown'
  AND volume.identity_strength = 'strong';

CREATE INDEX ix_namespace_reuse_policies_policy_v9
    ON namespace_reuse_policies(policy, volume_id, namespace_profile_id);

CREATE TRIGGER trg_namespace_reuse_policies_insert_guard_v9
BEFORE INSERT ON namespace_reuse_policies
WHEN NOT EXISTS (
    SELECT 1
    FROM namespace_profiles AS namespace
    JOIN volumes AS volume ON volume.id = namespace.volume_id
    WHERE namespace.id = NEW.namespace_profile_id
      AND namespace.volume_id = NEW.volume_id
      AND namespace.origin = 'observed_v5'
      AND namespace.reuse_scope = 'cross_session'
      AND namespace.bound_mount_session_key IS NULL
      AND namespace.key_strategy = 'exact_native_v1'
      AND namespace.case_behavior <> 'unknown'
      AND volume.identity_strength = 'strong'
      AND NEW.created_at_ms >= namespace.created_at_ms
      AND (
          NEW.policy = 'fresh_attempt_only'
          OR (
              NEW.policy = 'evidence_reuse_eligible'
              AND namespace.unicode_behavior <> 'unknown'
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'namespace reuse policy exceeds immutable namespace evidence');
END;

CREATE TRIGGER trg_namespace_reuse_policies_no_update_v9
BEFORE UPDATE ON namespace_reuse_policies
BEGIN
    SELECT RAISE(ABORT, 'namespace reuse policy is immutable');
END;

CREATE TRIGGER trg_namespace_reuse_policies_no_delete_v9
BEFORE DELETE ON namespace_reuse_policies
BEGIN
    SELECT RAISE(ABORT, 'namespace reuse policy cannot be deleted');
END;

-- This append-only epoch makes the migration boundary independently
-- revalidatable after reopen. Row ids at or below the cutoff are v8 legacy;
-- every later id must carry an explicit v9 strategy.
CREATE TABLE scan_attempt_strategy_epochs (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    legacy_scan_run_id_cutoff INTEGER NOT NULL
        CHECK (legacy_scan_run_id_cutoff >= 0)
) STRICT;

INSERT INTO scan_attempt_strategy_epochs (id, legacy_scan_run_id_cutoff)
SELECT 1, COALESCE(max(id), 0) FROM scan_runs;

CREATE TRIGGER trg_scan_attempt_strategy_epochs_no_insert_v9
BEFORE INSERT ON scan_attempt_strategy_epochs
WHEN EXISTS (SELECT 1 FROM scan_attempt_strategy_epochs)
BEGIN
    SELECT RAISE(ABORT, 'scan attempt strategy epoch already exists');
END;

CREATE TRIGGER trg_scan_attempt_strategy_epochs_no_update_v9
BEFORE UPDATE ON scan_attempt_strategy_epochs
BEGIN
    SELECT RAISE(ABORT, 'scan attempt strategy epoch is immutable');
END;

CREATE TRIGGER trg_scan_attempt_strategy_epochs_no_delete_v9
BEFORE DELETE ON scan_attempt_strategy_epochs
BEGIN
    SELECT RAISE(ABORT, 'scan attempt strategy epoch cannot be deleted');
END;

-- Migrated v8 rows retain legacy. New v9 rows are forced by an insert trigger
-- to state an explicit initial or fresh-child strategy.
ALTER TABLE scan_runs ADD COLUMN attempt_strategy TEXT NOT NULL DEFAULT 'legacy'
    CHECK (
        attempt_strategy = 'legacy'
        OR (
            attempt_strategy = 'initial_full_v1'
            AND parent_scan_run_id IS NULL
            AND scan_mode = 'full'
        )
        OR (
            attempt_strategy = 'fresh_full_child_v1'
            AND parent_scan_run_id IS NOT NULL
            AND scan_mode = 'full'
        )
    );

CREATE TRIGGER trg_scan_runs_attempt_strategy_insert_v9
BEFORE INSERT ON scan_runs
WHEN NEW.attempt_strategy = 'legacy'
  OR NOT (
      (NEW.attempt_strategy = 'initial_full_v1'
       AND NEW.parent_scan_run_id IS NULL AND NEW.scan_mode = 'full')
      OR
      (NEW.attempt_strategy = 'fresh_full_child_v1'
       AND NEW.parent_scan_run_id IS NOT NULL AND NEW.scan_mode = 'full')
  )
BEGIN
    SELECT RAISE(ABORT, 'new scan run requires an explicit full-attempt strategy');
END;

CREATE TRIGGER trg_scan_runs_attempt_strategy_epoch_insert_v9
AFTER INSERT ON scan_runs
WHEN NOT EXISTS (
    SELECT 1 FROM scan_attempt_strategy_epochs AS epoch
    WHERE epoch.id = 1
      AND NEW.id > epoch.legacy_scan_run_id_cutoff
      AND NEW.attempt_strategy IN ('initial_full_v1', 'fresh_full_child_v1')
)
BEGIN
    SELECT RAISE(ABORT, 'new scan run does not follow the immutable v9 strategy epoch');
END;

CREATE TRIGGER trg_scan_runs_attempt_lineage_no_update_v9
BEFORE UPDATE OF id, attempt_strategy, parent_scan_run_id, scan_mode ON scan_runs
WHEN NEW.id IS NOT OLD.id
  OR NEW.attempt_strategy IS NOT OLD.attempt_strategy
  OR NEW.parent_scan_run_id IS NOT OLD.parent_scan_run_id
  OR NEW.scan_mode IS NOT OLD.scan_mode
BEGIN
    SELECT RAISE(ABORT, 'scan attempt strategy and parent lineage are immutable');
END;

-- v8 rejected unknown Unicode for every cross-session namespace. v9 permits
-- it only as a byte-exact namespace; the companion policy prevents evidence
-- reuse and permits fresh lineage only.
DROP TRIGGER trg_namespace_profiles_insert_guard_v5;

CREATE TRIGGER trg_namespace_profiles_insert_guard_v9
BEFORE INSERT ON namespace_profiles
WHEN (NEW.origin = 'observed_v5' AND NOT EXISTS (
          SELECT 1 FROM volumes AS volume
          WHERE volume.id = NEW.volume_id
            AND (
                NEW.reuse_scope <> 'cross_session'
                OR (
                    volume.identity_strength = 'strong'
                    AND NEW.case_behavior <> 'unknown'
                    AND NEW.key_strategy = 'exact_native_v1'
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
            AND NEW.key_strategy = 'exact_native_v1'
      ))
   OR (NEW.legacy_capability_profile_id IS NOT NULL AND NOT EXISTS (
          SELECT 1 FROM capability_profiles AS profile
          WHERE profile.id = NEW.legacy_capability_profile_id
            AND profile.volume_id = NEW.volume_id
      ))
BEGIN
    SELECT RAISE(ABORT, 'namespace profile evidence is incomplete or not reusable');
END;

-- The v5 trigger still checks the complete job/namespace/root relation. These
-- v9 guards add the policy and explicit-attempt requirements that v5 could not
-- express before the companion table existed.
CREATE TRIGGER trg_scan_job_scopes_recovery_policy_insert_v9
BEFORE INSERT ON scan_job_scopes
WHEN NEW.origin = 'observed_v5'
 AND NEW.recoverable = 1
 AND NOT EXISTS (
    SELECT 1
    FROM namespace_reuse_policies AS policy
    JOIN namespace_profiles AS namespace
      ON namespace.id = policy.namespace_profile_id
     AND namespace.volume_id = policy.volume_id
    JOIN volumes AS volume ON volume.id = policy.volume_id
    WHERE policy.namespace_profile_id = NEW.namespace_profile_id
      AND policy.volume_id = NEW.volume_id
      AND policy.policy IN ('fresh_attempt_only', 'evidence_reuse_eligible')
      AND namespace.reuse_scope = 'cross_session'
      AND namespace.case_behavior <> 'unknown'
      AND namespace.key_strategy = 'exact_native_v1'
      AND volume.identity_strength = 'strong'
 )
BEGIN
    SELECT RAISE(ABORT, 'recoverable scan scope lacks a fresh-attempt policy');
END;

CREATE TRIGGER trg_scan_job_runs_attempt_strategy_insert_v9
BEFORE INSERT ON scan_job_runs
WHEN NOT EXISTS (
    SELECT 1
    FROM scan_runs AS candidate_run
    JOIN scan_jobs AS candidate_job
      ON candidate_job.id = NEW.scan_job_id
     AND candidate_job.volume_id = NEW.volume_id
    JOIN scan_job_scopes AS scope
      ON scope.scan_job_id = NEW.scan_job_id
     AND scope.volume_id = NEW.volume_id
    JOIN namespace_profiles AS namespace
      ON namespace.id = scope.namespace_profile_id
     AND namespace.volume_id = scope.volume_id
    WHERE candidate_run.id = NEW.scan_run_id
      AND candidate_run.volume_id = NEW.volume_id
      AND candidate_run.scan_mode = 'full'
      AND (
          (NEW.attempt_number = 1
           AND candidate_run.attempt_strategy = 'initial_full_v1'
           AND candidate_run.parent_scan_run_id IS NULL
           AND candidate_job.state = 'queued'
           AND candidate_job.active_scan_run_id IS NULL)
          OR
          (NEW.attempt_number > 1
           AND candidate_run.attempt_strategy = 'fresh_full_child_v1'
           AND candidate_run.parent_scan_run_id = candidate_job.active_scan_run_id
           AND candidate_job.state = 'failed'
           AND scope.recoverable = 1
           AND namespace.reuse_scope = 'cross_session'
           AND EXISTS (
               SELECT 1
               FROM namespace_reuse_policies AS policy
               JOIN scan_runs AS parent
                 ON parent.id = candidate_run.parent_scan_run_id
                AND parent.volume_id = candidate_run.volume_id
               WHERE policy.namespace_profile_id = scope.namespace_profile_id
                 AND policy.volume_id = scope.volume_id
                 AND policy.policy IN (
                     'fresh_attempt_only', 'evidence_reuse_eligible'
                 )
                 AND parent.attempt_strategy IN (
                     'initial_full_v1', 'fresh_full_child_v1'
                 )
                 AND parent.state = 'interrupted'
                 AND NOT EXISTS (
                     SELECT 1 FROM scan_runtime_leases AS lease
                     WHERE lease.scan_run_id = parent.id
                       AND lease.state = 'active'
                 )
           ))
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'scan attempt strategy or recovery policy is invalid');
END;

CREATE TRIGGER trg_scan_run_sessions_fresh_policy_insert_v9
BEFORE INSERT ON scan_run_sessions
WHEN EXISTS (
    SELECT 1 FROM scan_job_runs AS binding
    WHERE binding.scan_job_id = NEW.scan_job_id
      AND binding.scan_run_id = NEW.scan_run_id
      AND binding.volume_id = NEW.volume_id
      AND binding.attempt_number > 1
 )
 AND NOT EXISTS (
    SELECT 1
    FROM scan_job_scopes AS scope
    JOIN namespace_reuse_policies AS policy
      ON policy.namespace_profile_id = scope.namespace_profile_id
     AND policy.volume_id = scope.volume_id
    JOIN scan_runs AS run
      ON run.id = NEW.scan_run_id AND run.volume_id = NEW.volume_id
    WHERE scope.scan_job_id = NEW.scan_job_id
      AND scope.volume_id = NEW.volume_id
      AND scope.namespace_profile_id = NEW.namespace_profile_id
      AND scope.recoverable = 1
      AND policy.policy IN ('fresh_attempt_only', 'evidence_reuse_eligible')
      AND run.attempt_strategy = 'fresh_full_child_v1'
 )
BEGIN
    SELECT RAISE(ABORT, 'fresh scan session lacks its lineage-only policy');
END;

CREATE INDEX ix_scan_job_scopes_fresh_attempt_v9
    ON scan_job_scopes(
        volume_id, namespace_profile_id, path_encoding,
        stable_root_path_key, root_scope_key, scan_job_id
    )
    WHERE origin = 'observed_v5' AND recoverable = 1;

CREATE INDEX ix_scan_jobs_failed_recovery_v9
    ON scan_jobs(volume_id, updated_at_ms DESC, id, active_scan_run_id, state_version)
    WHERE state = 'failed' AND active_scan_run_id IS NOT NULL;

-- Fail the migration if a valid v8 source was not mapped to the exact v9
-- policy/strategy representation described above.
CREATE TABLE guiying_v9_invariant_guard (
    violation INTEGER NOT NULL CHECK (violation = 0)
) STRICT;

INSERT INTO guiying_v9_invariant_guard (violation)
SELECT 1
FROM namespace_profiles AS namespace
JOIN volumes AS volume ON volume.id = namespace.volume_id
LEFT JOIN namespace_reuse_policies AS policy
  ON policy.namespace_profile_id = namespace.id
 AND policy.volume_id = namespace.volume_id
WHERE namespace.origin = 'observed_v5'
  AND namespace.reuse_scope = 'cross_session'
  AND (
      volume.identity_strength <> 'strong'
      OR namespace.case_behavior = 'unknown'
      OR namespace.key_strategy <> 'exact_native_v1'
      OR policy.namespace_profile_id IS NULL
      OR policy.policy <> 'evidence_reuse_eligible'
      OR namespace.unicode_behavior = 'unknown'
  )
LIMIT 1;

INSERT INTO guiying_v9_invariant_guard (violation)
SELECT 1 FROM scan_runs WHERE attempt_strategy <> 'legacy' LIMIT 1;

INSERT INTO guiying_v9_invariant_guard (violation)
SELECT 1
FROM scan_attempt_strategy_epochs AS epoch
WHERE epoch.id <> 1
   OR epoch.legacy_scan_run_id_cutoff <> COALESCE((SELECT max(id) FROM scan_runs), 0)
LIMIT 1;

INSERT INTO guiying_v9_invariant_guard (violation)
SELECT 1
FROM scan_job_scopes AS scope
LEFT JOIN namespace_reuse_policies AS policy
  ON policy.namespace_profile_id = scope.namespace_profile_id
 AND policy.volume_id = scope.volume_id
WHERE scope.recoverable = 1
  AND (
      policy.namespace_profile_id IS NULL
      OR policy.policy NOT IN ('fresh_attempt_only', 'evidence_reuse_eligible')
  )
LIMIT 1;

DROP TABLE guiying_v9_invariant_guard;
