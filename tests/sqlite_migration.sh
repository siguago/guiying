#!/bin/sh

set -eu

repository_root=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "sqlite3 is required" >&2
    exit 1
fi

test_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/guiying-sqlite.XXXXXX")
trap 'rm -r -- "$test_tmp_dir"' EXIT HUP INT TERM

failures=0

pass() {
    echo "PASS $1"
}

fail() {
    echo "FAIL $1" >&2
    failures=$((failures + 1))
}

expect_ok() {
    test_name=$1
    test_db=$2
    test_sql=$3

    if sqlite3 "$test_db" "PRAGMA foreign_keys=ON; $test_sql"; then
        pass "$test_name"
    else
        fail "$test_name"
    fi
}

expect_fail() {
    test_name=$1
    test_db=$2
    test_sql=$3

    if sqlite3 "$test_db" "PRAGMA foreign_keys=ON; $test_sql" \
        >/dev/null 2>&1; then
        fail "$test_name"
    else
        pass "$test_name"
    fi
}

expect_value() {
    test_name=$1
    test_db=$2
    test_sql=$3
    expected_value=$4
    actual_value=$(sqlite3 "$test_db" "PRAGMA foreign_keys=ON; $test_sql")

    if [ "$actual_value" = "$expected_value" ]; then
        pass "$test_name"
    else
        echo "expected: $expected_value" >&2
        echo "actual:   $actual_value" >&2
        fail "$test_name"
    fi
}

schema_db="$test_tmp_dir/schema.db"
sqlite3 "$schema_db" <<'SQL'
.bail on
.read src-tauri/migrations/0001_init.sql
SQL

expect_value schema_integrity "$schema_db" \
    "PRAGMA integrity_check;" "ok"
expect_value schema_foreign_keys "$schema_db" \
    "PRAGMA foreign_key_check;" ""
expect_value strict_table_count "$schema_db" \
    "SELECT count(*) FROM pragma_table_list
     WHERE schema='main' AND type='table' AND strict=1;" "14"
foreign_key_index_lint=$(sqlite3 "$schema_db" ".lint fkey-indexes")
if [ -z "$foreign_key_index_lint" ]; then
    pass foreign_key_child_indexes
else
    echo "$foreign_key_index_lint" >&2
    fail foreign_key_child_indexes
fi

core_db="$test_tmp_dir/core.db"
sqlite3 "$core_db" <<'SQL'
.bail on
.read src-tauri/migrations/0001_init.sql

INSERT INTO volumes (
    id, identity_key, identity_strength, filesystem_type, is_read_only,
    first_seen_at_ms, last_seen_at_ms, created_at_ms, updated_at_ms
) VALUES
    (1, 'vol-1', 'strong', 'apfs', 0, 1, 1, 1, 1),
    (2, 'vol-2', 'strong', 'apfs', 0, 1, 1, 1, 1);

INSERT INTO capability_profiles (
    id, volume_id, profile_hash, probe_mode, probe_status, observed_at_ms,
    os_build, can_read, can_write, is_current, created_at_ms
) VALUES
    (1, 1, zeroblob(32), 'active', 'complete', 1,
        'test', 1, 1, 1, 1),
    (2, 2,
        x'0101010101010101010101010101010101010101010101010101010101010101',
        'active', 'complete', 1, 'test', 1, 1, 1, 1);

INSERT INTO scan_runs (
    id, run_key, volume_id, capability_profile_id, root_relative_path,
    root_path_key, scan_mode, state, created_at_ms, updated_at_ms
) VALUES
    (1, 'scan-1', 1, 1, '', x'01', 'full', 'completed', 1, 1),
    (2, 'scan-2', 2, 2, '', x'02', 'full', 'completed', 1, 1);

INSERT INTO media_files (
    id, volume_id, first_seen_scan_run_id, last_seen_scan_run_id,
    relative_path, path_key, media_kind, size_bytes, created_at_ms,
    updated_at_ms
) VALUES
    (1, 1, 1, 1, 'source.jpg', x'01', 'photo', 10, 1, 1),
    (2, 1, 1, 1, 'keeper.jpg', x'02', 'photo', 10, 1, 1),
    (3, 1, 1, 1, 'target.jpg', x'03', 'photo', 10, 1, 1),
    (4, 1, 1, 1, 'target.xmp', x'04', 'sidecar', 5, 1, 1),
    (20, 2, 2, 2, 'other.jpg', x'20', 'photo', 10, 1, 1);

INSERT INTO fingerprints (
    id, volume_id, media_file_id, scan_run_id, fingerprint_kind,
    algorithm, algorithm_version, parameters_hash, source_signature, digest,
    observed_size_bytes, bytes_read, completed_at_ms, created_at_ms
) VALUES
    (1, 1, 1, 1, 'exact_bytes', 'blake3', 1, zeroblob(32),
        x'0101010101010101010101010101010101010101010101010101010101010101',
        x'AA', 10, 10, 1, 1),
    (2, 1, 2, 1, 'exact_bytes', 'blake3', 1, zeroblob(32),
        x'0202020202020202020202020202020202020202020202020202020202020202',
        x'AA', 10, 10, 1, 1),
    (3, 1, 1, 1, 'sample', 'sample', 1, zeroblob(32),
        x'0303030303030303030303030303030303030303030303030303030303030303',
        x'AB', 10, 2, 1, 1),
    (20, 2, 20, 2, 'exact_bytes', 'blake3', 1, zeroblob(32),
        x'2020202020202020202020202020202020202020202020202020202020202020',
        x'CC', 10, 10, 1, 1);

INSERT INTO duplicate_groups (
    id, volume_id, scan_run_id, group_key, match_kind, algorithm,
    algorithm_version, similarity_basis_points, confidence_basis_points,
    review_state, created_at_ms, updated_at_ms
) VALUES (
    1, 1, 1, zeroblob(32), 'exact_bytes', 'blake3', 1, 10000, 10000,
    'approved', 1, 1
);

INSERT INTO duplicate_group_members (
    id, volume_id, duplicate_group_id, media_file_id,
    evidence_fingerprint_id, evidence_fingerprint_kind, member_role,
    recommended_action, created_at_ms
) VALUES
    (1, 1, 1, 1, 1, 'exact_bytes', 'candidate', 'quarantine', 1),
    (2, 1, 1, 2, 2, 'exact_bytes', 'keeper', 'keep', 1);

INSERT INTO asset_links (
    id, link_key, volume_id, scan_run_id, from_media_file_id,
    to_media_file_id, link_kind, relation_state, confidence_basis_points,
    created_at_ms, updated_at_ms
) VALUES (
    1, zeroblob(32), 1, 1, 4, 3, 'sidecar_for', 'confirmed', 10000, 1, 1
);

INSERT INTO time_candidates (
    id, candidate_key, volume_id, media_file_id, scan_run_id,
    source_media_file_id, source_asset_link_id, source_kind, raw_value,
    raw_text, raw_encoding, parse_status, wall_time, utc_offset_minutes,
    offset_kind, utc_instant_ns, precision_ns, precision_kind,
    confidence_basis_points, is_selected, normalized_at_ms, created_at_ms
) VALUES (
    1, zeroblob(32), 1, 3, 1, 4, 1, 'xmp_sidecar', x'32303230', '2020',
    'utf-8', 'parsed', '2020-01-01T00:00:00', 480, 'sidecar',
    1577808000000000000, 1000000000, 'exact', 10000, 1, 1, 1
);

INSERT INTO operation_batches (
    id, batch_key, volume_id, scan_run_id, capability_profile_id,
    operation_kind, requires_confirmation, confirmed_at_ms, created_at_ms,
    updated_at_ms
) VALUES
    (1, 'batch-1', 1, 1, 1, 'quarantine', 1, 10, 10, 10),
    (2, 'batch-2', 1, 1, 1, 'restore', 0, NULL, 10, 10);

INSERT INTO operation_items (
    id, operation_batch_id, volume_id, item_key, media_file_id,
    keeper_media_file_id, duplicate_group_member_id,
    precondition_fingerprint_id, operation_kind,
    source_relative_path_snapshot, source_relative_path_raw,
    source_path_encoding, destination_relative_path,
    destination_relative_path_raw, destination_path_encoding,
    expected_size_bytes, expected_digest, created_at_ms, updated_at_ms
) VALUES (
    1, 1, 1, 'item-1', 1, 2, 1, 1, 'quarantine', 'source.jpg',
    CAST('source.jpg' AS BLOB), 'unix_bytes', '.guiying/q/source.jpg',
    CAST('.guiying/q/source.jpg' AS BLOB), 'unix_bytes', 10, x'AA', 10, 10
);

UPDATE operation_batches
SET sealed_at_ms = 11,
    manifest_digest =
        x'9999999999999999999999999999999999999999999999999999999999999999',
    updated_at_ms = 11
WHERE id = 1;

INSERT INTO volume_manifest_outbox (
    outbox_key, volume_id, operation_batch_id, record_kind, sequence_number,
    target_volume_identity_key, target_mount_session_key,
    target_relative_path, sealed_plan_digest, record_payload, payload_digest,
    record_digest, local_recorded_at_ms, created_at_ms, updated_at_ms
) VALUES (
    'batch-manifest', 1, 1, 'batch_manifest', 0, 'vol-1', 'mount-1',
    '.guiying/audit/batch-1.jsonl',
    x'9999999999999999999999999999999999999999999999999999999999999999',
    x'01',
    x'1010101010101010101010101010101010101010101010101010101010101010',
    x'2020202020202020202020202020202020202020202020202020202020202020',
    12, 12, 12
);
SQL

expect_fail cross_volume_fingerprint "$core_db" \
    "INSERT INTO fingerprints (
        id, volume_id, media_file_id, scan_run_id, fingerprint_kind,
        algorithm, algorithm_version, parameters_hash, source_signature,
        digest, observed_size_bytes, bytes_read, completed_at_ms, created_at_ms
     ) VALUES (
        90, 1, 1, 2, 'exact_bytes', 'blake3', 1, zeroblob(32),
        zeroblob(32), x'90', 10, 10, 1, 1
     );"

expect_fail wrong_member_evidence_file "$core_db" \
    "INSERT INTO duplicate_group_members (
        id, volume_id, duplicate_group_id, media_file_id,
        evidence_fingerprint_id, evidence_fingerprint_kind, created_at_ms
     ) VALUES (90, 1, 1, 1, 2, 'exact_bytes', 1);"

expect_fail fingerprint_evidence_immutable "$core_db" \
    "UPDATE fingerprints SET digest=x'FF' WHERE id=1;"

expect_fail duplicate_group_evidence_identity_immutable "$core_db" \
    "UPDATE duplicate_groups SET algorithm='sha256' WHERE id=1;"

expect_fail wrong_sidecar_direction "$core_db" \
    "INSERT INTO time_candidates (
        id, candidate_key, volume_id, media_file_id, scan_run_id,
        source_media_file_id, source_asset_link_id, source_kind, raw_value,
        raw_encoding, parse_status, precision_kind, confidence_basis_points,
        normalized_at_ms, created_at_ms
     ) VALUES (
        90,
        x'9090909090909090909090909090909090909090909090909090909090909090',
        1, 1, 1, 4, 1, 'xmp_sidecar', x'31', 'utf-8', 'unparseable',
        'unknown', 0, 1, 1
     );"

expect_fail time_candidate_evidence_immutable "$core_db" \
    "UPDATE time_candidates SET utc_instant_ns=0 WHERE id=1;"

expect_fail keeper_cannot_be_its_own_destructive_source "$core_db" \
    "INSERT INTO operation_items (
        id, operation_batch_id, volume_id, item_key, media_file_id,
        keeper_media_file_id, duplicate_group_member_id,
        precondition_fingerprint_id, operation_kind,
        source_relative_path_snapshot, source_relative_path_raw,
        source_path_encoding, destination_relative_path,
        destination_relative_path_raw, destination_path_encoding,
        expected_size_bytes, expected_digest, created_at_ms, updated_at_ms
     ) VALUES (
        93, 1, 1, 'self-keeper', 2, 2, 2, 2, 'quarantine', 'keeper.jpg',
        CAST('keeper.jpg' AS BLOB), 'unix_bytes', '.guiying/q/keeper.jpg',
        CAST('.guiying/q/keeper.jpg' AS BLOB), 'unix_bytes', 10, x'AA', 1, 1
     );"

expect_fail operation_kind_must_match_batch "$core_db" \
    "INSERT INTO operation_items (
        id, operation_batch_id, volume_id, item_key, media_file_id,
        keeper_media_file_id, duplicate_group_member_id,
        precondition_fingerprint_id, operation_kind,
        source_relative_path_snapshot, source_relative_path_raw,
        source_path_encoding, expected_size_bytes, expected_digest,
        created_at_ms, updated_at_ms
     ) VALUES (
        94, 2, 1, 'wrong-batch-kind', 1, 2, 1, 1, 'purge', 'source.jpg',
        CAST('source.jpg' AS BLOB), 'unix_bytes', 10, x'AA', 1, 1
     );"

expect_fail display_path_traversal_is_rejected "$core_db" \
    "INSERT INTO operation_items (
        id, operation_batch_id, volume_id, item_key, media_file_id,
        precondition_fingerprint_id, operation_kind,
        source_relative_path_snapshot, source_relative_path_raw,
        source_path_encoding, destination_relative_path,
        destination_relative_path_raw, destination_path_encoding,
        expected_size_bytes, expected_digest, created_at_ms, updated_at_ms
     ) VALUES (
        95, 2, 1, 'display-traversal', 1, 1, 'restore', 'source.jpg',
        CAST('source.jpg' AS BLOB), 'unix_bytes', '../escape.jpg',
        CAST('../escape.jpg' AS BLOB), 'unix_bytes', 10, x'AA', 1, 1
     );"

expect_fail raw_path_traversal_is_rejected "$core_db" \
    "INSERT INTO operation_items (
        id, operation_batch_id, volume_id, item_key, media_file_id,
        precondition_fingerprint_id, operation_kind,
        source_relative_path_snapshot, source_relative_path_raw,
        source_path_encoding, destination_relative_path,
        destination_relative_path_raw, destination_path_encoding,
        expected_size_bytes, expected_digest, created_at_ms, updated_at_ms
     ) VALUES (
        96, 2, 1, 'raw-traversal', 1, 1, 'restore', 'source.jpg',
        CAST('source.jpg' AS BLOB), 'unix_bytes', 'safe/escape.jpg',
        CAST('../escape.jpg' AS BLOB), 'unix_bytes', 10, x'AA', 1, 1
     );"

expect_fail quarantine_requires_destination "$core_db" \
    "INSERT INTO operation_items (
        id, operation_batch_id, volume_id, item_key, media_file_id,
        keeper_media_file_id, duplicate_group_member_id,
        precondition_fingerprint_id, operation_kind,
        source_relative_path_snapshot, source_relative_path_raw,
        source_path_encoding, expected_size_bytes, expected_digest,
        created_at_ms, updated_at_ms
     ) VALUES (
        97, 1, 1, 'missing-destination', 1, 2, 1, 1, 'quarantine',
        'source.jpg', CAST('source.jpg' AS BLOB), 'unix_bytes',
        10, x'AA', 1, 1
     );"

expect_fail precondition_wrong_file "$core_db" \
    "INSERT INTO operation_items (
        id, operation_batch_id, volume_id, item_key, media_file_id,
        precondition_fingerprint_id, operation_kind,
        source_relative_path_snapshot, source_relative_path_raw,
        source_path_encoding, destination_relative_path,
        destination_relative_path_raw, destination_path_encoding,
        expected_size_bytes, expected_digest,
        created_at_ms, updated_at_ms
     ) VALUES (
        90, 2, 1, 'wrong-file', 1, 2, 'restore', 'source.jpg',
        CAST('source.jpg' AS BLOB), 'unix_bytes', 'restored/source.jpg',
        CAST('restored/source.jpg' AS BLOB), 'unix_bytes', 10, x'AA', 1, 1
     );"

expect_fail precondition_not_exact "$core_db" \
    "INSERT INTO operation_items (
        id, operation_batch_id, volume_id, item_key, media_file_id,
        precondition_fingerprint_id, operation_kind,
        source_relative_path_snapshot, source_relative_path_raw,
        source_path_encoding, destination_relative_path,
        destination_relative_path_raw, destination_path_encoding,
        expected_size_bytes, expected_digest,
        created_at_ms, updated_at_ms
     ) VALUES (
        91, 2, 1, 'not-exact', 1, 3, 'restore', 'source.jpg',
        CAST('source.jpg' AS BLOB), 'unix_bytes', 'restored/source.jpg',
        CAST('restored/source.jpg' AS BLOB), 'unix_bytes', 10, x'AB', 1, 1
     );"

expect_fail precondition_snapshot_mismatch "$core_db" \
    "INSERT INTO operation_items (
        id, operation_batch_id, volume_id, item_key, media_file_id,
        precondition_fingerprint_id, operation_kind,
        source_relative_path_snapshot, source_relative_path_raw,
        source_path_encoding, destination_relative_path,
        destination_relative_path_raw, destination_path_encoding,
        expected_size_bytes, expected_digest,
        created_at_ms, updated_at_ms
     ) VALUES (
        92, 2, 1, 'bad-digest', 1, 1, 'restore', 'source.jpg',
        CAST('source.jpg' AS BLOB), 'unix_bytes', 'restored/source.jpg',
        CAST('restored/source.jpg' AS BLOB), 'unix_bytes', 10, x'FF', 1, 1
     );"

expect_fail bind_pending_batch_manifest "$core_db" \
    "UPDATE operation_batches
     SET volume_manifest_outbox_id=1, updated_at_ms=13 WHERE id=1;"

expect_fail run_without_verified_manifest "$core_db" \
    "UPDATE operation_batches
     SET state='running', state_version=1, started_at_ms=13, updated_at_ms=13
     WHERE id=1;"

expect_fail outbox_skip_sequence "$core_db" \
    "INSERT INTO volume_manifest_outbox (
        outbox_key, volume_id, operation_batch_id, operation_item_id,
        record_kind, sequence_number, target_volume_identity_key,
        target_mount_session_key, target_relative_path, sealed_plan_digest,
        record_payload, payload_digest, previous_record_digest, record_digest,
        local_recorded_at_ms, created_at_ms, updated_at_ms
     ) VALUES (
        'skip', 1, 1, 1, 'item_intent', 2, 'vol-1', 'mount-1',
        '.guiying/audit/batch-1.jsonl',
        x'9999999999999999999999999999999999999999999999999999999999999999',
        x'02', zeroblob(32),
        x'2020202020202020202020202020202020202020202020202020202020202020',
        x'3030303030303030303030303030303030303030303030303030303030303030',
        13, 13, 13
     );"

expect_fail outbox_payload_immutable "$core_db" \
    "UPDATE volume_manifest_outbox SET record_payload=x'FF' WHERE id=1;"

expect_fail outbox_wrong_state_version "$core_db" \
    "UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=2, target_offset_bytes=0,
         target_length_bytes=1, written_at_ms=13, updated_at_ms=13
     WHERE id=1;"

expect_fail operation_events_immutable "$core_db" \
    "UPDATE operation_events SET actor='tampered' WHERE id=1;"

expect_fail outbox_no_delete "$core_db" \
    "DELETE FROM volume_manifest_outbox WHERE id=1;"

expect_ok queue_item_intent "$core_db" \
    "INSERT INTO volume_manifest_outbox (
        outbox_key, volume_id, operation_batch_id, operation_item_id,
        record_kind, sequence_number, target_volume_identity_key,
        target_mount_session_key, target_relative_path, sealed_plan_digest,
        record_payload, payload_digest, previous_record_digest, record_digest,
        local_recorded_at_ms, created_at_ms, updated_at_ms
     ) VALUES (
        'intent', 1, 1, 1, 'item_intent', 1, 'vol-1', 'mount-1',
        '.guiying/audit/batch-1.jsonl',
        x'9999999999999999999999999999999999999999999999999999999999999999',
        x'02', zeroblob(32),
        x'2020202020202020202020202020202020202020202020202020202020202020',
        x'3030303030303030303030303030303030303030303030303030303030303030',
        14, 14, 14
     );"

expect_fail outbox_predecessor_must_be_verified "$core_db" \
    "UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=1, target_offset_bytes=1,
         target_length_bytes=1, written_at_ms=15, updated_at_ms=15
     WHERE id=2;"

expect_ok verify_batch_manifest "$core_db" \
    "UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=1, target_offset_bytes=0,
         target_length_bytes=1, written_at_ms=15, updated_at_ms=15
     WHERE id=1;
     UPDATE volume_manifest_outbox
     SET delivery_state='fsynced', state_version=2, fsynced_at_ms=16,
         updated_at_ms=16 WHERE id=1;
     UPDATE volume_manifest_outbox
     SET delivery_state='verified', state_version=3, verified_at_ms=17,
         readback_digest=record_digest, updated_at_ms=17 WHERE id=1;
     UPDATE operation_batches
     SET volume_manifest_outbox_id=1, updated_at_ms=18 WHERE id=1;
     UPDATE operation_batches
     SET state='running', state_version=1, started_at_ms=19,
         updated_at_ms=19 WHERE id=1;"

expect_fail bind_pending_item_intent "$core_db" \
    "UPDATE operation_items
     SET volume_intent_outbox_id=2, updated_at_ms=20 WHERE id=1;"

expect_fail start_without_verified_item_intent "$core_db" \
    "UPDATE operation_items
     SET state='in_progress', state_version=1, updated_at_ms=20 WHERE id=1;"

expect_ok verify_and_bind_item_intent "$core_db" \
    "UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=1, target_offset_bytes=1,
         target_length_bytes=1, written_at_ms=20, updated_at_ms=20
     WHERE id=2;
     UPDATE volume_manifest_outbox
     SET delivery_state='fsynced', state_version=2, fsynced_at_ms=21,
         updated_at_ms=21 WHERE id=2;
     UPDATE volume_manifest_outbox
     SET delivery_state='verified', state_version=3, verified_at_ms=22,
         readback_digest=record_digest, updated_at_ms=22 WHERE id=2;
     UPDATE operation_items
     SET volume_intent_outbox_id=2, updated_at_ms=23 WHERE id=1;"

expect_ok reject_group "$core_db" \
    "UPDATE duplicate_groups
     SET review_state='rejected', updated_at_ms=23 WHERE id=1;"

expect_fail destructive_rechecks_group "$core_db" \
    "UPDATE operation_items
     SET state='in_progress', state_version=1, updated_at_ms=24 WHERE id=1;"

expect_ok approve_and_start "$core_db" \
    "UPDATE duplicate_groups
     SET review_state='approved', updated_at_ms=24 WHERE id=1;
     UPDATE operation_items
     SET state='in_progress', state_version=1, attempt_count=1,
         updated_at_ms=25 WHERE id=1;"

expect_fail applied_without_dual_result "$core_db" \
    "UPDATE operation_items
     SET state='applied', state_version=2, applied_at_ms=26, updated_at_ms=26
     WHERE id=1;"

expect_ok complete_dual_logged_item "$core_db" \
    "INSERT INTO volume_manifest_outbox (
        outbox_key, volume_id, operation_batch_id, operation_item_id,
        record_kind, sequence_number, target_volume_identity_key,
        target_mount_session_key, target_relative_path, sealed_plan_digest,
        record_payload, payload_digest, previous_record_digest, record_digest,
        local_recorded_at_ms, created_at_ms, updated_at_ms
     ) VALUES (
        'applied', 1, 1, 1, 'item_applied', 2, 'vol-1', 'mount-1',
        '.guiying/audit/batch-1.jsonl',
        x'9999999999999999999999999999999999999999999999999999999999999999',
        x'03', zeroblob(32),
        x'3030303030303030303030303030303030303030303030303030303030303030',
        x'4040404040404040404040404040404040404040404040404040404040404040',
        26, 26, 26
     );
     UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=1, target_offset_bytes=2,
         target_length_bytes=1, written_at_ms=27, updated_at_ms=27
     WHERE id=3;
     UPDATE volume_manifest_outbox
     SET delivery_state='fsynced', state_version=2, fsynced_at_ms=28,
         updated_at_ms=28 WHERE id=3;
     UPDATE volume_manifest_outbox
     SET delivery_state='verified', state_version=3, verified_at_ms=29,
         readback_digest=record_digest, updated_at_ms=29 WHERE id=3;
     UPDATE operation_items
     SET state='applied', state_version=2, applied_at_ms=30,
         updated_at_ms=30 WHERE id=1;
     UPDATE operation_items
     SET state='verifying', state_version=3, updated_at_ms=31 WHERE id=1;
     INSERT INTO volume_manifest_outbox (
        outbox_key, volume_id, operation_batch_id, operation_item_id,
        record_kind, sequence_number, target_volume_identity_key,
        target_mount_session_key, target_relative_path, sealed_plan_digest,
        record_payload, payload_digest, previous_record_digest, record_digest,
        local_recorded_at_ms, created_at_ms, updated_at_ms
     ) VALUES (
        'verified', 1, 1, 1, 'item_verified', 3, 'vol-1', 'mount-1',
        '.guiying/audit/batch-1.jsonl',
        x'9999999999999999999999999999999999999999999999999999999999999999',
        x'04', zeroblob(32),
        x'4040404040404040404040404040404040404040404040404040404040404040',
        x'5050505050505050505050505050505050505050505050505050505050505050',
        32, 32, 32
     );
     UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=1, target_offset_bytes=3,
         target_length_bytes=1, written_at_ms=33, updated_at_ms=33
     WHERE id=4;
     UPDATE volume_manifest_outbox
     SET delivery_state='fsynced', state_version=2, fsynced_at_ms=34,
         updated_at_ms=34 WHERE id=4;
     UPDATE volume_manifest_outbox
     SET delivery_state='verified', state_version=3, verified_at_ms=35,
         readback_digest=record_digest, updated_at_ms=35 WHERE id=4;
     UPDATE operation_items
     SET state='succeeded', state_version=4, verified_at_ms=36,
         finished_at_ms=36, updated_at_ms=36 WHERE id=1;
     UPDATE operation_batches
     SET state='completed', state_version=2, finished_at_ms=37,
         updated_at_ms=37 WHERE id=1;"

expect_value core_final_states "$core_db" \
    "SELECT batch.state || '/' || item.state
     FROM operation_batches AS batch
     JOIN operation_items AS item ON item.operation_batch_id=batch.id
     WHERE batch.id=1 AND item.id=1;" "completed/succeeded"
expect_value core_outbox_count "$core_db" \
    "SELECT count(*) FROM volume_manifest_outbox;" "4"
expect_value core_audit_event_count "$core_db" \
    "SELECT count(*) FROM operation_events;" "25"
expect_value core_integrity "$core_db" "PRAGMA integrity_check;" "ok"
expect_value core_foreign_keys "$core_db" "PRAGMA foreign_key_check;" ""

donor_db="$test_tmp_dir/donor.db"
sqlite3 "$donor_db" <<'SQL'
.bail on
.read src-tauri/migrations/0001_init.sql

INSERT INTO volumes (
    id, identity_key, identity_strength, filesystem_type, is_read_only,
    first_seen_at_ms, last_seen_at_ms, created_at_ms, updated_at_ms
) VALUES (1, 'vol-1', 'strong', 'apfs', 0, 1, 1, 1, 1);

INSERT INTO capability_profiles (
    id, volume_id, profile_hash, probe_mode, probe_status, observed_at_ms,
    os_build, can_read, can_write, is_current, created_at_ms
) VALUES (1, 1, zeroblob(32), 'active', 'complete', 1,
    'test', 1, 1, 1, 1);

INSERT INTO scan_runs (
    id, run_key, volume_id, capability_profile_id, root_relative_path,
    root_path_key, scan_mode, state, created_at_ms, updated_at_ms
) VALUES (1, 'scan', 1, 1, '', x'01', 'full', 'completed', 1, 1);

INSERT INTO media_files (
    id, volume_id, first_seen_scan_run_id, last_seen_scan_run_id,
    relative_path, path_key, media_kind, size_bytes, created_at_ms,
    updated_at_ms
) VALUES
    (1, 1, 1, 1, 'donor.jpg', x'01', 'photo', 10, 1, 1),
    (2, 1, 1, 1, 'keeper.jpg', x'02', 'photo', 10, 1, 1),
    (3, 1, 1, 1, 'target.jpg', x'03', 'photo', 10, 1, 1);

INSERT INTO fingerprints (
    id, volume_id, media_file_id, scan_run_id, fingerprint_kind,
    algorithm, algorithm_version, parameters_hash, source_signature, digest,
    observed_size_bytes, bytes_read, completed_at_ms, created_at_ms
) VALUES
    (1, 1, 1, 1, 'exact_bytes', 'blake3', 1, zeroblob(32),
        zeroblob(32), x'AA', 10, 10, 1, 1),
    (2, 1, 2, 1, 'exact_bytes', 'blake3', 1, zeroblob(32),
        x'0101010101010101010101010101010101010101010101010101010101010101',
        x'AA', 10, 10, 1, 1),
    (3, 1, 3, 1, 'exact_bytes', 'blake3', 1, zeroblob(32),
        x'0202020202020202020202020202020202020202020202020202020202020202',
        x'AA', 10, 10, 1, 1);

INSERT INTO duplicate_groups (
    id, volume_id, scan_run_id, group_key, match_kind, algorithm,
    algorithm_version, similarity_basis_points, confidence_basis_points,
    review_state, created_at_ms, updated_at_ms
) VALUES (1, 1, 1, zeroblob(32), 'exact_bytes', 'blake3', 1,
    10000, 10000, 'approved', 1, 1);

INSERT INTO duplicate_group_members (
    id, volume_id, duplicate_group_id, media_file_id,
    evidence_fingerprint_id, evidence_fingerprint_kind, member_role,
    created_at_ms
) VALUES
    (1, 1, 1, 1, 1, 'exact_bytes', 'candidate', 1),
    (2, 1, 1, 2, 2, 'exact_bytes', 'keeper', 1),
    (3, 1, 1, 3, 3, 'exact_bytes', 'candidate', 1);

INSERT INTO time_candidates (
    id, candidate_key, volume_id, media_file_id, scan_run_id,
    source_media_file_id, source_duplicate_group_id, source_kind, raw_value,
    raw_encoding, parse_status, wall_time, utc_offset_minutes, offset_kind,
    utc_instant_ns, precision_ns, precision_kind, confidence_basis_points,
    is_selected, normalized_at_ms, created_at_ms
) VALUES (
    1, zeroblob(32), 1, 3, 1, 1, 1, 'duplicate_peer', x'31', 'utf-8',
    'parsed', '2020-01-01T00:00:00', 480, 'embedded',
    1577808000000000000, 1000000000, 'exact', 10000, 1, 1, 1
);

INSERT INTO operation_batches (
    id, batch_key, volume_id, scan_run_id, capability_profile_id,
    operation_kind, requires_confirmation, confirmed_at_ms, created_at_ms,
    updated_at_ms
) VALUES
    (1, 'quarantine', 1, 1, 1, 'quarantine', 1, 1, 1, 1),
    (2, 'repair', 1, 1, 1, 'repair_time', 1, 1, 1, 1);

INSERT INTO operation_items (
    id, operation_batch_id, volume_id, item_key, media_file_id,
    keeper_media_file_id, duplicate_group_member_id,
    precondition_fingerprint_id, operation_kind,
    source_relative_path_snapshot, source_relative_path_raw,
    source_path_encoding, destination_relative_path,
    destination_relative_path_raw, destination_path_encoding,
    expected_size_bytes, expected_digest, created_at_ms, updated_at_ms
) VALUES (
    1, 1, 1, 'donor-quarantine', 1, 2, 1, 1, 'quarantine', 'donor.jpg',
    CAST('donor.jpg' AS BLOB), 'unix_bytes', '.guiying/q/donor.jpg',
    CAST('.guiying/q/donor.jpg' AS BLOB), 'unix_bytes', 10, x'AA', 1, 1
);

INSERT INTO operation_items (
    id, operation_batch_id, volume_id, item_key, media_file_id,
    time_candidate_id, precondition_fingerprint_id, operation_kind,
    source_relative_path_snapshot, source_relative_path_raw,
    source_path_encoding, expected_size_bytes, expected_digest,
    created_at_ms, updated_at_ms
) VALUES (
    2, 2, 1, 'target-repair', 3, 1, 3, 'repair_time', 'target.jpg',
    CAST('target.jpg' AS BLOB), 'unix_bytes', 10, x'AA', 1, 1
);
SQL

expect_fail seal_without_donor_dependency "$donor_db" \
    "UPDATE operation_batches
     SET sealed_at_ms=2,
         manifest_digest=
            x'9999999999999999999999999999999999999999999999999999999999999999',
         updated_at_ms=2
     WHERE id=1;"

expect_ok add_dependency_and_seal "$donor_db" \
    "INSERT INTO operation_item_dependencies (
        id, dependency_key, volume_id, dependent_operation_item_id,
        prerequisite_operation_item_id, time_candidate_id, dependency_kind,
        created_at_ms
     ) VALUES (1, 'dep-1', 1, 1, 2, 1, 'donor_time_preservation', 2);
     UPDATE operation_batches
     SET sealed_at_ms=2,
         manifest_digest=
            x'9999999999999999999999999999999999999999999999999999999999999999',
         updated_at_ms=2
     WHERE id=1;"

expect_fail dependency_no_update "$donor_db" \
    "UPDATE operation_item_dependencies SET dependency_key='changed' WHERE id=1;"
expect_fail dependency_no_delete "$donor_db" \
    "DELETE FROM operation_item_dependencies WHERE id=1;"

expect_ok prepare_donor_dual_log_gate "$donor_db" \
    "INSERT INTO volume_manifest_outbox (
        outbox_key, volume_id, operation_batch_id, record_kind,
        sequence_number, target_volume_identity_key, target_mount_session_key,
        target_relative_path, sealed_plan_digest, record_payload,
        payload_digest, record_digest, local_recorded_at_ms, created_at_ms,
        updated_at_ms
     ) VALUES (
        'batch', 1, 1, 'batch_manifest', 0, 'vol-1', 'mount-1',
        '.guiying/audit/donor.jsonl',
        x'9999999999999999999999999999999999999999999999999999999999999999',
        x'01', zeroblob(32),
        x'1010101010101010101010101010101010101010101010101010101010101010',
        3, 3, 3
     );
     UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=1, target_offset_bytes=0,
         target_length_bytes=1, written_at_ms=4, updated_at_ms=4 WHERE id=1;
     UPDATE volume_manifest_outbox
     SET delivery_state='fsynced', state_version=2, fsynced_at_ms=5,
         updated_at_ms=5 WHERE id=1;
     UPDATE volume_manifest_outbox
     SET delivery_state='verified', state_version=3, verified_at_ms=6,
         readback_digest=record_digest, updated_at_ms=6 WHERE id=1;
     UPDATE operation_batches
     SET volume_manifest_outbox_id=1, updated_at_ms=7 WHERE id=1;
     UPDATE operation_batches
     SET state='running', state_version=1, started_at_ms=8,
         updated_at_ms=8 WHERE id=1;
     INSERT INTO volume_manifest_outbox (
        outbox_key, volume_id, operation_batch_id, operation_item_id,
        record_kind, sequence_number, target_volume_identity_key,
        target_mount_session_key, target_relative_path, sealed_plan_digest,
        record_payload, payload_digest, previous_record_digest, record_digest,
        local_recorded_at_ms, created_at_ms, updated_at_ms
     ) VALUES (
        'intent', 1, 1, 1, 'item_intent', 1, 'vol-1', 'mount-1',
        '.guiying/audit/donor.jsonl',
        x'9999999999999999999999999999999999999999999999999999999999999999',
        x'02', zeroblob(32),
        x'1010101010101010101010101010101010101010101010101010101010101010',
        x'2020202020202020202020202020202020202020202020202020202020202020',
        9, 9, 9
     );
     UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=1, target_offset_bytes=1,
         target_length_bytes=1, written_at_ms=10, updated_at_ms=10 WHERE id=2;
     UPDATE volume_manifest_outbox
     SET delivery_state='fsynced', state_version=2, fsynced_at_ms=11,
         updated_at_ms=11 WHERE id=2;
     UPDATE volume_manifest_outbox
     SET delivery_state='verified', state_version=3, verified_at_ms=12,
         readback_digest=record_digest, updated_at_ms=12 WHERE id=2;
     UPDATE operation_items
     SET volume_intent_outbox_id=2, updated_at_ms=13 WHERE id=1;"

expect_fail donor_blocked_until_repair_succeeded "$donor_db" \
    "UPDATE operation_items
     SET state='in_progress', state_version=1, updated_at_ms=14 WHERE id=1;"

expect_ok complete_repair_and_release_donor "$donor_db" \
    "UPDATE operation_batches
     SET sealed_at_ms=20,
         manifest_digest=
            x'8888888888888888888888888888888888888888888888888888888888888888',
         updated_at_ms=20
     WHERE id=2;
     INSERT INTO volume_manifest_outbox (
        outbox_key, volume_id, operation_batch_id, record_kind,
        sequence_number, target_volume_identity_key, target_mount_session_key,
        target_relative_path, sealed_plan_digest, record_payload,
        payload_digest, record_digest, local_recorded_at_ms, created_at_ms,
        updated_at_ms
     ) VALUES (
        'repair-batch', 1, 2, 'batch_manifest', 0, 'vol-1', 'mount-1',
        '.guiying/audit/repair.jsonl',
        x'8888888888888888888888888888888888888888888888888888888888888888',
        x'11', zeroblob(32),
        x'6161616161616161616161616161616161616161616161616161616161616161',
        21, 21, 21
     );
     UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=1, target_offset_bytes=0,
         target_length_bytes=1, written_at_ms=22, updated_at_ms=22 WHERE id=3;
     UPDATE volume_manifest_outbox
     SET delivery_state='fsynced', state_version=2, fsynced_at_ms=23,
         updated_at_ms=23 WHERE id=3;
     UPDATE volume_manifest_outbox
     SET delivery_state='verified', state_version=3, verified_at_ms=24,
         readback_digest=record_digest, updated_at_ms=24 WHERE id=3;
     UPDATE operation_batches
     SET volume_manifest_outbox_id=3, updated_at_ms=25 WHERE id=2;
     UPDATE operation_batches
     SET state='running', state_version=1, started_at_ms=26,
         updated_at_ms=26 WHERE id=2;
     INSERT INTO volume_manifest_outbox (
        outbox_key, volume_id, operation_batch_id, operation_item_id,
        record_kind, sequence_number, target_volume_identity_key,
        target_mount_session_key, target_relative_path, sealed_plan_digest,
        record_payload, payload_digest, previous_record_digest, record_digest,
        local_recorded_at_ms, created_at_ms, updated_at_ms
     ) VALUES (
        'repair-intent', 1, 2, 2, 'item_intent', 1, 'vol-1', 'mount-1',
        '.guiying/audit/repair.jsonl',
        x'8888888888888888888888888888888888888888888888888888888888888888',
        x'12', zeroblob(32),
        x'6161616161616161616161616161616161616161616161616161616161616161',
        x'6262626262626262626262626262626262626262626262626262626262626262',
        27, 27, 27
     );
     UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=1, target_offset_bytes=1,
         target_length_bytes=1, written_at_ms=28, updated_at_ms=28 WHERE id=4;
     UPDATE volume_manifest_outbox
     SET delivery_state='fsynced', state_version=2, fsynced_at_ms=29,
         updated_at_ms=29 WHERE id=4;
     UPDATE volume_manifest_outbox
     SET delivery_state='verified', state_version=3, verified_at_ms=30,
         readback_digest=record_digest, updated_at_ms=30 WHERE id=4;
     UPDATE operation_items
     SET volume_intent_outbox_id=4, updated_at_ms=31 WHERE id=2;
     UPDATE operation_items
     SET state='in_progress', state_version=1, updated_at_ms=32 WHERE id=2;
     INSERT INTO volume_manifest_outbox (
        outbox_key, volume_id, operation_batch_id, operation_item_id,
        record_kind, sequence_number, target_volume_identity_key,
        target_mount_session_key, target_relative_path, sealed_plan_digest,
        record_payload, payload_digest, previous_record_digest, record_digest,
        local_recorded_at_ms, created_at_ms, updated_at_ms
     ) VALUES (
        'repair-applied', 1, 2, 2, 'item_applied', 2, 'vol-1', 'mount-1',
        '.guiying/audit/repair.jsonl',
        x'8888888888888888888888888888888888888888888888888888888888888888',
        x'13', zeroblob(32),
        x'6262626262626262626262626262626262626262626262626262626262626262',
        x'6363636363636363636363636363636363636363636363636363636363636363',
        33, 33, 33
     );
     UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=1, target_offset_bytes=2,
         target_length_bytes=1, written_at_ms=34, updated_at_ms=34 WHERE id=5;
     UPDATE volume_manifest_outbox
     SET delivery_state='fsynced', state_version=2, fsynced_at_ms=35,
         updated_at_ms=35 WHERE id=5;
     UPDATE volume_manifest_outbox
     SET delivery_state='verified', state_version=3, verified_at_ms=36,
         readback_digest=record_digest, updated_at_ms=36 WHERE id=5;
     UPDATE operation_items
     SET state='applied', state_version=2, applied_at_ms=37,
         updated_at_ms=37 WHERE id=2;
     UPDATE operation_items
     SET state='verifying', state_version=3, updated_at_ms=38 WHERE id=2;
     INSERT INTO volume_manifest_outbox (
        outbox_key, volume_id, operation_batch_id, operation_item_id,
        record_kind, sequence_number, target_volume_identity_key,
        target_mount_session_key, target_relative_path, sealed_plan_digest,
        record_payload, payload_digest, previous_record_digest, record_digest,
        local_recorded_at_ms, created_at_ms, updated_at_ms
     ) VALUES (
        'repair-verified', 1, 2, 2, 'item_verified', 3, 'vol-1', 'mount-1',
        '.guiying/audit/repair.jsonl',
        x'8888888888888888888888888888888888888888888888888888888888888888',
        x'14', zeroblob(32),
        x'6363636363636363636363636363636363636363636363636363636363636363',
        x'6464646464646464646464646464646464646464646464646464646464646464',
        39, 39, 39
     );
     UPDATE volume_manifest_outbox
     SET delivery_state='written', state_version=1, target_offset_bytes=3,
         target_length_bytes=1, written_at_ms=40, updated_at_ms=40 WHERE id=6;
     UPDATE volume_manifest_outbox
     SET delivery_state='fsynced', state_version=2, fsynced_at_ms=41,
         updated_at_ms=41 WHERE id=6;
     UPDATE volume_manifest_outbox
     SET delivery_state='verified', state_version=3, verified_at_ms=42,
         readback_digest=record_digest, updated_at_ms=42 WHERE id=6;
     UPDATE operation_items
     SET state='succeeded', state_version=4, verified_at_ms=43,
         finished_at_ms=43, updated_at_ms=43 WHERE id=2;
     UPDATE operation_batches
     SET state='completed', state_version=2, finished_at_ms=44,
         updated_at_ms=44 WHERE id=2;
     UPDATE operation_items
     SET state='in_progress', state_version=1, updated_at_ms=45 WHERE id=1;"

expect_value donor_dependency_states "$donor_db" \
    "SELECT prerequisite.state || '/' || dependent.state
     FROM operation_items AS prerequisite
     JOIN operation_item_dependencies AS dependency
       ON dependency.prerequisite_operation_item_id=prerequisite.id
     JOIN operation_items AS dependent
       ON dependent.id=dependency.dependent_operation_item_id
     WHERE dependency.id=1;" "succeeded/in_progress"

expect_value donor_integrity "$donor_db" "PRAGMA integrity_check;" "ok"
expect_value donor_foreign_keys "$donor_db" "PRAGMA foreign_key_check;" ""

if [ "$failures" -ne 0 ]; then
    echo "$failures sqlite migration check(s) failed" >&2
    exit 1
fi

echo "All SQLite migration checks passed."
