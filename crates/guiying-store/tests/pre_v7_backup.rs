use std::fs;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;

use guiying_store::{Store, StoreError};
#[cfg(unix)]
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use tempfile::TempDir;

#[cfg(unix)]
const APPLICATION_ID: i32 = 0x4755_5949;
#[cfg(unix)]
const PRE_V7_PREFIX: &str = ".guiying-pre-v7-v6-";

#[cfg(unix)]
const MIGRATIONS: [(&str, &str); 6] = [
    (
        "initial_data_model",
        include_str!("../src/migrations/0001_init.sql"),
    ),
    (
        "store_runtime",
        include_str!("../src/migrations/0002_store_runtime.sql"),
    ),
    (
        "store_hardening",
        include_str!("../src/migrations/0003_store_hardening.sql"),
    ),
    (
        "evidence_binding",
        include_str!("../src/migrations/0004_evidence_binding.sql"),
    ),
    (
        "session_bound_evidence",
        include_str!("../src/migrations/0005_session_bound_evidence.sql"),
    ),
    (
        "runtime_stream_evidence",
        include_str!("../src/migrations/0006_runtime_stream_evidence.sql"),
    ),
];

#[cfg(unix)]
#[test]
fn v6_open_publishes_one_verified_pre_v7_snapshot_before_upgrade(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let private_parent = fs::canonicalize(temporary.path())?;
    let database = private_parent.join("managed-v6.sqlite3");
    create_empty_managed_v6(&database)?;

    let existing = private_parent.join(format!("{PRE_V7_PREFIX}existing.sqlite3"));
    let sentinel = b"existing snapshot name must never be overwritten";
    fs::write(&existing, sentinel)?;
    make_private(&existing)?;

    let store = Store::open_existing(&database)?;
    assert_eq!(store.schema_version()?, 7);
    store.close()?;

    let candidates = pre_v7_candidates(&private_parent)?;
    assert_eq!(
        candidates.len(),
        2,
        "expected sentinel plus one new snapshot"
    );
    assert_eq!(fs::read(&existing)?, sentinel);
    let snapshot = candidates
        .iter()
        .find(|path| path.as_path() != existing)
        .ok_or("pre-v7 snapshot missing")?;
    assert_pre_v7_snapshot(snapshot, 6)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(snapshot)?.mode() & 0o777, 0o600);
    }

    Store::open_existing(&database)?.close()?;
    assert_eq!(
        pre_v7_candidates(&private_parent)?,
        candidates,
        "opening an already-v7 database must not create another snapshot"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn every_supported_pre_v7_version_gets_an_exact_self_contained_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    for expected_version in 1_i64..=6 {
        let temporary = TempDir::new()?;
        let parent = fs::canonicalize(temporary.path())?;
        let database = parent.join(format!("managed-v{expected_version}.sqlite3"));
        create_empty_managed_version(&database, expected_version)?;

        Store::open_existing(&database)?.close()?;

        let prefix = format!(".guiying-pre-v7-v{expected_version}-");
        let snapshots = candidates_with_prefix(&parent, &prefix)?;
        assert_eq!(snapshots.len(), 1, "version {expected_version}");
        assert_pre_v7_snapshot(&snapshots[0], expected_version)?;
    }
    Ok(())
}

#[test]
fn destination_sidecar_sentinel_fails_closed_without_clobber(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let parent = fs::canonicalize(temporary.path())?;
    let database = parent.join("current.sqlite3");
    let destination = parent.join("manual-backup.sqlite3");
    let sentinel_path = family_path(&destination, "-wal");
    let sentinel = b"pre-existing destination WAL sentinel";
    let store = Store::open_or_create(database)?;
    fs::write(&sentinel_path, sentinel)?;
    make_private(&sentinel_path)?;

    let error = store
        .backup_to(&destination)
        .expect_err("a destination sidecar must block backup publication");

    assert!(matches!(
        error,
        StoreError::BackupDestinationFamilyExists(ref path) if path == &sentinel_path
    ));
    assert!(!destination.exists());
    assert_eq!(fs::read(&sentinel_path)?, sentinel);
    store.close()?;
    Ok(())
}

#[test]
fn destination_cannot_alias_any_source_family_member() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let parent = fs::canonicalize(temporary.path())?;
    let database = parent.join("current.sqlite3");
    let store = Store::open_or_create(&database)?;
    let destination = family_path(&database, "-wal");

    let error = store
        .backup_to(&destination)
        .expect_err("a source-family alias must be rejected");

    assert!(matches!(
        error,
        StoreError::BackupDestinationIsSourceFamily(ref path) if path == &destination
    ));
    store.close()?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn unknown_source_sidecar_fails_closed_before_sqlite_open() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let parent = fs::canonicalize(temporary.path())?;
    let database = parent.join("unknown-sidecar-v6.sqlite3");
    create_empty_managed_v6(&database)?;
    let before = fs::read(&database)?;
    let unknown = family_path(&database, "-mystery");
    let sentinel = b"unknown SQLite-family sentinel";
    fs::write(&unknown, sentinel)?;
    make_private(&unknown)?;

    let error = Store::open_existing(&database)
        .err()
        .ok_or("an unknown source sidecar unexpectedly opened")?;

    assert!(matches!(error, StoreError::PreV7SourceFamilyUnsafe { .. }));
    assert_eq!(fs::read(&database)?, before);
    assert_eq!(fs::read(&unknown)?, sentinel);
    assert!(pre_v7_candidates(&parent)?.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn simultaneous_wal_and_journal_fail_closed_before_sqlite_open(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let parent = fs::canonicalize(temporary.path())?;
    let database = parent.join("conflicting-sidecars-v6.sqlite3");
    create_empty_managed_v6(&database)?;
    let before = fs::read(&database)?;
    let wal = family_path(&database, "-wal");
    let journal = family_path(&database, "-journal");
    fs::write(&wal, b"WAL sentinel")?;
    fs::write(&journal, b"journal sentinel")?;
    make_private(&wal)?;
    make_private(&journal)?;

    let error = Store::open_existing(&database)
        .err()
        .ok_or("conflicting source sidecars unexpectedly opened")?;

    assert!(matches!(error, StoreError::PreV7SourceFamilyUnsafe { .. }));
    assert_eq!(fs::read(&database)?, before);
    assert_eq!(fs::read(&wal)?, b"WAL sentinel");
    assert_eq!(fs::read(&journal)?, b"journal sentinel");
    assert!(pre_v7_candidates(&parent)?.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn crash_wal_without_shm_is_recovered_into_the_snapshot() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TempDir::new()?;
    let parent = fs::canonicalize(temporary.path())?;
    let database = parent.join("wal-crash-v6.sqlite3");
    create_empty_managed_v6(&database)?;
    let detached_main = parent.join("detached-main.sqlite3");

    run_crash_fixture("wal", &database)?;

    let wal = family_path(&database, "-wal");
    let shm = family_path(&database, "-shm");
    assert!(wal.is_file(), "crash fixture must retain its WAL");
    assert!(fs::metadata(&wal)?.len() > 32);
    assert!(
        !shm.exists(),
        "the fixture intentionally omits disposable SHM"
    );
    fs::write(&detached_main, fs::read(&database)?)?;
    make_private(&detached_main)?;
    assert_eq!(migration_applied_at(&detached_main, 1)?, 1_001);

    Store::open_existing(&database)?.close()?;

    let snapshots = candidates_with_prefix(&parent, PRE_V7_PREFIX)?;
    assert_eq!(snapshots.len(), 1);
    assert_pre_v7_snapshot(&snapshots[0], 6)?;
    assert_eq!(migration_applied_at(&snapshots[0], 1)?, 424_242);
    assert_eq!(migration_applied_at(&database, 1)?, 424_242);
    Ok(())
}

#[cfg(unix)]
#[test]
fn hot_rollback_journal_is_recovered_only_on_the_isolated_clone(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let parent = fs::canonicalize(temporary.path())?;
    let database = parent.join("journal-crash-v6.sqlite3");
    create_empty_managed_v6(&database)?;
    let checksum_before = migration_checksum(&database, 1)?;

    run_crash_fixture("journal", &database)?;

    let journal = family_path(&database, "-journal");
    assert!(journal.is_file(), "crash fixture must retain its journal");
    assert!(fs::metadata(&journal)?.len() > 512);

    Store::open_existing(&database)?.close()?;

    let snapshots = candidates_with_prefix(&parent, PRE_V7_PREFIX)?;
    assert_eq!(snapshots.len(), 1);
    assert_pre_v7_snapshot(&snapshots[0], 6)?;
    assert_eq!(migration_checksum(&snapshots[0], 1)?, checksum_before);
    assert_eq!(migration_checksum(&database, 1)?, checksum_before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn pre_v7_crash_fixture_child() {
    let Ok(mode) = std::env::var("GUIYING_PRE_V7_CRASH_MODE") else {
        return;
    };
    let path = PathBuf::from(
        std::env::var_os("GUIYING_PRE_V7_CRASH_PATH")
            .expect("crash fixture database path must be provided"),
    );
    let connection = Connection::open(&path).expect("crash fixture must open");
    connection
        .pragma_update(None, "synchronous", "FULL")
        .expect("crash fixture must enable FULL sync");
    match mode.as_str() {
        "wal" => {
            let journal_mode: String = connection
                .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
                .expect("crash fixture must enter WAL mode");
            assert!(journal_mode.eq_ignore_ascii_case("wal"));
            connection
                .pragma_update(None, "wal_autocheckpoint", 0)
                .expect("crash fixture must disable auto-checkpoint");
            connection
                .execute_batch(
                    "BEGIN IMMEDIATE; \
                     UPDATE guiying_schema_migrations \
                     SET applied_at_ms = 424242 WHERE version = 1; \
                     COMMIT;",
                )
                .expect("WAL-only transaction must commit");
            assert_eq!(
                migration_applied_at_connection(&connection, 1)
                    .expect("WAL value must be readable"),
                424_242
            );
            let wal = family_path(&path, "-wal");
            assert!(fs::metadata(wal).expect("WAL must exist").len() > 32);
            let shm = family_path(&path, "-shm");
            if shm.exists() {
                fs::remove_file(&shm).expect("SHM must be removable before the simulated crash");
            }
            assert!(!shm.exists());
        }
        "journal" => {
            let journal_mode: String = connection
                .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
                .expect("crash fixture must enter rollback-journal mode");
            assert!(journal_mode.eq_ignore_ascii_case("delete"));
            connection
                .execute_batch(
                    "BEGIN IMMEDIATE; \
                     UPDATE guiying_schema_migrations \
                     SET checksum = zeroblob(32) WHERE version = 1;",
                )
                .expect("rollback-journal transaction must start");
            connection
                .cache_flush()
                .expect("dirty database pages must reach the main file");
            let journal = family_path(&path, "-journal");
            assert!(
                fs::metadata(journal)
                    .expect("rollback journal must exist")
                    .len()
                    > 512
            );
        }
        other => panic!("unknown crash fixture mode: {other}"),
    }
    std::process::abort();
}

#[cfg(unix)]
fn assert_pre_v7_snapshot(
    path: &Path,
    expected_version: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let header = fs::read(path)?;
    assert!(header.len() >= 20);
    assert_eq!(
        &header[18..20],
        &[1, 1],
        "published snapshot must use a self-contained rollback journal header"
    );
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(path, flags)?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let migration_count: i64 = connection.query_row(
        "SELECT count(*) FROM guiying_schema_migrations",
        [],
        |row| row.get(0),
    )?;
    let v7_table_count: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'scan_time_sessions'",
        [],
        |row| row.get(0),
    )?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let foreign_key_violations: i64 =
        connection.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    assert_eq!(version, expected_version);
    assert_eq!(application_id, i64::from(APPLICATION_ID));
    assert_eq!(migration_count, expected_version);
    assert_eq!(v7_table_count, 0);
    assert_eq!(integrity, "ok");
    assert_eq!(foreign_key_violations, 0);
    Ok(())
}

#[cfg(unix)]
fn pre_v7_candidates(parent: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    candidates_with_prefix(parent, PRE_V7_PREFIX)
}

#[cfg(unix)]
fn candidates_with_prefix(
    parent: &Path,
    prefix: &str,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut paths = fs::read_dir(parent)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn family_path(database: &Path, suffix: &str) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

#[cfg(unix)]
fn run_crash_fixture(mode: &str, database: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("pre_v7_crash_fixture_child")
        .arg("--nocapture")
        .env("GUIYING_PRE_V7_CRASH_MODE", mode)
        .env("GUIYING_PRE_V7_CRASH_PATH", database)
        .status()?;
    assert!(!status.success(), "crash fixture exited cleanly");
    Ok(())
}

#[cfg(unix)]
fn migration_applied_at(path: &Path, version: i64) -> rusqlite::Result<i64> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    migration_applied_at_connection(&connection, version)
}

#[cfg(unix)]
fn migration_applied_at_connection(connection: &Connection, version: i64) -> rusqlite::Result<i64> {
    connection.query_row(
        "SELECT applied_at_ms FROM guiying_schema_migrations WHERE version = ?1",
        [version],
        |row| row.get(0),
    )
}

#[cfg(unix)]
fn migration_checksum(path: &Path, version: i64) -> rusqlite::Result<Vec<u8>> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.query_row(
        "SELECT checksum FROM guiying_schema_migrations WHERE version = ?1",
        [version],
        |row| row.get(0),
    )
}

#[cfg(unix)]
fn create_empty_managed_v6(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    create_empty_managed_version(path, 6)
}

#[cfg(unix)]
fn create_empty_managed_version(
    path: &Path,
    target_version: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = Connection::open(path)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    for (index, (name, sql)) in MIGRATIONS.iter().enumerate() {
        let version = i64::try_from(index)? + 1;
        if version > target_version {
            break;
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if version == 1 {
            transaction.execute_batch(
                r#"CREATE TABLE guiying_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    checksum BLOB NOT NULL CHECK (length(checksum) = 32),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
) STRICT;"#,
            )?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        }
        let body = if version == 1 {
            strip_initial_transaction(sql)?
        } else {
            sql
        };
        transaction.execute_batch(body)?;
        let checksum = blake3::hash(sql.as_bytes());
        transaction.execute(
            "INSERT INTO guiying_schema_migrations (version, name, checksum, applied_at_ms) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                version,
                name,
                checksum.as_bytes().as_slice(),
                1_000 + version
            ],
        )?;
        transaction.pragma_update(None, "user_version", version)?;
        transaction.commit()?;
    }
    connection.close().map_err(|(_, error)| error)?;
    make_private(path)?;
    Ok(())
}

#[cfg(unix)]
fn strip_initial_transaction(sql: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let begin = sql
        .find("BEGIN IMMEDIATE;\n")
        .ok_or("initial migration is missing BEGIN IMMEDIATE")?
        + "BEGIN IMMEDIATE;\n".len();
    let commit = sql
        .rfind("COMMIT;")
        .ok_or("initial migration is missing COMMIT")?;
    Ok(&sql[begin..commit])
}

#[cfg(unix)]
fn make_private(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_private(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
