# guiying-store

`guiying-store` is Guiying's local SQLite persistence boundary. It stores scan
jobs, immutable scan evidence, file observations, issues, reports, and the
existing safety/audit model. It does **not** open or mutate user media files.

Safety properties:

- database paths are supplied by the caller and must be absolute;
- the normal open/create API never creates parent directories implicitly;
- the complete v1 migration is packaged inside this crate; packaged builds do
  not depend on a sibling `src-tauri` source tree;
- an existing file is first opened read-only with `SQLITE_OPEN_NOFOLLOW` and is
  checked for application id, supported version, contiguous/checksummed
  migration registry, `quick_check`, foreign keys, and its actual
  `sqlite_schema`; only then is it reopened read-write. The read-write handle
  repeats the preflight before WAL or migrations can change the file;
- the schema manifest hashes every explicit application table, index, and
  trigger against a schema compiled from the embedded migrations. Added,
  removed, or edited safety triggers therefore fail closed even if a migration
  registry row was copied or forged. Object count and SQL size are bounded;
- on Unix, existing database files must be owner-readable/writable with no
  group/world permission bits, must share an owner with their parent, and the
  parent must not be group/world writable. New files are mode `0600`; parents
  created explicitly by this crate are mode `0700`. On Windows, Rust's standard
  library has no complete ACL ownership check, so callers must place the DB in
  the per-user application-data directory with an OS ACL; regular-file and
  `SQLITE_OPEN_NOFOLLOW` checks still apply;
- every connection enforces and reads back foreign keys, a 5-second busy
  timeout, `synchronous=FULL`, WAL mode, and `trusted_schema=OFF`;
- SQLite defensive mode is enabled and double-quoted string literals are
  disabled;
- migrations are atomic and registered with a BLAKE3 checksum, application id,
  and `user_version`; unknown, missing, reordered, or modified history fails
  closed;
- opening runs `quick_check` plus `foreign_key_check`; a public full integrity
  check is available;
- backups use SQLite's online Backup API, are written to a private temporary
  file, fully checked and synced, and are published with no-clobber rename.
  Busy retries, total step count, and wall-clock duration are all bounded. The
  wall-clock deadline is checked between 128-page backup steps and every
  validation/sync phase; an individual blocking OS call cannot be preempted,
  but an over-deadline operation is aborted before publication. On
  Unix, both file content and the destination directory entry are synced. On
  platforms where directory handles cannot be synced through `std`, file
  content is synced but post-crash directory-entry durability remains an OS
  guarantee/best effort rather than a claim made by this crate;
- backup parent and temporary-file identities are rechecked before publish. A
  pathname can still be swapped after the final check on platforms without a
  descriptor-relative no-clobber rename API, so backup destinations must also
  live in an application-private, non-writable-by-others directory. Any
  detected mismatch aborts; an existing destination is never replaced;
- repository writes are short `BEGIN IMMEDIATE` transactions. Filesystem and
  hashing work must happen before entering the callback. If any public
  repository mutator returns an error, the repository is poisoned: even when
  the callback catches that error and returns success, `write_transaction`
  rejects the commit and SQLite rolls back the entire transaction;
- repository input identifiers, display text, raw paths, opaque blobs, and
  serialized JSON are all hard-bounded before persistence. Reports have their
  separate 16 MiB ceiling; ordinary JSON and opaque evidence are capped at
  1 MiB, paths at 64 KiB, and semantic keys at 4 KiB;
- strong volume identifiers are immutable and cannot alias another identity
  key. The only identifier fill operation is an explicit weak-to-strong
  upgrade into previously empty strong-ID fields. Capability snapshots are
  immutable except for the `is_current` selector and cannot be deleted;
- capability hashes are computed internally from a version-2 canonical JSON
  payload and re-derived on every open. Its recursive encoder sorts object keys
  by UTF-8 bytes and uses explicit type and length domains, independent of
  `serde_json` map-order features. The payload covers the mount session,
  probe protocol, driver/mount facts, case and Unicode behavior, path-semantics
  version, rename/no-replace behavior, directory sync, append durability,
  single-writer status, timestamps, hard-link/clone support, size limits, and
  raw probe result. Unknown probe results remain SQL `NULL`. A hash hit is
  field-by-field checked before reuse. Legacy v1 fields that were not covered
  by the old digest are migrated as `NULL`, never re-signed as trusted facts;
- exact path bytes plus canonical `utf8`, `unix_bytes`, or
  `windows_utf16_le` encoding are persisted separately from display text, so
  non-UTF-8 Unix and WTF-16 Windows names are not lossy. Version 3 migrates the
  earlier `windows_wtf16le` label without changing bytes. Version 4 also binds
  job/run root bytes and every media-path observation to the exact capability
  profile and path-semantics version that produced its semantic key. UTF-8 raw
  bytes must exactly equal the display path;
- `PathKey` is an opaque, bounded key accepted only through the filesystem
  adapter constructor. The store deliberately does not invent filesystem
  case/Unicode behavior: APFS, exFAT, NTFS, and SMB semantic key derivation is
  the probed volume adapter's responsibility;
- file, issue, and active-job reads use bounded keyset pages (`id > cursor`),
  never caller-controlled offsets or unbounded vectors. Page size is 1–256 and
  each returned page also has a 16 MiB aggregate byte budget. Checkpoint and
  report reads inspect SQLite lengths before materializing their JSON payloads;
- progress advances only for a `running` run, is monotonic, and always keeps
  `fingerprinted_count <= discovered_count`. Checkpoints use optimistic
  versions, a versioned/bounded cursor, the same volume/run binding, and must
  exactly match already-persisted progress counts;
- job/run bindings require identical volume-relative root text, raw bytes,
  encoding, semantic key, capability profile, and semantics version. Root and
  binding evidence is immutable, active-run replacement is limited to a
  failed/interrupted attempt, and impossible active job/run state combinations
  are rejected by both the repository and schema triggers;
- job and run state changes are one coordinated repository operation. Both
  rows use optimistic `state_version` compare-and-swap counters, the ordering
  is chosen to satisfy immediate SQLite guards, and an internal savepoint
  prevents a caught half-transition from being committed. Error code/message
  evidence is required exactly for `failed` and `interrupted` runs. Every edge
  into `running` additionally compares the expected current capability profile
  and mount-session key and requires a complete, readable, canonical v2 probe;
- version 4 creates immutable per-run media observations. A semantic path key
  from one capability profile or semantics version can never overwrite the
  current record created under another profile/version; the legacy
  `media_files.path_key` slot is now an internal domain-separated storage key.
  New observations are accepted only while that run is `running` and its
  capability profile is still current, so paused and terminal evidence is
  sealed;
- full report JSON is capped at 16 MiB. Large per-file or per-group result sets
  belong in normalized paginated tables rather than one report blob;
- all crate tests use `tempfile::TempDir` and never point at user media.

The operation-plan/outbox tables inherited from migration v1 are dormant,
untrusted compatibility schema. This crate exposes no public operation API and
no executor may consume, seal, or start those rows. M2 must first make batch
seal mutations and the item manifest deterministic, reject keeper-target
cycles/chains that could leave no survivor, and bind every outbox item to the
batch's current volume identity, canonical capability profile, and mount
session with an execution-time re-probe.

Keyset cursors provide a bounded continuation point, not a snapshot-isolation
token. `list_files_page` is currently the latest-file projection selected by
`media_files.last_seen_scan_run_id`; it is not a historical terminal-run export.
The immutable observation rows preserve the normalized evidence, but a public
paginated observation/export API remains an M2 deliverable. Until then, callers
must not represent the current-view page API as a complete historical report.

The pathname checks bind the database to the same regular-file identity across
ordinary calls, but no portable `std`/SQLite API proves that an already-open
SQLite handle still names the pathname after a malicious same-UID rename swap.
Deployment therefore requires an app-private `0700` directory (or equivalent
Windows ACL), a fixed Tauri app-data path, and single-instance ownership. The
store does not claim protection from a hostile process running as the same OS
account. Any future media executor must independently revalidate volume and
file evidence; database-path identity is never authority to modify user media.
