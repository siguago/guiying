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
  earlier `windows_wtf16le` label without changing bytes. Version 5 separates
  the stable volume namespace and job scope from each mount session. Every run
  is bound to a current capability profile, a canonical 32-byte mount-session
  key, the exact root bytes, and a root-object signature. Namespaces whose
  behavior is safe only for the current session persist that same authenticated
  mount key and cannot be reused by a later mount; cross-session namespaces
  must not carry one. Each observation must
  prove component-wise that its mount-relative path is the bound root followed
  by its root-relative path. UTF-8 raw bytes must exactly equal display text;
- `PathKey` is an opaque, bounded key accepted only through the filesystem
  adapter constructor. The store deliberately does not invent filesystem
  case/Unicode behavior: APFS, exFAT, NTFS, and SMB semantic key derivation is
  the probed volume adapter's responsibility. Version 5 evidence uses distinct
  fixed-size types for namespace, stable-path, root-scope, source-signature,
  parameter, build, manifest, and mount-session keys, preventing one key domain
  from being substituted for another;
- file, issue, and active-job reads use bounded keyset pages (`id > cursor`),
  never caller-controlled offsets or unbounded vectors. Page size is 1–256 and
  each returned page also has a 16 MiB aggregate byte budget. Checkpoint and
  report reads inspect SQLite lengths before materializing their JSON payloads.
  Version 5 observations, candidate buckets, exact fingerprints, verified
  duplicate groups, and group members have endpoint-specific versioned keyset
  cursors so a cursor cannot be silently reused with another query;
- progress advances only for a `running` run, is monotonic, and always keeps
  `fingerprinted_count <= discovered_count`. Checkpoints use optimistic
  versions, a versioned/bounded cursor, the same volume/run binding, and must
  exactly match already-persisted progress counts;
- version 5 jobs are stable, capability-independent namespace/root scopes. Each
  run adds immutable session evidence for its current capability and mount.
  A later attempt is allowed only for a recoverable, strong, cross-session
  namespace after the prior attempt is terminal; paused or running jobs cannot
  be replaced. Impossible active job/run state combinations are rejected by
  both the repository and schema triggers;
- job and run state changes are one coordinated repository operation. Both
  rows use optimistic `state_version` compare-and-swap counters, the ordering
  is chosen to satisfy immediate SQLite guards, and an internal savepoint
  prevents a caught half-transition from being committed. Error code/message
  evidence is required exactly for `failed` and `interrupted` runs. Every edge
  into `running` additionally compares the expected current capability profile
  and mount-session key and requires a complete, readable, canonical v2 probe;
- version 5 is the only API for creating new scan evidence. The legacy public
  mutators for job/run/file evidence, unguarded progress/checkpoints/issues,
  unguarded state transitions, and monolithic scan reports return
  `LegacyEvidenceApiDisabled` before writing. Version 4 rows remain historical
  migration input only and are never eligible as version 5 fingerprints or
  duplicate-group evidence. Version 5 progress, checkpoints, issues, immutable
  observation snapshots, and fresh per-run fingerprints require the typed
  capability/mount guard; batches contain at most 128 observations or
  fingerprints. Enumeration, sampling, full-hash, and exact-verification seals
  are ordered and immutable, and a run cannot become completed before the final
  seal exists;
- version 6 adds bounded process-local core tickets, directory observations,
  and a separate coverage outcome. A run that opts into this bridge cannot seal
  enumeration until every observation has its authenticated ticket, and cannot
  seal exact verification until both the core coverage seal and an independent
  volume-verification manifest are complete. Tickets remain opaque current-
  process evidence; reopening interrupts the run instead of treating them as
  reusable authority. Public version-6 mutators atomically bind the core
  session, pair each file observation with its ticket, record directory replay
  tickets, and persist the terminal coverage result. Any changed idempotent
  retry poisons and rolls back the whole write transaction. File and directory
  ticket pages use bounded keyset cursors and additionally require the current
  run, capability, mount-session, and core-session guards, so stale rows cannot
  be paged as live read authority after restart;
- filesystem timestamp precision is nullable in version 6. The nanosecond
  representation unit is stored separately from actual filesystem granularity,
  so an unknown APFS/exFAT/NTFS/SMB precision stays unknown and disables cache
  reuse instead of being guessed as one nanosecond. Stage seals and exact-group
  finalization must not predate their observations, fingerprints, comparisons,
  or coverage evidence. Bound issues may identify a media file only when that
  same run recorded its immutable observation;
- exact duplicate groups begin as drafts. The repository derives every member
  leaf from current database evidence, requires a full verification edge for
  each non-representative member, streams and recomputes the canonical manifest,
  uses checked reclaim arithmetic, and atomically changes the draft to
  `verified`. Read APIs expose verified groups only; no file operation is
  performed by this crate;
- the version 5 fingerprint and comparison DTOs are claims supplied by the
  trusted in-process runtime adapter, not opaque proof that this crate performed
  file I/O. This crate never opens media. These dormant APIs must not be exposed
  directly over IPC or used to authorize a file operation; a bad adapter could
  copy a historical hint back as if it had reread the source. Hints are only a
  fail-closed optimization, and pinned volume/root/file handles plus core-owned
  read proof remain a blocker for the execution phase;
- every writable reopen reconciles any old nonterminal scan session to an
  interrupted terminal state before new runtime work can resume. A worker from
  the previous process therefore cannot continue progress, checkpoints, issues,
  fingerprints, groups, or state transitions under a stale session guard;
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
token. Version 5's run-bound observation and verified-group pages are the
immutable evidence read surface. `list_files_page` remains a legacy latest-file
projection selected by `media_files.last_seen_scan_run_id`; callers must not
represent that projection as a complete historical terminal-run report.

The pathname checks bind the database to the same regular-file identity across
ordinary calls, but no portable `std`/SQLite API proves that an already-open
SQLite handle still names the pathname after a malicious same-UID rename swap.
Deployment therefore requires an app-private `0700` directory (or equivalent
Windows ACL), a fixed Tauri app-data path, and single-instance ownership. The
store does not claim protection from a hostile process running as the same OS
account. Any future media executor must independently revalidate volume and
file evidence; database-path identity is never authority to modify user media.
