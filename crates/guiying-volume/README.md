# `guiying-volume`

This crate is Guiying's read-only trust boundary for a selected filesystem
root. It does not expose create, rename, timestamp, remove, raw-descriptor, or
target-volume write APIs.

## Guarantees

- On macOS, binding opens every component of the absolute selected root with
  `O_DIRECTORY | O_NOFOLLOW`. Ancestor symlinks, including compatibility
  spellings such as `/var` and `/tmp`, are rejected; callers must provide the
  canonical no-symlink spelling. The descriptor is observed twice for object,
  mount, UUID, and read-only format evidence before binding succeeds.
- `F_GETPATH_NOFIRMLINK` supplies the descriptor's exact no-firmlink path. The
  implementation validates its byte/component budgets, strips the mount point
  only at a component boundary, reopens the current mount point from `/`, and
  traverses the selected root again component-by-component without following
  links. Every revalidation repeats that fresh global mount-point traversal;
  pinned descriptors alone are never treated as proof that an unmounted or
  replaced filesystem is still current.
- A stable native UUID creates a `Strong` volume identity. Missing UUIDs create
  an explicitly `Weak` observation identity. Every bind also receives a fresh,
  independently random `mount_session_key`, even for the same currently mounted
  volume. The stable `PathSemanticsProfile` key never contains that session
  nonce: it is derived from the volume identity and observed native path
  semantics. `cross_session` requires a `Strong` identity plus fully known,
  internally consistent case behavior and fully known Unicode normalization.
  `fresh_attempt_only` requires the same strong identity and known, internally
  consistent case behavior but permits Unicode normalization to remain
  `Unknown`. It allows only a fresh, full child lineage after independently
  matching the same logical filesystem UUID and exact native selected-root
  bytes. It does not prove the same physical medium or directory object,
  establish Unicode/case alias equivalence, reuse a fingerprint hint, open a
  file, or continue a persisted cursor. Weak identity or unknown/contradictory
  case behavior remains `current_session_only`. A UUID by itself never
  authorizes access or a write.
- The selected root is exposed as lossless mount-relative bytes, a versioned
  stable root path key, and a domain-separated `RootScopeKey`. The root scope
  includes the stable volume identity, namespace profile, native encoding, and
  exact mount-relative selected-root bytes. It is stable for the same root
  across binds, differs for distinct roots, and never substitutes for a live
  mount session.
- Write capability fields remain `None`. Filesystem names and mount flags are
  observations, never permission to write.
- Relative files are opened from the root descriptor one component at a time.
  Every component uses no-follow semantics; non-regular final objects and
  nested mount boundaries are rejected. Every opened ancestor and final file
  descriptor must match the root's `st_dev`, `f_fsid`, mount point/source,
  filesystem name and numeric type/subtype, mount flags/extended flags, and
  mount owner.
- `BoundVolumeSession::relative_path` returns a `BoundMediaPath` containing a
  non-serializable `RootRelativePath` locator bound to the exact live mount
  session and a `MountRelativePath` stable namespace address. This binding is
  required for every identity/scope, including `fresh_attempt_only` and
  `cross_session`. `open_regular_file` and `verify_directory` accept only
  `BoundMediaPath`;
  persisted or caller-constructed `MountRelativePath` values are untrusted
  evidence and can never be passed to an open API.
- `ReadOnlyFile::verify_unchanged` first rejects a different mount-session key,
  then checks the original descriptor, safely
  reopens the exact lossless path, and revalidates the mount session. This is a
  metadata stability check; callers still need a full content hash for content
  proof.
- `verify_directory` similarly performs two nofollow reopens with complete
  mount-signature checks and returns only `RootObjectIdentity`; no directory or
  raw descriptor escapes the crate.
- Native bytes/code units are retained exactly. Display text is never used for
  addressing. The stable path key uses the complete path relative to the real
  mount root, so equal suffixes under different selected roots do not collide,
  while overlapping roots produce the same key for the same physical path.
- Profile and path algorithms are version 2. Public version-1 constants exist
  only to identify preserved historical records; this crate exposes no legacy
  constructor that can turn version-1 session-bound evidence into an open
  capability. Fixed old/new hash vectors protect the migration boundary.
- Hard limits are 64 KiB per relative path, 1,024 components, and 16 KiB per
  component. Absolute paths, NUL, empty components, `.`/`..`, Windows ADS/drive
  syntax, reserved devices, and ambiguous Windows names are rejected before
  filesystem access.
- Every serialized `u64` filesystem observation is emitted as a decimal string
  so a future JSON/JavaScript IPC boundary cannot silently round identifiers,
  sizes, counters, mount flags, or a known timestamp granularity. Cryptographic
  keys are fixed 64-character lowercase hexadecimal strings.

## Platform boundary

macOS uses `open`/`openat`, `fstat`, `fstatfs`, and `fgetattrlist` through
`rustix`/`libc`. It never launches `diskutil`, a shell, or another process.
Linux and Windows return `UnsupportedPlatform` for volume binding rather than
guessing identity or capabilities. `PathSemanticsProfile::conservative_offline`
still permits bounded Unix-byte or Windows-UTF-16 path import validation, but
such a profile cannot authorize a bound file open.

The two narrowly wrapped unsafe calls are macOS `fgetattrlist` and
`fcntl(F_GETPATH_NOFIRMLINK)`. Both use fixed-size buffers, retain descriptor
borrows for the calls, validate termination/returned lengths, and independently
rebind the resulting path before it becomes trusted evidence.

## Deliberate limitations

- A weak identity, or any profile with unknown/contradictory case evidence, is
  suitable for a current-session read-only scan observation, not automatic
  reuse after rebinding. Unknown Unicode normalization on a strong identity
  with known case behavior permits only `fresh_attempt_only`, never broader
  cross-session reuse.
- Unicode normalization behavior remains `Unknown`; the current key strategy
  hashes exact native bytes. A fresh attempt must rebuild full child evidence
  from exact native root/path bytes; it never guesses equivalence from a
  filesystem name.
- macOS currently supplies no reliable read-only observation of actual
  filesystem timestamp precision, so `timestamp_granularity_ns` is `None`.
  `*_nanoseconds` stat fields preserve returned values but do not imply one-
  nanosecond filesystem granularity; unknown precision must never enable cache
  reuse.
- The Unix-byte validator and namespace composition preserve non-UTF-8 bytes.
  APFS on the test host rejects creating invalid-UTF-8 names with `EILSEQ`, so
  no test fabricates a successful macOS open for a name the filesystem itself
  refuses. Byte-level strip/composition/serialization paths are still covered.
- macOS has no generally applicable no-atime open flag. Reading may therefore
  update access-time metadata according to the mounted filesystem's policy.
- This crate proves no write durability capability. A future write/probe layer
  must be separate, explicitly authorized, mount-session-bound, and tested on
  the actual filesystem/driver combination.

## Validation

From this directory, or with `--manifest-path crates/guiying-volume/Cargo.toml`:

```sh
cargo +1.77.2 check --locked --all-targets
cargo +1.77.2 test --locked --all-targets
cargo +1.77.2 clippy --fix --allow-dirty --allow-staged
cargo +1.77.2 clippy --locked --all-targets -- -D warnings
cargo +1.77.2 fmt --check
cargo +1.77.2 check --locked --target x86_64-pc-windows-msvc --all-targets
cargo +1.77.2 clippy --locked --target x86_64-pc-windows-msvc --all-targets -- -D warnings
```
