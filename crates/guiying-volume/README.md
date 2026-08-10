# `guiying-volume`

This crate is Guiying's read-only trust boundary for a selected filesystem
root. It does not expose create, rename, timestamp, remove, raw-descriptor, or
target-volume write APIs.

## Guarantees

- On macOS, binding opens the absolute root with `O_DIRECTORY | O_NOFOLLOW`,
  records `st_dev`/inode, obtains mount point, mount source, filesystem type,
  flags, capacity, and optional native UUID/capabilities from descriptor-based
  system APIs, then repeats the observations before returning.
- The original path is reopened and compared with the bound root descriptor on
  every session revalidation. Replacing a same-name directory does not reuse
  the binding.
- A stable native UUID creates a `Strong` volume identity. Missing UUIDs create
  an explicitly `Weak` observation identity. Every bind also receives a fresh,
  independently random `mount_session_key`, even for the same currently mounted
  volume. `Strong` means stronger identity evidence only: a UUID by itself
  never authorizes a write or destructive action. Such actions still require a
  current matching mount session, proven capabilities, a sealed plan, and the
  independent safety gates outside this read-only crate.
- Write capability fields remain `None`. Filesystem names and mount flags are
  observations, never permission to write.
- Relative files are opened from the root descriptor one component at a time.
  Every component uses no-follow semantics; non-regular final objects and
  nested mount boundaries are rejected. Every opened ancestor and final file
  descriptor must match the root's `st_dev`, `f_fsid`, mount point/source,
  filesystem name and numeric type/subtype, mount flags/extended flags, and
  mount owner.
- `ReadOnlyFile::verify_unchanged` checks the original descriptor, safely
  reopens the exact lossless path, and revalidates the mount session. This is a
  metadata stability check; callers still need a full content hash for content
  proof.
- `LosslessRelativePath` retains native bytes/code units. Display text is never
  used for addressing. Encoding, raw value, path key, and a versioned
  `PathSemanticsProfile` key are cryptographically bound together.
- Hard limits are 64 KiB per relative path, 1,024 components, and 16 KiB per
  component. Absolute paths, NUL, empty components, `.`/`..`, Windows ADS/drive
  syntax, reserved devices, and ambiguous Windows names are rejected before
  filesystem access.
- Every serialized `u64` filesystem observation is emitted as a decimal string
  so a future JSON/JavaScript IPC boundary cannot silently round identifiers,
  sizes, counters, or mount flags.

## Platform boundary

macOS uses `open`/`openat`, `fstat`, `fstatfs`, and `fgetattrlist` through
`rustix`/`libc`. It never launches `diskutil`, a shell, or another process.
Linux and Windows return `UnsupportedPlatform` for volume binding rather than
guessing identity or capabilities. `PathSemanticsProfile::conservative_offline`
still permits bounded Unix-byte or Windows-UTF-16 path import validation, but
such a profile cannot authorize a bound file open.

The one unsafe block is the narrowly wrapped macOS `fgetattrlist` FFI call. It
uses fixed-size buffers, checks the kernel-reported length before decoding, and
treats unavailable optional attributes as unknown.

## Deliberate limitations

- A weak identity is suitable for a read-only scan observation, not automatic
  reuse of a destructive plan after rebinding.
- Unicode normalization behavior remains `Unknown`; the current key strategy
  hashes exact native bytes. It never guesses equivalence from a filesystem
  name.
- macOS has no generally applicable no-atime open flag. Reading may therefore
  update access-time metadata according to the mounted filesystem's policy.
- This crate proves no write durability capability. A future write/probe layer
  must be separate, explicitly authorized, mount-session-bound, and tested on
  the actual filesystem/driver combination.

## Validation

From this directory, or with `--manifest-path crates/guiying-volume/Cargo.toml`:

```sh
cargo +1.77.2 check --all-targets
cargo +1.77.2 test --all-targets
cargo +1.77.2 clippy --fix --allow-dirty --allow-staged
cargo +1.77.2 clippy --all-targets -- -D warnings
cargo +1.77.2 fmt --check
cargo check --target x86_64-pc-windows-msvc --all-targets
cargo clippy --target x86_64-pc-windows-msvc --all-targets -- -D warnings
```
