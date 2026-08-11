# guiying-runtime

`guiying-runtime` is the trusted, read-only adapter between three deliberately
separate safety boundaries:

- `guiying-core` owns authenticated current-process scan tickets and actual
  sampled/full/exact reads;
- `guiying-volume` owns the selected-root descriptor, mount-session identity,
  mount-boundary checks, and lossless native paths;
- `guiying-store` owns normalized immutable evidence and fail-closed state
  transitions.

The runtime never moves, renames, removes, timestamps, or writes user media.
During enumeration it validates every core root, file, and directory against
the independently bound volume session before a short Store transaction can
persist the event batch. Filesystem I/O is never performed while a SQLite write
transaction is open.

The macOS runtime now also implements the first two read-only candidate stages:

1. sample only files in an enumeration-sealed duplicate-size bucket;
2. fully hash only files in a sampling-sealed collision bucket.

Before either core read starts, the adapter opens the same lossless locator
through the bound volume session and matches its stable path, physical file
identity, and size. After the core read, the held descriptor, original path,
and mount session are revalidated before the opaque core proof can be converted
to a Store input. Cancellation or any failed read leaves the stage unsealed and
closes the run fail-closed.

Directory-coverage finalization, byte-for-byte groups, metadata/time, and
quarantine executors remain unavailable until their own proof adapters and
fault-injection gates are implemented.
