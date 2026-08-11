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

Current scope is the authenticated enumeration bridge on macOS. Fingerprint,
exact-comparison, metadata/time, and quarantine executors remain unavailable
until their own proof adapters and fault-injection gates are implemented.
