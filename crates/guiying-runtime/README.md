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

The macOS runtime now implements the complete read-only D1 evidence pipeline:

1. sample only files in an enumeration-sealed duplicate-size bucket;
2. fully hash only files in a sampling-sealed collision bucket;
3. compare every full-hash candidate byte-for-byte through authenticated core
   tickets and independently held volume descriptors;
4. build bounded, invisible Store drafts and publish a group only when every
   member, comparison edge, source signature, digest, and manifest agrees;
5. replay every directory ticket in canonical order, bracketed by the current
   volume mount, then seal the exact stage and complete the run.

Before either core read starts, the adapter opens the same lossless locator
through the bound volume session and matches its stable path, physical file
identity, and size. After the core read, the held descriptor, original path,
and mount session are revalidated before the opaque core proof can be converted
to a Store input. Cancellation or any failed read leaves the stage unsealed and
closes the run fail-closed.

Complete coverage requires both the core directory-set digest and a separate
volume manifest derived from lossless directory locators, object identities,
root scope, and mount session. Partial enumeration, a changed directory, a
changed root, cancellation, or a mismatched count cannot unlock exact groups.
Coverage intentionally runs after all file reads so it brackets the entire
analysis. A cryptographic hash collision abandons that whole hash bucket rather
than guessing at a subgroup; other verified buckets can still complete.

Metadata/time and quarantine executors remain unavailable until their own proof
adapters and fault-injection gates are implemented.
