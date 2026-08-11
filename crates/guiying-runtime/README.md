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

The metadata/time boundary now has a current-session-only descriptor bridge and
a durable in-process Store adapter, but it is intentionally not an IPC proof
API. Only a Store record proving membership in a sealed byte-exact group may
create its private probe scope; a generic full-hash bucket is insufficient
because collision buckets are abandoned. For each group the bridge reserves at
most four probe descriptors and 32 MiB across both extraction passes, requires
a byte-for-byte identical second extraction, then revalidates the descriptor,
original path and mount session. The whole optional stage also has a checked
4 GiB byte ceiling and a proportional read-operation ceiling; cancellation is
checked before each page, group, probe, descriptor read and Store evidence
batch. Floating timestamps remain floating and filesystem birth/mtime are
never offered to the capture-time policy as automatic donor evidence.

The public `ActiveReadOnlyScan::analyze_capture_times` entry accepts only a
scan cancellation control. Runtime itself samples the UTC system clock once
and constructs the conservative policy with no reference wall time, so a
webview cannot self-report a policy, local timezone, source proof, path, donor,
or write capability. Its public result exposes only path-free status, bounded
failure codes, group counters, and read-budget counters through getters.

The post-D1 stage pages those guarded Store scopes only after exact coverage is
sealed and the duplicate result has completed, without caching the group set,
and hands each private proof, metadata report and policy analysis directly to an
in-process persistence adapter while the core and mount sessions are still
live. The adapter freezes canonical metadata and analysis manifests, writes in
bounded short transactions, and retains a no-usable-evidence analysis even when
a revalidated source has no supported timestamp field. Filesystem times stay on
a separate review timeline; unknown filesystem precision never becomes donor
eligibility, and the adapter deliberately persists no keeper or write
authorization. Cancellation or an adapter failure stops new media reads and
attempts to clean up any draft and seal the optional session partial. If that
cleanup itself fails, the remaining draft stays fail-closed and is reconciled
on the next writable Store reopen. It cannot unseal, alter or interrupt D1
duplicate evidence. Quarantine executors remain unavailable until their own
proof adapters and fault-injection gates are implemented.
