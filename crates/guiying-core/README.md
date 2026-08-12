# guiying-core

`guiying-core` is the read-only duplicate-scanning engine for 归影. It exposes
no move, rename, timestamp-write, quarantine, or delete API.

## Bounded persistent-runtime API

The legacy `Scanner::scan` and `Scanner::scan_with_control` report APIs remain
available for small compatibility workloads. Production persistence should use
`Scanner::start_streaming` and `StreamingScanSession`:

1. `enumerate` emits root evidence, lossless file/directory observations,
   issues, and progress to a synchronous `StreamingScanSink`. Directory
   identities (device, inode) are de-duplicated globally across the whole
   session, exactly like the batch scanner: a repeated identity (aliased
   root, alias, or mount loop) is skipped with a
   `DirectoryIdentityAlreadyVisited` issue and keeps the enumeration and any
   later coverage decision `Partial`.
2. The sink persists opaque file and directory tickets. A callback must return
   only after accepting the complete batch; a sink error poisons the session.
3. Candidate selection happens in durable storage. At most 128 authenticated
   file tickets are returned to `sample_batch` or `full_hash_batch` at a time.
4. At most 128 authenticated pairs are returned to `exact_compare_batch`.
5. Directory tickets are read back in strictly increasing `sort_key` order and
   passed to `revalidate_directory_batch`. `finalize_coverage` refuses a seal
   unless the exact enumerated ticket set was replayed once and selected roots
   match their original descriptor-bound observations when revalidated. This
   local match remains subject to the independent volume bracketing below.

Event batches have independent count and estimated-byte limits. The hard caps
are 128 events and 1 MiB; caller-provided stage batches are also capped at 128.
Directory entries are consumed one at a time. Core memory is therefore bounded
by configured path depth, one-file read buffers, and one event batch rather
than the total number of photos.

Every file and directory observation contains its original `root_index` and a
lossless root-relative `PathRef`. The relative value is created directly from
the validated native components (the selected root itself is the empty path);
it is never inferred by stripping an absolute display string. This keeps equal
suffixes under different selected roots distinct. Observation fields also
carry size, allocated size when available, device/inode, generation, mode,
link count, and nanosecond birth/modified/change times. Timestamp granularity,
sparse state, and sharing/clone state remain unknown unless a volume adapter
can prove them. Observed access time is informational and is excluded from
stable identity because read-only scanning itself may update atime.

The sink is deliberately synchronous. This is the backpressure mechanism: no
new filesystem read begins while durable storage is still handling the current
batch. Cooperative cancellation is checked between reads and sink calls; it
cannot interrupt a filesystem call or a sink callback that has not returned.

## Fresh evidence and trust boundary

Tickets are canonical native-component locators authenticated by a random
per-session key. Their bytes may be stored, but they cannot be modified,
fabricated, replayed in another session, or used after the live root descriptors
are gone. A ticket is not a durable filesystem capability.

Fresh fingerprint and exact-comparison evidence has no public constructor. It
is created only after root-anchored, component-by-component `openat`/nofollow
reads and records:

- live session ID and authenticated observation ticket ID;
- read origin, algorithm/version, and parameters hash;
- expected length, actual bytes read, and EOF verification;
- before and after source signatures;
- raw digest bytes; and
- for exact comparisons, both sides and the exact compared byte count.

The observation source signature binds the session, original root index,
lossless root-relative raw path, and all stable snapshot identity fields. The
same signature is authenticated inside its ticket and must equal both the
before and after signature in successful fresh-read evidence.

Callers never submit a digest, byte count, EOF flag, or source signature as
fresh proof. A changed object, short read, extra byte, invalid ticket,
cancellation, or sink failure cannot mint evidence.

Core evidence intentionally reports `CurrentCoreSessionOnly`. It does **not**
establish a stable volume identity or a durable mount session. On macOS,
`StreamRootObservation` exposes device, inode, generation, mode, ctime, and the
complete core source signature from the actually bound root descriptor. The
runtime must compare those fields with the active `guiying-volume`
`BoundVolumeSession` and add its capability/mount/root-scope proof before a
store adapter accepts the evidence as v5 fresh evidence. Missing or mismatched
volume evidence must fail closed.

Matching the selected root identity is necessary but not sufficient. Core's
`stay_on_filesystem` check uses the object device ID, which cannot distinguish
every same-device descendant or bind mount. The runtime must therefore ask the
active volume session to verify the complete mount signature for every
root-relative file/directory locator, bracketing each fresh read and final
coverage decision. A core `CoverageSeal` proves only the live local walker's
authenticated ticket set and descriptor snapshots; it must never be persisted
or upgraded directly into a v5 coverage seal.

`StreamRootKind::RegularFile` exists only for compatibility with the legacy
standalone-file scanner. The persistent runtime must reject it until the volume
crate provides an equivalent pinned root-file capability; a directory-scoped
volume binding cannot authorize it.

`Partial`, `Cancelled`, and `Interrupted` outcomes never produce a complete
coverage seal. A later process cannot resume these descriptors; it must bind a
fresh volume session, create a new scan attempt, and enumerate again.
