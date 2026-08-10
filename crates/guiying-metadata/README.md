# guiying-metadata

`guiying-metadata` is Guiying's bounded, read-only metadata evidence layer. It
accepts an already-bound random-access source instead of a path, never mutates
the source, preserves the exact field bytes and their byte locators, and turns
all parser failures into an isolated report status. Duplicate-content proof
must never depend on this crate succeeding. This crate locates raw fields; it
does not decide whether their contents are valid, plausible, mutually
consistent, or suitable for time repair.

The first parser version recognizes:

- JPEG APP1 Exif and standalone TIFF timestamps;
- little- and big-endian TIFF IFDs with strict bounds and cycle checks;
- ISO-BMFF/QuickTime `mvhd` creation time;
- QuickTime `com.apple.quicktime.creationdate` and `©day` text values in
  `meta`/`ilst` atoms.

All reads, structure visits, recursion depth, extracted fields, and retained
field bytes are subject to caller-controlled limits.

## Safety contract

- The crate has no path, seek, write, rename, timestamp, or delete API.
- Caller limits are automatically tightened by parser-owned hard ceilings;
  the effective values are returned in every extraction report.
- Every offset and length calculation uses checked arithmetic and is bounded by
  both its enclosing container and the advertised source length.
- Short positional reads are completed exactly; premature EOF, I/O errors,
  malformed structures, cycles, excessive counts, and unsupported versions
  become a fail-closed report status with no trusted fields.
- The caller remains responsible for pinning the source identity and checking
  that it did not change before/after extraction. Guiying's scanner does this
  around the already-open file descriptor.
- `ExtractedUnvalidated` means only that structurally valid containers exposed
  raw fields at accepted locations. It does not mean that a field contains a
  valid date or trustworthy capture time.
- Multiple values of the same kind are all preserved. The policy layer must
  detect conflicts; it may not pick the first value silently.
- Metadata evidence is never a substitute for Guiying's full hash plus
  byte-for-byte D1 proof.
