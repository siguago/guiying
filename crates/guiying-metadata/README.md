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
  `meta`/`ilst` atoms, accepting both `meta` dialects: the ISO full box
  (version/flags) and the QuickTime-style versionless layout used by Apple
  `.mov` files (detected by the mandatory leading `hdlr` child);
- HEIF/HEIC `Exif` items in a root-level `pict` `meta`: `iinf` (versions 0/1,
  `infe` versions 2/3) resolves the `Exif` item, `iloc` (versions 0/1/2) must
  address it with construction method 0 (absolute file offset), no external
  data reference, and exactly one extent; anything else fails closed as a
  structural issue. The item payload's four-byte TIFF header offset is applied
  before the embedded TIFF is parsed with the ordinary bounded TIFF walker.

All reads, structure visits, recursion depth, extracted fields, and retained
field bytes are subject to caller-controlled limits.

## Safety contract

- The crate has no path, seek, write, rename, timestamp, or delete API.
- Caller limits are automatically tightened by parser-owned hard ceilings;
  the effective values are returned in every extraction report.
- Every offset and length calculation uses checked arithmetic and is bounded by
  both its enclosing container and the advertised source length.
- Short positional reads are completed exactly; premature EOF, I/O errors,
  budget exhaustion, and arithmetic overflow always fail the whole report
  closed with no trusted fields, keeping repeated extraction passes
  deterministic and comparable.
- Malformed structures, cycles, and unsupported versions are structural
  issues isolated to their own container region: fields recovered from other
  regions of the same source are kept and the report status becomes
  `Partial`. A report with any issue never claims `ExtractedUnvalidated`.
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
