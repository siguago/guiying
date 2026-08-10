# guiying-time

`guiying-time` is Guiying's pure timestamp normalization and evidence-policy
layer. It consumes bounded, read-only reports from `guiying-metadata`, strictly
validates their raw fields, preserves every raw field with its parser and byte
locator, and reports ambiguity instead of inventing a timezone or selecting the
first repeated value.

The crate deliberately has no filesystem, clock, timezone-database, path, or
write API. The caller supplies the reference instant, optional reference wall
time, additional sentinel rules, and tolerance policy through `PolicyContext`.

## Safety boundary

- A metadata report's `ExtractedUnvalidated` status is never itself evidence of
  a valid time. Every field is parsed and range-checked again here.
- A plain `ExtractionReport` is review-only. Automatic evidence requires an
  opaque `SourceVerifiedExtractionReport` produced only when a second bounded
  extraction from a runtime-pinned source exactly reproduces the retained
  report, including every raw byte and locator. The proof permanently carries
  the caller's `SourceKey`; `EvidenceSource::source_verified` takes that key
  from the proof, so it cannot be rebound afterward. The runtime must still
  check file identity around both extractions and repeat the check before
  execution.
- Detected format and locator container must agree exactly. TIFF/JPEG scopes,
  canonical QuickTime box paths and offsets, per-field limits, and
  format-specific counters and nesting limits are checked before a field can
  contribute. A BMFF locator may retain at most six canonical path components;
  aggregate path components are bounded and rejected before fields are cloned.
- `EvidenceGateDecision::Eligible` only means that the timestamp evidence
  passed this crate's policy. It is **not authorization to change a file**.
  Guiying must still satisfy the frozen-plan, user-confirmation, volume C4,
  write/read-back, content-hash, dual-log, and donor-preservation gates.
- `Partial` or `Failed` extraction, parser/encoding contradictions, malformed
  fields, repeated values of one kind that disagree, strong-evidence conflicts,
  sentinels, and obvious-future values all fail closed.
- A timestamp without an explicit offset remains a floating wall time. The
  current Mac timezone is never consulted or applied.
- Caller tolerances can be tightened but are clamped by parser-policy hard
  ceilings (5 seconds for strong agreement, 5 seconds around integer hours,
  7 days for obvious-future tolerance, and ±14 hours for offset suspicion), so
  configuration cannot silently disable the evidence gates.
- Automatic UTC instants are hard-limited to signed-64-bit Unix nanoseconds.
  Parsed values outside roughly 1677--2262 remain fully visible for review but
  cannot become eligible. Caller lower/upper bounds can only tighten that
  interval. The common 1904, 1970, and 1980 sentinel years are also
  non-removable; callers may add at most 1,024 more sentinel rules. Those rules
  are deduplicated and indexed by year, date, wall time, or Unix second before
  candidates are matched.
- QuickTime `mvhd` is decoded as unsigned seconds since 1904-01-01 UTC, but is
  always marked semantically uncertain and can never be high-confidence by
  itself. Matching `mvhd` and creation-date text remains review-only until a
  future parser can also bind track time and common movie-box ancestry.
- Copy count never increases confidence. Callers assign the same `LineageKey`
  to copy-derived sources; support is deduplicated by that lineage.
- Sources, observations, extractor issues, retained raw bytes, and generated
  policy issues all have parser-owned aggregate ceilings. Exceeding any ceiling
  returns one fail-closed `AnalysisLimitExceeded` result. Conflict processing
  uses bounded ordered grouping rather than copy-count pair voting.
- Every analysis carries `POLICY_IDENTITY`; every observation retains the
  extractor parser identity and exact byte locator for durable audit records.
- Sidecar ownership is intentionally out of scope for this crate version.
