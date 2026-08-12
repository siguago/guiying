#![forbid(unsafe_code)]
//! Bounded, read-only extraction of original timestamp evidence.
//!
//! The API is deliberately path-independent: callers pass an already-open or
//! otherwise pinned [`ReadAtSource`]. Parsing failure is represented by
//! [`ExtractionReport::status`] and [`ExtractionReport::issues`], never by a
//! filesystem mutation and never as duplicate-content evidence.

mod bmff;
mod jpeg;
mod reader;
mod tiff;

use std::io;

use reader::{BudgetedReader, ParseError};

/// Identity persisted alongside every extracted field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ParserIdentity {
    pub name: &'static str,
    pub version: &'static str,
}

pub const PARSER_IDENTITY: ParserIdentity = ParserIdentity {
    name: "guiying-metadata",
    version: env!("CARGO_PKG_VERSION"),
};

/// A path-free source with positional reads.
///
/// Implementations may return short reads. Returning `Ok(0)` before the
/// advertised length is treated as an unexpected EOF. The parser never seeks
/// or writes through this interface.
pub trait ReadAtSource {
    /// Return the stable logical length advertised for this extraction.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the source length cannot be obtained.
    fn source_len(&self) -> io::Result<u64>;

    /// Read at `offset` without changing shared seek state.
    ///
    /// Short reads are allowed and completed by the extractor.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the positional read cannot be completed.
    fn read_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<usize>;
}

impl ReadAtSource for [u8] {
    fn source_len(&self) -> io::Result<u64> {
        u64::try_from(self.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "byte slice length does not fit in u64",
            )
        })
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(offset).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "offset does not fit in usize")
        })?;
        if start >= self.len() || destination.is_empty() {
            return Ok(0);
        }
        let available = self.len().checked_sub(start).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "slice read range underflow")
        })?;
        let count = available.min(destination.len());
        let end = start.checked_add(count).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "slice read range overflow")
        })?;
        destination[..count].copy_from_slice(&self[start..end]);
        Ok(count)
    }
}

impl ReadAtSource for Vec<u8> {
    fn source_len(&self) -> io::Result<u64> {
        self.as_slice().source_len()
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<usize> {
        self.as_slice().read_at(offset, destination)
    }
}

#[cfg(unix)]
impl ReadAtSource for std::fs::File {
    fn source_len(&self) -> io::Result<u64> {
        self.metadata().map(|metadata| metadata.len())
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        FileExt::read_at(self, destination, offset)
    }
}

#[cfg(windows)]
impl ReadAtSource for std::fs::File {
    fn source_len(&self) -> io::Result<u64> {
        self.metadata().map(|metadata| metadata.len())
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<usize> {
        use std::os::windows::fs::FileExt;
        FileExt::seek_read(self, destination, offset)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtractionLimits {
    pub max_total_bytes_read: u64,
    pub max_read_operations: u64,
    pub max_retained_field_bytes: u64,
    pub max_field_bytes: u64,
    pub max_fields: u32,
    pub max_jpeg_segments: u32,
    pub max_ifd_entries: u32,
    pub max_ifd_depth: u16,
    pub max_bmff_boxes: u32,
    pub max_bmff_depth: u16,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_total_bytes_read: 8 * 1024 * 1024,
            max_read_operations: 32 * 1024,
            max_retained_field_bytes: 256 * 1024,
            max_field_bytes: 16 * 1024,
            max_fields: 128,
            max_jpeg_segments: 4096,
            max_ifd_entries: 4096,
            max_ifd_depth: 8,
            max_bmff_boxes: 8192,
            max_bmff_depth: 16,
        }
    }
}

impl ExtractionLimits {
    /// Return the effective limits after applying parser-owned hard ceilings.
    ///
    /// Callers may tighten any limit, but cannot disable the absolute memory,
    /// work, and nesting safeguards by supplying a larger value.
    #[must_use]
    pub fn effective(self) -> Self {
        reader::harden_limits(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExtractionUsage {
    pub bytes_read: u64,
    pub read_operations: u64,
    pub retained_field_bytes: u64,
    pub fields_emitted: u32,
    pub jpeg_segments_visited: u32,
    pub ifd_entries_visited: u32,
    pub bmff_boxes_visited: u32,
    pub max_depth_observed: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtractionStatus {
    /// A recognized container was parsed and at least one raw field was found.
    ///
    /// Field values have **not** been validated as dates and this state must
    /// never be interpreted as a trustworthy capture time.
    ExtractedUnvalidated,
    /// A recognized container was valid but had no supported timestamp field.
    NoMetadata,
    /// Raw fields were recovered, but another recognized structure inside the
    /// same source was malformed and had to be skipped. The recovered fields
    /// carry the same caveats as [`ExtractionStatus::ExtractedUnvalidated`].
    Partial,
    /// A recognized source could not be parsed safely. No evidence is trusted.
    /// Budget exhaustion, arithmetic overflow, and I/O failures always fail
    /// the whole report closed, discarding any partially extracted fields.
    Failed,
    /// The source is not one of the supported containers.
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectedFormat {
    Jpeg,
    Tiff,
    IsoBmff,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MetadataFieldKind {
    /// Exif `DateTimeOriginal` (0x9003), preserved without normalization.
    ExifDateTimeOriginal,
    /// Exif `DateTimeDigitized`/`CreateDate` (0x9004).
    ExifCreateDate,
    /// TIFF/Exif `DateTime`/`ModifyDate` (0x0132).
    ExifModifyDate,
    /// Exif `OffsetTimeOriginal` (0x9011).
    ExifOffsetTimeOriginal,
    /// Exif `SubSecTimeOriginal` (0x9291).
    ExifSubSecTimeOriginal,
    /// Unsigned big-endian seconds since 1904-01-01 UTC from `mvhd`.
    QuickTimeMovieHeaderCreationTime,
    /// UTF-8 creation-date text from `QuickTime` metadata.
    QuickTimeMetadataCreationDate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldEncoding {
    /// The container declares TIFF ASCII. Date syntax and semantics are not
    /// validated by this extraction layer.
    DeclaredAscii,
    /// The container declares UTF-8 and the extractor verified the bytes are
    /// valid UTF-8. Date syntax and semantics remain unvalidated.
    ValidatedUtf8,
    UnsignedBigEndian,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TiffByteOrder {
    LittleEndian,
    BigEndian,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataContainer {
    Tiff {
        header_offset: u64,
        ifd_offset: u64,
        tag: u16,
        byte_order: TiffByteOrder,
    },
    JpegExif {
        app1_offset: u64,
        header_offset: u64,
        ifd_offset: u64,
        tag: u16,
        byte_order: TiffByteOrder,
    },
    IsoBmff {
        box_offset: u64,
        box_path: Vec<[u8; 4]>,
    },
}

/// Exact source location of [`MetadataField::raw_bytes`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataLocator {
    pub absolute_offset: u64,
    pub byte_len: u64,
    pub container: MetadataContainer,
}

/// Original bytes plus enough identity and location data to audit/re-read them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataField {
    pub parser: ParserIdentity,
    pub kind: MetadataFieldKind,
    pub encoding: FieldEncoding,
    pub locator: MetadataLocator,
    pub raw_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataIssueCode {
    Io,
    UnexpectedEof,
    ArithmeticOverflow,
    OutOfBounds,
    InvalidStructure,
    CycleDetected,
    LimitExceeded,
    UnsupportedVersion,
    InvalidSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataIssue {
    pub parser: ParserIdentity,
    pub code: MetadataIssueCode,
    pub offset: Option<u64>,
    /// A bounded parser-owned description; it never contains source bytes.
    pub context: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionReport {
    pub parser: ParserIdentity,
    /// Effective (hard-ceiling-clamped) limits used for this extraction.
    pub limits: ExtractionLimits,
    pub format: Option<DetectedFormat>,
    /// Structural extraction status, never a time-confidence decision.
    pub status: ExtractionStatus,
    pub fields: Vec<MetadataField>,
    pub issues: Vec<MetadataIssue>,
    pub usage: ExtractionUsage,
}

/// Extract timestamp evidence without ever making metadata a condition of D1.
///
/// All source and parser errors are converted to a report. A caller may safely
/// persist the report and continue exact-content duplicate processing.
/// `ExtractedUnvalidated` only means that raw fields were located; a separate
/// policy layer must validate syntax, timezone semantics, range and conflicts.
pub fn extract_timestamp_evidence(
    source: &dyn ReadAtSource,
    limits: ExtractionLimits,
) -> ExtractionReport {
    let limits = limits.effective();
    let Ok(source_len) = source.source_len() else {
        return failed_report(limits, ParseError::io(None, "read source length"));
    };

    let mut reader = BudgetedReader::new(source, source_len, limits);
    let detected = match detect_format(&mut reader) {
        Ok(format) => format,
        Err(error) => return reader.finish(None, Vec::new(), vec![error]),
    };

    let Some(format) = detected else {
        return reader.finish(None, Vec::new(), Vec::new());
    };

    let parsed = match format {
        DetectedFormat::Jpeg => jpeg::parse(&mut reader),
        DetectedFormat::Tiff => tiff::parse_direct(&mut reader),
        DetectedFormat::IsoBmff => bmff::parse(&mut reader),
    };

    match parsed {
        // Structural problems local to one container region arrive as issues
        // next to the fields that other regions still produced.
        Ok(outcome) => reader.finish(Some(format), outcome.fields, outcome.issues),
        // Budget, arithmetic, and I/O failures stay whole-report failures so
        // that repeated extraction passes remain deterministic and comparable.
        Err(error) => reader.finish(Some(format), Vec::new(), vec![error]),
    }
}

fn detect_format(reader: &mut BudgetedReader<'_>) -> Result<Option<DetectedFormat>, ParseError> {
    let prefix_len = reader.source_len().min(16);
    if prefix_len == 0 {
        return Ok(None);
    }
    let prefix = reader.read_vec(0, prefix_len, "read format signature")?;
    if prefix.starts_with(&[0xff, 0xd8]) {
        return Ok(Some(DetectedFormat::Jpeg));
    }
    if prefix.starts_with(b"II\x2a\x00") || prefix.starts_with(b"MM\x00\x2a") {
        return Ok(Some(DetectedFormat::Tiff));
    }
    if prefix.len() >= 8 {
        let box_type = &prefix[4..8];
        if matches!(box_type, b"ftyp" | b"moov" | b"wide" | b"free") {
            return Ok(Some(DetectedFormat::IsoBmff));
        }
    }
    Ok(None)
}

fn failed_report(limits: ExtractionLimits, error: ParseError) -> ExtractionReport {
    ExtractionReport {
        parser: PARSER_IDENTITY,
        limits,
        format: None,
        status: ExtractionStatus::Failed,
        fields: Vec::new(),
        issues: vec![error.into_issue()],
        usage: ExtractionUsage::default(),
    }
}
