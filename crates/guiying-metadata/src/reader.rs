use crate::{
    DetectedFormat, ExtractionLimits, ExtractionReport, ExtractionStatus, ExtractionUsage,
    MetadataField, MetadataIssue, MetadataIssueCode, ReadAtSource, PARSER_IDENTITY,
};

// These hard ceilings remain in force even if a caller supplies permissive
// limits. They keep malformed metadata from turning a parser configuration
// mistake into unbounded allocation, CPU work, or recursion.
const HARD_MAX_TOTAL_BYTES_READ: u64 = 64 * 1024 * 1024;
const HARD_MAX_SINGLE_READ_BYTES: u64 = 4 * 1024 * 1024;
const HARD_MAX_READ_OPERATIONS: u64 = 262_144;
const HARD_MAX_RETAINED_FIELD_BYTES: u64 = 16 * 1024 * 1024;
const HARD_MAX_FIELD_BYTES: u64 = 1024 * 1024;
const HARD_MAX_FIELDS: u32 = 4096;
const HARD_MAX_JPEG_SEGMENTS: u32 = 65_536;
const HARD_MAX_IFD_ENTRIES: u32 = 65_536;
const HARD_MAX_IFD_DEPTH: u16 = 64;
const HARD_MAX_BMFF_BOXES: u32 = 65_536;
const HARD_MAX_BMFF_DEPTH: u16 = 64;

pub(crate) fn harden_limits(limits: ExtractionLimits) -> ExtractionLimits {
    ExtractionLimits {
        max_total_bytes_read: limits.max_total_bytes_read.min(HARD_MAX_TOTAL_BYTES_READ),
        max_read_operations: limits.max_read_operations.min(HARD_MAX_READ_OPERATIONS),
        max_retained_field_bytes: limits
            .max_retained_field_bytes
            .min(HARD_MAX_RETAINED_FIELD_BYTES),
        max_field_bytes: limits.max_field_bytes.min(HARD_MAX_FIELD_BYTES),
        max_fields: limits.max_fields.min(HARD_MAX_FIELDS),
        max_jpeg_segments: limits.max_jpeg_segments.min(HARD_MAX_JPEG_SEGMENTS),
        max_ifd_entries: limits.max_ifd_entries.min(HARD_MAX_IFD_ENTRIES),
        max_ifd_depth: limits.max_ifd_depth.min(HARD_MAX_IFD_DEPTH),
        max_bmff_boxes: limits.max_bmff_boxes.min(HARD_MAX_BMFF_BOXES),
        max_bmff_depth: limits.max_bmff_depth.min(HARD_MAX_BMFF_DEPTH),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParseError {
    code: MetadataIssueCode,
    offset: Option<u64>,
    context: &'static str,
}

impl ParseError {
    pub(crate) const fn new(
        code: MetadataIssueCode,
        offset: Option<u64>,
        context: &'static str,
    ) -> Self {
        Self {
            code,
            offset,
            context,
        }
    }

    pub(crate) const fn io(offset: Option<u64>, context: &'static str) -> Self {
        Self::new(MetadataIssueCode::Io, offset, context)
    }

    pub(crate) const fn invalid(offset: u64, context: &'static str) -> Self {
        Self::new(MetadataIssueCode::InvalidStructure, Some(offset), context)
    }

    pub(crate) const fn out_of_bounds(offset: u64, context: &'static str) -> Self {
        Self::new(MetadataIssueCode::OutOfBounds, Some(offset), context)
    }

    pub(crate) const fn limit(offset: Option<u64>, context: &'static str) -> Self {
        Self::new(MetadataIssueCode::LimitExceeded, offset, context)
    }

    pub(crate) const fn overflow(offset: Option<u64>, context: &'static str) -> Self {
        Self::new(MetadataIssueCode::ArithmeticOverflow, offset, context)
    }

    pub(crate) const fn cycle(offset: u64, context: &'static str) -> Self {
        Self::new(MetadataIssueCode::CycleDetected, Some(offset), context)
    }

    pub(crate) const fn unsupported_version(offset: u64, context: &'static str) -> Self {
        Self::new(MetadataIssueCode::UnsupportedVersion, Some(offset), context)
    }

    pub(crate) const fn invalid_source(offset: u64, context: &'static str) -> Self {
        Self::new(MetadataIssueCode::InvalidSource, Some(offset), context)
    }

    /// Whether this error describes malformed source structure that can be
    /// isolated to one container region while sibling evidence is kept.
    ///
    /// Budget, arithmetic, and source/I-O failures are deliberately excluded:
    /// they must stay whole-report failures so the two extraction passes of
    /// the sealing gate remain deterministic and comparable.
    pub(crate) const fn is_structural(&self) -> bool {
        matches!(
            self.code,
            MetadataIssueCode::InvalidStructure
                | MetadataIssueCode::OutOfBounds
                | MetadataIssueCode::CycleDetected
                | MetadataIssueCode::UnsupportedVersion
        )
    }

    pub(crate) fn into_issue(self) -> MetadataIssue {
        MetadataIssue {
            parser: PARSER_IDENTITY,
            code: self.code,
            offset: self.offset,
            context: self.context,
        }
    }
}

/// Fields plus isolated structural issues produced by one parser invocation.
///
/// A parser returns `Err` only for non-structural (budget, arithmetic, I/O)
/// failures; those still fail the whole extraction closed.
#[derive(Default)]
pub(crate) struct ParseOutcome {
    pub(crate) fields: Vec<MetadataField>,
    pub(crate) issues: Vec<ParseError>,
}

pub(crate) struct BudgetedReader<'a> {
    source: &'a dyn ReadAtSource,
    source_len: u64,
    limits: ExtractionLimits,
    usage: ExtractionUsage,
}

impl<'a> BudgetedReader<'a> {
    pub(crate) fn new(
        source: &'a dyn ReadAtSource,
        source_len: u64,
        limits: ExtractionLimits,
    ) -> Self {
        let limits = harden_limits(limits);
        Self {
            source,
            source_len,
            limits,
            usage: ExtractionUsage::default(),
        }
    }

    pub(crate) const fn source_len(&self) -> u64 {
        self.source_len
    }

    pub(crate) const fn limits(&self) -> &ExtractionLimits {
        &self.limits
    }

    pub(crate) fn read_vec(
        &mut self,
        offset: u64,
        length: u64,
        context: &'static str,
    ) -> Result<Vec<u8>, ParseError> {
        let end = checked_add(offset, length, Some(offset), "read range overflow")?;
        if end > self.source_len {
            return Err(ParseError::out_of_bounds(offset, context));
        }
        if length > HARD_MAX_SINGLE_READ_BYTES {
            return Err(ParseError::limit(Some(offset), "single read byte limit"));
        }

        let projected = checked_add(
            self.usage.bytes_read,
            length,
            Some(offset),
            "byte budget overflow",
        )?;
        if projected > self.limits.max_total_bytes_read {
            return Err(ParseError::limit(Some(offset), "total byte-read limit"));
        }

        let allocation = usize::try_from(length)
            .map_err(|_| ParseError::limit(Some(offset), "read allocation does not fit usize"))?;
        let mut bytes = vec![0_u8; allocation];
        let mut completed = 0_usize;

        while completed < allocation {
            self.usage.read_operations = checked_add(
                self.usage.read_operations,
                1,
                Some(offset),
                "read operation counter overflow",
            )?;
            if self.usage.read_operations > self.limits.max_read_operations {
                return Err(ParseError::limit(Some(offset), "read operation limit"));
            }

            let completed_u64 = u64::try_from(completed).map_err(|_| {
                ParseError::overflow(Some(offset), "completed read count does not fit u64")
            })?;
            let read_offset = checked_add(
                offset,
                completed_u64,
                Some(offset),
                "positional read offset overflow",
            )?;
            let read = self
                .source
                .read_at(read_offset, &mut bytes[completed..])
                .map_err(|_| ParseError::io(Some(read_offset), context))?;
            if read == 0 {
                return Err(ParseError::new(
                    MetadataIssueCode::UnexpectedEof,
                    Some(read_offset),
                    context,
                ));
            }
            let remaining = allocation.checked_sub(completed).ok_or_else(|| {
                ParseError::overflow(Some(read_offset), "remaining read length underflow")
            })?;
            if read > remaining {
                return Err(ParseError::invalid_source(
                    read_offset,
                    "source returned more bytes than requested",
                ));
            }

            let read_u64 = u64::try_from(read).map_err(|_| {
                ParseError::overflow(Some(read_offset), "read count does not fit u64")
            })?;
            self.usage.bytes_read = checked_add(
                self.usage.bytes_read,
                read_u64,
                Some(read_offset),
                "byte usage counter overflow",
            )?;
            if self.usage.bytes_read > self.limits.max_total_bytes_read {
                return Err(ParseError::limit(
                    Some(read_offset),
                    "total byte-read limit",
                ));
            }
            completed = completed
                .checked_add(read)
                .ok_or_else(|| ParseError::overflow(Some(read_offset), "read index overflow"))?;
        }

        Ok(bytes)
    }

    pub(crate) fn read_field_bytes(
        &mut self,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, ParseError> {
        if length > self.limits.max_field_bytes {
            return Err(ParseError::limit(Some(offset), "single field byte limit"));
        }
        let next_field_count = self
            .usage
            .fields_emitted
            .checked_add(1)
            .ok_or_else(|| ParseError::overflow(Some(offset), "field counter overflow"))?;
        if next_field_count > self.limits.max_fields {
            return Err(ParseError::limit(
                Some(offset),
                "metadata field count limit",
            ));
        }
        let next_retained = checked_add(
            self.usage.retained_field_bytes,
            length,
            Some(offset),
            "retained field byte counter overflow",
        )?;
        if next_retained > self.limits.max_retained_field_bytes {
            return Err(ParseError::limit(
                Some(offset),
                "retained metadata byte limit",
            ));
        }

        let bytes = self.read_vec(offset, length, "read metadata field")?;
        self.usage.fields_emitted = next_field_count;
        self.usage.retained_field_bytes = next_retained;
        Ok(bytes)
    }

    pub(crate) fn visit_jpeg_segment(&mut self, offset: u64) -> Result<(), ParseError> {
        self.usage.jpeg_segments_visited = self
            .usage
            .jpeg_segments_visited
            .checked_add(1)
            .ok_or_else(|| ParseError::overflow(Some(offset), "JPEG segment counter overflow"))?;
        if self.usage.jpeg_segments_visited > self.limits.max_jpeg_segments {
            return Err(ParseError::limit(Some(offset), "JPEG segment limit"));
        }
        Ok(())
    }

    pub(crate) fn visit_ifd_entries(&mut self, offset: u64, count: u32) -> Result<(), ParseError> {
        if count > self.limits.max_ifd_entries {
            return Err(ParseError::limit(Some(offset), "TIFF IFD entry limit"));
        }
        self.usage.ifd_entries_visited = self
            .usage
            .ifd_entries_visited
            .checked_add(count)
            .ok_or_else(|| ParseError::overflow(Some(offset), "IFD entry counter overflow"))?;
        if self.usage.ifd_entries_visited > self.limits.max_ifd_entries {
            return Err(ParseError::limit(
                Some(offset),
                "cumulative TIFF IFD entry limit",
            ));
        }
        Ok(())
    }

    pub(crate) fn visit_bmff_box(&mut self, offset: u64) -> Result<(), ParseError> {
        self.usage.bmff_boxes_visited = self
            .usage
            .bmff_boxes_visited
            .checked_add(1)
            .ok_or_else(|| ParseError::overflow(Some(offset), "BMFF box counter overflow"))?;
        if self.usage.bmff_boxes_visited > self.limits.max_bmff_boxes {
            return Err(ParseError::limit(Some(offset), "BMFF box limit"));
        }
        Ok(())
    }

    pub(crate) fn observe_depth(
        &mut self,
        depth: u16,
        limit: u16,
        offset: u64,
        context: &'static str,
    ) -> Result<(), ParseError> {
        if depth > limit {
            return Err(ParseError::limit(Some(offset), context));
        }
        self.usage.max_depth_observed = self.usage.max_depth_observed.max(depth);
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
        format: Option<DetectedFormat>,
        fields: Vec<MetadataField>,
        errors: Vec<ParseError>,
    ) -> ExtractionReport {
        let status = match (format, fields.is_empty(), errors.is_empty()) {
            (None, _, true) => ExtractionStatus::Unsupported,
            (_, false, true) => ExtractionStatus::ExtractedUnvalidated,
            (Some(_), true, true) => ExtractionStatus::NoMetadata,
            (_, false, false) => ExtractionStatus::Partial,
            (_, true, false) => ExtractionStatus::Failed,
        };
        self.usage.fields_emitted = u32::try_from(fields.len()).unwrap_or(u32::MAX);
        self.usage.retained_field_bytes = fields.iter().fold(0_u64, |total, field| {
            total.saturating_add(u64::try_from(field.raw_bytes.len()).unwrap_or(u64::MAX))
        });
        ExtractionReport {
            parser: PARSER_IDENTITY,
            limits: self.limits,
            format,
            status,
            fields,
            issues: errors.into_iter().map(ParseError::into_issue).collect(),
            usage: self.usage,
        }
    }
}

pub(crate) fn checked_add(
    left: u64,
    right: u64,
    offset: Option<u64>,
    context: &'static str,
) -> Result<u64, ParseError> {
    left.checked_add(right)
        .ok_or_else(|| ParseError::overflow(offset, context))
}

pub(crate) fn checked_mul(
    left: u64,
    right: u64,
    offset: Option<u64>,
    context: &'static str,
) -> Result<u64, ParseError> {
    left.checked_mul(right)
        .ok_or_else(|| ParseError::overflow(offset, context))
}

pub(crate) fn checked_sub(
    left: u64,
    right: u64,
    offset: Option<u64>,
    context: &'static str,
) -> Result<u64, ParseError> {
    left.checked_sub(right)
        .ok_or_else(|| ParseError::invalid(offset.unwrap_or(left), context))
}
