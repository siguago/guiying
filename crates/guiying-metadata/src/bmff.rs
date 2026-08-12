use crate::reader::{
    checked_add, checked_mul, checked_sub, BudgetedReader, ParseError, ParseOutcome,
};
use crate::tiff::{self, TiffOrigin};
use crate::{
    FieldEncoding, MetadataContainer, MetadataField, MetadataFieldKind, MetadataLocator,
    PARSER_IDENTITY,
};

const BOX_HEADER_BYTES: u64 = 8;
const EXTENDED_BOX_HEADER_BYTES: u64 = 16;
const UUID_USER_TYPE_BYTES: u64 = 16;
const FULL_BOX_HEADER_BYTES: u64 = 4;
const QUICKTIME_DATA_HEADER_BYTES: u64 = 8;
const HANDLER_HEADER_BYTES: u64 = 12;
const EXIF_ITEM_PREFIX_BYTES: u64 = 4;
const CREATION_DATE_KEY: &[u8] = b"com.apple.quicktime.creationdate";
const COPYRIGHT_DAY: [u8; 4] = [0xa9, b'd', b'a', b'y'];

#[derive(Clone, Copy, Debug)]
struct BoxHeader {
    offset: u64,
    box_type: [u8; 4],
    payload_offset: u64,
    end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WalkContext {
    Root,
    Movie,
    UserData,
}

/// Mutable output channels for one BMFF walk.
struct Emit<'a> {
    path: &'a mut Vec<[u8; 4]>,
    fields: &'a mut Vec<MetadataField>,
    issues: &'a mut Vec<ParseError>,
}

/// Absolute location of one item payload proven by `iloc`.
#[derive(Clone, Copy, Debug)]
struct ItemLocation {
    offset: u64,
    length: u64,
}

impl BoxHeader {
    fn payload_len(self) -> Result<u64, ParseError> {
        checked_sub(
            self.end,
            self.payload_offset,
            Some(self.offset),
            "BMFF payload range",
        )
    }
}

pub(crate) fn parse(reader: &mut BudgetedReader<'_>) -> Result<ParseOutcome, ParseError> {
    let mut outcome = ParseOutcome::default();
    let mut path = Vec::new();
    let mut emit = Emit {
        path: &mut path,
        fields: &mut outcome.fields,
        issues: &mut outcome.issues,
    };
    walk_range(
        reader,
        0,
        reader.source_len(),
        1,
        WalkContext::Root,
        &mut emit,
    )?;
    Ok(outcome)
}

fn walk_range(
    reader: &mut BudgetedReader<'_>,
    start: u64,
    end: u64,
    depth: u16,
    context: WalkContext,
    emit: &mut Emit<'_>,
) -> Result<(), ParseError> {
    reader.observe_depth(
        depth,
        reader.limits().max_bmff_depth,
        start,
        "BMFF nesting depth limit",
    )?;
    let mut cursor = start;
    while cursor < end {
        let header = match read_box_header(reader, cursor, end) {
            Ok(header) => header,
            Err(error) if error.is_structural() => {
                // Broken box framing: siblings cannot be located safely, but
                // evidence from earlier complete boxes stays valid.
                emit.issues.push(error);
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        emit.path.push(header.box_type);
        let handled = match (context, &header.box_type) {
            (WalkContext::Root, b"moov") | (WalkContext::Movie, b"udta") => {
                let child_depth = depth.checked_add(1).ok_or_else(|| {
                    ParseError::overflow(Some(header.offset), "BMFF nesting depth overflow")
                });
                let child_context = if context == WalkContext::Root {
                    WalkContext::Movie
                } else {
                    WalkContext::UserData
                };
                child_depth.and_then(|child_depth| {
                    walk_range(
                        reader,
                        header.payload_offset,
                        header.end,
                        child_depth,
                        child_context,
                        emit,
                    )
                })
            }
            (WalkContext::Root, b"meta") => parse_root_meta(reader, header, depth, emit),
            (WalkContext::Movie, b"mvhd") => parse_mvhd(reader, header, emit),
            (WalkContext::Movie | WalkContext::UserData, b"meta") => {
                parse_meta(reader, header, depth, emit)
            }
            (WalkContext::UserData, value) if *value == COPYRIGHT_DAY => {
                parse_legacy_copyright_day(reader, header, emit)
            }
            _ => Ok(()),
        };
        emit.path.pop();
        match handled {
            Ok(()) => {}
            Err(error) if error.is_structural() => emit.issues.push(error),
            Err(error) => return Err(error),
        }
        cursor = header.end;
    }
    Ok(())
}

/// Determine where the children of a `meta` box begin.
///
/// ISO BMFF declares `meta` as a full box with version/flags, while the
/// QuickTime file format (Apple `.mov`, the primary carrier of
/// `com.apple.quicktime.creationdate`) has no version/flags and starts
/// directly with the mandatory `hdlr` child. The dialect is detected by
/// peeking the first eight payload bytes: a `hdlr` type at offset 4 proves the
/// QuickTime layout, since an ISO child size of `0x68646c72` cannot fit any
/// bounded parent.
fn meta_children_start(
    reader: &mut BudgetedReader<'_>,
    header: BoxHeader,
) -> Result<u64, ParseError> {
    let payload_len = header.payload_len()?;
    if payload_len >= BOX_HEADER_BYTES {
        let probe = reader.read_vec(
            header.payload_offset,
            BOX_HEADER_BYTES,
            "probe meta dialect",
        )?;
        if probe[4..8] == *b"hdlr" {
            return Ok(header.payload_offset);
        }
        if probe[0] != 0 {
            return Err(ParseError::unsupported_version(
                header.payload_offset,
                "meta version",
            ));
        }
        return checked_add(
            header.payload_offset,
            FULL_BOX_HEADER_BYTES,
            Some(header.payload_offset),
            "meta children offset overflow",
        );
    }
    if payload_len >= FULL_BOX_HEADER_BYTES {
        let version_flags = reader.read_vec(
            header.payload_offset,
            FULL_BOX_HEADER_BYTES,
            "read meta full-box header",
        )?;
        if version_flags[0] != 0 {
            return Err(ParseError::unsupported_version(
                header.payload_offset,
                "meta version",
            ));
        }
        return checked_add(
            header.payload_offset,
            FULL_BOX_HEADER_BYTES,
            Some(header.payload_offset),
            "meta children offset overflow",
        );
    }
    Err(ParseError::out_of_bounds(
        header.payload_offset,
        "meta full-box header",
    ))
}

fn parse_mvhd(
    reader: &mut BudgetedReader<'_>,
    header: BoxHeader,
    emit: &mut Emit<'_>,
) -> Result<(), ParseError> {
    if header.payload_len()? < FULL_BOX_HEADER_BYTES {
        return Err(ParseError::out_of_bounds(
            header.payload_offset,
            "mvhd full-box header",
        ));
    }
    let prefix = reader.read_vec(
        header.payload_offset,
        FULL_BOX_HEADER_BYTES,
        "read mvhd full-box header",
    )?;
    let (value_delta, value_length, minimum_payload) = match prefix[0] {
        0 => (4_u64, 4_u64, 20_u64),
        1 => (4_u64, 8_u64, 32_u64),
        _ => {
            return Err(ParseError::unsupported_version(
                header.payload_offset,
                "mvhd version",
            ));
        }
    };
    if header.payload_len()? < minimum_payload {
        return Err(ParseError::out_of_bounds(
            header.payload_offset,
            "mvhd payload",
        ));
    }
    let value_offset = checked_add(
        header.payload_offset,
        value_delta,
        Some(header.payload_offset),
        "mvhd creation-time offset overflow",
    )?;
    let raw_bytes = reader.read_field_bytes(value_offset, value_length)?;
    let box_path = emit.path.clone();
    emit.fields.push(MetadataField {
        parser: PARSER_IDENTITY,
        kind: MetadataFieldKind::QuickTimeMovieHeaderCreationTime,
        encoding: FieldEncoding::UnsignedBigEndian,
        locator: MetadataLocator {
            absolute_offset: value_offset,
            byte_len: value_length,
            container: MetadataContainer::IsoBmff {
                box_offset: header.offset,
                box_path,
            },
        },
        raw_bytes,
    });
    Ok(())
}

fn parse_meta(
    reader: &mut BudgetedReader<'_>,
    header: BoxHeader,
    parent_depth: u16,
    emit: &mut Emit<'_>,
) -> Result<(), ParseError> {
    let children_start = meta_children_start(reader, header)?;
    let child_depth = parent_depth
        .checked_add(1)
        .ok_or_else(|| ParseError::overflow(Some(header.offset), "BMFF depth overflow"))?;
    reader.observe_depth(
        child_depth,
        reader.limits().max_bmff_depth,
        children_start,
        "BMFF nesting depth limit",
    )?;

    let mut children = Vec::new();
    let mut cursor = children_start;
    while cursor < header.end {
        let child = read_box_header(reader, cursor, header.end)?;
        children.push(child);
        cursor = child.end;
    }

    let mut recognized_keys = Vec::new();
    for child in &children {
        if child.box_type == *b"keys" {
            recognized_keys = parse_keys(reader, *child)?;
            break;
        }
    }

    for child in children {
        if child.box_type == *b"ilst" {
            emit.path.push(child.box_type);
            let parsed = parse_ilst(reader, child, child_depth, &recognized_keys, emit);
            emit.path.pop();
            parsed?;
        }
    }
    Ok(())
}

/// Handle a root-level `meta` box (HEIF/HEIC still images).
///
/// Only the `pict` handler with an `Exif` item is consumed. The item must be
/// addressed by `iloc` with construction method 0 (absolute file offset) and
/// exactly one extent; anything else fails closed as a structural issue for
/// this box only.
fn parse_root_meta(
    reader: &mut BudgetedReader<'_>,
    header: BoxHeader,
    parent_depth: u16,
    emit: &mut Emit<'_>,
) -> Result<(), ParseError> {
    let children_start = meta_children_start(reader, header)?;
    let child_depth = parent_depth
        .checked_add(1)
        .ok_or_else(|| ParseError::overflow(Some(header.offset), "BMFF depth overflow"))?;
    reader.observe_depth(
        child_depth,
        reader.limits().max_bmff_depth,
        children_start,
        "BMFF nesting depth limit",
    )?;

    let mut handler_type = None;
    let mut item_info = None;
    let mut item_location = None;
    let mut cursor = children_start;
    while cursor < header.end {
        let child = read_box_header(reader, cursor, header.end)?;
        match &child.box_type {
            b"hdlr" if handler_type.is_none() => {
                handler_type = read_handler_type(reader, &child)?;
            }
            b"iinf" if item_info.is_none() => item_info = Some(child),
            b"iloc" if item_location.is_none() => item_location = Some(child),
            _ => {}
        }
        cursor = child.end;
    }

    if handler_type != Some(*b"pict") {
        return Ok(());
    }
    let Some(info) = item_info else {
        return Ok(());
    };
    let Some(exif_item) = find_exif_item(reader, &info)? else {
        return Ok(());
    };
    let Some(location_box) = item_location else {
        return Err(ParseError::invalid(
            header.offset,
            "Exif item has no location box",
        ));
    };
    let location = find_item_location(reader, &location_box, exif_item)?;
    extract_exif_item(reader, location, emit)
}

fn read_handler_type(
    reader: &mut BudgetedReader<'_>,
    header: &BoxHeader,
) -> Result<Option<[u8; 4]>, ParseError> {
    if header.payload_len()? < HANDLER_HEADER_BYTES {
        return Ok(None);
    }
    let head = reader.read_vec(
        header.payload_offset,
        HANDLER_HEADER_BYTES,
        "read hdlr header",
    )?;
    Ok(Some([head[8], head[9], head[10], head[11]]))
}

fn find_exif_item(
    reader: &mut BudgetedReader<'_>,
    header: &BoxHeader,
) -> Result<Option<u64>, ParseError> {
    if header.payload_len()? < FULL_BOX_HEADER_BYTES {
        return Err(ParseError::out_of_bounds(
            header.payload_offset,
            "iinf full-box header",
        ));
    }
    let head = reader.read_vec(
        header.payload_offset,
        FULL_BOX_HEADER_BYTES,
        "read iinf header",
    )?;
    let count_bytes = match head[0] {
        0 => 2_u64,
        1 => 4_u64,
        _ => {
            return Err(ParseError::unsupported_version(
                header.payload_offset,
                "iinf version",
            ));
        }
    };
    let header_bytes = checked_add(
        FULL_BOX_HEADER_BYTES,
        count_bytes,
        Some(header.payload_offset),
        "iinf header length overflow",
    )?;
    let entries_start = checked_add(
        header.payload_offset,
        header_bytes,
        Some(header.payload_offset),
        "iinf entry offset overflow",
    )?;
    if entries_start > header.end {
        return Err(ParseError::out_of_bounds(
            header.payload_offset,
            "iinf entry table",
        ));
    }
    let mut cursor = entries_start;
    while cursor < header.end {
        let entry = read_box_header(reader, cursor, header.end)?;
        if entry.box_type == *b"infe" {
            if let Some(item_id) = exif_item_id(reader, &entry)? {
                return Ok(Some(item_id));
            }
        }
        cursor = entry.end;
    }
    Ok(None)
}

fn exif_item_id(
    reader: &mut BudgetedReader<'_>,
    entry: &BoxHeader,
) -> Result<Option<u64>, ParseError> {
    let payload_len = entry.payload_len()?;
    if payload_len < FULL_BOX_HEADER_BYTES {
        return Err(ParseError::out_of_bounds(
            entry.payload_offset,
            "infe full-box header",
        ));
    }
    let head = reader.read_vec(
        entry.payload_offset,
        FULL_BOX_HEADER_BYTES,
        "read infe header",
    )?;
    let (item_id, protection_index, item_type) = match head[0] {
        // Versions 0 and 1 carry no item type, so they can never be `Exif`.
        0 | 1 => return Ok(None),
        2 => {
            if payload_len < 12 {
                return Err(ParseError::out_of_bounds(
                    entry.payload_offset,
                    "infe entry",
                ));
            }
            let body = reader.read_vec(entry.payload_offset, 12, "read infe entry")?;
            (
                u64::from(u16::from_be_bytes([body[4], body[5]])),
                u16::from_be_bytes([body[6], body[7]]),
                [body[8], body[9], body[10], body[11]],
            )
        }
        3 => {
            if payload_len < 14 {
                return Err(ParseError::out_of_bounds(
                    entry.payload_offset,
                    "infe entry",
                ));
            }
            let body = reader.read_vec(entry.payload_offset, 14, "read infe entry")?;
            (
                u64::from(u32::from_be_bytes([body[4], body[5], body[6], body[7]])),
                u16::from_be_bytes([body[8], body[9]]),
                [body[10], body[11], body[12], body[13]],
            )
        }
        _ => {
            return Err(ParseError::unsupported_version(
                entry.payload_offset,
                "infe version",
            ));
        }
    };
    if item_type != *b"Exif" {
        return Ok(None);
    }
    if protection_index != 0 {
        return Err(ParseError::invalid(
            entry.payload_offset,
            "protected Exif item",
        ));
    }
    Ok(Some(item_id))
}

fn find_item_location(
    reader: &mut BudgetedReader<'_>,
    header: &BoxHeader,
    wanted_item: u64,
) -> Result<ItemLocation, ParseError> {
    if header.payload_len()? < 8 {
        return Err(ParseError::out_of_bounds(
            header.payload_offset,
            "iloc header",
        ));
    }
    let head = reader.read_vec(header.payload_offset, 8, "read iloc header")?;
    let version = head[0];
    if version > 2 {
        return Err(ParseError::unsupported_version(
            header.payload_offset,
            "iloc version",
        ));
    }
    let offset_size = u64::from(head[4] >> 4);
    let length_size = u64::from(head[4] & 0x0f);
    let base_offset_size = u64::from(head[5] >> 4);
    let index_size = if version >= 1 {
        u64::from(head[5] & 0x0f)
    } else {
        0
    };
    for size in [offset_size, length_size, base_offset_size, index_size] {
        if !matches!(size, 0 | 4 | 8) {
            return Err(ParseError::invalid(
                header.payload_offset,
                "iloc size field",
            ));
        }
    }
    let (item_count, mut cursor) = if version == 2 {
        let count_offset = checked_add(
            header.payload_offset,
            6,
            Some(header.payload_offset),
            "iloc item count offset overflow",
        )?;
        let count_end = checked_add(
            count_offset,
            4,
            Some(count_offset),
            "iloc item count end overflow",
        )?;
        if count_end > header.end {
            return Err(ParseError::out_of_bounds(count_offset, "iloc item count"));
        }
        let counted = reader.read_vec(count_offset, 4, "read iloc item count")?;
        (
            u64::from(u32::from_be_bytes([
                counted[0], counted[1], counted[2], counted[3],
            ])),
            count_end,
        )
    } else {
        (
            u64::from(u16::from_be_bytes([head[6], head[7]])),
            checked_add(
                header.payload_offset,
                8,
                Some(header.payload_offset),
                "iloc item table offset overflow",
            )?,
        )
    };

    for _ in 0..item_count {
        reader.visit_bmff_box(cursor)?;
        let item_offset = cursor;
        let item_id = if version == 2 {
            u64::from(take_u32(
                reader,
                &mut cursor,
                header.end,
                "read iloc item id",
            )?)
        } else {
            u64::from(take_u16(
                reader,
                &mut cursor,
                header.end,
                "read iloc item id",
            )?)
        };
        let construction_method = if version >= 1 {
            take_u16(
                reader,
                &mut cursor,
                header.end,
                "read iloc construction method",
            )? & 0x000f
        } else {
            0
        };
        let data_reference_index = take_u16(
            reader,
            &mut cursor,
            header.end,
            "read iloc data reference index",
        )?;
        let base_offset = take_uint(
            reader,
            &mut cursor,
            header.end,
            base_offset_size,
            "read iloc base offset",
        )?;
        let extent_count = u64::from(take_u16(
            reader,
            &mut cursor,
            header.end,
            "read iloc extent count",
        )?);

        if item_id == wanted_item {
            if data_reference_index != 0 {
                return Err(ParseError::invalid(
                    item_offset,
                    "Exif item uses an external data reference",
                ));
            }
            if construction_method != 0 {
                return Err(ParseError::invalid(
                    item_offset,
                    "unsupported Exif item construction method",
                ));
            }
            if extent_count != 1 {
                return Err(ParseError::invalid(
                    item_offset,
                    "Exif item does not have exactly one extent",
                ));
            }
            if index_size > 0 {
                take_bytes(
                    reader,
                    &mut cursor,
                    header.end,
                    index_size,
                    "read iloc extent index",
                )?;
            }
            let extent_offset = take_uint(
                reader,
                &mut cursor,
                header.end,
                offset_size,
                "read iloc extent offset",
            )?;
            let extent_length = take_uint(
                reader,
                &mut cursor,
                header.end,
                length_size,
                "read iloc extent length",
            )?;
            if extent_length == 0 {
                return Err(ParseError::invalid(
                    item_offset,
                    "Exif item extent has no length",
                ));
            }
            let absolute = checked_add(
                base_offset,
                extent_offset,
                Some(item_offset),
                "Exif item offset overflow",
            )?;
            return Ok(ItemLocation {
                offset: absolute,
                length: extent_length,
            });
        }

        // Skip this item's extent table without reading it.
        let per_extent = checked_add(
            checked_add(
                index_size,
                offset_size,
                Some(item_offset),
                "iloc extent width overflow",
            )?,
            length_size,
            Some(item_offset),
            "iloc extent width overflow",
        )?;
        let extent_bytes = checked_mul(
            extent_count,
            per_extent,
            Some(item_offset),
            "iloc extent table overflow",
        )?;
        let next = checked_add(
            cursor,
            extent_bytes,
            Some(item_offset),
            "iloc cursor overflow",
        )?;
        if next > header.end {
            return Err(ParseError::out_of_bounds(item_offset, "iloc extent table"));
        }
        cursor = next;
    }

    Err(ParseError::invalid(
        header.offset,
        "Exif item location is missing",
    ))
}

/// Read the located Exif item payload: a four-byte big-endian TIFF header
/// offset followed by the Exif payload, per HEIF `ExifDataBlock`.
fn extract_exif_item(
    reader: &mut BudgetedReader<'_>,
    location: ItemLocation,
    emit: &mut Emit<'_>,
) -> Result<(), ParseError> {
    let end = checked_add(
        location.offset,
        location.length,
        Some(location.offset),
        "Exif item range overflow",
    )?;
    if end > reader.source_len() {
        return Err(ParseError::out_of_bounds(
            location.offset,
            "Exif item extent",
        ));
    }
    if location.length <= EXIF_ITEM_PREFIX_BYTES {
        return Err(ParseError::invalid(
            location.offset,
            "Exif item payload is too small",
        ));
    }
    let prefix = reader.read_vec(
        location.offset,
        EXIF_ITEM_PREFIX_BYTES,
        "read Exif item header offset",
    )?;
    let tiff_delta = u64::from(u32::from_be_bytes([
        prefix[0], prefix[1], prefix[2], prefix[3],
    ]));
    let after_prefix = checked_add(
        location.offset,
        EXIF_ITEM_PREFIX_BYTES,
        Some(location.offset),
        "Exif item prefix overflow",
    )?;
    let tiff_header = checked_add(
        after_prefix,
        tiff_delta,
        Some(location.offset),
        "Exif TIFF header offset overflow",
    )?;
    if tiff_header >= end {
        return Err(ParseError::invalid(
            location.offset,
            "Exif TIFF header offset is outside the item",
        ));
    }
    tiff::parse_in_range(
        reader,
        tiff_header,
        end,
        TiffOrigin::Direct,
        emit.fields,
        emit.issues,
    )
}

fn take_bytes(
    reader: &mut BudgetedReader<'_>,
    cursor: &mut u64,
    end: u64,
    length: u64,
    context: &'static str,
) -> Result<Vec<u8>, ParseError> {
    let next = checked_add(*cursor, length, Some(*cursor), "BMFF table cursor overflow")?;
    if next > end {
        return Err(ParseError::out_of_bounds(*cursor, context));
    }
    let bytes = reader.read_vec(*cursor, length, context)?;
    *cursor = next;
    Ok(bytes)
}

fn take_u16(
    reader: &mut BudgetedReader<'_>,
    cursor: &mut u64,
    end: u64,
    context: &'static str,
) -> Result<u16, ParseError> {
    let bytes = take_bytes(reader, cursor, end, 2, context)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take_u32(
    reader: &mut BudgetedReader<'_>,
    cursor: &mut u64,
    end: u64,
    context: &'static str,
) -> Result<u32, ParseError> {
    let bytes = take_bytes(reader, cursor, end, 4, context)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read an unsigned big-endian integer whose width was validated to be 0, 4,
/// or 8 bytes. Width 0 reads nothing and yields 0.
fn take_uint(
    reader: &mut BudgetedReader<'_>,
    cursor: &mut u64,
    end: u64,
    size: u64,
    context: &'static str,
) -> Result<u64, ParseError> {
    if size == 0 {
        return Ok(0);
    }
    let bytes = take_bytes(reader, cursor, end, size, context)?;
    let mut padded = [0_u8; 8];
    let start = padded
        .len()
        .checked_sub(bytes.len())
        .ok_or_else(|| ParseError::overflow(Some(*cursor), "BMFF integer exceeds eight bytes"))?;
    padded[start..].copy_from_slice(&bytes);
    Ok(u64::from_be_bytes(padded))
}

fn parse_keys(reader: &mut BudgetedReader<'_>, header: BoxHeader) -> Result<Vec<bool>, ParseError> {
    if header.payload_len()? < 8 {
        return Err(ParseError::out_of_bounds(
            header.payload_offset,
            "keys full-box payload",
        ));
    }
    let prefix = reader.read_vec(header.payload_offset, 8, "read keys header")?;
    if prefix[0] != 0 {
        return Err(ParseError::unsupported_version(
            header.payload_offset,
            "keys version",
        ));
    }
    let count = u32::from_be_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]);
    if count > reader.limits().max_bmff_boxes {
        return Err(ParseError::limit(
            Some(header.payload_offset),
            "QuickTime metadata key count limit",
        ));
    }
    let capacity = usize::try_from(count).map_err(|_| {
        ParseError::limit(
            Some(header.payload_offset),
            "QuickTime key count does not fit usize",
        )
    })?;
    let mut recognized = Vec::with_capacity(capacity);
    let mut cursor = checked_add(
        header.payload_offset,
        8,
        Some(header.payload_offset),
        "keys entry offset overflow",
    )?;

    for _ in 0..count {
        reader.visit_bmff_box(cursor)?;
        let entry_header_end = checked_add(
            cursor,
            8,
            Some(cursor),
            "QuickTime key entry header end overflow",
        )?;
        if entry_header_end > header.end {
            return Err(ParseError::out_of_bounds(
                cursor,
                "QuickTime key entry header",
            ));
        }
        let entry_header = reader.read_vec(cursor, 8, "read QuickTime key entry")?;
        let entry_size = u64::from(u32::from_be_bytes([
            entry_header[0],
            entry_header[1],
            entry_header[2],
            entry_header[3],
        ]));
        if entry_size < 8 {
            return Err(ParseError::invalid(cursor, "QuickTime key entry size"));
        }
        let entry_end = checked_add(
            cursor,
            entry_size,
            Some(cursor),
            "QuickTime key entry end overflow",
        )?;
        if entry_end > header.end {
            return Err(ParseError::out_of_bounds(cursor, "QuickTime key entry"));
        }
        let key_length = checked_sub(entry_size, 8, Some(cursor), "QuickTime key entry payload")?;
        let namespace = &entry_header[4..8];
        let is_creation_date = if namespace == b"mdta"
            && key_length
                == u64::try_from(CREATION_DATE_KEY.len()).map_err(|_| {
                    ParseError::overflow(Some(cursor), "creation-date key length overflow")
                })? {
            let key_offset = checked_add(
                cursor,
                8,
                Some(cursor),
                "QuickTime key bytes offset overflow",
            )?;
            reader.read_vec(key_offset, key_length, "read QuickTime key bytes")?
                == CREATION_DATE_KEY
        } else {
            false
        };
        recognized.push(is_creation_date);
        cursor = entry_end;
    }

    if cursor != header.end {
        return Err(ParseError::invalid(
            cursor,
            "trailing bytes in QuickTime keys box",
        ));
    }
    Ok(recognized)
}

fn parse_ilst(
    reader: &mut BudgetedReader<'_>,
    header: BoxHeader,
    parent_depth: u16,
    recognized_keys: &[bool],
    emit: &mut Emit<'_>,
) -> Result<(), ParseError> {
    let depth = parent_depth
        .checked_add(1)
        .ok_or_else(|| ParseError::overflow(Some(header.offset), "BMFF depth overflow"))?;
    reader.observe_depth(
        depth,
        reader.limits().max_bmff_depth,
        header.payload_offset,
        "BMFF nesting depth limit",
    )?;
    let mut cursor = header.payload_offset;
    while cursor < header.end {
        let item = read_box_header(reader, cursor, header.end)?;
        let key_index = u32::from_be_bytes(item.box_type);
        let recognized_index = key_index
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| recognized_keys.get(index))
            .copied()
            .unwrap_or(false);
        let recognized = item.box_type == COPYRIGHT_DAY || recognized_index;
        if recognized {
            emit.path.push(item.box_type);
            let parsed = parse_metadata_item(reader, item, depth, emit);
            emit.path.pop();
            parsed?;
        }
        cursor = item.end;
    }
    Ok(())
}

fn parse_metadata_item(
    reader: &mut BudgetedReader<'_>,
    item: BoxHeader,
    parent_depth: u16,
    emit: &mut Emit<'_>,
) -> Result<(), ParseError> {
    let depth = parent_depth
        .checked_add(1)
        .ok_or_else(|| ParseError::overflow(Some(item.offset), "BMFF depth overflow"))?;
    reader.observe_depth(
        depth,
        reader.limits().max_bmff_depth,
        item.payload_offset,
        "BMFF nesting depth limit",
    )?;
    let mut cursor = item.payload_offset;
    while cursor < item.end {
        let data = read_box_header(reader, cursor, item.end)?;
        if data.box_type == *b"data" {
            if data.payload_len()? <= QUICKTIME_DATA_HEADER_BYTES {
                return Err(ParseError::invalid(
                    data.payload_offset,
                    "QuickTime data atom payload",
                ));
            }
            let data_header = reader.read_vec(
                data.payload_offset,
                QUICKTIME_DATA_HEADER_BYTES,
                "read QuickTime data header",
            )?;
            let data_type = u32::from_be_bytes([
                data_header[0],
                data_header[1],
                data_header[2],
                data_header[3],
            ]);
            if data_type != 1 {
                return Err(ParseError::invalid(
                    data.payload_offset,
                    "QuickTime creation date is not UTF-8 text",
                ));
            }
            let value_offset = checked_add(
                data.payload_offset,
                QUICKTIME_DATA_HEADER_BYTES,
                Some(data.payload_offset),
                "QuickTime text offset overflow",
            )?;
            let value_length = checked_sub(
                data.end,
                value_offset,
                Some(value_offset),
                "QuickTime text range",
            )?;
            let raw_bytes = reader.read_field_bytes(value_offset, value_length)?;
            std::str::from_utf8(&raw_bytes).map_err(|_| {
                ParseError::invalid(
                    value_offset,
                    "QuickTime creation date contains invalid UTF-8",
                )
            })?;
            let mut box_path = emit.path.clone();
            box_path.push(data.box_type);
            emit.fields.push(MetadataField {
                parser: PARSER_IDENTITY,
                kind: MetadataFieldKind::QuickTimeMetadataCreationDate,
                encoding: FieldEncoding::ValidatedUtf8,
                locator: MetadataLocator {
                    absolute_offset: value_offset,
                    byte_len: value_length,
                    container: MetadataContainer::IsoBmff {
                        box_offset: data.offset,
                        box_path,
                    },
                },
                raw_bytes,
            });
        }
        cursor = data.end;
    }
    Ok(())
}

fn parse_legacy_copyright_day(
    reader: &mut BudgetedReader<'_>,
    header: BoxHeader,
    emit: &mut Emit<'_>,
) -> Result<(), ParseError> {
    if header.payload_len()? < 4 {
        return Err(ParseError::out_of_bounds(
            header.payload_offset,
            "legacy QuickTime date header",
        ));
    }
    let prefix = reader.read_vec(
        header.payload_offset,
        4,
        "read legacy QuickTime date header",
    )?;
    let value_length = u64::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    if value_length == 0 {
        return Err(ParseError::invalid(
            header.payload_offset,
            "empty legacy QuickTime creation date",
        ));
    }
    let value_offset = checked_add(
        header.payload_offset,
        4,
        Some(header.payload_offset),
        "legacy QuickTime date offset overflow",
    )?;
    let value_end = checked_add(
        value_offset,
        value_length,
        Some(value_offset),
        "legacy QuickTime date end overflow",
    )?;
    if value_end > header.end {
        return Err(ParseError::out_of_bounds(
            value_offset,
            "legacy QuickTime creation date",
        ));
    }
    let raw_bytes = reader.read_field_bytes(value_offset, value_length)?;
    std::str::from_utf8(&raw_bytes).map_err(|_| {
        ParseError::invalid(
            value_offset,
            "legacy QuickTime creation date contains invalid UTF-8",
        )
    })?;
    let box_path = emit.path.clone();
    emit.fields.push(MetadataField {
        parser: PARSER_IDENTITY,
        kind: MetadataFieldKind::QuickTimeMetadataCreationDate,
        encoding: FieldEncoding::ValidatedUtf8,
        locator: MetadataLocator {
            absolute_offset: value_offset,
            byte_len: value_length,
            container: MetadataContainer::IsoBmff {
                box_offset: header.offset,
                box_path,
            },
        },
        raw_bytes,
    });
    Ok(())
}

fn read_box_header(
    reader: &mut BudgetedReader<'_>,
    offset: u64,
    parent_end: u64,
) -> Result<BoxHeader, ParseError> {
    if offset >= parent_end {
        return Err(ParseError::out_of_bounds(offset, "BMFF box header"));
    }
    let minimum_end = checked_add(
        offset,
        BOX_HEADER_BYTES,
        Some(offset),
        "BMFF header end overflow",
    )?;
    if minimum_end > parent_end {
        return Err(ParseError::out_of_bounds(
            offset,
            "truncated BMFF box header",
        ));
    }
    let basic = reader.read_vec(offset, BOX_HEADER_BYTES, "read BMFF box header")?;
    reader.visit_bmff_box(offset)?;
    let size32 = u32::from_be_bytes([basic[0], basic[1], basic[2], basic[3]]);
    let box_type = [basic[4], basic[5], basic[6], basic[7]];

    let (size, mut header_size) = match size32 {
        0 => (
            checked_sub(parent_end, offset, Some(offset), "BMFF size-zero box range")?,
            BOX_HEADER_BYTES,
        ),
        1 => {
            let extended_end = checked_add(
                minimum_end,
                8,
                Some(offset),
                "BMFF extended header end overflow",
            )?;
            if extended_end > parent_end {
                return Err(ParseError::out_of_bounds(
                    offset,
                    "truncated BMFF extended-size header",
                ));
            }
            let extended = reader.read_vec(minimum_end, 8, "read BMFF extended-size box header")?;
            (
                u64::from_be_bytes([
                    extended[0],
                    extended[1],
                    extended[2],
                    extended[3],
                    extended[4],
                    extended[5],
                    extended[6],
                    extended[7],
                ]),
                EXTENDED_BOX_HEADER_BYTES,
            )
        }
        value => (u64::from(value), BOX_HEADER_BYTES),
    };
    if box_type == *b"uuid" {
        header_size = checked_add(
            header_size,
            UUID_USER_TYPE_BYTES,
            Some(offset),
            "UUID box header size overflow",
        )?;
    }
    if size < header_size {
        return Err(ParseError::invalid(
            offset,
            "BMFF box size smaller than header",
        ));
    }
    let end = checked_add(offset, size, Some(offset), "BMFF box end overflow")?;
    if end > parent_end {
        return Err(ParseError::out_of_bounds(offset, "BMFF box exceeds parent"));
    }
    let payload_offset = checked_add(
        offset,
        header_size,
        Some(offset),
        "BMFF payload offset overflow",
    )?;
    Ok(BoxHeader {
        offset,
        box_type,
        payload_offset,
        end,
    })
}
