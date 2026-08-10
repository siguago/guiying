use crate::reader::{checked_add, checked_sub, BudgetedReader, ParseError};
use crate::{
    FieldEncoding, MetadataContainer, MetadataField, MetadataFieldKind, MetadataLocator,
    PARSER_IDENTITY,
};

const BOX_HEADER_BYTES: u64 = 8;
const EXTENDED_BOX_HEADER_BYTES: u64 = 16;
const UUID_USER_TYPE_BYTES: u64 = 16;
const FULL_BOX_HEADER_BYTES: u64 = 4;
const QUICKTIME_DATA_HEADER_BYTES: u64 = 8;
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

pub(crate) fn parse(reader: &mut BudgetedReader<'_>) -> Result<Vec<MetadataField>, ParseError> {
    let mut fields = Vec::new();
    let mut path = Vec::new();
    walk_range(
        reader,
        0,
        reader.source_len(),
        1,
        WalkContext::Root,
        &mut path,
        &mut fields,
    )?;
    Ok(fields)
}

fn walk_range(
    reader: &mut BudgetedReader<'_>,
    start: u64,
    end: u64,
    depth: u16,
    context: WalkContext,
    path: &mut Vec<[u8; 4]>,
    fields: &mut Vec<MetadataField>,
) -> Result<(), ParseError> {
    reader.observe_depth(
        depth,
        reader.limits().max_bmff_depth,
        start,
        "BMFF nesting depth limit",
    )?;
    let mut cursor = start;
    while cursor < end {
        let header = read_box_header(reader, cursor, end)?;
        path.push(header.box_type);
        match (context, &header.box_type) {
            (WalkContext::Root, b"moov") | (WalkContext::Movie, b"udta") => {
                let child_depth = depth.checked_add(1).ok_or_else(|| {
                    ParseError::overflow(Some(header.offset), "BMFF nesting depth overflow")
                })?;
                let child_context = if context == WalkContext::Root {
                    WalkContext::Movie
                } else {
                    WalkContext::UserData
                };
                walk_range(
                    reader,
                    header.payload_offset,
                    header.end,
                    child_depth,
                    child_context,
                    path,
                    fields,
                )?;
            }
            (WalkContext::Movie, b"mvhd") => parse_mvhd(reader, header, path, fields)?,
            (WalkContext::Movie | WalkContext::UserData, b"meta") => {
                parse_meta(reader, header, depth, path, fields)?;
            }
            (WalkContext::UserData, value) if *value == COPYRIGHT_DAY => {
                parse_legacy_copyright_day(reader, header, path, fields)?;
            }
            _ => {}
        }
        path.pop();
        cursor = header.end;
    }
    Ok(())
}

fn parse_mvhd(
    reader: &mut BudgetedReader<'_>,
    header: BoxHeader,
    path: &[[u8; 4]],
    fields: &mut Vec<MetadataField>,
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
    fields.push(MetadataField {
        parser: PARSER_IDENTITY,
        kind: MetadataFieldKind::QuickTimeMovieHeaderCreationTime,
        encoding: FieldEncoding::UnsignedBigEndian,
        locator: MetadataLocator {
            absolute_offset: value_offset,
            byte_len: value_length,
            container: MetadataContainer::IsoBmff {
                box_offset: header.offset,
                box_path: path.to_vec(),
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
    path: &mut Vec<[u8; 4]>,
    fields: &mut Vec<MetadataField>,
) -> Result<(), ParseError> {
    if header.payload_len()? < FULL_BOX_HEADER_BYTES {
        return Err(ParseError::out_of_bounds(
            header.payload_offset,
            "meta full-box header",
        ));
    }
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
    let children_start = checked_add(
        header.payload_offset,
        FULL_BOX_HEADER_BYTES,
        Some(header.payload_offset),
        "meta children offset overflow",
    )?;
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
            path.push(child.box_type);
            parse_ilst(reader, child, child_depth, path, &recognized_keys, fields)?;
            path.pop();
        }
    }
    Ok(())
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
    path: &mut Vec<[u8; 4]>,
    recognized_keys: &[bool],
    fields: &mut Vec<MetadataField>,
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
            path.push(item.box_type);
            parse_metadata_item(reader, item, depth, path, fields)?;
            path.pop();
        }
        cursor = item.end;
    }
    Ok(())
}

fn parse_metadata_item(
    reader: &mut BudgetedReader<'_>,
    item: BoxHeader,
    parent_depth: u16,
    path: &[[u8; 4]],
    fields: &mut Vec<MetadataField>,
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
            let mut box_path = path.to_vec();
            box_path.push(data.box_type);
            fields.push(MetadataField {
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
    path: &[[u8; 4]],
    fields: &mut Vec<MetadataField>,
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
    fields.push(MetadataField {
        parser: PARSER_IDENTITY,
        kind: MetadataFieldKind::QuickTimeMetadataCreationDate,
        encoding: FieldEncoding::ValidatedUtf8,
        locator: MetadataLocator {
            absolute_offset: value_offset,
            byte_len: value_length,
            container: MetadataContainer::IsoBmff {
                box_offset: header.offset,
                box_path: path.to_vec(),
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
