use std::collections::HashSet;

use crate::reader::{checked_add, checked_mul, BudgetedReader, ParseError, ParseOutcome};
use crate::{
    FieldEncoding, MetadataContainer, MetadataField, MetadataFieldKind, MetadataLocator,
    TiffByteOrder, PARSER_IDENTITY,
};

const TIFF_HEADER_BYTES: u64 = 8;
const IFD_ENTRY_BYTES: u64 = 12;
const IFD_NEXT_POINTER_BYTES: u64 = 4;

const TAG_MODIFY_DATE: u16 = 0x0132;
const TAG_EXIF_IFD: u16 = 0x8769;
const TAG_DATE_TIME_ORIGINAL: u16 = 0x9003;
const TAG_CREATE_DATE: u16 = 0x9004;
const TAG_OFFSET_TIME_ORIGINAL: u16 = 0x9011;
const TAG_SUBSEC_TIME_ORIGINAL: u16 = 0x9291;

const TIFF_TYPE_ASCII: u16 = 2;
const TIFF_TYPE_LONG: u16 = 4;

#[derive(Clone, Copy, Debug)]
pub(crate) enum TiffOrigin {
    Direct,
    Jpeg { app1_offset: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IfdRole {
    Primary,
    Exif,
    Other,
}

#[derive(Clone, Copy, Debug)]
struct IfdTask {
    relative_offset: u64,
    role: IfdRole,
    depth: u16,
}

/// Shared, copyable location facts for one TIFF container walk.
#[derive(Clone, Copy, Debug)]
struct TiffWalk {
    header_offset: u64,
    container_end: u64,
    byte_order: TiffByteOrder,
    origin: TiffOrigin,
}

pub(crate) fn parse_direct(reader: &mut BudgetedReader<'_>) -> Result<ParseOutcome, ParseError> {
    let mut outcome = ParseOutcome::default();
    match parse_in_range(
        reader,
        0,
        reader.source_len(),
        TiffOrigin::Direct,
        &mut outcome.fields,
        &mut outcome.issues,
    ) {
        Ok(()) => Ok(outcome),
        Err(error) if error.is_structural() => {
            outcome.issues.push(error);
            Ok(outcome)
        }
        Err(error) => Err(error),
    }
}

/// Walk one TIFF container. Structural problems local to one IFD or one entry
/// are appended to `issues` and the walk continues; already extracted fields
/// stay in `fields`. Only non-structural failures are returned as `Err`.
pub(crate) fn parse_in_range(
    reader: &mut BudgetedReader<'_>,
    header_offset: u64,
    container_end: u64,
    origin: TiffOrigin,
    fields: &mut Vec<MetadataField>,
    issues: &mut Vec<ParseError>,
) -> Result<(), ParseError> {
    if container_end > reader.source_len() || header_offset > container_end {
        return Err(ParseError::out_of_bounds(
            header_offset,
            "TIFF container range",
        ));
    }
    ensure_in_container(
        header_offset,
        TIFF_HEADER_BYTES,
        container_end,
        "TIFF header",
    )?;
    let header = reader.read_vec(header_offset, TIFF_HEADER_BYTES, "read TIFF header")?;
    let byte_order = match &header[..2] {
        b"II" => TiffByteOrder::LittleEndian,
        b"MM" => TiffByteOrder::BigEndian,
        _ => return Err(ParseError::invalid(header_offset, "TIFF byte-order marker")),
    };
    if read_u16(byte_order, &header[2..4]) != 42 {
        return Err(ParseError::invalid(header_offset, "TIFF magic number"));
    }

    let first_ifd = u64::from(read_u32(byte_order, &header[4..8]));
    if first_ifd == 0 {
        return Ok(());
    }

    let walk = TiffWalk {
        header_offset,
        container_end,
        byte_order,
        origin,
    };
    let mut visited = HashSet::new();
    let mut pending = vec![IfdTask {
        relative_offset: first_ifd,
        role: IfdRole::Primary,
        depth: 1,
    }];

    while let Some(task) = pending.pop() {
        match process_ifd(
            reader,
            walk,
            task,
            &mut visited,
            &mut pending,
            fields,
            issues,
        ) {
            Ok(()) => {}
            Err(error) if error.is_structural() => issues.push(error),
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn process_ifd(
    reader: &mut BudgetedReader<'_>,
    walk: TiffWalk,
    task: IfdTask,
    visited: &mut HashSet<u64>,
    pending: &mut Vec<IfdTask>,
    fields: &mut Vec<MetadataField>,
    issues: &mut Vec<ParseError>,
) -> Result<(), ParseError> {
    let ifd_offset = checked_add(
        walk.header_offset,
        task.relative_offset,
        Some(walk.header_offset),
        "TIFF IFD offset overflow",
    )?;
    if task.relative_offset < TIFF_HEADER_BYTES {
        return Err(ParseError::invalid(
            ifd_offset,
            "TIFF IFD points into header",
        ));
    }
    if !visited.insert(ifd_offset) {
        return Err(ParseError::cycle(ifd_offset, "TIFF IFD pointer cycle"));
    }
    reader.observe_depth(
        task.depth,
        reader.limits().max_ifd_depth,
        ifd_offset,
        "TIFF IFD depth limit",
    )?;

    ensure_in_container(ifd_offset, 2, walk.container_end, "TIFF IFD entry count")?;
    let count_bytes = reader.read_vec(ifd_offset, 2, "read TIFF IFD entry count")?;
    let count = u32::from(read_u16(walk.byte_order, &count_bytes));
    reader.visit_ifd_entries(ifd_offset, count)?;

    let entries_bytes = checked_mul(
        u64::from(count),
        IFD_ENTRY_BYTES,
        Some(ifd_offset),
        "TIFF IFD table length overflow",
    )?;
    let table_bytes = checked_add(
        entries_bytes,
        IFD_NEXT_POINTER_BYTES,
        Some(ifd_offset),
        "TIFF IFD table length overflow",
    )?;
    let table_offset = checked_add(
        ifd_offset,
        2,
        Some(ifd_offset),
        "TIFF IFD table offset overflow",
    )?;
    ensure_in_container(
        table_offset,
        table_bytes,
        walk.container_end,
        "TIFF IFD table",
    )?;
    let table = reader.read_vec(table_offset, table_bytes, "read TIFF IFD table")?;
    let entries_len = usize::try_from(entries_bytes)
        .map_err(|_| ParseError::limit(Some(table_offset), "TIFF IFD table does not fit usize"))?;

    let mut exif_ifd = None;
    for (index, entry) in table[..entries_len].chunks_exact(12).enumerate() {
        let index_u64 = u64::try_from(index).map_err(|_| {
            ParseError::overflow(Some(table_offset), "TIFF IFD index does not fit u64")
        })?;
        let entry_delta = checked_mul(
            index_u64,
            IFD_ENTRY_BYTES,
            Some(table_offset),
            "TIFF entry offset overflow",
        )?;
        let entry_offset = checked_add(
            table_offset,
            entry_delta,
            Some(table_offset),
            "TIFF entry offset overflow",
        )?;
        let tag = read_u16(walk.byte_order, &entry[0..2]);
        let field_type = read_u16(walk.byte_order, &entry[2..4]);
        let value_count = read_u32(walk.byte_order, &entry[4..8]);

        if tag == TAG_EXIF_IFD && task.role == IfdRole::Primary {
            if field_type != TIFF_TYPE_LONG || value_count != 1 {
                issues.push(ParseError::invalid(
                    entry_offset,
                    "Exif IFD pointer type/count",
                ));
                continue;
            }
            let relative = u64::from(read_u32(walk.byte_order, &entry[8..12]));
            if relative == 0 {
                continue;
            }
            if exif_ifd.is_some() {
                issues.push(ParseError::invalid(
                    entry_offset,
                    "duplicate Exif IFD pointer",
                ));
            } else {
                exif_ifd = Some(relative);
            }
            continue;
        }

        let Some(kind) = field_kind(task.role, tag) else {
            continue;
        };
        match extract_timestamp_field(reader, walk, ifd_offset, entry_offset, entry, kind) {
            Ok(field) => fields.push(field),
            Err(error) if error.is_structural() => issues.push(error),
            Err(error) => return Err(error),
        }
    }

    let next_relative = u64::from(read_u32(walk.byte_order, &table[entries_len..]));
    let next_depth = task
        .depth
        .checked_add(1)
        .ok_or_else(|| ParseError::overflow(Some(ifd_offset), "TIFF IFD depth overflow"))?;
    if next_relative != 0 {
        pending.push(IfdTask {
            relative_offset: next_relative,
            role: IfdRole::Other,
            depth: next_depth,
        });
    }
    if let Some(relative_offset) = exif_ifd {
        pending.push(IfdTask {
            relative_offset,
            role: IfdRole::Exif,
            depth: next_depth,
        });
    }
    Ok(())
}

fn extract_timestamp_field(
    reader: &mut BudgetedReader<'_>,
    walk: TiffWalk,
    ifd_offset: u64,
    entry_offset: u64,
    entry: &[u8],
    kind: MetadataFieldKind,
) -> Result<MetadataField, ParseError> {
    let tag = read_u16(walk.byte_order, &entry[0..2]);
    let field_type = read_u16(walk.byte_order, &entry[2..4]);
    let value_count = read_u32(walk.byte_order, &entry[4..8]);
    if field_type != TIFF_TYPE_ASCII || value_count == 0 {
        return Err(ParseError::invalid(
            entry_offset,
            "timestamp field is not non-empty TIFF ASCII",
        ));
    }
    let value_length = u64::from(value_count);
    let value_offset = if value_length <= 4 {
        checked_add(
            entry_offset,
            8,
            Some(entry_offset),
            "inline TIFF value offset overflow",
        )?
    } else {
        checked_add(
            walk.header_offset,
            u64::from(read_u32(walk.byte_order, &entry[8..12])),
            Some(entry_offset),
            "external TIFF value offset overflow",
        )?
    };
    ensure_in_container(
        value_offset,
        value_length,
        walk.container_end,
        "TIFF timestamp value",
    )?;
    let raw_bytes = reader.read_field_bytes(value_offset, value_length)?;
    let container = match walk.origin {
        TiffOrigin::Direct => MetadataContainer::Tiff {
            header_offset: walk.header_offset,
            ifd_offset,
            tag,
            byte_order: walk.byte_order,
        },
        TiffOrigin::Jpeg { app1_offset } => MetadataContainer::JpegExif {
            app1_offset,
            header_offset: walk.header_offset,
            ifd_offset,
            tag,
            byte_order: walk.byte_order,
        },
    };
    Ok(MetadataField {
        parser: PARSER_IDENTITY,
        kind,
        encoding: FieldEncoding::DeclaredAscii,
        locator: MetadataLocator {
            absolute_offset: value_offset,
            byte_len: value_length,
            container,
        },
        raw_bytes,
    })
}

fn field_kind(role: IfdRole, tag: u16) -> Option<MetadataFieldKind> {
    match (role, tag) {
        (IfdRole::Primary, TAG_MODIFY_DATE) => Some(MetadataFieldKind::ExifModifyDate),
        (IfdRole::Exif, TAG_DATE_TIME_ORIGINAL) => Some(MetadataFieldKind::ExifDateTimeOriginal),
        (IfdRole::Exif, TAG_CREATE_DATE) => Some(MetadataFieldKind::ExifCreateDate),
        (IfdRole::Exif, TAG_OFFSET_TIME_ORIGINAL) => {
            Some(MetadataFieldKind::ExifOffsetTimeOriginal)
        }
        (IfdRole::Exif, TAG_SUBSEC_TIME_ORIGINAL) => {
            Some(MetadataFieldKind::ExifSubSecTimeOriginal)
        }
        _ => None,
    }
}

fn ensure_in_container(
    offset: u64,
    length: u64,
    container_end: u64,
    context: &'static str,
) -> Result<(), ParseError> {
    let end = checked_add(offset, length, Some(offset), "TIFF range overflow")?;
    if end > container_end {
        return Err(ParseError::out_of_bounds(offset, context));
    }
    Ok(())
}

fn read_u16(byte_order: TiffByteOrder, bytes: &[u8]) -> u16 {
    let value = [bytes[0], bytes[1]];
    match byte_order {
        TiffByteOrder::LittleEndian => u16::from_le_bytes(value),
        TiffByteOrder::BigEndian => u16::from_be_bytes(value),
    }
}

fn read_u32(byte_order: TiffByteOrder, bytes: &[u8]) -> u32 {
    let value = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match byte_order {
        TiffByteOrder::LittleEndian => u32::from_le_bytes(value),
        TiffByteOrder::BigEndian => u32::from_be_bytes(value),
    }
}
