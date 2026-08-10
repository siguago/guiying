use crate::reader::{checked_add, checked_sub, BudgetedReader, ParseError};
use crate::tiff::{self, TiffOrigin};
use crate::MetadataField;

const MARKER_PREFIX: u8 = 0xff;
const MARKER_SOI: u8 = 0xd8;
const MARKER_EOI: u8 = 0xd9;
const MARKER_SOS: u8 = 0xda;
const MARKER_APP1: u8 = 0xe1;

pub(crate) fn parse(reader: &mut BudgetedReader<'_>) -> Result<Vec<MetadataField>, ParseError> {
    let soi = reader.read_vec(0, 2, "read JPEG SOI")?;
    if soi != [MARKER_PREFIX, MARKER_SOI] {
        return Err(ParseError::invalid(0, "JPEG SOI marker"));
    }

    let mut fields = Vec::new();
    let mut cursor = 2_u64;
    loop {
        if cursor >= reader.source_len() {
            return Err(ParseError::out_of_bounds(cursor, "JPEG marker prefix"));
        }
        let marker_offset = cursor;
        let prefix = reader.read_vec(cursor, 1, "read JPEG marker prefix")?[0];
        if prefix != MARKER_PREFIX {
            return Err(ParseError::invalid(cursor, "JPEG marker prefix"));
        }

        loop {
            cursor = checked_add(cursor, 1, Some(cursor), "JPEG marker offset overflow")?;
            if cursor >= reader.source_len() {
                return Err(ParseError::out_of_bounds(cursor, "JPEG marker code"));
            }
            let code = reader.read_vec(cursor, 1, "read JPEG marker code")?[0];
            if code == MARKER_PREFIX {
                continue;
            }
            if code == 0x00 {
                return Err(ParseError::invalid(
                    cursor,
                    "stuffed JPEG marker outside scan data",
                ));
            }
            let code_offset = cursor;
            cursor = checked_add(cursor, 1, Some(cursor), "JPEG marker offset overflow")?;
            reader.visit_jpeg_segment(marker_offset)?;

            match code {
                MARKER_EOI | MARKER_SOS => return Ok(fields),
                0x01 | 0xd0..=0xd7 => break,
                MARKER_SOI => {
                    return Err(ParseError::invalid(code_offset, "nested JPEG SOI marker"));
                }
                _ => {
                    let length_bytes = reader.read_vec(cursor, 2, "read JPEG segment length")?;
                    let segment_length =
                        u64::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
                    if segment_length < 2 {
                        return Err(ParseError::invalid(cursor, "JPEG segment length"));
                    }
                    let payload_offset =
                        checked_add(cursor, 2, Some(cursor), "JPEG payload offset overflow")?;
                    let payload_length = checked_sub(
                        segment_length,
                        2,
                        Some(cursor),
                        "JPEG segment length is smaller than header",
                    )?;
                    let segment_end = checked_add(
                        payload_offset,
                        payload_length,
                        Some(payload_offset),
                        "JPEG segment end overflow",
                    )?;
                    if segment_end > reader.source_len() {
                        return Err(ParseError::out_of_bounds(cursor, "JPEG segment payload"));
                    }

                    if code == MARKER_APP1 && payload_length >= 6 {
                        let signature =
                            reader.read_vec(payload_offset, 6, "read JPEG APP1 signature")?;
                        if signature == b"Exif\0\0" {
                            let header_offset = checked_add(
                                payload_offset,
                                6,
                                Some(payload_offset),
                                "JPEG Exif TIFF offset overflow",
                            )?;
                            let mut app1_fields = tiff::parse_in_range(
                                reader,
                                header_offset,
                                segment_end,
                                TiffOrigin::Jpeg {
                                    app1_offset: marker_offset,
                                },
                            )?;
                            fields.append(&mut app1_fields);
                        }
                    }
                    cursor = segment_end;
                    break;
                }
            }
        }
    }
}
