use crate::{
    calendar, NormalizedTimestamp, TimePrecision, UtcInstant, UtcOffset, WallTime, NANOS_PER_SECOND,
};

const QUICKTIME_TO_UNIX_SECONDS: i128 = 2_082_844_800;

/// Strict timestamp parsing failure. Raw bytes remain in the observation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TimestampParseError {
    Empty,
    InvalidEncoding,
    InvalidSyntax,
    YearOutOfRange,
    MonthOutOfRange,
    DayOutOfRange,
    HourOutOfRange,
    MinuteOutOfRange,
    SecondOutOfRange,
    NanosecondOutOfRange,
    SubsecondOutOfRange,
    OffsetOutOfRange,
    UnknownNegativeZeroOffset,
    PrecisionOutOfRange,
    UnsupportedBinaryLength,
    ArithmeticOverflow,
}

/// Parse Exif `YYYY:MM:DD HH:MM:SS` with optional SubSecTimeOriginal and
/// OffsetTimeOriginal. Missing offset deliberately returns a floating value.
pub fn parse_exif_timestamp(
    datetime: &[u8],
    subsecond: Option<&[u8]>,
    offset: Option<&[u8]>,
) -> Result<NormalizedTimestamp, TimestampParseError> {
    let text = trim_ascii_field(datetime)?;
    if text.len() != 19
        || text.get(4) != Some(&b':')
        || text.get(7) != Some(&b':')
        || text.get(10) != Some(&b' ')
        || text.get(13) != Some(&b':')
        || text.get(16) != Some(&b':')
    {
        return Err(TimestampParseError::InvalidSyntax);
    }

    let mut wall = WallTime::new(
        parse_u16(&text[0..4])?,
        parse_u8(&text[5..7])?,
        parse_u8(&text[8..10])?,
        parse_u8(&text[11..13])?,
        parse_u8(&text[14..16])?,
        parse_u8(&text[17..19])?,
        0,
    )?;

    let precision = if let Some(raw) = subsecond {
        let (nanosecond, _, precision) = parse_subsecond(raw)?;
        wall = wall.with_nanosecond(nanosecond)?;
        precision
    } else {
        TimePrecision::seconds()
    };

    match offset {
        Some(raw) => NormalizedTimestamp::explicit(wall, parse_offset(raw)?, precision),
        None => Ok(NormalizedTimestamp::floating(wall, precision)),
    }
}

/// Parse a strict QuickTime ISO-8601 timestamp. `Z` and `±HH:MM` are
/// supported. A missing offset is retained as floating rather than guessed.
pub fn parse_quicktime_timestamp(raw: &[u8]) -> Result<NormalizedTimestamp, TimestampParseError> {
    let text = trim_utf8_field(raw)?;
    if text.len() < 19
        || text.get(4) != Some(&b'-')
        || text.get(7) != Some(&b'-')
        || !matches!(text.get(10), Some(b'T' | b't'))
        || text.get(13) != Some(&b':')
        || text.get(16) != Some(&b':')
    {
        return Err(TimestampParseError::InvalidSyntax);
    }

    let mut cursor = 19;
    let mut nanosecond = 0;
    let mut precision = TimePrecision::seconds();
    if text.get(cursor) == Some(&b'.') {
        cursor += 1;
        let fraction_start = cursor;
        while text.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        let fraction = text
            .get(fraction_start..cursor)
            .ok_or(TimestampParseError::InvalidSyntax)?;
        if fraction.is_empty() || fraction.len() > 9 {
            return Err(TimestampParseError::SubsecondOutOfRange);
        }
        let (parsed, _, parsed_precision) = parse_fraction_digits(fraction)?;
        nanosecond = parsed;
        precision = parsed_precision;
    }

    let wall = WallTime::new(
        parse_u16(&text[0..4])?,
        parse_u8(&text[5..7])?,
        parse_u8(&text[8..10])?,
        parse_u8(&text[11..13])?,
        parse_u8(&text[14..16])?,
        parse_u8(&text[17..19])?,
        nanosecond,
    )?;

    let suffix = text
        .get(cursor..)
        .ok_or(TimestampParseError::InvalidSyntax)?;
    if suffix.is_empty() {
        return Ok(NormalizedTimestamp::floating(wall, precision));
    }
    if suffix == b"Z" || suffix == b"z" {
        return NormalizedTimestamp::explicit(wall, UtcOffset::from_minutes(0)?, precision);
    }
    NormalizedTimestamp::explicit(wall, parse_iso_offset(suffix)?, precision)
}

/// Decode unsigned big-endian QuickTime `mvhd` seconds since 1904 UTC.
/// Semantic uncertainty is represented by `OffsetKind::QuickTimeEpochAssumedUtc`
/// and is enforced by the policy layer.
pub fn parse_quicktime_mvhd(raw: &[u8]) -> Result<NormalizedTimestamp, TimestampParseError> {
    let seconds = match raw.len() {
        4 => i128::from(u32::from_be_bytes(
            raw.try_into()
                .map_err(|_| TimestampParseError::UnsupportedBinaryLength)?,
        )),
        8 => i128::from(u64::from_be_bytes(
            raw.try_into()
                .map_err(|_| TimestampParseError::UnsupportedBinaryLength)?,
        )),
        _ => return Err(TimestampParseError::UnsupportedBinaryLength),
    };
    let unix_seconds = seconds
        .checked_sub(QUICKTIME_TO_UNIX_SECONDS)
        .ok_or(TimestampParseError::ArithmeticOverflow)?;
    let instant = UtcInstant::new(unix_seconds, 0)?;
    let wall = calendar::unix_seconds_to_wall_time(unix_seconds)?;
    NormalizedTimestamp::quicktime_epoch(wall, instant)
}

pub(crate) fn parse_offset(raw: &[u8]) -> Result<UtcOffset, TimestampParseError> {
    let text = trim_ascii_field(raw)?;
    if text.len() != 6 || !matches!(text.first(), Some(b'+' | b'-')) || text.get(3) != Some(&b':') {
        return Err(TimestampParseError::InvalidSyntax);
    }
    let hours = i16::from(parse_u8(&text[1..3])?);
    let minutes = i16::from(parse_u8(&text[4..6])?);
    if minutes > 59 || hours > 14 || (hours == 14 && minutes != 0) {
        return Err(TimestampParseError::OffsetOutOfRange);
    }
    let magnitude = hours
        .checked_mul(60)
        .and_then(|value| value.checked_add(minutes))
        .ok_or(TimestampParseError::ArithmeticOverflow)?;
    if text[0] == b'-' && magnitude == 0 {
        return Err(TimestampParseError::UnknownNegativeZeroOffset);
    }
    let signed = if text[0] == b'-' {
        -magnitude
    } else {
        magnitude
    };
    UtcOffset::from_minutes(signed)
}

fn parse_iso_offset(raw: &[u8]) -> Result<UtcOffset, TimestampParseError> {
    if raw.len() == 6 {
        return parse_offset(raw);
    }
    if raw.len() != 5 || !matches!(raw.first(), Some(b'+' | b'-')) {
        return Err(TimestampParseError::InvalidSyntax);
    }
    let hours = i16::from(parse_u8(&raw[1..3])?);
    let minutes = i16::from(parse_u8(&raw[3..5])?);
    if minutes > 59 || hours > 14 || (hours == 14 && minutes != 0) {
        return Err(TimestampParseError::OffsetOutOfRange);
    }
    let magnitude = hours
        .checked_mul(60)
        .and_then(|value| value.checked_add(minutes))
        .ok_or(TimestampParseError::ArithmeticOverflow)?;
    if raw[0] == b'-' && magnitude == 0 {
        return Err(TimestampParseError::UnknownNegativeZeroOffset);
    }
    let signed = if raw[0] == b'-' {
        -magnitude
    } else {
        magnitude
    };
    UtcOffset::from_minutes(signed)
}

pub(crate) fn parse_subsecond(raw: &[u8]) -> Result<(u32, u8, TimePrecision), TimestampParseError> {
    let text = trim_ascii_field(raw)?;
    parse_fraction_digits(text)
}

fn parse_fraction_digits(text: &[u8]) -> Result<(u32, u8, TimePrecision), TimestampParseError> {
    if text.is_empty() || text.len() > 9 || !text.iter().all(u8::is_ascii_digit) {
        return Err(TimestampParseError::SubsecondOutOfRange);
    }
    let digits = u8::try_from(text.len()).map_err(|_| TimestampParseError::ArithmeticOverflow)?;
    let numeric = text.iter().try_fold(0_u32, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u32::from(*digit - b'0')))
            .ok_or(TimestampParseError::ArithmeticOverflow)
    })?;
    let scale = 10_u32
        .checked_pow(u32::from(9 - digits))
        .ok_or(TimestampParseError::ArithmeticOverflow)?;
    let nanosecond = numeric
        .checked_mul(scale)
        .ok_or(TimestampParseError::ArithmeticOverflow)?;
    if nanosecond >= NANOS_PER_SECOND {
        return Err(TimestampParseError::NanosecondOutOfRange);
    }
    Ok((nanosecond, digits, TimePrecision::from_nanoseconds(scale)?))
}

fn trim_ascii_field(raw: &[u8]) -> Result<&[u8], TimestampParseError> {
    if !raw.is_ascii() {
        return Err(TimestampParseError::InvalidEncoding);
    }
    trim_field(raw)
}

fn trim_utf8_field(raw: &[u8]) -> Result<&[u8], TimestampParseError> {
    std::str::from_utf8(raw).map_err(|_| TimestampParseError::InvalidEncoding)?;
    trim_field(raw)
}

fn trim_field(raw: &[u8]) -> Result<&[u8], TimestampParseError> {
    let end = raw
        .iter()
        .rposition(|byte| !matches!(byte, b'\0' | b' ' | b'\t' | b'\r' | b'\n'))
        .map_or(0, |index| index + 1);
    let trimmed = raw.get(..end).ok_or(TimestampParseError::InvalidSyntax)?;
    if trimmed.is_empty() {
        return Err(TimestampParseError::Empty);
    }
    if trimmed.contains(&b'\0') {
        return Err(TimestampParseError::InvalidSyntax);
    }
    Ok(trimmed)
}

fn parse_u16(bytes: &[u8]) -> Result<u16, TimestampParseError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(TimestampParseError::InvalidSyntax);
    }
    bytes.iter().try_fold(0_u16, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u16::from(*digit - b'0')))
            .ok_or(TimestampParseError::ArithmeticOverflow)
    })
}

fn parse_u8(bytes: &[u8]) -> Result<u8, TimestampParseError> {
    let value = parse_u16(bytes)?;
    u8::try_from(value).map_err(|_| TimestampParseError::InvalidSyntax)
}
