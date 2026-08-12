use crate::{TimestampParseError, WallTime, NANOS_PER_SECOND};

const SECONDS_PER_DAY: i128 = 86_400;

pub(crate) fn validate_components(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
) -> Result<(), TimestampParseError> {
    if !(1..=9999).contains(&year) {
        return Err(TimestampParseError::YearOutOfRange);
    }
    if !(1..=12).contains(&month) {
        return Err(TimestampParseError::MonthOutOfRange);
    }
    if day == 0 || day > days_in_month(year, month) {
        return Err(TimestampParseError::DayOutOfRange);
    }
    if hour > 23 {
        return Err(TimestampParseError::HourOutOfRange);
    }
    if minute > 59 {
        return Err(TimestampParseError::MinuteOutOfRange);
    }
    if second > 59 {
        return Err(TimestampParseError::SecondOutOfRange);
    }
    if nanosecond >= NANOS_PER_SECOND {
        return Err(TimestampParseError::NanosecondOutOfRange);
    }
    Ok(())
}

const fn is_leap_year(year: u16) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

pub(crate) fn wall_time_to_unix_seconds(value: WallTime) -> i128 {
    let days = days_from_civil(
        i64::from(value.year()),
        i64::from(value.month()),
        i64::from(value.day()),
    );
    i128::from(days) * SECONDS_PER_DAY
        + i128::from(value.hour()) * 3_600
        + i128::from(value.minute()) * 60
        + i128::from(value.second())
}

pub(crate) fn unix_seconds_to_wall_time(
    unix_seconds: i128,
) -> Result<WallTime, TimestampParseError> {
    let days = unix_seconds.div_euclid(SECONDS_PER_DAY);
    let seconds = unix_seconds.rem_euclid(SECONDS_PER_DAY);
    let days_i64 = i64::try_from(days).map_err(|_| TimestampParseError::YearOutOfRange)?;
    let (year, month, day) = civil_from_days(days_i64);
    let year = u16::try_from(year).map_err(|_| TimestampParseError::YearOutOfRange)?;
    if !(1..=9999).contains(&year) {
        return Err(TimestampParseError::YearOutOfRange);
    }
    let hour =
        u8::try_from(seconds / 3_600).map_err(|_| TimestampParseError::ArithmeticOverflow)?;
    let minute = u8::try_from((seconds % 3_600) / 60)
        .map_err(|_| TimestampParseError::ArithmeticOverflow)?;
    let second = u8::try_from(seconds % 60).map_err(|_| TimestampParseError::ArithmeticOverflow)?;
    WallTime::new(year, month, day, hour, minute, second, 0)
}

// Howard Hinnant's public-domain civil calendar algorithms, expressed with
// checked input bounds supplied by WallTime. Epoch is 1970-01-01.
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

const fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    (year, month as u8, day as u8)
}
