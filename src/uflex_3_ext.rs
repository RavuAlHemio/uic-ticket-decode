//! Extensions for handling UFLEX version 3 tickets.


use std::fmt;

use chrono::{
    DateTime, Days, Duration, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc,
};

use crate::asn1_uper::Integer;
use crate::uflex_3::{
    CountermarkData, DocumentData, DocumentDataTicket, FipTicketData, IssuingData, OpenTicketData,
    ParkingGroundData, PassData, ReservationData, StationPassageData,
};



fn add_subtract_days(date: NaiveDate, days: i64) -> Option<NaiveDate> {
    let abs_days = days.abs_diff(0);
    if days < 0 {
        date.checked_sub_days(Days::new(abs_days))
    } else {
        date.checked_add_days(Days::new(abs_days))
    }
}


fn uic_offset_to_timezone(offset: i32) -> Option<FixedOffset> {
    // UTC = local + offset * 15min
    // the offset is given as local-to-UTC (UTC-to-local is more common)
    // => use west() to compensate for this
    let offset_seconds = offset * 15 * 60;
    FixedOffset::west_opt(offset_seconds)
}


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DateTimeOptionTz {
    Date(NaiveDate),
    DateTime(NaiveDateTime),
    DateTimeTz(DateTime<FixedOffset>),
}
impl DateTimeOptionTz {
    pub fn naive_date(&self) -> NaiveDate {
        match self {
            Self::Date(d) => *d,
            Self::DateTime(dt) => dt.date(),
            Self::DateTimeTz(dt) => dt.date_naive(),
        }
    }
}
impl fmt::Display for DateTimeOptionTz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Date(d) => d.fmt(f),
            Self::DateTime(dt) => dt.fmt(f),
            Self::DateTimeTz(dt) => dt.fmt(f),
        }
    }
}


fn uic_date_time_triplet(base_date: NaiveDate, day: &Integer, time_opt: Option<&Integer>, utc_offset_opt: Option<&Integer>) -> (NaiveDate, DateTimeOptionTz) {
    let day_i64: i64 = day.try_into().expect("failed to convert day to i64");
    let naive_date = add_subtract_days(base_date, day_i64).expect("failed to add days to base date");
    if let Some(time) = time_opt {
        let time_i64: i64 = time.try_into().expect("failed to convert time to i64");
        let naive_date_time = naive_date
            .and_hms_opt(0, 0, 0).expect("date did not have midnight?!")
            .checked_add_signed(Duration::minutes(time_i64)).expect("failed to add/subtract minutes to/from date");
        if let Some(offset) = utc_offset_opt {
            let offset_i32: i32 = offset.try_into().expect("failed to convert offset to i32");
            let timezone = uic_offset_to_timezone(offset_i32)
                .expect("failed to convert offset to timezone");
            let date_time = timezone.from_local_datetime(&naive_date_time)
                .single().expect("ambiguous point in time with fixed offset?!");
            (naive_date, DateTimeOptionTz::DateTimeTz(date_time))
        } else {
            (naive_date, DateTimeOptionTz::DateTime(naive_date_time))
        }
    } else {
        (naive_date, DateTimeOptionTz::Date(naive_date))
    }
}

fn uic_date_time_quadruplet(year: &Integer, day: &Integer, time_opt: Option<&Integer>, utc_offset_opt: Option<&Integer>) -> DateTimeOptionTz {
    let year_i32: i32 = year
        .try_into().expect("failed to convert issuing year to i32");
    let day_u32: u32 = day
        .try_into().expect("failed to convert issuing day to u32");
    let date = NaiveDate::from_yo_opt(year_i32, day_u32)
            .expect("failed to convert issuing year and day to date");
    if let Some(time) = time_opt {
        let minute: i64 = time
            .try_into().expect("failed to convert issuing minute to i64");
        let naive_date_time = date
            .and_hms_opt(0, 0, 0).expect("date did not have midnight?!")
            .checked_add_signed(Duration::minutes(minute)).expect("failed to add minutes to date");
        if let Some(offset) = utc_offset_opt {
            let offset_i32: i32 = offset.try_into().expect("failed to convert offset to i32");
            let timezone = uic_offset_to_timezone(offset_i32)
                .expect("failed to convert offset to timezone");
            let date_time = timezone.from_local_datetime(&naive_date_time)
                .single().expect("ambiguous point in time with fixed offset?!");
            DateTimeOptionTz::DateTimeTz(date_time)
        } else {
            DateTimeOptionTz::DateTime(naive_date_time)
        }
    } else {
        DateTimeOptionTz::Date(date)
    }
}


/// Date calculations for the issuance of a ticket.
pub trait IssuanceExt {
    fn issuance_date(&self) -> DateTime<Utc>;
}
impl IssuanceExt for IssuingData {
    fn issuance_date(&self) -> DateTime<Utc> {
        let year: i32 = (&self.issuing_year)
            .try_into().expect("failed to convert issuing year to i32");
        let day: u32 = (&self.issuing_day)
            .try_into().expect("failed to convert issuing day to u32");
        let minute: i64 = (&self.issuing_time)
            .try_into().expect("failed to convert issuing minute to i64");
        let date = NaiveDate::from_yo_opt(year, day)
            .expect("failed to convert issuing year and day to date");
        let date_time = date
            .and_hms_opt(0, 0, 0).expect("issuing date did not have midnight?!")
            .checked_add_signed(Duration::minutes(minute)).expect("failed to add minutes to issuing date");
        Utc.from_utc_datetime(&date_time)
    }
}


/// A ticket whose validity is given by a departure (days relative to issuance and time) and arrival
/// (days relative to departure and time).
pub trait ValidityDepartureArrival {
    fn uic_departure_days_from_issuance(&self) -> &Integer;
    fn uic_departure_time(&self) -> Option<&Integer>;
    fn uic_departure_offset(&self) -> Option<&Integer>;
    fn uic_arrival_days_from_departure(&self) -> &Integer;
    fn uic_arrival_time(&self) -> Option<&Integer>;
    fn uic_arrival_offset(&self) -> Option<&Integer>;

    fn departure_date(&self, issuance_date: DateTime<Utc>) -> Option<NaiveDate> {
        let issuance_naive_date = issuance_date.date_naive();
        let departure_days: i64 = self.uic_departure_days_from_issuance()
            .try_into().ok()?;
        add_subtract_days(issuance_naive_date, departure_days)
    }

    fn departure(&self, issuance_date: DateTime<Utc>) -> Option<DateTimeOptionTz> {
        let (_departure_date, departure_time) = uic_date_time_triplet(
            issuance_date.date_naive(),
            self.uic_departure_days_from_issuance(),
            self.uic_departure_time(),
            self.uic_departure_offset(),
        );
        Some(departure_time)
    }

    fn arrival_date(&self, issuance_date: DateTime<Utc>) -> Option<NaiveDate> {
        let departure_date = self.departure_date(issuance_date)?;
        let arrival_days: i64 = self.uic_arrival_days_from_departure()
            .try_into().ok()?;
        add_subtract_days(departure_date, arrival_days)
    }

    fn arrival(&self, issuance_date: DateTime<Utc>) -> Option<DateTimeOptionTz> {
        let (_arrival_date, arrival_time) = uic_date_time_triplet(
            self.departure_date(issuance_date)?,
            self.uic_arrival_days_from_departure(),
            self.uic_arrival_time(),
            self.uic_arrival_offset().or(self.uic_departure_offset()),
        );
        Some(arrival_time)
    }
}
impl ValidityDepartureArrival for ReservationData {
    fn uic_departure_days_from_issuance(&self) -> &Integer { &self.departure_date }
    fn uic_departure_time(&self) -> Option<&Integer> { Some(&self.departure_time) }
    fn uic_departure_offset(&self) -> Option<&Integer> { self.departure_utc_offset.as_ref() }
    fn uic_arrival_days_from_departure(&self) -> &Integer { &self.arrival_date }
    fn uic_arrival_time(&self) -> Option<&Integer> { self.arrival_time.as_ref() }
    fn uic_arrival_offset(&self) -> Option<&Integer> { self.arrival_utc_offset.as_ref() }
}
impl ValidityDepartureArrival for OpenTicketData {
    fn uic_departure_days_from_issuance(&self) -> &Integer { &self.valid_from_day }
    fn uic_departure_time(&self) -> Option<&Integer> { self.valid_from_time.as_ref() }
    fn uic_departure_offset(&self) -> Option<&Integer> { self.valid_from_utc_offset.as_ref() }
    fn uic_arrival_days_from_departure(&self) -> &Integer { &self.valid_until_day }
    fn uic_arrival_time(&self) -> Option<&Integer> { self.valid_until_time.as_ref() }
    fn uic_arrival_offset(&self) -> Option<&Integer> { self.valid_until_utc_offset.as_ref() }

    // however, see also activatedDay
}
impl ValidityDepartureArrival for PassData {
    fn uic_departure_days_from_issuance(&self) -> &Integer { &self.valid_from_day }
    fn uic_departure_time(&self) -> Option<&Integer> { self.valid_from_time.as_ref() }
    fn uic_departure_offset(&self) -> Option<&Integer> { self.valid_from_utc_offset.as_ref() }
    fn uic_arrival_days_from_departure(&self) -> &Integer { &self.valid_until_day }
    fn uic_arrival_time(&self) -> Option<&Integer> { self.valid_until_time.as_ref() }
    fn uic_arrival_offset(&self) -> Option<&Integer> { self.valid_until_utc_offset.as_ref() }

    // however, see also validityPeriodDetails and activatedDay
}
impl ValidityDepartureArrival for CountermarkData {
    fn uic_departure_days_from_issuance(&self) -> &Integer { &self.valid_from_day }
    fn uic_departure_time(&self) -> Option<&Integer> { self.valid_from_time.as_ref() }
    fn uic_departure_offset(&self) -> Option<&Integer> { self.valid_from_utc_offset.as_ref() }
    fn uic_arrival_days_from_departure(&self) -> &Integer { &self.valid_until_day }
    fn uic_arrival_time(&self) -> Option<&Integer> { self.valid_until_time.as_ref() }
    fn uic_arrival_offset(&self) -> Option<&Integer> { self.valid_until_utc_offset.as_ref() }
}
impl ValidityDepartureArrival for ParkingGroundData {
    fn uic_departure_days_from_issuance(&self) -> &Integer { &self.from_parking_date }
    fn uic_departure_time(&self) -> Option<&Integer> { None }
    fn uic_departure_offset(&self) -> Option<&Integer> { None }
    fn uic_arrival_days_from_departure(&self) -> &Integer { &self.until_parking_date }
    fn uic_arrival_time(&self) -> Option<&Integer> { None }
    fn uic_arrival_offset(&self) -> Option<&Integer> { None }
}
impl ValidityDepartureArrival for FipTicketData {
    fn uic_departure_days_from_issuance(&self) -> &Integer { &self.valid_from_day }
    fn uic_departure_time(&self) -> Option<&Integer> { None }
    fn uic_departure_offset(&self) -> Option<&Integer> { None }
    fn uic_arrival_days_from_departure(&self) -> &Integer { &self.valid_until_day }
    fn uic_arrival_time(&self) -> Option<&Integer> { None }
    fn uic_arrival_offset(&self) -> Option<&Integer> { None }
}
impl ValidityDepartureArrival for StationPassageData {
    fn uic_departure_days_from_issuance(&self) -> &Integer { &self.valid_from_day }
    fn uic_departure_time(&self) -> Option<&Integer> { self.valid_from_time.as_ref() }
    fn uic_departure_offset(&self) -> Option<&Integer> { self.valid_from_utc_offset.as_ref() }
    fn uic_arrival_days_from_departure(&self) -> &Integer { &self.valid_until_day }
    fn uic_arrival_time(&self) -> Option<&Integer> { self.valid_until_time.as_ref() }
    fn uic_arrival_offset(&self) -> Option<&Integer> { self.valid_until_utc_offset.as_ref() }
}


pub(crate) fn output_ticket_validity(issuing_data: &IssuingData, documents: &[DocumentData]) {
    let issuance_date = issuing_data.issuance_date();
    println!("issued: {}", issuance_date);

    for (i, document) in documents.iter().enumerate() {
        println!("ticket {}:", i + 1);
        match &document.ticket {
            DocumentDataTicket::Reservation(ticket) => {
                let valid_from = ticket.departure(issuance_date).unwrap();
                let valid_to = ticket.arrival(issuance_date).unwrap();
                println!("  departure: {}", valid_from);
                println!("  arrival: {}", valid_to);
            },
            DocumentDataTicket::CarCarriageReservation(ticket) => {
                let (_, begin_loading) = uic_date_time_triplet(
                    issuance_date.date_naive(),
                    &ticket.begin_loading_date,
                    ticket.begin_loading_time.as_ref(),
                    ticket.loading_utc_offset.as_ref(),
                );
                let (_, end_loading) = uic_date_time_triplet(
                    issuance_date.date_naive(),
                    &ticket.begin_loading_date,
                    ticket.end_loading_time.as_ref(),
                    ticket.loading_utc_offset.as_ref(),
                );
                println!("  begin loading: {}", begin_loading);
                println!("  end loading: {}", end_loading);
            },
            DocumentDataTicket::OpenTicket(ticket) => {
                let valid_from = ticket.departure(issuance_date).unwrap();
                let valid_to = ticket.arrival(issuance_date).unwrap();
                println!("  valid from: {}", valid_from);
                println!("  valid to: {}", valid_to);

                for activated_day in &ticket.activated_day {
                    let days_i64: i64 = activated_day.try_into().unwrap();
                    let day = add_subtract_days(valid_from.naive_date(), days_i64).unwrap();
                    println!("  activated on {}", day);
                }
            },
            DocumentDataTicket::Pass(ticket) => {
                let valid_from = ticket.departure(issuance_date).unwrap();
                let valid_to = ticket.arrival(issuance_date).unwrap();
                println!("  valid from: {}", valid_from);
                println!("  valid to: {}", valid_to);

                if let Some(details) = &ticket.validity_period_details {
                    println!("  in detail:");
                    for period in &details.validity_period {
                        let (valid_from_date, valid_from_time) = uic_date_time_triplet(
                            issuance_date.date_naive(),
                            &period.valid_from_day,
                            period.valid_from_time.as_ref(),
                            period.valid_from_utc_offset.as_ref(),
                        );
                        let (_, valid_to_time) = uic_date_time_triplet(
                            valid_from_date,
                            &period.valid_until_day,
                            period.valid_until_time.as_ref(),
                            period.valid_until_utc_offset.as_ref().or(period.valid_from_utc_offset.as_ref()),
                        );
                        println!("    valid from {} to {}", valid_from_time, valid_to_time);
                    }
                    for exclusion in &details.excluded_time_range {
                        let from_minutes: i64 = (&exclusion.from_time)
                            .try_into().expect("failed to convert from_time to i64");
                        let to_minutes: i64 = (&exclusion.until_time)
                            .try_into().expect("failed to convert until_time to i64");
                        let (from_time, _overflow_days) = NaiveTime::from_hms_opt(0, 0, 0)
                            .expect("no midnight?!")
                            .overflowing_add_signed(Duration::minutes(from_minutes));
                        let (to_time, _overflow_days) = NaiveTime::from_hms_opt(0, 0, 0)
                            .expect("no midnight?!")
                            .overflowing_add_signed(Duration::minutes(to_minutes));
                        println!("    invalid between {} and {}", from_time, to_time);
                    }
                }

                for activated_day in &ticket.activated_day {
                    let days_i64: i64 = activated_day.try_into().unwrap();
                    let day = add_subtract_days(valid_from.naive_date(), days_i64).unwrap();
                    println!("  activated on {}", day);
                }
            },
            DocumentDataTicket::Voucher(ticket) => {
                let from_year: i32 = (&ticket.valid_from_year)
                    .try_into().expect("failed to convert from-year to i32");
                let from_day: u32 = (&ticket.valid_from_day)
                    .try_into().expect("failed to convert from-day to u32");
                let from_date = NaiveDate::from_yo_opt(from_year, from_day)
                    .expect("failed to convert from-date to date");

                let to_year: i32 = (&ticket.valid_until_year)
                    .try_into().expect("failed to convert to-year to i32");
                let to_day: u32 = (&ticket.valid_until_day)
                    .try_into().expect("failed to convert to-day to u32");
                let to_date = NaiveDate::from_yo_opt(to_year, to_day)
                    .expect("failed to convert to-date to date");

                println!("  valid from: {}", from_date);
                println!("  valid to: {}", to_date);
            },
            DocumentDataTicket::CustomerCard(ticket) => {
                let from_year: i32 = (&ticket.valid_from_year)
                    .try_into().expect("failed to convert from-year to i32");
                if let Some(from_day) = ticket.valid_from_day.as_ref() {
                    let from_day_u32: u32 = from_day
                        .try_into().expect("failed to convert from-day to u32");
                    let from_date = NaiveDate::from_yo_opt(from_year, from_day_u32)
                        .expect("failed to convert from-date to date");
                    println!("  valid from: {}", from_date);
                } else {
                    println!("  valid from: {}", from_year);
                }

                let to_year: i32 = (&ticket.valid_until_year)
                    .try_into().expect("failed to convert to-year to i32");
                if let Some(to_day) = ticket.valid_until_day.as_ref() {
                    let to_day_u32: u32 = to_day
                        .try_into().expect("failed to convert to-day to u32");
                    let to_date = NaiveDate::from_yo_opt(to_year, to_day_u32)
                        .expect("failed to convert to-date to date");
                    println!("  valid from: {}", to_date);
                } else {
                    println!("  valid from: {}", to_year);
                }
            },
            DocumentDataTicket::CounterMark(ticket) => {
                let valid_from = ticket.departure(issuance_date).unwrap();
                let valid_to = ticket.arrival(issuance_date).unwrap();
                println!("  valid from: {}", valid_from);
                println!("  valid to: {}", valid_to);
            },
            DocumentDataTicket::ParkingGround(ticket) => {
                let valid_from = ticket.departure(issuance_date).unwrap();
                let valid_to = ticket.arrival(issuance_date).unwrap();
                println!("  parking from: {}", valid_from);
                println!("  parking to: {}", valid_to);
            },
            DocumentDataTicket::FipTicket(ticket) => {
                let valid_from = ticket.departure(issuance_date).unwrap();
                let valid_to = ticket.arrival(issuance_date).unwrap();
                println!("  valid from: {}", valid_from);
                println!("  valid to: {}", valid_to);
            },
            DocumentDataTicket::StationPassage(ticket) => {
                let valid_from = ticket.departure(issuance_date).unwrap();
                let valid_to = ticket.arrival(issuance_date).unwrap();
                println!("  valid from: {}", valid_from);
                println!("  valid to: {}", valid_to);
            },
            DocumentDataTicket::Extension(_ticket) => {
                // shrug
            },
            DocumentDataTicket::DelayConfirmation(ticket) => {
                if let Some(year) = ticket.departure_year.as_ref() {
                    if let Some(day) = ticket.departure_day.as_ref() {
                        let departure_time = uic_date_time_quadruplet(
                            year,
                            day,
                            ticket.departure_time.as_ref(),
                            ticket.departure_utc_offset.as_ref(),
                        );
                        println!("  departure time: {}", departure_time);
                    }
                }
            },
        }
    }
}
