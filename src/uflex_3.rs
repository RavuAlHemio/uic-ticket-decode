#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UicRailTicketData {
    pub issuing_detail: IssuingData,
    pub traveler_detail: Option<TravelerData>,
    pub transport_document: Vec<DocumentData>,
    pub control_detail: Option<ControlData>,
    pub extension: Vec<ExtensionData>,
}
impl UicRailTicketData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 4)?;
        let (rest, issuing_detail) = IssuingData::try_from_uper(rest)?;
        let (rest, traveler_detail) = if optional_bits[0] {
            let (rest, value) = TravelerData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, transport_document) = if optional_bits[1] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = DocumentData::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, control_detail) = if optional_bits[2] {
            let (rest, value) = ControlData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, extension) = if optional_bits[3] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = ExtensionData::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let sequence = Self {
            issuing_detail,
            traveler_detail,
            transport_document,
            control_detail,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DocumentData {
    pub token: Option<TokenType>,
    pub ticket: DocumentDataTicket,
}
impl DocumentData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 1)?;
        let (rest, token) = if optional_bits[0] {
            let (rest, value) = TokenType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, ticket) = DocumentDataTicket::try_from_uper(rest)?;
        let sequence = Self {
            token,
            ticket,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DocumentDataTicket {
    Reservation(ReservationData),
    CarCarriageReservation(CarCarriageReservationData),
    OpenTicket(OpenTicketData),
    Pass(PassData),
    Voucher(VoucherData),
    CustomerCard(CustomerCardData),
    CounterMark(CountermarkData),
    ParkingGround(ParkingGroundData),
    FipTicket(FipTicketData),
    StationPassage(StationPassageData),
    Extension(ExtensionData),
    DelayConfirmation(DelayConfirmation),
}
impl DocumentDataTicket {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (mut rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(12) })?;
        let choice_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => {
                let (new_rest, inner_value) = ReservationData::try_from_uper(rest)?;
                rest = new_rest;
                Self::Reservation(inner_value)
            },
            1 => {
                let (new_rest, inner_value) = CarCarriageReservationData::try_from_uper(rest)?;
                rest = new_rest;
                Self::CarCarriageReservation(inner_value)
            },
            2 => {
                let (new_rest, inner_value) = OpenTicketData::try_from_uper(rest)?;
                rest = new_rest;
                Self::OpenTicket(inner_value)
            },
            3 => {
                let (new_rest, inner_value) = PassData::try_from_uper(rest)?;
                rest = new_rest;
                Self::Pass(inner_value)
            },
            4 => {
                let (new_rest, inner_value) = VoucherData::try_from_uper(rest)?;
                rest = new_rest;
                Self::Voucher(inner_value)
            },
            5 => {
                let (new_rest, inner_value) = CustomerCardData::try_from_uper(rest)?;
                rest = new_rest;
                Self::CustomerCard(inner_value)
            },
            6 => {
                let (new_rest, inner_value) = CountermarkData::try_from_uper(rest)?;
                rest = new_rest;
                Self::CounterMark(inner_value)
            },
            7 => {
                let (new_rest, inner_value) = ParkingGroundData::try_from_uper(rest)?;
                rest = new_rest;
                Self::ParkingGround(inner_value)
            },
            8 => {
                let (new_rest, inner_value) = FipTicketData::try_from_uper(rest)?;
                rest = new_rest;
                Self::FipTicket(inner_value)
            },
            9 => {
                let (new_rest, inner_value) = StationPassageData::try_from_uper(rest)?;
                rest = new_rest;
                Self::StationPassage(inner_value)
            },
            10 => {
                let (new_rest, inner_value) = ExtensionData::try_from_uper(rest)?;
                rest = new_rest;
                Self::Extension(inner_value)
            },
            11 => {
                let (new_rest, inner_value) = DelayConfirmation::try_from_uper(rest)?;
                rest = new_rest;
                Self::DelayConfirmation(inner_value)
            },
            other => panic!("unexpected DocumentDataTicket value {}", other),
        };
        Ok((rest, choice_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DelayConfirmation {
    pub reference_ia_5: Option<String>,
    pub reference_num: Option<crate::asn1_uper::Integer>,
    pub train_num: Option<crate::asn1_uper::Integer>,
    pub train_ia_5: Option<String>,
    pub departure_year: Option<crate::asn1_uper::Integer>,
    pub departure_day: Option<crate::asn1_uper::Integer>,
    pub departure_time: Option<crate::asn1_uper::Integer>,
    pub departure_utc_offset: Option<crate::asn1_uper::Integer>,
    pub station_code_table: CodeTableType,
    pub station_num: Option<crate::asn1_uper::Integer>,
    pub station_ia_5: Option<String>,
    pub delay: crate::asn1_uper::Integer,
    pub train_cancelled: bool,
    pub confirmation_type: ConfirmationType,
    pub affected_tickets: Vec<TicketLinkType>,
    pub info_text: Option<String>,
    pub extension: Option<ExtensionData>,
}
impl DelayConfirmation {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 15)?;
        let (rest, reference_ia_5) = if optional_bits[0] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_num) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, train_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, train_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, departure_year) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(2016), max: crate::asn1_uper::Integer::from_short(2269) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, departure_day) = if optional_bits[5] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(366) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, departure_time) = if optional_bits[6] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, departure_utc_offset) = if optional_bits[7] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, station_code_table) = if optional_bits[8] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUic;
            (rest, default_value)
        };
        let (rest, station_num) = if optional_bits[9] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, station_ia_5) = if optional_bits[10] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, delay) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(999) })?;
        let (rest, train_cancelled) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, confirmation_type) = if optional_bits[11] {
            ConfirmationType::try_from_uper(rest)?
        } else {
            let default_value = ConfirmationType::TravelerDelayConfirmation;
            (rest, default_value)
        };
        let (rest, affected_tickets) = if optional_bits[12] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = TicketLinkType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, info_text) = if optional_bits[13] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, extension) = if optional_bits[14] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            reference_ia_5,
            reference_num,
            train_num,
            train_ia_5,
            departure_year,
            departure_day,
            departure_time,
            departure_utc_offset,
            station_code_table,
            station_num,
            station_ia_5,
            delay,
            train_cancelled,
            confirmation_type,
            affected_tickets,
            info_text,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ConfirmationType {
    TrainDelayConfirmation = 0,
    TravelerDelayConfirmation = 1,
    TrainLinkedTicketDelay = 2,
}
impl ConfirmationType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(2) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::TrainDelayConfirmation,
            1 => Self::TravelerDelayConfirmation,
            2 => Self::TrainLinkedTicketDelay,
            other => panic!("unexpected ConfirmationType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IssuingData {
    pub security_provider_num: Option<crate::asn1_uper::Integer>,
    pub security_provider_ia_5: Option<String>,
    pub issuer_num: Option<crate::asn1_uper::Integer>,
    pub issuer_ia_5: Option<String>,
    pub issuing_year: crate::asn1_uper::Integer,
    pub issuing_day: crate::asn1_uper::Integer,
    pub issuing_time: crate::asn1_uper::Integer,
    pub issuer_name: Option<String>,
    pub specimen: bool,
    pub secure_paper_ticket: bool,
    pub activated: bool,
    pub currency: String,
    pub currency_fract: crate::asn1_uper::Integer,
    pub issuer_pnr: Option<String>,
    pub extension: Option<ExtensionData>,
    pub issued_on_train_num: Option<crate::asn1_uper::Integer>,
    pub issued_on_train_ia_5: Option<String>,
    pub issued_on_line: Option<crate::asn1_uper::Integer>,
    pub point_of_sale: Option<GeoCoordinateType>,
}
impl IssuingData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 13)?;
        let (rest, security_provider_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, security_provider_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, issuer_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, issuer_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, issuing_year) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(2016), max: crate::asn1_uper::Integer::from_short(2269) })?;
        let (rest, issuing_day) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(366) })?;
        let (rest, issuing_time) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
        let (rest, issuer_name) = if optional_bits[4] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, specimen) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, secure_paper_ticket) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, activated) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, currency) = if optional_bits[5] {
            {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
}
        } else {
            let default_value = "EUR".to_owned();
            (rest, default_value)
        };
        let (rest, currency_fract) = if optional_bits[6] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(3) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(2);
            (rest, default_value)
        };
        let (rest, issuer_pnr) = if optional_bits[7] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, extension) = if optional_bits[8] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, issued_on_train_num) = if optional_bits[9] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, issued_on_train_ia_5) = if optional_bits[10] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, issued_on_line) = if optional_bits[11] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, point_of_sale) = if optional_bits[12] {
            let (rest, value) = GeoCoordinateType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            security_provider_num,
            security_provider_ia_5,
            issuer_num,
            issuer_ia_5,
            issuing_year,
            issuing_day,
            issuing_time,
            issuer_name,
            specimen,
            secure_paper_ticket,
            activated,
            currency,
            currency_fract,
            issuer_pnr,
            extension,
            issued_on_train_num,
            issued_on_train_ia_5,
            issued_on_line,
            point_of_sale,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ControlData {
    pub identification_by_card_reference: Vec<CardReferenceType>,
    pub identification_by_id_card: bool,
    pub identification_by_passport_id: bool,
    pub identification_item: Option<crate::asn1_uper::Integer>,
    pub passport_validation_required: bool,
    pub online_validation_required: bool,
    pub random_detailed_validation_required: Option<crate::asn1_uper::Integer>,
    pub age_check_required: bool,
    pub reduction_card_check_required: bool,
    pub info_text: Option<String>,
    pub included_tickets: Vec<TicketLinkType>,
    pub extension: Option<ExtensionData>,
}
impl ControlData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 6)?;
        let (rest, identification_by_card_reference) = if optional_bits[0] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = CardReferenceType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, identification_by_id_card) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, identification_by_passport_id) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, identification_item) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, passport_validation_required) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, online_validation_required) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, random_detailed_validation_required) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(99) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, age_check_required) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, reduction_card_check_required) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, info_text) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, included_tickets) = if optional_bits[4] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = TicketLinkType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, extension) = if optional_bits[5] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            identification_by_card_reference,
            identification_by_id_card,
            identification_by_passport_id,
            identification_item,
            passport_validation_required,
            online_validation_required,
            random_detailed_validation_required,
            age_check_required,
            reduction_card_check_required,
            info_text,
            included_tickets,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TravelerData {
    pub traveler: Vec<TravelerType>,
    pub preferred_language: Option<String>,
    pub group_name: Option<String>,
}
impl TravelerData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 3)?;
        let (rest, traveler) = if optional_bits[0] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = TravelerType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, preferred_language) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, group_name) = if optional_bits[2] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            traveler,
            preferred_language,
            group_name,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReservationData {
    pub train_num: Option<crate::asn1_uper::Integer>,
    pub train_ia_5: Option<String>,
    pub departure_date: crate::asn1_uper::Integer,
    pub reference_ia_5: Option<String>,
    pub reference_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_ia_5: Option<String>,
    pub product_id_num: Option<crate::asn1_uper::Integer>,
    pub product_id_ia_5: Option<String>,
    pub service_brand: Option<crate::asn1_uper::Integer>,
    pub service_brand_abr_utf_8: Option<String>,
    pub service_brand_name_utf_8: Option<String>,
    pub service: ServiceType,
    pub station_code_table: CodeTableType,
    pub from_station_num: Option<crate::asn1_uper::Integer>,
    pub from_station_ia_5: Option<String>,
    pub to_station_num: Option<crate::asn1_uper::Integer>,
    pub to_station_ia_5: Option<String>,
    pub from_station_name_utf_8: Option<String>,
    pub to_station_name_utf_8: Option<String>,
    pub departure_time: crate::asn1_uper::Integer,
    pub departure_utc_offset: Option<crate::asn1_uper::Integer>,
    pub arrival_date: crate::asn1_uper::Integer,
    pub arrival_time: Option<crate::asn1_uper::Integer>,
    pub arrival_utc_offset: Option<crate::asn1_uper::Integer>,
    pub carrier_num: Vec<crate::asn1_uper::Integer>,
    pub carrier_ia_5: Vec<String>,
    pub class_code: TravelClassType,
    pub service_level: Option<String>,
    pub places: Option<PlacesType>,
    pub additional_places: Option<PlacesType>,
    pub bicycle_places: Option<PlacesType>,
    pub compartment_details: Option<CompartmentDetailsType>,
    pub number_of_overbooked: crate::asn1_uper::Integer,
    pub berth: Vec<BerthDetailData>,
    pub tariff: Vec<TariffType>,
    pub price_type: PriceTypeType,
    pub price: Option<crate::asn1_uper::Integer>,
    pub vat_detail: Vec<VatDetailType>,
    pub type_of_supplement: crate::asn1_uper::Integer,
    pub number_of_supplements: crate::asn1_uper::Integer,
    pub luggage: Option<LuggageRestrictionType>,
    pub info_text: Option<String>,
    pub extension: Option<ExtensionData>,
}
impl ReservationData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 43)?;
        let (rest, train_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, train_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, departure_date) = if optional_bits[2] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(500) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, reference_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_num) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_num) = if optional_bits[5] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_ia_5) = if optional_bits[6] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_num) = if optional_bits[7] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(65535) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_ia_5) = if optional_bits[8] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, service_brand) = if optional_bits[9] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, service_brand_abr_utf_8) = if optional_bits[10] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, service_brand_name_utf_8) = if optional_bits[11] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, service) = if optional_bits[12] {
            ServiceType::try_from_uper(rest)?
        } else {
            let default_value = ServiceType::Seat;
            (rest, default_value)
        };
        let (rest, station_code_table) = if optional_bits[13] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUicReservation;
            (rest, default_value)
        };
        let (rest, from_station_num) = if optional_bits[14] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_ia_5) = if optional_bits[15] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_num) = if optional_bits[16] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_ia_5) = if optional_bits[17] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_name_utf_8) = if optional_bits[18] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_name_utf_8) = if optional_bits[19] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, departure_time) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
        let (rest, departure_utc_offset) = if optional_bits[20] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, arrival_date) = if optional_bits[21] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(20) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, arrival_time) = if optional_bits[22] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, arrival_utc_offset) = if optional_bits[23] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, carrier_num) = if optional_bits[24] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, carrier_ia_5) = if optional_bits[25] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, class_code) = if optional_bits[26] {
            TravelClassType::try_from_uper(rest)?
        } else {
            let default_value = TravelClassType::Second;
            (rest, default_value)
        };
        let (rest, service_level) = if optional_bits[27] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, places) = if optional_bits[28] {
            let (rest, value) = PlacesType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, additional_places) = if optional_bits[29] {
            let (rest, value) = PlacesType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, bicycle_places) = if optional_bits[30] {
            let (rest, value) = PlacesType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, compartment_details) = if optional_bits[31] {
            let (rest, value) = CompartmentDetailsType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, number_of_overbooked) = if optional_bits[32] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(200) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, berth) = if optional_bits[33] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = BerthDetailData::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, tariff) = if optional_bits[34] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = TariffType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, price_type) = if optional_bits[35] {
            PriceTypeType::try_from_uper(rest)?
        } else {
            let default_value = PriceTypeType::TravelPrice;
            (rest, default_value)
        };
        let (rest, price) = if optional_bits[36] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, vat_detail) = if optional_bits[37] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = VatDetailType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, type_of_supplement) = if optional_bits[38] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(9) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, number_of_supplements) = if optional_bits[39] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(200) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, luggage) = if optional_bits[40] {
            let (rest, value) = LuggageRestrictionType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, info_text) = if optional_bits[41] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, extension) = if optional_bits[42] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            train_num,
            train_ia_5,
            departure_date,
            reference_ia_5,
            reference_num,
            product_owner_num,
            product_owner_ia_5,
            product_id_num,
            product_id_ia_5,
            service_brand,
            service_brand_abr_utf_8,
            service_brand_name_utf_8,
            service,
            station_code_table,
            from_station_num,
            from_station_ia_5,
            to_station_num,
            to_station_ia_5,
            from_station_name_utf_8,
            to_station_name_utf_8,
            departure_time,
            departure_utc_offset,
            arrival_date,
            arrival_time,
            arrival_utc_offset,
            carrier_num,
            carrier_ia_5,
            class_code,
            service_level,
            places,
            additional_places,
            bicycle_places,
            compartment_details,
            number_of_overbooked,
            berth,
            tariff,
            price_type,
            price,
            vat_detail,
            type_of_supplement,
            number_of_supplements,
            luggage,
            info_text,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VatDetailType {
    pub country: crate::asn1_uper::Integer,
    pub percentage: crate::asn1_uper::Integer,
    pub amount: Option<crate::asn1_uper::Integer>,
    pub vat_id: Option<String>,
}
impl VatDetailType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 2)?;
        let (rest, country) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(999) })?;
        let (rest, percentage) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(999) })?;
        let (rest, amount) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, vat_id) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            country,
            percentage,
            amount,
            vat_id,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CarCarriageReservationData {
    pub train_num: Option<crate::asn1_uper::Integer>,
    pub train_ia_5: Option<String>,
    pub begin_loading_date: crate::asn1_uper::Integer,
    pub begin_loading_time: Option<crate::asn1_uper::Integer>,
    pub end_loading_time: Option<crate::asn1_uper::Integer>,
    pub loading_utc_offset: Option<crate::asn1_uper::Integer>,
    pub reference_ia_5: Option<String>,
    pub reference_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_ia_5: Option<String>,
    pub product_id_num: Option<crate::asn1_uper::Integer>,
    pub product_id_ia_5: Option<String>,
    pub service_brand: Option<crate::asn1_uper::Integer>,
    pub service_brand_abr_utf_8: Option<String>,
    pub service_brand_name_utf_8: Option<String>,
    pub station_code_table: CodeTableType,
    pub from_station_num: Option<crate::asn1_uper::Integer>,
    pub from_station_ia_5: Option<String>,
    pub to_station_num: Option<crate::asn1_uper::Integer>,
    pub to_station_ia_5: Option<String>,
    pub from_station_name_utf_8: Option<String>,
    pub to_station_name_utf_8: Option<String>,
    pub coach: Option<String>,
    pub place: Option<String>,
    pub compartment_details: Option<CompartmentDetailsType>,
    pub number_plate: String,
    pub trailer_plate: Option<String>,
    pub car_category: crate::asn1_uper::Integer,
    pub boat_category: Option<crate::asn1_uper::Integer>,
    pub textile_roof: bool,
    pub roof_rack_type: RoofRackType,
    pub roof_rack_height: Option<crate::asn1_uper::Integer>,
    pub attached_boats: Option<crate::asn1_uper::Integer>,
    pub attached_bicycles: Option<crate::asn1_uper::Integer>,
    pub attached_surfboards: Option<crate::asn1_uper::Integer>,
    pub loading_list_entry: Option<crate::asn1_uper::Integer>,
    pub loading_deck: LoadingDeckType,
    pub carrier_num: Vec<crate::asn1_uper::Integer>,
    pub carrier_ia_5: Vec<String>,
    pub tariff: TariffType,
    pub price_type: PriceTypeType,
    pub price: Option<crate::asn1_uper::Integer>,
    pub vat_detail: Vec<VatDetailType>,
    pub info_text: Option<String>,
    pub extension: Option<ExtensionData>,
}
impl CarCarriageReservationData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 41)?;
        let (rest, train_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, train_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, begin_loading_date) = if optional_bits[2] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(500) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, begin_loading_time) = if optional_bits[3] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, end_loading_time) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, loading_utc_offset) = if optional_bits[5] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_ia_5) = if optional_bits[6] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_num) = if optional_bits[7] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_num) = if optional_bits[8] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_ia_5) = if optional_bits[9] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_num) = if optional_bits[10] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(65535) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_ia_5) = if optional_bits[11] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, service_brand) = if optional_bits[12] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, service_brand_abr_utf_8) = if optional_bits[13] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, service_brand_name_utf_8) = if optional_bits[14] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, station_code_table) = if optional_bits[15] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUicReservation;
            (rest, default_value)
        };
        let (rest, from_station_num) = if optional_bits[16] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_ia_5) = if optional_bits[17] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_num) = if optional_bits[18] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_ia_5) = if optional_bits[19] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_name_utf_8) = if optional_bits[20] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_name_utf_8) = if optional_bits[21] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, coach) = if optional_bits[22] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, place) = if optional_bits[23] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, compartment_details) = if optional_bits[24] {
            let (rest, value) = CompartmentDetailsType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, number_plate) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        let (rest, trailer_plate) = if optional_bits[25] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, car_category) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(9) })?;
        let (rest, boat_category) = if optional_bits[26] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(6) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, textile_roof) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, roof_rack_type) = if optional_bits[27] {
            RoofRackType::try_from_uper(rest)?
        } else {
            let default_value = RoofRackType::Norack;
            (rest, default_value)
        };
        let (rest, roof_rack_height) = if optional_bits[28] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(99) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, attached_boats) = if optional_bits[29] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(2) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, attached_bicycles) = if optional_bits[30] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(4) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, attached_surfboards) = if optional_bits[31] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(5) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, loading_list_entry) = if optional_bits[32] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, loading_deck) = if optional_bits[33] {
            LoadingDeckType::try_from_uper(rest)?
        } else {
            let default_value = LoadingDeckType::Upper;
            (rest, default_value)
        };
        let (rest, carrier_num) = if optional_bits[34] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, carrier_ia_5) = if optional_bits[35] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, tariff) = TariffType::try_from_uper(rest)?;
        let (rest, price_type) = if optional_bits[36] {
            PriceTypeType::try_from_uper(rest)?
        } else {
            let default_value = PriceTypeType::TravelPrice;
            (rest, default_value)
        };
        let (rest, price) = if optional_bits[37] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, vat_detail) = if optional_bits[38] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = VatDetailType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, info_text) = if optional_bits[39] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, extension) = if optional_bits[40] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            train_num,
            train_ia_5,
            begin_loading_date,
            begin_loading_time,
            end_loading_time,
            loading_utc_offset,
            reference_ia_5,
            reference_num,
            product_owner_num,
            product_owner_ia_5,
            product_id_num,
            product_id_ia_5,
            service_brand,
            service_brand_abr_utf_8,
            service_brand_name_utf_8,
            station_code_table,
            from_station_num,
            from_station_ia_5,
            to_station_num,
            to_station_ia_5,
            from_station_name_utf_8,
            to_station_name_utf_8,
            coach,
            place,
            compartment_details,
            number_plate,
            trailer_plate,
            car_category,
            boat_category,
            textile_roof,
            roof_rack_type,
            roof_rack_height,
            attached_boats,
            attached_bicycles,
            attached_surfboards,
            loading_list_entry,
            loading_deck,
            carrier_num,
            carrier_ia_5,
            tariff,
            price_type,
            price,
            vat_detail,
            info_text,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpenTicketData {
    pub reference_num: Option<crate::asn1_uper::Integer>,
    pub reference_ia_5: Option<String>,
    pub product_owner_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_ia_5: Option<String>,
    pub product_id_num: Option<crate::asn1_uper::Integer>,
    pub product_id_ia_5: Option<String>,
    pub ext_issuer_id: Option<crate::asn1_uper::Integer>,
    pub issuer_autorization_id: Option<crate::asn1_uper::Integer>,
    pub return_included: bool,
    pub station_code_table: CodeTableType,
    pub from_station_num: Option<crate::asn1_uper::Integer>,
    pub from_station_ia_5: Option<String>,
    pub to_station_num: Option<crate::asn1_uper::Integer>,
    pub to_station_ia_5: Option<String>,
    pub from_station_name_utf_8: Option<String>,
    pub to_station_name_utf_8: Option<String>,
    pub valid_region_desc: Option<String>,
    pub valid_region: Vec<RegionalValidityType>,
    pub return_description: Option<ReturnRouteDescriptionType>,
    pub valid_from_day: crate::asn1_uper::Integer,
    pub valid_from_time: Option<crate::asn1_uper::Integer>,
    pub valid_from_utc_offset: Option<crate::asn1_uper::Integer>,
    pub valid_until_day: crate::asn1_uper::Integer,
    pub valid_until_time: Option<crate::asn1_uper::Integer>,
    pub valid_until_utc_offset: Option<crate::asn1_uper::Integer>,
    pub activated_day: Vec<crate::asn1_uper::Integer>,
    pub class_code: TravelClassType,
    pub service_level: Option<String>,
    pub carrier_num: Vec<crate::asn1_uper::Integer>,
    pub carrier_ia_5: Vec<String>,
    pub included_service_brands: Vec<crate::asn1_uper::Integer>,
    pub excluded_service_brands: Vec<crate::asn1_uper::Integer>,
    pub tariffs: Vec<TariffType>,
    pub price: Option<crate::asn1_uper::Integer>,
    pub vat_detail: Vec<VatDetailType>,
    pub info_text: Option<String>,
    pub included_add_ons: Vec<IncludedOpenTicketType>,
    pub luggage: Option<LuggageRestrictionType>,
    pub included_transport_type: Vec<crate::asn1_uper::Integer>,
    pub excluded_transport_type: Vec<crate::asn1_uper::Integer>,
    pub extension: Option<ExtensionData>,
}
impl OpenTicketData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 40)?;
        let (rest, reference_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_num) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(65535) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_ia_5) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, ext_issuer_id) = if optional_bits[6] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, issuer_autorization_id) = if optional_bits[7] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, return_included) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, station_code_table) = if optional_bits[8] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUic;
            (rest, default_value)
        };
        let (rest, from_station_num) = if optional_bits[9] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_ia_5) = if optional_bits[10] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_num) = if optional_bits[11] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_ia_5) = if optional_bits[12] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_name_utf_8) = if optional_bits[13] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_name_utf_8) = if optional_bits[14] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_region_desc) = if optional_bits[15] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_region) = if optional_bits[16] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = RegionalValidityType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, return_description) = if optional_bits[17] {
            let (rest, value) = ReturnRouteDescriptionType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_day) = if optional_bits[18] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-367), max: crate::asn1_uper::Integer::from_short(700) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_from_time) = if optional_bits[19] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_utc_offset) = if optional_bits[20] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_day) = if optional_bits[21] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(500) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_until_time) = if optional_bits[22] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_utc_offset) = if optional_bits[23] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, activated_day) = if optional_bits[24] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(500) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, class_code) = if optional_bits[25] {
            TravelClassType::try_from_uper(rest)?
        } else {
            let default_value = TravelClassType::Second;
            (rest, default_value)
        };
        let (rest, service_level) = if optional_bits[26] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, carrier_num) = if optional_bits[27] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, carrier_ia_5) = if optional_bits[28] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, included_service_brands) = if optional_bits[29] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_service_brands) = if optional_bits[30] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, tariffs) = if optional_bits[31] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = TariffType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, price) = if optional_bits[32] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, vat_detail) = if optional_bits[33] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = VatDetailType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, info_text) = if optional_bits[34] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, included_add_ons) = if optional_bits[35] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = IncludedOpenTicketType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, luggage) = if optional_bits[36] {
            let (rest, value) = LuggageRestrictionType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, included_transport_type) = if optional_bits[37] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(31) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_transport_type) = if optional_bits[38] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(31) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, extension) = if optional_bits[39] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            reference_num,
            reference_ia_5,
            product_owner_num,
            product_owner_ia_5,
            product_id_num,
            product_id_ia_5,
            ext_issuer_id,
            issuer_autorization_id,
            return_included,
            station_code_table,
            from_station_num,
            from_station_ia_5,
            to_station_num,
            to_station_ia_5,
            from_station_name_utf_8,
            to_station_name_utf_8,
            valid_region_desc,
            valid_region,
            return_description,
            valid_from_day,
            valid_from_time,
            valid_from_utc_offset,
            valid_until_day,
            valid_until_time,
            valid_until_utc_offset,
            activated_day,
            class_code,
            service_level,
            carrier_num,
            carrier_ia_5,
            included_service_brands,
            excluded_service_brands,
            tariffs,
            price,
            vat_detail,
            info_text,
            included_add_ons,
            luggage,
            included_transport_type,
            excluded_transport_type,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PassData {
    pub reference_num: Option<crate::asn1_uper::Integer>,
    pub reference_ia_5: Option<String>,
    pub product_owner_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_ia_5: Option<String>,
    pub product_id_num: Option<crate::asn1_uper::Integer>,
    pub product_id_ia_5: Option<String>,
    pub pass_type: Option<crate::asn1_uper::Integer>,
    pub pass_description: Option<String>,
    pub class_code: TravelClassType,
    pub valid_from_day: crate::asn1_uper::Integer,
    pub valid_from_time: Option<crate::asn1_uper::Integer>,
    pub valid_from_utc_offset: Option<crate::asn1_uper::Integer>,
    pub valid_until_day: crate::asn1_uper::Integer,
    pub valid_until_time: Option<crate::asn1_uper::Integer>,
    pub valid_until_utc_offset: Option<crate::asn1_uper::Integer>,
    pub validity_period_details: Option<ValidityPeriodDetailType>,
    pub number_of_validity_days: Option<crate::asn1_uper::Integer>,
    pub train_validity: Option<TrainValidityType>,
    pub number_of_possible_trips: Option<crate::asn1_uper::Integer>,
    pub number_of_days_of_travel: Option<crate::asn1_uper::Integer>,
    pub activated_day: Vec<crate::asn1_uper::Integer>,
    pub countries: Vec<crate::asn1_uper::Integer>,
    pub included_carrier_num: Vec<crate::asn1_uper::Integer>,
    pub included_carrier_ia_5: Vec<String>,
    pub excluded_carrier_num: Vec<crate::asn1_uper::Integer>,
    pub excluded_carrier_ia_5: Vec<String>,
    pub included_service_brands: Vec<crate::asn1_uper::Integer>,
    pub excluded_service_brands: Vec<crate::asn1_uper::Integer>,
    pub valid_region: Vec<RegionalValidityType>,
    pub tariffs: Vec<TariffType>,
    pub price: Option<crate::asn1_uper::Integer>,
    pub vat_detail: Vec<VatDetailType>,
    pub info_text: Option<String>,
    pub extension: Option<ExtensionData>,
}
impl PassData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 34)?;
        let (rest, reference_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_num) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(65535) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_ia_5) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, pass_type) = if optional_bits[6] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(250) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, pass_description) = if optional_bits[7] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, class_code) = if optional_bits[8] {
            TravelClassType::try_from_uper(rest)?
        } else {
            let default_value = TravelClassType::Second;
            (rest, default_value)
        };
        let (rest, valid_from_day) = if optional_bits[9] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-367), max: crate::asn1_uper::Integer::from_short(700) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_from_time) = if optional_bits[10] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_utc_offset) = if optional_bits[11] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_day) = if optional_bits[12] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(500) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_until_time) = if optional_bits[13] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_utc_offset) = if optional_bits[14] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, validity_period_details) = if optional_bits[15] {
            let (rest, value) = ValidityPeriodDetailType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, number_of_validity_days) = if optional_bits[16] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(500) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, train_validity) = if optional_bits[17] {
            let (rest, value) = TrainValidityType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, number_of_possible_trips) = if optional_bits[18] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(250) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, number_of_days_of_travel) = if optional_bits[19] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(250) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, activated_day) = if optional_bits[20] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(500) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, countries) = if optional_bits[21] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(250) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, included_carrier_num) = if optional_bits[22] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, included_carrier_ia_5) = if optional_bits[23] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_carrier_num) = if optional_bits[24] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_carrier_ia_5) = if optional_bits[25] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, included_service_brands) = if optional_bits[26] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_service_brands) = if optional_bits[27] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, valid_region) = if optional_bits[28] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = RegionalValidityType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, tariffs) = if optional_bits[29] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = TariffType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, price) = if optional_bits[30] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, vat_detail) = if optional_bits[31] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = VatDetailType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, info_text) = if optional_bits[32] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, extension) = if optional_bits[33] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            reference_num,
            reference_ia_5,
            product_owner_num,
            product_owner_ia_5,
            product_id_num,
            product_id_ia_5,
            pass_type,
            pass_description,
            class_code,
            valid_from_day,
            valid_from_time,
            valid_from_utc_offset,
            valid_until_day,
            valid_until_time,
            valid_until_utc_offset,
            validity_period_details,
            number_of_validity_days,
            train_validity,
            number_of_possible_trips,
            number_of_days_of_travel,
            activated_day,
            countries,
            included_carrier_num,
            included_carrier_ia_5,
            excluded_carrier_num,
            excluded_carrier_ia_5,
            included_service_brands,
            excluded_service_brands,
            valid_region,
            tariffs,
            price,
            vat_detail,
            info_text,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrainValidityType {
    pub valid_from_day: crate::asn1_uper::Integer,
    pub valid_from_time: Option<crate::asn1_uper::Integer>,
    pub valid_from_utc_offset: Option<crate::asn1_uper::Integer>,
    pub valid_until_day: crate::asn1_uper::Integer,
    pub valid_until_time: Option<crate::asn1_uper::Integer>,
    pub valid_until_utc_offset: Option<crate::asn1_uper::Integer>,
    pub included_carrier_num: Vec<crate::asn1_uper::Integer>,
    pub included_carrier_ia_5: Vec<String>,
    pub excluded_carrier_num: Vec<crate::asn1_uper::Integer>,
    pub excluded_carrier_ia_5: Vec<String>,
    pub included_service_brands: Vec<crate::asn1_uper::Integer>,
    pub excluded_service_brands: Vec<crate::asn1_uper::Integer>,
    pub boarding_or_arrival: BoardingOrArrivalRestrictionType,
}
impl TrainValidityType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 13)?;
        let (rest, valid_from_day) = if optional_bits[0] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-367), max: crate::asn1_uper::Integer::from_short(700) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_from_time) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_utc_offset) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_day) = if optional_bits[3] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(500) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_until_time) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_utc_offset) = if optional_bits[5] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, included_carrier_num) = if optional_bits[6] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, included_carrier_ia_5) = if optional_bits[7] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_carrier_num) = if optional_bits[8] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_carrier_ia_5) = if optional_bits[9] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, included_service_brands) = if optional_bits[10] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_service_brands) = if optional_bits[11] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, boarding_or_arrival) = if optional_bits[12] {
            BoardingOrArrivalRestrictionType::try_from_uper(rest)?
        } else {
            let default_value = BoardingOrArrivalRestrictionType::Boarding;
            (rest, default_value)
        };
        let sequence = Self {
            valid_from_day,
            valid_from_time,
            valid_from_utc_offset,
            valid_until_day,
            valid_until_time,
            valid_until_utc_offset,
            included_carrier_num,
            included_carrier_ia_5,
            excluded_carrier_num,
            excluded_carrier_ia_5,
            included_service_brands,
            excluded_service_brands,
            boarding_or_arrival,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ValidityPeriodDetailType {
    pub validity_period: Vec<ValidityPeriodType>,
    pub excluded_time_range: Vec<TimeRangeType>,
}
impl ValidityPeriodDetailType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 2)?;
        let (rest, validity_period) = if optional_bits[0] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = ValidityPeriodType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_time_range) = if optional_bits[1] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = TimeRangeType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let sequence = Self {
            validity_period,
            excluded_time_range,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ValidityPeriodType {
    pub valid_from_day: crate::asn1_uper::Integer,
    pub valid_from_time: Option<crate::asn1_uper::Integer>,
    pub valid_from_utc_offset: Option<crate::asn1_uper::Integer>,
    pub valid_until_day: crate::asn1_uper::Integer,
    pub valid_until_time: Option<crate::asn1_uper::Integer>,
    pub valid_until_utc_offset: Option<crate::asn1_uper::Integer>,
}
impl ValidityPeriodType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 6)?;
        let (rest, valid_from_day) = if optional_bits[0] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-367), max: crate::asn1_uper::Integer::from_short(700) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_from_time) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_utc_offset) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_day) = if optional_bits[3] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(500) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_until_time) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_utc_offset) = if optional_bits[5] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            valid_from_day,
            valid_from_time,
            valid_from_utc_offset,
            valid_until_day,
            valid_until_time,
            valid_until_utc_offset,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TimeRangeType {
    pub from_time: crate::asn1_uper::Integer,
    pub until_time: crate::asn1_uper::Integer,
}
impl TimeRangeType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, from_time) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
        let (rest, until_time) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
        let sequence = Self {
            from_time,
            until_time,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VoucherData {
    pub reference_ia_5: Option<String>,
    pub reference_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_ia_5: Option<String>,
    pub product_id_num: Option<crate::asn1_uper::Integer>,
    pub product_id_ia_5: Option<String>,
    pub valid_from_year: crate::asn1_uper::Integer,
    pub valid_from_day: crate::asn1_uper::Integer,
    pub valid_until_year: crate::asn1_uper::Integer,
    pub valid_until_day: crate::asn1_uper::Integer,
    pub value: crate::asn1_uper::Integer,
    pub type_: Option<crate::asn1_uper::Integer>,
    pub info_text: Option<String>,
    pub extension: Option<ExtensionData>,
}
impl VoucherData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 10)?;
        let (rest, reference_ia_5) = if optional_bits[0] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_num) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_num) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(65535) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_ia_5) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_year) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(2016), max: crate::asn1_uper::Integer::from_short(2269) })?;
        let (rest, valid_from_day) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(500) })?;
        let (rest, valid_until_year) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(2016), max: crate::asn1_uper::Integer::from_short(2269) })?;
        let (rest, valid_until_day) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(500) })?;
        let (rest, value) = if optional_bits[6] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, type_) = if optional_bits[7] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, info_text) = if optional_bits[8] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, extension) = if optional_bits[9] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            reference_ia_5,
            reference_num,
            product_owner_num,
            product_owner_ia_5,
            product_id_num,
            product_id_ia_5,
            valid_from_year,
            valid_from_day,
            valid_until_year,
            valid_until_day,
            value,
            type_,
            info_text,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FipTicketData {
    pub reference_ia_5: Option<String>,
    pub reference_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_ia_5: Option<String>,
    pub product_id_num: Option<crate::asn1_uper::Integer>,
    pub product_id_ia_5: Option<String>,
    pub valid_from_day: crate::asn1_uper::Integer,
    pub valid_until_day: crate::asn1_uper::Integer,
    pub activated_day: Vec<crate::asn1_uper::Integer>,
    pub carrier_num: Vec<crate::asn1_uper::Integer>,
    pub carrier_ia_5: Vec<String>,
    pub number_of_travel_days: crate::asn1_uper::Integer,
    pub includes_supplements: bool,
    pub class_code: TravelClassType,
    pub extension: Option<ExtensionData>,
}
impl FipTicketData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 13)?;
        let (rest, reference_ia_5) = if optional_bits[0] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_num) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_num) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(65535) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_ia_5) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_day) = if optional_bits[6] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-367), max: crate::asn1_uper::Integer::from_short(700) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_until_day) = if optional_bits[7] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(500) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, activated_day) = if optional_bits[8] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(500) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, carrier_num) = if optional_bits[9] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, carrier_ia_5) = if optional_bits[10] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, number_of_travel_days) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(200) })?;
        let (rest, includes_supplements) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, class_code) = if optional_bits[11] {
            TravelClassType::try_from_uper(rest)?
        } else {
            let default_value = TravelClassType::Second;
            (rest, default_value)
        };
        let (rest, extension) = if optional_bits[12] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            reference_ia_5,
            reference_num,
            product_owner_num,
            product_owner_ia_5,
            product_id_num,
            product_id_ia_5,
            valid_from_day,
            valid_until_day,
            activated_day,
            carrier_num,
            carrier_ia_5,
            number_of_travel_days,
            includes_supplements,
            class_code,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StationPassageData {
    pub reference_ia_5: Option<String>,
    pub reference_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_ia_5: Option<String>,
    pub product_id_num: Option<crate::asn1_uper::Integer>,
    pub product_id_ia_5: Option<String>,
    pub product_name: Option<String>,
    pub station_code_table: CodeTableType,
    pub station_num: Vec<crate::asn1_uper::Integer>,
    pub station_ia_5: Vec<String>,
    pub station_name_utf_8: Vec<String>,
    pub area_code_num: Vec<crate::asn1_uper::Integer>,
    pub area_code_ia_5: Vec<String>,
    pub area_name_utf_8: Vec<String>,
    pub valid_from_day: crate::asn1_uper::Integer,
    pub valid_from_time: Option<crate::asn1_uper::Integer>,
    pub valid_from_utc_offset: Option<crate::asn1_uper::Integer>,
    pub valid_until_day: crate::asn1_uper::Integer,
    pub valid_until_time: Option<crate::asn1_uper::Integer>,
    pub valid_until_utc_offset: Option<crate::asn1_uper::Integer>,
    pub number_of_days_valid: Option<crate::asn1_uper::Integer>,
    pub extension: Option<ExtensionData>,
}
impl StationPassageData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 21)?;
        let (rest, reference_ia_5) = if optional_bits[0] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_num) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_num) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(65535) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_ia_5) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_name) = if optional_bits[6] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, station_code_table) = if optional_bits[7] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUic;
            (rest, default_value)
        };
        let (rest, station_num) = if optional_bits[8] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, station_ia_5) = if optional_bits[9] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, station_name_utf_8) = if optional_bits[10] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, area_code_num) = if optional_bits[11] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, area_code_ia_5) = if optional_bits[12] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, area_name_utf_8) = if optional_bits[13] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, valid_from_day) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-367), max: crate::asn1_uper::Integer::from_short(700) })?;
        let (rest, valid_from_time) = if optional_bits[14] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_utc_offset) = if optional_bits[15] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_day) = if optional_bits[16] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(500) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_until_time) = if optional_bits[17] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_utc_offset) = if optional_bits[18] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, number_of_days_valid) = if optional_bits[19] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, extension) = if optional_bits[20] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            reference_ia_5,
            reference_num,
            product_owner_num,
            product_owner_ia_5,
            product_id_num,
            product_id_ia_5,
            product_name,
            station_code_table,
            station_num,
            station_ia_5,
            station_name_utf_8,
            area_code_num,
            area_code_ia_5,
            area_name_utf_8,
            valid_from_day,
            valid_from_time,
            valid_from_utc_offset,
            valid_until_day,
            valid_until_time,
            valid_until_utc_offset,
            number_of_days_valid,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CustomerCardData {
    pub customer: Option<TravelerType>,
    pub card_id_ia_5: Option<String>,
    pub card_id_num: Option<crate::asn1_uper::Integer>,
    pub valid_from_year: crate::asn1_uper::Integer,
    pub valid_from_day: Option<crate::asn1_uper::Integer>,
    pub valid_until_year: crate::asn1_uper::Integer,
    pub valid_until_day: Option<crate::asn1_uper::Integer>,
    pub class_code: Option<TravelClassType>,
    pub card_type: Option<crate::asn1_uper::Integer>,
    pub card_type_descr: Option<String>,
    pub customer_status: Option<crate::asn1_uper::Integer>,
    pub customer_status_descr: Option<String>,
    pub included_services: Vec<crate::asn1_uper::Integer>,
    pub extension: Option<ExtensionData>,
}
impl CustomerCardData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 13)?;
        let (rest, customer) = if optional_bits[0] {
            let (rest, value) = TravelerType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, card_id_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, card_id_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_year) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(2016), max: crate::asn1_uper::Integer::from_short(2269) })?;
        let (rest, valid_from_day) = if optional_bits[3] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(500) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_year) = if optional_bits[4] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(250) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_until_day) = if optional_bits[5] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(500) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, class_code) = if optional_bits[6] {
            let (rest, value) = TravelClassType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, card_type) = if optional_bits[7] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(1000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, card_type_descr) = if optional_bits[8] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, customer_status) = if optional_bits[9] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, customer_status_descr) = if optional_bits[10] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, included_services) = if optional_bits[11] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, extension) = if optional_bits[12] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            customer,
            card_id_ia_5,
            card_id_num,
            valid_from_year,
            valid_from_day,
            valid_until_year,
            valid_until_day,
            class_code,
            card_type,
            card_type_descr,
            customer_status,
            customer_status_descr,
            included_services,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParkingGroundData {
    pub reference_ia_5: Option<String>,
    pub reference_num: Option<crate::asn1_uper::Integer>,
    pub parking_ground_id: String,
    pub from_parking_date: crate::asn1_uper::Integer,
    pub until_parking_date: crate::asn1_uper::Integer,
    pub product_owner_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_ia_5: Option<String>,
    pub product_id_num: Option<crate::asn1_uper::Integer>,
    pub product_id_ia_5: Option<String>,
    pub access_code: Option<String>,
    pub location: String,
    pub station_code_table: CodeTableType,
    pub station_num: Option<crate::asn1_uper::Integer>,
    pub station_ia_5: Option<String>,
    pub special_information: Option<String>,
    pub entry_track: Option<String>,
    pub number_plate: Option<String>,
    pub price: Option<crate::asn1_uper::Integer>,
    pub vat_detail: Vec<VatDetailType>,
    pub extension: Option<ExtensionData>,
}
impl ParkingGroundData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 17)?;
        let (rest, reference_ia_5) = if optional_bits[0] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_num) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, parking_ground_id) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        let (rest, from_parking_date) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-367), max: crate::asn1_uper::Integer::from_short(370) })?;
        let (rest, until_parking_date) = if optional_bits[2] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(500) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, product_owner_num) = if optional_bits[3] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_ia_5) = if optional_bits[4] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_num) = if optional_bits[5] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(65535) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_ia_5) = if optional_bits[6] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, access_code) = if optional_bits[7] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, location) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        let (rest, station_code_table) = if optional_bits[8] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUic;
            (rest, default_value)
        };
        let (rest, station_num) = if optional_bits[9] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, station_ia_5) = if optional_bits[10] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, special_information) = if optional_bits[11] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, entry_track) = if optional_bits[12] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, number_plate) = if optional_bits[13] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, price) = if optional_bits[14] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, vat_detail) = if optional_bits[15] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = VatDetailType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, extension) = if optional_bits[16] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            reference_ia_5,
            reference_num,
            parking_ground_id,
            from_parking_date,
            until_parking_date,
            product_owner_num,
            product_owner_ia_5,
            product_id_num,
            product_id_ia_5,
            access_code,
            location,
            station_code_table,
            station_num,
            station_ia_5,
            special_information,
            entry_track,
            number_plate,
            price,
            vat_detail,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CountermarkData {
    pub reference_ia_5: Option<String>,
    pub reference_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_ia_5: Option<String>,
    pub product_id_num: Option<crate::asn1_uper::Integer>,
    pub product_id_ia_5: Option<String>,
    pub ticket_reference_ia_5: Option<String>,
    pub ticket_reference_num: Option<crate::asn1_uper::Integer>,
    pub number_of_countermark: crate::asn1_uper::Integer,
    pub total_of_countermarks: crate::asn1_uper::Integer,
    pub group_name: String,
    pub station_code_table: CodeTableType,
    pub from_station_num: Option<crate::asn1_uper::Integer>,
    pub from_station_ia_5: Option<String>,
    pub to_station_num: Option<crate::asn1_uper::Integer>,
    pub to_station_ia_5: Option<String>,
    pub from_station_name_utf_8: Option<String>,
    pub to_station_name_utf_8: Option<String>,
    pub valid_region_desc: Option<String>,
    pub valid_region: Vec<RegionalValidityType>,
    pub return_included: bool,
    pub return_description: Option<ReturnRouteDescriptionType>,
    pub valid_from_day: crate::asn1_uper::Integer,
    pub valid_from_time: Option<crate::asn1_uper::Integer>,
    pub valid_from_utc_offset: Option<crate::asn1_uper::Integer>,
    pub valid_until_day: crate::asn1_uper::Integer,
    pub valid_until_time: Option<crate::asn1_uper::Integer>,
    pub valid_until_utc_offset: Option<crate::asn1_uper::Integer>,
    pub class_code: TravelClassType,
    pub carrier_num: Vec<crate::asn1_uper::Integer>,
    pub carrier_ia_5: Vec<String>,
    pub included_service_brands: Vec<crate::asn1_uper::Integer>,
    pub excluded_service_brands: Vec<crate::asn1_uper::Integer>,
    pub info_text: Option<String>,
    pub extension: Option<ExtensionData>,
}
impl CountermarkData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 31)?;
        let (rest, reference_ia_5) = if optional_bits[0] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_num) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_num) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(65535) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_ia_5) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, ticket_reference_ia_5) = if optional_bits[6] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, ticket_reference_num) = if optional_bits[7] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, number_of_countermark) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(200) })?;
        let (rest, total_of_countermarks) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(200) })?;
        let (rest, group_name) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        let (rest, station_code_table) = if optional_bits[8] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUic;
            (rest, default_value)
        };
        let (rest, from_station_num) = if optional_bits[9] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_ia_5) = if optional_bits[10] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_num) = if optional_bits[11] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_ia_5) = if optional_bits[12] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_name_utf_8) = if optional_bits[13] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_name_utf_8) = if optional_bits[14] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_region_desc) = if optional_bits[15] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_region) = if optional_bits[16] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = RegionalValidityType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, return_included) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, return_description) = if optional_bits[17] {
            let (rest, value) = ReturnRouteDescriptionType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_day) = if optional_bits[18] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-367), max: crate::asn1_uper::Integer::from_short(700) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_from_time) = if optional_bits[19] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_utc_offset) = if optional_bits[20] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_day) = if optional_bits[21] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(500) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_until_time) = if optional_bits[22] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_utc_offset) = if optional_bits[23] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, class_code) = if optional_bits[24] {
            TravelClassType::try_from_uper(rest)?
        } else {
            let default_value = TravelClassType::Second;
            (rest, default_value)
        };
        let (rest, carrier_num) = if optional_bits[25] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, carrier_ia_5) = if optional_bits[26] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, included_service_brands) = if optional_bits[27] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_service_brands) = if optional_bits[28] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, info_text) = if optional_bits[29] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, extension) = if optional_bits[30] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            reference_ia_5,
            reference_num,
            product_owner_num,
            product_owner_ia_5,
            product_id_num,
            product_id_ia_5,
            ticket_reference_ia_5,
            ticket_reference_num,
            number_of_countermark,
            total_of_countermarks,
            group_name,
            station_code_table,
            from_station_num,
            from_station_ia_5,
            to_station_num,
            to_station_ia_5,
            from_station_name_utf_8,
            to_station_name_utf_8,
            valid_region_desc,
            valid_region,
            return_included,
            return_description,
            valid_from_day,
            valid_from_time,
            valid_from_utc_offset,
            valid_until_day,
            valid_until_time,
            valid_until_utc_offset,
            class_code,
            carrier_num,
            carrier_ia_5,
            included_service_brands,
            excluded_service_brands,
            info_text,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExtensionData {
    pub extension_id: String,
    pub extension_data: Vec<u8>,
}
impl ExtensionData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, extension_id) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        let (rest, extension_data) = crate::asn1_uper::decode_octet_string(rest)?;
        let sequence = Self {
            extension_id,
            extension_data,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IncludedOpenTicketType {
    pub product_owner_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_ia_5: Option<String>,
    pub product_id_num: Option<crate::asn1_uper::Integer>,
    pub product_id_ia_5: Option<String>,
    pub external_issuer_id: Option<crate::asn1_uper::Integer>,
    pub issuer_autorization_id: Option<crate::asn1_uper::Integer>,
    pub station_code_table: CodeTableType,
    pub valid_region: Vec<RegionalValidityType>,
    pub valid_from_day: crate::asn1_uper::Integer,
    pub valid_from_time: Option<crate::asn1_uper::Integer>,
    pub valid_from_utc_offset: Option<crate::asn1_uper::Integer>,
    pub valid_until_day: crate::asn1_uper::Integer,
    pub valid_until_time: Option<crate::asn1_uper::Integer>,
    pub valid_until_utc_offset: Option<crate::asn1_uper::Integer>,
    pub class_code: Option<TravelClassType>,
    pub service_level: Option<String>,
    pub carrier_num: Vec<crate::asn1_uper::Integer>,
    pub carrier_ia_5: Vec<String>,
    pub included_service_brands: Vec<crate::asn1_uper::Integer>,
    pub excluded_service_brands: Vec<crate::asn1_uper::Integer>,
    pub tariffs: Vec<TariffType>,
    pub info_text: Option<String>,
    pub included_transport_type: Vec<crate::asn1_uper::Integer>,
    pub excluded_transport_type: Vec<crate::asn1_uper::Integer>,
    pub extension: Option<ExtensionData>,
}
impl IncludedOpenTicketType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 25)?;
        let (rest, product_owner_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(65535) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_id_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, external_issuer_id) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, issuer_autorization_id) = if optional_bits[5] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, station_code_table) = if optional_bits[6] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUic;
            (rest, default_value)
        };
        let (rest, valid_region) = if optional_bits[7] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = RegionalValidityType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, valid_from_day) = if optional_bits[8] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-367), max: crate::asn1_uper::Integer::from_short(700) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_from_time) = if optional_bits[9] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_from_utc_offset) = if optional_bits[10] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_day) = if optional_bits[11] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(500) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(0);
            (rest, default_value)
        };
        let (rest, valid_until_time) = if optional_bits[12] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_until_utc_offset) = if optional_bits[13] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, class_code) = if optional_bits[14] {
            let (rest, value) = TravelClassType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, service_level) = if optional_bits[15] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, carrier_num) = if optional_bits[16] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, carrier_ia_5) = if optional_bits[17] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, included_service_brands) = if optional_bits[18] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_service_brands) = if optional_bits[19] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, tariffs) = if optional_bits[20] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = TariffType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, info_text) = if optional_bits[21] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, included_transport_type) = if optional_bits[22] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(31) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_transport_type) = if optional_bits[23] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(31) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, extension) = if optional_bits[24] {
            let (rest, value) = ExtensionData::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            product_owner_num,
            product_owner_ia_5,
            product_id_num,
            product_id_ia_5,
            external_issuer_id,
            issuer_autorization_id,
            station_code_table,
            valid_region,
            valid_from_day,
            valid_from_time,
            valid_from_utc_offset,
            valid_until_day,
            valid_until_time,
            valid_until_utc_offset,
            class_code,
            service_level,
            carrier_num,
            carrier_ia_5,
            included_service_brands,
            excluded_service_brands,
            tariffs,
            info_text,
            included_transport_type,
            excluded_transport_type,
            extension,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TariffType {
    pub number_of_passengers: crate::asn1_uper::Integer,
    pub passenger_type: Option<PassengerType>,
    pub age_below: Option<crate::asn1_uper::Integer>,
    pub age_above: Option<crate::asn1_uper::Integer>,
    pub travelerid: Vec<crate::asn1_uper::Integer>,
    pub restricted_to_country_of_residence: bool,
    pub restricted_to_route_section: Option<RouteSectionType>,
    pub series_data_details: Option<SeriesDetailType>,
    pub tariff_id_num: Option<crate::asn1_uper::Integer>,
    pub tariff_id_ia_5: Option<String>,
    pub tariff_desc: Option<String>,
    pub reduction_card: Vec<CardReferenceType>,
}
impl TariffType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 11)?;
        let (rest, number_of_passengers) = if optional_bits[0] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(200) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(1);
            (rest, default_value)
        };
        let (rest, passenger_type) = if optional_bits[1] {
            let (rest, value) = PassengerType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, age_below) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(64) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, age_above) = if optional_bits[3] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(128) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, travelerid) = if optional_bits[4] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(254) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, restricted_to_country_of_residence) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, restricted_to_route_section) = if optional_bits[5] {
            let (rest, value) = RouteSectionType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, series_data_details) = if optional_bits[6] {
            let (rest, value) = SeriesDetailType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, tariff_id_num) = if optional_bits[7] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, tariff_id_ia_5) = if optional_bits[8] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, tariff_desc) = if optional_bits[9] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reduction_card) = if optional_bits[10] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = CardReferenceType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let sequence = Self {
            number_of_passengers,
            passenger_type,
            age_below,
            age_above,
            travelerid,
            restricted_to_country_of_residence,
            restricted_to_route_section,
            series_data_details,
            tariff_id_num,
            tariff_id_ia_5,
            tariff_desc,
            reduction_card,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SeriesDetailType {
    pub supplying_carrier: Option<crate::asn1_uper::Integer>,
    pub offer_identification: Option<crate::asn1_uper::Integer>,
    pub series: Option<crate::asn1_uper::Integer>,
}
impl SeriesDetailType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 3)?;
        let (rest, supplying_carrier) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, offer_identification) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(99) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, series) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            supplying_carrier,
            offer_identification,
            series,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteSectionType {
    pub station_code_table: CodeTableType,
    pub from_station_num: Option<crate::asn1_uper::Integer>,
    pub from_station_ia_5: Option<String>,
    pub to_station_num: Option<crate::asn1_uper::Integer>,
    pub to_station_ia_5: Option<String>,
    pub from_station_name_utf_8: Option<String>,
    pub to_station_name_utf_8: Option<String>,
}
impl RouteSectionType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 7)?;
        let (rest, station_code_table) = if optional_bits[0] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUic;
            (rest, default_value)
        };
        let (rest, from_station_num) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_ia_5) = if optional_bits[2] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_num) = if optional_bits[3] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_ia_5) = if optional_bits[4] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_name_utf_8) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_name_utf_8) = if optional_bits[6] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            station_code_table,
            from_station_num,
            from_station_ia_5,
            to_station_num,
            to_station_ia_5,
            from_station_name_utf_8,
            to_station_name_utf_8,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CardReferenceType {
    pub card_issuer_num: Option<crate::asn1_uper::Integer>,
    pub card_issuer_ia_5: Option<String>,
    pub card_id_num: Option<crate::asn1_uper::Integer>,
    pub card_id_ia_5: Option<String>,
    pub card_name: Option<String>,
    pub card_type: Option<crate::asn1_uper::Integer>,
    pub leading_card_id_num: Option<crate::asn1_uper::Integer>,
    pub leading_card_id_ia_5: Option<String>,
    pub trailing_card_id_num: Option<crate::asn1_uper::Integer>,
    pub trailing_card_id_ia_5: Option<String>,
}
impl CardReferenceType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 10)?;
        let (rest, card_issuer_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, card_issuer_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, card_id_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, card_id_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, card_name) = if optional_bits[4] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, card_type) = if optional_bits[5] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, leading_card_id_num) = if optional_bits[6] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, leading_card_id_ia_5) = if optional_bits[7] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, trailing_card_id_num) = if optional_bits[8] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, trailing_card_id_ia_5) = if optional_bits[9] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            card_issuer_num,
            card_issuer_ia_5,
            card_id_num,
            card_id_ia_5,
            card_name,
            card_type,
            leading_card_id_num,
            leading_card_id_ia_5,
            trailing_card_id_num,
            trailing_card_id_ia_5,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TravelerType {
    pub first_name: Option<String>,
    pub second_name: Option<String>,
    pub last_name: Option<String>,
    pub id_card: Option<String>,
    pub passport_id: Option<String>,
    pub title: Option<String>,
    pub gender: Option<GenderType>,
    pub customer_id_ia_5: Option<String>,
    pub customer_id_num: Option<crate::asn1_uper::Integer>,
    pub year_of_birth: Option<crate::asn1_uper::Integer>,
    pub month_of_birth: Option<crate::asn1_uper::Integer>,
    pub day_of_birth_in_month: Option<crate::asn1_uper::Integer>,
    pub ticket_holder: bool,
    pub passenger_type: Option<PassengerType>,
    pub passenger_with_reduced_mobility: Option<bool>,
    pub country_of_residence: Option<crate::asn1_uper::Integer>,
    pub country_of_passport: Option<crate::asn1_uper::Integer>,
    pub country_of_id_card: Option<crate::asn1_uper::Integer>,
    pub status: Vec<CustomerStatusType>,
}
impl TravelerType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 18)?;
        let (rest, first_name) = if optional_bits[0] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, second_name) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, last_name) = if optional_bits[2] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, id_card) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, passport_id) = if optional_bits[4] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, title) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, gender) = if optional_bits[6] {
            let (rest, value) = GenderType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, customer_id_ia_5) = if optional_bits[7] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, customer_id_num) = if optional_bits[8] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, year_of_birth) = if optional_bits[9] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1901), max: crate::asn1_uper::Integer::from_short(2155) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, month_of_birth) = if optional_bits[10] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(12) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, day_of_birth_in_month) = if optional_bits[11] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(31) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, ticket_holder) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, passenger_type) = if optional_bits[12] {
            let (rest, value) = PassengerType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, passenger_with_reduced_mobility) = if optional_bits[13] {
            let (rest, value) = crate::asn1_uper::decode_bool(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, country_of_residence) = if optional_bits[14] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, country_of_passport) = if optional_bits[15] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, country_of_id_card) = if optional_bits[16] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, status) = if optional_bits[17] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = CustomerStatusType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let sequence = Self {
            first_name,
            second_name,
            last_name,
            id_card,
            passport_id,
            title,
            gender,
            customer_id_ia_5,
            customer_id_num,
            year_of_birth,
            month_of_birth,
            day_of_birth_in_month,
            ticket_holder,
            passenger_type,
            passenger_with_reduced_mobility,
            country_of_residence,
            country_of_passport,
            country_of_id_card,
            status,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CustomerStatusType {
    pub status_provider_num: Option<crate::asn1_uper::Integer>,
    pub status_provider_ia_5: Option<String>,
    pub customer_status: Option<crate::asn1_uper::Integer>,
    pub customer_status_descr: Option<String>,
}
impl CustomerStatusType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 4)?;
        let (rest, status_provider_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, status_provider_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, customer_status) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, customer_status_descr) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            status_provider_num,
            status_provider_ia_5,
            customer_status,
            customer_status_descr,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReturnRouteDescriptionType {
    pub from_station_num: Option<crate::asn1_uper::Integer>,
    pub from_station_ia_5: Option<String>,
    pub to_station_num: Option<crate::asn1_uper::Integer>,
    pub to_station_ia_5: Option<String>,
    pub from_station_name_utf_8: Option<String>,
    pub to_station_name_utf_8: Option<String>,
    pub valid_return_region_desc: Option<String>,
    pub valid_return_region: Vec<RegionalValidityType>,
}
impl ReturnRouteDescriptionType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 8)?;
        let (rest, from_station_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_num) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_ia_5) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_name_utf_8) = if optional_bits[4] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_name_utf_8) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_return_region_desc) = if optional_bits[6] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, valid_return_region) = if optional_bits[7] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = RegionalValidityType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let sequence = Self {
            from_station_num,
            from_station_ia_5,
            to_station_num,
            to_station_ia_5,
            from_station_name_utf_8,
            to_station_name_utf_8,
            valid_return_region_desc,
            valid_return_region,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RegionalValidityType {
    TrainLink(TrainLinkType),
    ViaStations(ViaStationType),
    Zones(ZoneType),
    Lines(LineType),
    Polygone(PolygoneType),
}
impl RegionalValidityType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (mut rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(5) })?;
        let choice_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => {
                let (new_rest, inner_value) = TrainLinkType::try_from_uper(rest)?;
                rest = new_rest;
                Self::TrainLink(inner_value)
            },
            1 => {
                let (new_rest, inner_value) = ViaStationType::try_from_uper(rest)?;
                rest = new_rest;
                Self::ViaStations(inner_value)
            },
            2 => {
                let (new_rest, inner_value) = ZoneType::try_from_uper(rest)?;
                rest = new_rest;
                Self::Zones(inner_value)
            },
            3 => {
                let (new_rest, inner_value) = LineType::try_from_uper(rest)?;
                rest = new_rest;
                Self::Lines(inner_value)
            },
            4 => {
                let (new_rest, inner_value) = PolygoneType::try_from_uper(rest)?;
                rest = new_rest;
                Self::Polygone(inner_value)
            },
            other => panic!("unexpected RegionalValidityType value {}", other),
        };
        Ok((rest, choice_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrainLinkType {
    pub train_num: Option<crate::asn1_uper::Integer>,
    pub train_ia_5: Option<String>,
    pub travel_date: crate::asn1_uper::Integer,
    pub departure_time: crate::asn1_uper::Integer,
    pub departure_utc_offset: Option<crate::asn1_uper::Integer>,
    pub from_station_num: Option<crate::asn1_uper::Integer>,
    pub from_station_ia_5: Option<String>,
    pub to_station_num: Option<crate::asn1_uper::Integer>,
    pub to_station_ia_5: Option<String>,
    pub from_station_name_utf_8: Option<String>,
    pub to_station_name_utf_8: Option<String>,
}
impl TrainLinkType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 9)?;
        let (rest, train_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, train_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, travel_date) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-1), max: crate::asn1_uper::Integer::from_short(500) })?;
        let (rest, departure_time) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1439) })?;
        let (rest, departure_utc_offset) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(-60), max: crate::asn1_uper::Integer::from_short(60) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_num) = if optional_bits[3] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_ia_5) = if optional_bits[4] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_num) = if optional_bits[5] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_ia_5) = if optional_bits[6] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, from_station_name_utf_8) = if optional_bits[7] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, to_station_name_utf_8) = if optional_bits[8] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            train_num,
            train_ia_5,
            travel_date,
            departure_time,
            departure_utc_offset,
            from_station_num,
            from_station_ia_5,
            to_station_num,
            to_station_ia_5,
            from_station_name_utf_8,
            to_station_name_utf_8,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LineType {
    pub carrier_num: Option<crate::asn1_uper::Integer>,
    pub carrier_ia_5: Option<String>,
    pub line_id: Vec<crate::asn1_uper::Integer>,
    pub station_code_table: CodeTableType,
    pub entry_station_num: Option<crate::asn1_uper::Integer>,
    pub entry_station_ia_5: Option<String>,
    pub terminating_station_num: Option<crate::asn1_uper::Integer>,
    pub terminating_station_ia_5: Option<String>,
    pub city: Option<crate::asn1_uper::Integer>,
}
impl LineType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 9)?;
        let (rest, carrier_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, carrier_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, line_id) = if optional_bits[2] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, station_code_table) = if optional_bits[3] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUic;
            (rest, default_value)
        };
        let (rest, entry_station_num) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, entry_station_ia_5) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, terminating_station_num) = if optional_bits[6] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, terminating_station_ia_5) = if optional_bits[7] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, city) = if optional_bits[8] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            carrier_num,
            carrier_ia_5,
            line_id,
            station_code_table,
            entry_station_num,
            entry_station_ia_5,
            terminating_station_num,
            terminating_station_ia_5,
            city,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ZoneType {
    pub carrier_num: Option<crate::asn1_uper::Integer>,
    pub carrier_ia_5: Option<String>,
    pub station_code_table: CodeTableType,
    pub entry_station_num: Option<crate::asn1_uper::Integer>,
    pub entry_station_ia_5: Option<String>,
    pub terminating_station_num: Option<crate::asn1_uper::Integer>,
    pub terminating_station_ia_5: Option<String>,
    pub city: Option<crate::asn1_uper::Integer>,
    pub zone_id: Vec<crate::asn1_uper::Integer>,
    pub binary_zone_id: Option<Vec<u8>>,
    pub nuts_code: Option<String>,
}
impl ZoneType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 11)?;
        let (rest, carrier_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, carrier_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, station_code_table) = if optional_bits[2] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUic;
            (rest, default_value)
        };
        let (rest, entry_station_num) = if optional_bits[3] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, entry_station_ia_5) = if optional_bits[4] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, terminating_station_num) = if optional_bits[5] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, terminating_station_ia_5) = if optional_bits[6] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, city) = if optional_bits[7] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, zone_id) = if optional_bits[8] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, binary_zone_id) = if optional_bits[9] {
            let (rest, value) = crate::asn1_uper::decode_octet_string(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, nuts_code) = if optional_bits[10] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            carrier_num,
            carrier_ia_5,
            station_code_table,
            entry_station_num,
            entry_station_ia_5,
            terminating_station_num,
            terminating_station_ia_5,
            city,
            zone_id,
            binary_zone_id,
            nuts_code,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ViaStationType {
    pub station_code_table: CodeTableType,
    pub station_num: Option<crate::asn1_uper::Integer>,
    pub station_ia_5: Option<String>,
    pub alternative_routes: Vec<ViaStationType>,
    pub route: Vec<ViaStationType>,
    pub border: bool,
    pub carrier_num: Vec<crate::asn1_uper::Integer>,
    pub carrier_ia_5: Vec<String>,
    pub series_id: Option<crate::asn1_uper::Integer>,
    pub route_id: Option<crate::asn1_uper::Integer>,
    pub included_service_brands: Vec<crate::asn1_uper::Integer>,
    pub excluded_service_brands: Vec<crate::asn1_uper::Integer>,
}
impl ViaStationType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 11)?;
        let (rest, station_code_table) = if optional_bits[0] {
            CodeTableType::try_from_uper(rest)?
        } else {
            let default_value = CodeTableType::StationUic;
            (rest, default_value)
        };
        let (rest, station_num) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(9999999) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, station_ia_5) = if optional_bits[2] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, alternative_routes) = if optional_bits[3] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = ViaStationType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, route) = if optional_bits[4] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = ViaStationType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, border) = crate::asn1_uper::decode_bool(rest)?;
        let (rest, carrier_num) = if optional_bits[5] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, carrier_ia_5) = if optional_bits[6] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, series_id) = if optional_bits[7] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, route_id) = if optional_bits[8] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, included_service_brands) = if optional_bits[9] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, excluded_service_brands) = if optional_bits[10] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let sequence = Self {
            station_code_table,
            station_num,
            station_ia_5,
            alternative_routes,
            route,
            border,
            carrier_num,
            carrier_ia_5,
            series_id,
            route_id,
            included_service_brands,
            excluded_service_brands,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PolygoneType {
    pub first_edge: GeoCoordinateType,
    pub edges: Vec<DeltaCoordinates>,
}
impl PolygoneType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, first_edge) = GeoCoordinateType::try_from_uper(rest)?;
        let (rest, edges) = {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = DeltaCoordinates::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
};
        let sequence = Self {
            first_edge,
            edges,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TokenType {
    pub token_provider_num: Option<crate::asn1_uper::Integer>,
    pub token_provider_ia_5: Option<String>,
    pub token_specification: Option<String>,
    pub token: Vec<u8>,
}
impl TokenType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 3)?;
        let (rest, token_provider_num) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, token_provider_ia_5) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, token_specification) = if optional_bits[2] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, token) = crate::asn1_uper::decode_octet_string(rest)?;
        let sequence = Self {
            token_provider_num,
            token_provider_ia_5,
            token_specification,
            token,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TicketLinkType {
    pub reference_ia_5: Option<String>,
    pub reference_num: Option<crate::asn1_uper::Integer>,
    pub issuer_name: Option<String>,
    pub issuer_pnr: Option<String>,
    pub product_owner_num: Option<crate::asn1_uper::Integer>,
    pub product_owner_ia_5: Option<String>,
    pub ticket_type: TicketType,
    pub link_mode: LinkMode,
}
impl TicketLinkType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 8)?;
        let (rest, reference_ia_5) = if optional_bits[0] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, reference_num) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, issuer_name) = if optional_bits[2] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, issuer_pnr) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_num) = if optional_bits[4] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(32000) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, product_owner_ia_5) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, ticket_type) = if optional_bits[6] {
            TicketType::try_from_uper(rest)?
        } else {
            let default_value = TicketType::OpenTicket;
            (rest, default_value)
        };
        let (rest, link_mode) = if optional_bits[7] {
            LinkMode::try_from_uper(rest)?
        } else {
            let default_value = LinkMode::IssuedTogether;
            (rest, default_value)
        };
        let sequence = Self {
            reference_ia_5,
            reference_num,
            issuer_name,
            issuer_pnr,
            product_owner_num,
            product_owner_ia_5,
            ticket_type,
            link_mode,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CodeTableType {
    StationUic = 0,
    StationUicReservation = 1,
    StationEra = 2,
    LocalCarrierStationCodeTable = 3,
    ProprietaryIssuerStationCodeTable = 4,
}
impl CodeTableType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(4) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::StationUic,
            1 => Self::StationUicReservation,
            2 => Self::StationEra,
            3 => Self::LocalCarrierStationCodeTable,
            4 => Self::ProprietaryIssuerStationCodeTable,
            other => panic!("unexpected CodeTableType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ServiceType {
    Seat = 0,
    Couchette = 1,
    Berth = 2,
    Carcarriage = 3,
}
impl ServiceType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(3) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::Seat,
            1 => Self::Couchette,
            2 => Self::Berth,
            3 => Self::Carcarriage,
            other => panic!("unexpected ServiceType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PassengerType {
    Adult = 0,
    Senior = 1,
    Child = 2,
    Youth = 3,
    Dog = 4,
    Bicycle = 5,
    FreeAddonPassenger = 6,
    FreeAddonChild = 7,
}
impl PassengerType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(7) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::Adult,
            1 => Self::Senior,
            2 => Self::Child,
            3 => Self::Youth,
            4 => Self::Dog,
            5 => Self::Bicycle,
            6 => Self::FreeAddonPassenger,
            7 => Self::FreeAddonChild,
            other => panic!("unexpected PassengerType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TicketType {
    OpenTicket = 0,
    Pass = 1,
    Reservation = 2,
    CarCarriageReservation = 3,
}
impl TicketType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(3) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::OpenTicket,
            1 => Self::Pass,
            2 => Self::Reservation,
            3 => Self::CarCarriageReservation,
            other => panic!("unexpected TicketType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LinkMode {
    IssuedTogether = 0,
    OnlyValidInCombination = 1,
}
impl LinkMode {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::IssuedTogether,
            1 => Self::OnlyValidInCombination,
            other => panic!("unexpected LinkMode value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlacesType {
    pub coach: Option<String>,
    pub place_string: Option<String>,
    pub place_description: Option<String>,
    pub place_ia_5: Vec<String>,
    pub place_num: Vec<crate::asn1_uper::Integer>,
}
impl PlacesType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 5)?;
        let (rest, coach) = if optional_bits[0] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, place_string) = if optional_bits[1] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, place_description) = if optional_bits[2] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, place_ia_5) = if optional_bits[3] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let (rest, place_num) = if optional_bits[4] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(254) })?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let sequence = Self {
            coach,
            place_string,
            place_description,
            place_ia_5,
            place_num,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PriceTypeType {
    NoPrice = 0,
    ReservationFee = 1,
    Supplement = 2,
    TravelPrice = 3,
}
impl PriceTypeType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(3) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::NoPrice,
            1 => Self::ReservationFee,
            2 => Self::Supplement,
            3 => Self::TravelPrice,
            other => panic!("unexpected PriceTypeType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum BerthTypeType {
    Single = 0,
    Special = 1,
    Double = 2,
    T2 = 3,
    T3 = 4,
    T4 = 5,
}
impl BerthTypeType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(5) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::Single,
            1 => Self::Special,
            2 => Self::Double,
            3 => Self::T2,
            4 => Self::T3,
            5 => Self::T4,
            other => panic!("unexpected BerthTypeType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CompartmentGenderType {
    Unspecified = 0,
    Family = 1,
    Female = 2,
    Male = 3,
    Mixed = 4,
}
impl CompartmentGenderType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(4) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::Unspecified,
            1 => Self::Family,
            2 => Self::Female,
            3 => Self::Male,
            4 => Self::Mixed,
            other => panic!("unexpected CompartmentGenderType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GenderType {
    Unspecified = 0,
    Female = 1,
    Male = 2,
    Other = 3,
}
impl GenderType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(3) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::Unspecified,
            1 => Self::Female,
            2 => Self::Male,
            3 => Self::Other,
            other => panic!("unexpected GenderType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TravelClassType {
    NotApplicable = 0,
    First = 1,
    Second = 2,
    Tourist = 3,
    Comfort = 4,
    Premium = 5,
    Business = 6,
    All = 7,
    PremiumFirst = 8,
    StandardFirst = 9,
    PremiumSecond = 10,
    StandardSecond = 11,
}
impl TravelClassType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(11) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::NotApplicable,
            1 => Self::First,
            2 => Self::Second,
            3 => Self::Tourist,
            4 => Self::Comfort,
            5 => Self::Premium,
            6 => Self::Business,
            7 => Self::All,
            8 => Self::PremiumFirst,
            9 => Self::StandardFirst,
            10 => Self::PremiumSecond,
            11 => Self::StandardSecond,
            other => panic!("unexpected TravelClassType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BerthDetailData {
    pub berth_type: BerthTypeType,
    pub number_of_berths: crate::asn1_uper::Integer,
    pub gender: CompartmentGenderType,
}
impl BerthDetailData {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 1)?;
        let (rest, berth_type) = BerthTypeType::try_from_uper(rest)?;
        let (rest, number_of_berths) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(999) })?;
        let (rest, gender) = if optional_bits[0] {
            CompartmentGenderType::try_from_uper(rest)?
        } else {
            let default_value = CompartmentGenderType::Family;
            (rest, default_value)
        };
        let sequence = Self {
            berth_type,
            number_of_berths,
            gender,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CompartmentDetailsType {
    pub coach_type: Option<crate::asn1_uper::Integer>,
    pub compartment_type: Option<crate::asn1_uper::Integer>,
    pub special_allocation: Option<crate::asn1_uper::Integer>,
    pub coach_type_descr: Option<String>,
    pub compartment_type_descr: Option<String>,
    pub special_allocation_descr: Option<String>,
    pub position: CompartmentPositionType,
}
impl CompartmentDetailsType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 7)?;
        let (rest, coach_type) = if optional_bits[0] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(99) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, compartment_type) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(99) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, special_allocation) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(99) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, coach_type_descr) = if optional_bits[3] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, compartment_type_descr) = if optional_bits[4] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, special_allocation_descr) = if optional_bits[5] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, position) = if optional_bits[6] {
            CompartmentPositionType::try_from_uper(rest)?
        } else {
            let default_value = CompartmentPositionType::Unspecified;
            (rest, default_value)
        };
        let sequence = Self {
            coach_type,
            compartment_type,
            special_allocation,
            coach_type_descr,
            compartment_type_descr,
            special_allocation_descr,
            position,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LuggageRestrictionType {
    pub max_hand_luggage_pieces: crate::asn1_uper::Integer,
    pub max_non_hand_luggage_pieces: crate::asn1_uper::Integer,
    pub registered_luggage: Vec<RegisteredLuggageType>,
}
impl LuggageRestrictionType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 3)?;
        let (rest, max_hand_luggage_pieces) = if optional_bits[0] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(99) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(3);
            (rest, default_value)
        };
        let (rest, max_non_hand_luggage_pieces) = if optional_bits[1] {
            crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(99) })?
        } else {
            let default_value = crate::asn1_uper::Integer::from_short(1);
            (rest, default_value)
        };
        let (rest, registered_luggage) = if optional_bits[2] {
            {
    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
    let length_usize = length_integer.try_to_usize()
        .expect("failed to convert length to usize");
    let mut buf = Vec::with_capacity(length_usize);
    for _ in 0..length_usize {
        let (new_rest, member) = RegisteredLuggageType::try_from_uper(rest)?;
        buf.push(member);
        rest = new_rest;
    }
    (rest, buf)
}
        } else {
            (rest, Vec::new())
        };
        let sequence = Self {
            max_hand_luggage_pieces,
            max_non_hand_luggage_pieces,
            registered_luggage,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegisteredLuggageType {
    pub registration_id: Option<String>,
    pub max_weight: Option<crate::asn1_uper::Integer>,
    pub max_size: Option<crate::asn1_uper::Integer>,
}
impl RegisteredLuggageType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 3)?;
        let (rest, registration_id) = if optional_bits[0] {
            let (rest, value) = {
    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest)?;
    let utf8_string = String::from_utf8(octet_string).expect("failed to decode UTF-8 string as UTF-8");
    (rest, utf8_string)
};
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, max_weight) = if optional_bits[1] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(99) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let (rest, max_size) = if optional_bits[2] {
            let (rest, value) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(1), max: crate::asn1_uper::Integer::from_short(300) })?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            registration_id,
            max_weight,
            max_size,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GeoCoordinateType {
    pub geo_unit: GeoUnitType,
    pub coordinate_system: GeoCoordinateSystemType,
    pub hemisphere_longitude: HemisphereLongitudeType,
    pub hemisphere_latitude: HemisphereLatitudeType,
    pub longitude: crate::asn1_uper::Integer,
    pub latitude: crate::asn1_uper::Integer,
    pub accuracy: Option<GeoUnitType>,
}
impl GeoCoordinateType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, 5)?;
        let (rest, geo_unit) = if optional_bits[0] {
            GeoUnitType::try_from_uper(rest)?
        } else {
            let default_value = GeoUnitType::MilliDegree;
            (rest, default_value)
        };
        let (rest, coordinate_system) = if optional_bits[1] {
            GeoCoordinateSystemType::try_from_uper(rest)?
        } else {
            let default_value = GeoCoordinateSystemType::Wgs84;
            (rest, default_value)
        };
        let (rest, hemisphere_longitude) = if optional_bits[2] {
            HemisphereLongitudeType::try_from_uper(rest)?
        } else {
            let default_value = HemisphereLongitudeType::North;
            (rest, default_value)
        };
        let (rest, hemisphere_latitude) = if optional_bits[3] {
            HemisphereLatitudeType::try_from_uper(rest)?
        } else {
            let default_value = HemisphereLatitudeType::East;
            (rest, default_value)
        };
        let (rest, longitude) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
        let (rest, latitude) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
        let (rest, accuracy) = if optional_bits[4] {
            let (rest, value) = GeoUnitType::try_from_uper(rest)?;
            (rest, Some(value))
        } else {
            (rest, None)
        };
        let sequence = Self {
            geo_unit,
            coordinate_system,
            hemisphere_longitude,
            hemisphere_latitude,
            longitude,
            latitude,
            accuracy,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeltaCoordinates {
    pub longitude: crate::asn1_uper::Integer,
    pub latitude: crate::asn1_uper::Integer,
}
impl DeltaCoordinates {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, longitude) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
        let (rest, latitude) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;
        let sequence = Self {
            longitude,
            latitude,
        };
        Ok((rest, sequence))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GeoCoordinateSystemType {
    Wgs84 = 0,
    Grs80 = 1,
}
impl GeoCoordinateSystemType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::Wgs84,
            1 => Self::Grs80,
            other => panic!("unexpected GeoCoordinateSystemType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GeoUnitType {
    MicroDegree = 0,
    TenthmilliDegree = 1,
    MilliDegree = 2,
    CentiDegree = 3,
    DeciDegree = 4,
}
impl GeoUnitType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(4) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::MicroDegree,
            1 => Self::TenthmilliDegree,
            2 => Self::MilliDegree,
            3 => Self::CentiDegree,
            4 => Self::DeciDegree,
            other => panic!("unexpected GeoUnitType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum HemisphereLongitudeType {
    North = 0,
    South = 1,
}
impl HemisphereLongitudeType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::North,
            1 => Self::South,
            other => panic!("unexpected HemisphereLongitudeType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum HemisphereLatitudeType {
    East = 0,
    West = 1,
}
impl HemisphereLatitudeType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::East,
            1 => Self::West,
            other => panic!("unexpected HemisphereLatitudeType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LoadingDeckType {
    Unspecified = 0,
    Upper = 1,
    Lower = 2,
}
impl LoadingDeckType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(2) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::Unspecified,
            1 => Self::Upper,
            2 => Self::Lower,
            other => panic!("unexpected LoadingDeckType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CompartmentPositionType {
    Unspecified = 0,
    UpperLevel = 1,
    LowerLevel = 2,
}
impl CompartmentPositionType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(2) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::Unspecified,
            1 => Self::UpperLevel,
            2 => Self::LowerLevel,
            other => panic!("unexpected CompartmentPositionType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RoofRackType {
    Norack = 0,
    RoofRailing = 1,
    LuggageRack = 2,
    SkiRack = 3,
    BoxRack = 4,
    RackWithOneBox = 5,
    RackWithTwoBoxes = 6,
    BicycleRack = 7,
    OtherRack = 8,
}
impl RoofRackType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(8) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::Norack,
            1 => Self::RoofRailing,
            2 => Self::LuggageRack,
            3 => Self::SkiRack,
            4 => Self::BoxRack,
            5 => Self::RackWithOneBox,
            6 => Self::RackWithTwoBoxes,
            7 => Self::BicycleRack,
            8 => Self::OtherRack,
            other => panic!("unexpected RoofRackType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum BoardingOrArrivalRestrictionType {
    Boarding = 0,
    Arrival = 1,
}
impl BoardingOrArrivalRestrictionType {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::Error<'a>>> {
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short(1) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            0 => Self::Boarding,
            1 => Self::Arrival,
            other => panic!("unexpected BoardingOrArrivalRestrictionType value {}", other),
        };
        Ok((rest, enum_value))
    }
}
