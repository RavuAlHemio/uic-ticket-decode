mod asn1_uper;


use std::env;
use std::io::{Cursor, Read};

use flate2;
use rxing;

use crate::asn1_uper::{
    decode_bool, decode_bools, decode_ia5_string, decode_integer, decode_length,
    decode_octet_string, Integer, to_bits_msb_first, WholeNumberConstraint,
};


fn hexdump(bs: &[u8]) {
    for b in bs {
        print!(" {:02X}", b);
    }
    println!();
}


fn main() {
    let args: Vec<String> = env::args().collect();
    let barcode = rxing::helpers::detect_in_file(&args[1], None)
        .expect("failed to detect Aztec barcode");
    let barcode_contents: Vec<u8> = barcode.getText().chars()
        .map(|c| u8::try_from(u32::from(c)).expect("failed to decode character as byte"))
        .collect();

    print!("barcode contents:");
    hexdump(&barcode_contents);

    // ERA-REC-122 B.12 § 10.6
    if !barcode_contents.starts_with(b"#UT") {
        panic!("barcode does not contain a UIC ticket");
    }
    let version = &barcode_contents[3..5];
    let compressed_bytes = if version == b"01" {
        println!("UIC ticket version 1");

        let signer_number_bytes = &barcode_contents[5..9];
        let signer_number = String::from_utf8(Vec::from(signer_number_bytes))
            .expect("signer number is not decodable");
        println!("  signer number: {}", signer_number);

        let key_id_bytes = &barcode_contents[9..14];
        let key_id = String::from_utf8(Vec::from(key_id_bytes))
            .expect("key ID is not decodable");
        println!("  key ID: {}", key_id);

        let signature_bytes = &barcode_contents[14..64];
        print!("  signature bytes (ASN.1):");
        hexdump(signature_bytes);

        let compressed_len_bytes = &barcode_contents[64..68];
        let compressed_len_string = String::from_utf8(Vec::from(compressed_len_bytes))
            .expect("compressed length is not decodable");
        let compressed_len: usize = compressed_len_string.parse()
            .expect("compressed length is not parsable");
        println!("  compressed data length is {} bytes", compressed_len);
        &barcode_contents[68..68+compressed_len]
    } else if version == b"02" {
        println!("UIC ticket version 2");

        let signer_number_bytes = &barcode_contents[5..9];
        let signer_number = String::from_utf8(Vec::from(signer_number_bytes))
            .expect("signer number is not decodable");
        println!("  signer number: {}", signer_number);

        let key_id_bytes = &barcode_contents[9..14];
        let key_id = String::from_utf8(Vec::from(key_id_bytes))
            .expect("key ID is not decodable");
        println!("  key ID: {}", key_id);

        let signature_r = &barcode_contents[14..46];
        print!("  DSA signature r:");
        hexdump(signature_r);

        let signature_s = &barcode_contents[46..78];
        print!("  DSA signature s:");
        hexdump(signature_s);

        let compressed_len_bytes = &barcode_contents[78..82];
        let compressed_len_string = String::from_utf8(Vec::from(compressed_len_bytes))
            .expect("compressed length is not decodable");
        let compressed_len: usize = compressed_len_string.parse()
            .expect("compressed length is not parsable");
        println!("  compressed data length is {} bytes", compressed_len);
        &barcode_contents[82..82+compressed_len]
    } else {
        panic!("unknown UIC ticket version {:?}", version);
    };

    print!("  compressed data bytes:");
    hexdump(compressed_bytes);

    // uncompress
    let mut data_bytes = Vec::new();
    flate2::read::ZlibDecoder::new(Cursor::new(compressed_bytes))
        .read_to_end(&mut data_bytes)
        .expect("failed to decompress data");

    print!("  uncompressed data bytes:");
    hexdump(&data_bytes);

    let mut remaining_bytes = data_bytes.as_slice();
    while remaining_bytes.len() > 0 {
        println!();

        let record_id = &remaining_bytes[0..6];
        let record_id_string = String::from_utf8(Vec::from(record_id))
            .expect("failed to decode record ID");
        println!("record {}", record_id_string);

        let record_version = &remaining_bytes[6..8];
        let record_version_string = String::from_utf8(Vec::from(record_version))
            .expect("failed to decode record version");
        println!("  version {}", record_version_string);

        let record_length_bytes = &remaining_bytes[8..12];
        let record_length_string = String::from_utf8(Vec::from(record_length_bytes))
            .expect("failed to decode record length");
        let record_length: usize = record_length_string.parse()
            .expect("failed to parse record length");
        println!("  length (including ID and version): {}", record_length);

        let record_data = &remaining_bytes[12..record_length];
        decode_record(record_id, record_version, record_data);

        remaining_bytes = &remaining_bytes[record_length..];
    }
}

fn decode_record(record_id: &[u8], record_version: &[u8], record_data: &[u8]) {
    if record_id == b"U_FLEX" && record_version == b"03" {
        decode_record_uflex_3(record_data);
    } else {
        println!("cannot decode this record type");
    }
}

fn decode_record_uflex_3(record_data: &[u8]) {
    // https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicRailTicketData_v3.0.3.asn

    // convert record data to bits
    let record_data_bits = to_bits_msb_first(record_data);

    // we start with UicRailTicketData, which is extensible and has four optional fields
    let (rest, uic_rail_ticket_data_optionals) = decode_bools(&record_data_bits, 5)
        .expect("failed to decode UicRailTicketData optionals");
    let uic_rail_ticket_data_has_extension_weirdness = uic_rail_ticket_data_optionals[0];
    let uic_rail_ticket_data_has_traveler_data = uic_rail_ticket_data_optionals[1];
    let uic_rail_ticket_data_has_transport_document_data = uic_rail_ticket_data_optionals[2];
    let uic_rail_ticket_data_has_control_data = uic_rail_ticket_data_optionals[3];
    let uic_rail_ticket_data_has_extension_data = uic_rail_ticket_data_optionals[4];

    if uic_rail_ticket_data_has_extension_weirdness {
        panic!("cannot deal with ASN.1 extensibility");
    }

    let mut rest = decode_record_uflex_3_issuing_data(rest);
    if uic_rail_ticket_data_has_traveler_data {
        rest = decode_record_uflex_3_traveler_data(rest);
    }
    if uic_rail_ticket_data_has_transport_document_data {
        let (this_rest, sequence_count) = decode_length(&rest, &WholeNumberConstraint::SemiConstrained { min: Integer::from_short(0) })
            .expect("failed to decode number of transport document data entries");
        for _ in 0..sequence_count.try_to_usize().expect("does not fit into usize") {
            rest = decode_record_uflex_3_transport_document_data(rest);
        }
        rest = this_rest;
    }
    if uic_rail_ticket_data_has_control_data {
        rest = decode_record_uflex_3_control_data(rest);
    }
    if uic_rail_ticket_data_has_extension_data {
        let (this_rest, sequence_count) = decode_length(&rest, &WholeNumberConstraint::SemiConstrained { min: Integer::from_short(0) })
            .expect("failed to decode number of transport document data entries");
        for _ in 0..sequence_count.try_to_usize().expect("does not fit into usize") {
            rest = decode_record_uflex_3_extension_data(rest);
        }
        rest = this_rest;
    }
}

fn decode_record_uflex_3_issuing_data(record_data: &[bool]) -> &[bool] {
    // we are extensible and have 13 optional/default fields
    let (mut rest, issuing_data_optionals) = decode_bools(record_data, 14)
        .expect("failed to decode IssuingData optionals");
    let issuing_data_has_extension_weirdness = issuing_data_optionals[0];
    let issuing_data_has_security_provider_num = issuing_data_optionals[1];
    let issuing_data_has_security_provider_ia5 = issuing_data_optionals[2];
    let issuing_data_has_issuer_num = issuing_data_optionals[3];
    let issuing_data_has_issuer_ia5 = issuing_data_optionals[4];
    let issuing_data_has_issuer_name = issuing_data_optionals[5];
    let issuing_data_has_currency = issuing_data_optionals[6];
    let issuing_data_has_currency_fraction = issuing_data_optionals[7];
    let issuing_data_has_issuer_pnr = issuing_data_optionals[8];
    let issuing_data_has_extension = issuing_data_optionals[9];
    let issuing_data_has_issued_on_train_number = issuing_data_optionals[10];
    let issuing_data_has_issued_on_train_ia5 = issuing_data_optionals[11];
    let issuing_data_has_issued_on_line = issuing_data_optionals[12];
    let issuing_data_has_point_of_sale = issuing_data_optionals[13];

    if issuing_data_has_extension_weirdness {
        panic!("cannot deal with ASN.1 extensibility");
    }

    if issuing_data_has_security_provider_num {
        let constraint = WholeNumberConstraint::Constrained {
            min: Integer::from_short(1),
            max: Integer::from_short(32000),
        };
        let (this_rest, provider_num) = decode_integer(rest, &constraint)
            .expect("failed to decode IssuingData.securityProviderNum");
        println!("  security provider number: {}", provider_num);
        rest = this_rest;
    }
    if issuing_data_has_security_provider_ia5 {
        let (this_rest, security_provider_ia5_bytes) = decode_ia5_string(rest)
            .expect("failed to decode IssuingData.securityProviderIA5");
        let security_provider_ia5 = String::from_utf8(security_provider_ia5_bytes)
            .expect("failed to decode IssuingData.securityProviderIA5 as UTF-8");
        println!("  security provider IA5: {:?}", security_provider_ia5);
        rest = this_rest;
    }
    if issuing_data_has_issuer_num {
        let constraint = WholeNumberConstraint::Constrained {
            min: Integer::from_short(1),
            max: Integer::from_short(32000),
        };
        let (this_rest, issuer_num) = decode_integer(rest, &constraint)
            .expect("failed to decode IssuingData.securityProviderNum");
        println!("  issuer number: {}", issuer_num);
        rest = this_rest;
    }
    if issuing_data_has_issuer_ia5 {
        let (this_rest, issuer_ia5_bytes) = decode_ia5_string(rest)
            .expect("failed to decode IssuingData.issuerIA5");
        let issuer_ia5 = String::from_utf8(issuer_ia5_bytes)
            .expect("failed to decode IssuingData.issuerIA5 as UTF-8");
        println!("  issuer IA5: {:?}", issuer_ia5);
        rest = this_rest;
    }

    let issuing_year_constraint = WholeNumberConstraint::Constrained {
        min: Integer::from_short(2016),
        max: Integer::from_short(2269),
    };
    let (rest, issuing_year) = decode_integer(rest, &issuing_year_constraint)
        .expect("failed to decode IssuingData.issuingYear");
    println!("  issuing year: {}", issuing_year);

    let issuing_day_constraint = WholeNumberConstraint::Constrained {
        min: Integer::from_short(1),
        max: Integer::from_short(366),
    };
    let (rest, issuing_day) = decode_integer(rest, &issuing_day_constraint)
        .expect("failed to decode IssuingData.issuingDay");
    println!("  issuing day: {}", issuing_day);

    let issuing_time_constraint = WholeNumberConstraint::Constrained {
        min: Integer::from_short(0),
        max: Integer::from_short(1439),
    };
    let (mut rest, issuing_time) = decode_integer(rest, &issuing_time_constraint)
        .expect("failed to decode IssuingData.issuingTime");
    println!("  issuing time (minute): {}", issuing_time);

    if issuing_data_has_issuer_name {
        let (this_rest, issuer_name_bytes) = decode_octet_string(rest)
            .expect("failed to decode IssuingData.issuerName");
        let issuer_name = String::from_utf8(issuer_name_bytes)
            .expect("failed to decode IssuingData.issuerName as UTF-8");
        println!("  issuer name: {:?}", issuer_name);
        rest = this_rest;
    }

    let (rest, is_specimen) = decode_bool(rest)
        .expect("failed to decode IssuingData.specimen");
    if is_specimen {
        println!("  is a specimen");
    } else {
        println!("  is not a specimen");
    }

    let (rest, is_secure_paper_ticket) = decode_bool(rest)
        .expect("failed to decode IssuingData.securePaperTicket");
    if is_secure_paper_ticket {
        println!("  is a secure paper ticket");
    } else {
        println!("  is not a secure paper ticket");
    }

    let (mut rest, is_activated) = decode_bool(rest)
        .expect("failed to decode IssuingData.activated");
    if is_activated {
        println!("  is activated");
    } else {
        println!("  is not activated");
    }

    if issuing_data_has_currency {
        let (this_rest, issuer_name_bytes) = decode_ia5_string(rest)
            .expect("failed to decode IssuingData.currency");
        let currency = String::from_utf8(issuer_name_bytes)
            .expect("failed to decode IssuingData.currency as UTF-8");
        println!("  currency: {:?}", currency);
        rest = this_rest;
    } else {
        println!("  default currency (EUR)");
    }

    if issuing_data_has_currency_fraction {
        let currency_fraction_constraint = WholeNumberConstraint::Constrained {
            min: Integer::from_short(1),
            max: Integer::from_short(3),
        };
        let (this_rest, currency_fraction) = decode_integer(rest, &currency_fraction_constraint)
            .expect("failed to decode IssuingData.currencyFract");
        println!("  currency fraction: {:?}", currency_fraction);
        rest = this_rest;
    } else {
        println!("  default currency fraction (2)");
    }

    if issuing_data_has_issuer_pnr {
        let (this_rest, issuer_pnr_bytes) = decode_ia5_string(rest)
            .expect("failed to decode IssuingData.currency");
        let issuer_pnr = String::from_utf8(issuer_pnr_bytes)
            .expect("failed to decode IssuingData.currency as UTF-8");
        println!("  issuer PNR: {:?}", issuer_pnr);
        rest = this_rest;
    }

    if issuing_data_has_extension {
        rest = decode_record_uflex_3_extension_data(rest);
    }

    if issuing_data_has_issued_on_train_number {
        let (this_rest, train_number) = decode_integer(rest, &WholeNumberConstraint::Unconstrained)
            .expect("failed to decode Issuingdata.issuedOnTrainNum");
        println!("  issued on train number: {}", train_number);
        rest = this_rest;
    }
    if issuing_data_has_issued_on_train_ia5 {
        let (this_rest, train_ia5_bytes) = decode_ia5_string(rest)
            .expect("failed to decode Issuingdata.issuedOnTrainIA5");
        let train_ia5 = String::from_utf8(train_ia5_bytes)
            .expect("failed to decode IssuingData.issuedOnTrainIA5 as UTF-8");
        println!("  issued on train: {}", train_ia5);
        rest = this_rest;
    }
    if issuing_data_has_issued_on_line {
        let (this_rest, train_line) = decode_integer(rest, &WholeNumberConstraint::Unconstrained)
            .expect("failed to decode Issuingdata.issuedOnLine");
        println!("  issued on line: {}", train_line);
        rest = this_rest;
    }
    if issuing_data_has_point_of_sale {
        todo!("cannot handle GeoCoordinateType yet");
    }

    rest
}

fn decode_record_uflex_3_extension_data(rest: &[bool]) -> &[bool] {
    println!("  extension:");
    let (this_rest, extension_id_bytes) = decode_ia5_string(rest)
        .expect("failed to decode IssuingData.extension.extensionId");
    let extension_id = String::from_utf8(extension_id_bytes)
        .expect("failed to decode IssuingData.extension.extensionId as UTF-8");
    println!("    extension ID: {:?}", extension_id);
    let (this_rest, extension_data) = decode_octet_string(this_rest)
        .expect("failed to decode IssuingData.extension.extensionData");
    println!("    extension data: {:?}", extension_data);
    this_rest
}
