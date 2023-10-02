mod asn1_uper;
mod uflex_3;
mod utlay_painter;


use std::env;
use std::io::{Cursor, Read};

use flate2;
use rxing;

use crate::asn1_uper::to_bits_msb_first;


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
    } else if record_id == b"U_HEAD" && record_version == b"01" {
        decode_record_uhead_1(record_data);
    } else if record_id == b"U_TLAY" && record_version == b"01" {
        decode_record_utlay_1(record_data);
    } else {
        println!("  cannot decode this record type; hex dump:");
        hexdump(record_data);
    }
}

fn decode_record_uflex_3(record_data: &[u8]) {
    // https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicRailTicketData_v3.0.3.asn

    // convert record data to bits
    let record_data_bits = to_bits_msb_first(record_data);

    // the top structure is UicRailTicketData
    let (_rest, uic_rail_ticket_data) = crate::uflex_3::UicRailTicketData::try_from_uper(&record_data_bits)
        .expect("failed to decode UicRailTicketData");

    println!("{:#?}", uic_rail_ticket_data);
}

fn bytes_to_string(bs: &[u8]) -> String {
    match std::str::from_utf8(bs) {
        Ok(s) => format!("{:?}", s),
        Err(_) => format!("{:?}", bs),
    }
}

fn decode_record_uhead_1(record_data: &[u8]) {
    // https://www.era.europa.eu/system/files/2022-11/era_technical_document_tap_b_7_v1.3.0.pdf § 8.3

    let distributing_ru = bytes_to_string(&record_data[0..4]);
    println!("  distributing RU: {}", distributing_ru);

    let ticket_key = bytes_to_string(&record_data[4..24]);
    println!("  ticket key: {}", ticket_key);

    let time_of_issuance = bytes_to_string(&record_data[24..36]);
    println!("  time of issuance: {}", time_of_issuance);

    let flags = bytes_to_string(&record_data[36..37]);
    println!("  flags: {}", flags);
    if let Ok(s) = std::str::from_utf8(&record_data[36..37]) {
        if let Ok(b) = s.parse::<u8>() {
            if b == 0 {
                println!("    no flags set");
            } else {
                if b & 0b001 != 0 {
                    println!("    international ticket");
                }
                if b & 0b010 != 0 {
                    println!("    edited by agent");
                }
                if b & 0b100 != 0 {
                    println!("    specimen");
                }
            }
        }
    }

    let language = bytes_to_string(&record_data[37..39]);
    println!("  language: {}", language);

    let second_language = bytes_to_string(&record_data[39..41]);
    println!("  second language: {}", second_language);
}

fn decode_record_utlay_1(record_data: &[u8]) {
    // https://www.era.europa.eu/system/files/2022-11/era_technical_document_tap_b_7_v1.3.0.pdf § 8.4

    let layout_standard = bytes_to_string(&record_data[0..4]);
    println!("  layout standard: {}", layout_standard);

    let number_fields = bytes_to_string(&record_data[4..8]);
    println!("  number of fields: {}", number_fields);
    if let Ok(s) = std::str::from_utf8(&record_data[4..8]) {
        if let Ok(n) = s.parse::<usize>() {
            let mut canvas = utlay_painter::Canvas::new();
            let mut index = 8;
            for i in 0..n {
                println!("  field {}:", i);

                let field_line = bytes_to_string(&record_data[index+0..index+2]);
                println!("    line: {}", field_line);

                let field_column = bytes_to_string(&record_data[index+2..index+4]);
                println!("    column: {}", field_column);

                let field_height = bytes_to_string(&record_data[index+4..index+6]);
                println!("    height: {}", field_height);

                let field_width = bytes_to_string(&record_data[index+6..index+8]);
                println!("    width: {}", field_width);

                let field_formatting = bytes_to_string(&record_data[index+8..index+9]);
                println!("    formatting: {}", field_formatting);

                let field_text_length = bytes_to_usize(&record_data[index+9..index+13])
                    .expect("failed to decode field text length");

                let field_text = bytes_to_string(&record_data[index+13..index+13+field_text_length]);
                println!("    text: {}", field_text);

                let orig_index = index;
                index += 13 + field_text_length;

                let Some(line_num) = bytes_to_usize(&record_data[orig_index+0..orig_index+2]) else { continue };
                let Some(col_num) = bytes_to_usize(&record_data[orig_index+2..orig_index+4]) else { continue };
                let Some(height_num) = bytes_to_usize(&record_data[orig_index+4..orig_index+6]) else { continue };
                let Some(width_num) = bytes_to_usize(&record_data[orig_index+6..orig_index+8]) else { continue };
                let Ok(text) = String::from_utf8(Vec::from(&record_data[orig_index+13..orig_index+13+field_text_length])) else { continue };
                let record = utlay_painter::Record {
                    line: line_num,
                    column: col_num,
                    width: width_num,
                    height: height_num,
                    text,
                };
                canvas.paint_record(&record);
            }
            let canvas_in_a_box = utlay_painter::CanvasInABox(&canvas);
            println!("{}", canvas_in_a_box);
        }
    }
}

fn bytes_to_usize(slice: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(slice).ok()?;
    s.parse().ok()
}
