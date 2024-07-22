mod asn1_uper;
mod key_db;
mod pngify;
mod uflex_3;
mod uflex_3_ext;
mod utlay_painter;


use std::fs::File;
use std::io::{Cursor, Read, BufWriter};
use std::path::{Path, PathBuf};

use clap::Parser;
use flate2;
use rand::Rng as _;
use rxing::Writer as _;

use crate::asn1_uper::{to_bits_msb_first, to_bytes_msb_first};
use crate::key_db::Signature;
use crate::uflex_3_ext::output_ticket_validity;


#[derive(Parser)]
enum ProgMode {
    Barcode(BarcodeArgs),
    Data(DataArgs),
    Encode(EncodeArgs),
}

#[derive(Parser)]
struct BarcodeArgs {
    pub barcode_path: String,

    /// Path to the XML key database for verification.
    #[arg(short, long)]
    pub keys_path: Option<PathBuf>,
}

#[derive(Parser)]
struct DataArgs {
    pub data_path: PathBuf,

    #[arg(short, long)]
    pub re_encode_path: Option<PathBuf>,

    /// Path to the XML key database for verification.
    #[arg(short, long)]
    pub keys_path: Option<PathBuf>,
}

#[derive(Parser)]
struct EncodeArgs {
    pub json_path: PathBuf,
    pub output_path: PathBuf,

    #[arg(short, long)]
    pub png: bool,

    #[arg(default_value = "6969")]
    pub signer_number: String,

    #[arg(default_value = "66666")]
    pub key_id: String,
}


fn hexdump(bs: &[u8]) {
    for b in bs {
        print!(" {:02X}", b);
    }
    println!();
}


fn encode(encode_args: EncodeArgs) {
    if encode_args.signer_number.len() != 4 {
        panic!("signer number {:?} is not 4 bytes long", encode_args.signer_number);
    }
    if encode_args.key_id.len() != 5 {
        panic!("key ID {:?} is not 4 bytes long", encode_args.key_id);
    }

    // outer structure:
    // "#UT02"
    // 4 bytes signer number
    // 5 bytes key ID
    // 32 bytes DSA signature r
    // 32 bytes DSA signature s
    // 4 bytes textual representation of compressed length
    // rest compressed data: ZLIB(inner structure)

    // inner structure:
    // loop start
    // 6 bytes record ID ("U_FLEX")
    // 2 bytes version ("03")
    // 4 bytes textual representation of record length
    // rest record data
    // loop end

    // record data: unaligned PER encoding of UicRailTicketData structure

    // deserialize UicRailTicketData from JSON
    let json_string = std::fs::read_to_string(&encode_args.json_path)
        .expect("failed to read JSON file");
    let ticket_data: crate::uflex_3::UicRailTicketData = serde_json::from_str(&json_string)
        .expect("failed to deserialize JSON");

    // serialize UicRailTicketData to bytes
    let mut uper_bits = Vec::new();
    ticket_data.write_uper(&mut uper_bits)
        .expect("failed to serialize ticket bits");
    let uper_bytes = to_bytes_msb_first(&uper_bits);
    let uper_length = 6 + 2 + 4 + uper_bytes.len();
    let uper_length_text = format!("{:04}", uper_length);
    if uper_length_text.len() != 4 {
        panic!("record length as text does not fit into four bytes");
    }
    let mut full_flex: Vec<u8> = Vec::with_capacity(uper_length);
    full_flex.extend(b"U_FLEX03");
    full_flex.extend(uper_length_text.as_bytes());
    full_flex.extend(&uper_bytes);

    // zlib-compress
    let mut compressed_bytes = Vec::new();
    flate2::read::ZlibEncoder::new(Cursor::new(&full_flex), flate2::Compression::best())
        .read_to_end(&mut compressed_bytes)
        .expect("failed to compress data");
    let compressed_length_text = format!("{:04}", compressed_bytes.len());
    if compressed_length_text.len() != 4 {
        panic!("compressed data length as text does not fit into four bytes");
    }

    // embed in outer structure
    let mut outer_bytes: Vec<u8> = Vec::new();
    outer_bytes.extend(b"#UT02");
    outer_bytes.extend(encode_args.signer_number.as_bytes());
    outer_bytes.extend(encode_args.key_id.as_bytes());

    let mut dsa_r = [0u8; 32];
    let mut dsa_s = [0u8; 32];
    rand::thread_rng().fill(&mut dsa_r);
    rand::thread_rng().fill(&mut dsa_s);
    outer_bytes.extend(&dsa_r);
    outer_bytes.extend(&dsa_s);
    outer_bytes.extend(compressed_length_text.as_bytes());
    outer_bytes.extend(&compressed_bytes);

    if encode_args.png {
        // convert bytes to pseudo-textual string by pretending it's ISO-8859-1
        let mut outer_string = String::new();
        for &b in &outer_bytes {
            let c = char::from_u32(b.into()).unwrap();
            outer_string.push(c);
        }

        // encode as Aztec
        let aztec_barcode = rxing::aztec::AztecWriter.encode(
            &outer_string,
            &rxing::BarcodeFormat::AZTEC,
            0, 0,
        ).expect("failed to encode as Aztec");

        // write out as PNG
        let f = File::create(&encode_args.output_path)
            .expect("failed to create output");
        let bufw = BufWriter::new(f);
        pngify::write_bit_matrix_as_png(bufw, &aztec_barcode, 5, 25);
    } else {
    // write out data
        std::fs::write(&encode_args.output_path, &outer_bytes)
            .expect("failed to write output");
    }
}


fn main() {
    let prog_mode = ProgMode::parse();
    let (barcode_contents, re_encode_path, keys_path_opt) = match prog_mode {
        ProgMode::Barcode(barcode_args) => {
            let barcode = rxing::helpers::detect_in_file(&barcode_args.barcode_path, None)
                .expect("failed to detect Aztec barcode");
            let barcode_contents: Vec<u8> = barcode.getText().chars()
                .map(|c| u8::try_from(u32::from(c)).expect("failed to decode character as byte"))
                .collect();
            (barcode_contents, None, barcode_args.keys_path)
        },
        ProgMode::Data(data_args) => {
            let data = std::fs::read(&data_args.data_path)
                .expect("failed to read barcode data");
            (data, data_args.re_encode_path, data_args.keys_path)
        },
        ProgMode::Encode(encode_args) => {
            encode(encode_args);
            return;
        },
    };

    print!("barcode contents:");
    hexdump(&barcode_contents);

    // ERA-REC-122 B.12 § 10.6
    if !barcode_contents.starts_with(b"#UT") {
        panic!("barcode does not contain a UIC ticket");
    }
    let version = &barcode_contents[3..5];
    let (compressed_bytes, signer_number, key_id, signature) = if version == b"01" {
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
        (&barcode_contents[68..68+compressed_len], signer_number, key_id, Signature::Asn1(signature_bytes.to_vec()))
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
        (&barcode_contents[82..82+compressed_len], signer_number, key_id, Signature::Dsa { r: signature_r.to_vec(), s: signature_s.to_vec() })
    } else {
        panic!("unknown UIC ticket version {:?}", version);
    };

    print!("  compressed data bytes:");
    hexdump(compressed_bytes);

    // verify?
    if let Some(keys_path) = keys_path_opt {
        let keys_db_string = std::fs::read_to_string(keys_path)
            .expect("failed to read key database");
        let keys_db = crate::key_db::database_from_xml(&keys_db_string)
            .expect("failed to parse key database");

        let signer_number_u16: u16 = signer_number.parse()
            .expect("failed to parse signer number as u16");
        let key_id_u32: u32 = key_id.parse()
            .expect("failed to parse key ID as u32");
        let key = keys_db.get(&(signer_number_u16, key_id_u32))
            .expect("key not found, cannot verify");

        let data_valid = key.verify(&signature, &compressed_bytes)
            .expect("verification failed");
        if data_valid {
            println!("  signature is OK");
        } else {
            panic!("signature is invalid!");
        }
    }

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
        decode_record(record_id, record_version, record_data, re_encode_path.as_ref().map(|p| p.as_path()));

        remaining_bytes = &remaining_bytes[record_length..];
    }
}

fn decode_record(record_id: &[u8], record_version: &[u8], record_data: &[u8], re_encode_path: Option<&Path>) {
    if record_id == b"U_FLEX" && record_version == b"03" {
        decode_record_uflex_3(record_data, re_encode_path);
    } else if record_id == b"U_HEAD" && record_version == b"01" {
        decode_record_uhead_1(record_data);
    } else if record_id == b"U_TLAY" && record_version == b"01" {
        decode_record_utlay_1(record_data);
    } else {
        println!("  cannot decode this record type; hex dump:");
        hexdump(record_data);
    }
}

fn decode_record_uflex_3(record_data: &[u8], re_encode_path: Option<&Path>) {
    // https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicRailTicketData_v3.0.3.asn

    // convert record data to bits
    let record_data_bits = to_bits_msb_first(record_data);

    // the top structure is UicRailTicketData
    let (_rest, uic_rail_ticket_data) = crate::uflex_3::UicRailTicketData::try_from_uper(&record_data_bits)
        .expect("failed to decode UicRailTicketData");

    println!("{:#?}", uic_rail_ticket_data);

    // output interpreted date/time info
    output_ticket_validity(&uic_rail_ticket_data.issuing_detail, &uic_rail_ticket_data.transport_document);

    if let Some(path) = re_encode_path {
        let mut buf = Vec::new();
        uic_rail_ticket_data.write_uper(&mut buf)
            .expect("failed to re-encode UicRailTicketData");

        let bytes = to_bytes_msb_first(&buf);
        std::fs::write(path, &bytes)
            .expect("failed to write re-encoded data");
    }
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
