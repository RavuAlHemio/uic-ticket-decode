use std::io::Write;

use png;
use rxing::common::BitMatrix;

use crate::asn1_uper::to_bytes_msb_first;


pub(crate) fn write_bit_matrix_as_png<W: Write>(writer: W, bit_matrix: &BitMatrix, thickness: u32, margin: u32) {
    let width = bit_matrix.width() * thickness + 2 * margin;
    let height = bit_matrix.height() * thickness + 2 * margin;
    let mut enc = png::Encoder::new(writer, width, height);
    enc.set_color(png::ColorType::Grayscale);
    enc.set_depth(png::BitDepth::One);
    let mut writer = enc.write_header().unwrap();

    let mut margin_bits = Vec::new();
    for _ in 0..width {
        margin_bits.push(true);
    }
    let margin_row = to_bytes_msb_first(&margin_bits);

    let mut image_data = Vec::new();
    for _ in 0..margin {
        image_data.extend(&margin_row);
    }
    for y in 0..bit_matrix.height() {
        let mut row_bits = Vec::with_capacity(width.try_into().unwrap());
        for _ in 0..margin {
            row_bits.push(true);
        }
        for x in 0..bit_matrix.width() {
            let bit_val = bit_matrix.get(x, y);
            for _ in 0..thickness {
                // BitMatrix: true = dark
                // PNG: true = white
                row_bits.push(!bit_val);
            }
        }
        for _ in 0..margin {
            row_bits.push(true);
        }

        let row_bytes = to_bytes_msb_first(&row_bits);
        for _ in 0..thickness {
            image_data.extend(&row_bytes);
        }
    }
    for _ in 0..margin {
        image_data.extend(&margin_row);
    }
    writer.write_image_data(&image_data).unwrap();
    writer.finish().unwrap();
}
