use std::io::Write;

use png;
use rxing::common::BitMatrix;

use crate::asn1_uper::to_bytes_msb_first;


pub(crate) fn write_bit_matrix_as_png<W: Write>(writer: W, bit_matrix: &BitMatrix, thickness: u32) {
    let width = bit_matrix.width() * thickness;
    let height = bit_matrix.height() * thickness;
    let mut enc = png::Encoder::new(writer, width, height);
    enc.set_color(png::ColorType::Grayscale);
    enc.set_depth(png::BitDepth::One);
    let mut writer = enc.write_header().unwrap();

    let mut image_data = Vec::new();
    for y in 0..bit_matrix.height() {
        let mut row_bits = Vec::with_capacity(width.try_into().unwrap());
        for x in 0..bit_matrix.width() {
            let bit_val = bit_matrix.get(x, y);
            for _ in 0..thickness {
                row_bits.push(bit_val);
            }
        }

        let row_bytes = to_bytes_msb_first(&row_bits);
        for _ in 0..thickness {
            image_data.extend(&row_bytes);
        }
    }
    writer.write_image_data(&image_data).unwrap();
    writer.finish().unwrap();
}
