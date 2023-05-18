//! ASN.1 PER UNALIGNED parser.
//!
//! Implementation of a parser for data encoded using ASN.1 Packed Encoding Rules in their UNALIGNED
//! variant according to ITU-T X.691.


mod integer;


use std::fmt;

pub use self::integer::Integer;


pub type ParseResult<'a, T> = nom::IResult<&'a [bool], T, Error<'a>>;


/// An error that may occur when decoding PER-encoded data.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error<'a> {
    bits: &'a [bool],
    kind: ErrorKind,
}
impl<'a> Error<'a> {
    pub fn new(
        bits: &'a [bool],
        kind: ErrorKind,
    ) -> Self {
        Self {
            bits,
            kind,
        }
    }
}
impl<'a> fmt::Display for Error<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}
impl<'a> std::error::Error for Error<'a> {
}


/// The type of error that may occur when decoding PER-encoded data.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The end of the bit stream was encountered when more data was expected.
    #[non_exhaustive]
    Eof {},

    /// An invalid huge-length value has been encountered.
    ///
    /// Valid huge-length values are 1, 2, 3, and 4, corresponding to 16384, 32768, 49152, and
    /// 65536, respectively. Any other values are invalid.
    ///
    /// The behavior of huge-length values is specified in X.691 § 11.9.3.8.
    #[non_exhaustive]
    InvalidHugeLength { value: Integer },

    /// Failed to convert a length value to usize.
    #[non_exhaustive]
    LengthValueNotUsize { value: Integer },
}
impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof {}
                => write!(f, "end of file"),
            Self::InvalidHugeLength { value }
                => write!(f, "invalid huge-length value {}", value),
            Self::LengthValueNotUsize { value }
                => write!(f, "failed to convert length value {} to usize", value),
        }
    }
}


/// A description of what range a whole number may occupy.
#[derive(Clone, Debug, Default, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum WholeNumberConstraint {
    /// A whole number that may take any value.
    ///
    /// Defined in X.691 § 3.7.27.
    #[default] Unconstrained,

    /// A whole number which may take any value greater than or equal to a minimum value.
    ///
    /// Defined in X.691 § 3.7.24.
    SemiConstrained { min: Integer },

    /// A whole number which is greater than or equal to a minimum value and less than or equal to a
    /// maximum value.
    ///
    /// Defined in X.691 § 3.7.7.
    Constrained { min: Integer, max: Integer },

    /// An unbounded non-negative number which is more likely to have a value < 64 than not.
    ///
    /// Defined in X.691 § 3.7.19.
    NormallySmall,
}


/// Calculates the minimum number of bits required to encode a given number of unique values.
fn bits_required_for_unique_values(n: &Integer) -> usize {
    let zero = Integer::from_short(0);

    assert!(n > &zero);

    let mut value = n - &Integer::from_short(1);
    let mut count = 0;
    while value > zero {
        value >>= 1;
        count += 1;
    }
    count
}


fn split_at_fallible<'a>(bits: &'a [bool], after_length: usize) -> Result<(&'a [bool], &'a [bool]), nom::Err<Error<'a>>> {
    if bits.len() < after_length {
        Err(nom::Err::Incomplete(nom::Needed::new(after_length - bits.len())))
    } else {
        Ok(bits.split_at(after_length))
    }
}


/// Decodes a non-negative binary integer.
///
/// It is expected that the bits passed represent the full integer. For integers of indeterminate
/// size, PER prescribes a length encoding that generally precedes the integer itself.
///
/// The encoding process is described in X.691 § 11.3.
fn decode_nonneg_int_complete<'a>(complete_bits: &'a [bool]) -> ParseResult<'a, Integer> {
    let ret = Integer::from_bits_unsigned(complete_bits);
    Ok((&[], ret))
}


/// Decodes a constrained whole number.
///
/// The encoding process is described in X.691 § 11.5.
fn decode_constrained_int<'a>(bits: &'a [bool], min: &Integer, max: &Integer) -> ParseResult<'a, Integer> {
    assert!(min < max);
    let range = &(max - min) + &Integer::from_short(1);
    if &range == &Integer::from_short(1) {
        // an integer that can only occupy one value is encoded into zero bits (X.691 § 11.5.4);
        // just return min
        return Ok((bits, min.clone()));
    }

    // what is encoded is not `n` but `n - min` (as a non-negative binary integer; § 11.5.6)
    let bit_count = bits_required_for_unique_values(&range);

    // take as many bits
    let (my_bits, rest) = split_at_fallible(bits, bit_count)?;
    let my_offset = Integer::from_bits_unsigned(my_bits);
    let my_value = &my_offset + min;

    Ok((rest, my_value))
}


/// Decodes a normally-small non-negative integer.
///
/// The encoding process is described in X.691 § 11.6.
fn decode_normally_small_nonneg_int<'a>(bits: &'a [bool]) -> ParseResult<'a, Integer> {
    let (is_large, rest) = split_at_fallible(bits, 1)?;
    if is_large[0] {
        // X.691 § 11.6.2 forwards us to § 11.7 (semi-constrained integer)
        // with § 11.9 to govern the length
        let (rest, length_integer) = decode_length(rest, &WholeNumberConstraint::SemiConstrained { min: Integer::from_short(0) })?;
        let length = length_integer.try_to_usize()
            .ok_or_else(|| nom::Err::Error(Error::new(rest, ErrorKind::LengthValueNotUsize { value: length_integer })))?;
        let (int_slice, rest) = split_at_fallible(rest, length)?;
        let (_, value) = decode_semi_constrained_int_complete(int_slice, &Integer::from_short(0))?;
        Ok((rest, value))
    } else {
        // take six bits
        let (my_bits, rest) = split_at_fallible(rest, 6)?;
        let my_value = Integer::from_bits_unsigned(my_bits);
        Ok((rest, my_value))
    }
}


/// Decodes a semi-constrained integer.
///
/// It is expected that the bits passed represent the full integer. For integers of indeterminate
/// size, PER prescribes a length encoding that generally precedes the integer itself.
///
/// The encoding process is described in X.691 § 11.7.
fn decode_semi_constrained_int_complete<'a>(complete_bits: &'a [bool], min: &Integer) -> ParseResult<'a, Integer> {
    // what is encoded is not `n` but `(n - min)`
    let (rest, mut integer) = decode_nonneg_int_complete(complete_bits)?;
    integer += min;
    assert_eq!(rest.len(), 0);
    Ok((rest, integer))
}


/// Decodes an unconstrained integer.
///
/// It is expected that the bits passed represent the full integer. For integers of indeterminate
/// size, PER prescribes a length encoding that generally precedes the integer itself.
///
/// The encoding process is described in X.691 § 11.8.
fn decode_unconstrained_int_complete<'a>(complete_bits: &'a [bool]) -> ParseResult<'a, Integer> {
    let ret = Integer::from_bits_signed(complete_bits);
    Ok((&[], ret))
}


/// Returns whether the value with the given length is fragmented into multiple pieces.
fn value_with_length_is_fragmented(length: &Integer) -> bool {
    length == &Integer::from_short(1*16384)
        || length == &Integer::from_short(2*16384)
        || length == &Integer::from_short(3*16384)
        || length == &Integer::from_short(4*16384)
}


/// Decodes a length value.
///
/// The encoding process is described in X.691 § 11.9.4.
pub fn decode_length<'a>(bits: &'a [bool], constraint: &WholeNumberConstraint) -> ParseResult<'a, Integer> {
    if let WholeNumberConstraint::Constrained { min, max } = constraint {
        // X.691 § 11.9.4.1
        let one = Integer::from_short(1);
        let range = &(max - min) + &one;
        if &range == &one {
            // the length is encoded in 0 bits because it is fixed;
            // just return min
            return Ok((bits, min.clone()));
        }
        let int_64k = Integer::from_short(64*1024);
        if max < &int_64k {
            // non-negative binary integer, minimum length
            let bit_count = bits_required_for_unique_values(&range);
            let (int_bits, rest) = split_at_fallible(bits, bit_count)?;
            let (_, value) = decode_nonneg_int_complete(int_bits)?;
            return Ok((rest, value));
        }
    }

    // X.691 § 11.9.4.2 -> § 11.9.3.4 through 11.9.3.8.4

    if let WholeNumberConstraint::NormallySmall = constraint {
        // § 11.9.3.4
        return decode_normally_small_nonneg_int(bits);
    }

    // grab a bit
    let (is_big, rest) = split_at_fallible(bits, 1)?;
    if !is_big[0] {
        // take seven bits as an unsigned integer; that's the length
        let (my_bits, rest) = split_at_fallible(rest, 7)?;
        let my_value = Integer::from_bits_unsigned(my_bits);
        Ok((rest, my_value))
    } else {
        // take another bit
        let (is_huge, rest) = split_at_fallible(rest, 1)?;
        if !is_huge[0] {
            // take 14 bits as an unsigned integer; that's the length
            let (my_bits, rest) = split_at_fallible(rest, 14)?;
            let my_value = Integer::from_bits_unsigned(my_bits);
            Ok((rest, my_value))
        } else {
            // overlong value split into multiple blocks
            let (my_bits, rest) = split_at_fallible(rest, 6)?;
            let mut my_value = Integer::from_bits_unsigned(my_bits);
            if my_value < Integer::from_short(1) || my_value > Integer::from_short(4) {
                // invalid value
                Err(nom::Err::Error(Error::new(rest, ErrorKind::InvalidHugeLength { value: my_value })))
            } else {
                // multiply value with 16K (16384)
                my_value *= &Integer::from_short(16384);

                // that's the length... for the time being
                Ok((rest, my_value))
            }
        }
    }
}


/// Decodes a boolean value.
///
/// The encoding is specified in X.691 § 12.
pub fn decode_bool<'a>(bits: &'a [bool]) -> ParseResult<'a, bool> {
    let (value, rest) = split_at_fallible(bits, 1)?;
    Ok((rest, value[0]))
}


/// Decodes an integer.
///
/// The encoding is specified in X.691 § 13.
pub fn decode_integer<'a>(bits: &'a [bool], constraint: &WholeNumberConstraint) -> ParseResult<'a, Integer> {
    match constraint {
        WholeNumberConstraint::Constrained { min, max } => {
            // this is a definite-length case
            // no length is stored, the number is simply encoded into as few bits as possible
            decode_constrained_int(bits, min, max)
        },
        WholeNumberConstraint::SemiConstrained { .. } | WholeNumberConstraint::Unconstrained { .. } => {
            // this is an indefinite-length case
            // a length is stored which represents the number of octets used to store the number
            let (rest, length_integer) = decode_length(bits, &WholeNumberConstraint::Unconstrained)?;
            let length_bits = length_integer.try_to_usize()
                .ok_or_else(|| nom::Err::Error(Error::new(rest, ErrorKind::LengthValueNotUsize { value: length_integer })))?;
            let length_bytes = 8 * length_bits;
            let (integer_bits, rest) = split_at_fallible(rest, length_bytes)?;
            let integer = Integer::from_bits_signed(integer_bits);
            Ok((rest, integer))
        },
        _ => unreachable!(),
    }
}


/// Decodes an octet string.
///
/// The encoding is specified in X.691 § 17.
pub fn decode_octet_string<'a>(bits: &'a [bool]) -> ParseResult<'a, Vec<u8>> {
    let (rest, length_integer) = decode_length(bits, &WholeNumberConstraint::Unconstrained)?;
    let length_bytes: usize = length_integer.try_to_usize()
        .ok_or_else(|| nom::Err::Error(Error::new(rest, ErrorKind::LengthValueNotUsize { value: length_integer })))?;
    let length_bits = 8 * length_bytes;
    let (octet_bits, rest) = split_at_fallible(rest, length_bits)?;
    Ok((rest, bits_to_bytes(octet_bits, 8)))
}


/// Decodes an IA5 string.
///
/// The encoding is specified in X.691 § 17 in conjunction with § 30.5.3.
pub fn decode_ia5_string<'a>(bits: &'a [bool]) -> ParseResult<'a, Vec<u8>> {
    // each IA5String character fits in 7 bytes
    let (rest, length_integer) = decode_length(bits, &WholeNumberConstraint::Unconstrained)?;
    let length_bytes: usize = length_integer.try_to_usize()
        .ok_or_else(|| nom::Err::Error(Error::new(rest, ErrorKind::LengthValueNotUsize { value: length_integer })))?;
    let length_bits = 7 * length_bytes;
    let (octet_bits, rest) = split_at_fallible(rest, length_bits)?;
    Ok((rest, bits_to_bytes(octet_bits, 7)))
}


/// Decodes a sequence of boolean values.
///
/// This can be used e.g. to obtain the bit field declaring the presence of optional values in a
/// SEQUENCE with OPTIONAL values, as expounded upon in X.691 § 19.2.
pub fn decode_bools<'a>(bits: &'a [bool], count: usize) -> ParseResult<'a, &'a [bool]> {
    let (value, rest) = split_at_fallible(bits, count)?;
    Ok((rest, value))
}


/// Converts a slice of bytes to a vector of bits, most significant bit of each byte first.
pub fn to_bits_msb_first(bytes: &[u8]) -> Vec<bool> {
    let mut ret = Vec::with_capacity(bytes.len() * 8);
    for &byte in bytes {
        for shift_count in (0..8).rev() {
            ret.push(byte & (1 << shift_count) != 0);
        }
    }
    ret
}

/// Decodes a slice of bits to bytes.
fn bits_to_bytes(bits: &[bool], bits_per_byte: usize) -> Vec<u8> {
    assert_eq!(bits.len() % bits_per_byte, 0);
    let mut ret = Vec::with_capacity(bits.len() / bits_per_byte);
    let mut iter = bits.into_iter();
    while let Some(b7) = iter.next() {
        let mut byte = if *b7 { 1 << (bits_per_byte - 1) } else { 0 };
        for shift_count in (0..(bits_per_byte - 1)).rev() {
            if *iter.next().unwrap() {
                byte |= 1 << shift_count;
            }
        }
        ret.push(byte);
    }
    ret
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_bits_msb_first() {
        assert_eq!(to_bits_msb_first(&[0x00]), &[false, false, false, false, false, false, false, false]);
        assert_eq!(to_bits_msb_first(&[0x23]), &[false, false, true,  false, false, false, true,  true ]);
        assert_eq!(to_bits_msb_first(&[0x7F]), &[false, true,  true,  true,  true,  true,  true,  true ]);
        assert_eq!(to_bits_msb_first(&[0x80]), &[true,  false, false, false, false, false, false, false]);
        assert_eq!(to_bits_msb_first(&[0xFF]), &[true,  true,  true,  true,  true,  true,  true,  true ]);
        assert_eq!(to_bits_msb_first(&[0x01, 0x80]), &[false, false, false, false, false, false, false, true,  true,  false, false, false, false, false, false, false]);
    }

    #[test]
    fn test_decode_nonneg_int_complete() {
        assert_eq!(decode_nonneg_int_complete(&[false, false, false, false, false, false, false, true ]).unwrap().1, Integer::from_short(1));
        assert_eq!(decode_nonneg_int_complete(&[false, false, false, false, false, false, true,  true ]).unwrap().1, Integer::from_short(3));
        assert_eq!(decode_nonneg_int_complete(&[false, true,  true,  true,  true,  true,  true,  true ]).unwrap().1, Integer::from_short(127));
        assert_eq!(decode_nonneg_int_complete(&[true,  false, false, false, false, false, false, false]).unwrap().1, Integer::from_short(128));
        assert_eq!(decode_nonneg_int_complete(&[true,  false, false, false, false, false, false, true ]).unwrap().1, Integer::from_short(129));
        assert_eq!(decode_nonneg_int_complete(&[true,  false, false, false, false, false, true,  true ]).unwrap().1, Integer::from_short(131));
        assert_eq!(decode_nonneg_int_complete(&[false, true,  false, false, false, false, false, false, false]).unwrap().1, Integer::from_short(128));
        assert_eq!(decode_nonneg_int_complete(&[false, true,  false, false, false, false, false, false, true ]).unwrap().1, Integer::from_short(129));
        assert_eq!(decode_nonneg_int_complete(&[false, true,  false, false, false, false, false, true,  true ]).unwrap().1, Integer::from_short(131));
    }

    #[test]
    fn test_decode_unconstrained_int_complete() {
        assert_eq!(decode_unconstrained_int_complete(&[false, false, false, false, false, false, false, true ]).unwrap().1, Integer::from_short(1));
        assert_eq!(decode_unconstrained_int_complete(&[false, false, false, false, false, false, true,  true ]).unwrap().1, Integer::from_short(3));
        assert_eq!(decode_unconstrained_int_complete(&[false, true,  true,  true,  true,  true,  true,  true ]).unwrap().1, Integer::from_short(127));
        assert_eq!(decode_unconstrained_int_complete(&[true,  false, false, false, false, false, false, false]).unwrap().1, Integer::from_short(-128));
        assert_eq!(decode_unconstrained_int_complete(&[true,  false, false, false, false, false, false, true ]).unwrap().1, Integer::from_short(-127));
        assert_eq!(decode_unconstrained_int_complete(&[true,  false, false, false, false, false, true,  true ]).unwrap().1, Integer::from_short(-125));
        assert_eq!(decode_unconstrained_int_complete(&[false, true,  false, false, false, false, false, false, false]).unwrap().1, Integer::from_short(128));
        assert_eq!(decode_unconstrained_int_complete(&[false, true,  false, false, false, false, false, false, true ]).unwrap().1, Integer::from_short(129));
        assert_eq!(decode_unconstrained_int_complete(&[false, true,  false, false, false, false, false, true,  true ]).unwrap().1, Integer::from_short(131));
    }

    #[test]
    fn test_bits_required() {
        assert_eq!(bits_required_for_unique_values(&Integer::from_short(1)), 0);
        assert_eq!(bits_required_for_unique_values(&Integer::from_short(2)), 1);
        assert_eq!(bits_required_for_unique_values(&Integer::from_short(3)), 2);
        assert_eq!(bits_required_for_unique_values(&Integer::from_short(4)), 2);
        assert_eq!(bits_required_for_unique_values(&Integer::from_short(5)), 3);
        assert_eq!(bits_required_for_unique_values(&Integer::from_short(6)), 3);
        assert_eq!(bits_required_for_unique_values(&Integer::from_short(7)), 3);
        assert_eq!(bits_required_for_unique_values(&Integer::from_short(8)), 3);
        assert_eq!(bits_required_for_unique_values(&Integer::from_short(9)), 4);
    }
}
