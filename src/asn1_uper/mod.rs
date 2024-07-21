//! ASN.1 PER UNALIGNED parser.
//!
//! Implementation of a parser for data encoded using ASN.1 Packed Encoding Rules in their UNALIGNED
//! variant according to ITU-T X.691.


mod integer;


use std::fmt;

pub use self::integer::Integer;


pub type ParseResult<'a, T> = nom::IResult<&'a [bool], T, DecodingError<'a>>;


/// An error that may occur when decoding PER-encoded data.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DecodingError<'a> {
    bits: &'a [bool],
    kind: ErrorKind,
}
impl<'a> DecodingError<'a> {
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
impl<'a> fmt::Display for DecodingError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}
impl<'a> std::error::Error for DecodingError<'a> {
}


/// An error that may occur when encoding data into PER.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum EncodingError {
    #[non_exhaustive]
    SingleValueIntegerHasWrongValue { expected: Integer, obtained: Integer },

    #[non_exhaustive]
    NonNegativeIntegerHasNegativeValue { obtained: Integer },

    #[non_exhaustive]
    IntegerDoesNotFitIntoBits { value: Integer, bits: usize },

    #[non_exhaustive]
    Ia5ByteHasTopBitSet { string: String, byte_index: usize },
}
impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleValueIntegerHasWrongValue { expected, obtained }
                => write!(f, "single-value integer (expected {}) has wrong value {}", expected, obtained),
            Self::NonNegativeIntegerHasNegativeValue { obtained }
                => write!(f, "non-negative integer has negative value {}", obtained),
            Self::IntegerDoesNotFitIntoBits { value, bits }
                => write!(f, "integer {} does not fit into {} bits", value, bits),
            Self::Ia5ByteHasTopBitSet { string, byte_index }
                => write!(f, "IA5 string {:?} byte {} (0x{:02X}) has top bit set", string, byte_index, string.as_bytes()[*byte_index]),
        }
    }
}
impl std::error::Error for EncodingError {
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

    /// The string is not valid UTF-8.
    #[non_exhaustive]
    InvalidUtf8String { bytes: Vec<u8> },
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
            Self::InvalidUtf8String { bytes }
                => write!(f, "byte string is not valid UTF-8: {:?}", bytes),
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
impl WholeNumberConstraint {
    pub fn singular_value(&self) -> Option<&Integer> {
        match self {
            Self::Unconstrained => None,
            Self::SemiConstrained { .. } => None,
            Self::Constrained { min, max } => if min == max {
                Some(min)
            } else {
                None
            },
            Self::NormallySmall => None,
        }
    }
}


/// Calculates the exact number of bits required to encode the given value.
fn bits_required_for_unsigned_value(n: &Integer) -> usize {
    let zero = Integer::from_short(0);
    assert!(n >= &zero);

    let mut my_n = n.clone();
    let mut bits = 0;
    while my_n > zero {
        my_n >>= 1;
        bits += 1;
    }
    bits
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


fn split_at_fallible<'a>(bits: &'a [bool], after_length: usize) -> Result<(&'a [bool], &'a [bool]), nom::Err<DecodingError<'a>>> {
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


/// Encodes a non-negative binary integer into the given number of bits. Used for encoding integers
/// of determinate size.
///
/// For integers of indeterminate size, PER prescribes a length encoding that generally precedes the
/// integer itself.
///
/// The encoding process is described in X.691 § 11.3.
#[must_use]
fn encode_nonneg_int(uper_buf: &mut Vec<bool>, value: &Integer, bit_count: usize) -> Result<(), EncodingError> {
    // ensure the integer is really non-negative
    let zero = Integer::from_short(0);
    if value < &zero {
        return Err(EncodingError::NonNegativeIntegerHasNegativeValue { obtained: value.clone() });
    }

    // ensure the integer fits in the bits
    let bit_count_u32 = u32::try_from(bit_count).unwrap();
    if (value >> u32::try_from(bit_count).unwrap()) != zero {
        return Err(EncodingError::IntegerDoesNotFitIntoBits { value: value.clone(), bits: bit_count });
    }

    let one = Integer::from_short(1);
    for i in (0..bit_count_u32).rev() {
        let mask = (&one) << i;
        let bit_value = value & (&mask) != zero;
        uper_buf.push(bit_value);
    }
    Ok(())
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
            .ok_or_else(|| nom::Err::Error(DecodingError::new(rest, ErrorKind::LengthValueNotUsize { value: length_integer })))?;
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


/// Encodes a normally-small non-negative integer.
///
/// The encoding process is described in X.691 § 11.6.
fn encode_normally_small_nonneg_int(uper_buf: &mut Vec<bool>, value: &Integer) -> Result<(), EncodingError> {
    let too_much_for_six_bits = Integer::from_usize(0b100_0000);
    if value < &too_much_for_six_bits {
        // announce small integer
        uper_buf.push(false);

        // encode in six bits
        encode_nonneg_int(uper_buf, value, 6)?;
    } else {
        // announce large integer
        uper_buf.push(true);

        // X.691 § 11.6.2 forwards us to § 11.7 (semi-constrained integer)
        // with § 11.9 to govern the length
        encode_semi_constrained_int(uper_buf, &Integer::from_short(0), value)?;
    }
    Ok(())
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
                Err(nom::Err::Error(DecodingError::new(rest, ErrorKind::InvalidHugeLength { value: my_value })))
            } else {
                // multiply value with 16K (16384)
                my_value *= &Integer::from_short(16384);

                // that's the length... for the time being
                Ok((rest, my_value))
            }
        }
    }
}


/// Encodes a length value.
///
/// The encoding process is described in X.691 § 11.9.4.
#[must_use]
pub fn encode_length(uper_buf: &mut Vec<bool>, constraint: &WholeNumberConstraint, value: usize) -> Result<(), EncodingError> {
    if let WholeNumberConstraint::Constrained { min, max } = constraint {
        // X.691 § 11.9.4.1
        let one = Integer::from_short(1);
        let range = &(max - min) + &one;
        if &range == &one {
            // the length is encoded in 0 bits because it is fixed
            if &Integer::from_usize(value) != min {
                return Err(EncodingError::SingleValueIntegerHasWrongValue { expected: min.clone(), obtained: Integer::from_usize(value) });
            }
            return Ok(());
        }
        let int_64k = Integer::from_short(64*1024);
        if max < &int_64k {
            // non-negative binary integer, minimum length
            let bit_count = bits_required_for_unique_values(&range);
            encode_nonneg_int(uper_buf, &(&Integer::from_usize(value) - min), bit_count)?;
            return Ok(());
        }
    }

    // X.691 § 11.9.4.2 -> § 11.9.3.4 through 11.9.3.8.4

    if let WholeNumberConstraint::NormallySmall = constraint {
        // § 11.9.3.4
        encode_normally_small_nonneg_int(uper_buf, &Integer::from_usize(value))?;
        return Ok(());
    }

    if value <= 0x7F {
        // fits in seven bits; encoded as 0LLL LLLL
        uper_buf.push(false);
        for i in (0..7).rev() {
            let bit_val = value & (1 << i) != 0;
            uper_buf.push(bit_val);
        }
    } else if value <= 0x3FFF {
        // fits in 14 bits, encoded as 10LL LLLL LLLL LLLL
        uper_buf.push(true);
        uper_buf.push(false);
        for i in (0..14).rev() {
            let bit_val = value & (1 << i) != 0;
            uper_buf.push(bit_val);
        }
    } else {
        // overlong value split into multiple blocks
        // number of blocks encoded as 11BB BBBB where L = B * 16384
        uper_buf.push(true);
        uper_buf.push(true);
        let block_count = value / 16384;
        for i in (0..6).rev() {
            let bit_val = value & (1 << i) != 0;
            uper_buf.push(bit_val);
        }
    }
    Ok(())
}


/// Decodes a boolean value.
///
/// The encoding is specified in X.691 § 12.
pub fn decode_bool<'a>(bits: &'a [bool]) -> ParseResult<'a, bool> {
    let (value, rest) = split_at_fallible(bits, 1)?;
    Ok((rest, value[0]))
}


/// Encodes a boolean value.
///
/// The encoding is specified in X.691 § 12.
pub fn encode_bool(uper_buf: &mut Vec<bool>, value: bool) {
    uper_buf.push(value);
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
                .ok_or_else(|| nom::Err::Error(DecodingError::new(rest, ErrorKind::LengthValueNotUsize { value: length_integer })))?;
            let length_bytes = 8 * length_bits;
            let (integer_bits, rest) = split_at_fallible(rest, length_bytes)?;
            let integer = Integer::from_bits_signed(integer_bits);
            Ok((rest, integer))
        },
        _ => unreachable!(),
    }
}


/// Encodes an integer.
///
/// The encoding is specified in X.691 § 13.
#[must_use]
pub fn encode_integer(uper_buf: &mut Vec<bool>, constraint: &WholeNumberConstraint, value: &Integer) -> Result<(), EncodingError> {
    // § 13.2.1
    if let Some(singular_value) = constraint.singular_value() {
        if value != singular_value {
            return Err(EncodingError::SingleValueIntegerHasWrongValue { expected: singular_value.clone(), obtained: value.clone() });
        }
        // perfect, nothing to add
        return Ok(());
    }

    match constraint {
        WholeNumberConstraint::Constrained { min, max } => {
            // § 13.2.2
            encode_constrained_int(uper_buf, min, max, value)?;
        },
        WholeNumberConstraint::SemiConstrained { min } => {
            // § 13.2.3
            encode_semi_constrained_int(uper_buf, min, value)?;
        },
        WholeNumberConstraint::Unconstrained { } => {
            // § 13.2.4
            encode_unconstrained_int(uper_buf, value)?;
        },
        _ => unreachable!(),
    }

    Ok(())
}


/// Encodes a constrained integer.
///
/// This is specified in X.691 § 11.5.
#[must_use]
fn encode_constrained_int(uper_buf: &mut Vec<bool>, min: &Integer, max: &Integer, value: &Integer) -> Result<(), EncodingError> {
    assert!(value >= min);
    assert!(value <= max);

    // § 11.5.3
    let range = &(max - min) + &Integer::from_short(1);
    if &range == &Integer::from_short(1) {
        // § 11.5.3
        // an integer that can only occupy one value is encoded into zero bits
        return Ok(());
    }

    // § 11.5.4
    let bit_count = bits_required_for_unique_values(&range);
    let encode_value = value - min;
    encode_nonneg_int(uper_buf, &encode_value, bit_count)?;
    Ok(())
}


/// Encodes a semi-constrained integer (including, prepended, its length).
///
/// This is specified in X.691 § 11.7, which mostly refers to § 11.3.
#[must_use]
fn encode_semi_constrained_int(uper_buf: &mut Vec<bool>, min: &Integer, value: &Integer) -> Result<(), EncodingError> {
    assert!(value >= min);

    // § 11.7.4
    let encode_value = value - min;
    let mut bit_count = bits_required_for_unsigned_value(&encode_value);

    // § 11.3.6 applies
    // (X.691 prescribes the "minimal number of octets" encoding here, not the "minimal number of bits" encoding)
    // => round up to the next full octet and store length in octets, not bits
    while bit_count % 8 != 0 {
        bit_count += 1;
    }
    let byte_count = bit_count / 8;
    encode_length(uper_buf, &WholeNumberConstraint::SemiConstrained { min: Integer::from_short(0) }, byte_count)?;
    encode_nonneg_int(uper_buf, &encode_value, bit_count)?;
    Ok(())
}


/// Encodes an unconstrained integer (including, prepended, its length).
///
/// This is specified in X.691 § 11.8, which pretty much directly refers to § 11.4.
#[must_use]
fn encode_unconstrained_int(uper_buf: &mut Vec<bool>, value: &Integer) -> Result<(), EncodingError> {
    // § 11.7.4

    // encode a 2's complement integer in the lowest number of octets (not bits!)

    let zero = Integer::from_short(0);
    let one = Integer::from_short(1);
    let mut bits = if value < &zero {
        // -2**31 fits into i32 while 2**31 does not
        // => find the lowest number of bits for ((-n) - 1)
        let positive_minus_one = &(-value) - &one;
        let bit_count = bits_required_for_unsigned_value(&positive_minus_one);

        // encode into that
        let mut bits = Vec::new();
        encode_nonneg_int(&mut bits, &positive_minus_one, bit_count)?;

        // 2's complement negation ((NOT a) + 1)
        // we can reuse ((-n) - 1) here because that's equivalent to (NOT (a - 1))
        // => NOT
        bits.reverse();
        for bit in &mut bits {
            *bit = !*bit;
        }

        // pad with 1s to next octet
        while bits.len() % 8 != 0 {
            bits.push(true);
        }

        // reverse back
        bits.reverse();

        bits
    } else {
        // positive integers are rather boring
        let bit_count = bits_required_for_unsigned_value(&value);
        let mut bits = Vec::with_capacity(bit_count + 1);
        encode_nonneg_int(&mut bits, &value, bit_count)?;

        bits.reverse();
        if bits.len() > 0 && *bits.last().unwrap() {
            // top bit is 1, but our sign is positive
            // => prepend (since we reversed: append) a 0
            bits.push(false);
        }

        // pad with 0s to next octet
        while bits.len() % 8 != 0 {
            bits.push(false);
        }

        // reverse back
        bits.reverse();

        bits
    };

    // write it out
    let byte_count = bits.len() / 8;
    encode_length(uper_buf, &WholeNumberConstraint::SemiConstrained { min: Integer::from_short(0) }, byte_count)?;
    uper_buf.append(&mut bits);

    Ok(())
}


/// Decodes an octet string.
///
/// The encoding is specified in X.691 § 17.
pub fn decode_octet_string<'a>(bits: &'a [bool], length_constraint: &WholeNumberConstraint) -> ParseResult<'a, Vec<u8>> {
    let (rest, length_integer) = decode_length(bits, length_constraint)?;
    let length_bytes: usize = length_integer.try_to_usize()
        .ok_or_else(|| nom::Err::Error(DecodingError::new(rest, ErrorKind::LengthValueNotUsize { value: length_integer })))?;
    let length_bits = 8 * length_bytes;
    let (octet_bits, rest) = split_at_fallible(rest, length_bits)?;
    Ok((rest, bits_to_bytes(octet_bits, 8)))
}


/// Decodes an IA5 string.
///
/// The encoding is specified in X.691 § 17 in conjunction with § 30.5.3.
pub fn decode_ia5_string<'a>(bits: &'a [bool], length_constraint: &WholeNumberConstraint) -> ParseResult<'a, Vec<u8>> {
    // each IA5String character fits in 7 bytes
    let (rest, length_integer) = decode_length(bits, length_constraint)?;
    let length_bytes: usize = length_integer.try_to_usize()
        .ok_or_else(|| nom::Err::Error(DecodingError::new(rest, ErrorKind::LengthValueNotUsize { value: length_integer })))?;
    let length_bits = 7 * length_bytes;
    let (octet_bits, rest) = split_at_fallible(rest, length_bits)?;
    Ok((rest, bits_to_bytes(octet_bits, 7)))
}


/// Encodes an octet string.
///
/// The encoding is specified in X.691 § 17.
#[must_use]
pub fn encode_octet_string(uper_buf: &mut Vec<bool>, length_constraint: &WholeNumberConstraint, value: &[u8]) -> Result<(), EncodingError> {
    encode_length(uper_buf, length_constraint, value.len())?;
    for b in value {
        // for 7, 6, 5, 4, 3, 2, 1, 0
        for i in (0..8).rev() {
            let bit = (*b & (1 << i)) != 0;
            uper_buf.push(bit);
        }
    }
    Ok(())
}

/// Encodes an IA5 string.
///
/// The encoding is specified in X.691 § 17 in conjunction with § 30.5.3.
#[must_use]
pub fn encode_ia5_string(uper_buf: &mut Vec<bool>, length_constraint: &WholeNumberConstraint, value: &str) -> Result<(), EncodingError> {
    encode_length(uper_buf, length_constraint, value.len())?;
    for (byte_index, b) in value.bytes().enumerate() {
        // top bit must not be set
        if b & 0b1000_0000 != 0 {
            return Err(EncodingError::Ia5ByteHasTopBitSet { string: value.to_owned(), byte_index });
        }

        // for 6, 5, 4, 3, 2, 1, 0
        for i in (0..7).rev() {
            let bit = (b & (1 << i)) != 0;
            uper_buf.push(bit);
        }
    }
    Ok(())
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

/// Converts a slice of bits, most significant bit of each byte first, to a vector of bytes.
pub fn to_bytes_msb_first(bits: &[bool]) -> Vec<u8> {
    let mut byte_count = bits.len() / 8;
    if bits.len() % 8 != 0 {
        byte_count += 1;
    }
    let mut ret = Vec::with_capacity(byte_count);
    let mut bit_index = 0;
    let mut bit_assembly = 0;
    for &bit in bits {
        if bit {
            let shift_count = 7 - bit_index;
            bit_assembly |= 1 << shift_count;
        }
        if bit_index == 7 {
            ret.push(bit_assembly);
            bit_assembly = 0;
            bit_index = 0;
        } else {
            bit_index += 1;
        }
    }
    if bit_index != 0 {
        ret.push(bit_assembly);
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

/// Attempts to convert an octet string into a UTF-8 string.
pub fn octet_string_to_utf8<'a>(rest: &'a [bool], octet_string: Vec<u8>) -> ParseResult<'a, String> {
    let utf8_string = String::from_utf8(octet_string)
        .map_err(|e| nom::Err::Error(
            DecodingError::new(rest, ErrorKind::InvalidUtf8String { bytes: e.into_bytes() })
        ))?;
    Ok((rest, utf8_string))
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
