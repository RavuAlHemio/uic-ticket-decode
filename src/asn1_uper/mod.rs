//! ASN.1 PER UNALIGNED parser.
//!
//! Implementation of a parser for data encoded using ASN.1 Packed Encoding Rules in their UNALIGNED
//! variant according to ITU-T X.691.


mod integer;


use nom::error::{Error as NomError, ErrorKind as NomErrorKind};

use self::integer::Integer;


pub type ParseResult<'a, T> = nom::IResult<&'a [bool], T>;


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


fn get_eof<'a, T>(bits: &'a [bool]) -> ParseResult<'a, T> {
    return Err(nom::Err::Error(NomError::new(bits, NomErrorKind::Eof)));
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
    if bits.len() < bit_count {
        return get_eof(bits);
    }
    let (my_bits, rest) = bits.split_at(bit_count);
    let my_value = Integer::from_bits(my_bits);

    Ok((rest, my_value))
}


/// Decodes a normally-small non-negative integer.
///
/// The encoding process is described in X.691 § 11.6.
fn decode_normally_small_nonneg_int<'a>(bits: &'a [bool]) -> ParseResult<'a, Integer> {
    if bits.len() < 1 {
        return get_eof(bits);
    }
    let (is_large, rest) = bits.split_at(1);
    if is_large[0] {
        // X.691 § 11.6.2 forwards us to § 11.7 (semi-constrained integer)
        // with § 11.9 to govern the length
        todo!();
    } else {
        // take six bits
        if rest.len() < 6 {
            return get_eof(bits);
        }
        let (my_bits, rest) = bits.split_at(6);
        let my_value = Integer::from_bits(my_bits);
        Ok((rest, my_value))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

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