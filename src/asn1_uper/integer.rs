//! Arbitrary-size integers for ASN.1.


use std::borrow::Cow;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Rem, Shl, Shr, Sub};

use num_bigint::BigInt;
use once_cell::sync::Lazy;


pub type ShortInt = i128;

static SHORT_MIN: Lazy<BigInt> = Lazy::new(|| BigInt::from(ShortInt::MIN));
static SHORT_MAX: Lazy<BigInt> = Lazy::new(|| BigInt::from(ShortInt::MAX));


/// An ASN.1 arbitrary-size integer.
pub struct Integer {
    inner: IntegerInner,
}
impl Integer {
    /// Creates an ASN.1 integer with the given short value.
    pub const fn from_short(value: ShortInt) -> Self {
        Self {
            inner: IntegerInner::Short(value),
        }
    }

    /// Creates an ASN.1 integer with the given long value.
    pub fn from_long(value: BigInt) -> Self {
        if &value >= &SHORT_MIN && &value <= &SHORT_MAX {
            // reduce this
            Self::from_short(value.try_into().unwrap())
        } else {
            Self {
                inner: IntegerInner::Long(value),
            }
        }
    }

    /// Returns the inner integer as a BigInt value.
    #[inline]
    pub fn to_bigint(&self) -> Cow<BigInt> {
        self.inner.to_bigint()
    }
}

macro_rules! implement_bin_op {
    (@infallible, $trait:ident, $func:ident) => {
        impl $trait for &Integer {
            type Output = Integer;

            fn $func(self, rhs: Self) -> Self::Output {
                match (&self.inner, &rhs.inner) {
                    (IntegerInner::Short(l), IntegerInner::Short(r)) => {
                        // stay short
                        Integer::from_short($trait::$func(*l, *r))
                    },
                    // otherwise, work with BigInt and reduce if possible
                    (IntegerInner::Short(l), IntegerInner::Long(r)) => {
                        Integer::from_long($trait::$func(BigInt::from(*l), r))
                    },
                    (IntegerInner::Long(l), IntegerInner::Short(r)) => {
                        Integer::from_long($trait::$func(l, BigInt::from(*r)))
                    },
                    (IntegerInner::Long(l), IntegerInner::Long(r)) => {
                        Integer::from_long($trait::$func(l, r))
                    },
                }
            }
        }
    };
    (@checked, $trait:ident, $func:ident, $checked_op_func:ident) => {
        impl $trait for &Integer {
            type Output = Integer;

            fn $func(self, rhs: Self) -> Self::Output {
                match (&self.inner, &rhs.inner) {
                    (IntegerInner::Short(l), IntegerInner::Short(r)) => {
                        // stay short if it fits
                        match l.$checked_op_func(*r) {
                            Some(sum) => Integer::from_short(sum),
                            None => Integer::from_long($trait::$func(BigInt::from(*l), BigInt::from(*r))),
                        }
                    },
                    // otherwise, work with BigInt and reduce if possible
                    (IntegerInner::Short(l), IntegerInner::Long(r)) => {
                        Integer::from_long($trait::$func(BigInt::from(*l), r))
                    },
                    (IntegerInner::Long(l), IntegerInner::Short(r)) => {
                        Integer::from_long($trait::$func(l, BigInt::from(*r)))
                    },
                    (IntegerInner::Long(l), IntegerInner::Long(r)) => {
                        Integer::from_long($trait::$func(l, r))
                    },
                }
            }
        }
    };
    (@checked_rhs, $trait:ident, $func:ident, $checked_op_func:ident, $rhs_type:ty) => {
        impl $trait<$rhs_type> for &Integer {
            type Output = Integer;

            fn $func(self, rhs: $rhs_type) -> Self::Output {
                match &self.inner {
                    IntegerInner::Short(l) => {
                        // stay short if it fits
                        match l.$checked_op_func(rhs) {
                            Some(sum) => Integer::from_short(sum),
                            None => Integer::from_long($trait::$func(BigInt::from(*l), rhs)),
                        }
                    },
                    IntegerInner::Long(l) => {
                        // work with BigInt and reduce if possible
                        Integer::from_long($trait::$func(l, rhs))
                    },
                }
            }
        }
    };
}
implement_bin_op!(@checked, Add, add, checked_add);
implement_bin_op!(@infallible, BitAnd, bitand);
implement_bin_op!(@infallible, BitOr, bitor);
implement_bin_op!(@infallible, BitXor, bitxor);
implement_bin_op!(@checked, Div, div, checked_div);
implement_bin_op!(@checked, Mul, mul, checked_mul);
implement_bin_op!(@checked, Rem, rem, checked_rem);
implement_bin_op!(@checked_rhs, Shl, shl, checked_shl, u32);
implement_bin_op!(@checked_rhs, Shr, shr, checked_shr, u32);
implement_bin_op!(@checked, Sub, sub, checked_sub);
impl Neg for Integer {
    type Output = Integer;

    fn neg(self) -> Self::Output {
        match &self.inner {
            IntegerInner::Short(v) => {
                match v.checked_neg() {
                    Some(neg) => Integer::from_short(neg),
                    None => Integer::from_long(Neg::neg(BigInt::from(*v))),
                }
            },
            IntegerInner::Long(l) => {
                Integer::from_long(Neg::neg(l))
            },
        }
    }
}



/// The magic behind an ASN.1 integer.
///
/// The enum is hidden inside the struct so that the variants cannot be constructed by the user.
/// This makes it possible to ensure that integers are always normalized (i.e. short integers are
/// always used when the value fits).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum IntegerInner {
    Short(ShortInt),
    Long(BigInt),
}
impl IntegerInner {
    pub fn to_bigint(&self) -> Cow<BigInt> {
        match self {
            Self::Short(s) => Cow::Owned(BigInt::from(*s)),
            Self::Long(l) => Cow::Borrowed(l),
        }
    }
}
impl Default for IntegerInner {
    fn default() -> Self { Self::Short(0) }
}
