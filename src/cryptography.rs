use der::Sequence;
use der::asn1::Uint;
use digest::generic_array::ArrayLength;
use ecdsa::PrimeCurve;
use ecdsa::elliptic_curve::CurveArithmetic;
use ecdsa::hazmat::VerifyPrimitive;
use signature::hazmat::PrehashVerifier;


#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Sequence)]
pub(crate) struct DsaParametersAsn1 {
    pub p: Uint,
    pub q: Uint,
    pub g: Uint,
}


#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Sequence)]
pub(crate) struct DsaSignatureAsn1 {
    pub r: Uint,
    pub s: Uint,
}


pub(crate) trait SignatureVerifier {
    fn verify_prehash(&self, prehash: &[u8]) -> Result<(), signature::Error>;
}

pub(crate) struct DsaSignatureVerifier {
    pub key: dsa::VerifyingKey,
    pub signature: dsa::Signature,
}
impl SignatureVerifier for DsaSignatureVerifier {
    fn verify_prehash(&self, prehash: &[u8]) -> Result<(), signature::Error> {
        self.key.verify_prehash(prehash, &self.signature)
    }
}

pub(crate) struct EcdsaSignatureVerifier<C>
    where
        C: CurveArithmetic + PrimeCurve,
        <C as CurveArithmetic>::AffinePoint: VerifyPrimitive<C>,
        <<C as ecdsa::elliptic_curve::Curve>::FieldBytesSize as std::ops::Add>::Output: ArrayLength<u8> {
    pub key: ecdsa::VerifyingKey<C>,
    pub signature: ecdsa::Signature<C>,
}
impl<C> SignatureVerifier for EcdsaSignatureVerifier<C>
    where
        C: CurveArithmetic + PrimeCurve,
        <C as CurveArithmetic>::AffinePoint: VerifyPrimitive<C>,
        <<C as ecdsa::elliptic_curve::Curve>::FieldBytesSize as std::ops::Add>::Output: ArrayLength<u8> {
    fn verify_prehash(&self, prehash: &[u8]) -> Result<(), signature::Error> {
        self.key.verify_prehash(prehash, &self.signature)
    }
}
