use std::collections::BTreeMap;
use std::fmt;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::NaiveDate;
use der::oid::ObjectIdentifier;
use der::{Decode, Reader, SliceReader};
use der::asn1::Uint;
use digest::Digest;
use digest::generic_array::GenericArray;
use dsa::BigUint;
use ecdsa::EncodedPoint;
use p256::NistP256;
use sha1::Sha1;
use sha2::{Sha224, Sha256};
use sxd_document::QName;
use sxd_document::dom::Element;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

use crate::cryptography::{DsaParametersAsn1, DsaSignatureAsn1, DsaSignatureVerifier, EcdsaSignatureVerifier, SignatureVerifier};


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Signature {
    Dsa { r: Vec<u8>, s: Vec<u8> },
    Asn1(Vec<u8>),
}
impl Signature {
    pub fn to_dsa_signature(&self) -> Result<dsa::Signature, Error> {
        let (r_int, s_int) = match self {
            Self::Dsa { r, s } => {
                let r_int = BigUint::from_bytes_be(&r);
                let s_int = BigUint::from_bytes_be(&s);
                (r_int, s_int)
            },
            Self::Asn1(bs) => {
                let dsa_signature = DsaSignatureAsn1::from_der(bs)
                    .map_err(|e| Error::UnexpectedDsaSignatureStructure(e))?;

                let r_int = BigUint::from_bytes_be(&dsa_signature.r.as_bytes());
                let s_int = BigUint::from_bytes_be(&dsa_signature.s.as_bytes());
                (r_int, s_int)
            },
        };
        let signature = dsa::Signature::from_components(r_int, s_int)?;
        Ok(signature)
    }

    pub fn to_p256_ecdsa_signature(&self) -> Result<ecdsa::Signature<NistP256>, Error> {
        let signature = match self {
            Self::Dsa { r, s } => {
                let r_bytes = GenericArray::from_exact_iter(r.iter().cloned())
                    .ok_or(Error::MalformedEcdsaSignature)?;
                let s_bytes = GenericArray::from_exact_iter(s.iter().cloned())
                    .ok_or(Error::MalformedEcdsaSignature)?;
                ecdsa::Signature::from_scalars(r_bytes, s_bytes)
                    .map_err(|_| Error::MalformedEcdsaSignature)?
            },
            Self::Asn1(bs) => {
                ecdsa::Signature::from_der(bs)
                    .map_err(|_| Error::MalformedEcdsaSignature)?
            },
        };
        Ok(signature)
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Key {
    pub issuer_name: String,
    pub issuer_code: u16, // 0000-9999
    pub version_type: String,
    pub signature_algorithm: String,
    pub id: u32, // 00000-99999
    pub subject_public_key_info: SubjectPublicKeyInfoOwned,
    pub barcode_version: u8, // 1-3
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    pub barcode_xsd: String,
    pub allowed_product_owner_codes: Vec<ProductOwnerCode>,
    // keyForged is always empty
    pub comment_for_encryption_type: String,
}
impl Key {
    fn assemble_dsa_key(&self) -> Result<dsa::VerifyingKey, Error> {
        let Some(params_any) = &self.subject_public_key_info.algorithm.parameters else {
            return Err(Error::MissingDsaParameters);
        };

        // RFC 3279 § 2.3.2

        // parameters
        let params: DsaParametersAsn1 = match params_any.decode_as() {
            Ok(p) => p,
            Err(_) => return Err(Error::MalformedDsaParameters),
        };

        let p = BigUint::from_bytes_be(params.p.as_bytes());
        let q = BigUint::from_bytes_be(params.q.as_bytes());
        let g = BigUint::from_bytes_be(params.g.as_bytes());

        // key itself
        let key_bit_string = &self.subject_public_key_info.subject_public_key;
        let mut kbs_reader = SliceReader::new(key_bit_string.raw_bytes())
            .map_err(|_| Error::MalformedDsaKey)?;
        let y_uint: Uint = kbs_reader.decode()
            .map_err(|_| Error::MalformedDsaKey)?;
        let y = BigUint::from_bytes_be(y_uint.as_bytes());

        // assemble
        let components = dsa::Components::from_components(p, q, g)
            .map_err(|_| Error::MalformedDsaKey)?;
        dsa::VerifyingKey::from_components(components, y)
            .map_err(|_| Error::MalformedDsaKey)
    }

    fn assemble_dsa_verifier(&self, signature: &Signature) -> Result<Box<dyn SignatureVerifier>, Error> {
        let key = self.assemble_dsa_key()?;
        let expected_dsa_signature = signature.to_dsa_signature()?;
        Ok(Box::new(DsaSignatureVerifier {
            key,
            signature: expected_dsa_signature,
        }))
    }

    fn assemble_ecdsa_verifier(&self, signature: &Signature) -> Result<Box<dyn SignatureVerifier>, Error> {
        // find out which curve is being used
        // parameters is a CHOICE of ECParameters|OBJECT IDENTIFIER|NULL
        // to us, only OBJECT IDENTIFIER (named curve) is acceptable
        const CURVE_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

        let parameters_any = match self.subject_public_key_info.algorithm.parameters.as_ref() {
            Some(p) => p,
            None => return Err(Error::MissingEcdsaParameters),
        };
        let curve_name: ObjectIdentifier = parameters_any.decode_as()
            .map_err(|_| Error::EcdsaCurveNotNamed)?;
        if curve_name == CURVE_PRIME256V1 {
            let public_key = self.subject_public_key_info.subject_public_key.as_bytes()
                .ok_or(Error::MalformedEcdsaKey)?;
            let public_point = EncodedPoint::<NistP256>::from_bytes(public_key)
                .map_err(|_| Error::MalformedEcdsaKey)?;
            let key = ecdsa::VerifyingKey::<NistP256>::from_encoded_point(&public_point)
                .map_err(|_| Error::MalformedEcdsaKey)?;

            // oddly enough, the signature itself has the same structure as classic DSA
            let expected_ecdsa_signature = signature.to_p256_ecdsa_signature()?;
            Ok(Box::new(EcdsaSignatureVerifier {
                key,
                signature: expected_ecdsa_signature,
            }))
        } else {
            Err(Error::UnsupportedCurve(curve_name))
        }
    }

    pub fn verify(&self, signature: &Signature, data: &[u8]) -> Result<bool, Error> {
        match self.signature_algorithm.as_str() {
            "DSA_SHA1 (1024)"|"DSA1024"|"SHA1-DSA (1024,160)"|"SHA1-DSA (1024)"|"SHA1withDSA"|"SHA1withDSA(1024,160)" => {
                let verifier = self.assemble_dsa_verifier(signature)?;

                // perform the digest
                let mut sha1 = Sha1::new();
                sha1.update(data);
                let sha1_digest = sha1.finalize();

                // verify it
                Ok(verifier.verify_prehash(&sha1_digest).is_ok())
            },
            "SHA224withDSA" => {
                let verifier = self.assemble_dsa_verifier(signature)?;
                let mut sha224 = Sha224::new();
                sha224.update(data);
                let sha224_digest = sha224.finalize();
                Ok(verifier.verify_prehash(&sha224_digest).is_ok())
            },
            "SHA256withDSA(2048,256)" => {
                let verifier = self.assemble_dsa_verifier(signature)?;
                let mut sha256 = Sha256::new();
                sha256.update(data);
                let sha256_digest = sha256.finalize();
                Ok(verifier.verify_prehash(&sha256_digest).is_ok())
            },
            "SHA256withECDSA"|"SHA256withECDSA-P256" => {
                let verifier = self.assemble_ecdsa_verifier(signature)?;
                let mut sha256 = Sha256::new();
                sha256.update(data);
                let sha256_digest = sha256.finalize();
                Ok(verifier.verify_prehash(&sha256_digest).is_ok())
            },
            other => panic!("unsupported signature algorithm {:?}", other),
        }
    }
}

#[derive(Clone, Debug, Default, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProductOwnerCode {
    pub code: u16, // 0000-9999
    pub name: String,
}

#[derive(Debug)]
pub enum Error {
    XmlParsing(sxd_document::parser::Error),
    MissingRootElement,
    UnexpectedRootName { expected: OwnedQName, obtained: OwnedQName },
    RequiredElementNotFound { expected: OwnedQName },
    ParsingProperty { property: &'static str, value: String },
    OperatorNameWithoutCode(String),
    Base64Decoding(base64::DecodeError),
    CreatingDerReader(der::Error),
    DecodingCertificate(der::Error),
    DsaSignature(dsa::signature::Error),
    UnexpectedDsaSignatureStructure(der::Error),
    MissingDsaParameters,
    MalformedDsaParameters,
    MalformedDsaKey,
    MissingEcdsaParameters,
    EcdsaCurveNotNamed,
    UnsupportedCurve(der::oid::ObjectIdentifier),
    MalformedEcdsaKey,
    MalformedEcdsaSignature,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XmlParsing(e)
                => write!(f, "error parsing XML: {}", e),
            Self::MissingRootElement
                => write!(f, "XML is missing root element"),
            Self::UnexpectedRootName { expected, obtained }
                => write!(f, "root element has unexpected name {}, expected {}", obtained, expected),
            Self::RequiredElementNotFound { expected }
                => write!(f, "expected element named {} not found", expected),
            Self::ParsingProperty { property, value }
                => write!(f, "failed to parse {} {:?}", property, value),
            Self::OperatorNameWithoutCode(name)
                => write!(f, "operator {:?} has no corresponding code", name),
            Self::Base64Decoding(e)
                => write!(f, "error decoding base64: {}", e),
            Self::CreatingDerReader(e)
                => write!(f, "error creating DER reader: {}", e),
            Self::DecodingCertificate(e)
                => write!(f, "error decoding certificate: {}", e),
            Self::DsaSignature(e)
                => write!(f, "error with DSA signature: {}", e),
            Self::UnexpectedDsaSignatureStructure(e)
                => write!(f, "unexpected DSA signature structure: {}", e),
            Self::MissingDsaParameters
                => write!(f, "certificate is missing DSA parameters"),
            Self::MalformedDsaParameters
                => write!(f, "certificate contains malformed DSA parameters"),
            Self::MalformedDsaKey
                => write!(f, "certificate contains malformed DSA key"),
            Self::MissingEcdsaParameters
                => write!(f, "DSA parameters are missing"),
            Self::EcdsaCurveNotNamed
                => write!(f, "ECDSA curve is not a named curve"),
            Self::UnsupportedCurve(oid)
                => write!(f, "ECDSA curve {} is currently not supported", oid),
            Self::MalformedEcdsaKey
                => write!(f, "certificate contains malformed ECDSA key"),
            Self::MalformedEcdsaSignature
                => write!(f, "ECDSA signature is malformed"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::XmlParsing(e) => Some(e),
            Self::MissingRootElement => None,
            Self::UnexpectedRootName { .. } => None,
            Self::RequiredElementNotFound { .. } => None,
            Self::ParsingProperty { .. } => None,
            Self::OperatorNameWithoutCode(_) => None,
            Self::Base64Decoding(e) => Some(e),
            Self::CreatingDerReader(e) => Some(e),
            Self::DecodingCertificate(e) => Some(e),
            Self::DsaSignature(_) => None,
            Self::UnexpectedDsaSignatureStructure(e) => Some(e),
            Self::MissingDsaParameters => None,
            Self::MalformedDsaParameters => None,
            Self::MalformedDsaKey => None,
            Self::MissingEcdsaParameters => None,
            Self::EcdsaCurveNotNamed => None,
            Self::UnsupportedCurve(_) => None,
            Self::MalformedEcdsaKey => None,
            Self::MalformedEcdsaSignature => None,
        }
    }
}
impl From<sxd_document::parser::Error> for Error {
    fn from(value: sxd_document::parser::Error) -> Self { Self::XmlParsing(value) }
}
impl From<base64::DecodeError> for Error {
    fn from(value: base64::DecodeError) -> Self { Self::Base64Decoding(value) }
}
impl From<dsa::signature::Error> for Error {
    fn from(value: dsa::signature::Error) -> Self { Self::DsaSignature(value) }
}

#[derive(Clone, Debug, Default, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct OwnedQName {
    pub namespace: Option<String>,
    pub local_name: String,
}
impl OwnedQName {
    pub fn new<N: Into<String>, L: Into<String>>(namespace: Option<N>, local_name: L) -> Self {
        Self {
            namespace: namespace.map(|n| n.into()),
            local_name: local_name.into(),
        }
    }
}
impl fmt::Display for OwnedQName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ns) = self.namespace.as_ref() {
            write!(f, "{}{}{}{}", '{', ns, '}', self.local_name)
        } else {
            write!(f, "{}", self.local_name)
        }
    }
}
impl<'d> From<QName<'d>> for OwnedQName {
    fn from(value: QName<'d>) -> Self {
        Self::new(value.namespace_uri(), value.local_part())
    }
}

fn verify_root_name<'d>(root_elem: Element<'d>, namespace: Option<&str>, local: &str) -> Result<(), Error> {
    let expected_name = QName::with_namespace_uri(namespace, local);
    if root_elem.name() == expected_name {
        Ok(())
    } else {
        Err(Error::UnexpectedRootName { expected: expected_name.into(), obtained: root_elem.name().into() })
    }
}

fn get_child_element<'d>(base_elem: Element<'d>, namespace: Option<&str>, local: &str) -> Result<Element<'d>, Error> {
    let name = QName::with_namespace_uri(namespace, local);
    let child = base_elem
        .children()
        .into_iter()
        .filter_map(|c| c.element())
        .filter(|e| e.name() == name)
        .nth(0)
        .ok_or(Error::RequiredElementNotFound { expected: name.into() })?;
    Ok(child)
}

fn get_element_text<'d>(elem: Element<'d>) -> String {
    elem
        .children()
        .into_iter()
        .filter_map(|c| c.text())
        .map(|t| t.text())
        .collect()
}

fn get_child_element_text<'d>(base_elem: Element<'d>, namespace: Option<&str>, local: &str) -> Result<String, Error> {
    let child = get_child_element(base_elem, namespace, local)?;
    Ok(get_element_text(child))
}

pub fn database_from_xml(xml_str: &str) -> Result<BTreeMap<(u16, u32), Key>, Error> {
    let package = sxd_document::parser::parse(xml_str)?;
    let doc = package.as_document();

    let root_elem = doc.root()
        .children()
        .into_iter()
        .filter_map(|c| c.element())
        .nth(0)
        .ok_or(Error::MissingRootElement)?;
    verify_root_name(root_elem, None, "keys")?;
    let key_elems = root_elem
        .children()
        .into_iter()
        .filter_map(|c| c.element())
        .filter(|e| e.name() == "key".into());
    let mut database = BTreeMap::new();
    for key_elem in key_elems {
        let issuer_name = get_child_element_text(key_elem, None, "issuerName")?;
        let issuer_code_str = get_child_element_text(key_elem, None, "issuerCode")?;
        let version_type = get_child_element_text(key_elem, None, "versionType")?;
        let signature_algorithm = get_child_element_text(key_elem, None, "signatureAlgorithm")?;
        let id_str = get_child_element_text(key_elem, None, "id")?;
        let public_key_b64 = get_child_element_text(key_elem, None, "publicKey")?
            .replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "");
        let barcode_version_str = get_child_element_text(key_elem, None, "barcodeVersion")?;
        let start_date_str = get_child_element_text(key_elem, None, "startDate")?;
        let end_date_str = get_child_element_text(key_elem, None, "endDate")?;
        let barcode_xsd = get_child_element_text(key_elem, None, "barcodeXsd")?;
        // allowedProductOwnerCodes -- structured items
        // keyForged -- unknown values, skip
        let comment_for_encryption_type = get_child_element_text(key_elem, None, "commentForEncryptionType")?;

        let mut allowed_product_owner_codes = Vec::new();
        let apoc_children = get_child_element(key_elem, None, "allowedProductOwnerCodes")?
            .children()
            .into_iter()
            .filter_map(|c| c.element());
        let mut last_code = None;
        for apoc_child in apoc_children {
            if apoc_child.name() == QName::new("productOwnerCode") {
                let code_str = get_element_text(apoc_child);
                let code: u16 = code_str.parse()
                    .map_err(|_| Error::ParsingProperty { property: "operator code", value: code_str })?;
                last_code = Some(code);
            } else if apoc_child.name() == QName::new("productOwnerName") {
                let name = get_element_text(apoc_child);
                if let Some(lc) = last_code {
                    allowed_product_owner_codes.push(ProductOwnerCode {
                        name,
                        code: lc,
                    });
                } else {
                    return Err(Error::OperatorNameWithoutCode(name));
                }
            }
        }

        let issuer_code: u16 = issuer_code_str.parse()
            .map_err(|_| Error::ParsingProperty { property: "issuer code", value: issuer_code_str })?;
        let mut id: u32 = id_str.parse()
            .map_err(|_| Error::ParsingProperty { property: "key ID", value: id_str })?;
        let public_key_bytes = BASE64_STANDARD.decode(&public_key_b64)?;
        let barcode_version: u8 = barcode_version_str.parse()
            .map_err(|_| Error::ParsingProperty { property: "barcode version", value: barcode_version_str })?;
        let start_date = NaiveDate::parse_from_str(&start_date_str, "%Y-%m-%d")
            .map_err(|_| Error::ParsingProperty { property: "start date", value: start_date_str })?;
        let end_date = NaiveDate::parse_from_str(&end_date_str, "%Y-%m-%d")
            .map_err(|_| Error::ParsingProperty { property: "end date", value: end_date_str })?;

        if id > 99_999 {
            // perhaps it contains the issuer code too? (1251/125110002)
            if id / 100_000 == u32::from(issuer_code) {
                // yup; strip it off
                id %= 100_000;
            }
        }

        // try to read as certificate
        let mut certificate_reader = der::SliceReader::new(public_key_bytes.as_slice())
            .map_err(|e| Error::CreatingDerReader(e))?;
        let subject_public_key_info: SubjectPublicKeyInfoOwned = match Certificate::decode(&mut certificate_reader) {
            Ok(c) => c.tbs_certificate.subject_public_key_info,
            Err(_) => {
                // try reading as SubjectPublicKeyInfo instead
                let mut spki_reader = der::SliceReader::new(public_key_bytes.as_slice())
                    .map_err(|e| Error::CreatingDerReader(e))?;
                SubjectPublicKeyInfoOwned::decode(&mut spki_reader)
                    .map_err(|e| Error::DecodingCertificate(e))?
            },
        };

        database.insert(
            (issuer_code, id),
            Key {
                issuer_name,
                issuer_code,
                version_type,
                signature_algorithm,
                id,
                subject_public_key_info,
                barcode_version,
                start_date,
                end_date,
                barcode_xsd,
                allowed_product_owner_codes,
                comment_for_encryption_type,
            }
        );
    }

    Ok(database)
}
