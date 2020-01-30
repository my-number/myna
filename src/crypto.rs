extern crate der_parser;
extern crate failure;
extern crate rsa;
extern crate alloc;
extern crate sha2;
use alloc::vec;
use alloc::vec::Vec;
use der_parser::{ber::BerObjectContent, error::BerError, oid::Oid, parse_der};
use rsa::{
    errors::Error as RSAError, hash::Hashes, BigUint, PaddingScheme, PublicKey, RSAPublicKey,
};
use sha2::{
    digest::{FixedOutput, Input},
    Sha256,
};
use x509_parser::{error::X509Error, parse_x509_der};
#[derive(Debug)]
pub enum Error {
    ParseError,
    NumberError,
    NoCAError,
    VerificationError,
}
impl From<BerError> for Error {
    fn from(_: BerError) -> Error {
        Error::ParseError
    }
}
impl From<X509Error> for Error {
    fn from(_: X509Error) -> Error {
        Error::ParseError
    }
}
impl From<RSAError> for Error {
    fn from(_: RSAError) -> Error {
        Error::NumberError
    }
}

pub fn encode_for_signature<H: rsa::hash::Hash>(
    hashed: &[u8],
    hashType: Option<&H>,
) -> Result<Vec<u8>, RSAError> {
    Ok(vec![0; 0])

    // ASN.1のTagとかLengthの固定値をくっつけるだけ。
    // マイナンバーカードにかませられるだけのデータを。
    // てか、噛ませられるデータって実は任意なのでは？
}

/// It verifies signature. Hash function is SHA256. Padding scheme is PKCS 1.
pub fn verify(
    pubkey: RSAPublicKey,
    hash: &[u8],
    signature: &[u8],
) -> Result<(), rsa::errors::Error> {
    pubkey.verify(
        PaddingScheme::PKCS1v15,
        Some(&Hashes::SHA2_256),
        &hash,
        &signature,
    )
}

/// It converts der formatted public key slice to RSAPublicKey object.
pub fn convert_pubkey_der(pubkey_der: &[u8]) -> Result<RSAPublicKey, Error> {
    let parsed = match parse_der(pubkey_der) {
        Ok(s) => s.1,
        Err(_) => return Err(Error::ParseError),
    };
    let pubkey = parsed.as_sequence()?;
    let n = match pubkey[0].content {
        BerObjectContent::Integer(s) => BigUint::from_bytes_be(s),
        _ => return Err(Error::NumberError),
    };
    let e = match pubkey[1].content {
        BerObjectContent::Integer(s) => BigUint::from_bytes_be(s),
        _ => return Err(Error::NumberError),
    };
    Ok(RSAPublicKey::new(n, e)?)
}
fn parse_cert(cert_der: &[u8]) -> Result<x509_parser::X509Certificate, Error> {
    let parsed = match parse_x509_der(cert_der) {
        Ok(p) => p.1,
        Err(_) => return Err(Error::ParseError),
    };
    Ok(parsed)
}
pub fn extract_pubkey(cert_der: &[u8]) -> Result<RSAPublicKey, Error> {
    let pubkey_der = parse_cert(cert_der)?
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data;
    convert_pubkey_der(pubkey_der)
}

pub fn verify_cert(cert_der: &[u8], cacert_der: &[u8]) -> Result<(), Error> {
    let cacert = parse_cert(cacert_der)?;
    if !cacert.tbs_certificate.is_ca() {
        return Err(Error::NoCAError);
    }
    let capub = extract_pubkey(cacert_der)?;
    let cert = parse_cert(cert_der)?;
    let to_hash = &cert.tbs_certificate;
    if cert.signature_algorithm.algorithm == Oid::from(&[1, 2, 840, 113549, 1, 1, 11]) {
        // sha256WithRSAEncryption
        let mut hasher = Sha256::default();
        hasher.input(to_hash);
        let hashed = &hasher.fixed_result();

        match verify(capub, hashed, cert.signature_value.data) {
            Ok(()) => return Ok(()),
            Err(_) => return Err(Error::VerificationError),
        };
    // verify code to be written after meeting
    } else {
        unimplemented!()
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vector;
    #[test]
    fn it_verifies_valid_signature() {
        let pubkey = convert_pubkey_der(test_vector::PUBKEY_DER).unwrap();
        assert!(verify(
            pubkey,
            &test_vector::MSG1_SHA256,
            &test_vector::SIG_MSG1_SHA256RSAPKCS,
        )
        .is_ok())
    }
    #[test]
    fn it_fails_invalid_signature() {
        let pubkey = convert_pubkey_der(test_vector::PUBKEY_DER).unwrap();
        assert!(verify(pubkey, &test_vector::MSG1_SHA256, &[0; 256],).is_err())
    }
    #[test]
    fn it_fails_invalid_hash() {
        let pubkey = convert_pubkey_der(test_vector::PUBKEY_DER).unwrap();
        assert!(verify(pubkey, &[0; 32], test_vector::SIG_MSG1_SHA256RSAPKCS).is_err())
    }
    #[test]
    fn it_fails_invalid_pubkey_der() {
        assert!(convert_pubkey_der(&[0; 34]).is_err())
    }
    #[test]
    fn it_verifies_certificate() {
        assert!(verify_cert(test_vector::CERT_DER, test_vector::CA_JPKI_AUTH_01).is_ok())
    }
    #[test]
    fn it_verifies_selfsigned_certificate() {
        assert!(verify_cert(test_vector::CA_JPKI_AUTH_01, test_vector::CA_JPKI_AUTH_01).is_ok())
    }
    #[test]
    fn it_rejects_non_ca() {
        assert!(verify_cert(test_vector::CERT_DER, test_vector::CERT_DER).is_err())
    }
}
