extern crate der_parser;
extern crate failure;
extern crate rsa;
use der_parser::{ber::BerObjectContent, error::BerError, parse_der};
use rsa::{
    errors::Error as RSAError, hash::Hashes, BigUint, PaddingScheme, PublicKey, RSAPublicKey,
};

#[derive(Debug)]
pub enum Error {
    ParseError,
    NumberError,
}
impl From<BerError> for Error {
    fn from(_: BerError) -> Error {
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
pub fn extract_pubkey(cert_der: &[u8]) -> Result<RSAPublicKey, Error> {
    let parsed = parse_der(cert_der)?.1;
    let pubkey_der = parsed.as_sequence()?[6].as_sequence()?[1]
        .as_bitstring()?
        .data;
    convert_pubkey_der(pubkey_der)
}

pub fn verify_cert(cert_der: &[u8], cacert_der: &[u8]) -> Result<(), Error> {
    let capub = extract_pubkey(cacert_der)?;
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
}
