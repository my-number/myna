extern crate der_parser;
extern crate failure;
extern crate rsa;
use der_parser::{ber::BerObjectContent, parse_der};
use rsa::{hash::Hashes, BigUint, PaddingScheme, PublicKey, RSAPublicKey};
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

pub fn convert_pubkey_der(pubkey_der: &[u8]) -> Result<RSAPublicKey, ()> {
    let parsed = parse_der(pubkey_der)?.1;
    let pubkey = parsed.as_sequence()?;
    let n = match pubkey[0].content {
        BerObjectContent::Integer(s) => BigUint::from_bytes_be(s),
        _ => return Err(()),
    };
    let e = match pubkey[1].content {
        BerObjectContent::Integer(s) => BigUint::from_bytes_be(s),
        _ => return Err(()),
    };
    RSAPublicKey::new(n, e)
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
