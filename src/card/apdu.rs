use super::make_apdu;

pub fn select_df(dfid: &[u8]) -> Vec<u8> {
    make_apdu(0x00, 0xa4, (0x04, 0x0c), dfid, None)
}

pub fn select_ef(efid: &[u8]) -> Vec<u8> {
    make_apdu(0x00, 0xa4, (0x02, 0x0c), efid, None)
}

pub fn select_jpki_ap() -> Vec<u8> {
    select_df(b"\xD3\x92\xf0\x00\x26\x01\x00\x00\x00\x01")
}

pub fn select_jpki_token() -> Vec<u8> {
    select_ef(b"\x00\x06")
}
pub fn select_jpki_cert_auth() -> Vec<u8> {
    select_ef(b"\x00\x0a")
}

pub fn select_jpki_auth_pin() -> Vec<u8> {
    select_ef(b"\x00\x18")
}
pub fn select_jpki_auth_key() -> Vec<u8> {
    select_ef(b"\x00\x17")
}
/// return APDU that get random number.
pub fn get_challenge(size: u8) -> Vec<u8> {
    make_apdu(0x00, 0x84, (0, 0), &[], Some(size))
}

/// return APDU that get the head 7byte of certificate of current file.
pub fn get_jpki_cert_header() -> Vec<u8> {
    make_apdu(0x00, 0xb0, (0x00, 0x00), &[], Some(7))
}

pub fn verify(pin: &str) -> Vec<u8> {
    make_apdu(0x00, 0x20, (0x00, 0x80), &pin.as_bytes(), None)
}

pub fn compute_sig(hash_pkcs1: &[u8]) -> Vec<u8> {
    make_apdu(0x80, 0x2a, (0x00, 0x80), hash_pkcs1, Some(0)) // zero, the value of Le probably means 256. it overflowed.
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate hex_literal;
    use hex_literal::hex;
    #[test]
    fn it_makes_jpki_token_apdu() {
        assert_eq!(
            make_apdu(0x00, 0xa4, (0x02, 0x0c), b"\x00\x06", 0x00),
            hex!("00a4020c02000600")
        );
    }
}
