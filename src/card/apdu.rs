use super::make_apdu;

pub fn select_df(dfid: &[u8]) -> Vec<u8> {
    make_apdu(0x00, 0xa4, (0x04, 0x0c), 0, dfid)
}

pub fn select_ef(efid: &[u8]) -> Vec<u8> {
    make_apdu(0x00, 0xa4, (0x02, 0x0c), 0, efid)
}

pub fn select_jpki_ap() {
    select_df(b"\xD3\x92\xf0\x00\x26\x01\x00\x00\x00\x01");
}

pub fn get_jpki_token() {
    select_ef(b"\x00\x06");
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate hex_literal;
    use hex_literal::hex;
    #[test]
    fn it_makes_jpki_token_apdu() {
        assert_eq!(
            make_apdu(0x00, 0xa4, (0x02, 0x0c), 0x00, b"\x00\x06"),
            hex!("00a4020c02000600")
        );
    }
}
