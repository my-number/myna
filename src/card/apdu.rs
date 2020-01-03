use super::make_apdu;
use block_modes::{block_padding::Iso7816, Cbc};
use des::TdesEde2;

type TdesEde2Cbc = Cbc<TdesEde2, Iso7816>;
pub fn select_mf(mfid: &[u8]) -> Vec<u8> {
    make_apdu(0x00, 0xa4, (0x00, 0x00), 0, mfid)
}
pub fn select_df(dfid: &[u8]) -> Vec<u8> {
    make_apdu(0x00, 0xa4, (0x04, 0x0c), 0, dfid)
}

pub fn select_ef(efid: &[u8]) -> Vec<u8> {
    make_apdu(0x00, 0xa4, (0x02, 0x0c), 0, efid)
}

fn encrypt(data: &[u8], k_enc: [u8; 16]) -> &[u8] {
    let cipher = TdesEde2Cbc::new_var(&k_enc, &[0u8; 8]).unwrap(); // change var to fix later
    &cipher.encrypt_vec(data)[..]
}
/// returns APDU that execute authentication by card number etc.
pub fn verify(auth_code: [u8; 12], session_key: [u8; 16]) -> Vec<u8> {
    let ciphertext = encrypt(&auth_code, session_key);
    make_apdu(0x08, 0x20, (0x00, 0x86), 0, ciphertext)
}

/// returns APDU that gets RND.ICC(card random) by GET_CHALLENGE command
pub fn get_challenge() -> Vec<u8> {
    make_apdu(0x00, 0x84, (0x00, 0x00), 8, &[])
}

/// returns APDU of MUTUAL_AUTHENTICATE command
pub fn mutual_authenticate(
    rnd_ifd: &[u8; 8],
    rnd_icc: [u8; 8],
    k_ifd: [u8; 16],
    k_enc: [u8; 16],
) -> Vec<u8> {
    let mut concatenated = [0u8; 32];
    concatenated[0..8].copy_from_slice(rnd_ifd);
    concatenated[8..16].copy_from_slice(rnd_icc);
    concatenated[16..].copy_from_slice(k_ifd);
    let e_ifd = encrypt(concatenated, k_enc);

    make_apdu()
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
    fn it_encrypts_card_number() {
        assert_eq!(
            verify(hex!("41 41 31 32 33 34 35 36 37 38 42 42")),
            hex!("08 20 00 86 13 86 11 01 1A A8 29 73 DB 95 9A 81 1F 97 11 D7 28 F0 EE F6")
        )
    }
}
