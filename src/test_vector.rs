#![allow(dead_code)]
use hex_literal::hex;

pub const CERT_DER: &[u8] = include_bytes!("./test_vector/auth-cert-myna.cer");
pub const PUBKEY_DER: &[u8] = include_bytes!("./test_vector/auth-pubkey-myna.der");

pub const MSG1: &[u8] = include_bytes!("./test_vector/message1.txt");
pub const MSG1_SHA256: &[u8] =
    &hex!("97d035e32036a670058f2be4e008a7c56355489750a5da6f2af342db4a968e99"); //32bytes

pub const SIG_MSG1_SHA256RSAPKCS: &[u8] =
    include_bytes!("./test_vector/auth-message1-sha256rsapkcs.sig");

pub const PKCS1_ENCODED: &[u8] = &hex!("3031300d06096086480165030402010500042097d035e32036a670058f2be4e008a7c56355489750a5da6f2af342db4a968e99"); //51bytes

pub const CA_JPKI_AUTH_01: &[u8] = include_bytes!("./test_vector/authca01.cer"); // CA certificate "authca01" for JPKI Auth Certificate
