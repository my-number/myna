use super::make_apdu;
extern crate alloc;
use alloc::vec::Vec;
use der_parser::der::der_read_element_header;

type ApduBody = Vec<u8>;

#[derive(Debug)]
pub enum ApduRes {
    /// SW is 9000 or 9100
    Ok(ApduBody),
    /// SW is 6a86
    ParamIncorrect,
    /// SW is 67XX
    WrongLength,
    /// Errors not defined here
    OtherError(u8, u8),
}
impl ApduRes {
    pub fn new(sw1: u8, sw2: u8, data: ApduBody) -> Self {
        if (sw1 == 0x90 || sw1 == 0x91) && sw2 == 0x00 {
            return Self::Ok(data);
        }
        if sw1 == 0x6a && sw2 == 0x86 {
            return Self::ParamIncorrect;
        }
        if sw1 == 0x67 {
            return Self::WrongLength;
        }
        ApduRes::OtherError(sw1, sw2)
    }
    pub fn from_apdu(apdu: &[u8]) -> Self {
        Self::new(
            apdu[apdu.len() - 2],
            apdu[apdu.len() - 1],
            apdu[0..apdu.len() - 2].to_vec(),
        )
    }
    pub fn unwrap(self) -> ApduBody {
        match self {
            Self::Ok(t) => t,
            _ => panic!("Unwrap failed"),
        }
    }
}

type TransFunc = dyn Fn(&[u8]) -> ApduRes;

pub struct Apdu<T>
where
    T: Fn(&[u8]) -> ApduRes,
{
    /// Function that transmit APDU request & make response into ApduRes
    transfunc: T,
}

type Result<T> = core::result::Result<T, &'static str>;

impl<T> Apdu<T>
where
    T: Fn(&[u8]) -> ApduRes,
{
    pub fn new(transfunc: T) -> Self {
        Self { transfunc }
    }
    pub(crate) fn transmit(&self, data: ApduBody) -> ApduRes {
        (self.transfunc)(&data[..])
    }
    pub fn select_df(&self, dfid: &[u8]) -> Result<()> {
        match self.transmit(make_apdu(0x00, 0xa4, (0x04, 0x0c), dfid, None)) {
            ApduRes::Ok(_) => Ok(()),
            _ => Err("Failed to SELECT DF"),
        }
    }

    pub fn select_ef(&self, efid: &[u8]) -> Result<()> {
        match self.transmit(make_apdu(0x00, 0xa4, (0x02, 0x0c), efid, None)) {
            ApduRes::Ok(_) => Ok(()),
            _ => Err("Failed to SELECT EF"),
        }
    }

    pub fn select_jpki_ap(&self) -> Result<()> {
        self.select_df(b"\xD3\x92\xf0\x00\x26\x01\x00\x00\x00\x01")
    }
    pub fn select_jpki_token(&self) -> Result<()> {
        self.select_ef(b"\x00\x06")
    }
    pub fn select_jpki_cert_auth(&self) -> Result<()> {
        self.select_ef(b"\x00\x0a")
    }

    pub fn select_jpki_auth_pin(&self) -> Result<()> {
        self.select_ef(b"\x00\x18")
    }
    pub fn select_jpki_auth_key(&self) -> Result<()> {
        self.select_ef(b"\x00\x17")
    }
    pub fn get_challenge(&self, size: u8) -> Result<ApduBody> {
        match self.transmit(make_apdu(0x00, 0x84, (0, 0), &[], Some(size))) {
            ApduRes::Ok(data) => Ok(data),
            _ => Err("GET CHALLENGE failed"),
        }
    }
    pub fn verify_pin(&self, pin: &str) -> Result<()> {
        match self.transmit(make_apdu(0x00, 0x20, (0x00, 0x80), &pin.as_bytes(), None)) {
            ApduRes::Ok(_) => Ok(()),
            _ => Err("VERIFY PIN failed"),
        }
    }
    pub fn compute_sig(&self, hash_pkcs1: &[u8]) -> Result<ApduBody> {
        match self.transmit(make_apdu(0x80, 0x2a, (0x00, 0x80), hash_pkcs1, Some(0))) {
            // zero, the value of Le probably means 256. it overflowed.
            ApduRes::Ok(sig) => Ok(sig),
            _ => Err("COMPUTE DIGITAL SIGNATURE failed"),
        }
    }
    pub fn read_binary(&self) -> Result<Vec<u8>> {
        let header = match self.transmit(make_apdu(0x00, 0xb0, (0u8, 0u8), &[], Some(7u8))) {
            ApduRes::Ok(s) => s,
            _ => return Err("READ BINARY failed"),
        };

        let parsed = der_read_element_header(&header[..]).unwrap();
        let length = parsed.1.len as usize + header.len() - parsed.0.len();

        let mut data = Vec::<u8>::with_capacity(length);
        loop {
            let current_size = data.len();
            let p1 = ((current_size >> 8) & 0xff) as u8;
            let p2 = (current_size & 0xff) as u8;
            let remaining_size = length - current_size;
            let read_size = if remaining_size < 0xff {
                remaining_size as u8
            } else {
                0xffu8
            };
            match self.transmit(make_apdu(0x00, 0xb0, (p1, p2), &[], Some(read_size))) {
                ApduRes::Ok(s) => {
                    data.extend_from_slice(&s[..]);
                    if remaining_size < 0xff {
                        return Ok(data);
                    }
                }
                _ => return Err("READ BINARY failed"),
            }
        }
    }
}
