use super::make_apdu;
use std::future::Future;

pub enum ApduError<E> {
    CommandError(u8,u8),
    TransmissionError(E),
    ExecutionError(&'static str)
}
pub type ApduBody = Vec<u8>;

pub struct Apdu<F, E>
where
    F: Fn(&[u8]) -> Result<ApduBody, E>,
{
    /// Function that transmit APDU request & make response into ApduRes
    transfunc: F,
}

impl<F, E> Apdu<F, E>
where
    F: Fn(&[u8]) -> Result<ApduBody, E>,
{
    pub fn new(transfunc: F) -> Self {
        Self { transfunc }
    }
    pub(crate) fn transmit(&self, data: ApduBody) -> Result<ApduBody, ApduError<E>> {
        match (self.transfunc)(&data[..]) {
            Ok(apdu) => {
                let len = apdu.len();
                let sw1 = apdu[len - 2];
                let sw2 = apdu[len - 1];
                if (sw1 == 0x90 || sw1 == 0x91) && sw2 == 0x00 {
                    return Ok(apdu[0..len - 2].to_vec());
                }
                return Err(ApduError::CommandError(sw1,sw2));
            }
            Err(e) => Err(ApduError::TransmissionError(e)),
        }
    }
    pub fn select_df(&self, dfid: &[u8]) -> Result<(), ApduError<E>> {
        match self.transmit(make_apdu(0x00, 0xa4, (0x04, 0x0c), dfid, None)) {
            Ok(_) => Ok(()),
            _ => Err(ApduError::ExecutionError("Failed to SELECT DF")),
        }
    }
    pub fn select_ef(&self, efid: &[u8]) -> Result<(), ApduError<E>> {
        match self.transmit(make_apdu(0x00, 0xa4, (0x02, 0x0c), efid, None)) {
            Ok(_) => Ok(()),
            _ => Err(ApduError::ExecutionError("Failed to SELECT EF")),
        }
    }

    pub fn select_jpki_ap(&self) -> Result<(), ApduError<E>> {
        self.select_df(b"\xD3\x92\xf0\x00\x26\x01\x00\x00\x00\x01")
    }
    pub fn select_jpki_token(&self) -> Result<(), ApduError<E>> {
        self.select_ef(b"\x00\x06")
    }
    pub fn select_jpki_cert_auth(&self) -> Result<(), ApduError<E>> {
        self.select_ef(b"\x00\x0a")
    }

    pub fn select_jpki_auth_pin(&self) -> Result<(), ApduError<E>> {
        self.select_ef(b"\x00\x18")
    }
    pub fn select_jpki_auth_key(&self) -> Result<(), ApduError<E>> {
        self.select_ef(b"\x00\x17")
    }
}
