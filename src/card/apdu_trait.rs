use super::make_apdu;
pub enum Error<T> {
    Transmission(T),
    Command(u8, u8),
    Execution(&'static str),
}

type Request = Vec<u8>;
type Response = Vec<u8>;
type BinaryData = Vec<u8>;
type Hash<'a> = &'a [u8];
type FileId<'a> = &'a [u8];

pub trait Apdu {
    type TransErr;
    fn raw_transmit(&self, data: Request) -> Result<Response, Self::TransErr>;

    fn transmit(&self, data: Request) -> Result<Response, Error<Self::TransErr>> {
        match self.raw_transmit(data) {
            Ok(apdu) => {
                let len = apdu.len();
                let sw1 = apdu[len - 2];
                let sw2 = apdu[len - 1];
                if (sw1 == 0x90 || sw1 == 0x91) && sw2 == 0x00 {
                    return Ok(apdu[0..(len - 2)].to_vec());
                }
                return Err(Error::Command(sw1, sw2));
            }
            Err(e) => Err(Error::Transmission(e)),
        }
    }
    fn select_df(&self, dfid: FileId) -> Result<(), Error<Self::TransErr>> {
        match self.transmit(make_apdu(0x00, 0xa4, (0x04, 0x0c), dfid, None)) {
            Ok(_) => Ok(()),
            _ => Err(Error::Execution("Failed to SELECT DF")),
        }
    }
    fn select_ef(&self, efid: FileId) -> Result<(), Error<Self::TransErr>> {
        match self.transmit(make_apdu(0x00, 0xa4, (0x02, 0x0c), efid, None)) {
            Ok(_) => Ok(()),
            _ => Err(Error::Execution("Failed to SELECT EF")),
        }
    }
    fn select_jpki_ap(&self) -> Result<(), Error<Self::TransErr>> {
        self.select_df(b"\xD3\x92\xf0\x00\x26\x01\x00\x00\x00\x01")
    }
    fn select_jpki_token(&self) -> Result<(), Error<Self::TransErr>> {
        self.select_ef(b"\x00\x06")
    }
    fn select_jpki_cert_auth(&self) -> Result<(), Error<Self::TransErr>> {
        self.select_ef(b"\x00\x0a")
    }

    fn select_jpki_auth_pin(&self) -> Result<(), Error<Self::TransErr>> {
        self.select_ef(b"\x00\x18")
    }
    fn select_jpki_auth_key(&self) -> Result<(), Error<Self::TransErr>> {
        self.select_ef(b"\x00\x17")
    }
    fn get_challenge(&self, size: u8) -> Result<Response, Error<Self::TransErr>> {
        match self.transmit(make_apdu(0x00, 0x84, (0, 0), &[], Some(size))) {
            Ok(s) => Ok(s),
            _ => Err(Error::Execution("GET CHALLENGE failed")),
        }
    }
    fn verify_pin(&self, pin: [u8; 4]) -> Result<(), Error<Self::TransErr>> {
        // do we need PIN ^[0-9]{4}$ validation here?
        match self.transmit(make_apdu(0x00, 0x20, (0x00, 0x80), &pin[..], None)) {
            Ok(_) => Ok(()),
            _ => Err(Error::Execution("VERIFY PIN failed")),
        }
    }
    fn compute_sig(&self, hash_pkcs1: Hash) -> Result<Response, Error<Self::TransErr>> {
        match self.transmit(make_apdu(
            0x80,
            0x2a,
            (0x00, 0x80),
            &hash_pkcs1[..],
            Some(0),
        )) {
            // zero, the value of Le probably means 256. it overflowed.
            Ok(sig) => Ok(sig),
            _ => Err(Error::Execution("COMPUTE DIGITAL SIGNATURE failed")),
        }
    }

    fn read_binary(&self) -> Result<BinaryData, Error<Self::TransErr>> {
        let mut data: Vec<u8> = Vec::new();
        loop {
            let current_size = data.len();
            let p1 = ((current_size >> 8) & 0xff) as u8;
            let p2 = (current_size & 0xff) as u8;
            let read_size: u8 = 0xffu8;
            match self.transmit(make_apdu(0x00, 0xb0, (p1, p2), &[], Some(read_size))) {
                Ok(s) => {
                    data.extend_from_slice(&s[..]);
                    if s.len() < read_size as usize {
                        return Ok(data);
                    }
                }
                _ => return Err(Error::Execution("READ BINARY failed")),
            }
        }
    }
}
