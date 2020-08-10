use crate::error::ApduError as Error;
use crate::utils::{check_password, check_pin, make_apdu};
use alloc::vec::Vec;
use der_parser::der::der_read_element_header;

type Request = Vec<u8>;
type Response = Vec<u8>;
type BinaryData = Vec<u8>;
type Hash<'a> = &'a [u8];
type FileId<'a> = &'a [u8];

#[derive(Clone, Copy, Debug)]
pub enum KeyType {
    UserAuth,
    DigitalSign,
}

pub trait Apdu {
    /// (Required) Error type that transmit() returns when failed to read card
    type TransErr;
    /// (Required) Implement card communication here.
    fn transmit(&self, data: Request) -> Result<Response, Self::TransErr>;

    /// Transmit request and transform and error check the response
    fn transmit_checked(&self, data: Request) -> Result<Response, Error<Self::TransErr>> {
        match self.transmit(data) {
            Ok(apdu) => {
                let len = apdu.len();
                if len < 2 {
                    return Err(Error::Fatal("No response"));
                }
                let sw1 = apdu[len - 2]; // overflow
                let sw2 = apdu[len - 1];
                if (sw1 == 0x90 || sw1 == 0x91) && sw2 == 0x00 {
                    return Ok(apdu[0..(len - 2)].to_vec());
                }
                return Err(Error::Command(sw1, sw2));
            }
            Err(e) => Err(Error::Transmission(e)),
        }
    }
    /// SELECT DF
    fn select_df(&self, dfid: FileId) -> Result<(), Error<Self::TransErr>> {
        match self.transmit_checked(make_apdu(0x00, 0xa4, (0x04, 0x0c), dfid, None)) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.check_err("Failed to SELECT DF")),
        }
    }
    /// SELECT EF
    /// 
    /// Call it with DF selected
    fn select_ef(&self, efid: FileId) -> Result<(), Error<Self::TransErr>> {
        match self.transmit_checked(make_apdu(0x00, 0xa4, (0x02, 0x0c), efid, None)) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.check_err("Failed to SELECT EF")),
        }
    }

    /// GET CHALLENGE
    fn get_challenge(&self, size: u8) -> Result<Response, Error<Self::TransErr>> {
        match self.transmit_checked(make_apdu(0x00, 0x84, (0, 0), &[], Some(size))) {
            Ok(s) => Ok(s),
            Err(e) => Err(e.check_err("GET CHALLENGE failed")),
        }
    }

    /// VERIFY PIN
    /// 
    /// Call it with PIN EF selected
    fn verify_pin(&self, pin: &str, key_type: KeyType) -> Result<(), Error<Self::TransErr>> {
        match key_type {
            KeyType::UserAuth => {
                if !check_pin(pin) {
                    return Err(Error::Execution("PIN is invalid"));
                }
            }
            KeyType::DigitalSign => {
                if !check_password(pin) {
                    return Err(Error::Execution("PIN is invalid"));
                }
            }
        };

        match self.transmit_checked(make_apdu(0x00, 0x20, (0x00, 0x80), pin.as_bytes(), None)) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.pin_err()),
        }
    }

    /// VERIFY PIN without PIN
    ///
    /// check PIN retry counter
    fn lookup_pin(&self) -> Result<u8, Error<Self::TransErr>> {
        if let Err(e) = self.transmit_checked(make_apdu(0x00, 0x20, (0x00, 0x80), &[], None)) {
            if let Error::PinIncorrect(remaining) = e.pin_err() {
                return Ok(remaining);
            }
        }
        return Err(Error::Fatal("Unexpected Error"));
    }

    /// COMPUTE DIGITAL SIGNATURE
    ///
    /// Call it with Private Key EF selected
    fn compute_digital_signature(&self, hash_pkcs1: Hash) -> Result<Response, Error<Self::TransErr>> {
        match self.transmit_checked(make_apdu(
            0x80,
            0x2a,
            (0x00, 0x80),
            &hash_pkcs1[..],
            Some(0),
        )) {
            // zero, the value of Le probably means 256. it overflowed.
            Ok(sig) => Ok(sig),
            Err(e) => Err(e.check_err("COMPUTE DIGITAL SIGNATURE failed")),
        }
    }
    /// READ BINARY
    ///
    /// Call it with readable object selected
    fn read_binary(&self, length: usize) -> Result<BinaryData, Error<Self::TransErr>> {
        let mut data: Vec<u8> = Vec::with_capacity(length);
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
            match self.transmit_checked(make_apdu(0x00, 0xb0, (p1, p2), &[], Some(read_size))) {
                Ok(s) => {
                    data.extend_from_slice(&s[..]);
                    if remaining_size < 0xff {
                        return Ok(data);
                    }
                }
                Err(e) => return Err(e.check_err("READ BINARY failed")),
            }
        }
    }
    
    /// Read binary as X.509 Certificate
    fn read_cert(&self) -> Result<BinaryData, Error<Self::TransErr>> {
        let header = self.read_binary(8)?;

        let parsed = der_read_element_header(&header[..])
            .map_err(|_| Error::Execution("Failed to parse Certificate header"))?;
        let length = parsed.1.len as usize + header.len() - parsed.0.len();

        return self.read_binary(length);
    }

    /// Selects JPKI AP DF
    fn select_jpki_ap(&self) -> Result<(), Error<Self::TransErr>> {
        self.select_df(b"\xD3\x92\xf0\x00\x26\x01\x00\x00\x00\x01")
    }
    
    /// Selects JPKI Token EF
    fn select_jpki_token(&self) -> Result<(), Error<Self::TransErr>> {
        self.select_ef(b"\x00\x06")
    }

    /// Selects JPKI Certificate EF
    fn select_jpki_cert(&self, key_type: KeyType) -> Result<(), Error<Self::TransErr>> {
        match key_type {
            KeyType::UserAuth => self.select_ef(b"\x00\x0a"),
            KeyType::DigitalSign => self.select_ef(b"\x00\x01"),
        }
    }

    /// Selects JPKI PIN EF
    fn select_jpki_pin(&self, key_type: KeyType) -> Result<(), Error<Self::TransErr>> {
        match key_type {
            KeyType::UserAuth => self.select_ef(b"\x00\x18"),
            KeyType::DigitalSign => self.select_ef(b"\x00\x1B"),
        }
    }

    /// Selects JPKI Private Key EF
    fn select_jpki_key(&self, key_type: KeyType) -> Result<(), Error<Self::TransErr>> {
        match key_type {
            KeyType::UserAuth => self.select_ef(b"\x00\x17"),
            _ => unimplemented!(),
        }
    }

    /// Checks if it is mynumber card
    fn is_mynumber_card(&self) -> Result<bool, Error<Self::TransErr>> {
        self.select_jpki_ap()?;
        self.select_jpki_token()?;
        let jpki_token = self.read_binary(32)?;
        Ok(&jpki_token[..] == b"JPKIAPICCTOKEN2                 ")
    }

    /// Gets Certificate
    fn get_cert(&self, key_type: KeyType) -> Result<BinaryData, Error<Self::TransErr>> {
        self.select_jpki_ap()?;
        self.select_jpki_key(key_type)?;
        self.select_jpki_cert(key_type)?;

        let cert = self.read_cert()?;
        Ok(cert)
    }

    /// Computes signature
    fn compute_sig(&self, pin: &str, hash: Hash, key_type: KeyType) -> Result<Response, Error<Self::TransErr>> {
        self.select_jpki_ap()?;
        self.select_jpki_pin(key_type)?;
        self.verify_pin(pin, key_type)?;
        self.select_jpki_key(key_type)?;
        let sig = self.compute_digital_signature(hash)?;
        Ok(sig)
    }

    /// Gets PIN retry counter
    fn get_retry_counter(&self, key_type: KeyType) -> Result<u8, Error<Self::TransErr>> {
        self.select_jpki_ap()?;
        self.select_jpki_pin(key_type)?;
        let count = self.lookup_pin()?;
        Ok(count)
    }
}
