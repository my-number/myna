/// APDU Error
#[derive(Debug)]
pub enum ApduError<T> {
    /// Error when communication to card
    Transmission(T),
    /// APDU Error code
    Command(u8, u8),
    /// Error when execution failure detected
    Execution(&'static str),
    /// Fatal error that seems not to be able to recover
    Fatal(&'static str),
    /// PIN Incorrect Error with remaining retries
    PinIncorrect(u8)
}
impl<T> ApduError<T> {
    pub fn check_err(self, err_msg: &'static str) -> Self {
        match self {
            Self::Command(_, _) => Self::Execution(err_msg),
            _ => self,
        }
    }
    pub fn pin_err(self) -> Self {
        if let Self::Command(sw1, sw2) = self {
            if sw1 == 0x63 && (sw2 & 0xF0 ==  0xC0) {
                return Self::PinIncorrect(sw2 & 0x0F);
            }
        }
        return self;
    }
}
#[derive(Debug)]
pub enum CryptoError {
    ParseError,
    NumberError,
    NoCAError,
    VerificationError,
}
