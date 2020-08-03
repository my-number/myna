
/// APDU Error
#[derive(Debug)]
pub enum ApduError<T> {
    /// Error when communication to card
    Transmission(T),
    /// APDU Error code
    Command(u8, u8),
    /// Error when execution failure detected
    Execution(&'static str),
}

#[derive(Debug)]
pub enum CryptoError {
    ParseError,
    NumberError,
    NoCAError,
    VerificationError,
}
