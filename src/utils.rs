use alloc::vec::Vec;
/// Returns constructed APDU vector.
pub fn make_apdu(cla: u8, ins: u8, param: (u8, u8), data: &[u8], maxsize: Option<u8>) -> Vec<u8> {
    let mut packet_size = 5;
    let data_size = data.len();
    if data_size == 0 {
        packet_size += 0;
    } else if data_size <= 0xff {
        packet_size += 1 + data_size;
    } else if data_size <= 0xffff {
        packet_size += 3 + data_size;
    } else {
        // Packet larger than 0xffff is very rare, explicitly abnormal
        panic!("Data size is too large");
    }
    let mut buf: Vec<u8> = Vec::with_capacity(packet_size);
    buf.push(cla);
    buf.push(ins);
    buf.push(param.0);
    buf.push(param.1);

    if data_size == 0 {
    } else if data_size <= 0xff {
        buf.push(data_size as u8);
    } else if data_size <= 0xffff {
        buf.push(0);
        buf.push(data_size as u8 >> 4);
        buf.push(data_size as u8 & 0xff);
    }
    buf.extend_from_slice(data);
    if let Some(max) = maxsize {
        buf.push(max);
    }
    buf
}

const fn is_digit(ch: u8) -> bool {
    ('0' as u8 <= ch) & (ch <= '9' as u8)
}

/// PIN ^[0-9]{4}$ validation
pub fn check_pin(pin_str: &str) -> bool {
    let pin = pin_str.as_bytes();
    pin.len() == 4
        && is_digit(pin[0])
        && is_digit(pin[1])
        && is_digit(pin[2])
        && is_digit(pin[3])
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate hex_literal;
    use hex_literal::hex;
    #[test]
    fn it_makes_apdu() {
        assert_eq!(
            make_apdu(0x00, 0x0a, (0x0b, 0x00), &[1, 2, 3, 4, 5], Some(0)),
            hex!("000a0b0005010203040500")
        );
    }
    #[test]
    fn it_makes_apdu_without_le() {
        assert_eq!(
            make_apdu(0x00, 0x0a, (0x0b, 0x00), &[1, 2, 3, 4, 5], None),
            hex!("000a0b00050102030405")
        );
    }
    #[test]
    fn it_checks_valid_pin() {
        assert_eq!(
            check_pin("1919"),
            true
        );
    }
    #[test]
    fn it_checks_non_digit_pin() {
        assert_eq!(
            check_pin("pien"),
            false
        );
    }
    #[test]
    fn it_checks_digit_non_digit_pin() {
        assert_eq!(
            check_pin("pa0n"),
            false
        );
    }
    #[test]
    fn it_checks_too_long_pin() {
        assert_eq!(
            check_pin("114514"),
            false
        );
    }
}
