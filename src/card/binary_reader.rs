use super::make_apdu;
use der_parser::der::der_read_element_header;

pub struct BinaryReader {
    pub data: Vec<u8>,
    pub length: usize,
}
impl BinaryReader {
    fn get_length(header: &[u8]) -> usize {
        let parsed = der_read_element_header(header).unwrap();
        parsed.1.len as usize + header.len() - parsed.0.len()
    }
    pub fn from_header(header: &[u8]) -> BinaryReader {
        let length = BinaryReader::get_length(header);
        BinaryReader::fixed_size(length)
    }
    pub fn fixed_size(length: usize) -> BinaryReader {
        BinaryReader {
            data: Vec::with_capacity(length),
            length,
        }
    }

    pub fn get_apdu(&self) -> Option<Vec<u8>> {
        let len = self.data.len();
        let p1 = len >> 8 & 0x7f;
        let p2 = len & 0xff;
        if self.length <= len {
            return None;
        }
        let le = if self.length - len > 0xff {
            0xff
        } else {
            self.length - len
        };
        Some(make_apdu(0x00, 0xb0, (p1 as u8, p2 as u8), &[], le as u8))
    }
    pub fn set_chunk(&mut self, chunk: &[u8]) -> i32 {
        self.data.extend_from_slice(&chunk[..]);
        (self.length - self.data.len()) as i32
    }
    pub fn finalize(&self) -> &[u8] {
        &self.data[..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vector;
    #[test]
    fn it_parses_partial_der() {
        assert_eq!(
            BinaryReader::get_length(&test_vector::CERT_DER[0..8]),
            1573 as usize
        );
    }
}
