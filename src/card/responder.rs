use super::make_apdu;

#[derive(Debug)]
pub struct ApduRes<'a> {
    data: &'a [u8],
    sw1: u8,
    sw2: u8,
}
impl ApduRes {
    pub fn is_success(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }
}

type TransFunc = fn(&[u8]) -> ApduRes;
pub struct Responder {
    transfunc: TransFunc,
}

type Result<T> = Result<T, ()>;

impl Responder {
    pub fn new(transfunc: TransFunc) -> Self {
        Self { transfunc }
    },
    pub fn select_df(&self, dfid: &[u8]) -> Result<()> {
        let req = make_apdu(0x00, 0xa4, (0x04, 0x0c), dfid, None);
        let res = self.transfunc(req);
        if res.is_success() {
            Ok(())
        }else{
            Err(())
        }
    }

    pub fn select_ef(&self, efid: &[u8]) -> Result<()> {
        let req = make_apdu(0x00, 0xa4, (0x02, 0x0c), efid, None);
        let res = self.transfunc(req);
        if res.is_success() {
            Ok(())
        }else{
            Err(())
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
    pub fn get_challenge(&self, size: u8) -> Result<&[u8]> {
        let res = self.transfunc(make_apdu(0x00, 0x84, (0, 0), &[], Some(size)));
        if res.is_success() {
            Ok(res.data)
        }else{
            Err(())
        }
    }
}
// エラーハンドリングをmatchを使ってカッコつけたいです。それではおやすみ
// あとResponderって名前なんとかなりませんか
