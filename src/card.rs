pub fn make_apdu(cla: u8, ins: u8, param: (u8, u8), maxsize: u8, data: &[u8]) -> &[u8] {
    let mut packet_size = 5;
    let data_size = data.len();
    if data_size <= 0xff {
        packet_size += 1 + data_size;
    } else if data_size <= 0xffff {
        packet_size += 3 + data_size;
    } else {
        panic!("Data size is too large");
    }
    let mut buf: &[u8] = &[0; packet_size];
    buf[0] = cla;
    buf[1] = ins;
    buf[2] = param.0;
    buf[3] = param.1;

    if data_size <= 0xff {
        //apdu.push(data_size);
    } else if data_size <= 0xff {
        // apdu.push(0);
        //apdu.push(data_size & 0xff);
        //apdu.push(data_size | 0xff);
    }
}

pub fn select_ef() -> [u8] {}
