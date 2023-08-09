use std::array::TryFromSliceError;

#[derive(Debug)]
pub struct UdpData {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

pub fn parse_udp(payload: &[u8]) -> Result<(&[u8], UdpData), TryFromSliceError> {
    let src_port = u16::from_be_bytes(<[u8;2]>::try_from(&payload[..2])?);
    let dst_port = u16::from_be_bytes(<[u8;2]>::try_from(&payload[2..4])?);
    let length = u16::from_be_bytes(<[u8;2]>::try_from(&payload[4..6])?);
    let checksum = u16::from_be_bytes(<[u8;2]>::try_from(&payload[6..8])?);

    let data = UdpData {src_port, dst_port, length, checksum};

   /*  let (_, payload) = payload.split_at(8);

    println!("udp: payload : {:?}", payload); */

    Ok((payload, data))
}