use std::array::TryFromSliceError;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub enum IpType{
    ICMP,
    TCP,
    UDP,
    Other(u8)
}

#[derive(Debug)]
pub struct Ipv4{
    pub version: u8,
    pub header_length: u8,
    pub dsf: u8,
    pub length: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol_type: IpType,
    pub header_checksum: u16,
    pub src_addr: Ipv4Addr,
    pub dest_addr: Ipv4Addr,
}

impl From<u8> for IpType {
    fn from(type_byte: u8) -> Self {
        match type_byte {
            1 => IpType::ICMP,
            6 => IpType::TCP,
            17 => IpType::UDP,
            other => IpType::Other(other)
        }
    }
}

pub fn parse_ipv4(payload: &[u8]) -> Result<(&[u8], Ipv4), TryFromSliceError> {
    let version_byte = <u8>::try_from(payload[0])?;
    let version = version_byte >> 4; // 4 bit right shift to get version
    let header_length = version_byte & 15; // we need right 4 bits so we need to and(&) version_byte with 15(00001111)
    let dsf = <u8>::try_from(payload[1])?;
    let length = u16::from_be_bytes(<[u8;2]>::try_from(&payload[2..4])?); // concatenating two u8
    let id = u16::from_be_bytes(<[u8;2]>::try_from(&payload[4..6])?); // concatenating two u8
    let flag_bytes =  u16::from_be_bytes(<[u8; 2]>::try_from(&payload[6..8])?);
    let flags = (flag_bytes >> 13) as u8;
    let fragment_offset = flag_bytes & 8191;
    let time_to_live = <u8>::try_from(payload[8])?;
    let protocol_type = IpType::from(<u8>::try_from(payload[9])?);
    let header_checksum =  u16::from_be_bytes(<[u8; 2]>::try_from(&payload[10..12])?);
    let src_addr = Ipv4Addr::from(<[u8; 4]>::try_from(&payload[12..16])?);
    let dest_addr = Ipv4Addr::from(<[u8; 4]>::try_from(&payload[16..20])?);

    let (_, payload) = if header_length > 5 {
        payload.split_at(20 + ((header_length - 5) * 4) as usize)
    } else {
        payload.split_at(20)
    };

    let ipv4_data = Ipv4{
        version,
        header_length,
        dsf,
        length,
        id,
        flags,
        fragment_offset,
        time_to_live,
        protocol_type,
        header_checksum,
        src_addr,
        dest_addr,
    };

    Ok((payload, ipv4_data))
}



