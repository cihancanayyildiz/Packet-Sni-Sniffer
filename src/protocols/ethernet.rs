use std::array::TryFromSliceError;
pub type Mac = [u8; 6];

#[derive(Debug)]
pub enum EthernetType {
    Ipv4,
    Ipv6,
    Arp,
    Other(u16),
}

#[derive(Debug)]
pub struct EthernetFrame{
    pub src_mac: Mac,
    pub dst_mac: Mac,
    pub ether_type: EthernetType,
}

impl From<u16> for EthernetType {
    fn from(ether_type: u16) -> Self {
        match ether_type {
            0x0800 => Self::Ipv4,           
            0x86DD => Self::Ipv6, 
            0x0806 => Self::Arp,            
            other => Self::Other(other),
        }
    }
}

pub fn parse_ethernet_layer(input: &[u8]) -> Result<(&[u8], EthernetFrame), TryFromSliceError> {
    let dst_mac = Mac::try_from(&input[0..6])?;
    let src_mac = Mac::try_from(&input[6..12])?;
    let ether_type_bytes = <[u8; 2]>::try_from(&input[12..14])?;
    let ether_type: EthernetType = EthernetType::from(u16::from_be_bytes(ether_type_bytes));

    let (_, input) = input.split_at(14);

    let frame = EthernetFrame {
        src_mac,
        dst_mac,
        ether_type
    };
    Ok((input, frame))
}

