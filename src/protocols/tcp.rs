use pktparse::tcp;
use super::tls::{self, ClientHello};
use super::errors::ProtocolError;

#[derive(Debug, PartialEq)]
pub enum TCP{
    TLS(tls::TLS),
    Empty
}

#[derive(Debug, PartialEq)]
pub struct TCPData{
    pub tcp_type: TCP,
    pub tcp_header: tcp::TcpHeader,
}

pub fn parse_tcp(payload: &[u8]) -> Result<TCPData, ProtocolError> {
    if let Ok((remaining, tcp_header)) = tcp::parse_tcp_header(payload){
        if remaining.is_empty(){
            Ok(TCPData { tcp_type: TCP::Empty, tcp_header})
        }
        else if let Ok(tls) = tls::parse_tls(remaining){
            Ok(TCPData { tcp_type: TCP::TLS(tls), tcp_header})
        }
        else{
            Err(ProtocolError::UnknownProtocol)
        }
    }
    else {
        Err(ProtocolError::ParsingError)
    }

    
} 