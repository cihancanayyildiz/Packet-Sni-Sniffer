use super::errors::ProtocolError;
use serde::Serialize;
use tls_parser::{
    parse_tls_extension, TlsClientHelloContents, TlsExtension, TlsMessage, TlsMessageHandshake,
    TlsServerHelloContents, TlsVersion, TlsMessageApplicationData,
};

#[derive(Debug, PartialEq, Serialize)]
pub enum TLS {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ClientHello {
    pub version: Option<&'static str>,
    pub hostname: Option<String>,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ServerHello {
    pub version: Option<&'static str>,
    pub cipher: Option<&'static str>,
}

impl ClientHello {
    pub fn new(ch: &TlsClientHelloContents, hostname: Option<String>) -> ClientHello {
        ClientHello {
            version: tls_version(ch.version),
            hostname,
        }
    }
}

impl ServerHello {
    pub fn new(sh: &TlsServerHelloContents) -> ServerHello {
        let cipher = sh.cipher.get_ciphersuite().map(|cs| cs.name);
        ServerHello {
            version: tls_version(sh.version),
            cipher,
        }
    }
}

fn tls_version(ver: TlsVersion) -> Option<&'static str> {
    match ver {
        TlsVersion::Ssl30 => Some("ssl3.0"),
        TlsVersion::Tls10 => Some("tls1.0"),
        TlsVersion::Tls11 => Some("tls1.1"),
        TlsVersion::Tls12 => Some("tls1.2"),
        TlsVersion::Tls13 => Some("tls1.3"),
        _ => None,
    }
}

pub fn parse_tls(remaining: &[u8]) -> Result<TLS, ProtocolError> {
    if let Ok((_remaining, tls)) = tls_parser::parse_tls_plaintext(remaining) {
        for msg in tls.msg {
            match msg {
                TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
                    let mut hostname = None;

                    if let Some(mut remaining) = ch.ext {
                        while let Ok((remaining2, ext)) = parse_tls_extension(remaining) {
                            remaining = remaining2;
                            if let TlsExtension::SNI(sni) = ext {
                                for s in sni {
                                    let name = std::str::from_utf8(s.1)
                                        .map_err(|_| ProtocolError::ParsingError)?;
                                    hostname = Some(name.to_owned());
                                }
                            }
                        }

                        return Ok(TLS::ClientHello(ClientHello::new(&ch, hostname)));
                    }
                },
                TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                    return Ok(TLS::ServerHello(ServerHello::new(&sh)));
                },
                _ => (),
            }
        }
        Err(ProtocolError::ParsingError)
    }
    else {
        Err(ProtocolError::WrongProtocol)
    }
}
