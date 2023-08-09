#[derive(Debug, PartialEq)]
pub enum ProtocolError {
    WrongProtocol,
    ParsingError,
    UnknownProtocol,
}