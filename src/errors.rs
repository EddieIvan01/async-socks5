#[derive(Debug)]
pub enum Socks5Error {
    UnsupportedVersion,
    UnexpectedEOF,
    ExtraDataRead,
    UnsupportedCommand,
    UnrecognizedAddrType,
    ParseAddrError,
    IOError(std::io::Error),
}

impl std::convert::From<std::io::Error> for Socks5Error {
    fn from(err: std::io::Error) -> Self {
        Socks5Error::IOError(err)
    }
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Socks5Error::UnsupportedVersion => "Unsupported socks5 protocol version".to_string(),
            Socks5Error::UnexpectedEOF => "Unexpected EOF".to_string(),
            Socks5Error::ExtraDataRead => "Unexpected extra data".to_string(),
            Socks5Error::UnsupportedCommand => "Unsupported command".to_string(),
            Socks5Error::UnrecognizedAddrType => "Unrecognized target address type".to_string(),
            Socks5Error::ParseAddrError => "Parse address error".to_string(),
            Socks5Error::IOError(err) => err.to_string(),
        };
        write!(f, "[Err] {}", msg)?;
        Ok(())
    }
}
