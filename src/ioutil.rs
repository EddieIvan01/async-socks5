use crate::errors::Socks5Error;
use async_std::io::ReadExt;
use std::convert::TryInto;

pub(crate) fn try_into_wrapper<F, T>(from: F) -> Result<T, <F as TryInto<T>>::Error>
where
    F: TryInto<T>,
{
    from.try_into()
}

pub(crate) async fn _read_n_bytes(
    mut stream: impl Unpin + ReadExt,
    buf: &mut [u8],
    count: usize,
) -> Result<usize, Socks5Error> {
    if count <= 0 {
        return Ok(0);
    }

    let mut nr = 0;
    while nr < count {
        let n = stream.read(&mut buf[nr..]).await?;
        if n == 0 {
            break;
        } else {
            nr += n;
        }
    }

    if nr == count {
        Ok(nr)
    } else if nr > count {
        Err(Socks5Error::ExtraDataRead)
    } else {
        Err(Socks5Error::UnexpectedEOF)
    }
}
