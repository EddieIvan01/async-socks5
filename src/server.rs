use crate::errors::Socks5Error;
use async_std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    prelude::*,
    task,
};
use futures::stream::StreamExt;

const SOCKS_VERSION: u8 = 0x5;
const NO_AUTH: u8 = 0x0;
const RSV: u8 = 0x0;
const CMD_CONNECT: u8 = 0x1;
const TYP_IPV4: u8 = 0x1;
const TYP_DOMAIN: u8 = 0x3;
const TYP_IPV6: u8 = 0x4;
const RESP_SUCCESS: u8 = 0x0;

async fn socks5_handshake(mut stream: &TcpStream) -> Result<Vec<SocketAddr>, Socks5Error> {
    let mut buf = [0u8; 0xff];

    stream.read_exact(&mut buf[..2]).await?;
    if buf[0] != SOCKS_VERSION {
        return Err(Socks5Error::UnsupportedVersion);
    }

    let nmethod = buf[1] as usize;
    stream.read_exact(&mut buf[..nmethod]).await?;

    stream.write_all(&[SOCKS_VERSION, NO_AUTH]).await?;

    stream.read_exact(&mut buf[..4]).await?;
    if buf[0] != SOCKS_VERSION {
        return Err(Socks5Error::UnsupportedVersion);
    }
    if buf[1] != CMD_CONNECT {
        return Err(Socks5Error::UnsupportedCommand);
    }

    let host: Vec<IpAddr>;
    match buf[3] {
        TYP_IPV4 => {
            stream.read_exact(&mut buf[..4]).await?;
            if let Ok(bs) = crate::ioutil::try_into_wrapper::<&[u8], [u8; 4]>(&buf[..4]) {
                host = vec![IpAddr::V4(Ipv4Addr::from(bs))];
            } else {
                return Err(Socks5Error::ParseAddrError);
            }
        }

        TYP_DOMAIN => {
            stream.read_exact(&mut buf[..1]).await?;
            let domain_len = buf[0] as usize;

            stream.read_exact(&mut buf[..domain_len]).await?;
            if let Ok(tmp_host) = String::from_utf8(buf[..domain_len].to_vec()) {
                host = dns_lookup::lookup_host(&tmp_host)?;
            } else {
                return Err(Socks5Error::ParseAddrError);
            }
        }

        TYP_IPV6 => {
            stream.read_exact(&mut buf[..16]).await?;
            if let Ok(bs) = crate::ioutil::try_into_wrapper::<&[u8], [u8; 16]>(&buf[..16]) {
                host = vec![IpAddr::V6(Ipv6Addr::from(bs))];
            } else {
                return Err(Socks5Error::ParseAddrError);
            }
        }
        _ => return Err(Socks5Error::UnrecognizedAddrType),
    };

    stream.read_exact(&mut buf[..2]).await?;

    // Transmute [u8; _] to SocketAddr manually,
    // to avoid `<str as async_std::net::ToSocketAddrs>::to_socket_addrs`'s shitty logic
    Ok(host
        .into_iter()
        .map(|h| SocketAddr::new(h, unsafe { *(buf.as_ptr() as *const u16) }.to_be()))
        .collect())
}

async fn socks5_forward(
    mut local: TcpStream,
    target: Vec<SocketAddr>,
) -> Result<(), std::io::Error> {
    let mut remote = TcpStream::connect(target.as_slice()).await?;

    match remote.peer_addr() {
        Ok(SocketAddr::V4(ipv4)) => {
            let buf = [
                SOCKS_VERSION,
                RESP_SUCCESS,
                RSV,
                TYP_IPV4,
                0x0,
                0x0,
                0x0,
                0x0,
                0x0,
                0x0,
            ];

            unsafe {
                *(buf.as_ptr().offset(4) as *mut u32) = u32::from(*ipv4.ip()).to_be();
                *(buf.as_ptr().offset(8) as *mut u16) = ipv4.port().to_be();
            };
            local.write_all(&buf).await?;
        }

        Ok(SocketAddr::V6(ipv6)) => {
            let mut buf = [0u8; 22];
            buf[0] = SOCKS_VERSION;
            buf[1] = RESP_SUCCESS;
            buf[2] = RSV;
            buf[3] = TYP_IPV6;

            unsafe {
                *(buf.as_ptr().offset(4) as *mut u128) = u128::from(*ipv6.ip()).to_be();
                *(buf.as_ptr().offset(20) as *mut u16) = ipv6.port().to_be();
            };
            local.write_all(&buf).await?;
        }
        _ => (),
    };

    let mut local_clone = local.clone();
    let mut remote_clone = remote.clone();

    task::spawn(async move {
        let _ = io::copy(&mut remote_clone, &mut local_clone).await;
        let _ = local_clone.shutdown(Shutdown::Both);
        let _ = remote_clone.shutdown(Shutdown::Both);
    });

    io::copy(&mut local, &mut remote).await?;
    local.shutdown(Shutdown::Both)?;
    remote.shutdown(Shutdown::Both)?;

    Ok(())
}

pub async fn start_socks5_server(
    addr: &String,
    max_connections: usize,
) -> Result<(), std::io::Error> {
    TcpListener::bind(addr)
        .await?
        .incoming()
        .for_each_concurrent(max_connections, |stream| async move {
            if let Ok(stream) = stream {
                match socks5_handshake(&stream).await {
                    Ok(target) => {
                        let _ = socks5_forward(stream, target).await;
                    }
                    Err(_) => (),
                };
            };
        })
        .await;

    Ok(())
}
