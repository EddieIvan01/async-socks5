use crate::errors::Socks5Error;
use async_std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
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

async fn socks5_handshake(mut stream: &mut TcpStream) -> Result<String, Socks5Error> {
    let mut buf = [0u8; 2];

    stream.read_exact(&mut buf).await?;
    if buf[0] != SOCKS_VERSION {
        return Err(Socks5Error::UnsupportedVersion);
    }

    let nmethod = buf[1] as usize;
    let mut buf = vec![0u8; nmethod];
    crate::ioutil::read_n_bytes(&mut stream, &mut buf, nmethod).await?;

    stream.write_all(&[SOCKS_VERSION, NO_AUTH]).await?;

    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;
    if buf[0] != SOCKS_VERSION {
        return Err(Socks5Error::UnsupportedVersion);
    }
    if buf[1] != CMD_CONNECT {
        return Err(Socks5Error::UnsupportedCommand);
    }

    let host: String;
    match buf[3] {
        TYP_IPV4 => {
            let mut buf = vec![0u8; 4];
            crate::ioutil::read_n_bytes(&mut stream, &mut buf, 4).await?;

            if let Ok(bs) = crate::ioutil::try_into_wrapper::<&[u8], [u8; 4]>(&buf) {
                host = Ipv4Addr::from(bs).to_string();
            } else {
                return Err(Socks5Error::ParseAddrError);
            }
        }

        TYP_DOMAIN => {
            let mut one_byte = [0u8; 1];
            stream.read_exact(&mut one_byte).await?;
            let domain_len = one_byte[0].clone() as usize;
            let mut domain = vec![0; domain_len];

            crate::ioutil::read_n_bytes(&mut stream, &mut domain, domain_len).await?;
            if let Ok(tmp_host) = String::from_utf8(domain) {
                host = tmp_host;
            } else {
                return Err(Socks5Error::ParseAddrError);
            }
        }

        TYP_IPV6 => {
            let mut buf = vec![0u8; 16];
            crate::ioutil::read_n_bytes(&mut stream, &mut buf, 16).await?;
            if let Ok(bs) = crate::ioutil::try_into_wrapper::<&[u8], [u8; 16]>(&buf) {
                host = Ipv6Addr::from(bs).to_string();
            } else {
                return Err(Socks5Error::ParseAddrError);
            }
        }
        _ => return Err(Socks5Error::UnrecognizedAddrType),
    };

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    let port = ((buf[0] as u16) << 8) + buf[1] as u16;

    Ok(host + ":" + &port.to_string())
}

async fn socks5_forward(mut local: TcpStream, target: String) -> Result<(), std::io::Error> {
    let mut remote = TcpStream::connect(target).await?;

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
            if let Ok(mut stream) = stream {
                match socks5_handshake(&mut stream).await {
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
