mod errors;
mod ioutil;
mod server;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let default_addr = &"0.0.0.0:1080".to_string();
    let bind_addr = args.get(1).unwrap_or(default_addr);

    futures::executor::block_on(server::start_socks5_server(bind_addr, 0)).unwrap();
}
