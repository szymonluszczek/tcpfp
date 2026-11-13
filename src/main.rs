mod endpoints;
mod fingerprints;
mod http;
mod inference;
mod packets;
mod proxy_protocol;
mod reputation;
mod store;

use std::env;

fn env_u16(key: &str, default: u16) -> u16 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_flag(key: &str) -> bool {
    env::var(key)
        .map(|value| value.to_lowercase() == "true")
        .unwrap_or(false)
}

#[tokio::main]
async fn main() {
    let is_secure = env_flag("TCPFP_SECURE");
    let listen_port = env_u16("TCPFP_PORT", if is_secure { 443 } else { 80 });
    let capture_port = env_u16("TCPFP_CAPTURE_PORT", listen_port);

    println!(
        "tcpfp starting: listen={listen_port} capture={capture_port} secure={is_secure} proxy_protocol={}",
        env_flag("TCPFP_PROXY_PROTOCOL")
    );

    let server = async {
        if is_secure {
            http::serve_api_tls(listen_port).await
        } else {
            http::serve_api(listen_port).await
        }
    };

    tokio::select! {
        capture = packets::capture_packets(capture_port) => {
            match capture {
                Ok(Err(err)) => eprintln!("packet capture failed: {err:#}"),
                Err(err) => eprintln!("packet capture crashed: {err}"),
                Ok(Ok(())) => eprintln!("packet capture stopped"),
            }
            std::process::exit(1);
        }
        _ = server => {}
    }
}
