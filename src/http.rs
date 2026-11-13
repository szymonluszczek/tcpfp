use axum::{Router, routing::get};
use hyper::body::Incoming;
use hyper::{Method, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tower::{Service, ServiceExt};
use tower_http::cors::{Any, CorsLayer};

use crate::endpoints;
use crate::proxy_protocol::client_addr;

fn create_router() -> Router {
    Router::new()
        .route("/fingerprint", get(endpoints::inspect::get_fingerprint))
        .route("/details", get(endpoints::inspect::get_details))
        .route("/index", get(endpoints::database::get_index))
        .route("/lookup", get(endpoints::database::get_lookup))
        .route("/metrics", get(endpoints::metrics::get_metrics))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST]),
        )
}

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .map(|value| value.to_lowercase() == "true")
        .unwrap_or(false)
}

pub async fn serve_api(port: u16) {
    let app = create_router();

    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    let use_proxy_protocol = env_flag("TCPFP_PROXY_PROTOCOL");

    let bind = std::env::var("TCPFP_BIND").unwrap_or_else(|_| "0.0.0.0".to_string());
    let listener = TcpListener::bind(format!("{bind}:{port}")).await.unwrap();
    println!("http listening on: {}", listener.local_addr().unwrap());

    loop {
        let Ok((mut socket, remote_addr)) = listener.accept().await else {
            continue;
        };

        let mut make_service = make_service.clone();

        tokio::spawn(async move {
            let Some(addr) = client_addr(&mut socket, remote_addr, use_proxy_protocol).await else {
                return;
            };

            let tower_service = unwrap_infallible(make_service.call(addr).await);
            let socket = TokioIo::new(socket);

            let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
                tower_service.clone().oneshot(request)
            });

            if let Err(err) = server::conn::auto::Builder::new(TokioExecutor::new())
                .http1()
                .keep_alive(false)
                .serve_connection(socket, hyper_service)
                .await
            {
                eprintln!("failed to serve connection: {err:#}");
            }
        });
    }
}

fn build_tls_config(cert: &[u8], key: &[u8]) -> anyhow::Result<Arc<ServerConfig>> {
    // every cert in the file, leaf first, so clients get the intermediates too
    let chain = CertificateDer::pem_slice_iter(cert).collect::<Result<Vec<_>, _>>()?;
    if chain.is_empty() {
        anyhow::bail!("no certificate in TCPFP_CERT");
    }

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, PrivateKeyDer::from_pem_slice(key)?)?;

    Ok(Arc::new(config))
}

struct CachedCert {
    cert_mod: Option<SystemTime>,
    key_mod: Option<SystemTime>,
    config: Arc<ServerConfig>,
}

struct CertReloader {
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    cached: Mutex<Option<CachedCert>>,
}

impl CertReloader {
    fn new() -> Self {
        Self {
            cert_path: std::env::var("TCPFP_CERT").ok().map(PathBuf::from),
            key_path: std::env::var("TCPFP_KEY").ok().map(PathBuf::from),
            cached: Mutex::new(None),
        }
    }

    fn reload(&self) -> anyhow::Result<Arc<ServerConfig>> {
        let (Some(cert_path), Some(key_path)) = (&self.cert_path, &self.key_path) else {
            anyhow::bail!("TCPFP_CERT and TCPFP_KEY must be set");
        };

        let cert_mod = std::fs::metadata(cert_path)?.modified()?;
        let key_mod = std::fs::metadata(key_path)?.modified()?;

        {
            let cached = self.cached.lock().unwrap();

            if let Some(cached) = cached.as_ref()
                && cached.cert_mod == Some(cert_mod)
                && cached.key_mod == Some(key_mod)
            {
                return Ok(cached.config.clone());
            }
        }

        let cert = std::fs::read(cert_path)?;
        let key = std::fs::read(key_path)?;
        let config = build_tls_config(&cert, &key)?;

        let mut cached = self.cached.lock().unwrap();
        *cached = Some(CachedCert {
            cert_mod: Some(cert_mod),
            key_mod: Some(key_mod),
            config: config.clone(),
        });

        Ok(config)
    }

    fn current(&self) -> Arc<ServerConfig> {
        match self.reload() {
            Ok(config) => config,
            Err(err) => {
                eprintln!("failed to reload tls certificate: {err:#}");

                if let Some(cached) = self.cached.lock().unwrap().as_ref() {
                    return cached.config.clone();
                }

                panic!("no usable tls certificate: {err:#}")
            }
        }
    }
}

pub async fn serve_api_tls(port: u16) {
    let app = create_router();

    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();

    let reloader = CertReloader::new();
    reloader.reload().expect("failed to load tls config");

    let use_proxy_protocol = env_flag("TCPFP_PROXY_PROTOCOL");

    let bind = std::env::var("TCPFP_BIND").unwrap_or_else(|_| "0.0.0.0".to_string());
    let listener = TcpListener::bind(format!("{bind}:{port}")).await.unwrap();

    println!("https listening on: {port} (proxy protocol: {use_proxy_protocol})");

    loop {
        let Ok((mut socket, remote_addr)) = listener.accept().await else {
            continue;
        };

        let acceptor = TlsAcceptor::from(reloader.current());
        let mut make_service = make_service.clone();

        tokio::spawn(async move {
            let Some(addr) = client_addr(&mut socket, remote_addr, use_proxy_protocol).await else {
                return;
            };

            let Ok(stream) = acceptor.accept(socket).await else {
                return;
            };

            let tower_service = unwrap_infallible(make_service.call(addr).await);

            let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
                tower_service.clone().oneshot(request)
            });

            if let Err(err) = server::conn::auto::Builder::new(TokioExecutor::new())
                .http1()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), hyper_service)
                .await
            {
                eprintln!("failed to serve connection: {err:#}");
            }
        });
    }
}

fn unwrap_infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => match err {},
    }
}
