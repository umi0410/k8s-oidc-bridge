//! k8s-oidc-bridge mutating admission webhook entrypoint.
//!
//! TLS certificates are read from files mounted by cert-manager (spec §4.8).

mod metrics;
mod mutate;
mod server;

use std::net::SocketAddr;

use anyhow::Context as _;
use axum_server::tls_rustls::RustlsConfig;
use kube::Client;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::server::{router, AppState};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls backend is ring-only. Install the process-level CryptoProvider
    // explicitly before any TLS use (webhook server + kube client); being explicit is safer.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install default rustls CryptoProvider (ring)");

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let metrics_addr: SocketAddr = env_or("METRICS_ADDR", "0.0.0.0:9090")
        .parse()
        .context("invalid METRICS_ADDR")?;
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(metrics_addr)
        .install()
        .context("failed to install prometheus exporter")?;
    metrics::describe();
    info!(%metrics_addr, "metrics listener started");

    let client = Client::try_default()
        .await
        .context("failed to build kube client")?;
    let app = router(AppState { client });

    let cert = env_or("TLS_CERT_FILE", "/etc/webhook/tls/tls.crt");
    let key = env_or("TLS_KEY_FILE", "/etc/webhook/tls/tls.key");
    let tls = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .with_context(|| format!("failed to load TLS material from {cert}/{key}"))?;

    let addr: SocketAddr = env_or("WEBHOOK_ADDR", "0.0.0.0:8443")
        .parse()
        .context("invalid WEBHOOK_ADDR")?;
    info!(%addr, "admission webhook listening (https)");

    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await
        .context("webhook server error")?;
    Ok(())
}
