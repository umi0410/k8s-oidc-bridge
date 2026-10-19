//! k8s-oidc-bridge controller (renew-worker) entrypoint.

mod error;
mod exchange;
mod jwt;
mod leader;
mod metrics;
mod providers;
mod reconcile;
mod secret;
mod token;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use kube::runtime::events::{Recorder, Reporter};
use kube::Client;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::reconcile::Context;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // The rustls backend is ring-only. Explicitly install the process-level CryptoProvider
    // before TLS is first used (e.g. the kube client); being explicit is safer.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install default rustls CryptoProvider (ring)");

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Prometheus exporter (spec §4.9).
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

    let provider_namespace = env_or("PROVIDER_NAMESPACE", "oidc-bridge");
    let holder_id = env_or("POD_NAME", &format!("oidc-bridge-{}", std::process::id()));

    let reporter = Reporter {
        controller: "oidc-bridge-controller".to_string(),
        instance: Some(holder_id.clone()),
    };
    let ctx = Arc::new(Context {
        client: client.clone(),
        http: reqwest::Client::builder()
            .build()
            .context("failed to build http client")?,
        provider_namespace: provider_namespace.clone(),
        configmap_name: env_or("PROVIDER_CONFIGMAP", providers::DEFAULT_CONFIGMAP),
        secret_name: env_or("PROVIDER_SECRET", providers::DEFAULT_SECRET),
        recorder: Recorder::new(client.clone(), reporter),
    });

    let lease_namespace = env_or("LEASE_NAMESPACE", &provider_namespace);
    leader::run(ctx, lease_namespace, holder_id).await
}
