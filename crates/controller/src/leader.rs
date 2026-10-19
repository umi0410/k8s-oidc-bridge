//! Leader election (spec §4.1): only 1 active replica of N reconciles.
//!
//! Acquires a coordination.k8s.io Lease via `kube-leader-election`. Once leader, it renews the
//! lease in the background and runs the controller.

use std::sync::Arc;
use std::time::Duration;

use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};
use tracing::{info, warn};

use crate::reconcile::{self, Context};

const LEASE_TTL: Duration = Duration::from_secs(15);
const RENEW_INTERVAL: Duration = Duration::from_secs(5);
const ACQUIRE_POLL: Duration = Duration::from_secs(3);

/// Wait until becoming leader, then run the controller.
pub async fn run(
    ctx: Arc<Context>,
    lease_namespace: String,
    holder_id: String,
) -> anyhow::Result<()> {
    let lock = LeaseLock::new(
        ctx.client.clone(),
        &lease_namespace,
        LeaseLockParams {
            holder_id: holder_id.clone(),
            lease_name: "oidc-bridge-controller".to_string(),
            lease_ttl: LEASE_TTL,
        },
    );

    info!(holder = %holder_id, "waiting for leadership");
    loop {
        if let LeaseLockResult::Acquired(_) = lock.try_acquire_or_renew().await? {
            break;
        }
        tokio::time::sleep(ACQUIRE_POLL).await;
    }
    info!(holder = %holder_id, "acquired leadership");

    // Background lease renewal.
    let renew_client = ctx.client.clone();
    let renew_ns = lease_namespace.clone();
    tokio::spawn(async move {
        let renew = LeaseLock::new(
            renew_client,
            &renew_ns,
            LeaseLockParams {
                holder_id,
                lease_name: "oidc-bridge-controller".to_string(),
                lease_ttl: LEASE_TTL,
            },
        );
        loop {
            tokio::time::sleep(RENEW_INTERVAL).await;
            if let Err(e) = renew.try_acquire_or_renew().await {
                warn!(error = %e, "failed to renew leader lease");
            }
        }
    });

    reconcile::run(ctx).await
}
