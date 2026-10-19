//! `TokenBinding` CRD YAML generator. Used to update the Helm chart's `crds/`.
//!
//! Usage: `cargo run -p oidc-bridge-common --bin crdgen > charts/k8s-oidc-bridge/crds/tokenbindings.yaml`

use kube::CustomResourceExt;
use oidc_bridge_common::crd::TokenBinding;

fn main() {
    let crd = TokenBinding::crd();
    print!("{}", serde_yaml::to_string(&crd).expect("serialize CRD"));
}
