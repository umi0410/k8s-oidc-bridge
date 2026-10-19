# Examples

End-to-end snippets for binding a workload's ServiceAccount to an upstream provider.
They assume k8s-oidc-bridge is already installed (see the root [README](../README.md)).

| File | Relying party | Driver | Shows |
|---|---|---|---|
| [`minio-aistor.yaml`](./minio-aistor.yaml) | MinIO / AIStor (S3 + STS) | `client-assertion` | claim-based S3 with no RoleArn, IRSA-style env |
| [`keycloak-rfc8693.yaml`](./keycloak-rfc8693.yaml) | any OAuth2 RP | `rfc8693` | standard token exchange |

## The contract these examples rely on

1. **Opt the namespace in** — label it `bridge.oidc.io/inject=enabled`. Only then does the
   webhook see its pods.
2. **Create a `TokenBinding`** whose `spec.serviceAccountName` names your app's SA. The webhook
   resolves the binding by that SA — **no per-pod annotation**.
3. **Run a pod on that SA.** It's injected automatically. To exclude one pod, label it
   `bridge.oidc.io/inject: "false"`.

The `provider` block in each file is shown as Helm values; apply it via
`helm upgrade --reuse-values -f provider.yaml …` or fold it into your install values. The provider
lives in the **bridge's** install namespace (ConfigMap `oidc-bridge-providers` + Secret
`oidc-bridge-secret`); the `TokenBinding` and workload live in **your app's** namespace.
