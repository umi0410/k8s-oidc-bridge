# Getting started

> **Prerequisites:** [cert-manager](https://cert-manager.io/) (for the webhook TLS certificate) and
> an upstream OIDC provider you control (Authentik, Keycloak, …).

## 1. Install the chart

```sh
helm install k8s-oidc-bridge ./charts/k8s-oidc-bridge \
  --namespace k8s-oidc-bridge --create-namespace \
  --set 'rbac.serviceAccountNames={my-app}'
```

`rbac.serviceAccountNames` is the allowlist of ServiceAccounts the controller may mint tokens for
(`serviceaccounts/token` is a cluster-takeover primitive — keep it scoped).

## 2. Declare the upstream provider

Providers are configured as chart values (or a ConfigMap). Secrets are referenced ArgoCD-style as
`$<secret>:<key>`:

```yaml
providers:
  config:
    authentik: |
      type: client-assertion
      tokenEndpoint: https://sso.example/application/o/token/
      clientId: my-rp
      scope: "openid my-rp"
      tokenField: id_token
```

### Exchange drivers

Pick the driver (`type`) that matches how your SSO issues tokens:

| driver | grant | use |
|---|---|---|
| `rfc8693` | OAuth 2.0 Token Exchange | Keycloak / Authentik, general |
| `oidc-jwt-bearer` | `urn:…:grant-type:jwt-bearer` | OIDC JWT-bearer providers |
| `client-assertion` | `client_credentials` + `client_assertion` | SSO that accepts the SA-JWT as a client assertion (e.g. Authentik M2M) |
| `aws-web-identity` | `AssumeRoleWithWebIdentity` | outputs AWS credentials (delivery differs) |

## 3. Opt the namespace in, then bind a ServiceAccount

```sh
kubectl label namespace my-apps bridge.oidc.io/inject=enabled
```

```yaml
apiVersion: bridge.oidc.io/v1alpha1
kind: TokenBinding
metadata:
  name: my-app
  namespace: my-apps
spec:
  serviceAccountName: my-app          # resolved by SA — no pod annotation needed
  providerRef: authentik
  audience: https://sso.example/application/o/token/
  projection:
    tokenFilePath: /var/run/secrets/rp/token
    env:
      - name: AWS_WEB_IDENTITY_TOKEN_FILE
        valueFromTokenFile: true
```

Any pod in `my-apps` running as `my-app` now starts with a renewing, SSO-issued web-identity token.
To exclude a single pod, label it `bridge.oidc.io/inject: "false"`.

## Verify

```sh
kubectl get tokenbindings -n my-apps          # Provider / SA / NextRenew columns
kubectl -n my-apps get pod -l app=my-app -o yaml | grep -A3 bridge.oidc.io   # injected label + volume/env
```

The delivered token file is re-read lazily by the consumer on its own expiry; the controller renews
the source token at 50 % of its TTL (exponential backoff with jitter, last-good token kept on
transient failure).

## How delivery works (IRSA-compatible)

The projection presets IRSA-shaped env (`AWS_WEB_IDENTITY_TOKEN_FILE` / `OIDC_TOKEN_FILE`), so
existing AWS/S3 SDKs work with no credential code. For apps that also use real AWS IRSA, give the
AIStor / relying-party consumer its own env names and token path via `projection.env` so the two coexist.

> **Claim-based relying parties (e.g. MinIO/AIStor):** do **not** send a `RoleArn` on
> `AssumeRoleWithWebIdentity` — see [ADR 0003](./adr/0003-claim-based-sts-no-rolearn.md).

More end-to-end recipes: [`examples/`](../examples).

## Roadmap

- **Scale** — back the webhook with a `TokenBinding` informer cache, so pod admission no longer does
  an API list on the pod-creation critical path.
- **Adoption** — identity-provider setup recipes (Authentik, Keycloak): docs + Terraform.
- **Breadth** — `rfc8693` multiple audiences / resources (one token accepted by several relying parties).
- **Packaging** — multi-arch images + a published Helm chart.

**Non-goals (by design).** Not an identity provider (it never signs tokens or decides claim values),
not a secrets manager (Vault), not a full workload-identity platform (SPIRE), not a policy engine.
