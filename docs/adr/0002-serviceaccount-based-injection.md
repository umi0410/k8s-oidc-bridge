# 0002. ServiceAccount-based injection contract

- **Status:** Accepted
- **Date:** 2026-10-19

## Context

The webhook must decide which pods to inject and which `TokenBinding` applies. An earlier design
required each pod to carry a `bridge.oidc.io/token-binding` annotation plus an opt-in label, which
pushed per-pod wiring onto every workload author and was easy to get wrong.

## Decision

Resolve the binding from the pod's `serviceAccountName`:

- **Namespace opt-in:** the webhook only sees pods in namespaces labeled
  `bridge.oidc.io/inject=enabled` (`namespaceSelector`).
- **Resolution by SA:** for an admitted pod, the webhook finds the `TokenBinding` in that namespace
  whose `spec.serviceAccountName` matches the pod's SA. Zero matches → skip; more than one → ambiguous,
  skip (a configuration error).
- **Per-pod opt-out:** a pod labeled `bridge.oidc.io/inject=false` is excluded
  (`objectSelector` `NotIn`, which still matches unlabeled pods).
- **Controller handoff:** on injection the webhook stamps a marker label
  (`bridge.oidc.io/injected=true`) and the resolved binding name as an annotation
  (`bridge.oidc.io/binding`). The controller watches/lists by the label and maps pods to bindings by
  the annotation. The binding name lives in an annotation, not the label value, to avoid the 63-char
  label-value limit.

## Consequences

- Workload authors only run on the bound SA; no per-pod annotation is required.
- The contract spans `crates/webhook` and `crates/controller` — changing one side (label/annotation
  keys, selector semantics) requires updating the other and the chart's webhook selectors together.
- `failurePolicy: Fail` means that if the webhook is down, pod creation in an opt-in namespace is
  blocked; HA (2 replicas + PDB) is therefore a prerequisite. Non-opt-in namespaces are unaffected.
