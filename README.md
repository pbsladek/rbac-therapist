# rbac-therapist

`rbac-therapist` is a Kubernetes operator + CLI for managing RBAC as declarative policy.

Core idea:
- Define **who** in `Team` resources.
- Define **what access** in `AccessPolicy` resources.
- Keep direct emergency access in `RBACBinding`.
- Materialize auditable **session-notes** in `RBACSession`.

The operator reconciles these CRDs into native Kubernetes:
- `RoleBinding`
- `ClusterRoleBinding`

## Status

Current API version: `rbac.therapist.io/v1alpha1`

Main implemented features:
- Team membership + team inheritance (`spec.extends`)
- AccessPolicy reconciliation to RBAC bindings
- AccessPolicy-managed custom `Role` and `ClusterRole` resources (`spec.managedRoles`, `spec.managedClusterRoles`)
- Policy role inheritance (`AccessPolicy.spec.extends`)
- Namespace targeting via:
  - static namespace lists
  - full label selectors (`matchLabels` + `matchExpressions`)
  - tag-based matching (`matchTeamTags`)
- Expiry and paused policy handling
- RBACSession session-notes snapshot for audit/explain workflows
- `rbact` CLI commands for generate/validate/diff/graph/explain/audit/who-can/snapshot/expire

## Repository Layout

```text
api/v1alpha1/                # CRD Go types
cmd/operator/                # operator entrypoint
cmd/rbact/                   # CLI entrypoint
cmd/ci-k3d-integration/      # Go-based k3d integration runner
internal/controllers/        # reconcilers
internal/engine/             # parser/tags/hasher logic
internal/webhooks/           # validating/defaulting webhooks
internal/integration/        # envtest integration tests
examples/                    # config and e2e manifests
examples/patterns/           # reusable non-e2e example manifests
config/                      # CRD/RBAC/operator manifests
hack/ci/                     # CI scripts/manifests
```

## Quickstart (Local)

### Prerequisites

- Go (as defined in `go.mod`)
- Docker
- A Kubernetes cluster (kind/k3d/minikube/etc.) or local kube context

### 1) Install dependencies

```bash
make tidy
```

### 2) Build binaries

```bash
make build
```

This creates:
- `bin/operator`
- `bin/rbact`

### 3) Install CRDs + operator permissions

```bash
kubectl apply -f config/crd/bases/
kubectl apply -f config/rbac/service_account.yaml
kubectl apply -f config/rbac/role.yaml
kubectl apply -f config/rbac/role_binding.yaml
```

### 4) Run operator locally

```bash
./bin/operator --enable-webhooks=false --leader-elect=false
```

### 5) Apply example manifests

```bash
kubectl apply -f examples/e2e/
```

For reusable, non-e2e templates:

```bash
kubectl apply -f examples/patterns/
```

Notable pattern examples:
- `examples/patterns/argo-workflows-rbac.yaml` for Argo Workflows-specific RBAC policies.
- `examples/patterns/cert-manager-rbac.yaml` for cert-manager-specific RBAC policies.
- `examples/patterns/managed-rbac-by-policy.yaml` for policy-owned role lifecycle.

Managed RBAC e2e fixture:
- `examples/e2e/60-managed-rbac.yaml` validates policy-owned Role/ClusterRole reconciliation in CI.

### 6) Query state with CLI

```bash
./bin/rbact who-can --namespace platform-monitoring
./bin/rbact graph
./bin/rbact snapshot --wait
```

## CRDs

- `Team`: identity group + tags + inheritance
- `AccessPolicy`: subject-to-role policy with namespace selection, inheritance, expiry, pause
- `RBACBinding`: direct break-glass style binding
- `RBACSession`: operator-generated session-notes snapshot for explain/audit

## `rbact` CLI

Available commands:

```text
rbact generate
rbact validate
rbact graph
rbact explain
rbact audit
rbact who-can
rbact diff
rbact snapshot
rbact expire
```

## Testing

### Unit + integration (envtest)

```bash
make test
```

### Go-based k3d integration flow

CI path uses:
- `.github/workflows/k3d-integration.yaml`
- `hack/ci/k3d_integration.sh` (thin wrapper)
- `cmd/ci-k3d-integration` (Kubernetes SDK driven assertions)

## Design Doc

See:
- `DESIGN.md`

## License

MIT. See `LICENSE`.
