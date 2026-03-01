# E2E Examples

This directory contains reusable manifests for end-to-end integration validation.

The `cmd/ci-k3d-integration` runner applies these manifests directly, so examples and e2e assertions stay aligned.

## Files

- `00-namespaces.yaml`: namespaces and labels used by selector/tag matching.
- `10-teams.yaml`: playful therapy-themed teams/tags and team inheritance (`extends`).
- `20-accesspolicies.yaml`: Freud/Gottman boundary plans for static/selector/tag-based access.
- `30-rbacbindings.yaml`: direct break-glass style binding with expiry.
- `40-long-policies.yaml`: inheritance-heavy and ABAC-heavy long policy fixtures for e2e stress coverage.
- `50-argo-workflows.yaml`: custom Argo Workflows RBAC (non-default roles) with inheritance and namespaced Role usage.
- `60-managed-rbac.yaml`: AccessPolicy-managed Role/ClusterRole lifecycle fixture with binding assertions.

## Local Usage

```bash
kubectl apply -f examples/e2e/
```
