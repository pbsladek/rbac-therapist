# Policy Pattern Examples

These manifests are reusable examples outside the CI e2e fixture set.

They are intended as copy/paste starting points for real clusters:

- `abac-team-groups.yaml`: ABAC with team groups and tags.
- `argo-workflows-rbac.yaml`: Argo Workflows custom role model (ClusterRole + Role + AccessPolicy).
- `cert-manager-rbac.yaml`: cert-manager custom role model (issuers/certificates + namespaced secret reader).
- `managed-rbac-by-policy.yaml`: AccessPolicy-owned Role/ClusterRole lifecycle with binding grants.
- `policy-inheritance-stack.yaml`: layered AccessPolicy inheritance.
- `break-glass-temporary.yaml`: expiring RBACBinding pattern.

Apply one or more files:

```bash
kubectl apply -f examples/patterns/
```
