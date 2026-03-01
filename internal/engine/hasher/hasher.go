// Package hasher provides deterministic naming for managed RBAC bindings.
//
// Every RoleBinding and ClusterRoleBinding created by rbac-therapist is named
// using a short hash derived from the policy name, binding type, role name,
// and namespace. This ensures:
//
//   - Names are stable across reconcile cycles (idempotent)
//   - Names are unique per (policy, role, namespace) tuple
//   - Stale bindings can be identified by comparing the hash set
//   - Names are short enough to fit Kubernetes naming limits
package hasher

import (
	"crypto/sha256"
	"fmt"
)

const (
	// ManagedByLabel is set on all resources created by rbac-therapist.
	ManagedByLabel = "rbac.therapist.io/managed-by"
	// ManagedByValue is the value for ManagedByLabel.
	ManagedByValue = "rbac-therapist"

	// PolicyLabel records which AccessPolicy or RBACBinding owns a binding.
	PolicyLabel = "rbac.therapist.io/policy"
	// PolicyKindLabel records whether the owner is an AccessPolicy or RBACBinding.
	PolicyKindLabel = "rbac.therapist.io/policy-kind"
	// HashLabel records the binding's content hash for drift detection.
	HashLabel = "rbac.therapist.io/hash"
)

// BindingName returns the deterministic name for a managed RoleBinding or ClusterRoleBinding.
// Format: rbact-{policyName}-{hash[:8]}
//
// The hash is derived from: policyName + roleKind + roleName + namespace
// so that the same role bound in different namespaces gets different names.
func BindingName(policyName, roleKind, roleName, namespace string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s/%s/%s/%s", policyName, roleKind, roleName, namespace)
	return fmt.Sprintf("rbact-%s-%x", truncate(policyName, 20), h.Sum(nil)[:4])
}

// ContentHash returns a full SHA-256 hex string for change detection.
// Input is any string that fully represents the desired state.
func ContentHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return fmt.Sprintf("sha256:%x", h)
}

// truncate shortens a string to at most n characters.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ManagedLabels returns the standard label set applied to all rbac-therapist managed resources.
func ManagedLabels(policyName, policyKind, hash string) map[string]string {
	return map[string]string{
		ManagedByLabel:  ManagedByValue,
		PolicyLabel:     policyName,
		PolicyKindLabel: policyKind,
		HashLabel:       hash,
	}
}
