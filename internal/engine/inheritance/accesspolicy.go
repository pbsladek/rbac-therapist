package inheritance

import (
	"fmt"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
)

const (
	// DefaultMaxPolicyExtendsDepth bounds recursive extends traversal.
	DefaultMaxPolicyExtendsDepth = 16
)

// AccessPolicyResolver resolves effective role sets for AccessPolicies,
// using memoization to avoid repeated expansion work in a reconcile cycle.
type AccessPolicyResolver struct {
	byName   map[string]therapistv1alpha1.AccessPolicy
	maxDepth int
	cache    map[string][]therapistv1alpha1.PolicyRole
}

func NewAccessPolicyResolver(policies []therapistv1alpha1.AccessPolicy, maxDepth int) *AccessPolicyResolver {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxPolicyExtendsDepth
	}
	byName := make(map[string]therapistv1alpha1.AccessPolicy, len(policies))
	for _, p := range policies {
		byName[p.Name] = p
	}
	return &AccessPolicyResolver{
		byName:   byName,
		maxDepth: maxDepth,
		cache:    make(map[string][]therapistv1alpha1.PolicyRole, len(policies)),
	}
}

// ResolveEffectivePolicy returns a policy copy with resolved effective roles
// (inherited parent roles first, then local roles).
func (r *AccessPolicyResolver) ResolveEffectivePolicy(policy therapistv1alpha1.AccessPolicy) (therapistv1alpha1.AccessPolicy, error) {
	roles, err := r.ResolveRoles(policy.Name)
	if err != nil {
		return therapistv1alpha1.AccessPolicy{}, err
	}
	effective := *policy.DeepCopy()
	effective.Spec.Roles = roles
	return effective, nil
}

// ResolveRoles returns effective roles for the named policy.
func (r *AccessPolicyResolver) ResolveRoles(policyName string) ([]therapistv1alpha1.PolicyRole, error) {
	return r.resolve(policyName, map[string]bool{}, 0)
}

func (r *AccessPolicyResolver) resolve(
	policyName string,
	visiting map[string]bool,
	depth int,
) ([]therapistv1alpha1.PolicyRole, error) {
	if roles, ok := r.cache[policyName]; ok {
		return roles, nil
	}
	if depth > r.maxDepth {
		return nil, fmt.Errorf("accesspolicy extends depth exceeded max depth %d while resolving %q", r.maxDepth, policyName)
	}
	if visiting[policyName] {
		return nil, fmt.Errorf("accesspolicy %q has a circular extends reference", policyName)
	}
	policy, ok := r.byName[policyName]
	if !ok {
		return nil, fmt.Errorf("accesspolicy %q not found while resolving extends", policyName)
	}

	visiting[policyName] = true
	defer delete(visiting, policyName)

	roles := make([]therapistv1alpha1.PolicyRole, 0, len(policy.Spec.Roles))
	for _, parentRef := range policy.Spec.Extends {
		parentRoles, err := r.resolve(parentRef.Name, visiting, depth+1)
		if err != nil {
			return nil, err
		}
		roles = append(roles, parentRoles...)
	}
	roles = append(roles, policy.Spec.Roles...)
	r.cache[policyName] = roles
	return roles, nil
}
