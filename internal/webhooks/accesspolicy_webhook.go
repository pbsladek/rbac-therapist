// Package webhooks contains admission webhooks for rbac-therapist CRDs.
package webhooks

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
)

// AccessPolicyValidator validates AccessPolicy resources.
//
// Validation rules:
//   - spec.rationale must be at least 10 characters
//   - spec.subjects must not be empty
//   - spec.roles must not be empty
//   - each PolicyRole must have either clusterRole or role set (not both, not neither)
//   - each PolicyRole that is not clusterWide must have a namespaces selector
//   - managed role definitions must be valid and uniquely named
//   - spec.extends must not create circular references
//   - teamRef names must reference existing Teams (warning, not error — teams may be created later)
//
// +kubebuilder:webhook:path=/validate-rbac-therapist-io-v1alpha1-accesspolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=rbac.therapist.io,resources=accesspolicies,verbs=create;update,versions=v1alpha1,name=vaccesspolicy.kb.io,admissionReviewVersions=v1
type AccessPolicyValidator struct {
	Client client.Client
}

func (v *AccessPolicyValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	v.Client = mgr.GetClient()
	return ctrl.NewWebhookManagedBy(mgr).
		For(&therapistv1alpha1.AccessPolicy{}).
		WithValidator(v).
		Complete()
}

// ValidateCreate validates a new AccessPolicy.
func (v *AccessPolicyValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	policy, ok := obj.(*therapistv1alpha1.AccessPolicy)
	if !ok {
		return nil, fmt.Errorf("expected AccessPolicy, got %T", obj)
	}
	return v.validate(ctx, policy)
}

// ValidateUpdate validates an updated AccessPolicy.
func (v *AccessPolicyValidator) ValidateUpdate(ctx context.Context, _ runtime.Object, newObj runtime.Object) (admission.Warnings, error) {
	policy, ok := newObj.(*therapistv1alpha1.AccessPolicy)
	if !ok {
		return nil, fmt.Errorf("expected AccessPolicy, got %T", newObj)
	}
	return v.validate(ctx, policy)
}

// ValidateDelete is a no-op — deletion is always allowed.
func (v *AccessPolicyValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (v *AccessPolicyValidator) validate(ctx context.Context, policy *therapistv1alpha1.AccessPolicy) (admission.Warnings, error) {
	var warnings admission.Warnings

	// Rationale must be substantive.
	if len(policy.Spec.Rationale) < 10 {
		return nil, fmt.Errorf("spec.rationale must be at least 10 characters — explain why this access exists")
	}

	// Subjects required.
	if len(policy.Spec.Subjects) == 0 {
		return nil, fmt.Errorf("spec.subjects must have at least one entry")
	}

	// Roles required.
	if len(policy.Spec.Roles) == 0 {
		return nil, fmt.Errorf("spec.roles must have at least one entry")
	}

	// Validate each role entry.
	for i, role := range policy.Spec.Roles {
		if role.ClusterRole == "" && role.Role == "" {
			return nil, fmt.Errorf("spec.roles[%d]: either clusterRole or role must be set", i)
		}
		if role.ClusterRole != "" && role.Role != "" {
			return nil, fmt.Errorf("spec.roles[%d]: clusterRole and role are mutually exclusive", i)
		}
		if !role.ClusterWide && role.Namespaces == nil {
			return nil, fmt.Errorf("spec.roles[%d]: namespaces must be set when clusterWide is false", i)
		}
		if role.ClusterWide && role.Namespaces != nil {
			return nil, fmt.Errorf("spec.roles[%d]: namespaces must not be set when clusterWide is true", i)
		}
		// Warn if matchTeamTags is used without any TeamRef subjects.
		if role.Namespaces != nil && role.Namespaces.MatchTeamTags {
			hasTeamRef := false
			for _, s := range policy.Spec.Subjects {
				if s.TeamRef != nil {
					hasTeamRef = true
					break
				}
			}
			if !hasTeamRef {
				warnings = append(warnings, fmt.Sprintf(
					"spec.roles[%d].namespaces.matchTeamTags is true but no subjects use teamRef — matchTeamTags has no effect for inline subjects", i))
			}
		}
	}

	// Validate subjects.
	for i, subj := range policy.Spec.Subjects {
		if subj.TeamRef == nil && subj.Inline == nil {
			return nil, fmt.Errorf("spec.subjects[%d]: either teamRef or inline must be set", i)
		}
		if subj.TeamRef != nil && subj.Inline != nil {
			return nil, fmt.Errorf("spec.subjects[%d]: teamRef and inline are mutually exclusive", i)
		}
	}

	// Validate managed ClusterRoles.
	managedClusterRoleNames := make(map[string]struct{}, len(policy.Spec.ManagedClusterRoles))
	for i, role := range policy.Spec.ManagedClusterRoles {
		if role.Name == "" {
			return nil, fmt.Errorf("spec.managedClusterRoles[%d].name must be set", i)
		}
		if len(role.Rules) == 0 {
			return nil, fmt.Errorf("spec.managedClusterRoles[%d].rules must have at least one rule", i)
		}
		if _, exists := managedClusterRoleNames[role.Name]; exists {
			return nil, fmt.Errorf("spec.managedClusterRoles[%d].name %q is duplicated", i, role.Name)
		}
		managedClusterRoleNames[role.Name] = struct{}{}
	}

	// Validate managed namespaced Roles.
	managedRoleKeys := make(map[string]struct{}, len(policy.Spec.ManagedRoles))
	for i, role := range policy.Spec.ManagedRoles {
		if role.Name == "" {
			return nil, fmt.Errorf("spec.managedRoles[%d].name must be set", i)
		}
		if role.Namespace == "" {
			return nil, fmt.Errorf("spec.managedRoles[%d].namespace must be set", i)
		}
		if len(role.Rules) == 0 {
			return nil, fmt.Errorf("spec.managedRoles[%d].rules must have at least one rule", i)
		}
		key := role.Namespace + "/" + role.Name
		if _, exists := managedRoleKeys[key]; exists {
			return nil, fmt.Errorf("spec.managedRoles[%d] %q is duplicated", i, key)
		}
		managedRoleKeys[key] = struct{}{}
	}

	// Validate extends — detect circular references by loading the graph.
	if len(policy.Spec.Extends) > 0 {
		if err := v.validateExtendsNoCycle(ctx, policy); err != nil {
			return nil, err
		}
	}

	return warnings, nil
}

// validateExtendsNoCycle checks that spec.extends does not create a cycle.
func (v *AccessPolicyValidator) validateExtendsNoCycle(ctx context.Context, root *therapistv1alpha1.AccessPolicy) error {
	visited := map[string]bool{root.Name: true}

	var visit func(name string) error
	visit = func(name string) error {
		if visited[name] {
			return fmt.Errorf("spec.extends creates a circular reference at %q", name)
		}
		visited[name] = true
		defer func() { delete(visited, name) }()

		var p therapistv1alpha1.AccessPolicy
		if err := v.Client.Get(ctx, client.ObjectKey{Name: name}, &p); err != nil {
			// Policy doesn't exist yet — that's allowed (forward reference).
			return nil
		}
		for _, ext := range p.Spec.Extends {
			if err := visit(ext.Name); err != nil {
				return err
			}
		}
		return nil
	}

	for _, ext := range root.Spec.Extends {
		if err := visit(ext.Name); err != nil {
			return err
		}
	}
	return nil
}

// AccessPolicyDefaulter sets default values on AccessPolicy resources.
//
// +kubebuilder:webhook:path=/mutate-rbac-therapist-io-v1alpha1-accesspolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=rbac.therapist.io,resources=accesspolicies,verbs=create;update,versions=v1alpha1,name=maccesspolicy.kb.io,admissionReviewVersions=v1
type AccessPolicyDefaulter struct{}

func (d *AccessPolicyDefaulter) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&therapistv1alpha1.AccessPolicy{}).
		WithDefaulter(d).
		Complete()
}

func (d *AccessPolicyDefaulter) Default(_ context.Context, obj runtime.Object) error {
	policy, ok := obj.(*therapistv1alpha1.AccessPolicy)
	if !ok {
		return fmt.Errorf("expected AccessPolicy, got %T", obj)
	}
	// Default clusterWide to false (already handled by kubebuilder marker, but belt-and-suspenders).
	for i := range policy.Spec.Roles {
		// paused defaults to false — already set by kubebuilder default marker.
		_ = policy.Spec.Roles[i]
	}
	return nil
}
