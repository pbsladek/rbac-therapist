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

// TeamValidator validates Team resources.
//
// Validation rules:
//   - spec.extends must not create circular references
//   - warn if spec.members is empty (a team with no members is valid but unusual)
//   - warn if a referenced team in spec.extends does not exist yet (forward reference allowed)
//
// +kubebuilder:webhook:path=/validate-rbac-therapist-io-v1alpha1-team,mutating=false,failurePolicy=fail,sideEffects=None,groups=rbac.therapist.io,resources=teams,verbs=create;update,versions=v1alpha1,name=vteam.kb.io,admissionReviewVersions=v1
type TeamValidator struct {
	Client client.Client
}

func (v *TeamValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	v.Client = mgr.GetClient()
	return ctrl.NewWebhookManagedBy(mgr).
		For(&therapistv1alpha1.Team{}).
		WithValidator(v).
		Complete()
}

// ValidateCreate validates a new Team.
func (v *TeamValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	team, ok := obj.(*therapistv1alpha1.Team)
	if !ok {
		return nil, fmt.Errorf("expected Team, got %T", obj)
	}
	return v.validate(ctx, team)
}

// ValidateUpdate validates an updated Team.
func (v *TeamValidator) ValidateUpdate(ctx context.Context, _ runtime.Object, newObj runtime.Object) (admission.Warnings, error) {
	team, ok := newObj.(*therapistv1alpha1.Team)
	if !ok {
		return nil, fmt.Errorf("expected Team, got %T", newObj)
	}
	return v.validate(ctx, team)
}

// ValidateDelete is a no-op — deletion is always allowed.
func (v *TeamValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (v *TeamValidator) validate(ctx context.Context, team *therapistv1alpha1.Team) (admission.Warnings, error) {
	var warnings admission.Warnings

	// Warn on empty members — valid but unusual.
	if len(team.Spec.Members) == 0 && len(team.Spec.Extends) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"team %q has no members and no extends — it will have no effective members", team.Name))
	}

	// Validate extends — detect circular references.
	if len(team.Spec.Extends) > 0 {
		if err := v.validateExtendsNoCycle(ctx, team); err != nil {
			return nil, err
		}
	}

	// Warn for each extends reference that does not yet exist (forward ref is allowed).
	for _, ext := range team.Spec.Extends {
		var referenced therapistv1alpha1.Team
		if err := v.Client.Get(ctx, client.ObjectKey{Name: ext.Name}, &referenced); err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"spec.extends references team %q which does not exist yet — this is allowed but may cause incomplete membership until it is created", ext.Name))
		}
	}

	return warnings, nil
}

// validateExtendsNoCycle checks that spec.extends does not create a cycle.
// Uses DFS with a visited set seeded with the current team name.
func (v *TeamValidator) validateExtendsNoCycle(ctx context.Context, root *therapistv1alpha1.Team) error {
	visited := map[string]bool{root.Name: true}

	var visit func(name string) error
	visit = func(name string) error {
		if visited[name] {
			return fmt.Errorf("spec.extends creates a circular reference at %q", name)
		}
		visited[name] = true
		defer func() { delete(visited, name) }()

		var t therapistv1alpha1.Team
		if err := v.Client.Get(ctx, client.ObjectKey{Name: name}, &t); err != nil {
			// Team doesn't exist yet — forward reference allowed.
			return nil
		}
		for _, ext := range t.Spec.Extends {
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

// TeamDefaulter sets default values on Team resources.
//
// +kubebuilder:webhook:path=/mutate-rbac-therapist-io-v1alpha1-team,mutating=true,failurePolicy=fail,sideEffects=None,groups=rbac.therapist.io,resources=teams,verbs=create;update,versions=v1alpha1,name=mteam.kb.io,admissionReviewVersions=v1
type TeamDefaulter struct{}

func (d *TeamDefaulter) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&therapistv1alpha1.Team{}).
		WithDefaulter(d).
		Complete()
}

func (d *TeamDefaulter) Default(_ context.Context, obj runtime.Object) error {
	_, ok := obj.(*therapistv1alpha1.Team)
	if !ok {
		return fmt.Errorf("expected Team, got %T", obj)
	}
	// No defaulting needed for Team — all fields have sensible zero values.
	return nil
}
