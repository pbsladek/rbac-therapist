// Package webhooks contains admission webhooks for rbac-therapist CRDs.
package webhooks

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
)

// RBACBindingValidator validates RBACBinding resources.
//
// Validation rules:
//   - spec.rationale must be at least 10 characters
//   - spec.subjects must not be empty
//   - exactly one of clusterRole or role must be set
//   - namespace required when role is set or when not clusterWide
//   - namespace must be empty when clusterWide is true
//   - expiresAt must be in the future if set
//   - warn if expiresAt is not set (strongly recommended)
//   - warn if expiresAt is more than 30 days in the future (break-glass should be short-lived)
//
// +kubebuilder:webhook:path=/validate-rbac-therapist-io-v1alpha1-rbacbinding,mutating=false,failurePolicy=fail,sideEffects=None,groups=rbac.therapist.io,resources=rbacbindings,verbs=create;update,versions=v1alpha1,name=vrbacbinding.kb.io,admissionReviewVersions=v1
type RBACBindingValidator struct{}

func (v *RBACBindingValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&therapistv1alpha1.RBACBinding{}).
		WithValidator(v).
		Complete()
}

// ValidateCreate validates a new RBACBinding.
func (v *RBACBindingValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	binding, ok := obj.(*therapistv1alpha1.RBACBinding)
	if !ok {
		return nil, fmt.Errorf("expected RBACBinding, got %T", obj)
	}
	return v.validate(binding)
}

// ValidateUpdate validates an updated RBACBinding.
func (v *RBACBindingValidator) ValidateUpdate(_ context.Context, _ runtime.Object, newObj runtime.Object) (admission.Warnings, error) {
	binding, ok := newObj.(*therapistv1alpha1.RBACBinding)
	if !ok {
		return nil, fmt.Errorf("expected RBACBinding, got %T", newObj)
	}
	return v.validate(binding)
}

// ValidateDelete is a no-op — deletion is always allowed.
func (v *RBACBindingValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (v *RBACBindingValidator) validate(binding *therapistv1alpha1.RBACBinding) (admission.Warnings, error) {
	var warnings admission.Warnings

	// Rationale must be substantive.
	if len(binding.Spec.Rationale) < 10 {
		return nil, fmt.Errorf("spec.rationale must be at least 10 characters — document the incident or ticket that authorized this access")
	}

	// Subjects required.
	if len(binding.Spec.Subjects) == 0 {
		return nil, fmt.Errorf("spec.subjects must have at least one entry")
	}

	// Exactly one of clusterRole or role must be set.
	if binding.Spec.ClusterRole == "" && binding.Spec.Role == "" {
		return nil, fmt.Errorf("either spec.clusterRole or spec.role must be set")
	}
	if binding.Spec.ClusterRole != "" && binding.Spec.Role != "" {
		return nil, fmt.Errorf("spec.clusterRole and spec.role are mutually exclusive")
	}

	// Namespace / clusterWide consistency.
	if binding.Spec.ClusterWide && binding.Spec.Namespace != "" {
		return nil, fmt.Errorf("spec.namespace must not be set when spec.clusterWide is true")
	}
	if !binding.Spec.ClusterWide && binding.Spec.Namespace == "" {
		return nil, fmt.Errorf("spec.namespace is required when spec.clusterWide is false")
	}
	if binding.Spec.Role != "" && binding.Spec.Namespace == "" {
		return nil, fmt.Errorf("spec.namespace is required when spec.role is set")
	}

	// ExpiresAt validations.
	if binding.Spec.ExpiresAt == nil {
		warnings = append(warnings, "spec.expiresAt is not set — RBACBindings are emergency interventions and should always have an expiry")
	} else {
		now := time.Now()
		if !binding.Spec.ExpiresAt.After(now) {
			return nil, fmt.Errorf("spec.expiresAt must be in the future")
		}
		// Warn if expiry is more than 30 days out — break-glass should be short-lived.
		if binding.Spec.ExpiresAt.After(now.Add(30 * 24 * time.Hour)) {
			warnings = append(warnings, fmt.Sprintf(
				"spec.expiresAt is more than 30 days in the future (%s) — RBACBindings are emergency interventions and should be short-lived",
				binding.Spec.ExpiresAt.Format(time.RFC3339)))
		}
	}

	return warnings, nil
}

// RBACBindingDefaulter sets default values on RBACBinding resources.
//
// +kubebuilder:webhook:path=/mutate-rbac-therapist-io-v1alpha1-rbacbinding,mutating=true,failurePolicy=fail,sideEffects=None,groups=rbac.therapist.io,resources=rbacbindings,verbs=create;update,versions=v1alpha1,name=mrbacbinding.kb.io,admissionReviewVersions=v1
type RBACBindingDefaulter struct{}

func (d *RBACBindingDefaulter) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&therapistv1alpha1.RBACBinding{}).
		WithDefaulter(d).
		Complete()
}

func (d *RBACBindingDefaulter) Default(_ context.Context, obj runtime.Object) error {
	_, ok := obj.(*therapistv1alpha1.RBACBinding)
	if !ok {
		return fmt.Errorf("expected RBACBinding, got %T", obj)
	}
	// clusterWide defaults to false via kubebuilder marker.
	return nil
}
