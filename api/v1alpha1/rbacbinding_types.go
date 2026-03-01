package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RBACBindingSpec defines the desired state of an RBACBinding.
//
// RBACBinding is the emergency intervention — a low-level, direct subject-to-role
// binding for situations that cannot be expressed through the AccessPolicy model.
//
// Common use cases:
//   - Break-glass cluster-admin access during an incident
//   - One-time access grants for auditors or contractors
//   - Legacy bindings being migrated to AccessPolicies
//
// Unlike AccessPolicy, RBACBinding does not support Teams, tag matching, or
// namespace selectors. It maps directly to a single RoleBinding or ClusterRoleBinding.
//
// All RBACBindings should have an expiresAt set. The admission webhook warns
// (and can be configured to reject) RBACBindings without an expiry.
//
// Therapy note: This is the emergency intervention. It should be temporary.
// If you're creating a lot of these, your RBAC needs therapy.
type RBACBindingSpec struct {
	// Rationale is a mandatory justification for this binding.
	// Since RBACBindings are typically exceptional, the rationale should reference
	// the specific incident, ticket, or approval that authorized this access.
	//
	// Example:
	//   rationale: "Break-glass access for incident INC-2024-0042. Approved by: @sre-lead"
	//
	// +kubebuilder:validation:MinLength=10
	Rationale string `json:"rationale"`

	// Subjects lists who receives this binding.
	// Supports User, Group, and ServiceAccount kinds.
	//
	// +kubebuilder:validation:MinItems=1
	Subjects []rbacv1.Subject `json:"subjects"`

	// ClusterRole is the name of the ClusterRole to bind.
	// Mutually exclusive with Role.
	//
	// +optional
	ClusterRole string `json:"clusterRole,omitempty"`

	// Role is the name of a namespaced Role to bind.
	// Requires Namespace to be set.
	// Mutually exclusive with ClusterRole.
	//
	// +optional
	Role string `json:"role,omitempty"`

	// Namespace is the namespace in which to create a RoleBinding.
	// Required when Role is set or when ClusterRole is being bound namespace-scoped.
	// Must not be set when ClusterWide is true.
	//
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// ClusterWide creates a ClusterRoleBinding instead of a namespace-scoped RoleBinding.
	// When true, Namespace must not be set.
	//
	// +kubebuilder:default=false
	// +optional
	ClusterWide bool `json:"clusterWide,omitempty"`

	// ExpiresAt is the hard expiry for this binding.
	// After this time, the operator will delete the managed binding and set
	// Expired=True on this resource.
	//
	// Strongly recommended for all RBACBindings. The admission webhook will warn
	// if this is not set.
	//
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
}

// RBACBindingStatus defines the observed state of an RBACBinding.
type RBACBindingStatus struct {
	// Conditions represent the latest reconciliation state.
	//
	// Condition types:
	//   - Ready:   True when the binding is reconciled successfully.
	//   - Expired: True when spec.expiresAt has passed.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ManagedBinding is the single RoleBinding or ClusterRoleBinding created
	// by this RBACBinding.
	//
	// +optional
	ManagedBinding *ManagedBinding `json:"managedBinding,omitempty"`

	// ObservedGeneration is the .metadata.generation last reconciled.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=rb,categories=rbac-therapist
// +kubebuilder:printcolumn:name="Role",type="string",JSONPath=".spec.clusterRole",description="ClusterRole being bound"
// +kubebuilder:printcolumn:name="ClusterWide",type="boolean",JSONPath=".spec.clusterWide"
// +kubebuilder:printcolumn:name="Expires",type="date",JSONPath=".spec.expiresAt"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// RBACBinding is the emergency intervention — a direct, low-level subject-to-role
// binding for exceptional cases not covered by AccessPolicy.
//
// Every RBACBinding should have an expiresAt and a specific rationale.
// If you find yourself creating many RBACBindings, migrate them to AccessPolicies.
//
// Therapy note: This is the crisis intervention. Stabilize, then do the real work.
type RBACBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec RBACBindingSpec `json:"spec"`

	// +optional
	Status RBACBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RBACBindingList contains a list of RBACBinding.
type RBACBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RBACBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RBACBinding{}, &RBACBindingList{})
}
