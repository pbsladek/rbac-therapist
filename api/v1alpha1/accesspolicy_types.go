package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AccessPolicySpec defines the desired state of an AccessPolicy.
//
// An AccessPolicy is the prescription: it declares which subjects (via Teams or
// inline) should receive which Kubernetes RBAC roles in which namespaces.
//
// The operator reconciles each AccessPolicy into native Kubernetes RoleBindings
// and ClusterRoleBindings, named deterministically and owned by the policy.
// Stale bindings are pruned automatically.
//
// AccessPolicies are the primary resource in rbac-therapist. Everything else
// supports them.
type AccessPolicySpec struct {
	// Rationale is a mandatory human-readable justification for why this access
	// policy exists. It is the most important field.
	//
	// This text is:
	//   - Surfaced verbatim in `rbact explain` output
	//   - Provided to the LLM for audit report generation
	//   - Visible in `rbact graph` node labels
	//   - Stored in the RBACSession snapshot
	//
	// Write this as if explaining to a future auditor why this access is necessary.
	// Be specific. Reference ticket numbers, architectural decisions, or team charters.
	//
	// Example:
	//   rationale: >
	//     Platform engineers require admin access to production platform namespaces
	//     to deploy infrastructure components and respond to incidents.
	//     Approved in RFC-0042. Reviewed quarterly.
	//
	// +kubebuilder:validation:MinLength=10
	Rationale string `json:"rationale"`

	// Subjects lists who receives the access defined in this policy.
	// Each entry is either a reference to a Team CRD or an inline Kubernetes subject.
	//
	// TeamRef is preferred — it is auditable, composable, and tag-aware.
	// Inline subjects are an escape hatch for service accounts or one-off users
	// that do not warrant their own Team.
	//
	// At least one subject is required.
	//
	// +kubebuilder:validation:MinItems=1
	Subjects []PolicySubject `json:"subjects"`

	// Roles defines the access grants: what roles are bound, and where.
	// Each entry binds a ClusterRole (or Role) to a set of namespaces, or cluster-wide.
	//
	// At least one role entry is required.
	//
	// +kubebuilder:validation:MinItems=1
	Roles []PolicyRole `json:"roles"`

	// ManagedClusterRoles are optional ClusterRoles that this AccessPolicy owns
	// and reconciles before binding evaluation.
	//
	// Use this to keep custom RBAC role definitions and policy grants together
	// in a single declarative resource.
	//
	// +optional
	ManagedClusterRoles []ManagedClusterRoleSpec `json:"managedClusterRoles,omitempty"`

	// ManagedRoles are optional namespaced Roles that this AccessPolicy owns
	// and reconciles before binding evaluation.
	//
	// +optional
	ManagedRoles []ManagedRoleSpec `json:"managedRoles,omitempty"`

	// Extends lists parent AccessPolicies whose role grants are inherited by this policy.
	// Inheritance is additive — subjects of this policy receive roles from both
	// this policy and all ancestor policies.
	//
	// Circular references are rejected by the admission webhook.
	//
	// Use this for layered access patterns:
	//   extends:
	//     - name: base-read-policy
	//
	// +optional
	Extends []PolicyReference `json:"extends,omitempty"`

	// Paused suspends reconciliation of this AccessPolicy.
	// When true, the operator will not create, update, or delete any bindings
	// for this policy. Existing bindings are left in place.
	//
	// Use this to temporarily suspend access without deleting the policy.
	// Analogous to ArgoCD's spec.suspend.
	//
	// +kubebuilder:default=false
	// +optional
	Paused bool `json:"paused,omitempty"`

	// ExpiresAt is an optional hard expiry for this policy.
	// After this time, the operator will delete all managed bindings and set
	// a Expired=True condition on the policy.
	//
	// Ideal for temporary access grants, break-glass scenarios, or
	// time-boxed contractor access.
	//
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
}

// PolicySubject is a subject entry in an AccessPolicy.
// Exactly one of TeamRef or Inline must be set.
type PolicySubject struct {
	// TeamRef references a Team CRD by name.
	// The operator resolves the team's effective members at reconcile time.
	// This is the preferred way to specify subjects.
	//
	// +optional
	TeamRef *TeamReference `json:"teamRef,omitempty"`

	// Inline is a direct Kubernetes RBAC subject (User, Group, or ServiceAccount).
	// Use this for subjects that do not have a Team, such as a specific service account
	// in a third-party namespace.
	//
	// +optional
	Inline *rbacv1.Subject `json:"inline,omitempty"`
}

// PolicyRole defines a single role grant within an AccessPolicy.
// Exactly one of ClusterRole or Role must be set.
// If ClusterWide is false (default), Namespaces must be specified.
type PolicyRole struct {
	// ClusterRole is the name of the ClusterRole to bind.
	// This is the most common case — binding a ClusterRole as either a
	// namespace-scoped RoleBinding (default) or a cluster-wide ClusterRoleBinding.
	//
	// Mutually exclusive with Role.
	//
	// +optional
	ClusterRole string `json:"clusterRole,omitempty"`

	// Role is the name of a namespaced Role to bind.
	// The Role must exist in each target namespace at reconcile time.
	// If the Role does not exist in a namespace, the RoleBinding is skipped
	// and a warning condition is set.
	//
	// Mutually exclusive with ClusterRole.
	//
	// +optional
	Role string `json:"role,omitempty"`

	// ClusterWide creates a ClusterRoleBinding instead of per-namespace RoleBindings.
	// When true, Namespaces must not be set.
	//
	// Use this for cluster-scoped resources (nodes, PVs, CRDs, etc.)
	//
	// +kubebuilder:default=false
	// +optional
	ClusterWide bool `json:"clusterWide,omitempty"`

	// Namespaces defines where this role is bound.
	// Required when ClusterWide is false.
	//
	// +optional
	Namespaces *NamespaceSelector `json:"namespaces,omitempty"`
}

// ManagedClusterRoleSpec defines a ClusterRole that should be created and
// maintained by an AccessPolicy.
type ManagedClusterRoleSpec struct {
	// Name is the ClusterRole name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Rules are the RBAC rules for this ClusterRole.
	// +kubebuilder:validation:MinItems=1
	Rules []rbacv1.PolicyRule `json:"rules"`

	// Labels are optional labels merged with operator-managed labels.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations are optional annotations for the managed ClusterRole.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ManagedRoleSpec defines a namespaced Role that should be created and
// maintained by an AccessPolicy.
type ManagedRoleSpec struct {
	// Name is the Role name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace is the namespace where the Role is managed.
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`

	// Rules are the RBAC rules for this Role.
	// +kubebuilder:validation:MinItems=1
	Rules []rbacv1.PolicyRule `json:"rules"`

	// Labels are optional labels merged with operator-managed labels.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations are optional annotations for the managed Role.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// NamespaceSelector defines which namespaces a role grant applies to.
// Multiple selection mechanisms can be combined — the result is their union.
type NamespaceSelector struct {
	// Names is a static list of namespace names.
	// Bindings are created exactly for these namespaces.
	//
	// +optional
	Names []string `json:"names,omitempty"`

	// Selector is a label selector matched against all namespaces in the cluster.
	// Bindings are created for all matching namespaces.
	// Re-evaluated on every namespace create/update event.
	//
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// MatchTeamTags enables attribute-based access control (ABAC) namespace matching.
	//
	// When true, the operator finds all namespaces whose labels are a superset
	// of the tags defined on each subject Team. This is modeled after AWS IAM
	// attribute-based access control: you tag your namespaces, you tag your teams,
	// and access flows automatically without maintaining explicit namespace lists.
	//
	// Only meaningful when the policy subject is a TeamRef (not an inline subject).
	// Ignored for inline subjects.
	//
	// Example:
	//   Team 'platform-engineers' has tags: {tier: platform, env: production}
	//   Namespace 'monitoring' has labels: {tier: platform, env: production, app: prometheus}
	//   → The team gets bound to 'monitoring' because its labels are a superset of the team tags.
	//
	// +kubebuilder:default=false
	// +optional
	MatchTeamTags bool `json:"matchTeamTags,omitempty"`
}

// PolicyReference is a reference to another AccessPolicy (used in Extends).
type PolicyReference struct {
	// Name of the AccessPolicy.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// ManagedBinding is a record of a single RoleBinding or ClusterRoleBinding
// created and owned by this AccessPolicy.
type ManagedBinding struct {
	// Name of the binding resource.
	Name string `json:"name"`

	// Namespace of the RoleBinding. Empty for ClusterRoleBindings.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Kind is either RoleBinding or ClusterRoleBinding.
	Kind string `json:"kind"`

	// RoleName is the ClusterRole or Role this binding references.
	RoleName string `json:"roleName"`
}

// AccessPolicyStatus defines the observed state of an AccessPolicy.
type AccessPolicyStatus struct {
	// Conditions represent the latest reconciliation state of the AccessPolicy.
	//
	// Condition types:
	//   - Ready:   True when all bindings are reconciled successfully.
	//   - Expired: True when spec.expiresAt is set and has passed.
	//   - Paused:  True when spec.paused is true.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ManagedBindings is the list of RoleBindings and ClusterRoleBindings
	// currently owned by this policy. Updated after each reconcile.
	//
	// +optional
	ManagedBindings []ManagedBinding `json:"managedBindings,omitempty"`

	// ObservedHash is a deterministic hash of the resolved spec (subjects + roles + namespaces).
	// Used to detect drift and skip unnecessary reconciliations.
	//
	// +optional
	ObservedHash string `json:"observedHash,omitempty"`

	// LastReconcileTime is the timestamp of the most recent successful reconciliation.
	//
	// +optional
	LastReconcileTime *metav1.Time `json:"lastReconcileTime,omitempty"`

	// ObservedGeneration is the .metadata.generation last reconciled.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=ap,categories=rbac-therapist
// +kubebuilder:printcolumn:name="Subjects",type="integer",JSONPath=".spec.subjects",description="Number of subject entries"
// +kubebuilder:printcolumn:name="Bindings",type="integer",JSONPath=".status.managedBindings",description="Number of managed bindings"
// +kubebuilder:printcolumn:name="Paused",type="boolean",JSONPath=".spec.paused"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// AccessPolicy is the prescription: a declarative binding of subjects (Teams or
// inline) to Kubernetes RBAC roles in selected namespaces.
//
// The operator reconciles each AccessPolicy into native RoleBindings and
// ClusterRoleBindings. Bindings are named deterministically, owned by the policy,
// and pruned when the policy changes or is deleted.
//
// Key features:
//   - rationale field is required — every policy must justify itself
//   - teamRef subjects enable tag-based ABAC namespace matching
//   - extends allows policy inheritance and composition
//   - expiresAt enables time-boxed access grants
//   - paused suspends reconciliation without deleting bindings
//
// Therapy note: The AccessPolicy is the treatment plan.
// The rationale is the clinical justification. The expiry is the review date.
type AccessPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec AccessPolicySpec `json:"spec"`

	// +optional
	Status AccessPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessPolicyList contains a list of AccessPolicy.
type AccessPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AccessPolicy{}, &AccessPolicyList{})
}
