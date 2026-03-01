package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TeamSpec defines the desired state of a Team.
//
// A Team is the fundamental identity unit in rbac-therapist — it represents a
// named group of Kubernetes subjects (Users, Groups, ServiceAccounts) that share
// a common purpose, ownership, and tag set.
//
// Teams are analogous to IAM Groups in AWS: they aggregate subjects and carry
// tags that drive attribute-based access control (ABAC) when bound to AccessPolicies.
type TeamSpec struct {
	// Description is a human-readable explanation of who this team is and what
	// they are responsible for. This text is surfaced in `rbact explain` output
	// and LLM audit reports.
	//
	// Example: "Platform team responsible for cluster infrastructure and SRE functions."
	//
	// +optional
	Description string `json:"description,omitempty"`

	// Members lists the Kubernetes subjects that belong to this team.
	// Supported kinds: User, Group, ServiceAccount.
	//
	// For ServiceAccounts, both Name and Namespace are required.
	// For Users and Groups, only Name is required.
	//
	// +optional
	Members []rbacv1.Subject `json:"members,omitempty"`

	// Tags are arbitrary key-value labels attached to this team.
	// They serve two purposes:
	//
	//   1. ABAC namespace matching — when an AccessPolicy role entry sets
	//      matchTeamTags: true, the operator binds this team to all namespaces
	//      whose labels are a superset of these tags.
	//
	//   2. Audit metadata — tags appear in `rbact explain` and `rbact graph` output
	//      to make access patterns self-documenting.
	//
	// Modeled after AWS IAM attribute-based access control (ABAC).
	// See: https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction_attribute-based-access-control.html
	//
	// Example:
	//   tags:
	//     env: production
	//     tier: platform
	//     costCenter: cc-001
	//
	// +optional
	Tags map[string]string `json:"tags,omitempty"`

	// Extends lists other Teams whose members this team inherits.
	// Inheritance is additive — the effective member set is the union of
	// this team's members and all inherited teams' effective members.
	//
	// Circular references are rejected by the admission webhook.
	//
	// Use this for patterns like "oncall extends platform-engineers":
	//   extends:
	//     - name: platform-engineers
	//
	// +optional
	Extends []TeamReference `json:"extends,omitempty"`
}

// TeamReference is a reference to another Team resource.
type TeamReference struct {
	// Name of the Team resource.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// TeamStatus defines the observed state of a Team.
type TeamStatus struct {
	// Conditions represent the latest reconciliation state of the Team.
	//
	// Condition types:
	//   - Ready: True when the team is valid and all extends references resolve.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// EffectiveMembers is the computed union of this team's direct members and
	// all inherited members from Extends. Populated by the operator.
	//
	// +optional
	EffectiveMembers []rbacv1.Subject `json:"effectiveMembers,omitempty"`

	// BoundPolicies lists the names of AccessPolicies that currently reference
	// this Team. Populated by the AccessPolicy controller.
	//
	// +optional
	BoundPolicies []string `json:"boundPolicies,omitempty"`

	// ObservedGeneration is the .metadata.generation of this Team that was last
	// reconciled by the controller.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=team,categories=rbac-therapist
// +kubebuilder:printcolumn:name="Members",type="integer",JSONPath=".status.effectiveMembers",description="Number of effective members"
// +kubebuilder:printcolumn:name="Policies",type="string",JSONPath=".status.boundPolicies",description="Bound AccessPolicies"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Team is a named group of Kubernetes subjects (Users, Groups, ServiceAccounts)
// that share a purpose and a tag set.
//
// Teams are the identity primitive in rbac-therapist. They are referenced by
// AccessPolicies to grant access to namespaces. Tags on a Team drive automatic
// ABAC-style namespace matching when used with matchTeamTags in an AccessPolicy.
//
// Therapy note: The team is the patient. AccessPolicies are their treatment plan.
type Team struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec TeamSpec `json:"spec,omitempty"`

	// +optional
	Status TeamStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TeamList contains a list of Team.
type TeamList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Team `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Team{}, &TeamList{})
}
