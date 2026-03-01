package inheritance_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/inheritance"
)

func TestResolver_ResolvesInheritedRoles(t *testing.T) {
	policies := []therapistv1alpha1.AccessPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "base"},
			Spec: therapistv1alpha1.AccessPolicySpec{
				Rationale: "base policy",
				Roles: []therapistv1alpha1.PolicyRole{
					{ClusterRole: "view", ClusterWide: true},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "child"},
			Spec: therapistv1alpha1.AccessPolicySpec{
				Rationale: "child policy",
				Extends: []therapistv1alpha1.PolicyReference{
					{Name: "base"},
				},
				Roles: []therapistv1alpha1.PolicyRole{
					{ClusterRole: "edit", ClusterWide: true},
				},
			},
		},
	}

	resolver := inheritance.NewAccessPolicyResolver(policies, inheritance.DefaultMaxPolicyExtendsDepth)
	roles, err := resolver.ResolveRoles("child")
	require.NoError(t, err)
	require.Len(t, roles, 2)
	require.Equal(t, "view", roles[0].ClusterRole)
	require.Equal(t, "edit", roles[1].ClusterRole)
}

func TestResolver_CycleDetected(t *testing.T) {
	policies := []therapistv1alpha1.AccessPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "a"},
			Spec: therapistv1alpha1.AccessPolicySpec{
				Rationale: "a",
				Extends: []therapistv1alpha1.PolicyReference{
					{Name: "b"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "b"},
			Spec: therapistv1alpha1.AccessPolicySpec{
				Rationale: "b",
				Extends: []therapistv1alpha1.PolicyReference{
					{Name: "a"},
				},
			},
		},
	}

	resolver := inheritance.NewAccessPolicyResolver(policies, inheritance.DefaultMaxPolicyExtendsDepth)
	_, err := resolver.ResolveRoles("a")
	require.Error(t, err)
}

func TestResolver_MaxDepthEnforced(t *testing.T) {
	policies := []therapistv1alpha1.AccessPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "a"},
			Spec: therapistv1alpha1.AccessPolicySpec{
				Rationale: "a",
				Extends: []therapistv1alpha1.PolicyReference{
					{Name: "b"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "b"},
			Spec: therapistv1alpha1.AccessPolicySpec{
				Rationale: "b",
				Extends: []therapistv1alpha1.PolicyReference{
					{Name: "c"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "c"},
			Spec: therapistv1alpha1.AccessPolicySpec{
				Rationale: "c",
				Roles: []therapistv1alpha1.PolicyRole{
					{ClusterRole: "view", ClusterWide: true},
				},
			},
		},
	}

	resolver := inheritance.NewAccessPolicyResolver(policies, 1)
	_, err := resolver.ResolveRoles("a")
	require.Error(t, err)
}
