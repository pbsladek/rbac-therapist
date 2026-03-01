package parser_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/parser"
)

func makeTeam(name string, members []rbacv1.Subject, tags map[string]string) therapistv1alpha1.Team {
	return therapistv1alpha1.Team{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: therapistv1alpha1.TeamSpec{
			Members: members,
			Tags:    tags,
		},
	}
}

func makeNamespace(name string, labels map[string]string) corev1.Namespace {
	return corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
}

func makePolicy(name string, subjects []therapistv1alpha1.PolicySubject, roles []therapistv1alpha1.PolicyRole) therapistv1alpha1.AccessPolicy {
	return therapistv1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: therapistv1alpha1.AccessPolicySpec{
			Rationale: "test policy rationale",
			Subjects:  subjects,
			Roles:     roles,
		},
	}
}

func TestParse_staticNamespace(t *testing.T) {
	team := makeTeam("platform", []rbacv1.Subject{{Kind: "Group", Name: "platform@acme.com"}}, nil)
	policy := makePolicy("test-policy",
		[]therapistv1alpha1.PolicySubject{
			{TeamRef: &therapistv1alpha1.TeamReference{Name: "platform"}},
		},
		[]therapistv1alpha1.PolicyRole{
			{
				ClusterRole: "admin",
				Namespaces: &therapistv1alpha1.NamespaceSelector{
					Names: []string{"monitoring"},
				},
			},
		},
	)

	bindings := parser.Parse(parser.Input{
		Policy:     policy,
		Teams:      []therapistv1alpha1.Team{team},
		Namespaces: []corev1.Namespace{makeNamespace("monitoring", nil)},
	})

	require.Len(t, bindings, 1)
	assert.Equal(t, "monitoring", bindings[0].Namespace)
	assert.Equal(t, "ClusterRole", bindings[0].RoleRef.Kind)
	assert.Equal(t, "admin", bindings[0].RoleRef.Name)
	assert.Equal(t, "static name list", bindings[0].MatchReason)
}

func TestParse_clusterWide(t *testing.T) {
	team := makeTeam("platform", []rbacv1.Subject{{Kind: "Group", Name: "platform@acme.com"}}, nil)
	policy := makePolicy("test-policy",
		[]therapistv1alpha1.PolicySubject{
			{TeamRef: &therapistv1alpha1.TeamReference{Name: "platform"}},
		},
		[]therapistv1alpha1.PolicyRole{
			{ClusterRole: "view", ClusterWide: true},
		},
	)

	bindings := parser.Parse(parser.Input{
		Policy: policy,
		Teams:  []therapistv1alpha1.Team{team},
	})

	require.Len(t, bindings, 1)
	assert.True(t, bindings[0].ClusterWide)
	assert.Empty(t, bindings[0].Namespace)
}

func TestParse_matchTeamTags(t *testing.T) {
	team := makeTeam("platform",
		[]rbacv1.Subject{{Kind: "Group", Name: "platform@acme.com"}},
		map[string]string{"tier": "platform", "env": "production"},
	)
	namespaces := []corev1.Namespace{
		makeNamespace("monitoring", map[string]string{"tier": "platform", "env": "production"}),
		makeNamespace("logging", map[string]string{"tier": "platform", "env": "production"}),
		makeNamespace("frontend", map[string]string{"tier": "app", "env": "production"}),
	}
	policy := makePolicy("test-policy",
		[]therapistv1alpha1.PolicySubject{
			{TeamRef: &therapistv1alpha1.TeamReference{Name: "platform"}},
		},
		[]therapistv1alpha1.PolicyRole{
			{
				ClusterRole: "admin",
				Namespaces:  &therapistv1alpha1.NamespaceSelector{MatchTeamTags: true},
			},
		},
	)

	bindings := parser.Parse(parser.Input{
		Policy:     policy,
		Teams:      []therapistv1alpha1.Team{team},
		Namespaces: namespaces,
	})

	require.Len(t, bindings, 2)
	nsNames := []string{bindings[0].Namespace, bindings[1].Namespace}
	assert.Contains(t, nsNames, "monitoring")
	assert.Contains(t, nsNames, "logging")
	assert.NotContains(t, nsNames, "frontend")
}

func TestParse_teamNotFound(t *testing.T) {
	policy := makePolicy("test-policy",
		[]therapistv1alpha1.PolicySubject{
			{TeamRef: &therapistv1alpha1.TeamReference{Name: "nonexistent"}},
		},
		[]therapistv1alpha1.PolicyRole{
			{ClusterRole: "admin", ClusterWide: true},
		},
	)

	bindings := parser.Parse(parser.Input{
		Policy: policy,
		Teams:  nil,
	})

	assert.Empty(t, bindings, "missing team should produce no bindings")
}

func TestParse_inlineSubject(t *testing.T) {
	policy := makePolicy("test-policy",
		[]therapistv1alpha1.PolicySubject{
			{Inline: &rbacv1.Subject{Kind: "ServiceAccount", Name: "ci-bot", Namespace: "ci"}},
		},
		[]therapistv1alpha1.PolicyRole{
			{
				ClusterRole: "view",
				Namespaces:  &therapistv1alpha1.NamespaceSelector{Names: []string{"staging"}},
			},
		},
	)

	bindings := parser.Parse(parser.Input{
		Policy:     policy,
		Namespaces: []corev1.Namespace{makeNamespace("staging", nil)},
	})

	require.Len(t, bindings, 1)
	require.Len(t, bindings[0].Subjects, 1)
	assert.Equal(t, "ci-bot", bindings[0].Subjects[0].Name)
}
