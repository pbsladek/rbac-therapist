package parser_test

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/parser"
)

func BenchmarkParse_ABACLarge(b *testing.B) {
	const (
		namespaceCount = 1500
		teamCount      = 200
	)

	namespaces := make([]corev1.Namespace, 0, namespaceCount)
	for i := 0; i < namespaceCount; i++ {
		labels := map[string]string{
			"tier": "app",
			"env":  "staging",
		}
		if i%2 == 0 {
			labels["tier"] = "platform"
			labels["env"] = "production"
		}
		namespaces = append(namespaces, corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   fmt.Sprintf("ns-%d", i),
				Labels: labels,
			},
		})
	}

	teams := make([]therapistv1alpha1.Team, 0, teamCount)
	subjects := make([]therapistv1alpha1.PolicySubject, 0, teamCount)
	for i := 0; i < teamCount; i++ {
		name := fmt.Sprintf("team-%d", i)
		tags := map[string]string{"tier": "platform", "env": "production"}
		if i%2 != 0 {
			tags = map[string]string{"tier": "app", "env": "staging"}
		}
		teams = append(teams, therapistv1alpha1.Team{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: therapistv1alpha1.TeamSpec{
				Members: []rbacv1.Subject{
					{Kind: "Group", Name: fmt.Sprintf("%s@example.com", name)},
				},
				Tags: tags,
			},
		})
		subjects = append(subjects, therapistv1alpha1.PolicySubject{
			TeamRef: &therapistv1alpha1.TeamReference{Name: name},
		})
	}

	policy := therapistv1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "bench-policy"},
		Spec: therapistv1alpha1.AccessPolicySpec{
			Rationale: "benchmark policy",
			Subjects:  subjects,
			Roles: []therapistv1alpha1.PolicyRole{
				{
					ClusterRole: "view",
					Namespaces: &therapistv1alpha1.NamespaceSelector{
						MatchTeamTags: true,
					},
				},
				{
					ClusterRole: "edit",
					Namespaces: &therapistv1alpha1.NamespaceSelector{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"tier": "app"},
							MatchExpressions: []metav1.LabelSelectorRequirement{
								{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"staging"}},
							},
						},
					},
				},
			},
		},
	}

	in := parser.Input{
		Policy:     policy,
		Teams:      teams,
		Namespaces: namespaces,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parser.Parse(in)
	}
}

func BenchmarkParse_ManyInlineSubjects(b *testing.B) {
	const subjectCount = 1000

	subjects := make([]therapistv1alpha1.PolicySubject, 0, subjectCount)
	for i := 0; i < subjectCount; i++ {
		subjects = append(subjects, therapistv1alpha1.PolicySubject{
			Inline: &rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      fmt.Sprintf("sa-%d", i),
				Namespace: "ci",
			},
		})
	}

	policy := therapistv1alpha1.AccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "bench-inline"},
		Spec: therapistv1alpha1.AccessPolicySpec{
			Rationale: "benchmark inline subjects",
			Subjects:  subjects,
			Roles: []therapistv1alpha1.PolicyRole{
				{
					ClusterRole: "view",
					Namespaces: &therapistv1alpha1.NamespaceSelector{
						Names: []string{"ns-a", "ns-b", "ns-c"},
					},
				},
			},
		},
	}

	in := parser.Input{
		Policy: policy,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parser.Parse(in)
	}
}
