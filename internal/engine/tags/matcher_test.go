package tags_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rbac-therapist/rbac-therapist/internal/engine/tags"
)

func makeNamespace(name string, labels map[string]string) corev1.Namespace {
	return corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}

func TestMatchNamespaces_supersetMatch(t *testing.T) {
	namespaces := []corev1.Namespace{
		makeNamespace("monitoring", map[string]string{"tier": "platform", "env": "production", "app": "prometheus"}),
		makeNamespace("logging", map[string]string{"tier": "platform", "env": "production"}),
		makeNamespace("frontend", map[string]string{"tier": "app", "env": "production"}),
	}
	teamTags := map[string]string{"tier": "platform", "env": "production"}

	matches := tags.MatchNamespaces(namespaces, teamTags)
	require.Len(t, matches, 2)

	names := []string{matches[0].Namespace, matches[1].Namespace}
	assert.Contains(t, names, "monitoring")
	assert.Contains(t, names, "logging")
}

func TestMatchNamespaces_noMatch(t *testing.T) {
	namespaces := []corev1.Namespace{
		makeNamespace("frontend", map[string]string{"tier": "app"}),
	}
	teamTags := map[string]string{"tier": "platform"}
	matches := tags.MatchNamespaces(namespaces, teamTags)
	assert.Empty(t, matches)
}

func TestMatchNamespaces_emptyTagsMatchNothing(t *testing.T) {
	// Safety: empty team tags must never grant access to all namespaces.
	namespaces := []corev1.Namespace{
		makeNamespace("monitoring", map[string]string{"tier": "platform"}),
	}
	matches := tags.MatchNamespaces(namespaces, map[string]string{})
	assert.Empty(t, matches, "empty teamTags must not match any namespace")
}

func TestMatchNamespaces_reasonIsInformative(t *testing.T) {
	namespaces := []corev1.Namespace{
		makeNamespace("monitoring", map[string]string{"tier": "platform"}),
	}
	matches := tags.MatchNamespaces(namespaces, map[string]string{"tier": "platform"})
	require.Len(t, matches, 1)
	assert.Contains(t, matches[0].Reason, "matchTeamTags")
	assert.Contains(t, matches[0].Reason, "tier=platform")
}
