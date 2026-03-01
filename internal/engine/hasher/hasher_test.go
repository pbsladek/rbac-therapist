package hasher_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/hasher"
)

func TestBindingName_format(t *testing.T) {
	name := hasher.BindingName("my-policy", "ClusterRole", "admin", "monitoring")
	assert.True(t, strings.HasPrefix(name, "rbact-"), "expected rbact- prefix, got: %s", name)
	assert.LessOrEqual(t, len(name), 63, "name must fit Kubernetes naming limit")
}

func TestBindingName_deterministic(t *testing.T) {
	a := hasher.BindingName("platform-admin", "ClusterRole", "admin", "monitoring")
	b := hasher.BindingName("platform-admin", "ClusterRole", "admin", "monitoring")
	assert.Equal(t, a, b, "same inputs must produce same name")
}

func TestBindingName_uniquePerNamespace(t *testing.T) {
	a := hasher.BindingName("platform-admin", "ClusterRole", "admin", "monitoring")
	b := hasher.BindingName("platform-admin", "ClusterRole", "admin", "logging")
	assert.NotEqual(t, a, b, "different namespaces must produce different names")
}

func TestBindingName_uniquePerPolicy(t *testing.T) {
	a := hasher.BindingName("policy-a", "ClusterRole", "admin", "monitoring")
	b := hasher.BindingName("policy-b", "ClusterRole", "admin", "monitoring")
	assert.NotEqual(t, a, b, "different policies must produce different names")
}

func TestManagedLabels(t *testing.T) {
	labels := hasher.ManagedLabels("my-policy", "AccessPolicy", "sha256:abc123")
	assert.Equal(t, "rbac-therapist", labels[hasher.ManagedByLabel])
	assert.Equal(t, "my-policy", labels[hasher.PolicyLabel])
	assert.Equal(t, "AccessPolicy", labels[hasher.PolicyKindLabel])
}
