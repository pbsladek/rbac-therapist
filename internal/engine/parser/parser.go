// Package parser resolves an AccessPolicy into the set of desired
// RoleBindings and ClusterRoleBindings.
//
// The parser is pure logic — it takes an AccessPolicy plus the current cluster
// state (namespaces, teams) and returns the desired binding set.
// It does not talk to the Kubernetes API.
package parser

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/hasher"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/tags"
)

// DesiredBinding represents a single RoleBinding or ClusterRoleBinding that
// the operator should ensure exists.
type DesiredBinding struct {
	// Name is the deterministic name for this binding (from hasher.BindingName).
	Name string
	// Namespace is the target namespace. Empty for ClusterRoleBindings.
	Namespace string
	// ClusterWide is true for ClusterRoleBindings.
	ClusterWide bool
	// RoleRef is the role being bound.
	RoleRef rbacv1.RoleRef
	// Subjects are the Kubernetes subjects receiving this binding.
	Subjects []rbacv1.Subject
	// Hash is the content hash for this binding (used for the HashLabel).
	Hash string
	// MatchReason explains why this namespace was selected (for RBACSession).
	MatchReason string
}

// Input holds all data needed to resolve an AccessPolicy.
type Input struct {
	// Policy is the AccessPolicy to resolve.
	Policy therapistv1alpha1.AccessPolicy
	// Teams is the full list of Team CRDs in the cluster.
	Teams []therapistv1alpha1.Team
	// Namespaces is the full list of namespaces in the cluster.
	Namespaces []corev1.Namespace
}

// Parse resolves an AccessPolicy into the set of desired bindings.
// It handles:
//   - TeamRef resolution (expanding a Team to its effective members)
//   - Inline subjects
//   - Static namespace lists
//   - Label selector namespace matching
//   - matchTeamTags ABAC matching
//   - ClusterWide bindings
func Parse(in Input) []DesiredBinding {
	// Build a team lookup map for fast resolution.
	teamByName := make(map[string]therapistv1alpha1.Team, len(in.Teams))
	for _, t := range in.Teams {
		teamByName[t.Name] = t
	}
	resolvedSubjects := resolveAllSubjects(in.Policy.Spec.Subjects, teamByName)

	var desired []DesiredBinding

	for _, role := range in.Policy.Spec.Roles {
		roleRef := resolveRoleRef(role)
		nsResolver := newNamespaceResolver(role.Namespaces, in.Namespaces)
		nsCache := make(map[string][]resolvedNamespace, len(resolvedSubjects))

		for _, subjectEntry := range resolvedSubjects {
			if len(subjectEntry.Subjects) == 0 {
				continue
			}

			if role.ClusterWide {
				name := hasher.BindingName(in.Policy.Name, roleRef.Kind, roleRef.Name, "")
				desired = append(desired, DesiredBinding{
					Name:        name,
					ClusterWide: true,
					RoleRef:     roleRef,
					Subjects:    subjectEntry.Subjects,
					Hash:        contentHash(name, subjectEntry.Subjects, roleRef),
					MatchReason: "cluster-wide binding",
				})
				continue
			}

			targetNamespaces, ok := nsCache[subjectEntry.CacheKey]
			if !ok {
				targetNamespaces = nsResolver.resolve(subjectEntry.TeamTags, subjectEntry.TeamName)
				nsCache[subjectEntry.CacheKey] = targetNamespaces
			}

			for _, ns := range targetNamespaces {
				name := hasher.BindingName(in.Policy.Name, roleRef.Kind, roleRef.Name, ns.Namespace)
				desired = append(desired, DesiredBinding{
					Name:        name,
					Namespace:   ns.Namespace,
					ClusterWide: false,
					RoleRef:     roleRef,
					Subjects:    subjectEntry.Subjects,
					Hash:        contentHash(name, subjectEntry.Subjects, roleRef),
					MatchReason: ns.Reason,
				})
			}
		}
	}

	return deduplicateBindings(desired)
}

// resolvedNamespace is a namespace name + the reason it was selected.
type resolvedNamespace struct {
	Namespace string
	Reason    string
}

type resolvedSubjectEntry struct {
	Subjects []rbacv1.Subject
	TeamTags map[string]string
	TeamName string
	CacheKey string
}

type namespaceResolver struct {
	selector      *metav1.LabelSelector
	compiled      labels.Selector
	staticNames   []string
	matchTeamTags bool
	allNamespaces []corev1.Namespace
}

// resolveRoleRef converts a PolicyRole into an rbacv1.RoleRef.
func resolveRoleRef(role therapistv1alpha1.PolicyRole) rbacv1.RoleRef {
	if role.ClusterRole != "" {
		return rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     role.ClusterRole,
		}
	}
	return rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "Role",
		Name:     role.Role,
	}
}

// resolveSubjects returns the concrete subjects for a PolicySubject entry,
// the team tags (if the subject is a TeamRef), and the team name.
func resolveSubjects(
	entry therapistv1alpha1.PolicySubject,
	teamByName map[string]therapistv1alpha1.Team,
) (subjects []rbacv1.Subject, teamTags map[string]string, teamName string) {
	if entry.TeamRef != nil {
		team, ok := teamByName[entry.TeamRef.Name]
		if !ok {
			// Team not found — skip. The controller sets a warning condition.
			return nil, nil, ""
		}
		// Use effective members (includes inherited members from Extends).
		members := team.Status.EffectiveMembers
		if len(members) == 0 {
			// Fall back to direct members if status not yet populated.
			members = team.Spec.Members
		}
		return members, team.Spec.Tags, team.Name
	}

	if entry.Inline != nil {
		return []rbacv1.Subject{*entry.Inline}, nil, ""
	}

	return nil, nil, ""
}

func resolveAllSubjects(
	entries []therapistv1alpha1.PolicySubject,
	teamByName map[string]therapistv1alpha1.Team,
) []resolvedSubjectEntry {
	resolved := make([]resolvedSubjectEntry, 0, len(entries))
	for _, subjectEntry := range entries {
		subjects, teamTags, teamName := resolveSubjects(subjectEntry, teamByName)
		if len(subjects) == 0 {
			continue
		}
		resolved = append(resolved, resolvedSubjectEntry{
			Subjects: subjects,
			TeamTags: teamTags,
			TeamName: teamName,
			CacheKey: subjectCacheKey(subjects, teamTags, teamName),
		})
	}
	return resolved
}

func subjectCacheKey(subjects []rbacv1.Subject, teamTags map[string]string, teamName string) string {
	if teamName != "" {
		return "team:" + teamName + ":" + tagsCacheKey(teamTags)
	}
	if len(subjects) == 1 {
		s := subjects[0]
		return "inline:" + s.Kind + "/" + s.Namespace + "/" + s.Name
	}
	keys := make([]string, 0, len(subjects))
	for _, s := range subjects {
		keys = append(keys, s.Kind+"/"+s.Namespace+"/"+s.Name)
	}
	sort.Strings(keys)
	return "subjects:" + strings.Join(keys, ",")
}

func tagsCacheKey(teamTags map[string]string) string {
	if len(teamTags) == 0 {
		return "{}"
	}
	pairs := make([]string, 0, len(teamTags))
	for k, v := range teamTags {
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

func newNamespaceResolver(
	sel *therapistv1alpha1.NamespaceSelector,
	allNamespaces []corev1.Namespace,
) namespaceResolver {
	resolver := namespaceResolver{allNamespaces: allNamespaces}
	if sel == nil {
		return resolver
	}
	resolver.selector = sel.Selector
	resolver.staticNames = sel.Names
	resolver.matchTeamTags = sel.MatchTeamTags
	if sel.Selector != nil {
		if compiled, err := metav1.LabelSelectorAsSelector(sel.Selector); err == nil {
			resolver.compiled = compiled
		}
	}
	return resolver
}

// resolve computes target namespace list from static names + label selector + matchTeamTags.
func (r namespaceResolver) resolve(teamTags map[string]string, teamName string) []resolvedNamespace {
	seen := make(map[string]bool)
	var result []resolvedNamespace

	add := func(ns, reason string) {
		if !seen[ns] {
			seen[ns] = true
			result = append(result, resolvedNamespace{Namespace: ns, Reason: reason})
		}
	}

	// 1. Static names.
	for _, name := range r.staticNames {
		add(name, "static name list")
	}

	// 2. Label selector.
	if r.selector != nil && r.compiled != nil {
		for _, ns := range r.allNamespaces {
			if labelSelectorMatches(r.compiled, ns.Labels) {
				add(ns.Name, "label selector: "+formatLabels(r.selector.MatchLabels))
			}
		}
	}

	// 3. matchTeamTags ABAC.
	if r.matchTeamTags && len(teamTags) > 0 {
		matches := tags.MatchNamespaces(r.allNamespaces, teamTags)
		for _, m := range matches {
			add(m.Namespace, m.Reason)
		}
	} else if r.matchTeamTags && teamName != "" {
		// teamTags is empty — log a warning but don't match anything.
		_ = teamName // warning emitted by controller
	}

	return result
}

// labelSelectorMatches applies full Kubernetes LabelSelector semantics,
// including both matchLabels and matchExpressions.
func labelSelectorMatches(compiled labels.Selector, nsLabels map[string]string) bool {
	return compiled.Matches(labels.Set(nsLabels))
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "{}"
	}
	s := "{"
	first := true
	for k, v := range labels {
		if !first {
			s += ", "
		}
		s += k + "=" + v
		first = false
	}
	return s + "}"
}

// contentHash produces a stable hash for a binding's content.
func contentHash(name string, subjects []rbacv1.Subject, roleRef rbacv1.RoleRef) string {
	content := name + "|" + roleRef.Kind + "/" + roleRef.Name
	for _, s := range subjects {
		content += "|" + s.Kind + "/" + s.Namespace + "/" + s.Name
	}
	return hasher.ContentHash(content)
}

// deduplicateBindings removes duplicate desired bindings (same name).
// When multiple subject entries resolve to the same namespace/role, subjects are merged.
func deduplicateBindings(bindings []DesiredBinding) []DesiredBinding {
	byName := make(map[string]*DesiredBinding)
	var order []string

	for i := range bindings {
		b := &bindings[i]
		if existing, ok := byName[b.Name]; ok {
			// Merge subjects, deduplicating.
			existing.Subjects = mergeSubjects(existing.Subjects, b.Subjects)
		} else {
			byName[b.Name] = b
			order = append(order, b.Name)
		}
	}

	result := make([]DesiredBinding, 0, len(order))
	for _, name := range order {
		result = append(result, *byName[name])
	}
	return result
}

func mergeSubjects(existing, newSubjects []rbacv1.Subject) []rbacv1.Subject {
	seen := make(map[string]bool)
	for _, s := range existing {
		seen[s.Kind+"/"+s.Namespace+"/"+s.Name] = true
	}
	result := existing
	for _, s := range newSubjects {
		key := s.Kind + "/" + s.Namespace + "/" + s.Name
		if !seen[key] {
			seen[key] = true
			result = append(result, s)
		}
	}
	return result
}
