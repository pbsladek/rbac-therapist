// Package tags implements the ABAC namespace matching engine.
//
// When an AccessPolicy role entry has matchTeamTags: true, the operator uses
// this package to find all namespaces whose labels are a superset of a team's tags.
//
// This is modeled after AWS IAM attribute-based access control (ABAC):
// you tag your resources, you tag your principals, and access flows automatically.
//
// See: https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction_attribute-based-access-control.html
package tags

import (
	corev1 "k8s.io/api/core/v1"
)

// MatchReason describes why a namespace was selected for tag-based matching.
type MatchReason struct {
	// Namespace is the name of the matched namespace.
	Namespace string
	// MatchedTags are the team tags that were found in the namespace labels.
	MatchedTags map[string]string
	// Reason is a human-readable explanation suitable for RBACSession.matchReason.
	Reason string
}

// MatchNamespaces returns all namespaces whose labels contain all of the given
// team tags as a subset.
//
// A namespace matches if, for every key-value pair in teamTags, the namespace
// has that same key with that same value. The namespace may have additional labels.
//
// If teamTags is empty, no namespaces match (empty tags don't grant access to everything).
func MatchNamespaces(namespaces []corev1.Namespace, teamTags map[string]string) []MatchReason {
	if len(teamTags) == 0 {
		return nil
	}

	var matches []MatchReason
	for _, ns := range namespaces {
		if isSuperset(ns.Labels, teamTags) {
			matches = append(matches, MatchReason{
				Namespace:   ns.Name,
				MatchedTags: teamTags,
				Reason:      formatReason(teamTags, ns.Labels),
			})
		}
	}
	return matches
}

// isSuperset returns true if the namespace labels contain all team tags.
func isSuperset(nsLabels, teamTags map[string]string) bool {
	for k, v := range teamTags {
		if nsLabels[k] != v {
			return false
		}
	}
	return true
}

// formatReason produces the human-readable match explanation stored in RBACSession.
func formatReason(teamTags, nsLabels map[string]string) string {
	_ = nsLabels
	msg := "matchTeamTags: team tags {"
	first := true
	for k, v := range teamTags {
		if !first {
			msg += ", "
		}
		msg += k + "=" + v
		first = false
	}
	msg += "} are a subset of namespace labels"
	return msg
}
