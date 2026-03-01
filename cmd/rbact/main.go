// rbact is the rbac-therapist CLI — the therapist in your terminal.
//
// Usage:
//
//	rbact generate    Generate CRD manifests from a config file
//	rbact validate    Validate AccessPolicy manifests without applying
//	rbact explain     LLM-powered: explain who has access to a namespace and why
//	rbact audit       LLM-powered: full cluster RBAC audit report
//	rbact graph       Generate a Mermaid dependency graph
//	rbact who-can     "who can do X on Y?" — queries the RBACSession
//	rbact diff        Show what would change if manifests were applied
//	rbact snapshot    Force-refresh the RBACSession
//	rbact expire      Immediately expire an AccessPolicy or RBACBinding
package main

import (
	"os"

	"github.com/rbac-therapist/rbac-therapist/cmd/rbact/commands"
)

func main() {
	if err := commands.NewRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
