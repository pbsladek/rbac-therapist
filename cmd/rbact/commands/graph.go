package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
)

func newGraphCommand() *cobra.Command {
	var (
		filterPolicy string
		filterTeam   string
		outputFile   string
	)

	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Generate a Mermaid dependency graph of RBAC policies",
		Long: `Generate a Mermaid diagram showing the relationships between
Teams, AccessPolicies, and Namespaces.

The output can be embedded in GitHub Markdown, rendered with the Mermaid
CLI, or pasted into mermaid.live for interactive exploration.

Example:
  # Print Mermaid to stdout
  rbact graph

  # Write to a file
  rbact graph -o rbac-graph.mmd

  # Filter to a specific policy
  rbact graph --policy platform-namespace-admin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGraph(filterPolicy, filterTeam, outputFile)
		},
	}

	cmd.Flags().StringVar(&filterPolicy, "policy", "", "Filter graph to a specific AccessPolicy")
	cmd.Flags().StringVar(&filterTeam, "team", "", "Filter graph to a specific Team")
	cmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "Write output to a file instead of stdout")

	return cmd
}

func runGraph(filterPolicy, filterTeam, outputFile string) error {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(therapistv1alpha1.AddToScheme(scheme))

	cfg, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("getting kubeconfig: %w", err)
	}

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	ctx := context.Background()

	var teams therapistv1alpha1.TeamList
	if err := c.List(ctx, &teams); err != nil {
		return fmt.Errorf("listing teams: %w", err)
	}

	var policies therapistv1alpha1.AccessPolicyList
	if err := c.List(ctx, &policies); err != nil {
		return fmt.Errorf("listing access policies: %w", err)
	}

	diagram := buildMermaidDiagram(teams.Items, policies.Items, filterPolicy, filterTeam)

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(diagram), 0644); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
		fmt.Printf("graph written to %s\n", outputFile)
		return nil
	}

	fmt.Print(diagram)
	return nil
}

// buildMermaidDiagram generates a Mermaid flowchart from Teams and AccessPolicies.
func buildMermaidDiagram(
	teams []therapistv1alpha1.Team,
	policies []therapistv1alpha1.AccessPolicy,
	filterPolicy, filterTeam string,
) string {
	var sb strings.Builder

	sb.WriteString("```mermaid\n")
	sb.WriteString("graph LR\n")

	// Teams subgraph.
	sb.WriteString("  subgraph Teams\n")
	for _, t := range teams {
		if filterTeam != "" && t.Name != filterTeam {
			continue
		}
		label := t.Name
		if t.Spec.Description != "" {
			label += "\\n" + truncateString(t.Spec.Description, 40)
		}
		if len(t.Spec.Tags) > 0 {
			label += "\\ntags: " + formatTagsInline(t.Spec.Tags)
		}
		memberCount := len(t.Status.EffectiveMembers)
		if memberCount == 0 {
			memberCount = len(t.Spec.Members)
		}
		if memberCount > 0 {
			label += fmt.Sprintf("\\n%d member(s)", memberCount)
		}
		nodeID := sanitizeID("T_" + t.Name)
		sb.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", nodeID, label))
	}
	sb.WriteString("  end\n\n")

	// Policies subgraph.
	sb.WriteString("  subgraph AccessPolicies\n")
	for _, p := range policies {
		if filterPolicy != "" && p.Name != filterPolicy {
			continue
		}
		label := p.Name
		if p.Spec.Paused {
			label += "\\n⏸ PAUSED"
		}
		if p.Spec.ExpiresAt != nil {
			label += "\\nexpires: " + p.Spec.ExpiresAt.Format("2006-01-02")
		}
		bindingCount := len(p.Status.ManagedBindings)
		if bindingCount > 0 {
			label += fmt.Sprintf("\\n%d binding(s)", bindingCount)
		}
		nodeID := sanitizeID("P_" + p.Name)
		sb.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", nodeID, label))
	}
	sb.WriteString("  end\n\n")

	// Namespace subgraph (from managed bindings).
	namespaces := collectNamespaces(policies)
	if len(namespaces) > 0 {
		sb.WriteString("  subgraph Namespaces\n")
		for _, ns := range namespaces {
			nodeID := sanitizeID("NS_" + ns)
			sb.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", nodeID, ns))
		}
		sb.WriteString("  end\n\n")
	}

	// Edges: Team → Policy (subject relationships).
	for _, p := range policies {
		if filterPolicy != "" && p.Name != filterPolicy {
			continue
		}
		policyID := sanitizeID("P_" + p.Name)
		for _, subj := range p.Spec.Subjects {
			if subj.TeamRef != nil {
				if filterTeam != "" && subj.TeamRef.Name != filterTeam {
					continue
				}
				teamID := sanitizeID("T_" + subj.TeamRef.Name)
				sb.WriteString(fmt.Sprintf("  %s -->|member of| %s\n", teamID, policyID))
			}
		}
	}

	// Edges: Policy → Namespace (binding relationships).
	for _, p := range policies {
		if filterPolicy != "" && p.Name != filterPolicy {
			continue
		}
		policyID := sanitizeID("P_" + p.Name)
		boundNS := make(map[string][]string) // role → namespaces
		for _, b := range p.Status.ManagedBindings {
			if b.Namespace != "" {
				boundNS[b.RoleName] = append(boundNS[b.RoleName], b.Namespace)
			}
		}
		for role, nsList := range boundNS {
			sort.Strings(nsList)
			for _, ns := range nsList {
				nsID := sanitizeID("NS_" + ns)
				sb.WriteString(fmt.Sprintf("  %s -->|%s| %s\n", policyID, role, nsID))
			}
		}
	}

	sb.WriteString("```\n")
	return sb.String()
}

func collectNamespaces(policies []therapistv1alpha1.AccessPolicy) []string {
	seen := make(map[string]bool)
	for _, p := range policies {
		for _, b := range p.Status.ManagedBindings {
			if b.Namespace != "" {
				seen[b.Namespace] = true
			}
		}
	}
	var result []string
	for ns := range seen {
		result = append(result, ns)
	}
	sort.Strings(result)
	return result
}

func sanitizeID(s string) string {
	replacer := strings.NewReplacer(
		"-", "_",
		".", "_",
		"/", "_",
		"@", "_at_",
		" ", "_",
	)
	return replacer.Replace(s)
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func formatTagsInline(tags map[string]string) string {
	var pairs []string
	for k, v := range tags {
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}
