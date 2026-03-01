package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/yaml"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
)

func newWhoCanCommand() *cobra.Command {
	var (
		namespace string
		role      string
	)
	cmd := &cobra.Command{
		Use:   "who-can",
		Short: `"Who can access this namespace/role?" — query the RBACSession`,
		Long: `Find all subjects that have access to a namespace or ClusterRole,
with the full policy chain that granted the access.

Queries the RBACSession for fast, pre-computed results.
Use 'kubectl auth can-i --list' for authoritative verb-level checks.

Examples:
  # Who has any access to namespace "production"?
  rbact who-can --namespace production

  # Who has the "cluster-admin" role?
  rbact who-can --role cluster-admin

  # Who has access to namespace "staging" via the "developer" role?
  rbact who-can --namespace staging --role developer

  # Output as JSON
  rbact who-can --namespace production --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if namespace == "" && role == "" {
				return fmt.Errorf("at least one of --namespace or --role is required")
			}
			return runWhoCan(namespace, role, globalFlags.Output)
		},
	}
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Filter by namespace (empty = any)")
	cmd.Flags().StringVar(&role, "role", "", "Filter by ClusterRole or Role name (empty = any)")
	return cmd
}

// whoCanResult is a single result row.
type whoCanResult struct {
	Subject    rbacv1.Subject `json:"subject"`
	Role       string         `json:"role"`
	Namespace  string         `json:"namespace,omitempty"`
	PolicyRef  string         `json:"policyRef"`
	PolicyKind string         `json:"policyKind"`
	TeamRef    string         `json:"teamRef,omitempty"`
	Rationale  string         `json:"rationale"`
}

func runWhoCan(namespace, roleName, outputFormat string) error {
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

	var session therapistv1alpha1.RBACSession
	if err := c.Get(ctx, client.ObjectKey{Name: "current"}, &session); err != nil {
		return fmt.Errorf("getting RBACSession: %w — run the operator to generate it", err)
	}

	var results []whoCanResult
	seen := map[string]bool{}

	for _, entry := range session.Status.SubjectAccess {
		for _, grant := range entry.Access {
			// Filter by namespace.
			if namespace != "" && grant.Namespace != namespace && !grant.ClusterWide {
				continue
			}
			// Filter by role.
			if roleName != "" && !strings.EqualFold(grant.Role, roleName) {
				continue
			}
			key := fmt.Sprintf("%s/%s/%s/%s/%s", entry.Subject.Kind, entry.Subject.Name, grant.Role, grant.Namespace, grant.Via.PolicyRef)
			if seen[key] {
				continue
			}
			seen[key] = true
			results = append(results, whoCanResult{
				Subject:    entry.Subject,
				Role:       grant.Role,
				Namespace:  grant.Namespace,
				PolicyRef:  grant.Via.PolicyRef,
				PolicyKind: grant.Via.PolicyKind,
				TeamRef:    grant.Via.TeamRef,
				Rationale:  grant.Via.Rationale,
			})
		}
	}

	if len(results) == 0 {
		fmt.Println("No matching access found in the current RBACSession.")
		fmt.Println("Note: run 'rbact snapshot' to force a refresh if policies were recently changed.")
		return nil
	}

	switch outputFormat {
	case "json":
		return printWhoCanJSON(results)
	case "yaml":
		return printWhoCanYAML(results)
	default:
		printWhoCanText(results, namespace, roleName)
	}
	return nil
}

func printWhoCanText(results []whoCanResult, namespace, roleName string) {
	var header strings.Builder
	header.WriteString("WHO CAN")
	if namespace != "" {
		header.WriteString(fmt.Sprintf(" access namespace %q", namespace))
	}
	if roleName != "" {
		header.WriteString(fmt.Sprintf(" with role %q", roleName))
	}
	fmt.Println(header.String())
	fmt.Println(strings.Repeat("─", 72))

	for _, r := range results {
		subj := fmt.Sprintf("%s/%s", r.Subject.Kind, r.Subject.Name)
		if r.Subject.Namespace != "" {
			subj += "/" + r.Subject.Namespace
		}

		fmt.Printf("  %s\n", subj)
		fmt.Printf("    Role:      %s\n", r.Role)
		if r.Namespace != "" {
			fmt.Printf("    Namespace: %s\n", r.Namespace)
		} else {
			fmt.Printf("    Scope:     cluster-wide\n")
		}
		fmt.Printf("    Via:       %s %s\n", r.PolicyKind, r.PolicyRef)
		if r.TeamRef != "" {
			fmt.Printf("    Team:      %s\n", r.TeamRef)
		}
		fmt.Printf("    Rationale: %s\n", truncateString(r.Rationale, 80))
		fmt.Println()
	}

	fmt.Printf("Total: %d subject(s) found\n", len(results))
}

func printWhoCanJSON(results []whoCanResult) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func printWhoCanYAML(results []whoCanResult) error {
	data, err := yaml.Marshal(results)
	if err != nil {
		return err
	}
	fmt.Print(string(data))
	return nil
}

