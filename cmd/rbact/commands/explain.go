package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	"github.com/rbac-therapist/rbac-therapist/pkg/llm"
)

func newExplainCommand() *cobra.Command {
	var (
		namespace string
		subject   string
		useLLM    bool
	)

	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain who has access to a namespace and why",
		Long: `Explain the access a specific subject has to a namespace,
with full provenance: which policy granted it, through which team,
why the namespace was selected, and the policy's rationale.

With --llm, the output is enriched by an LLM for a plain-English
explanation suitable for security audits or onboarding documentation.

Requires a running rbac-therapist operator with an up-to-date RBACSession.`,
		Example: `  # Explain access for a user in a namespace
  rbact explain --namespace monitoring --subject alice@acme.com

  # Explain with LLM-enriched output
  rbact explain --namespace monitoring --subject alice@acme.com --llm

  # Explain a group's access
  rbact explain --namespace staging --subject "platform@acme.com"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if namespace == "" || subject == "" {
				return fmt.Errorf("--namespace and --subject are required")
			}
			return runExplain(namespace, subject, useLLM)
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to explain access for (required)")
	cmd.Flags().StringVar(&subject, "subject", "", "Subject name to explain (User, Group, or ServiceAccount) (required)")
	cmd.Flags().BoolVar(&useLLM, "llm", false, "Enrich explanation with LLM-generated plain English")

	return cmd
}

func runExplain(namespace, subject string, useLLM bool) error {
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

	// Find the current RBACSession.
	var sessions therapistv1alpha1.RBACSessionList
	if err := c.List(ctx, &sessions); err != nil {
		return fmt.Errorf("listing RBACSession: %w", err)
	}
	if len(sessions.Items) == 0 {
		return fmt.Errorf("no RBACSession found — run 'rbact snapshot' to generate one")
	}

	// Use the most recent session.
	session := sessions.Items[0]
	for _, s := range sessions.Items[1:] {
		if s.Status.GeneratedAt != nil && session.Status.GeneratedAt != nil &&
			s.Status.GeneratedAt.After(session.Status.GeneratedAt.Time) {
			session = s
		}
	}

	// Build the explanation from the session.
	explanation := buildExplanation(session, namespace, subject)

	if useLLM {
		enriched, err := enrichWithLLM(explanation, namespace, subject)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: LLM enrichment failed: %v\n", err)
			// Fall through to plain output.
		} else {
			fmt.Println(enriched)
			return nil
		}
	}

	fmt.Print(explanation)
	return nil
}

// buildExplanation formats the plain-text explanation for a subject's access to a namespace.
func buildExplanation(session therapistv1alpha1.RBACSession, namespace, subjectName string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Access explanation for subject %q in namespace %q\n", subjectName, namespace))
	sb.WriteString(fmt.Sprintf("RBACSession generated at: %s\n\n", session.Status.GeneratedAt))

	var grants []therapistv1alpha1.AccessGrant
	var foundSubject bool

	for _, entry := range session.Status.SubjectAccess {
		if entry.Subject.Name == subjectName || matchesGroup(entry, subjectName) {
			foundSubject = true
			for _, g := range entry.Access {
				if g.Namespace == namespace || g.ClusterWide {
					grants = append(grants, g)
				}
			}
		}
	}

	if !foundSubject {
		sb.WriteString(fmt.Sprintf("No access found for subject %q.\n", subjectName))
		sb.WriteString("\nNote: The subject may access this namespace through group membership.\n")
		sb.WriteString("Try searching for their group name instead.\n")
		return sb.String()
	}

	if len(grants) == 0 {
		sb.WriteString(fmt.Sprintf("Subject %q has no access to namespace %q.\n", subjectName, namespace))
		return sb.String()
	}

	for _, g := range grants {
		if g.ClusterWide {
			sb.WriteString(fmt.Sprintf("ROLE: %s (cluster-wide, via ClusterRoleBinding)\n", g.Role))
		} else {
			sb.WriteString(fmt.Sprintf("ROLE: %s (namespace-scoped, via RoleBinding)\n", g.Role))
		}
		sb.WriteString(fmt.Sprintf("  ↳ Policy: %s (%s)\n", g.Via.PolicyRef, g.Via.PolicyKind))
		if g.Via.TeamRef != "" {
			sb.WriteString(fmt.Sprintf("  ↳ Via Team: %s\n", g.Via.TeamRef))
		}
		if g.Via.MatchReason != "" {
			sb.WriteString(fmt.Sprintf("  ↳ Namespace matched because: %s\n", g.Via.MatchReason))
		}
		if g.Via.Rationale != "" {
			sb.WriteString(fmt.Sprintf("\n  RATIONALE:\n    %s\n", g.Via.Rationale))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// matchesGroup checks if a subject entry matches a group name.
func matchesGroup(entry therapistv1alpha1.SubjectAccessEntry, name string) bool {
	return entry.Subject.Kind == "Group" && entry.Subject.Name == name
}

// enrichWithLLM sends the explanation to the LLM for plain-English enrichment.
func enrichWithLLM(explanation, namespace, subject string) (string, error) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("no LLM API key found (set ANTHROPIC_API_KEY)")
	}

	client, err := llm.NewClient(apiKey)
	if err != nil {
		return "", err
	}

	prompt := fmt.Sprintf(`You are a Kubernetes RBAC security auditor.
A user has asked you to explain why subject "%s" has access to namespace "%s".

Here is the raw access explanation from the rbac-therapist operator:

%s

Please rewrite this as a clear, professional plain-English explanation that:
1. Summarizes what access the subject has
2. Explains the chain of ownership (team → policy → binding)
3. Quotes the policy rationale verbatim
4. Notes any concerns (expired policies, overly broad access, missing rationale)
5. Is suitable for inclusion in a security audit report

Be concise but complete. Use bullet points for clarity.`, subject, namespace, explanation)

	return client.Complete(context.Background(), prompt)
}
