package commands

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	"github.com/rbac-therapist/rbac-therapist/pkg/llm"
)

func newAuditCommand() *cobra.Command {
	var (
		llmMode    bool
		outputFile string
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Generate a full cluster RBAC audit report",
		Long: `Generate a comprehensive audit report of all RBAC access managed
by rbac-therapist.

Without --llm, the report is a structured text summary covering:
  - All active AccessPolicies with subject counts and binding counts
  - All active RBACBindings with expiry status
  - Warnings: expired resources, cluster-admin grants, missing expiries
  - Summary statistics

With --llm (requires ANTHROPIC_API_KEY), an LLM enriches the report with:
  - Plain-English risk assessment for high-privilege access
  - Recommendations for policy hygiene
  - Identification of suspicious or overly broad access patterns
  - Executive summary suitable for security reviews

The report reads from the current RBACSession session-notes snapshot.
Run 'rbact snapshot --wait' first for the most up-to-date view.`,
		Example: `  # Generate a structured text audit report
  rbact audit

  # Generate an LLM-enriched audit report
  rbact audit --llm

  # Save the report to a file
  rbact audit --llm -o audit-report.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAudit(llmMode, outputFile)
		},
	}

	cmd.Flags().BoolVar(&llmMode, "llm", false, "Enrich the report with LLM analysis (requires ANTHROPIC_API_KEY)")
	cmd.Flags().StringVarP(&outputFile, "output-file", "o", "", "Write report to this file instead of stdout")

	return cmd
}

func runAudit(useLLM bool, outputFile string) error {
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
		return fmt.Errorf("getting RBACSession: %w\n\nRun 'rbact snapshot' to generate one", err)
	}

	var policies therapistv1alpha1.AccessPolicyList
	if err := c.List(ctx, &policies); err != nil {
		return fmt.Errorf("listing AccessPolicies: %w", err)
	}

	var rbacBindings therapistv1alpha1.RBACBindingList
	if err := c.List(ctx, &rbacBindings); err != nil {
		return fmt.Errorf("listing RBACBindings: %w", err)
	}

	report := buildAuditReport(session, policies.Items, rbacBindings.Items)

	if useLLM {
		enriched, err := enrichAuditWithLLM(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: LLM enrichment failed: %v\n", err)
			fmt.Fprintln(os.Stderr, "falling back to plain report")
		} else {
			report = enriched
		}
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(report), 0644); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		fmt.Printf("Report written to %s\n", outputFile)
		return nil
	}

	fmt.Print(report)
	return nil
}

func buildAuditReport(
	session therapistv1alpha1.RBACSession,
	policies []therapistv1alpha1.AccessPolicy,
	bindings []therapistv1alpha1.RBACBinding,
) string {
	var sb strings.Builder

	sb.WriteString("# rbac-therapist Cluster RBAC Audit Report\n\n")
	if session.Status.GeneratedAt != nil {
		sb.WriteString(fmt.Sprintf("**Snapshot generated:** %s\n\n", session.Status.GeneratedAt.Format(time.RFC3339)))
	}

	// --- Summary statistics ---
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Metric | Value |\n|--------|-------|\n"))
	sb.WriteString(fmt.Sprintf("| AccessPolicies | %d |\n", len(policies)))
	sb.WriteString(fmt.Sprintf("| RBACBindings | %d |\n", len(bindings)))
	sb.WriteString(fmt.Sprintf("| Subjects tracked | %d |\n", len(session.Status.SubjectAccess)))
	sb.WriteString(fmt.Sprintf("| Namespaces with access | %d |\n", len(session.Status.NamespaceAccess)))
	sb.WriteString(fmt.Sprintf("| Session warnings | %d |\n", len(session.Status.Warnings)))
	sb.WriteString("\n")

	// --- Warnings ---
	if len(session.Status.Warnings) > 0 {
		sb.WriteString("## Warnings\n\n")
		for _, w := range session.Status.Warnings {
			sb.WriteString(fmt.Sprintf("- ⚠️  %s\n", w))
		}
		sb.WriteString("\n")
	}

	// --- AccessPolicies ---
	sb.WriteString("## AccessPolicies\n\n")
	active, paused, expired := 0, 0, 0
	clusterAdmins := []string{}

	for _, p := range policies {
		status := "active"
		if p.Spec.Paused {
			status = "paused"
			paused++
		} else if p.Spec.ExpiresAt != nil && p.Spec.ExpiresAt.Before(&metav1.Time{Time: time.Now()}) {
			status = "EXPIRED"
			expired++
		} else {
			active++
		}

		sb.WriteString(fmt.Sprintf("### %s (%s)\n\n", p.Name, status))
		sb.WriteString(fmt.Sprintf("**Rationale:** %s\n\n", p.Spec.Rationale))
		sb.WriteString(fmt.Sprintf("**Subjects:** %d  |  **Managed bindings:** %d\n\n",
			len(p.Spec.Subjects), len(p.Status.ManagedBindings)))

		if p.Spec.ExpiresAt != nil {
			sb.WriteString(fmt.Sprintf("**Expires:** %s\n\n", p.Spec.ExpiresAt.Format(time.RFC3339)))
		}

		for _, role := range p.Spec.Roles {
			if role.ClusterRole == "cluster-admin" {
				clusterAdmins = append(clusterAdmins, p.Name)
			}
		}
	}

	sb.WriteString(fmt.Sprintf("**Policy status:** %d active, %d paused, %d expired\n\n", active, paused, expired))

	// --- RBACBindings ---
	sb.WriteString("## RBACBindings\n\n")
	if len(bindings) == 0 {
		sb.WriteString("No RBACBindings found.\n\n")
	} else {
		sb.WriteString("| Name | Role | Expires | Rationale |\n|------|------|---------|-----------|")
		for _, b := range bindings {
			expiry := "none (no expiry set)"
			if b.Spec.ExpiresAt != nil {
				expiry = b.Spec.ExpiresAt.Format("2006-01-02")
			}
			role := b.Spec.ClusterRole
			if role == "" {
				role = b.Spec.Role
			}
			sb.WriteString(fmt.Sprintf("\n| %s | %s | %s | %s |",
				b.Name, role, expiry, truncateString(b.Spec.Rationale, 60)))
		}
		sb.WriteString("\n\n")
	}

	// --- High-privilege grants ---
	if len(clusterAdmins) > 0 {
		sb.WriteString("## High-Privilege Access (cluster-admin)\n\n")
		sb.WriteString("The following AccessPolicies grant cluster-admin — review carefully:\n\n")
		for _, name := range clusterAdmins {
			sb.WriteString(fmt.Sprintf("- %s\n", name))
		}
		sb.WriteString("\n")
	}

	// --- Subjects summary ---
	sb.WriteString("## Subject Access Summary\n\n")
	sb.WriteString("| Subject | Kind | Teams | Grants |\n|---------|------|-------|--------|")
	for _, sa := range session.Status.SubjectAccess {
		teams := strings.Join(sa.Teams, ", ")
		if teams == "" {
			teams = "(none)"
		}
		sb.WriteString(fmt.Sprintf("\n| %s | %s | %s | %d |",
			sa.Subject.Name, sa.Subject.Kind, teams, len(sa.Access)))
	}
	sb.WriteString("\n\n")

	return sb.String()
}

func enrichAuditWithLLM(report string) (string, error) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	llmClient, err := llm.NewClient(apiKey)
	if err != nil {
		return "", err
	}

	prompt := fmt.Sprintf(`You are a senior Kubernetes security engineer conducting a RBAC audit.
Below is a structured audit report from the rbac-therapist operator.

Your job is to enrich this report with:
1. An executive summary (2-3 sentences) suitable for a security review board
2. A risk assessment for any high-privilege access (cluster-admin, etc.)
3. Specific, actionable recommendations for improving RBAC hygiene
4. Identification of any suspicious patterns (overly broad access, missing expiries on break-glass bindings, etc.)
5. Positive observations (policies that are well-structured, appropriate expiries, good rationale)

Format your additions as additional sections after the existing content.
Use Markdown. Be concise and specific — avoid generic advice.

AUDIT REPORT:
%s`, report)

	enriched, err := llmClient.Complete(context.Background(), prompt)
	if err != nil {
		return "", err
	}

	return report + "\n---\n\n## LLM Security Analysis\n\n" + enriched, nil
}
