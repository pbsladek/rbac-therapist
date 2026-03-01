package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	rbacv1 "k8s.io/api/rbac/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/hasher"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/parser"
)

func newDiffCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff [files...]",
		Short: "Show what would change if manifests were applied",
		Long: `Compare the current cluster state to the desired state described
by the given AccessPolicy manifest files.

For each AccessPolicy, the diff shows:
  + RoleBindings / ClusterRoleBindings that would be CREATED
  ~ RoleBindings / ClusterRoleBindings that already exist (no change)
  - RoleBindings / ClusterRoleBindings that would be DELETED (stale)

Namespace and Team data is read from the live cluster to accurately
resolve matchTeamTags and label selectors.

Exit codes:
  0 — no changes would be made
  1 — changes detected`,
		Example: `  rbact diff ./manifests/rbac/accesspolicy-platform.yaml
  rbact diff ./manifests/rbac/*.yaml`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(args)
		},
	}
	return cmd
}

func runDiff(files []string) error {
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

	var teamList therapistv1alpha1.TeamList
	if err := c.List(ctx, &teamList); err != nil {
		return fmt.Errorf("listing Teams: %w", err)
	}
	var nsList corev1.NamespaceList
	if err := c.List(ctx, &nsList); err != nil {
		return fmt.Errorf("listing Namespaces: %w", err)
	}

	codecs := serializer.NewCodecFactory(scheme)
	totalAdds, totalNoChange, totalDeletes := 0, 0, 0

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", file, err)
			continue
		}

		for _, doc := range splitYAMLDocs(string(data)) {
			if strings.TrimSpace(doc) == "" {
				continue
			}
			obj, _, decErr := codecs.UniversalDeserializer().Decode([]byte(doc), nil, nil)
			if decErr != nil {
				continue
			}
			policy, ok := obj.(*therapistv1alpha1.AccessPolicy)
			if !ok {
				continue
			}
			a, n, d := diffPolicy(ctx, c, policy, teamList.Items, nsList.Items)
			totalAdds += a
			totalNoChange += n
			totalDeletes += d
		}
	}

	fmt.Printf("\nSummary: +%d to create, ~%d unchanged, -%d to delete\n",
		totalAdds, totalNoChange, totalDeletes)

	if totalAdds == 0 && totalDeletes == 0 {
		fmt.Println("No changes detected.")
		return nil
	}
	return fmt.Errorf("changes detected: %d to create, %d to delete", totalAdds, totalDeletes)
}

func diffPolicy(
	ctx context.Context,
	c client.Client,
	policy *therapistv1alpha1.AccessPolicy,
	teams []therapistv1alpha1.Team,
	namespaces []corev1.Namespace,
) (adds, noChange, deletes int) {
	fmt.Printf("\nAccessPolicy: %s\n", policy.Name)
	fmt.Println(strings.Repeat("─", 60))

	desired := parser.Parse(parser.Input{
		Policy:     *policy,
		Teams:      teams,
		Namespaces: namespaces,
	})

	desiredNames := map[string]bool{}
	for _, db := range desired {
		desiredNames[db.Name] = true

		bindingKind := "RoleBinding"
		if db.ClusterWide {
			bindingKind = "ClusterRoleBinding"
		}

		exists := bindingExists(ctx, c, db.Name, db.Namespace, db.ClusterWide)
		if exists {
			fmt.Printf("  ~ %-22s %s (ns: %s)\n", bindingKind, db.Name, db.Namespace)
			noChange++
		} else {
			fmt.Printf("  + %-22s %s (ns: %s)\n", bindingKind, db.Name, db.Namespace)
			adds++
		}
	}

	// Stale bindings — exist in cluster with our label but not in the desired set.
	var rbList rbacv1.RoleBindingList
	if err := c.List(ctx, &rbList, client.MatchingLabels{
		hasher.ManagedByLabel: hasher.ManagedByValue,
		hasher.PolicyLabel:    policy.Name,
	}); err == nil {
		for _, rb := range rbList.Items {
			if !desiredNames[rb.Name] {
				fmt.Printf("  - %-22s %s (ns: %s)\n", "RoleBinding", rb.Name, rb.Namespace)
				deletes++
			}
		}
	}

	var crbList rbacv1.ClusterRoleBindingList
	if err := c.List(ctx, &crbList, client.MatchingLabels{
		hasher.ManagedByLabel: hasher.ManagedByValue,
		hasher.PolicyLabel:    policy.Name,
	}); err == nil {
		for _, crb := range crbList.Items {
			if !desiredNames[crb.Name] {
				fmt.Printf("  - %-22s %s\n", "ClusterRoleBinding", crb.Name)
				deletes++
			}
		}
	}

	if adds == 0 && deletes == 0 {
		fmt.Println("  (no changes)")
	}

	return adds, noChange, deletes
}

func bindingExists(ctx context.Context, c client.Client, name, namespace string, clusterWide bool) bool {
	if clusterWide {
		var crb rbacv1.ClusterRoleBinding
		return c.Get(ctx, client.ObjectKey{Name: name}, &crb) == nil
	}
	var rb rbacv1.RoleBinding
	return c.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, &rb) == nil
}
