package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
)

func newExpireCommand() *cobra.Command {
	var (
		kind    string
		confirm bool
	)

	cmd := &cobra.Command{
		Use:   "expire <name>",
		Short: "Immediately expire an AccessPolicy or RBACBinding",
		Long: `Set expiresAt to now on the specified resource.

The operator will detect the updated expiry on its next reconcile cycle
and remove all managed RoleBindings/ClusterRoleBindings.

Use this for emergency access revocation.

Supported kinds: accesspolicy (ap), rbacbinding (rb)

Examples:
  # Expire an AccessPolicy (emergency revocation)
  rbact expire platform-developer-access --kind accesspolicy

  # Expire an RBACBinding
  rbact expire break-glass-admin --kind rbacbinding

  # Skip the confirmation prompt (for scripting)
  rbact expire break-glass-admin --kind rbacbinding --confirm`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExpire(args[0], kind, confirm)
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "accesspolicy",
		"Resource kind: accesspolicy (ap) or rbacbinding (rb)")
	cmd.Flags().BoolVar(&confirm, "confirm", false,
		"Skip the confirmation prompt (use in scripts)")

	return cmd
}

func runExpire(name, kind string, confirmed bool) error {
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

	switch normalizeKind(kind) {
	case "accesspolicy":
		return expireAccessPolicy(ctx, c, name, confirmed)
	case "rbacbinding":
		return expireRBACBinding(ctx, c, name, confirmed)
	default:
		return fmt.Errorf("unknown kind %q — use accesspolicy or rbacbinding", kind)
	}
}

func expireAccessPolicy(ctx context.Context, c client.Client, name string, confirmed bool) error {
	var policy therapistv1alpha1.AccessPolicy
	if err := c.Get(ctx, types.NamespacedName{Name: name}, &policy); err != nil {
		return fmt.Errorf("AccessPolicy %q not found: %w", name, err)
	}

	if !confirmed {
		fmt.Printf("This will immediately expire AccessPolicy %q, revoking access for %d subject(s).\n",
			name, len(policy.Spec.Subjects))
		fmt.Printf("Rationale was: %s\n\n", policy.Spec.Rationale)
		fmt.Print("Are you sure? [y/N] ")
		var resp string
		_, _ = fmt.Scanln(&resp)
		if resp != "y" && resp != "Y" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	patch := client.MergeFrom(policy.DeepCopy())
	now := metav1.Now()
	policy.Spec.ExpiresAt = &now
	if err := c.Patch(ctx, &policy, patch); err != nil {
		return fmt.Errorf("patching AccessPolicy: %w", err)
	}

	fmt.Printf("AccessPolicy %q has been expired. The operator will revoke all managed bindings shortly.\n", name)
	fmt.Println("Run 'rbact snapshot --wait' to confirm the snapshot is updated.")
	return nil
}

func expireRBACBinding(ctx context.Context, c client.Client, name string, confirmed bool) error {
	var binding therapistv1alpha1.RBACBinding
	if err := c.Get(ctx, types.NamespacedName{Name: name}, &binding); err != nil {
		return fmt.Errorf("RBACBinding %q not found: %w", name, err)
	}

	if !confirmed {
		fmt.Printf("This will immediately expire RBACBinding %q.\n", name)
		fmt.Printf("Rationale was: %s\n\n", binding.Spec.Rationale)
		fmt.Print("Are you sure? [y/N] ")
		var resp string
		_, _ = fmt.Scanln(&resp)
		if resp != "y" && resp != "Y" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	patch := client.MergeFrom(binding.DeepCopy())
	now := metav1.Now()
	binding.Spec.ExpiresAt = &now
	if err := c.Patch(ctx, &binding, patch); err != nil {
		return fmt.Errorf("patching RBACBinding: %w", err)
	}

	fmt.Printf("RBACBinding %q has been expired. The operator will revoke the managed binding shortly.\n", name)
	return nil
}

// normalizeKind normalizes common aliases to canonical kind names.
func normalizeKind(kind string) string {
	switch kind {
	case "ap", "accesspolicies", "accesspolicy", "AccessPolicy":
		return "accesspolicy"
	case "rb", "rbacbindings", "rbacbinding", "RBACBinding":
		return "rbacbinding"
	default:
		return kind
	}
}
