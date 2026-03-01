package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	sessionctrl "github.com/rbac-therapist/rbac-therapist/internal/controllers/session"
)

func newSnapshotCommand() *cobra.Command {
	var wait bool

	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Force-refresh the RBACSession snapshot",
		Long: `Trigger the operator to regenerate the RBACSession immediately.

By default, the operator refreshes the session periodically (every 5 minutes).
Use this command after applying new policies to get an up-to-date view in
tools like 'rbact explain', 'rbact who-can', and 'rbact audit'.

The command sets the rbac.therapist.io/force-refresh annotation on the
RBACSession "current" object. The operator picks this up on its next
reconcile cycle and regenerates the snapshot, then removes the annotation.

With --wait, the command polls until the snapshot is updated.`,
		Example: `  # Trigger a refresh
  rbact snapshot

  # Trigger and wait for the refresh to complete
  rbact snapshot --wait`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSnapshot(wait)
		},
	}

	cmd.Flags().BoolVar(&wait, "wait", false, "Wait for the snapshot to be refreshed after triggering")

	return cmd
}

func runSnapshot(wait bool) error {
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

	// Fetch the current session.
	var session therapistv1alpha1.RBACSession
	if err := c.Get(ctx, types.NamespacedName{Name: sessionctrl.SessionName}, &session); err != nil {
		return fmt.Errorf("getting RBACSession %q: %w\n\nIs the rbac-therapist operator running?", sessionctrl.SessionName, err)
	}

	// Record the current generatedAt so we can detect when a new snapshot arrives.
	var prevGeneratedAt *metav1.Time
	if session.Status.GeneratedAt != nil {
		t := *session.Status.GeneratedAt
		prevGeneratedAt = &t
	}

	// Set the force-refresh annotation.
	patch := client.MergeFrom(session.DeepCopy())
	if session.Annotations == nil {
		session.Annotations = make(map[string]string)
	}
	session.Annotations[sessionctrl.ForceRefreshAnnotation] = "true"
	if err := c.Patch(ctx, &session, patch); err != nil {
		return fmt.Errorf("patching RBACSession: %w", err)
	}

	fmt.Printf("Triggered snapshot refresh on RBACSession %q.\n", sessionctrl.SessionName)

	if !wait {
		fmt.Println("Run 'rbact snapshot --wait' to wait for the refresh to complete.")
		return nil
	}

	// Poll until generatedAt advances.
	fmt.Print("Waiting for refresh")
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		fmt.Print(".")

		var updated therapistv1alpha1.RBACSession
		if err := c.Get(ctx, types.NamespacedName{Name: sessionctrl.SessionName}, &updated); err != nil {
			continue
		}

		if updated.Status.GeneratedAt == nil {
			continue
		}
		if prevGeneratedAt == nil || updated.Status.GeneratedAt.After(prevGeneratedAt.Time) {
			fmt.Println(" done!")
			fmt.Printf("RBACSession refreshed at %s\n", updated.Status.GeneratedAt.Format(time.RFC3339))
			fmt.Printf("Subjects tracked: %d\n", len(updated.Status.SubjectAccess))
			fmt.Printf("Namespaces tracked: %d\n", len(updated.Status.NamespaceAccess))
			if len(updated.Status.Warnings) > 0 {
				fmt.Printf("Warnings: %d\n", len(updated.Status.Warnings))
				for _, w := range updated.Status.Warnings {
					fmt.Printf("  ⚠  %s\n", w)
				}
			}
			return nil
		}
	}

	fmt.Println()
	return fmt.Errorf("timed out waiting for snapshot refresh — is the operator running?")
}
