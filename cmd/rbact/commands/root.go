// Package commands contains all rbact CLI command definitions.
package commands

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GlobalFlags are flags available on all subcommands.
type GlobalFlags struct {
	KubeContext string
	Kubeconfig  string
	Namespace   string
	Output      string // text, json, yaml
}

var globalFlags GlobalFlags

// NewRootCommand returns the root cobra command for rbact.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "rbact",
		Short: "rbac-therapist CLI — Kubernetes RBAC that's finally healthy",
		Long: `rbact is the command-line companion to the rbac-therapist operator.

It helps you generate, validate, visualize, and audit Kubernetes RBAC
access policies managed by rbac-therapist.

Think of rbact as your RBAC therapist:
  - It helps you understand complex access patterns
  - It explains why someone has (or doesn't have) access
  - It generates dependency graphs so you can see the whole picture
  - It uses LLMs to write plain-English audit reports

Therapy note: Your RBAC has trust issues. We're here to help.`,
		SilenceUsage: true,
	}

	// Global flags.
	root.PersistentFlags().StringVar(&globalFlags.KubeContext, "context", "", "Kubernetes context to use")
	root.PersistentFlags().StringVar(&globalFlags.Kubeconfig, "kubeconfig", "", "Path to kubeconfig (defaults to $KUBECONFIG or ~/.kube/config)")
	root.PersistentFlags().StringVarP(&globalFlags.Output, "output", "o", "text", "Output format: text, json, yaml")

	viper.AutomaticEnv()
	viper.SetEnvPrefix("RBACT")

	// Register subcommands.
	root.AddCommand(
		newGenerateCommand(),
		newValidateCommand(),
		newGraphCommand(),
		newExplainCommand(),
		newAuditCommand(),
		newWhoCanCommand(),
		newDiffCommand(),
		newSnapshotCommand(),
		newExpireCommand(),
	)

	return root
}
