package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/yaml"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
)

func newValidateCommand() *cobra.Command {
	var online bool

	cmd := &cobra.Command{
		Use:   "validate [files...]",
		Short: "Validate AccessPolicy, Team, and RBACBinding manifests",
		Long: `Validate one or more AccessPolicy, Team, or RBACBinding YAML files.

Offline checks (always run):
  - Schema validity (required fields, field constraints)
  - Rationale is at least 10 characters
  - Role fields are mutually exclusive and consistent
  - Namespace/clusterWide consistency
  - matchTeamTags without teamRef subjects (warning)

Online checks (with --online, requires cluster access):
  - ClusterRole references exist in the cluster
  - TeamRef references exist as Team CRDs

Exit codes:
  0 — all files valid (errors = 0)
  1 — validation errors found`,
		Example: `  # Validate files offline
  rbact validate ./manifests/rbac/*.yaml

  # Validate with live cluster checks
  rbact validate --online ./manifests/rbac/*.yaml`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidate(args, online)
		},
	}

	cmd.Flags().BoolVar(&online, "online", false, "Check against live cluster (role references, team existence)")

	return cmd
}

type validateResult struct {
	File     string
	Kind     string
	Name     string
	Errors   []string
	Warnings []string
}

func runValidate(files []string, online bool) error {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(therapistv1alpha1.AddToScheme(scheme))

	ctx := context.Background()

	var c client.Client
	if online {
		cfg, err := config.GetConfig()
		if err != nil {
			return fmt.Errorf("getting kubeconfig for online checks: %w", err)
		}
		var clientErr error
		c, clientErr = client.New(cfg, client.Options{Scheme: scheme})
		if clientErr != nil {
			return fmt.Errorf("creating client: %w", clientErr)
		}
	}

	codecs := serializer.NewCodecFactory(scheme)
	var results []validateResult
	hasErrors := false

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", file, err)
			hasErrors = true
			continue
		}

		for _, doc := range splitYAMLDocs(string(data)) {
			if strings.TrimSpace(doc) == "" {
				continue
			}
			res := validateDoc(ctx, []byte(doc), file, codecs, c)
			results = append(results, res)
			if len(res.Errors) > 0 {
				hasErrors = true
			}
		}
	}

	// Print results.
	passed := 0
	for _, res := range results {
		if len(res.Errors) == 0 && len(res.Warnings) == 0 {
			fmt.Printf("✓ %s (%s/%s)\n", res.File, res.Kind, res.Name)
			passed++
			continue
		}
		if len(res.Errors) == 0 {
			// Warnings only — still passes.
			fmt.Printf("⚠ %s (%s/%s)\n", res.File, res.Kind, res.Name)
			passed++
		} else {
			fmt.Printf("✗ %s (%s/%s)\n", res.File, res.Kind, res.Name)
		}
		for _, e := range res.Errors {
			fmt.Printf("  ERROR: %s\n", e)
		}
		for _, w := range res.Warnings {
			fmt.Printf("  WARN:  %s\n", w)
		}
	}

	total := len(results)
	errored := total - passed
	fmt.Printf("\n%d/%d valid", passed, total)
	if errored > 0 {
		fmt.Printf(", %d with errors", errored)
	}
	fmt.Println()

	if hasErrors {
		return fmt.Errorf("validation failed")
	}
	return nil
}

func validateDoc(ctx context.Context, data []byte, file string, codecs serializer.CodecFactory, c client.Client) validateResult {
	res := validateResult{File: file}

	// Detect kind via raw YAML parse (for the display name before full decode).
	var typeMeta struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	_ = yaml.Unmarshal(data, &typeMeta)
	res.Kind = typeMeta.Kind
	res.Name = typeMeta.Metadata.Name

	obj, _, err := codecs.UniversalDeserializer().Decode(data, nil, nil)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("decode error: %v", err))
		return res
	}

	switch typed := obj.(type) {
	case *therapistv1alpha1.AccessPolicy:
		validateAccessPolicy(ctx, typed, &res, c)
	case *therapistv1alpha1.Team:
		validateTeam(ctx, typed, &res, c)
	case *therapistv1alpha1.RBACBinding:
		validateRBACBindingOffline(typed, &res)
	default:
		res.Warnings = append(res.Warnings, fmt.Sprintf("kind %q — no rbact-specific checks apply", typeMeta.Kind))
	}

	return res
}

func validateAccessPolicy(ctx context.Context, policy *therapistv1alpha1.AccessPolicy, res *validateResult, c client.Client) {
	if len(policy.Spec.Rationale) < 10 {
		res.Errors = append(res.Errors, "spec.rationale must be at least 10 characters")
	}
	if len(policy.Spec.Subjects) == 0 {
		res.Errors = append(res.Errors, "spec.subjects must have at least one entry")
	}
	if len(policy.Spec.Roles) == 0 {
		res.Errors = append(res.Errors, "spec.roles must have at least one entry")
	}

	for i, role := range policy.Spec.Roles {
		if role.ClusterRole == "" && role.Role == "" {
			res.Errors = append(res.Errors, fmt.Sprintf("spec.roles[%d]: either clusterRole or role must be set", i))
		}
		if role.ClusterRole != "" && role.Role != "" {
			res.Errors = append(res.Errors, fmt.Sprintf("spec.roles[%d]: clusterRole and role are mutually exclusive", i))
		}
		if !role.ClusterWide && role.Namespaces == nil {
			res.Errors = append(res.Errors, fmt.Sprintf("spec.roles[%d]: namespaces must be set when clusterWide is false", i))
		}
		if role.ClusterWide && role.Namespaces != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("spec.roles[%d]: namespaces must not be set when clusterWide is true", i))
		}
		if role.Namespaces != nil && role.Namespaces.MatchTeamTags {
			hasTeamRef := false
			for _, s := range policy.Spec.Subjects {
				if s.TeamRef != nil {
					hasTeamRef = true
					break
				}
			}
			if !hasTeamRef {
				res.Warnings = append(res.Warnings, fmt.Sprintf(
					"spec.roles[%d].namespaces.matchTeamTags is true but no subjects use teamRef", i))
			}
		}
	}

	for i, s := range policy.Spec.Subjects {
		if s.TeamRef == nil && s.Inline == nil {
			res.Errors = append(res.Errors, fmt.Sprintf("spec.subjects[%d]: either teamRef or inline must be set", i))
		}
		if s.TeamRef != nil && s.Inline != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("spec.subjects[%d]: teamRef and inline are mutually exclusive", i))
		}
	}

	if c == nil {
		return
	}

	// Online: check teamRef existence.
	for _, s := range policy.Spec.Subjects {
		if s.TeamRef != nil {
			var team therapistv1alpha1.Team
			if err := c.Get(ctx, client.ObjectKey{Name: s.TeamRef.Name}, &team); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("teamRef %q does not exist in cluster yet", s.TeamRef.Name))
			}
		}
	}
	// Online: check clusterRole existence.
	for i, role := range policy.Spec.Roles {
		if role.ClusterRole != "" {
			var cr rbacv1.ClusterRole
			if err := c.Get(ctx, client.ObjectKey{Name: role.ClusterRole}, &cr); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("spec.roles[%d].clusterRole %q does not exist in cluster", i, role.ClusterRole))
			}
		}
	}
}

func validateTeam(ctx context.Context, team *therapistv1alpha1.Team, res *validateResult, c client.Client) {
	if len(team.Spec.Members) == 0 && len(team.Spec.Extends) == 0 {
		res.Warnings = append(res.Warnings, "team has no members and no extends — it will have no effective members")
	}

	if c == nil {
		return
	}

	for _, ext := range team.Spec.Extends {
		var t therapistv1alpha1.Team
		if err := c.Get(ctx, client.ObjectKey{Name: ext.Name}, &t); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("spec.extends references team %q which does not exist in cluster yet", ext.Name))
		}
	}
}

func validateRBACBindingOffline(binding *therapistv1alpha1.RBACBinding, res *validateResult) {
	if len(binding.Spec.Rationale) < 10 {
		res.Errors = append(res.Errors, "spec.rationale must be at least 10 characters")
	}
	if len(binding.Spec.Subjects) == 0 {
		res.Errors = append(res.Errors, "spec.subjects must have at least one entry")
	}
	if binding.Spec.ClusterRole == "" && binding.Spec.Role == "" {
		res.Errors = append(res.Errors, "either spec.clusterRole or spec.role must be set")
	}
	if binding.Spec.ClusterRole != "" && binding.Spec.Role != "" {
		res.Errors = append(res.Errors, "spec.clusterRole and spec.role are mutually exclusive")
	}
	if binding.Spec.ClusterWide && binding.Spec.Namespace != "" {
		res.Errors = append(res.Errors, "spec.namespace must not be set when spec.clusterWide is true")
	}
	if !binding.Spec.ClusterWide && binding.Spec.Namespace == "" {
		res.Errors = append(res.Errors, "spec.namespace is required when spec.clusterWide is false")
	}
	if binding.Spec.ExpiresAt == nil {
		res.Warnings = append(res.Warnings, "spec.expiresAt is not set — RBACBindings should always have an expiry")
	}
}

// splitYAMLDocs splits a multi-document YAML string into individual documents.
func splitYAMLDocs(data string) []string {
	return strings.Split(data, "\n---")
}
