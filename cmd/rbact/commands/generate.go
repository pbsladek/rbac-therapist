package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GenerateConfig is the user-facing YAML config format for `rbact generate`.
// It is simpler than the CRDs — designed for humans to write, not operators to consume.
type GenerateConfig struct {
	Teams    []GenerateTeam    `json:"teams,omitempty"`
	Policies []GeneratePolicy  `json:"policies,omitempty"`
}

type GenerateTeam struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Members     []GenerateMember  `json:"members,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Extends     []string          `json:"extends,omitempty"`
}

type GenerateMember struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type GeneratePolicy struct {
	Name      string          `json:"name"`
	Teams     []string        `json:"teams,omitempty"`
	Subjects  []GenerateMember `json:"subjects,omitempty"`
	Rationale string          `json:"rationale"`
	Access    []GenerateAccess `json:"access,omitempty"`
	ExpiresAt string          `json:"expiresAt,omitempty"`
}

type GenerateAccess struct {
	ClusterRole   string   `json:"clusterRole,omitempty"`
	Role          string   `json:"role,omitempty"`
	ClusterWide   bool     `json:"clusterWide,omitempty"`
	Namespaces    []string `json:"namespaces,omitempty"`
	MatchSelector map[string]string `json:"matchSelector,omitempty"`
	MatchTeamTags bool     `json:"matchTeamTags,omitempty"`
}

func newGenerateCommand() *cobra.Command {
	var (
		configFile string
		outputDir  string
		stdout     bool
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate CRD manifests from a simple YAML config file",
		Long: `Generate Team and AccessPolicy CRD manifests from a human-friendly
config file format. The generated manifests can be checked into git and
applied by ArgoCD or kubectl.

Example:
  rbact generate -f rbact-config.yaml -o ./manifests/rbac/

The config file format is simpler than the CRDs — it is designed for
humans to write and review, not for operators to consume directly.`,
		Example: `  # Generate manifests from a config file to a directory
  rbact generate -f rbact-config.yaml -o ./manifests/rbac/

  # Print manifests to stdout
  rbact generate -f rbact-config.yaml --stdout`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate(configFile, outputDir, stdout)
		},
	}

	cmd.Flags().StringVarP(&configFile, "file", "f", "", "Path to the rbact config file (required)")
	cmd.Flags().StringVarP(&outputDir, "output-dir", "d", "./manifests/rbac", "Directory to write generated manifests")
	cmd.Flags().BoolVar(&stdout, "stdout", false, "Print manifests to stdout instead of writing files")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

func runGenerate(configFile, outputDir string, stdout bool) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}

	var cfg GenerateConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing config file: %w", err)
	}

	manifests, err := generateManifests(cfg)
	if err != nil {
		return err
	}

	if stdout {
		for _, m := range manifests {
			fmt.Println("---")
			fmt.Print(m)
		}
		return nil
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	for name, content := range manifests {
		path := filepath.Join(outputDir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
		fmt.Printf("wrote %s\n", path)
	}

	return nil
}

// generateManifests converts a GenerateConfig into a map of filename → YAML content.
func generateManifests(cfg GenerateConfig) (map[string]string, error) {
	result := make(map[string]string)

	for _, t := range cfg.Teams {
		team := convertTeam(t)
		data, err := marshalResource(team)
		if err != nil {
			return nil, fmt.Errorf("marshaling team %s: %w", t.Name, err)
		}
		result[fmt.Sprintf("team-%s.yaml", t.Name)] = data
	}

	for _, p := range cfg.Policies {
		policy, err := convertPolicy(p)
		if err != nil {
			return nil, fmt.Errorf("converting policy %s: %w", p.Name, err)
		}
		data, err := marshalResource(policy)
		if err != nil {
			return nil, fmt.Errorf("marshaling policy %s: %w", p.Name, err)
		}
		result[fmt.Sprintf("accesspolicy-%s.yaml", p.Name)] = data
	}

	return result, nil
}

func convertTeam(t GenerateTeam) therapistv1alpha1.Team {
	team := therapistv1alpha1.Team{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.therapist.io/v1alpha1",
			Kind:       "Team",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: t.Name,
		},
		Spec: therapistv1alpha1.TeamSpec{
			Description: t.Description,
			Tags:        t.Tags,
		},
	}

	for _, m := range t.Members {
		team.Spec.Members = append(team.Spec.Members, rbacv1.Subject{
			Kind:      m.Kind,
			Name:      m.Name,
			Namespace: m.Namespace,
		})
	}

	for _, e := range t.Extends {
		team.Spec.Extends = append(team.Spec.Extends, therapistv1alpha1.TeamReference{Name: e})
	}

	return team
}

func convertPolicy(p GeneratePolicy) (therapistv1alpha1.AccessPolicy, error) {
	policy := therapistv1alpha1.AccessPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.therapist.io/v1alpha1",
			Kind:       "AccessPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: p.Name,
		},
		Spec: therapistv1alpha1.AccessPolicySpec{
			Rationale: p.Rationale,
		},
	}

	// Add team subjects.
	for _, teamName := range p.Teams {
		policy.Spec.Subjects = append(policy.Spec.Subjects, therapistv1alpha1.PolicySubject{
			TeamRef: &therapistv1alpha1.TeamReference{Name: teamName},
		})
	}

	// Add inline subjects.
	for _, s := range p.Subjects {
		policy.Spec.Subjects = append(policy.Spec.Subjects, therapistv1alpha1.PolicySubject{
			Inline: &rbacv1.Subject{
				Kind:      s.Kind,
				Name:      s.Name,
				Namespace: s.Namespace,
			},
		})
	}

	// Convert access grants.
	for _, a := range p.Access {
		role := therapistv1alpha1.PolicyRole{
			ClusterRole: a.ClusterRole,
			Role:        a.Role,
			ClusterWide: a.ClusterWide,
		}

		if !a.ClusterWide {
			nsSel := &therapistv1alpha1.NamespaceSelector{
				Names:         a.Namespaces,
				MatchTeamTags: a.MatchTeamTags,
			}
			if len(a.MatchSelector) > 0 {
				nsSel.Selector = &metav1.LabelSelector{
					MatchLabels: a.MatchSelector,
				}
			}
			role.Namespaces = nsSel
		}

		policy.Spec.Roles = append(policy.Spec.Roles, role)
	}

	return policy, nil
}

func marshalResource(obj interface{}) (string, error) {
	data, err := yaml.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
