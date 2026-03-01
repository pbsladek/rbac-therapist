package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
)

const (
	sessionNotesName = "current"
	rbacBinding      = "crisis-intervention-pass"
	defaultTimeout   = 12 * time.Minute

	operatorNamespace  = "rbac-therapist-system"
	operatorDeployment = "rbac-therapist-controller-manager"
)

func main() {
	timeout := defaultTimeout
	if v := os.Getenv("K3D_INTEGRATION_TIMEOUT"); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			failf("invalid K3D_INTEGRATION_TIMEOUT %q: %v", v, err)
		}
		if parsed <= 0 {
			failf("K3D_INTEGRATION_TIMEOUT must be > 0, got %q", v)
		}
		timeout = parsed
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(rbacv1.AddToScheme(scheme))
	utilruntime.Must(therapistv1alpha1.AddToScheme(scheme))

	cfg, err := config.GetConfig()
	if err != nil {
		failf("getting kubeconfig: %v", err)
	}
	// Reduce client-side throttling during CI bootstrap and bulk apply phases.
	cfg.QPS = 50
	cfg.Burst = 100

	c, err := ctrlclient.New(cfg, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		failf("creating client: %v", err)
	}

	if err := installOperator(ctx, cfg, c); err != nil {
		failf("installing operator resources: %v", err)
	}

	if err := applyExamples(ctx, cfg); err != nil {
		failf("applying e2e examples: %v", err)
	}

	if err := waitForAccessPolicyReady(ctx, c, "freud-tag-intake-view"); err != nil {
		failf("%v", err)
	}
	if err := waitForAccessPolicyReady(ctx, c, "gottman-repair-protocol"); err != nil {
		failf("%v", err)
	}
	if err := waitForAccessPolicyReady(ctx, c, "boundary-builders-edit"); err != nil {
		failf("%v", err)
	}
	if err := waitForAccessPolicyReady(ctx, c, "deep-work-plan"); err != nil {
		failf("%v", err)
	}
	if err := waitForAccessPolicyReady(ctx, c, "argo-submit-workflows"); err != nil {
		failf("%v", err)
	}
	if err := waitForAccessPolicyReady(ctx, c, "argo-operate-workflows"); err != nil {
		failf("%v", err)
	}
	if err := waitForAccessPolicyReady(ctx, c, "argo-template-audit-read"); err != nil {
		failf("%v", err)
	}
	if err := waitForAccessPolicyReady(ctx, c, "boundary-contracts-e2e"); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "managed ClusterRole boundary-template-reader-e2e exists", func(ctx context.Context) (bool, error) {
		return clusterRoleExists(ctx, c, "boundary-template-reader-e2e")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "managed Role boundary-secret-reader-e2e exists", func(ctx context.Context) (bool, error) {
		return roleExists(ctx, c, "workflow-ops", "boundary-secret-reader-e2e")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "freud-tag policy binds in platform-monitoring namespace", func(ctx context.Context) (bool, error) {
		return roleBindingExists(ctx, c, "platform-monitoring", "freud-tag-intake-view")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "boundary-builders policy binds in app-staging namespace", func(ctx context.Context) (bool, error) {
		return roleBindingExists(ctx, c, "app-staging", "boundary-builders-edit")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "deep-work plan binds in platform-monitoring namespace", func(ctx context.Context) (bool, error) {
		return roleBindingExists(ctx, c, "platform-monitoring", "deep-work-plan")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "deep-work plan binds in app-staging namespace", func(ctx context.Context) (bool, error) {
		return roleBindingExists(ctx, c, "app-staging", "deep-work-plan")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "argo submit policy binds in argo-workflows namespace", func(ctx context.Context) (bool, error) {
		return roleBindingExists(ctx, c, "argo-workflows", "argo-submit-workflows")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "argo submit policy binds in argo-sandbox namespace", func(ctx context.Context) (bool, error) {
		return roleBindingExists(ctx, c, "argo-sandbox", "argo-submit-workflows")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "argo operate policy binds in argo-workflows namespace", func(ctx context.Context) (bool, error) {
		return roleBindingExists(ctx, c, "argo-workflows", "argo-operate-workflows")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "argo template audit policy binds in argo-workflows namespace", func(ctx context.Context) (bool, error) {
		return roleBindingExists(ctx, c, "argo-workflows", "argo-template-audit-read")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "boundary contracts policy binds in workflow-ops namespace", func(ctx context.Context) (bool, error) {
		return roleBindingExists(ctx, c, "workflow-ops", "boundary-contracts-e2e")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "gottman-repair-protocol includes inherited view role", func(ctx context.Context) (bool, error) {
		return accessPolicyHasManagedRole(ctx, c, "gottman-repair-protocol", "view")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "gottman-repair-protocol includes direct admin role", func(ctx context.Context) (bool, error) {
		return accessPolicyHasManagedRole(ctx, c, "gottman-repair-protocol", "admin")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "deep-work-plan includes inherited edit role", func(ctx context.Context) (bool, error) {
		return accessPolicyHasManagedRole(ctx, c, "deep-work-plan", "edit")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "deep-work-plan includes direct admin role", func(ctx context.Context) (bool, error) {
		return accessPolicyHasManagedRole(ctx, c, "deep-work-plan", "admin")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "argo-operate-workflows includes inherited submitter role", func(ctx context.Context) (bool, error) {
		return accessPolicyHasManagedRole(ctx, c, "argo-operate-workflows", "argo-workflow-submitter")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "argo-operate-workflows includes direct operator role", func(ctx context.Context) (bool, error) {
		return accessPolicyHasManagedRole(ctx, c, "argo-operate-workflows", "argo-workflow-operator")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "argo-template-audit-read includes namespaced role", func(ctx context.Context) (bool, error) {
		return accessPolicyHasManagedRole(ctx, c, "argo-template-audit-read", "argo-template-reader")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "boundary-contracts-e2e includes managed namespaced role", func(ctx context.Context) (bool, error) {
		return accessPolicyHasManagedRole(ctx, c, "boundary-contracts-e2e", "boundary-secret-reader-e2e")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "boundary-contracts-e2e includes managed cluster role", func(ctx context.Context) (bool, error) {
		return accessPolicyHasManagedRole(ctx, c, "boundary-contracts-e2e", "boundary-template-reader-e2e")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "RBACBinding Ready", func(ctx context.Context) (bool, error) {
		return isRBACBindingReady(ctx, c, rbacBinding)
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "ClusterRoleBinding created by RBACBinding", func(ctx context.Context) (bool, error) {
		return clusterRoleBindingExists(ctx, c, rbacBinding)
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "RBACSession session-notes include gottman policy", func(ctx context.Context) (bool, error) {
		return sessionHasPolicy(ctx, c, sessionNotesName, "gottman-repair-protocol")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "RBACSession session-notes include deep-work plan", func(ctx context.Context) (bool, error) {
		return sessionHasPolicy(ctx, c, sessionNotesName, "deep-work-plan")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "RBACSession session-notes include argo policy", func(ctx context.Context) (bool, error) {
		return sessionHasPolicy(ctx, c, sessionNotesName, "argo-operate-workflows")
	}); err != nil {
		failf("%v", err)
	}

	if err := waitFor(ctx, "RBACSession session-notes include boundary contracts policy", func(ctx context.Context) (bool, error) {
		return sessionHasPolicy(ctx, c, sessionNotesName, "boundary-contracts-e2e")
	}); err != nil {
		failf("%v", err)
	}

	fmt.Println("k3d integration checks passed")
}

func installOperator(ctx context.Context, cfg *rest.Config, c ctrlclient.Client) error {
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}

	mapper, err := buildRESTMapper(cfg)
	if err != nil {
		return err
	}

	if err := applyManifestGlob(ctx, dc, mapper, "config/crd/bases/*.yaml"); err != nil {
		return err
	}
	if err := waitForAPIResources(ctx, mapper); err != nil {
		return err
	}
	if err := ensureNamespace(ctx, c, operatorNamespace); err != nil {
		return err
	}
	if err := applyManifestFile(ctx, dc, mapper, "config/rbac/service_account.yaml"); err != nil {
		return err
	}
	if err := applyManifestFile(ctx, dc, mapper, "config/rbac/role.yaml"); err != nil {
		return err
	}
	if err := applyManifestFile(ctx, dc, mapper, "config/rbac/role_binding.yaml"); err != nil {
		return err
	}
	if err := applyManifestFile(ctx, dc, mapper, "hack/ci/manifests/operator-deployment-ci.yaml"); err != nil {
		return err
	}

	if err := setOperatorImage(ctx, c); err != nil {
		return err
	}

	return waitFor(ctx, "operator deployment available", func(ctx context.Context) (bool, error) {
		var deploy appsv1.Deployment
		if err := c.Get(ctx, ctrlclient.ObjectKey{
			Namespace: operatorNamespace,
			Name:      operatorDeployment,
		}, &deploy); err != nil {
			return false, err
		}
		return deploy.Status.AvailableReplicas >= 1, nil
	})
}

func ensureNamespace(ctx context.Context, c ctrlclient.Client, name string) error {
	var ns corev1.Namespace
	if err := c.Get(ctx, ctrlclient.ObjectKey{Name: name}, &ns); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	return c.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})
}

func applyExamples(ctx context.Context, cfg *rest.Config) error {
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}
	mapper, err := buildRESTMapper(cfg)
	if err != nil {
		return err
	}
	return applyManifestGlob(ctx, dc, mapper, "examples/e2e/*.yaml")
}

func setOperatorImage(ctx context.Context, c ctrlclient.Client) error {
	image := os.Getenv("OPERATOR_IMAGE")
	if image == "" {
		return fmt.Errorf("OPERATOR_IMAGE is required")
	}

	var deploy appsv1.Deployment
	if err := c.Get(ctx, ctrlclient.ObjectKey{
		Namespace: operatorNamespace,
		Name:      operatorDeployment,
	}, &deploy); err != nil {
		return err
	}
	if len(deploy.Spec.Template.Spec.Containers) == 0 {
		return fmt.Errorf("operator deployment has no containers")
	}

	patch := ctrlclient.MergeFrom(deploy.DeepCopy())
	deploy.Spec.Template.Spec.Containers[0].Image = image
	return c.Patch(ctx, &deploy, patch)
}

func applyManifestGlob(ctx context.Context, dc dynamic.Interface, mapper *restmapper.DeferredDiscoveryRESTMapper, pattern string) error {
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("no files matched pattern %q", pattern)
	}
	for _, p := range paths {
		if err := applyManifestFile(ctx, dc, mapper, p); err != nil {
			return fmt.Errorf("applying %s: %w", p, err)
		}
	}
	return nil
}

func applyManifestFile(ctx context.Context, dc dynamic.Interface, mapper *restmapper.DeferredDiscoveryRESTMapper, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	decoder := utilyaml.NewYAMLOrJSONDecoder(f, 4096)
	for {
		var objMap map[string]any
		if err := decoder.Decode(&objMap); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if len(objMap) == 0 {
			continue
		}
		if err := applyUnstructured(ctx, dc, mapper, objMap); err != nil {
			return err
		}
	}
	return nil
}

func applyUnstructured(ctx context.Context, dc dynamic.Interface, mapper *restmapper.DeferredDiscoveryRESTMapper, objMap map[string]any) error {
	apiVersion, _ := objMap["apiVersion"].(string)
	kind, _ := objMap["kind"].(string)
	if apiVersion == "" || kind == "" {
		return nil
	}

	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return err
	}
	gvk := gv.WithKind(kind)
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return err
	}

	metaMap, _ := objMap["metadata"].(map[string]any)
	name, _ := metaMap["name"].(string)
	namespace, _ := metaMap["namespace"].(string)
	if name == "" {
		return fmt.Errorf("resource %s is missing metadata.name", gvk.String())
	}

	data, err := json.Marshal(objMap)
	if err != nil {
		return err
	}

	resource := dc.Resource(mapping.Resource)
	force := true
	var patchErr error
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		if namespace == "" {
			namespace = "default"
		}
		_, patchErr = resource.Namespace(namespace).Patch(ctx, name, types.ApplyPatchType, data, metav1.PatchOptions{
			FieldManager: "rbact-ci",
			Force:        &force,
		})
	} else {
		_, patchErr = resource.Patch(ctx, name, types.ApplyPatchType, data, metav1.PatchOptions{
			FieldManager: "rbact-ci",
			Force:        &force,
		})
	}

	if apierrors.IsNotFound(patchErr) {
		mapper.Reset()
	}
	return patchErr
}

func buildRESTMapper(cfg *rest.Config) (*restmapper.DeferredDiscoveryRESTMapper, error) {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(discoveryClient)), nil
}

func waitForAPIResources(ctx context.Context, mapper *restmapper.DeferredDiscoveryRESTMapper) error {
	required := []schema.GroupVersionKind{
		{Group: "rbac.therapist.io", Version: "v1alpha1", Kind: "AccessPolicy"},
		{Group: "rbac.therapist.io", Version: "v1alpha1", Kind: "Team"},
		{Group: "rbac.therapist.io", Version: "v1alpha1", Kind: "RBACBinding"},
		{Group: "rbac.therapist.io", Version: "v1alpha1", Kind: "RBACSession"},
	}

	return waitFor(ctx, "rbac-therapist CRD APIs discoverable", func(ctx context.Context) (bool, error) {
		for _, gvk := range required {
			if _, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version); err != nil {
				mapper.Reset()
				return false, nil
			}
		}
		return true, nil
	})
}

func isAccessPolicyReady(ctx context.Context, c ctrlclient.Client, name string) (bool, error) {
	var policy therapistv1alpha1.AccessPolicy
	if err := c.Get(ctx, ctrlclient.ObjectKey{Name: name}, &policy); err != nil {
		return false, err
	}
	return conditionStatus(policy.Status.Conditions, "Ready") == metav1.ConditionTrue, nil
}

func waitForAccessPolicyReady(ctx context.Context, c ctrlclient.Client, name string) error {
	what := fmt.Sprintf("AccessPolicy %s Ready", name)
	if err := waitFor(ctx, what, func(ctx context.Context) (bool, error) {
		return isAccessPolicyReady(ctx, c, name)
	}); err == nil {
		return nil
	}

	var policy therapistv1alpha1.AccessPolicy
	if getErr := c.Get(ctx, ctrlclient.ObjectKey{Name: name}, &policy); getErr != nil {
		return fmt.Errorf("%s: timeout and failed to read policy status: %w", what, getErr)
	}
	cond := findCondition(policy.Status.Conditions, "Ready")
	if cond == nil {
		return fmt.Errorf("%s: timeout and no Ready condition present", what)
	}
	return fmt.Errorf("%s: timeout; latest Ready=%s reason=%s message=%s", what, cond.Status, cond.Reason, cond.Message)
}

func accessPolicyHasManagedRole(ctx context.Context, c ctrlclient.Client, name, role string) (bool, error) {
	var policy therapistv1alpha1.AccessPolicy
	if err := c.Get(ctx, ctrlclient.ObjectKey{Name: name}, &policy); err != nil {
		return false, err
	}
	for _, b := range policy.Status.ManagedBindings {
		if b.RoleName == role {
			return true, nil
		}
	}
	return false, nil
}

func roleBindingExists(ctx context.Context, c ctrlclient.Client, namespace, policy string) (bool, error) {
	var rbs rbacv1.RoleBindingList
	if err := c.List(ctx, &rbs, ctrlclient.InNamespace(namespace), ctrlclient.MatchingLabels{
		"rbac.therapist.io/policy":      policy,
		"rbac.therapist.io/policy-kind": "AccessPolicy",
	}); err != nil {
		return false, err
	}
	return len(rbs.Items) > 0, nil
}

func isRBACBindingReady(ctx context.Context, c ctrlclient.Client, name string) (bool, error) {
	var binding therapistv1alpha1.RBACBinding
	if err := c.Get(ctx, ctrlclient.ObjectKey{Name: name}, &binding); err != nil {
		return false, err
	}
	return conditionStatus(binding.Status.Conditions, "Ready") == metav1.ConditionTrue, nil
}

func clusterRoleBindingExists(ctx context.Context, c ctrlclient.Client, policy string) (bool, error) {
	var crbs rbacv1.ClusterRoleBindingList
	if err := c.List(ctx, &crbs, ctrlclient.MatchingLabels{
		"rbac.therapist.io/policy":      policy,
		"rbac.therapist.io/policy-kind": "RBACBinding",
	}); err != nil {
		return false, err
	}
	return len(crbs.Items) > 0, nil
}

func roleExists(ctx context.Context, c ctrlclient.Client, namespace, name string) (bool, error) {
	var role rbacv1.Role
	if err := c.Get(ctx, ctrlclient.ObjectKey{Namespace: namespace, Name: name}, &role); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func clusterRoleExists(ctx context.Context, c ctrlclient.Client, name string) (bool, error) {
	var role rbacv1.ClusterRole
	if err := c.Get(ctx, ctrlclient.ObjectKey{Name: name}, &role); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func sessionHasPolicy(ctx context.Context, c ctrlclient.Client, session, policy string) (bool, error) {
	var s therapistv1alpha1.RBACSession
	if err := c.Get(ctx, ctrlclient.ObjectKey{Name: session}, &s); err != nil {
		return false, err
	}
	if s.Status.GeneratedAt == nil {
		return false, nil
	}
	for _, summary := range s.Status.PolicySummaries {
		if summary.Name == policy {
			return true, nil
		}
	}
	return false, nil
}

func conditionStatus(conditions []metav1.Condition, condType string) metav1.ConditionStatus {
	for _, c := range conditions {
		if c.Type == condType {
			return c.Status
		}
	}
	return metav1.ConditionUnknown
}

func findCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

func waitFor(ctx context.Context, what string, fn func(context.Context) (bool, error)) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		ok, err := fn(ctx)
		if err == nil && ok {
			fmt.Printf("ok: %s\n", what)
			return nil
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return fmt.Errorf("%s: %w", what, err)
			}
			return fmt.Errorf("%s: timeout", what)
		case <-ticker.C:
		}
	}
}

func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
