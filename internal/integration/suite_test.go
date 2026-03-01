// Package integration contains envtest-based integration tests for the rbac-therapist controllers.
//
// These tests run against a real Kubernetes API server (via controller-runtime's envtest)
// and verify end-to-end reconciliation behavior.
//
// Run with:
//
//	make test-integration
//
// or:
//
//	KUBEBUILDER_ASSETS=$(go run sigs.k8s.io/controller-runtime/tools/setup-envtest use --print path) \
//	  go test ./internal/integration/...
package integration_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	accesspolicyctrl "github.com/rbac-therapist/rbac-therapist/internal/controllers/accesspolicy"
	rbacbindingctrl "github.com/rbac-therapist/rbac-therapist/internal/controllers/rbacbinding"
	sessionctrl "github.com/rbac-therapist/rbac-therapist/internal/controllers/session"
	teamctrl "github.com/rbac-therapist/rbac-therapist/internal/controllers/team"
)

var (
	testEnv   *envtest.Environment
	k8sClient client.Client
	ctx       context.Context
	cancel    context.CancelFunc
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "rbac-therapist integration suite")
}

var _ = BeforeSuite(func() {
	ctrl.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	ctx, cancel = context.WithCancel(context.Background())

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(rbacv1.AddToScheme(scheme))
	utilruntime.Must(therapistv1alpha1.AddToScheme(scheme))

	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
		},
		ErrorIfCRDPathMissing: true,
		Scheme:                scheme,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())

	// Start manager with all controllers.
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		// Disable metrics in tests to avoid port conflicts.
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	Expect(err).NotTo(HaveOccurred())

	Expect((&teamctrl.Reconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("test-team"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr)).To(Succeed())

	Expect((&accesspolicyctrl.Reconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("test-accesspolicy"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr)).To(Succeed())

	Expect((&rbacbindingctrl.Reconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("test-rbacbinding"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr)).To(Succeed())

	Expect((&sessionctrl.Reconciler{
		Client:          mgr.GetClient(),
		Log:             ctrl.Log.WithName("test-session"),
		Scheme:          mgr.GetScheme(),
		RefreshInterval: 30 * time.Second,
	}).SetupWithManager(mgr)).To(Succeed())

	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(ctx)).To(Succeed())
	}()
})

var _ = AfterSuite(func() {
	cancel()
	Expect(testEnv.Stop()).To(Succeed())
})

// helpers ─────────────────────────────────────────────────────────────────────

func makeTestNamespace(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}

func createNamespace(name string, labels map[string]string) {
	ns := makeTestNamespace(name, labels)
	Expect(k8sClient.Create(ctx, ns)).To(Succeed())
}

func deleteNamespace(name string) {
	ns := &corev1.Namespace{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name}, ns); err == nil {
		Expect(k8sClient.Delete(ctx, ns)).To(Succeed())
	}
}

func makeSubject(kind, name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: kind, Name: name}
}
