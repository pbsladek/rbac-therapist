// main.go is the entrypoint for the rbac-therapist operator.
//
// Controllers registered:
//   - Team:         resolves team membership and inheritance
//   - AccessPolicy: reconciles access policies into RBAC bindings
//   - RBACBinding:  reconciles low-level direct bindings
//   - Session:      maintains the singleton RBACSession session-notes snapshot
//
// Webhooks registered:
//   - AccessPolicyValidator / AccessPolicyDefaulter
//   - TeamValidator / TeamDefaulter
//   - RBACBindingValidator / RBACBindingDefaulter
package main

import (
	"flag"
	"os"
	"time"

	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	accesspolicyctrl "github.com/rbac-therapist/rbac-therapist/internal/controllers/accesspolicy"
	rbacbindingctrl "github.com/rbac-therapist/rbac-therapist/internal/controllers/rbacbinding"
	sessionctrl "github.com/rbac-therapist/rbac-therapist/internal/controllers/session"
	teamctrl "github.com/rbac-therapist/rbac-therapist/internal/controllers/team"
	"github.com/rbac-therapist/rbac-therapist/internal/webhooks"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(rbacv1.AddToScheme(scheme))
	utilruntime.Must(therapistv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		probeAddr            string
		enableLeaderElection bool
		enableWebhooks       bool
		sessionRefresh       time.Duration
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address for the metrics endpoint.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address for health probes.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for high availability.")
	flag.BoolVar(&enableWebhooks, "enable-webhooks", true, "Enable admission webhooks (disable for local dev without cert-manager).")
	flag.DurationVar(&sessionRefresh, "session-refresh-interval", 5*time.Minute,
		"How often the RBACSession session-notes snapshot is refreshed (e.g. 5m, 1h).")
	flag.Parse()

	opts := zap.Options{
		Development: false,
		TimeEncoder: zapcore.ISO8601TimeEncoder,
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	log := ctrl.Log.WithName("operator")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "rbac-therapist-leader-election",
	})
	if err != nil {
		log.Error(err, "unable to create manager")
		os.Exit(1)
	}

	// Team controller — resolves membership inheritance.
	if err := (&teamctrl.Reconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Team"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to create Team controller")
		os.Exit(1)
	}

	// AccessPolicy controller — core RBAC reconciler.
	if err := (&accesspolicyctrl.Reconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("AccessPolicy"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to create AccessPolicy controller")
		os.Exit(1)
	}

	// RBACBinding controller — low-level direct bindings.
	if err := (&rbacbindingctrl.Reconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("RBACBinding"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to create RBACBinding controller")
		os.Exit(1)
	}

	// Session controller — maintains the RBACSession session-notes snapshot.
	if err := (&sessionctrl.Reconciler{
		Client:          mgr.GetClient(),
		Log:             ctrl.Log.WithName("controllers").WithName("Session"),
		Scheme:          mgr.GetScheme(),
		RefreshInterval: sessionRefresh,
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to create Session controller")
		os.Exit(1)
	}

	// Admission webhooks — only registered when --enable-webhooks=true.
	// In local dev without cert-manager, pass --enable-webhooks=false.
	if enableWebhooks {
		if err := (&webhooks.AccessPolicyValidator{}).SetupWebhookWithManager(mgr); err != nil {
			log.Error(err, "unable to register AccessPolicy validator webhook")
			os.Exit(1)
		}
		if err := (&webhooks.AccessPolicyDefaulter{}).SetupWebhookWithManager(mgr); err != nil {
			log.Error(err, "unable to register AccessPolicy defaulter webhook")
			os.Exit(1)
		}
		if err := (&webhooks.TeamValidator{}).SetupWebhookWithManager(mgr); err != nil {
			log.Error(err, "unable to register Team validator webhook")
			os.Exit(1)
		}
		if err := (&webhooks.TeamDefaulter{}).SetupWebhookWithManager(mgr); err != nil {
			log.Error(err, "unable to register Team defaulter webhook")
			os.Exit(1)
		}
		if err := (&webhooks.RBACBindingValidator{}).SetupWebhookWithManager(mgr); err != nil {
			log.Error(err, "unable to register RBACBinding validator webhook")
			os.Exit(1)
		}
		if err := (&webhooks.RBACBindingDefaulter{}).SetupWebhookWithManager(mgr); err != nil {
			log.Error(err, "unable to register RBACBinding defaulter webhook")
			os.Exit(1)
		}
		log.Info("admission webhooks registered")
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	log.Info("starting rbac-therapist operator",
		"sessionRefreshInterval", sessionRefresh,
		"leaderElection", enableLeaderElection,
		"webhooksEnabled", enableWebhooks,
	)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "problem running manager")
		os.Exit(1)
	}
}
