package integration_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	sessionctrl "github.com/rbac-therapist/rbac-therapist/internal/controllers/session"
)

var _ = Describe("Session controller", func() {
	const (
		timeout  = 20 * time.Second
		interval = 500 * time.Millisecond
	)

	Context("singleton session lifecycle", func() {
		It("creates the 'current' RBACSession on startup", func() {
			// The controller creates the singleton on first reconcile.
			// It may take a few seconds after startup.
			Eventually(func() error {
				var session therapistv1alpha1.RBACSession
				return k8sClient.Get(ctx, types.NamespacedName{Name: sessionctrl.SessionName}, &session)
			}, timeout, interval).Should(Succeed())
		})

		It("has a non-nil generatedAt after reconciliation", func() {
			Eventually(func() bool {
				var session therapistv1alpha1.RBACSession
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: sessionctrl.SessionName}, &session); err != nil {
					return false
				}
				return session.Status.GeneratedAt != nil
			}, timeout, interval).Should(BeTrue())
		})
	})

	Context("force refresh via annotation", func() {
		It("triggers an immediate refresh when annotation is set", func() {
			// Wait for the session to have an initial generatedAt.
			var initialTime *metav1.Time
			Eventually(func() bool {
				var session therapistv1alpha1.RBACSession
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: sessionctrl.SessionName}, &session); err != nil {
					return false
				}
				if session.Status.GeneratedAt == nil {
					return false
				}
				t := *session.Status.GeneratedAt
				initialTime = &t
				return true
			}, timeout, interval).Should(BeTrue())

			// Set the force-refresh annotation.
			var session therapistv1alpha1.RBACSession
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: sessionctrl.SessionName}, &session)).To(Succeed())
			patch := client.MergeFrom(session.DeepCopy())
			if session.Annotations == nil {
				session.Annotations = make(map[string]string)
			}
			session.Annotations[sessionctrl.ForceRefreshAnnotation] = "true"
			Expect(k8sClient.Patch(ctx, &session, patch)).To(Succeed())

			// The annotation should be removed and generatedAt should advance.
			Eventually(func() bool {
				var s therapistv1alpha1.RBACSession
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: sessionctrl.SessionName}, &s); err != nil {
					return false
				}
				// Annotation removed = refresh was processed.
				if s.Annotations[sessionctrl.ForceRefreshAnnotation] == "true" {
					return false
				}
				if s.Status.GeneratedAt == nil {
					return false
				}
				return s.Status.GeneratedAt.After(initialTime.Time)
			}, timeout, interval).Should(BeTrue())
		})
	})

	Context("session indexes access grants", func() {
		const (
			policyName = "test-session-policy"
			nsName     = "test-session-ns"
		)

		BeforeEach(func() {
			createNamespace(nsName, nil)

			policy := &therapistv1alpha1.AccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: therapistv1alpha1.AccessPolicySpec{
					Rationale: "Integration test: session indexing",
					Subjects: []therapistv1alpha1.PolicySubject{
						{Inline: &rbacv1.Subject{Kind: "User", Name: "eve@acme.com"}},
					},
					Roles: []therapistv1alpha1.PolicyRole{
						{
							ClusterRole: "view",
							Namespaces:  &therapistv1alpha1.NamespaceSelector{Names: []string{nsName}},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		})

		AfterEach(func() {
			policy := &therapistv1alpha1.AccessPolicy{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, policy); err == nil {
				Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			}
			deleteNamespace(nsName)
		})

		It("includes the policy's subjects in the session", func() {
			// Force refresh so the session picks up the new policy.
			var session therapistv1alpha1.RBACSession
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: sessionctrl.SessionName}, &session)).To(Succeed())
			patch := client.MergeFrom(session.DeepCopy())
			if session.Annotations == nil {
				session.Annotations = make(map[string]string)
			}
			session.Annotations[sessionctrl.ForceRefreshAnnotation] = "true"
			Expect(k8sClient.Patch(ctx, &session, patch)).To(Succeed())

			// Wait for the annotation to be removed (refresh processed) and then
			// check the session contains eve@acme.com.
			Eventually(func() bool {
				var s therapistv1alpha1.RBACSession
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: sessionctrl.SessionName}, &s); err != nil {
					return false
				}
				if s.Annotations[sessionctrl.ForceRefreshAnnotation] == "true" {
					return false // not yet processed
				}
				for _, entry := range s.Status.SubjectAccess {
					if entry.Subject.Name == "eve@acme.com" {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})
	})
})
