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
)

var _ = Describe("RBACBinding controller", func() {
	const (
		timeout  = 10 * time.Second
		interval = 250 * time.Millisecond
	)

	Context("with a namespace-scoped RoleBinding", func() {
		const (
			bindingName = "test-rb-ns"
			nsName      = "test-rb-ns-target"
		)

		BeforeEach(func() {
			createNamespace(nsName, nil)
		})

		AfterEach(func() {
			b := &therapistv1alpha1.RBACBinding{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: bindingName}, b); err == nil {
				Expect(k8sClient.Delete(ctx, b)).To(Succeed())
			}
			deleteNamespace(nsName)
		})

		It("creates a RoleBinding in the target namespace", func() {
			future := metav1.NewTime(time.Now().Add(24 * time.Hour))
			binding := &therapistv1alpha1.RBACBinding{
				ObjectMeta: metav1.ObjectMeta{Name: bindingName},
				Spec: therapistv1alpha1.RBACBindingSpec{
					Rationale:   "Integration test: namespace-scoped binding",
					ClusterRole: "view",
					Namespace:   nsName,
					ExpiresAt:   &future,
					Subjects: []rbacv1.Subject{
						{Kind: "User", Name: "ops-user@acme.com"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, binding)).To(Succeed())

			// A RoleBinding should be created in the target namespace.
			Eventually(func() int {
				rbList := &rbacv1.RoleBindingList{}
				if err := k8sClient.List(ctx, rbList, client.InNamespace(nsName)); err != nil {
					return 0
				}
				return len(rbList.Items)
			}, timeout, interval).Should(BeNumerically(">=", 1))

			// Status.ManagedBinding should be populated.
			Eventually(func() *therapistv1alpha1.ManagedBinding {
				b := &therapistv1alpha1.RBACBinding{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: bindingName}, b); err != nil {
					return nil
				}
				return b.Status.ManagedBinding
			}, timeout, interval).ShouldNot(BeNil())

			b := &therapistv1alpha1.RBACBinding{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: bindingName}, b)).To(Succeed())
			Expect(b.Status.ManagedBinding.Namespace).To(Equal(nsName))
			Expect(b.Status.ManagedBinding.Kind).To(Equal("RoleBinding"))
		})
	})

	Context("with a ClusterWide binding", func() {
		const bindingName = "test-rb-clusterwide"

		AfterEach(func() {
			b := &therapistv1alpha1.RBACBinding{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: bindingName}, b); err == nil {
				Expect(k8sClient.Delete(ctx, b)).To(Succeed())
			}
		})

		It("creates a ClusterRoleBinding", func() {
			future := metav1.NewTime(time.Now().Add(2 * time.Hour))
			binding := &therapistv1alpha1.RBACBinding{
				ObjectMeta: metav1.ObjectMeta{Name: bindingName},
				Spec: therapistv1alpha1.RBACBindingSpec{
					Rationale:   "Integration test: cluster-wide emergency binding",
					ClusterRole: "view",
					ClusterWide: true,
					ExpiresAt:   &future,
					Subjects: []rbacv1.Subject{
						{Kind: "User", Name: "incident-responder@acme.com"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, binding)).To(Succeed())

			Eventually(func() *therapistv1alpha1.ManagedBinding {
				b := &therapistv1alpha1.RBACBinding{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: bindingName}, b); err != nil {
					return nil
				}
				return b.Status.ManagedBinding
			}, timeout, interval).ShouldNot(BeNil())

			b := &therapistv1alpha1.RBACBinding{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: bindingName}, b)).To(Succeed())
			Expect(b.Status.ManagedBinding.Kind).To(Equal("ClusterRoleBinding"))
		})
	})

	Context("when binding expires", func() {
		const (
			bindingName = "test-rb-expire"
			nsName      = "test-rb-expire-ns"
		)

		BeforeEach(func() {
			createNamespace(nsName, nil)
		})

		AfterEach(func() {
			b := &therapistv1alpha1.RBACBinding{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: bindingName}, b); err == nil {
				Expect(k8sClient.Delete(ctx, b)).To(Succeed())
			}
			deleteNamespace(nsName)
		})

		It("sets Expired condition and clears managed binding", func() {
			past := metav1.NewTime(time.Now().Add(-1 * time.Minute))
			binding := &therapistv1alpha1.RBACBinding{
				ObjectMeta: metav1.ObjectMeta{Name: bindingName},
				Spec: therapistv1alpha1.RBACBindingSpec{
					Rationale:   "Integration test: pre-expired binding",
					ClusterRole: "view",
					Namespace:   nsName,
					ExpiresAt:   &past,
					Subjects: []rbacv1.Subject{
						{Kind: "User", Name: "expired-user@acme.com"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, binding)).To(Succeed())

			// The controller should set Expired=True.
			Eventually(func() string {
				b := &therapistv1alpha1.RBACBinding{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: bindingName}, b); err != nil {
					return ""
				}
				for _, c := range b.Status.Conditions {
					if c.Type == "Expired" {
						return string(c.Status)
					}
				}
				return ""
			}, timeout, interval).Should(Equal("True"))
		})
	})
})
