package integration_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/hasher"
)

var _ = Describe("AccessPolicy controller", func() {
	const (
		timeout  = 10 * time.Second
		interval = 250 * time.Millisecond
	)

	Context("with a simple ClusterRole binding to a static namespace", func() {
		const (
			policyName = "test-ap-static"
			nsName     = "test-ap-ns"
		)

		BeforeEach(func() {
			createNamespace(nsName, nil)
		})

		AfterEach(func() {
			// Clean up the AccessPolicy and the namespace.
			policy := &therapistv1alpha1.AccessPolicy{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, policy); err == nil {
				Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			}
			deleteNamespace(nsName)
		})

		It("creates a RoleBinding in the target namespace", func() {
			policy := &therapistv1alpha1.AccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: therapistv1alpha1.AccessPolicySpec{
					Rationale: "Integration test: static namespace binding",
					Subjects: []therapistv1alpha1.PolicySubject{
						{Inline: &rbacv1.Subject{Kind: "User", Name: "alice@acme.com"}},
					},
					Roles: []therapistv1alpha1.PolicyRole{
						{
							ClusterRole: "view",
							Namespaces: &therapistv1alpha1.NamespaceSelector{
								Names: []string{nsName},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			expectedName := hasher.BindingName(policyName, "ClusterRole", "view", nsName)

			// The controller should create a RoleBinding in the target namespace.
			rb := &rbacv1.RoleBinding{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      expectedName,
					Namespace: nsName,
				}, rb)
			}, timeout, interval).Should(Succeed())

			Expect(rb.RoleRef.Name).To(Equal("view"))
			Expect(rb.Subjects).To(ContainElement(rbacv1.Subject{
				Kind: "User",
				Name: "alice@acme.com",
			}))
			Expect(rb.Labels[hasher.PolicyLabel]).To(Equal(policyName))

			// Status should reflect the managed binding.
			Eventually(func() int {
				p := &therapistv1alpha1.AccessPolicy{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, p); err != nil {
					return 0
				}
				return len(p.Status.ManagedBindings)
			}, timeout, interval).Should(Equal(1))
		})
	})

	Context("with a ClusterWide binding", func() {
		const policyName = "test-ap-clusterwide"

		AfterEach(func() {
			policy := &therapistv1alpha1.AccessPolicy{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, policy); err == nil {
				Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			}
		})

		It("creates a ClusterRoleBinding", func() {
			policy := &therapistv1alpha1.AccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: therapistv1alpha1.AccessPolicySpec{
					Rationale: "Integration test: cluster-wide binding",
					Subjects: []therapistv1alpha1.PolicySubject{
						{Inline: &rbacv1.Subject{Kind: "Group", Name: "platform@acme.com"}},
					},
					Roles: []therapistv1alpha1.PolicyRole{
						{ClusterRole: "view", ClusterWide: true},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			expectedName := hasher.BindingName(policyName, "ClusterRole", "view", "")

			crb := &rbacv1.ClusterRoleBinding{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: expectedName}, crb)
			}, timeout, interval).Should(Succeed())

			Expect(crb.RoleRef.Name).To(Equal("view"))
			Expect(crb.RoleRef.Kind).To(Equal("ClusterRole"))
		})
	})

	Context("with a paused policy", func() {
		const policyName = "test-ap-paused"

		AfterEach(func() {
			policy := &therapistv1alpha1.AccessPolicy{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, policy); err == nil {
				Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			}
		})

		It("does not create any bindings", func() {
			policy := &therapistv1alpha1.AccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: therapistv1alpha1.AccessPolicySpec{
					Rationale: "Integration test: paused policy",
					Paused:    true,
					Subjects: []therapistv1alpha1.PolicySubject{
						{Inline: &rbacv1.Subject{Kind: "User", Name: "bob@acme.com"}},
					},
					Roles: []therapistv1alpha1.PolicyRole{
						{ClusterRole: "view", ClusterWide: true},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Wait for the controller to process it — it should set a Paused condition.
			Eventually(func() string {
				p := &therapistv1alpha1.AccessPolicy{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, p); err != nil {
					return ""
				}
				for _, c := range p.Status.Conditions {
					if c.Type == "Paused" {
						return string(c.Status)
					}
				}
				return ""
			}, timeout, interval).Should(Equal("True"))

			// Confirm no ClusterRoleBinding was created.
			crbList := &rbacv1.ClusterRoleBindingList{}
			Expect(k8sClient.List(ctx, crbList, client.MatchingLabels{
				hasher.PolicyLabel: policyName,
			})).To(Succeed())
			Expect(crbList.Items).To(BeEmpty())
		})
	})

	Context("with an expired policy", func() {
		const policyName = "test-ap-expired"

		AfterEach(func() {
			policy := &therapistv1alpha1.AccessPolicy{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, policy); err == nil {
				Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			}
		})

		It("sets Expired condition and removes bindings", func() {
			// Create a policy that is already expired.
			past := metav1.NewTime(time.Now().Add(-1 * time.Hour))
			policy := &therapistv1alpha1.AccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: therapistv1alpha1.AccessPolicySpec{
					Rationale: "Integration test: already expired policy",
					ExpiresAt: &past,
					Subjects: []therapistv1alpha1.PolicySubject{
						{Inline: &rbacv1.Subject{Kind: "User", Name: "charlie@acme.com"}},
					},
					Roles: []therapistv1alpha1.PolicyRole{
						{ClusterRole: "view", ClusterWide: true},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Controller should set Expired=True.
			Eventually(func() string {
				p := &therapistv1alpha1.AccessPolicy{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, p); err != nil {
					return ""
				}
				for _, c := range p.Status.Conditions {
					if c.Type == "Expired" {
						return string(c.Status)
					}
				}
				return ""
			}, timeout, interval).Should(Equal("True"))
		})
	})

	Context("with a TeamRef subject", func() {
		const (
			policyName = "test-ap-teamref"
			teamName   = "test-team-ap"
			nsName     = "test-ap-team-ns"
		)

		BeforeEach(func() {
			createNamespace(nsName, nil)

			team := &therapistv1alpha1.Team{
				ObjectMeta: metav1.ObjectMeta{Name: teamName},
				Spec: therapistv1alpha1.TeamSpec{
					Members: []rbacv1.Subject{
						{Kind: "User", Name: "dana@acme.com"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, team)).To(Succeed())
		})

		AfterEach(func() {
			policy := &therapistv1alpha1.AccessPolicy{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, policy); err == nil {
				Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			}
			team := &therapistv1alpha1.Team{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: teamName}, team); err == nil {
				Expect(k8sClient.Delete(ctx, team)).To(Succeed())
			}
			deleteNamespace(nsName)
		})

		It("expands team members into the RoleBinding subjects", func() {
			policy := &therapistv1alpha1.AccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: therapistv1alpha1.AccessPolicySpec{
					Rationale: "Integration test: team ref expansion",
					Subjects: []therapistv1alpha1.PolicySubject{
						{TeamRef: &therapistv1alpha1.TeamReference{Name: teamName}},
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

			expectedName := hasher.BindingName(policyName, "ClusterRole", "view", nsName)

			rb := &rbacv1.RoleBinding{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      expectedName,
					Namespace: nsName,
				}, rb)
			}, timeout, interval).Should(Succeed())

			Expect(rb.Subjects).To(ContainElement(rbacv1.Subject{
				Kind: "User",
				Name: "dana@acme.com",
			}))
		})
	})

	Context("with managed custom Role and ClusterRole definitions", func() {
		const (
			policyName   = "test-ap-managed-roles"
			nsName       = "test-ap-managed-roles-ns"
			oldRoleName  = "test-ap-managed-role-v1"
			newRoleName  = "test-ap-managed-role-v2"
			oldCRName    = "test-ap-managed-clusterrole-v1"
			newCRName    = "test-ap-managed-clusterrole-v2"
			subjectEmail = "managed-roles@acme.com"
		)

		BeforeEach(func() {
			createNamespace(nsName, nil)
		})

		AfterEach(func() {
			policy := &therapistv1alpha1.AccessPolicy{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, policy); err == nil {
				Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			}
			deleteNamespace(nsName)
		})

		It("reconciles and prunes managed role resources", func() {
			policy := &therapistv1alpha1.AccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: therapistv1alpha1.AccessPolicySpec{
					Rationale: "Integration test: policy manages custom roles and binds to them",
					Subjects: []therapistv1alpha1.PolicySubject{
						{Inline: &rbacv1.Subject{Kind: "User", Name: subjectEmail}},
					},
					ManagedClusterRoles: []therapistv1alpha1.ManagedClusterRoleSpec{
						{
							Name: oldCRName,
							Rules: []rbacv1.PolicyRule{
								{
									APIGroups: []string{""},
									Resources: []string{"pods"},
									Verbs:     []string{"get", "list"},
								},
							},
						},
					},
					ManagedRoles: []therapistv1alpha1.ManagedRoleSpec{
						{
							Name:      oldRoleName,
							Namespace: nsName,
							Rules: []rbacv1.PolicyRule{
								{
									APIGroups: []string{""},
									Resources: []string{"secrets"},
									Verbs:     []string{"get"},
								},
							},
						},
					},
					Roles: []therapistv1alpha1.PolicyRole{
						{ClusterRole: oldCRName, ClusterWide: true},
						{
							Role: oldRoleName,
							Namespaces: &therapistv1alpha1.NamespaceSelector{
								Names: []string{nsName},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			Eventually(func(g Gomega) {
				var cr rbacv1.ClusterRole
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: oldCRName}, &cr)).To(Succeed())
				g.Expect(cr.Rules).NotTo(BeEmpty())
				g.Expect(cr.Labels[hasher.PolicyLabel]).To(Equal(policyName))

				var role rbacv1.Role
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: oldRoleName, Namespace: nsName}, &role)).To(Succeed())
				g.Expect(role.Rules).NotTo(BeEmpty())
				g.Expect(role.Labels[hasher.PolicyLabel]).To(Equal(policyName))
			}, timeout, interval).Should(Succeed())

			expectedOldRB := hasher.BindingName(policyName, "Role", oldRoleName, nsName)
			Eventually(func() error {
				var rb rbacv1.RoleBinding
				return k8sClient.Get(ctx, types.NamespacedName{Name: expectedOldRB, Namespace: nsName}, &rb)
			}, timeout, interval).Should(Succeed())

			// Update managed role definitions and role grants to new names.
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, policy)
			}, timeout, interval).Should(Succeed())

			policy.Spec.ManagedClusterRoles = []therapistv1alpha1.ManagedClusterRoleSpec{
				{
					Name: newCRName,
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{""},
							Resources: []string{"pods", "services"},
							Verbs:     []string{"get", "list", "watch"},
						},
					},
				},
			}
			policy.Spec.ManagedRoles = []therapistv1alpha1.ManagedRoleSpec{
				{
					Name:      newRoleName,
					Namespace: nsName,
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{""},
							Resources: []string{"configmaps"},
							Verbs:     []string{"get", "list"},
						},
					},
				},
			}
			policy.Spec.Roles = []therapistv1alpha1.PolicyRole{
				{ClusterRole: newCRName, ClusterWide: true},
				{
					Role: newRoleName,
					Namespaces: &therapistv1alpha1.NamespaceSelector{
						Names: []string{nsName},
					},
				},
			}
			Expect(k8sClient.Update(ctx, policy)).To(Succeed())

			Eventually(func(g Gomega) {
				var newCR rbacv1.ClusterRole
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: newCRName}, &newCR)).To(Succeed())

				var newRole rbacv1.Role
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: newRoleName, Namespace: nsName}, &newRole)).To(Succeed())

				var oldCR rbacv1.ClusterRole
				err := k8sClient.Get(ctx, types.NamespacedName{Name: oldCRName}, &oldCR)
				g.Expect(apierrors.IsNotFound(err)).To(BeTrue())

				var oldRole rbacv1.Role
				err = k8sClient.Get(ctx, types.NamespacedName{Name: oldRoleName, Namespace: nsName}, &oldRole)
				g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
			}, timeout, interval).Should(Succeed())
		})
	})
})
