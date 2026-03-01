package integration_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
)

var _ = Describe("Team controller", func() {
	const (
		timeout  = 10 * time.Second
		interval = 250 * time.Millisecond
	)

	Context("with direct members", func() {
		const teamName = "test-team-direct"

		AfterEach(func() {
			team := &therapistv1alpha1.Team{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: teamName}, team); err == nil {
				Expect(k8sClient.Delete(ctx, team)).To(Succeed())
			}
		})

		It("populates effectiveMembers in status", func() {
			team := &therapistv1alpha1.Team{
				ObjectMeta: metav1.ObjectMeta{Name: teamName},
				Spec: therapistv1alpha1.TeamSpec{
					Members: []rbacv1.Subject{
						{Kind: "User", Name: "alice@acme.com"},
						{Kind: "User", Name: "bob@acme.com"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, team)).To(Succeed())

			Eventually(func() []rbacv1.Subject {
				t := &therapistv1alpha1.Team{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: teamName}, t); err != nil {
					return nil
				}
				return t.Status.EffectiveMembers
			}, timeout, interval).Should(HaveLen(2))

			t := &therapistv1alpha1.Team{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: teamName}, t)).To(Succeed())
			Expect(t.Status.EffectiveMembers).To(ContainElement(rbacv1.Subject{Kind: "User", Name: "alice@acme.com"}))
			Expect(t.Status.EffectiveMembers).To(ContainElement(rbacv1.Subject{Kind: "User", Name: "bob@acme.com"}))
		})

		It("sets Ready=True", func() {
			team := &therapistv1alpha1.Team{
				ObjectMeta: metav1.ObjectMeta{Name: teamName},
				Spec: therapistv1alpha1.TeamSpec{
					Members: []rbacv1.Subject{
						{Kind: "Group", Name: "platform@acme.com"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, team)).To(Succeed())

			Eventually(func() string {
				t := &therapistv1alpha1.Team{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: teamName}, t); err != nil {
					return ""
				}
				for _, c := range t.Status.Conditions {
					if c.Type == "Ready" {
						return string(c.Status)
					}
				}
				return ""
			}, timeout, interval).Should(Equal("True"))
		})
	})

	Context("with extends inheritance", func() {
		const (
			parentTeam = "test-team-parent"
			childTeam  = "test-team-child"
		)

		AfterEach(func() {
			for _, name := range []string{childTeam, parentTeam} {
				team := &therapistv1alpha1.Team{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: name}, team); err == nil {
					Expect(k8sClient.Delete(ctx, team)).To(Succeed())
				}
			}
		})

		It("inherits members from parent teams", func() {
			// Create parent.
			parent := &therapistv1alpha1.Team{
				ObjectMeta: metav1.ObjectMeta{Name: parentTeam},
				Spec: therapistv1alpha1.TeamSpec{
					Members: []rbacv1.Subject{
						{Kind: "User", Name: "parent-user@acme.com"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, parent)).To(Succeed())

			// Wait for parent to be reconciled.
			Eventually(func() []rbacv1.Subject {
				t := &therapistv1alpha1.Team{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: parentTeam}, t); err != nil {
					return nil
				}
				return t.Status.EffectiveMembers
			}, timeout, interval).Should(HaveLen(1))

			// Create child that extends parent.
			child := &therapistv1alpha1.Team{
				ObjectMeta: metav1.ObjectMeta{Name: childTeam},
				Spec: therapistv1alpha1.TeamSpec{
					Members: []rbacv1.Subject{
						{Kind: "User", Name: "child-user@acme.com"},
					},
					Extends: []therapistv1alpha1.TeamReference{
						{Name: parentTeam},
					},
				},
			}
			Expect(k8sClient.Create(ctx, child)).To(Succeed())

			// Child's effective members should include both parent and child members.
			Eventually(func() []rbacv1.Subject {
				t := &therapistv1alpha1.Team{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: childTeam}, t); err != nil {
					return nil
				}
				return t.Status.EffectiveMembers
			}, timeout, interval).Should(HaveLen(2))

			t := &therapistv1alpha1.Team{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: childTeam}, t)).To(Succeed())
			names := make([]string, 0, len(t.Status.EffectiveMembers))
			for _, m := range t.Status.EffectiveMembers {
				names = append(names, m.Name)
			}
			Expect(names).To(ContainElements("parent-user@acme.com", "child-user@acme.com"))
		})
	})
})
