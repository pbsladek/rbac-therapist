// Package accesspolicy contains the AccessPolicy controller.
//
// The AccessPolicy controller is the core of rbac-therapist. It watches
// AccessPolicy resources and reconciles them into native Kubernetes
// RoleBindings and ClusterRoleBindings.
//
// Reconciliation loop:
//  1. Fetch the AccessPolicy. If not found, exit (bindings are garbage-collected via ownerRefs).
//  2. Check paused / expired conditions — update status and exit early if applicable.
//  3. Resolve subjects (expand TeamRef → effective members).
//  4. Resolve target namespaces (static + label selector + matchTeamTags).
//  5. Compute desired bindings via engine/parser.
//  6. CreateOrUpdate each desired binding (idempotent).
//  7. Prune stale bindings owned by this policy that are no longer desired.
//  8. Update status.managedBindings and status.conditions.
package accesspolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/hasher"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/inheritance"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/parser"
)

const (
	finalizerName    = "rbac.therapist.io/finalizer"
	conditionReady   = "Ready"
	conditionExpired = "Expired"
	conditionPaused  = "Paused"
)

// Reconciler reconciles AccessPolicy objects.
type Reconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=rbac.therapist.io,resources=accesspolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.therapist.io,resources=accesspolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.therapist.io,resources=accesspolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.therapist.io,resources=teams,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete;bind;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete;bind;escalate

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("accesspolicy", req.Name)

	// 1. Fetch the AccessPolicy.
	var policy therapistv1alpha1.AccessPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// 2. Handle deletion — remove finalizer after bindings are cleaned up.
	if !policy.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, &policy)
	}

	// Ensure finalizer is present.
	if !controllerutil.ContainsFinalizer(&policy, finalizerName) {
		controllerutil.AddFinalizer(&policy, finalizerName)
		if err := r.Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// 3. Check expiry.
	if policy.Spec.ExpiresAt != nil && policy.Spec.ExpiresAt.Before(&metav1.Time{Time: time.Now()}) {
		return r.handleExpiry(ctx, log, &policy)
	}

	// 4. Check paused.
	if policy.Spec.Paused {
		return r.handlePaused(ctx, log, &policy)
	}

	// 5. Load dependencies: Teams and Namespaces.
	var teamList therapistv1alpha1.TeamList
	if err := r.List(ctx, &teamList); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing teams: %w", err)
	}
	var policyList therapistv1alpha1.AccessPolicyList
	if err := r.List(ctx, &policyList); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing access policies: %w", err)
	}

	var nsList corev1.NamespaceList
	if err := r.List(ctx, &nsList); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing namespaces: %w", err)
	}

	resolver := inheritance.NewAccessPolicyResolver(policyList.Items, inheritance.DefaultMaxPolicyExtendsDepth)
	effectivePolicy, err := resolver.ResolveEffectivePolicy(policy)
	if err != nil {
		return r.setFailedCondition(ctx, &policy, err)
	}

	// Reconcile optional managed Role/ClusterRole definitions owned by this policy.
	if err := r.reconcileManagedRBAC(ctx, log, &policy); err != nil {
		return r.setFailedCondition(ctx, &policy, err)
	}

	// 6. Resolve desired bindings.
	desired := parser.Parse(parser.Input{
		Policy:     effectivePolicy,
		Teams:      teamList.Items,
		Namespaces: nsList.Items,
	})

	// 7. Reconcile bindings (CreateOrUpdate desired, prune stale).
	managedBindings, err := r.reconcileBindings(ctx, log, &policy, desired)
	if err != nil {
		return r.setFailedCondition(ctx, &policy, err)
	}

	// 8. Update status.
	now := metav1.Now()
	policy.Status.ManagedBindings = managedBindings
	policy.Status.LastReconcileTime = &now
	policy.Status.ObservedGeneration = policy.Generation
	setCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionPaused,
		Status:             metav1.ConditionFalse,
		Reason:             "PolicyActive",
		Message:            "Policy is actively reconciling.",
		ObservedGeneration: policy.Generation,
	})
	setCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionExpired,
		Status:             metav1.ConditionFalse,
		Reason:             "PolicyNotExpired",
		Message:            "Policy has not expired.",
		ObservedGeneration: policy.Generation,
	})
	setCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             "ReconcileSuccess",
		Message:            fmt.Sprintf("%d bindings reconciled", len(managedBindings)),
		ObservedGeneration: policy.Generation,
	})

	if err := r.Status().Update(ctx, &policy); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("reconciled", "bindings", len(managedBindings))

	// Requeue before expiry if set.
	if policy.Spec.ExpiresAt != nil {
		return ctrl.Result{RequeueAfter: time.Until(policy.Spec.ExpiresAt.Time)}, nil
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) reconcileBindings(
	ctx context.Context,
	log logr.Logger,
	policy *therapistv1alpha1.AccessPolicy,
	desired []parser.DesiredBinding,
) ([]therapistv1alpha1.ManagedBinding, error) {
	desiredNames := make(map[string]bool, len(desired))
	var managed []therapistv1alpha1.ManagedBinding

	for _, d := range desired {
		desiredNames[d.Name] = true

		labels := hasher.ManagedLabels(policy.Name, "AccessPolicy", d.Hash)

		if d.ClusterWide {
			crb := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: d.Name},
			}
			_, err := controllerutil.CreateOrUpdate(ctx, r.Client, crb, func() error {
				crb.Labels = labels
				crb.RoleRef = d.RoleRef
				crb.Subjects = d.Subjects
				return controllerutil.SetControllerReference(policy, crb, r.Scheme)
			})
			if err != nil {
				return nil, fmt.Errorf("reconciling ClusterRoleBinding %s: %w", d.Name, err)
			}
			managed = append(managed, therapistv1alpha1.ManagedBinding{
				Name:     d.Name,
				Kind:     "ClusterRoleBinding",
				RoleName: d.RoleRef.Name,
			})
			log.V(4).Info("reconciled ClusterRoleBinding", "name", d.Name)
		} else {
			rb := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: d.Name, Namespace: d.Namespace},
			}
			_, err := controllerutil.CreateOrUpdate(ctx, r.Client, rb, func() error {
				rb.Labels = labels
				rb.RoleRef = d.RoleRef
				rb.Subjects = d.Subjects
				return controllerutil.SetControllerReference(policy, rb, r.Scheme)
			})
			if err != nil {
				return nil, fmt.Errorf("reconciling RoleBinding %s/%s: %w", d.Namespace, d.Name, err)
			}
			managed = append(managed, therapistv1alpha1.ManagedBinding{
				Name:      d.Name,
				Namespace: d.Namespace,
				Kind:      "RoleBinding",
				RoleName:  d.RoleRef.Name,
			})
			log.V(4).Info("reconciled RoleBinding", "name", d.Name, "namespace", d.Namespace)
		}
	}

	// Prune stale bindings: find all RoleBindings/ClusterRoleBindings owned by
	// this policy that are no longer in the desired set.
	if err := r.pruneRoleBindings(ctx, log, policy, desiredNames); err != nil {
		return nil, err
	}
	if err := r.pruneClusterRoleBindings(ctx, log, policy, desiredNames); err != nil {
		return nil, err
	}

	return managed, nil
}

func (r *Reconciler) reconcileManagedRBAC(
	ctx context.Context,
	log logr.Logger,
	policy *therapistv1alpha1.AccessPolicy,
) error {
	desiredRoleKeys := make(map[string]bool, len(policy.Spec.ManagedRoles))
	desiredClusterRoleNames := make(map[string]bool, len(policy.Spec.ManagedClusterRoles))

	for _, managedRole := range policy.Spec.ManagedRoles {
		key := managedRole.Namespace + "/" + managedRole.Name
		desiredRoleKeys[key] = true
		labels := mergeManagedLabels(
			managedRole.Labels,
			hasher.ManagedLabels(policy.Name, "AccessPolicy", managedRoleHash(managedRole)),
		)
		role := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      managedRole.Name,
				Namespace: managedRole.Namespace,
			},
		}
		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, role, func() error {
			role.Labels = labels
			role.Annotations = managedRole.Annotations
			role.Rules = managedRole.Rules
			return controllerutil.SetControllerReference(policy, role, r.Scheme)
		})
		if err != nil {
			return fmt.Errorf("reconciling managed Role %s/%s: %w", managedRole.Namespace, managedRole.Name, err)
		}
		log.V(4).Info("reconciled managed Role", "name", managedRole.Name, "namespace", managedRole.Namespace)
	}

	for _, managedClusterRole := range policy.Spec.ManagedClusterRoles {
		desiredClusterRoleNames[managedClusterRole.Name] = true
		labels := mergeManagedLabels(
			managedClusterRole.Labels,
			hasher.ManagedLabels(policy.Name, "AccessPolicy", managedClusterRoleHash(managedClusterRole)),
		)
		clusterRole := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: managedClusterRole.Name,
			},
		}
		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, clusterRole, func() error {
			clusterRole.Labels = labels
			clusterRole.Annotations = managedClusterRole.Annotations
			clusterRole.Rules = managedClusterRole.Rules
			return controllerutil.SetControllerReference(policy, clusterRole, r.Scheme)
		})
		if err != nil {
			return fmt.Errorf("reconciling managed ClusterRole %s: %w", managedClusterRole.Name, err)
		}
		log.V(4).Info("reconciled managed ClusterRole", "name", managedClusterRole.Name)
	}

	if err := r.pruneManagedRoles(ctx, log, policy, desiredRoleKeys); err != nil {
		return err
	}
	if err := r.pruneManagedClusterRoles(ctx, log, policy, desiredClusterRoleNames); err != nil {
		return err
	}

	return nil
}

func (r *Reconciler) pruneRoleBindings(
	ctx context.Context,
	log logr.Logger,
	policy *therapistv1alpha1.AccessPolicy,
	desiredNames map[string]bool,
) error {
	var list rbacv1.RoleBindingList
	if err := r.List(ctx, &list, client.MatchingLabels{
		hasher.ManagedByLabel:  hasher.ManagedByValue,
		hasher.PolicyLabel:     policy.Name,
		hasher.PolicyKindLabel: "AccessPolicy",
	}); err != nil {
		return fmt.Errorf("listing RoleBindings for pruning: %w", err)
	}
	for i := range list.Items {
		rb := &list.Items[i]
		if !desiredNames[rb.Name] {
			log.Info("pruning stale RoleBinding", "name", rb.Name, "namespace", rb.Namespace)
			if err := r.Delete(ctx, rb); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Reconciler) pruneClusterRoleBindings(
	ctx context.Context,
	log logr.Logger,
	policy *therapistv1alpha1.AccessPolicy,
	desiredNames map[string]bool,
) error {
	var list rbacv1.ClusterRoleBindingList
	if err := r.List(ctx, &list, client.MatchingLabels{
		hasher.ManagedByLabel:  hasher.ManagedByValue,
		hasher.PolicyLabel:     policy.Name,
		hasher.PolicyKindLabel: "AccessPolicy",
	}); client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("listing ClusterRoleBindings for pruning: %w", err)
	}
	for i := range list.Items {
		crb := &list.Items[i]
		if !desiredNames[crb.Name] {
			log.Info("pruning stale ClusterRoleBinding", "name", crb.Name)
			if err := r.Delete(ctx, crb); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Reconciler) pruneManagedRoles(
	ctx context.Context,
	log logr.Logger,
	policy *therapistv1alpha1.AccessPolicy,
	desiredRoleKeys map[string]bool,
) error {
	var list rbacv1.RoleList
	if err := r.List(ctx, &list, client.MatchingLabels{
		hasher.ManagedByLabel:  hasher.ManagedByValue,
		hasher.PolicyLabel:     policy.Name,
		hasher.PolicyKindLabel: "AccessPolicy",
	}); err != nil {
		return fmt.Errorf("listing managed Roles for pruning: %w", err)
	}
	for i := range list.Items {
		role := &list.Items[i]
		key := role.Namespace + "/" + role.Name
		if !desiredRoleKeys[key] {
			log.Info("pruning stale managed Role", "name", role.Name, "namespace", role.Namespace)
			if err := r.Delete(ctx, role); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Reconciler) pruneManagedClusterRoles(
	ctx context.Context,
	log logr.Logger,
	policy *therapistv1alpha1.AccessPolicy,
	desiredNames map[string]bool,
) error {
	var list rbacv1.ClusterRoleList
	if err := r.List(ctx, &list, client.MatchingLabels{
		hasher.ManagedByLabel:  hasher.ManagedByValue,
		hasher.PolicyLabel:     policy.Name,
		hasher.PolicyKindLabel: "AccessPolicy",
	}); err != nil {
		return fmt.Errorf("listing managed ClusterRoles for pruning: %w", err)
	}
	for i := range list.Items {
		clusterRole := &list.Items[i]
		if !desiredNames[clusterRole.Name] {
			log.Info("pruning stale managed ClusterRole", "name", clusterRole.Name)
			if err := r.Delete(ctx, clusterRole); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Reconciler) handleDeletion(ctx context.Context, policy *therapistv1alpha1.AccessPolicy) (ctrl.Result, error) {
	// Bindings are cleaned up automatically via ownerReferences + garbage collection.
	// Just remove the finalizer.
	controllerutil.RemoveFinalizer(policy, finalizerName)
	return ctrl.Result{}, r.Update(ctx, policy)
}

func (r *Reconciler) handleExpiry(ctx context.Context, log logr.Logger, policy *therapistv1alpha1.AccessPolicy) (ctrl.Result, error) {
	log.Info("policy has expired, removing all bindings")
	// Prune everything.
	if err := r.pruneRoleBindings(ctx, log, policy, map[string]bool{}); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.pruneClusterRoleBindings(ctx, log, policy, map[string]bool{}); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.pruneManagedRoles(ctx, log, policy, map[string]bool{}); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.pruneManagedClusterRoles(ctx, log, policy, map[string]bool{}); err != nil {
		return ctrl.Result{}, err
	}
	policy.Status.ManagedBindings = nil
	setCondition(&policy.Status.Conditions, metav1.Condition{
		Type:    conditionExpired,
		Status:  metav1.ConditionTrue,
		Reason:  "PolicyExpired",
		Message: fmt.Sprintf("Policy expired at %s", policy.Spec.ExpiresAt),
	})
	setCondition(&policy.Status.Conditions, metav1.Condition{
		Type:    conditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  "PolicyExpired",
		Message: "Policy has expired and all bindings have been removed",
	})
	return ctrl.Result{}, r.Status().Update(ctx, policy)
}

func (r *Reconciler) handlePaused(ctx context.Context, log logr.Logger, policy *therapistv1alpha1.AccessPolicy) (ctrl.Result, error) {
	log.Info("policy is paused, skipping reconciliation")
	setCondition(&policy.Status.Conditions, metav1.Condition{
		Type:    conditionExpired,
		Status:  metav1.ConditionFalse,
		Reason:  "PolicyNotExpired",
		Message: "Policy has not expired.",
	})
	setCondition(&policy.Status.Conditions, metav1.Condition{
		Type:    conditionPaused,
		Status:  metav1.ConditionTrue,
		Reason:  "PolicyPaused",
		Message: "Reconciliation is suspended. Set spec.paused=false to resume.",
	})
	return ctrl.Result{}, r.Status().Update(ctx, policy)
}

func (r *Reconciler) setFailedCondition(ctx context.Context, policy *therapistv1alpha1.AccessPolicy, err error) (ctrl.Result, error) {
	setCondition(&policy.Status.Conditions, metav1.Condition{
		Type:    conditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  "ReconcileError",
		Message: err.Error(),
	})
	_ = r.Status().Update(ctx, policy)
	return ctrl.Result{}, err
}

// SetupWithManager registers the controller and sets up watches.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Watch AccessPolicies directly.
	// Also watch Team changes and trigger re-reconcile of all policies that reference the team.
	// Also watch Namespace changes to handle dynamic namespace selectors.
	return ctrl.NewControllerManagedBy(mgr).
		For(&therapistv1alpha1.AccessPolicy{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.ClusterRole{}).
		Watches(
			&therapistv1alpha1.Team{},
			handler.EnqueueRequestsFromMapFunc(r.teamToPolicies),
		).
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.namespaceToPolicies),
		).
		Complete(r)
}

func mergeManagedLabels(custom, managed map[string]string) map[string]string {
	labels := make(map[string]string, len(custom)+len(managed))
	for k, v := range custom {
		labels[k] = v
	}
	for k, v := range managed {
		labels[k] = v
	}
	return labels
}

func managedRoleHash(role therapistv1alpha1.ManagedRoleSpec) string {
	payload, err := json.Marshal(role)
	if err != nil {
		return hasher.ContentHash(role.Namespace + "/" + role.Name)
	}
	return hasher.ContentHash(string(payload))
}

func managedClusterRoleHash(role therapistv1alpha1.ManagedClusterRoleSpec) string {
	payload, err := json.Marshal(role)
	if err != nil {
		return hasher.ContentHash(role.Name)
	}
	return hasher.ContentHash(string(payload))
}

// teamToPolicies maps a Team change event to the AccessPolicies that reference it.
func (r *Reconciler) teamToPolicies(ctx context.Context, obj client.Object) []reconcile.Request {
	team, ok := obj.(*therapistv1alpha1.Team)
	if !ok {
		return nil
	}

	var policyList therapistv1alpha1.AccessPolicyList
	if err := r.List(ctx, &policyList); err != nil {
		return nil
	}

	var requests []reconcile.Request
	for _, policy := range policyList.Items {
		for _, subject := range policy.Spec.Subjects {
			if subject.TeamRef != nil && subject.TeamRef.Name == team.Name {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: policy.Name},
				})
				break
			}
		}
	}
	return requests
}

// namespaceToPolicies maps a Namespace change to all AccessPolicies with dynamic selectors.
func (r *Reconciler) namespaceToPolicies(ctx context.Context, obj client.Object) []reconcile.Request {
	var policyList therapistv1alpha1.AccessPolicyList
	if err := r.List(ctx, &policyList); err != nil {
		return nil
	}

	var requests []reconcile.Request
	for _, policy := range policyList.Items {
		if hasDynamicNamespaceSelector(policy) {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: policy.Name},
			})
		}
	}
	return requests
}

// hasDynamicNamespaceSelector returns true if the policy has any label selector
// or matchTeamTags that would be affected by namespace changes.
func hasDynamicNamespaceSelector(policy therapistv1alpha1.AccessPolicy) bool {
	for _, role := range policy.Spec.Roles {
		if role.Namespaces == nil {
			continue
		}
		if role.Namespaces.Selector != nil || role.Namespaces.MatchTeamTags {
			return true
		}
	}
	return false
}

// setCondition upserts a condition into a condition slice.
func setCondition(conditions *[]metav1.Condition, newCondition metav1.Condition) {
	newCondition.LastTransitionTime = metav1.Now()
	for i, existing := range *conditions {
		if existing.Type == newCondition.Type {
			if existing.Status != newCondition.Status {
				(*conditions)[i] = newCondition
			} else {
				(*conditions)[i].Reason = newCondition.Reason
				(*conditions)[i].Message = newCondition.Message
			}
			return
		}
	}
	*conditions = append(*conditions, newCondition)
}
