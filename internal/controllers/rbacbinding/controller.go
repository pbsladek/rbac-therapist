// Package rbacbinding contains the RBACBinding controller.
//
// RBACBinding is the emergency intervention — a low-level, direct subject-to-role
// binding for exceptional cases not covered by AccessPolicy.
//
// Reconciliation loop:
//  1. Fetch the RBACBinding. If not found, exit.
//  2. Handle deletion — remove finalizer.
//  3. Check expiry — delete binding and set Expired condition.
//  4. Create or update the single managed RoleBinding or ClusterRoleBinding.
//  5. Update status.
package rbacbinding

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/hasher"
)

const (
	finalizerName    = "rbac.therapist.io/finalizer"
	conditionReady   = "Ready"
	conditionExpired = "Expired"
)

// Reconciler reconciles RBACBinding objects.
type Reconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=rbac.therapist.io,resources=rbacbindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.therapist.io,resources=rbacbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.therapist.io,resources=rbacbindings/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;bind
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;bind

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("rbacbinding", req.Name)

	var binding therapistv1alpha1.RBACBinding
	if err := r.Get(ctx, req.NamespacedName, &binding); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion.
	if !binding.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, &binding)
	}

	// Ensure finalizer.
	if !controllerutil.ContainsFinalizer(&binding, finalizerName) {
		controllerutil.AddFinalizer(&binding, finalizerName)
		if err := r.Update(ctx, &binding); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Check expiry.
	if binding.Spec.ExpiresAt != nil && binding.Spec.ExpiresAt.Before(&metav1.Time{Time: time.Now()}) {
		return r.handleExpiry(ctx, log, &binding)
	}

	// Reconcile the single managed binding.
	managed, err := r.reconcileBinding(ctx, log, &binding)
	if err != nil {
		setCondition(&binding.Status.Conditions, metav1.Condition{
			Type:    conditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  "ReconcileError",
			Message: err.Error(),
		})
		_ = r.Status().Update(ctx, &binding)
		return ctrl.Result{}, err
	}

	binding.Status.ManagedBinding = managed
	binding.Status.ObservedGeneration = binding.Generation
	setCondition(&binding.Status.Conditions, metav1.Condition{
		Type:    conditionReady,
		Status:  metav1.ConditionTrue,
		Reason:  "ReconcileSuccess",
		Message: fmt.Sprintf("%s %q reconciled", managed.Kind, managed.Name),
	})

	if err := r.Status().Update(ctx, &binding); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("reconciled", "binding", managed.Name, "kind", managed.Kind)

	if binding.Spec.ExpiresAt != nil {
		return ctrl.Result{RequeueAfter: time.Until(binding.Spec.ExpiresAt.Time)}, nil
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) reconcileBinding(
	ctx context.Context,
	log logr.Logger,
	binding *therapistv1alpha1.RBACBinding,
) (*therapistv1alpha1.ManagedBinding, error) {
	hash := hasher.ContentHash(binding.Name + "|" + binding.Spec.ClusterRole + "|" + binding.Spec.Role)
	labels := hasher.ManagedLabels(binding.Name, "RBACBinding", hash)

	if binding.Spec.ClusterWide {
		name := hasher.BindingName(binding.Name, "ClusterRole", binding.Spec.ClusterRole, "")
		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		}
		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, crb, func() error {
			crb.Labels = labels
			crb.RoleRef = rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     binding.Spec.ClusterRole,
			}
			crb.Subjects = binding.Spec.Subjects
			return controllerutil.SetControllerReference(binding, crb, r.Scheme)
		})
		if err != nil {
			return nil, fmt.Errorf("reconciling ClusterRoleBinding: %w", err)
		}
		log.V(4).Info("reconciled ClusterRoleBinding", "name", name)
		return &therapistv1alpha1.ManagedBinding{
			Name:     name,
			Kind:     "ClusterRoleBinding",
			RoleName: binding.Spec.ClusterRole,
		}, nil
	}

	// Namespace-scoped RoleBinding.
	roleKind := "ClusterRole"
	roleName := binding.Spec.ClusterRole
	if binding.Spec.Role != "" {
		roleKind = "Role"
		roleName = binding.Spec.Role
	}

	name := hasher.BindingName(binding.Name, roleKind, roleName, binding.Spec.Namespace)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: binding.Spec.Namespace},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, rb, func() error {
		rb.Labels = labels
		rb.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     roleKind,
			Name:     roleName,
		}
		rb.Subjects = binding.Spec.Subjects
		return controllerutil.SetControllerReference(binding, rb, r.Scheme)
	})
	if err != nil {
		return nil, fmt.Errorf("reconciling RoleBinding %s/%s: %w", binding.Spec.Namespace, name, err)
	}
	log.V(4).Info("reconciled RoleBinding", "name", name, "namespace", binding.Spec.Namespace)
	return &therapistv1alpha1.ManagedBinding{
		Name:      name,
		Namespace: binding.Spec.Namespace,
		Kind:      "RoleBinding",
		RoleName:  roleName,
	}, nil
}

func (r *Reconciler) handleDeletion(ctx context.Context, binding *therapistv1alpha1.RBACBinding) (ctrl.Result, error) {
	controllerutil.RemoveFinalizer(binding, finalizerName)
	return ctrl.Result{}, r.Update(ctx, binding)
}

func (r *Reconciler) handleExpiry(ctx context.Context, log logr.Logger, binding *therapistv1alpha1.RBACBinding) (ctrl.Result, error) {
	log.Info("RBACBinding expired, removing managed binding")

	// Delete owned RoleBindings.
	var rbList rbacv1.RoleBindingList
	if err := r.List(ctx, &rbList, client.MatchingLabels{
		hasher.ManagedByLabel:  hasher.ManagedByValue,
		hasher.PolicyLabel:     binding.Name,
		hasher.PolicyKindLabel: "RBACBinding",
	}); err == nil {
		for i := range rbList.Items {
			_ = r.Delete(ctx, &rbList.Items[i])
		}
	}

	// Delete owned ClusterRoleBindings.
	var crbList rbacv1.ClusterRoleBindingList
	if err := r.List(ctx, &crbList, client.MatchingLabels{
		hasher.ManagedByLabel:  hasher.ManagedByValue,
		hasher.PolicyLabel:     binding.Name,
		hasher.PolicyKindLabel: "RBACBinding",
	}); err == nil {
		for i := range crbList.Items {
			_ = r.Delete(ctx, &crbList.Items[i])
		}
	}

	binding.Status.ManagedBinding = nil
	setCondition(&binding.Status.Conditions, metav1.Condition{
		Type:    conditionExpired,
		Status:  metav1.ConditionTrue,
		Reason:  "BindingExpired",
		Message: fmt.Sprintf("Binding expired at %s. All managed resources removed.", binding.Spec.ExpiresAt),
	})
	setCondition(&binding.Status.Conditions, metav1.Condition{
		Type:    conditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  "BindingExpired",
		Message: "Binding has expired.",
	})
	return ctrl.Result{}, r.Status().Update(ctx, binding)
}

// SetupWithManager registers the controller.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&therapistv1alpha1.RBACBinding{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Complete(r)
}

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
