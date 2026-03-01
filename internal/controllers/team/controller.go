// Package team contains the Team controller.
//
// The Team controller reconciles Team resources. Its primary responsibilities are:
//  1. Resolve spec.extends — compute the full effective member set (union of direct
//     members and all inherited team members), detect circular references.
//  2. Update status.effectiveMembers with the resolved set.
//  3. Set Ready condition.
//
// The Team controller does NOT create any RBAC resources. That is the AccessPolicy
// controller's job. Teams are identity definitions; AccessPolicies are grants.
package team

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
)

const conditionReady = "Ready"

// Reconciler reconciles Team objects.
type Reconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=rbac.therapist.io,resources=teams,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.therapist.io,resources=teams/status,verbs=get;update;patch

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("team", req.Name)

	var team therapistv1alpha1.Team
	if err := r.Get(ctx, req.NamespacedName, &team); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Load all teams for extends resolution.
	var allTeams therapistv1alpha1.TeamList
	if err := r.List(ctx, &allTeams); err != nil {
		return ctrl.Result{}, err
	}

	teamByName := make(map[string]therapistv1alpha1.Team, len(allTeams.Items))
	for _, t := range allTeams.Items {
		teamByName[t.Name] = t
	}

	// Resolve effective members, detecting circular references.
	effectiveMembers, err := resolveEffectiveMembers(&team, teamByName, map[string]bool{})
	if err != nil {
		log.Error(err, "failed to resolve effective members")
		reason := "ResolveError"
		if strings.Contains(strings.ToLower(err.Error()), "circular reference") {
			reason = "CircularReference"
		}
		setCondition(&team.Status.Conditions, metav1.Condition{
			Type:    conditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: err.Error(),
		})
		return ctrl.Result{}, r.Status().Update(ctx, &team)
	}

	team.Status.EffectiveMembers = effectiveMembers
	team.Status.ObservedGeneration = team.Generation
	setCondition(&team.Status.Conditions, metav1.Condition{
		Type:    conditionReady,
		Status:  metav1.ConditionTrue,
		Reason:  "ReconcileSuccess",
		Message: fmt.Sprintf("%d effective members", len(effectiveMembers)),
	})

	if err := r.Status().Update(ctx, &team); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("reconciled", "effectiveMembers", len(effectiveMembers))
	return ctrl.Result{}, nil
}

// resolveEffectiveMembers computes the union of a team's direct members and all
// inherited members from spec.extends. Detects circular references via a visited set.
func resolveEffectiveMembers(
	team *therapistv1alpha1.Team,
	teamByName map[string]therapistv1alpha1.Team,
	visited map[string]bool,
) ([]rbacv1.Subject, error) {
	if visited[team.Name] {
		return nil, fmt.Errorf("circular reference detected in team %q", team.Name)
	}
	visited[team.Name] = true
	defer func() { delete(visited, team.Name) }()

	seen := make(map[string]bool)
	var result []rbacv1.Subject

	addSubject := func(s rbacv1.Subject) {
		key := s.Kind + "/" + s.Namespace + "/" + s.Name
		if !seen[key] {
			seen[key] = true
			result = append(result, s)
		}
	}

	// Direct members first.
	for _, m := range team.Spec.Members {
		addSubject(m)
	}

	// Inherited members from extends.
	for _, ref := range team.Spec.Extends {
		parent, ok := teamByName[ref.Name]
		if !ok {
			return nil, fmt.Errorf("team %q extends non-existent team %q", team.Name, ref.Name)
		}
		inherited, err := resolveEffectiveMembers(&parent, teamByName, visited)
		if err != nil {
			return nil, err
		}
		for _, m := range inherited {
			addSubject(m)
		}
	}

	return result, nil
}

// SetupWithManager registers the controller.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&therapistv1alpha1.Team{}).
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
