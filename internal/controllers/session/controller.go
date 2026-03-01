// Package session contains the RBACSession session-notes controller.
//
// The RBACSession controller periodically reconciles a cluster-wide session-notes snapshot
// of all RBAC access managed by rbac-therapist. It reads all AccessPolicies,
// RBACBindings, and Teams, then builds the full SubjectAccess and
// NamespaceAccess indexes stored in status.
//
// There is always exactly one RBACSession named "current". The controller
// creates it on first run and updates it on every reconcile cycle.
// An annotation on the RBACSession can be used to force an immediate refresh
// (set by `rbact snapshot`).
package session

import (
	"context"
	"fmt"
	"strings"
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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	therapistv1alpha1 "github.com/rbac-therapist/rbac-therapist/api/v1alpha1"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/inheritance"
	"github.com/rbac-therapist/rbac-therapist/internal/engine/parser"
)

const (
	// SessionName is the canonical name of the singleton RBACSession resource.
	SessionName = "current"

	// ForceRefreshAnnotation triggers an immediate refresh when set to "true".
	// The operator removes it after processing. Set by `rbact snapshot`.
	ForceRefreshAnnotation = "rbac.therapist.io/force-refresh"

	// DefaultRefreshInterval is how often session-notes refresh absent changes.
	DefaultRefreshInterval = 5 * time.Minute
)

// Reconciler reconciles the singleton RBACSession resource.
type Reconciler struct {
	client.Client
	Log             logr.Logger
	Scheme          *runtime.Scheme
	RefreshInterval time.Duration
}

// +kubebuilder:rbac:groups=rbac.therapist.io,resources=rbacsessions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.therapist.io,resources=rbacsessions/status,verbs=get;update;patch

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("session", req.Name)

	if req.Name != SessionName {
		return ctrl.Result{}, nil
	}

	// Fetch or create the singleton RBACSession.
	session := &therapistv1alpha1.RBACSession{}
	err := r.Get(ctx, types.NamespacedName{Name: SessionName}, session)
	if errors.IsNotFound(err) {
		session = &therapistv1alpha1.RBACSession{
			ObjectMeta: metav1.ObjectMeta{Name: SessionName},
		}
		if createErr := r.Create(ctx, session); createErr != nil {
			return ctrl.Result{}, fmt.Errorf("creating RBACSession: %w", createErr)
		}
		return ctrl.Result{Requeue: true}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	forceRefresh := session.Annotations[ForceRefreshAnnotation] == "true"

	// Load all data sources.
	var policies therapistv1alpha1.AccessPolicyList
	if err := r.List(ctx, &policies); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing AccessPolicies: %w", err)
	}
	var rbacBindings therapistv1alpha1.RBACBindingList
	if err := r.List(ctx, &rbacBindings); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing RBACBindings: %w", err)
	}
	var teams therapistv1alpha1.TeamList
	if err := r.List(ctx, &teams); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing Teams: %w", err)
	}
	var namespaces corev1.NamespaceList
	if err := r.List(ctx, &namespaces); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing Namespaces: %w", err)
	}

	// Build the session-notes snapshot.
	status, warnings := buildSnapshot(policies.Items, rbacBindings.Items, teams.Items, namespaces.Items)
	now := metav1.Now()
	status.GeneratedAt = &now
	status.Warnings = warnings
	session.Status = *status

	if err := r.Status().Update(ctx, session); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating RBACSession status: %w", err)
	}

	// Remove force-refresh annotation.
	if forceRefresh {
		patch := client.MergeFrom(session.DeepCopy())
		if session.Annotations != nil {
			delete(session.Annotations, ForceRefreshAnnotation)
		}
		if err := r.Patch(ctx, session, patch); err != nil {
			log.Error(err, "failed to remove force-refresh annotation")
		}
	}

	interval := r.RefreshInterval
	if interval == 0 {
		interval = DefaultRefreshInterval
	}

	log.Info("session-notes updated",
		"subjects", len(status.SubjectAccess),
		"namespaces", len(status.NamespaceAccess),
		"policies", len(status.PolicySummaries),
		"warnings", len(warnings),
	)

	return ctrl.Result{RequeueAfter: interval}, nil
}

// buildSnapshot constructs the full RBACSession status from all managed resources.
func buildSnapshot(
	policies []therapistv1alpha1.AccessPolicy,
	rbacBindings []therapistv1alpha1.RBACBinding,
	teams []therapistv1alpha1.Team,
	namespaces []corev1.Namespace,
) (*therapistv1alpha1.RBACSessionStatus, []string) {
	var warnings []string

	subjectTeams := buildSubjectTeamIndex(teams)

	nsLabels := make(map[string]map[string]string, len(namespaces))
	for _, ns := range namespaces {
		nsLabels[ns.Name] = ns.Labels
	}

	// subject key → grants
	subjectGrants := make(map[string][]therapistv1alpha1.AccessGrant)
	subjectByKey := make(map[string]rbacv1.Subject)
	// namespace → namespace grants
	nsGrants := make(map[string][]therapistv1alpha1.NamespaceAccessGrant)

	addGrant := func(subj rbacv1.Subject, grant therapistv1alpha1.AccessGrant, policyRef string) {
		key := subjectKey(subj)
		subjectByKey[key] = subj
		subjectGrants[key] = append(subjectGrants[key], grant)
		if grant.Namespace != "" {
			nsGrants[grant.Namespace] = append(nsGrants[grant.Namespace], therapistv1alpha1.NamespaceAccessGrant{
				Subject:   subj,
				Role:      grant.Role,
				PolicyRef: policyRef,
			})
		}
	}

	// Index AccessPolicy grants.
	resolver := inheritance.NewAccessPolicyResolver(policies, inheritance.DefaultMaxPolicyExtendsDepth)

	for _, policy := range policies {
		if policy.Spec.ExpiresAt != nil && policy.Spec.ExpiresAt.Before(&metav1.Time{Time: time.Now()}) {
			warnings = append(warnings, fmt.Sprintf("AccessPolicy %q has expired but still exists — delete or renew", policy.Name))
			continue
		}
		if policy.Spec.Paused {
			continue
		}

		effectivePolicy, err := resolver.ResolveEffectivePolicy(policy)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("AccessPolicy %q extends resolution failed: %v", policy.Name, err))
			effectivePolicy = policy
		}

		desired := parser.Parse(parser.Input{
			Policy:     effectivePolicy,
			Teams:      teams,
			Namespaces: namespaces,
		})
		desiredByName := make(map[string]parser.DesiredBinding, len(desired))
		for _, db := range desired {
			desiredByName[db.Name] = db
		}

		fallbackSubjects := resolveSubjectsFromPolicy(effectivePolicy, teams)
		for _, mb := range policy.Status.ManagedBindings {
			db, found := desiredByName[mb.Name]
			subjects := fallbackSubjects
			roleKind := "ClusterRole"
			matchReason := ""
			if found {
				subjects = db.Subjects
				roleKind = db.RoleRef.Kind
				matchReason = db.MatchReason
			}
			for _, subj := range subjects {
				addGrant(subj, therapistv1alpha1.AccessGrant{
					Role:        mb.RoleName,
					RoleKind:    roleKind,
					Namespace:   mb.Namespace,
					ClusterWide: mb.Kind == "ClusterRoleBinding",
					Via: therapistv1alpha1.AccessGrantProvenance{
						PolicyRef:   policy.Name,
						PolicyKind:  "AccessPolicy",
						TeamRef:     findTeamRefForSubject(policy, subj, subjectTeams),
						MatchReason: matchReason,
						Rationale:   policy.Spec.Rationale,
					},
				}, policy.Name)
			}
		}
		// Warn on high-privilege.
		for _, role := range effectivePolicy.Spec.Roles {
			if role.ClusterRole == "cluster-admin" {
				warnings = append(warnings, fmt.Sprintf("AccessPolicy %q grants cluster-admin — review carefully", policy.Name))
			}
		}
	}

	// Index RBACBinding grants.
	for _, rb := range rbacBindings {
		if rb.Spec.ExpiresAt != nil && rb.Spec.ExpiresAt.Before(&metav1.Time{Time: time.Now()}) {
			warnings = append(warnings, fmt.Sprintf("RBACBinding %q has expired but still exists — delete it", rb.Name))
			continue
		}
		if rb.Status.ManagedBinding == nil {
			continue
		}
		mb := rb.Status.ManagedBinding
		roleKind := "ClusterRole"
		if rb.Spec.Role != "" {
			roleKind = "Role"
		}
		for _, subj := range rb.Spec.Subjects {
			addGrant(subj, therapistv1alpha1.AccessGrant{
				Role:        mb.RoleName,
				RoleKind:    roleKind,
				Namespace:   mb.Namespace,
				ClusterWide: mb.Kind == "ClusterRoleBinding",
				Via: therapistv1alpha1.AccessGrantProvenance{
					PolicyRef:  rb.Name,
					PolicyKind: "RBACBinding",
					Rationale:  rb.Spec.Rationale,
				},
			}, rb.Name)
		}
		if rb.Spec.ClusterRole == "cluster-admin" && rb.Spec.ExpiresAt == nil {
			warnings = append(warnings, fmt.Sprintf("RBACBinding %q grants cluster-admin with no expiry", rb.Name))
		}
	}

	// Build SubjectAccess.
	var subjectAccess []therapistv1alpha1.SubjectAccessEntry
	for key, grants := range subjectGrants {
		subjectAccess = append(subjectAccess, therapistv1alpha1.SubjectAccessEntry{
			Subject: subjectByKey[key],
			Teams:   subjectTeams[key],
			Access:  grants,
		})
	}

	// Build NamespaceAccess.
	var namespaceAccess []therapistv1alpha1.NamespaceAccessEntry
	for ns, grants := range nsGrants {
		namespaceAccess = append(namespaceAccess, therapistv1alpha1.NamespaceAccessEntry{
			Namespace: ns,
			Labels:    nsLabels[ns],
			Grants:    grants,
		})
	}

	// Build PolicySummaries.
	var summaries []therapistv1alpha1.PolicySummary
	for _, policy := range policies {
		subjects := resolveSubjectsFromPolicy(policy, teams)
		summaries = append(summaries, therapistv1alpha1.PolicySummary{
			Name:                  policy.Name,
			Rationale:             policy.Spec.Rationale,
			EffectiveSubjectCount: len(subjects),
			ManagedBindingCount:   len(policy.Status.ManagedBindings),
			Paused:                policy.Spec.Paused,
			ExpiresAt:             policy.Spec.ExpiresAt,
		})
	}

	return &therapistv1alpha1.RBACSessionStatus{
		SubjectAccess:   subjectAccess,
		NamespaceAccess: namespaceAccess,
		PolicySummaries: summaries,
	}, warnings
}

func buildSubjectTeamIndex(teams []therapistv1alpha1.Team) map[string][]string {
	index := make(map[string][]string)
	for _, t := range teams {
		members := t.Status.EffectiveMembers
		if len(members) == 0 {
			members = t.Spec.Members
		}
		for _, m := range members {
			key := subjectKey(m)
			index[key] = append(index[key], t.Name)
		}
	}
	return index
}

func resolveSubjectsFromPolicy(policy therapistv1alpha1.AccessPolicy, teams []therapistv1alpha1.Team) []rbacv1.Subject {
	teamByName := make(map[string]therapistv1alpha1.Team, len(teams))
	for _, t := range teams {
		teamByName[t.Name] = t
	}
	seen := make(map[string]bool)
	var result []rbacv1.Subject
	add := func(s rbacv1.Subject) {
		k := subjectKey(s)
		if !seen[k] {
			seen[k] = true
			result = append(result, s)
		}
	}
	for _, ps := range policy.Spec.Subjects {
		if ps.TeamRef != nil {
			if t, ok := teamByName[ps.TeamRef.Name]; ok {
				members := t.Status.EffectiveMembers
				if len(members) == 0 {
					members = t.Spec.Members
				}
				for _, m := range members {
					add(m)
				}
			}
		}
		if ps.Inline != nil {
			add(*ps.Inline)
		}
	}
	return result
}

func findTeamRefForSubject(
	policy therapistv1alpha1.AccessPolicy,
	subject rbacv1.Subject,
	subjectTeams map[string][]string,
) string {
	policyTeamRefs := make(map[string]bool)
	for _, ps := range policy.Spec.Subjects {
		if ps.TeamRef != nil {
			policyTeamRefs[ps.TeamRef.Name] = true
		}
	}

	for _, team := range subjectTeams[subjectKey(subject)] {
		if policyTeamRefs[team] {
			return team
		}
	}
	return ""
}

func subjectKey(s rbacv1.Subject) string {
	return s.Kind + "/" + s.Namespace + "/" + s.Name
}

// SetupWithManager registers the controller with watches that enqueue the singleton.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	enqueueSingleton := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
		return []reconcile.Request{
			{NamespacedName: types.NamespacedName{Name: SessionName}},
		}
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&therapistv1alpha1.RBACSession{}).
		Watches(&therapistv1alpha1.AccessPolicy{}, enqueueSingleton).
		Watches(&therapistv1alpha1.RBACBinding{}, enqueueSingleton).
		Watches(&therapistv1alpha1.Team{}, enqueueSingleton).
		Complete(r)
}

// splitSubjectKey is the inverse of subjectKey — exported for tests.
func splitSubjectKey(key string) rbacv1.Subject {
	parts := strings.SplitN(key, "/", 3)
	if len(parts) == 3 {
		return rbacv1.Subject{Kind: parts[0], Namespace: parts[1], Name: parts[2]}
	}
	return rbacv1.Subject{Name: key}
}
