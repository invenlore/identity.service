package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/invenlore/identity.service/internal/repository"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type RBACPermissions struct {
	Roles        []string
	GlobalPerms  []string
	ProjectPerms []string
	Scopes       []string
}

type RBACService interface {
	EffectivePermissions(ctx context.Context, userID primitive.ObjectID) (*RBACPermissions, error)
	Authorize(ctx context.Context, userID primitive.ObjectID, action, resource string) (bool, error)
	AssignRole(ctx context.Context, userID primitive.ObjectID, role string, scopes []string) error
}

type rbacService struct {
	repo repository.IdentityRBACRepository
}

func NewRBACService(repo repository.IdentityRBACRepository) RBACService {
	return &rbacService{repo: repo}
}

func (s *rbacService) AssignRole(ctx context.Context, userID primitive.ObjectID, role string, scopes []string) error {
	return s.repo.AssignRole(ctx, userID, role, scopes)
}

func (s *rbacService) EffectivePermissions(ctx context.Context, userID primitive.ObjectID) (*RBACPermissions, error) {
	userRoles, err := s.repo.ListUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	roleNames := make([]string, 0, len(userRoles))
	scopes := make([]string, 0)

	for _, role := range userRoles {
		roleNames = append(roleNames, role.Role)
		scopes = append(scopes, role.Scopes...)
	}

	roles, err := s.repo.ListRoles(ctx, roleNames)
	if err != nil {
		return nil, err
	}

	globalPerms := make([]string, 0)
	projectPerms := make([]string, 0)

	for _, role := range roles {
		globalPerms = append(globalPerms, role.GlobalPermissions...)
		projectPerms = append(projectPerms, role.ProjectPermissions...)
	}

	return &RBACPermissions{
		Roles:        uniqueStrings(roleNames),
		GlobalPerms:  uniqueStrings(globalPerms),
		ProjectPerms: uniqueStrings(projectPerms),
		Scopes:       uniqueStrings(scopes),
	}, nil
}

func (s *rbacService) Authorize(ctx context.Context, userID primitive.ObjectID, action, resource string) (bool, error) {
	perms, err := s.EffectivePermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	projectID, scoped := parseResourceProject(resource)
	if !scoped {
		return hasPermission(perms.GlobalPerms, action), nil
	}

	if !hasPermission(perms.ProjectPerms, action) {
		return false, nil
	}

	return scopeMatches(perms.Scopes, projectID), nil
}

func hasPermission(perms []string, action string) bool {
	for _, perm := range perms {
		if perm == action {
			return true
		}

		if strings.HasSuffix(perm, ".*") && strings.HasPrefix(action, strings.TrimSuffix(perm, "*")) {
			return true
		}
	}

	return false
}

func scopeMatches(scopes []string, projectID string) bool {
	for _, scope := range scopes {
		if scope == "*" || scope == projectID {
			return true
		}
	}

	return false
}

func parseResourceProject(resource string) (string, bool) {
	parts := strings.Split(resource, ":")
	if len(parts) < 2 {
		return "", false
	}

	projectID := strings.TrimSpace(parts[1])
	if projectID == "" {
		return "", false
	}

	return projectID, true
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(items))

	for _, item := range items {
		value := strings.TrimSpace(item)

		if value == "" {
			continue
		}

		if _, ok := seen[value]; ok {
			continue
		}

		seen[value] = struct{}{}
		result = append(result, value)
	}

	return result
}

func ValidateResource(resource string) error {
	if strings.TrimSpace(resource) == "" {
		return nil
	}

	parts := strings.Split(resource, ":")

	if len(parts) < 2 {
		return fmt.Errorf("resource must include project id")
	}

	if strings.TrimSpace(parts[1]) == "" {
		return fmt.Errorf("resource project id is empty")
	}

	return nil
}
