package service

import (
	"context"
	"testing"

	"github.com/invenlore/identity.service/internal/domain"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type stubRBACRepo struct {
	roles     map[string]*domain.Role
	userRoles map[primitive.ObjectID][]*domain.UserRole
}

func (s *stubRBACRepo) UpsertRole(ctx context.Context, role *domain.Role) error {
	if role == nil {
		return nil
	}

	if s.roles == nil {
		s.roles = map[string]*domain.Role{}
	}

	s.roles[role.Name] = role
	return nil
}

func (s *stubRBACRepo) GetRole(ctx context.Context, name string) (*domain.Role, error) {
	if s.roles == nil {
		return nil, nil
	}

	role, ok := s.roles[name]
	if !ok {
		return nil, nil
	}

	return role, nil
}

func (s *stubRBACRepo) ListRoles(ctx context.Context, names []string) ([]*domain.Role, error) {
	roles := make([]*domain.Role, 0, len(names))

	for _, name := range names {
		if s.roles == nil {
			continue
		}

		if role, ok := s.roles[name]; ok {
			roles = append(roles, role)
		}
	}

	return roles, nil
}

func (s *stubRBACRepo) ListUserRoles(ctx context.Context, userID primitive.ObjectID) ([]*domain.UserRole, error) {
	if s.userRoles == nil {
		return nil, nil
	}

	return s.userRoles[userID], nil
}

func (s *stubRBACRepo) AssignRole(ctx context.Context, userID primitive.ObjectID, role string, scopes []string) error {
	if s.userRoles == nil {
		s.userRoles = map[primitive.ObjectID][]*domain.UserRole{}
	}

	entry := &domain.UserRole{UserID: userID, Role: role, Scopes: scopes}
	s.userRoles[userID] = append(s.userRoles[userID], entry)

	return nil
}

func TestRBACAuthorize_GlobalPermission(t *testing.T) {
	userID := primitive.NewObjectID()

	repo := &stubRBACRepo{}

	_ = repo.UpsertRole(context.Background(), &domain.Role{
		Name:              "admin",
		GlobalPermissions: []string{"identity.*"},
	})

	_ = repo.AssignRole(context.Background(), userID, "admin", []string{"*"})

	svc := NewRBACService(repo)

	allowed, err := svc.Authorize(context.Background(), userID, "identity.user.delete", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !allowed {
		t.Fatalf("expected global permission to allow action")
	}
}

func TestRBACAuthorize_ProjectPermissionAndScope(t *testing.T) {
	userID := primitive.NewObjectID()

	repo := &stubRBACRepo{}
	_ = repo.UpsertRole(context.Background(), &domain.Role{
		Name:               "editor",
		ProjectPermissions: []string{"wiki.page.edit"},
	})

	_ = repo.AssignRole(context.Background(), userID, "editor", []string{"project-1"})

	svc := NewRBACService(repo)

	allowed, err := svc.Authorize(context.Background(), userID, "wiki.page.edit", "project:project-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !allowed {
		t.Fatalf("expected scoped permission to allow action")
	}

	denied, err := svc.Authorize(context.Background(), userID, "wiki.page.edit", "project:project-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if denied {
		t.Fatalf("expected action to be denied for missing scope")
	}
}
