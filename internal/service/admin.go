package service

import (
	"context"
	"fmt"
	"time"

	"github.com/invenlore/identity.service/internal/domain"
	"github.com/invenlore/identity.service/internal/repository"
	identity_v1 "github.com/invenlore/proto/pkg/identity/v1"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc/codes"
)

type identityAdminService struct {
	Repository repository.IdentityAdminRepository
	rbacSvc    RBACService
}

type IdentityAdminService interface {
	AddUser(context.Context, *identity_v1.User) (string, codes.Code, error)
	GetUser(context.Context, string) (*identity_v1.User, codes.Code, error)
	DeleteUser(context.Context, string) (codes.Code, error)
	ListUsers(ctx context.Context) ([]*identity_v1.User, string, codes.Code, error)
}

func NewIdentityAdminService(repository repository.IdentityAdminRepository, rbacRepo repository.IdentityRBACRepository) IdentityAdminService {
	return &identityAdminService{
		Repository: repository,
		rbacSvc:    NewRBACService(rbacRepo),
	}
}

func (s *identityAdminService) AddUser(ctx context.Context, u *identity_v1.User) (string, codes.Code, error) {
	now := time.Now().UTC()
	lastInsertId, err := s.Repository.InsertUser(ctx, &domain.User{
		Name:      u.Name,
		Email:     u.Email,
		CreatedAt: now,
		UpdatedAt: now,
	})

	if err != nil {
		return "", codes.Internal, err
	}

	return lastInsertId.Hex(), codes.OK, nil
}

func (s *identityAdminService) GetUser(ctx context.Context, id string) (*identity_v1.User, codes.Code, error) {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, codes.InvalidArgument, fmt.Errorf("converting string to ObjectID failed: %v", err)
	}

	ptrUser, err := s.Repository.FindOneUser(ctx, objID)

	if err != nil {
		switch err {
		case mongo.ErrNoDocuments:
			return nil, codes.NotFound, fmt.Errorf("user for id (%s) is not found", id)
		default:
			return nil, codes.Internal, err
		}
	}

	perms, err := s.rbacSvc.EffectivePermissions(ctx, ptrUser.Id)
	if err != nil {
		return nil, codes.Internal, err
	}

	return &identity_v1.User{
		Id:           ptrUser.Id.Hex(),
		Name:         ptrUser.Name,
		Email:        ptrUser.Email,
		Roles:        perms.Roles,
		PermsGlobal:  perms.GlobalPerms,
		PermsProject: perms.ProjectPerms,
		Scopes:       perms.Scopes,
		CreatedAt:    ptrUser.CreatedAt.Unix(),
		UpdatedAt:    ptrUser.UpdatedAt.Unix(),
	}, codes.OK, nil
}

func (s *identityAdminService) DeleteUser(ctx context.Context, id string) (codes.Code, error) {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return codes.InvalidArgument, fmt.Errorf("converting string to ObjectID failed: %v", err)
	}

	deletedCount, err := s.Repository.DeleteOneUser(ctx, objID)
	if err != nil {
		return codes.Internal, err
	}

	if deletedCount == 0 {
		return codes.NotFound, fmt.Errorf("user for id (%s) is not found", id)
	}

	return codes.OK, nil
}

func (s *identityAdminService) ListUsers(ctx context.Context) ([]*identity_v1.User, string, codes.Code, error) {
	users := make([]*identity_v1.User, 0)

	dbUsers, err := s.Repository.ListUsers(ctx)
	if err != nil {
		return nil, "", codes.Internal, err
	}

	for _, u := range dbUsers {
		perms, err := s.rbacSvc.EffectivePermissions(ctx, u.Id)
		if err != nil {
			return nil, "", codes.Internal, err
		}

		users = append(users, &identity_v1.User{
			Id:           u.Id.Hex(),
			Name:         u.Name,
			Email:        u.Email,
			Roles:        perms.Roles,
			PermsGlobal:  perms.GlobalPerms,
			PermsProject: perms.ProjectPerms,
			Scopes:       perms.Scopes,
			CreatedAt:    u.CreatedAt.Unix(),
			UpdatedAt:    u.UpdatedAt.Unix(),
		})
	}

	return users, "", codes.OK, nil
}
