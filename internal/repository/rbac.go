package repository

import (
	"context"
	"time"

	"github.com/invenlore/core/pkg/config"
	"github.com/invenlore/identity.service/internal/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type IdentityRBACRepository interface {
	UpsertRole(ctx context.Context, role *domain.Role) error
	GetRole(ctx context.Context, name string) (*domain.Role, error)
	ListRoles(ctx context.Context, names []string) ([]*domain.Role, error)
	ListUserRoles(ctx context.Context, userID primitive.ObjectID) ([]*domain.UserRole, error)
	AssignRole(ctx context.Context, userID primitive.ObjectID, role string, scopes []string) error
}

type identityRBACRepository struct {
	rolesCol     *mongo.Collection
	userRolesCol *mongo.Collection
	cfg          *config.MongoConfig
}

func NewIdentityRBACRepository(db *mongo.Client, cfg *config.MongoConfig) IdentityRBACRepository {
	database := db.Database(cfg.DatabaseName)

	return &identityRBACRepository{
		rolesCol:     database.Collection("roles"),
		userRolesCol: database.Collection("user_roles"),
		cfg:          cfg,
	}
}

func (r *identityRBACRepository) UpsertRole(ctx context.Context, role *domain.Role) error {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.OperationTimeout)
	defer cancel()

	if role == nil {
		return nil
	}

	now := time.Now().UTC()
	filter := bson.M{"name": role.Name}
	update := bson.M{
		"$set": bson.M{
			"global_permissions":  role.GlobalPermissions,
			"project_permissions": role.ProjectPermissions,
			"updated_at":          now,
		},
		"$setOnInsert": bson.M{
			"created_at": now,
		},
	}

	_, err := r.rolesCol.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	return err
}

func (r *identityRBACRepository) GetRole(ctx context.Context, name string) (*domain.Role, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.OperationTimeout)
	defer cancel()

	var role domain.Role
	if err := r.rolesCol.FindOne(ctx, bson.M{"name": name}).Decode(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (r *identityRBACRepository) ListRoles(ctx context.Context, names []string) ([]*domain.Role, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.OperationTimeout)
	defer cancel()

	if len(names) == 0 {
		return []*domain.Role{}, nil
	}

	filter := bson.M{"name": bson.M{"$in": names}}
	cur, err := r.rolesCol.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cur.Close(context.Background()) }()

	roles := make([]*domain.Role, 0)
	for cur.Next(ctx) {
		var role domain.Role
		if err := cur.Decode(&role); err != nil {
			return nil, err
		}
		roles = append(roles, &role)
	}
	if err := cur.Err(); err != nil {
		return nil, err
	}

	return roles, nil
}

func (r *identityRBACRepository) ListUserRoles(ctx context.Context, userID primitive.ObjectID) ([]*domain.UserRole, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.OperationTimeout)
	defer cancel()

	cur, err := r.userRolesCol.Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, err
	}
	defer func() { _ = cur.Close(context.Background()) }()

	roles := make([]*domain.UserRole, 0)
	for cur.Next(ctx) {
		var role domain.UserRole
		if err := cur.Decode(&role); err != nil {
			return nil, err
		}
		roles = append(roles, &role)
	}
	if err := cur.Err(); err != nil {
		return nil, err
	}

	return roles, nil
}

func (r *identityRBACRepository) AssignRole(ctx context.Context, userID primitive.ObjectID, role string, scopes []string) error {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.OperationTimeout)
	defer cancel()

	now := time.Now().UTC()
	filter := bson.M{"user_id": userID, "role": role}
	update := bson.M{
		"$set": bson.M{
			"scopes":     scopes,
			"updated_at": now,
		},
		"$setOnInsert": bson.M{
			"created_at": now,
		},
	}

	_, err := r.userRolesCol.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	return err
}
