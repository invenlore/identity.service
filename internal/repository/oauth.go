package repository

import (
	"context"
	"strings"

	"github.com/invenlore/core/pkg/config"
	"github.com/invenlore/identity.service/internal/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type IdentityOAuthRepository interface {
	SaveState(ctx context.Context, state *domain.OAuthState) error
	ConsumeState(ctx context.Context, state string) (*domain.OAuthState, error)
	FindOAuthIdentity(ctx context.Context, provider, providerUserID string) (*domain.OAuthIdentity, error)
	UpsertOAuthIdentity(ctx context.Context, identity *domain.OAuthIdentity) error
}

type identityOAuthRepository struct {
	statesCol     *mongo.Collection
	identitiesCol *mongo.Collection
	cfg           *config.MongoConfig
}

func NewIdentityOAuthRepository(db *mongo.Client, cfg *config.MongoConfig) IdentityOAuthRepository {
	database := db.Database(cfg.DatabaseName)

	return &identityOAuthRepository{
		statesCol:     database.Collection("oauth_states"),
		identitiesCol: database.Collection("oauth_identities"),
		cfg:           cfg,
	}
}

func (r *identityOAuthRepository) SaveState(ctx context.Context, state *domain.OAuthState) error {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.OperationTimeout)
	defer cancel()

	_, err := r.statesCol.InsertOne(ctx, state)
	return err
}

func (r *identityOAuthRepository) ConsumeState(ctx context.Context, state string) (*domain.OAuthState, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.OperationTimeout)
	defer cancel()

	if strings.TrimSpace(state) == "" {
		return nil, mongo.ErrNoDocuments
	}

	filter := bson.M{"state": state}
	var result domain.OAuthState

	err := r.statesCol.FindOneAndDelete(ctx, filter).Decode(&result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (r *identityOAuthRepository) FindOAuthIdentity(ctx context.Context, provider, providerUserID string) (*domain.OAuthIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.OperationTimeout)
	defer cancel()

	filter := bson.M{
		"provider":         provider,
		"provider_user_id": providerUserID,
	}

	var identity domain.OAuthIdentity

	if err := r.identitiesCol.FindOne(ctx, filter).Decode(&identity); err != nil {
		return nil, err
	}

	return &identity, nil
}

func (r *identityOAuthRepository) UpsertOAuthIdentity(ctx context.Context, identity *domain.OAuthIdentity) error {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.OperationTimeout)
	defer cancel()

	filter := bson.M{
		"provider":         identity.Provider,
		"provider_user_id": identity.ProviderUserID,
	}

	update := bson.M{"$set": bson.M{
		"user_id":    identity.UserID,
		"email":      identity.Email,
		"updated_at": identity.UpdatedAt,
	}, "$setOnInsert": bson.M{
		"created_at": identity.CreatedAt,
	}}

	_, err := r.identitiesCol.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	return err
}
