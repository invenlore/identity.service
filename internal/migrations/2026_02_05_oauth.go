package migrations

import (
	"context"

	"github.com/invenlore/core/pkg/migrator"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	Migration_20260205_OAuthStatesCollection_1 = migrator.Migration{
		Version: 14,
		Name:    "oauth_states: create collection",
		Up: func(ctx context.Context, db *mongo.Database) error {
			names, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: "oauth_states"}})
			if err != nil {
				return err
			}

			if len(names) > 0 {
				return nil
			}

			return db.CreateCollection(ctx, "oauth_states")
		},
	}

	Migration_20260205_OAuthStatesIndexes_1 = migrator.Migration{
		Version: 15,
		Name:    "oauth_states: indexes",
		Up: func(ctx context.Context, db *mongo.Database) error {
			col := db.Collection("oauth_states")
			models := []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "state", Value: 1}},
					Options: options.Index().SetUnique(true).SetName("uniq_state"),
				},
				{
					Keys:    bson.D{{Key: "expires_at", Value: 1}},
					Options: options.Index().SetExpireAfterSeconds(0).SetName("ttl_expires_at"),
				},
			}

			_, err := col.Indexes().CreateMany(ctx, models)
			return err
		},
	}

	Migration_20260205_OAuthIdentitiesCollection_1 = migrator.Migration{
		Version: 16,
		Name:    "oauth_identities: create collection",
		Up: func(ctx context.Context, db *mongo.Database) error {
			names, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: "oauth_identities"}})
			if err != nil {
				return err
			}

			if len(names) > 0 {
				return nil
			}

			return db.CreateCollection(ctx, "oauth_identities")
		},
	}

	Migration_20260205_OAuthIdentitiesIndexes_1 = migrator.Migration{
		Version: 17,
		Name:    "oauth_identities: indexes",
		Up: func(ctx context.Context, db *mongo.Database) error {
			col := db.Collection("oauth_identities")
			models := []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "provider", Value: 1}, {Key: "provider_user_id", Value: 1}},
					Options: options.Index().SetUnique(true).SetName("uniq_provider_user"),
				},
				{
					Keys:    bson.D{{Key: "user_id", Value: 1}},
					Options: options.Index().SetName("idx_user_id"),
				},
			}

			_, err := col.Indexes().CreateMany(ctx, models)
			return err
		},
	}
)
