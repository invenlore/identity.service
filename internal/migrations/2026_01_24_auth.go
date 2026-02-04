package migrations

import (
	"context"
	"fmt"
	"time"

	"github.com/invenlore/core/pkg/migrator"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	Migration_20260124_AuthKeysCollection_1 = migrator.Migration{
		Version: 3,
		Name:    "auth_keys: create collection",
		Up: func(ctx context.Context, db *mongo.Database) error {
			names, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: "auth_keys"}})
			if err != nil {
				return err
			}

			if len(names) > 0 {
				return nil
			}

			return db.CreateCollection(ctx, "auth_keys")
		},
	}

	Migration_20260124_AuthKeysIndexes_1 = migrator.Migration{
		Version: 4,
		Name:    "auth_keys: indexes",
		Up: func(ctx context.Context, db *mongo.Database) error {
			col := db.Collection("auth_keys")
			models := []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "kid", Value: 1}},
					Options: options.Index().SetUnique(true).SetName("uniq_kid"),
				},
				{
					Keys:    bson.D{{Key: "status", Value: 1}},
					Options: options.Index().SetName("idx_status"),
				},
			}

			_, err := col.Indexes().CreateMany(ctx, models)
			return err
		},
	}

	Migration_20260124_RefreshSessionsCollection_1 = migrator.Migration{
		Version: 5,
		Name:    "refresh_sessions: create collection",
		Up: func(ctx context.Context, db *mongo.Database) error {
			names, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: "refresh_sessions"}})
			if err != nil {
				return err
			}

			if len(names) > 0 {
				return nil
			}

			return db.CreateCollection(ctx, "refresh_sessions")
		},
	}

	Migration_20260124_RefreshSessionsIndexes_1 = migrator.Migration{
		Version: 6,
		Name:    "refresh_sessions: indexes",
		Up: func(ctx context.Context, db *mongo.Database) error {
			col := db.Collection("refresh_sessions")
			models := []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "session_id", Value: 1}},
					Options: options.Index().SetUnique(true).SetName("uniq_session_id"),
				},
				{
					Keys:    bson.D{{Key: "user_id", Value: 1}},
					Options: options.Index().SetName("idx_user_id"),
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

	Migration_20260124_UsersAuthFields_1 = migrator.Migration{
		Version: 7,
		Name:    "users: auth fields default",
		Up: func(ctx context.Context, db *mongo.Database) error {
			col := db.Collection("users")
			update := bson.M{
				"$set": bson.M{
					"created_at": time.Now().UTC(),
					"updated_at": time.Now().UTC(),
				},
			}

			_, err := col.UpdateMany(ctx, bson.D{}, update)
			if err != nil {
				return fmt.Errorf("users auth fields migration failed: %w", err)
			}

			return nil
		},
	}
)
