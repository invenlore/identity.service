package migrations

import (
	"context"

	"github.com/invenlore/core/pkg/migrator"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	Migration_20260210_OAuthStatesConsumedAtIndex_1 = migrator.Migration{
		Version: 18,
		Name:    "oauth_states: add consumed_at index",
		Up: func(ctx context.Context, db *mongo.Database) error {
			col := db.Collection("oauth_states")
			model := mongo.IndexModel{
				Keys:    bson.D{{Key: "consumed_at", Value: 1}},
				Options: options.Index().SetName("idx_consumed_at"),
			}

			_, err := col.Indexes().CreateOne(ctx, model)
			return err
		},
	}
)
