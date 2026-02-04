package migrations

import (
	"context"
	"time"

	"github.com/invenlore/core/pkg/migrator"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	Migration_20260204_RolesCollection_1 = migrator.Migration{
		Version: 9,
		Name:    "roles: create collection",
		Up: func(ctx context.Context, db *mongo.Database) error {
			names, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: "roles"}})
			if err != nil {
				return err
			}

			if len(names) > 0 {
				return nil
			}

			return db.CreateCollection(ctx, "roles")
		},
	}

	Migration_20260204_RolesIndexes_1 = migrator.Migration{
		Version: 10,
		Name:    "roles: indexes",
		Up: func(ctx context.Context, db *mongo.Database) error {
			col := db.Collection("roles")

			model := mongo.IndexModel{
				Keys:    bson.D{{Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true).SetName("uniq_role_name"),
			}

			_, err := col.Indexes().CreateOne(ctx, model)
			return err
		},
	}

	Migration_20260204_UserRolesCollection_1 = migrator.Migration{
		Version: 11,
		Name:    "user_roles: create collection",
		Up: func(ctx context.Context, db *mongo.Database) error {
			names, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: "user_roles"}})
			if err != nil {
				return err
			}

			if len(names) > 0 {
				return nil
			}

			return db.CreateCollection(ctx, "user_roles")
		},
	}

	Migration_20260204_UserRolesIndexes_1 = migrator.Migration{
		Version: 12,
		Name:    "user_roles: indexes",
		Up: func(ctx context.Context, db *mongo.Database) error {
			col := db.Collection("user_roles")

			model := mongo.IndexModel{
				Keys:    bson.D{{Key: "user_id", Value: 1}, {Key: "role", Value: 1}},
				Options: options.Index().SetUnique(true).SetName("uniq_user_role"),
			}

			_, err := col.Indexes().CreateOne(ctx, model)
			return err
		},
	}

	Migration_20260204_RolesSeed_1 = migrator.Migration{
		Version: 13,
		Name:    "roles: seed admin and user",
		Up: func(ctx context.Context, db *mongo.Database) error {
			col := db.Collection("roles")
			now := time.Now().UTC()

			admin := bson.M{
				"name":                "admin",
				"global_permissions":  bson.A{"identity.*", "wiki.*", "media.*", "gateway.swagger.read"},
				"project_permissions": bson.A{"wiki.*"},
				"created_at":          now,
				"updated_at":          now,
			}

			user := bson.M{
				"name":                "user",
				"global_permissions":  bson.A{"wiki.project.create", "wiki.project.update", "wiki.project.delete"},
				"project_permissions": bson.A{"wiki.page.read", "wiki.page.create", "wiki.page.edit", "wiki.page.delete", "wiki.project.invite"},
				"created_at":          now,
				"updated_at":          now,
			}

			_, _ = col.UpdateOne(ctx, bson.M{"name": "admin"}, bson.M{"$set": admin}, options.Update().SetUpsert(true))
			_, _ = col.UpdateOne(ctx, bson.M{"name": "user"}, bson.M{"$set": user}, options.Update().SetUpsert(true))
			return nil
		},
	}
)
