package domain

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type OAuthIdentity struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`
	Provider       string             `bson:"provider"`
	ProviderUserID string             `bson:"provider_user_id"`
	UserID         primitive.ObjectID `bson:"user_id"`
	Email          string             `bson:"email"`
	CreatedAt      time.Time          `bson:"created_at"`
	UpdatedAt      time.Time          `bson:"updated_at"`
}
