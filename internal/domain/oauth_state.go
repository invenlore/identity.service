package domain

import (
	"time"
)

type OAuthState struct {
	State        string    `bson:"state"`
	Provider     string    `bson:"provider"`
	RedirectURI  string    `bson:"redirect_uri"`
	CodeVerifier string    `bson:"code_verifier"`
	ExpiresAt    time.Time `bson:"expires_at"`
}
