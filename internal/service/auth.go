package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/invenlore/core/pkg/config"
	"github.com/invenlore/identity.service/internal/domain"
	"github.com/invenlore/identity.service/internal/repository"
	identity_v1 "github.com/invenlore/proto/pkg/identity/v1"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/argon2"
	"google.golang.org/grpc/codes"
)

type IdentityAuthService interface {
	Register(ctx context.Context, req *identity_v1.RegisterRequest) (*identity_v1.RegisterResponse, codes.Code, error)
	Login(ctx context.Context, req *identity_v1.LoginRequest, userAgent, ip string) (*identity_v1.LoginResponse, codes.Code, error)
	Refresh(ctx context.Context, req *identity_v1.RefreshRequest, userAgent, ip string) (*identity_v1.RefreshResponse, codes.Code, error)
	Logout(ctx context.Context, req *identity_v1.LogoutRequest) (codes.Code, error)
	GetJWKS(ctx context.Context) (*identity_v1.JWKSet, codes.Code, error)
	EnsureActiveKey(ctx context.Context) error
	ValidateToken(ctx context.Context, token string) (*ValidatedClaims, error)
}

type ValidatedClaims struct {
	Subject      string
	Roles        []string
	PermsGlobal  []string
	PermsProject []string
	Scopes       []string
}

type identityAuthService struct {
	repo       repository.IdentityAuthRepository
	rbacRepo   repository.IdentityRBACRepository
	rbacSvc    RBACService
	accessTTL  time.Duration
	refreshTTL time.Duration
	issuer     string
	audience   string
}

func NewIdentityAuthService(repo repository.IdentityAuthRepository, rbacRepo repository.IdentityRBACRepository, authCfg *config.AuthConfig) IdentityAuthService {
	rbacSvc := NewRBACService(rbacRepo)

	return &identityAuthService{
		repo:       repo,
		rbacRepo:   rbacRepo,
		rbacSvc:    rbacSvc,
		accessTTL:  authCfg.AccessTokenTTL,
		refreshTTL: authCfg.RefreshTokenTTL,
		issuer:     strings.TrimSpace(authCfg.JWTIssuer),
		audience:   strings.TrimSpace(authCfg.JWTAudience),
	}
}

func (s *identityAuthService) Register(ctx context.Context, req *identity_v1.RegisterRequest) (*identity_v1.RegisterResponse, codes.Code, error) {
	if req == nil || strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.Password) == "" {
		return nil, codes.InvalidArgument, fmt.Errorf("email and password are required")
	}

	now := time.Now().UTC()

	user := &domain.User{
		Name:         strings.TrimSpace(req.Name),
		Email:        strings.ToLower(strings.TrimSpace(req.Email)),
		PasswordHash: hashPassword(req.Password),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	id, err := s.repo.InsertUserCredentials(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return nil, codes.AlreadyExists, fmt.Errorf("email already exists")
		}

		return nil, codes.Internal, err
	}

	if err := s.rbacRepo.AssignRole(ctx, id, "user", []string{}); err != nil {
		return nil, codes.Internal, err
	}

	perms, err := s.rbacSvc.EffectivePermissions(ctx, id)
	if err != nil {
		return nil, codes.Internal, err
	}

	return &identity_v1.RegisterResponse{
		Id: id.Hex(),
		User: &identity_v1.User{
			Id:           id.Hex(),
			Name:         user.Name,
			Email:        user.Email,
			Roles:        perms.Roles,
			PermsGlobal:  perms.GlobalPerms,
			PermsProject: perms.ProjectPerms,
			Scopes:       perms.Scopes,
			CreatedAt:    user.CreatedAt.Unix(),
			UpdatedAt:    user.UpdatedAt.Unix(),
		},
	}, codes.OK, nil
}

func (s *identityAuthService) Login(ctx context.Context, req *identity_v1.LoginRequest, userAgent, ip string) (*identity_v1.LoginResponse, codes.Code, error) {
	if req == nil || strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.Password) == "" {
		return nil, codes.InvalidArgument, fmt.Errorf("email and password are required")
	}

	user, err := s.repo.FindUserByEmail(ctx, strings.ToLower(strings.TrimSpace(req.Email)))
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, codes.NotFound, fmt.Errorf("user not found")
		}

		return nil, codes.Internal, err
	}

	if !verifyPassword(req.Password, user.PasswordHash) {
		return nil, codes.Unauthenticated, fmt.Errorf("invalid credentials")
	}

	perms, err := s.rbacSvc.EffectivePermissions(ctx, user.Id)
	if err != nil {
		return nil, codes.Internal, err
	}

	accessToken, expiresIn, err := s.issueAccessToken(ctx, user)
	if err != nil {
		return nil, codes.Internal, err
	}

	refreshToken, sessionID, err := s.issueRefreshSession(ctx, user, userAgent, ip)
	if err != nil {
		return nil, codes.Internal, err
	}

	_ = sessionID

	return &identity_v1.LoginResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		ExpiresInSeconds: expiresIn,
		User: &identity_v1.User{
			Id:           user.Id.Hex(),
			Name:         user.Name,
			Email:        user.Email,
			Roles:        perms.Roles,
			PermsGlobal:  perms.GlobalPerms,
			PermsProject: perms.ProjectPerms,
			Scopes:       perms.Scopes,
			CreatedAt:    user.CreatedAt.Unix(),
			UpdatedAt:    user.UpdatedAt.Unix(),
		},
	}, codes.OK, nil
}

func (s *identityAuthService) Refresh(ctx context.Context, req *identity_v1.RefreshRequest, userAgent, ip string) (*identity_v1.RefreshResponse, codes.Code, error) {
	if req == nil || strings.TrimSpace(req.RefreshToken) == "" {
		return nil, codes.InvalidArgument, fmt.Errorf("refresh token is required")
	}

	sessionID, tokenHash, err := splitRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, codes.InvalidArgument, err
	}

	session, err := s.repo.FindRefreshSession(ctx, sessionID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, codes.NotFound, fmt.Errorf("session not found")
		}

		return nil, codes.Internal, err
	}

	if session.RevokedAt != nil || time.Now().After(session.ExpiresAt) {
		return nil, codes.Unauthenticated, fmt.Errorf("refresh token expired")
	}
	if session.RefreshTokenHash != tokenHash {
		return nil, codes.Unauthenticated, fmt.Errorf("refresh token invalid")
	}

	user, err := s.repo.FindUserByID(ctx, session.UserID)
	if err != nil {
		return nil, codes.Internal, err
	}

	accessToken, expiresIn, err := s.issueAccessToken(ctx, user)
	if err != nil {
		return nil, codes.Internal, err
	}

	newRefreshToken, newHash, err := buildRefreshToken(session.SessionID)
	if err != nil {
		return nil, codes.Internal, err
	}

	now := time.Now().UTC()
	newExpires := now.Add(s.refreshTTL)

	if err := s.repo.RotateRefreshSession(ctx, session.SessionID, newHash, newExpires, now); err != nil {
		return nil, codes.Internal, err
	}

	return &identity_v1.RefreshResponse{
		AccessToken:      accessToken,
		RefreshToken:     newRefreshToken,
		ExpiresInSeconds: expiresIn,
	}, codes.OK, nil
}

func (s *identityAuthService) Logout(ctx context.Context, req *identity_v1.LogoutRequest) (codes.Code, error) {
	if req == nil || strings.TrimSpace(req.RefreshToken) == "" {
		return codes.InvalidArgument, fmt.Errorf("refresh token is required")
	}

	sessionID, _, err := splitRefreshToken(req.RefreshToken)
	if err != nil {
		return codes.InvalidArgument, err
	}

	if err := s.repo.RevokeRefreshSession(ctx, sessionID, time.Now().UTC()); err != nil {
		if err == mongo.ErrNoDocuments {
			return codes.NotFound, fmt.Errorf("session not found")
		}

		return codes.Internal, err
	}

	return codes.OK, nil
}

func (s *identityAuthService) GetJWKS(ctx context.Context) (*identity_v1.JWKSet, codes.Code, error) {
	keys, err := s.repo.ListActivePublicKeys(ctx)
	if err != nil {
		return nil, codes.Internal, err
	}

	result := &identity_v1.JWKSet{Keys: make([]*identity_v1.JWK, 0, len(keys))}
	for _, key := range keys {
		jwk, err := buildJWKFromPEM(key)

		if err != nil {
			return nil, codes.Internal, err
		}

		result.Keys = append(result.Keys, jwk)
	}

	return result, codes.OK, nil
}

func (s *identityAuthService) EnsureActiveKey(ctx context.Context) error {
	return EnsureActiveKey(ctx, s.repo)
}

func (s *identityAuthService) ValidateToken(ctx context.Context, token string) (*ValidatedClaims, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("token is required")
	}

	keySet, err := s.repo.ListActivePublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	keyMap := make(map[string]*rsa.PublicKey)
	for _, key := range keySet {
		pub, err := parseRSAPublicKey(key.PublicKeyPEM)
		if err != nil {
			return nil, err
		}
		if key.Kid != "" {
			keyMap[key.Kid] = pub
		}
	}

	parser := jwt.NewParser(jwt.WithAudience(s.audience), jwt.WithIssuer(s.issuer))
	claims := jwt.MapClaims{}

	_, err = parser.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("token kid missing")
		}
		key, ok := keyMap[kid]
		if !ok {
			return nil, fmt.Errorf("unknown kid")
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}

	return &ValidatedClaims{
		Subject:      claimString(claims, "sub"),
		Roles:        claimStringSlice(claims, "roles"),
		PermsGlobal:  claimStringSlice(claims, "perms_global"),
		PermsProject: claimStringSlice(claims, "perms_project"),
		Scopes:       claimStringSlice(claims, "scopes"),
	}, nil
}

func (s *identityAuthService) issueAccessToken(ctx context.Context, user *domain.User) (string, int64, error) {
	perms, err := s.rbacSvc.EffectivePermissions(ctx, user.Id)
	if err != nil {
		return "", 0, err
	}

	key, err := s.repo.FindActiveAuthKey(ctx)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			if err := EnsureActiveKey(ctx, s.repo); err != nil {
				return "", 0, err
			}

			key, err = s.repo.FindActiveAuthKey(ctx)
		}

		if err != nil {
			return "", 0, err
		}
	}

	privateKey, err := parseRSAPrivateKey(key.PrivateKeyPEM)
	if err != nil {
		return "", 0, err
	}

	now := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		Subject:   user.Id.Hex(),
		Issuer:    s.issuer,
		Audience:  jwt.ClaimStrings{s.audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTTL)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":           claims.Subject,
		"iss":           claims.Issuer,
		"aud":           claims.Audience,
		"iat":           claims.IssuedAt.Unix(),
		"exp":           claims.ExpiresAt.Unix(),
		"roles":         perms.Roles,
		"perms_global":  perms.GlobalPerms,
		"perms_project": perms.ProjectPerms,
		"scopes":        perms.Scopes,
	})

	if key.Kid != "" {
		token.Header["kid"] = key.Kid
	}

	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", 0, err
	}

	return signed, int64(s.accessTTL.Seconds()), nil
}

func (s *identityAuthService) issueRefreshSession(ctx context.Context, user *domain.User, userAgent, ip string) (string, string, error) {
	refreshToken, sessionID, err := buildRefreshToken("")
	if err != nil {
		return "", "", err
	}

	_, hash, err := splitRefreshToken(refreshToken)
	if err != nil {
		return "", "", err
	}

	now := time.Now().UTC()
	session := &domain.RefreshSession{
		SessionID:        sessionID,
		UserID:           user.Id,
		RefreshTokenHash: hash,
		UserAgent:        userAgent,
		IPAddress:        ip,
		CreatedAt:        now,
		ExpiresAt:        now.Add(s.refreshTTL),
	}

	if err := s.repo.InsertRefreshSession(ctx, session); err != nil {
		return "", "", err
	}

	return refreshToken, sessionID, nil
}

func buildRefreshToken(sessionID string) (string, string, error) {
	if sessionID == "" {
		sessionID = uuid.NewString()
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}

	token := base64.RawURLEncoding.EncodeToString(secret)
	return fmt.Sprintf("%s.%s", sessionID, token), sessionID, nil
}

func splitRefreshToken(token string) (string, string, error) {
	parts := strings.Split(token, ".")

	if len(parts) != 2 {
		return "", "", fmt.Errorf("refresh token format invalid")
	}

	hash := hashRefreshToken(parts[1])
	return parts[0], hash, nil
}

func hashRefreshToken(token string) string {
	if token == "" {
		return ""
	}

	checksum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(checksum[:])
}

func hashPassword(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)

	return fmt.Sprintf("%s:%s", base64.RawURLEncoding.EncodeToString(salt), base64.RawURLEncoding.EncodeToString(key))
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, ":")
	if len(parts) != 2 {
		return false
	}

	salt, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	stored, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return subtleCompare(key, stored)
}

func subtleCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	result := byte(0)
	for i := range a {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

func parseRSAPrivateKey(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("invalid private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parseRSAPublicKey(pemKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("invalid public key")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type")
	}

	return rsaKey, nil
}

func claimString(claims jwt.MapClaims, key string) string {
	if claims == nil {
		return ""
	}

	value, _ := claims[key].(string)
	return value
}

func claimStringSlice(claims jwt.MapClaims, key string) []string {
	if claims == nil {
		return nil
	}

	raw, ok := claims[key]
	if !ok || raw == nil {
		return nil
	}

	switch typed := raw.(type) {
	case []string:
		return typed
	case []any:
		result := make([]string, 0, len(typed))

		for _, item := range typed {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}

		return result
	default:
		return nil
	}
}

func buildJWKFromPEM(key *domain.AuthKey) (*identity_v1.JWK, error) {
	block, _ := pem.Decode([]byte(key.PublicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid public key")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type")
	}

	nBytes := rsaKey.N.Bytes()
	eBytes := make([]byte, 4)
	e := rsaKey.E

	for i := len(eBytes) - 1; i >= 0; i-- {
		eBytes[i] = byte(e & 0xff)
		e >>= 8
	}

	eBytes = bytesTrimLeftZero(eBytes)

	return &identity_v1.JWK{
		Kid: key.Kid,
		Kty: "RSA",
		Use: "sig",
		Alg: key.Alg,
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}, nil
}

func bytesTrimLeftZero(in []byte) []byte {
	for len(in) > 1 && in[0] == 0 {
		in = in[1:]
	}

	return in
}

func EnsureActiveKey(ctx context.Context, repo repository.IdentityAuthRepository) error {
	_, err := repo.FindActiveAuthKey(ctx)
	if err == nil {
		return nil
	}

	if err != mongo.ErrNoDocuments {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}

	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	key := &domain.AuthKey{
		Kid:           uuid.NewString(),
		Alg:           "RS256",
		Use:           "sig",
		PrivateKeyPEM: string(privPem),
		PublicKeyPEM:  string(pubPem),
		Status:        domain.AuthKeyStatusActive,
		CreatedAt:     time.Now().UTC(),
	}

	return repo.InsertAuthKey(ctx, key)
}
