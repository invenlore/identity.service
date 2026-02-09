package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/invenlore/core/pkg/config"
	"github.com/invenlore/identity.service/internal/domain"
	"github.com/invenlore/identity.service/internal/repository"
	identity_v1 "github.com/invenlore/proto/pkg/identity/v1"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"google.golang.org/grpc/codes"
)

type IdentityOAuthService interface {
	StartOAuth(ctx context.Context, provider identity_v1.OAuthProvider, redirectURI string) (*identity_v1.StartOAuthResponse, codes.Code, error)
	CompleteOAuth(ctx context.Context, provider identity_v1.OAuthProvider, code, state, userAgent, ip string) (*identity_v1.CompleteOAuthResponse, codes.Code, error)
}

type identityOAuthService struct {
	authRepo  repository.IdentityAuthRepository
	oauthRepo repository.IdentityOAuthRepository
	rbacRepo  repository.IdentityRBACRepository
	rbacSvc   RBACService
	authSvc   IdentityAuthService
	oauthCfg  *config.OAuthConfig
	appEnv    config.AppEnv
}

func NewIdentityOAuthService(
	authRepo repository.IdentityAuthRepository,
	oauthRepo repository.IdentityOAuthRepository,
	rbacRepo repository.IdentityRBACRepository,
	authSvc IdentityAuthService,
	oauthCfg *config.OAuthConfig,
	appEnv config.AppEnv,
) IdentityOAuthService {
	return &identityOAuthService{
		authRepo:  authRepo,
		oauthRepo: oauthRepo,
		rbacRepo:  rbacRepo,
		rbacSvc:   NewRBACService(rbacRepo),
		authSvc:   authSvc,
		oauthCfg:  oauthCfg,
		appEnv:    appEnv,
	}
}

func (s *identityOAuthService) StartOAuth(ctx context.Context, provider identity_v1.OAuthProvider, redirectURI string) (*identity_v1.StartOAuthResponse, codes.Code, error) {
	providerName, oauthConfig, codeVerifier, state, err := s.buildOAuthStart(provider)
	if err != nil {
		return nil, codes.InvalidArgument, err
	}

	allowedRedirect, err := s.normalizeRedirectURI(redirectURI)
	if err != nil {
		return nil, codes.InvalidArgument, err
	}

	now := time.Now().UTC()
	stateRecord := &domain.OAuthState{
		State:        state,
		Provider:     providerName,
		RedirectURI:  allowedRedirect,
		CodeVerifier: codeVerifier,
		ExpiresAt:    now.Add(s.oauthCfg.StateTTL),
	}

	if err := s.oauthRepo.SaveState(ctx, stateRecord); err != nil {
		return nil, codes.Internal, err
	}

	challenge := pkceChallenge(codeVerifier)
	authURL := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("code_challenge", challenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))

	return &identity_v1.StartOAuthResponse{
		AuthorizationUrl: authURL,
		State:            state,
	}, codes.OK, nil
}

func (s *identityOAuthService) CompleteOAuth(ctx context.Context, provider identity_v1.OAuthProvider, code, state, userAgent, ip string) (*identity_v1.CompleteOAuthResponse, codes.Code, error) {
	providerName, oauthConfig, _, _, err := s.buildOAuthStart(provider)
	if err != nil {
		return nil, codes.InvalidArgument, err
	}

	if strings.TrimSpace(code) == "" || strings.TrimSpace(state) == "" {
		return nil, codes.InvalidArgument, fmt.Errorf("code and state are required")
	}

	stored, err := s.oauthRepo.GetState(ctx, strings.TrimSpace(state))
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, codes.Unauthenticated, fmt.Errorf("state invalid or expired")
		}

		return nil, codes.Internal, err
	}

	if stored.ConsumedAt != nil {
		return nil, codes.Unauthenticated, fmt.Errorf("state already used")
	}

	if stored.Provider != providerName {
		return nil, codes.Unauthenticated, fmt.Errorf("state provider mismatch")
	}

	if time.Now().UTC().After(stored.ExpiresAt) {
		return nil, codes.Unauthenticated, fmt.Errorf("state expired")
	}

	token, err := oauthConfig.Exchange(ctx, strings.TrimSpace(code), oauth2.SetAuthURLParam("code_verifier", stored.CodeVerifier))
	if err != nil {
		logrus.WithError(err).WithField("scope", "oauth").Warn("oauth exchange failed")

		if strings.EqualFold(s.appEnv.String(), string(config.AppEnvDevelopment)) {
			return nil, codes.Unauthenticated, fmt.Errorf("oauth exchange failed: %w", err)
		}

		return nil, codes.Unauthenticated, fmt.Errorf("oauth exchange failed")
	}

	profile, err := s.fetchGitHubProfile(ctx, oauthConfig, token)
	if err != nil {
		return nil, codes.Internal, err
	}

	user, isNew, err := s.resolveUserFromOAuth(ctx, providerName, profile)
	if err != nil {
		return nil, codes.Internal, err
	}

	if isNew {
		if err := s.rbacRepo.AssignRole(ctx, user.Id, "user", []string{}); err != nil {
			return nil, codes.Internal, err
		}
	}

	perms, err := s.rbacSvc.EffectivePermissions(ctx, user.Id)
	if err != nil {
		return nil, codes.Internal, err
	}

	accessToken, refreshToken, expiresIn, err := s.authSvc.IssueTokensForUser(ctx, user, userAgent, ip)
	if err != nil {
		return nil, codes.Internal, err
	}

	if err := s.oauthRepo.MarkStateConsumed(ctx, stored.State); err != nil {
		return nil, codes.Internal, err
	}

	return &identity_v1.CompleteOAuthResponse{
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
		RedirectUri: stored.RedirectURI,
	}, codes.OK, nil
}

type oauthProfile struct {
	ProviderUserID string
	Email          string
	Name           string
}

func (s *identityOAuthService) buildOAuthStart(provider identity_v1.OAuthProvider) (string, *oauth2.Config, string, string, error) {
	if provider != identity_v1.OAuthProvider_OAUTH_PROVIDER_GITHUB {
		return "", nil, "", "", fmt.Errorf("unsupported oauth provider")
	}

	clientID := strings.TrimSpace(s.oauthCfg.GitHub.ClientID)
	clientSecret := strings.TrimSpace(s.oauthCfg.GitHub.ClientSecret)
	callbackURL := strings.TrimSpace(s.oauthCfg.GitHub.CallbackURL)
	if clientID == "" || clientSecret == "" || callbackURL == "" {
		return "", nil, "", "", fmt.Errorf("oauth github config is missing")
	}

	codeVerifier, err := randomBase64URL(64)
	if err != nil {
		return "", nil, "", "", err
	}

	state, err := randomBase64URL(32)
	if err != nil {
		return "", nil, "", "", err
	}

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     github.Endpoint,
		RedirectURL:  callbackURL,
		Scopes:       []string{"read:user", "user:email"},
	}

	return "github", oauthConfig, codeVerifier, state, nil
}

func (s *identityOAuthService) fetchGitHubProfile(ctx context.Context, oauthConfig *oauth2.Config, token *oauth2.Token) (*oauthProfile, error) {
	client := oauthConfig.Client(ctx, token)
	userReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	userReq.Header.Set("Accept", "application/vnd.github+json")
	userReq.Header.Set("User-Agent", "invenlore-identity")
	resp, err := client.Do(userReq)
	if err != nil {
		return nil, fmt.Errorf("github user request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github user request failed: status %d", resp.StatusCode)
	}

	var userPayload struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := decodeJSONBodyLoose(resp.Body, &userPayload); err != nil {
		return nil, fmt.Errorf("github user response invalid: %w", err)
	}

	email := strings.TrimSpace(userPayload.Email)
	if email == "" {
		email, err = s.fetchGitHubPrimaryEmail(ctx, client)
		if err != nil {
			return nil, err
		}
	}

	name := strings.TrimSpace(userPayload.Name)
	if name == "" {
		name = strings.TrimSpace(userPayload.Login)
	}

	if userPayload.ID == 0 || email == "" {
		return nil, errors.New("github profile incomplete")
	}

	return &oauthProfile{
		ProviderUserID: fmt.Sprintf("%d", userPayload.ID),
		Email:          email,
		Name:           name,
	}, nil
}

func (s *identityOAuthService) fetchGitHubPrimaryEmail(ctx context.Context, client *http.Client) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "invenlore-identity")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("github emails request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github emails request failed: status %d", resp.StatusCode)
	}

	var emailPayload []struct {
		Email      string `json:"email"`
		Primary    bool   `json:"primary"`
		Verified   bool   `json:"verified"`
		Visibility string `json:"visibility"`
	}

	if err := decodeJSONBodyLoose(resp.Body, &emailPayload); err != nil {
		return "", fmt.Errorf("github emails response invalid: %w", err)
	}

	for _, entry := range emailPayload {
		if entry.Primary && entry.Verified {
			return strings.TrimSpace(entry.Email), nil
		}
	}

	for _, entry := range emailPayload {
		if entry.Verified {
			return strings.TrimSpace(entry.Email), nil
		}
	}

	return "", errors.New("no verified email returned by github")
}

func (s *identityOAuthService) resolveUserFromOAuth(ctx context.Context, provider string, profile *oauthProfile) (*domain.User, bool, error) {
	identity, err := s.oauthRepo.FindOAuthIdentity(ctx, provider, profile.ProviderUserID)
	if err != nil && err != mongo.ErrNoDocuments {
		return nil, false, err
	}

	if identity != nil {
		user, err := s.authRepo.FindUserByID(ctx, identity.UserID)
		if err != nil {
			return nil, false, err
		}
		return user, false, nil
	}

	email := strings.ToLower(strings.TrimSpace(profile.Email))
	user, err := s.authRepo.FindUserByEmail(ctx, email)
	if err != nil && err != mongo.ErrNoDocuments {
		return nil, false, err
	}

	now := time.Now().UTC()
	if user == nil {
		newUser := &domain.User{
			Name:         profile.Name,
			Email:        email,
			PasswordHash: "",
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		userID, err := s.authRepo.InsertUserCredentials(ctx, newUser)
		if err != nil {
			return nil, false, err
		}
		newUser.Id = userID
		user = newUser
	}

	identity = &domain.OAuthIdentity{
		Provider:       provider,
		ProviderUserID: profile.ProviderUserID,
		UserID:         user.Id,
		Email:          email,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.oauthRepo.UpsertOAuthIdentity(ctx, identity); err != nil {
		return nil, false, err
	}

	return user, true, nil
}

func (s *identityOAuthService) normalizeRedirectURI(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "/swagger/", nil
	}

	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid redirect uri")
	}

	if parsed.IsAbs() {
		if !s.isAllowedRedirect(parsed.String()) {
			return "", fmt.Errorf("redirect uri not allowed")
		}
		return parsed.String(), nil
	}

	if !strings.HasPrefix(parsed.Path, "/") {
		return "", fmt.Errorf("redirect uri must be absolute path")
	}

	if strings.HasPrefix(parsed.Path, "//") {
		return "", fmt.Errorf("redirect uri invalid")
	}

	return parsed.String(), nil
}

func (s *identityOAuthService) isAllowedRedirect(uri string) bool {
	allowed := strings.TrimSpace(s.oauthCfg.AllowedRedirectURIs)
	if allowed == "" {
		return false
	}

	for _, entry := range strings.Split(allowed, ",") {
		candidate := strings.TrimSpace(entry)
		if candidate != "" && strings.EqualFold(candidate, uri) {
			return true
		}
	}

	return false
}

func randomBase64URL(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func pkceChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func decodeJSONBodyLoose(body io.Reader, out any) error {
	return json.NewDecoder(body).Decode(out)
}
