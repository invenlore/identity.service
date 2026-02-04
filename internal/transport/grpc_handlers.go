package transport

import (
	"context"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/invenlore/core/pkg/errmodel"
	"github.com/invenlore/identity.service/internal/service"
	common_v1 "github.com/invenlore/proto/pkg/common/v1"
	identity_v1 "github.com/invenlore/proto/pkg/identity/v1"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

var v = validator.New(validator.WithRequiredStructEnabled())

type addUserInput struct {
	Name  string `validate:"required,min=1,max=100"`
	Email string `validate:"required,email,max=254"`
}

// PUBLIC SCOPE
func (s *GRPCIdentityServer) Register(ctx context.Context, req *identity_v1.RegisterRequest) (*identity_v1.RegisterResponse, error) {
	resp, code, err := s.authSvc.Register(ctx, req)
	if err != nil {
		return nil, errmodel.Error(ctx, code, err.Error())
	}

	return resp, nil
}

// PUBLIC SCOPE
func (s *GRPCIdentityServer) Login(ctx context.Context, req *identity_v1.LoginRequest) (*identity_v1.LoginResponse, error) {
	resp, code, err := s.authSvc.Login(ctx, req, userAgentFromContext(ctx), ipFromContext(ctx))
	if err != nil {
		return nil, errmodel.Error(ctx, code, err.Error())
	}

	return resp, nil
}

// PUBLIC SCOPE
func (s *GRPCIdentityServer) Refresh(ctx context.Context, req *identity_v1.RefreshRequest) (*identity_v1.RefreshResponse, error) {
	resp, code, err := s.authSvc.Refresh(ctx, req, userAgentFromContext(ctx), ipFromContext(ctx))
	if err != nil {
		return nil, errmodel.Error(ctx, code, err.Error())
	}

	return resp, nil
}

// PUBLIC SCOPE
func (s *GRPCIdentityServer) Logout(ctx context.Context, req *identity_v1.LogoutRequest) (*identity_v1.LogoutResponse, error) {
	code, err := s.authSvc.Logout(ctx, req)
	if err != nil {
		return nil, errmodel.Error(ctx, code, err.Error())
	}

	return &identity_v1.LogoutResponse{}, nil
}

// PUBLIC SCOPE
func (s *GRPCIdentityServer) GetProfile(ctx context.Context, req *identity_v1.GetProfileRequest) (*identity_v1.GetProfileResponse, error) {
	return nil, errmodel.Error(ctx, codes.Unimplemented, "get profile is not implemented")
}

// PUBLIC SCOPE
func (s *GRPCIdentityServer) UpdateProfile(ctx context.Context, req *identity_v1.UpdateProfileRequest) (*identity_v1.UpdateProfileResponse, error) {
	return nil, errmodel.Error(ctx, codes.Unimplemented, "update profile is not implemented")
}

// INTERNAL SCOPE
func (s *GRPCIdentityServer) HealthCheck(ctx context.Context, req *common_v1.ServiceHealthRequest) (*common_v1.ServiceHealthResponse, error) {
	if !s.mongoReadiness.Ready() {
		return &common_v1.ServiceHealthResponse{Status: "down"}, errmodel.Error(ctx, codes.Unavailable, s.mongoReadiness.LastError())
	}

	return &common_v1.ServiceHealthResponse{Status: "up"}, nil
}

// INTERNAL SCOPE
func (s *GRPCIdentityServer) GetJWKS(ctx context.Context, req *identity_v1.GetJWKSRequest) (*identity_v1.GetJWKSResponse, error) {
	if err := s.authSvc.EnsureActiveKey(ctx); err != nil {
		return nil, errmodel.Error(ctx, codes.Internal, err.Error())
	}

	keys, code, err := s.authSvc.GetJWKS(ctx)
	if err != nil {
		return nil, errmodel.Error(ctx, code, err.Error())
	}

	return &identity_v1.GetJWKSResponse{Jwks: keys}, nil
}

// INTERNAL SCOPE
func (s *GRPCIdentityServer) ValidateToken(ctx context.Context, req *identity_v1.ValidateTokenRequest) (*identity_v1.ValidateTokenResponse, error) {
	if req == nil || strings.TrimSpace(req.Token) == "" {
		return nil, errmodel.BadRequest(ctx, "token is required", errmodel.FieldViolation("token", "token is required"))
	}

	claims, err := s.authSvc.ValidateToken(ctx, strings.TrimSpace(req.Token))
	if err != nil {
		return nil, errmodel.Error(ctx, codes.Unauthenticated, err.Error())
	}

	return &identity_v1.ValidateTokenResponse{
		Id:           claims.Subject,
		Roles:        claims.Roles,
		PermsGlobal:  claims.PermsGlobal,
		PermsProject: claims.PermsProject,
		Scopes:       claims.Scopes,
	}, nil
}

// INTERNAL SCOPE
func (s *GRPCIdentityServer) Authorize(ctx context.Context, req *identity_v1.AuthorizeRequest) (*identity_v1.AuthorizeResponse, error) {
	if req == nil || strings.TrimSpace(req.Id) == "" || strings.TrimSpace(req.Action) == "" {
		return nil, errmodel.BadRequest(ctx, "id and action are required", errmodel.FieldViolation("id", "id and action are required"))
	}

	userID, err := primitive.ObjectIDFromHex(strings.TrimSpace(req.Id))
	if err != nil {
		return nil, errmodel.BadRequest(ctx, "invalid user id", errmodel.FieldViolation("id", err.Error()))
	}

	if err := service.ValidateResource(req.Resource); err != nil {
		return nil, errmodel.BadRequest(ctx, "invalid resource", errmodel.FieldViolation("resource", err.Error()))
	}

	allowed, err := s.rbacSvc.Authorize(ctx, userID, strings.TrimSpace(req.Action), strings.TrimSpace(req.Resource))
	if err != nil {
		return nil, errmodel.Error(ctx, codes.Internal, err.Error())
	}

	return &identity_v1.AuthorizeResponse{Allowed: allowed}, nil
}

// INTERNAL SCOPE
func (s *GRPCIdentityServer) GetUserBrief(ctx context.Context, req *identity_v1.GetUserBriefRequest) (*identity_v1.GetUserBriefResponse, error) {
	return nil, errmodel.Error(ctx, codes.Unimplemented, "get user brief is not implemented")
}

// ADMIN SCOPE
func (s *GRPCIdentityServer) AddUser(ctx context.Context, req *identity_v1.AddUserRequest) (*identity_v1.AddUserResponse, error) {
	if req == nil || req.User == nil {
		return nil, errmodel.BadRequest(ctx, "user is required", errmodel.FieldViolation("user", "user is required"))
	}

	in := addUserInput{
		Name:  strings.TrimSpace(req.User.Name),
		Email: strings.TrimSpace(req.User.Email),
	}

	if err := v.Struct(in); err != nil {
		return nil, errmodel.BadRequest(ctx, "invalid user", errmodel.FieldViolation("user", err.Error()))
	}

	req.User.Name = in.Name
	req.User.Email = in.Email

	lastInsertId, code, err := s.adminSvc.AddUser(ctx, req.User)
	if err != nil {
		return nil, errmodel.Error(ctx, code, err.Error())
	}

	return &identity_v1.AddUserResponse{Id: lastInsertId}, nil
}

// ADMIN SCOPE
func (s *GRPCIdentityServer) GetUser(ctx context.Context, req *identity_v1.GetUserRequest) (*identity_v1.GetUserResponse, error) {
	if req == nil || strings.TrimSpace(req.Id) == "" {
		return nil, errmodel.BadRequest(ctx, "id is required", errmodel.FieldViolation("id", "id is required"))
	}

	ptrUser, code, err := s.adminSvc.GetUser(ctx, strings.TrimSpace(req.Id))
	if err != nil {
		return nil, errmodel.Error(ctx, code, err.Error())
	}

	return &identity_v1.GetUserResponse{User: ptrUser}, nil
}

// ADMIN SCOPE
func (s *GRPCIdentityServer) DeleteUser(ctx context.Context, req *identity_v1.DeleteUserRequest) (*identity_v1.DeleteUserResponse, error) {
	if req == nil || strings.TrimSpace(req.Id) == "" {
		return nil, errmodel.BadRequest(ctx, "id is required", errmodel.FieldViolation("id", "id is required"))
	}

	code, err := s.adminSvc.DeleteUser(ctx, strings.TrimSpace(req.Id))
	if err != nil {
		return nil, errmodel.Error(ctx, code, err.Error())
	}

	return &identity_v1.DeleteUserResponse{}, nil
}

// ADMIN SCOPE
func (s *GRPCIdentityServer) ListUsers(ctx context.Context, req *identity_v1.ListUsersRequest) (*identity_v1.ListUsersResponse, error) {
	users, nextToken, code, err := s.adminSvc.ListUsers(ctx)
	if err != nil {
		return nil, errmodel.Error(ctx, code, err.Error())
	}

	return &identity_v1.ListUsersResponse{Users: users, NextPageToken: nextToken}, nil
}

// TODO: -> core/pkg/logger
func userAgentFromContext(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get("user-agent"); len(values) > 0 {
			return values[0]
		}
	}

	return ""
}

// TODO: -> core/pkg/logger
func ipFromContext(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get("x-forwarded-for"); len(values) > 0 {
			return values[0]
		}

		if values := md.Get("x-real-ip"); len(values) > 0 {
			return values[0]
		}
	}

	return ""
}
