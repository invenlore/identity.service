package transport

import (
	"fmt"
	"net"

	"github.com/invenlore/core/pkg/config"
	"github.com/invenlore/core/pkg/db"
	"github.com/invenlore/core/pkg/logger"
	"github.com/invenlore/core/pkg/recovery"
	"github.com/invenlore/identity.service/internal/service"
	identity_v1 "github.com/invenlore/proto/pkg/identity/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type GRPCIdentityServer struct {
	adminSvc       service.IdentityAdminService
	authSvc        service.IdentityAuthService
	oauthSvc       service.IdentityOAuthService
	rbacSvc        service.RBACService
	mongoReadiness *db.MongoReadiness
	identity_v1.UnimplementedIdentityPublicServiceServer
	identity_v1.UnimplementedIdentityInternalServiceServer
}

func NewGRPCIdentityServer(adminSvc service.IdentityAdminService, authSvc service.IdentityAuthService, oauthSvc service.IdentityOAuthService, rbacSvc service.RBACService, mongoReadiness *db.MongoReadiness) *GRPCIdentityServer {
	return &GRPCIdentityServer{
		adminSvc:       adminSvc,
		authSvc:        authSvc,
		oauthSvc:       oauthSvc,
		rbacSvc:        rbacSvc,
		mongoReadiness: mongoReadiness,
	}
}

func StartGRPCServer(cfg *config.GRPCServerConfig, adminSvc service.IdentityAdminService, authSvc service.IdentityAuthService, oauthSvc service.IdentityOAuthService, rbacSvc service.RBACService, mongoReadiness *db.MongoReadiness) (*grpc.Server, net.Listener, error) {
	var (
		loggerEntry = logrus.WithField("scope", "grpcServer")
		listenAddr  = net.JoinHostPort(cfg.Host, cfg.Port)
	)

	loggerEntry.Info("starting gRPC server...")

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("gRPC server failed to listen on %s: %w", listenAddr, err)
	}

	unaryInterceptors := []grpc.UnaryServerInterceptor{
		recovery.RecoveryUnaryInterceptor,
		logger.ServerRequestIDInterceptor,
		logger.ServerLoggingInterceptor,
		db.MongoGateUnary(mongoReadiness, identity_v1.IdentityInternalService_HealthCheck_FullMethodName),
	}

	streamInterceptors := []grpc.StreamServerInterceptor{
		recovery.RecoveryStreamInterceptor,
		logger.ServerStreamRequestIDInterceptor,
		logger.ServerStreamLoggingInterceptor,
		db.MongoGateStream(mongoReadiness, identity_v1.IdentityInternalService_HealthCheck_FullMethodName),
	}

	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	)

	grpcServer := NewGRPCIdentityServer(adminSvc, authSvc, oauthSvc, rbacSvc, mongoReadiness)
	identity_v1.RegisterIdentityPublicServiceServer(server, grpcServer)
	identity_v1.RegisterIdentityInternalServiceServer(server, grpcServer)

	return server, ln, nil
}
