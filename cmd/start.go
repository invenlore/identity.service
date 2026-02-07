package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/invenlore/core/pkg/config"
	"github.com/invenlore/core/pkg/db"
	"github.com/invenlore/core/pkg/metrics"
	"github.com/invenlore/core/pkg/migrator"
	"github.com/invenlore/identity.service/internal/migrations"
	"github.com/invenlore/identity.service/internal/repository"
	"github.com/invenlore/identity.service/internal/service"
	"github.com/invenlore/identity.service/internal/transport"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

func Start() {
	loggerEntry := logrus.WithField("scope", "service")
	loggerEntry.Info("service starting...")

	cfg, err := config.Config()
	if err != nil {
		loggerEntry.Fatalf("failed to load configuration: %v", err)
	}

	appCfg := cfg.GetConfig()
	mongoCfg := appCfg.GetMongoConfig()
	authCfg := appCfg.GetAuthConfig()

	baseCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	g, ctx := errgroup.WithContext(baseCtx)

	serviceName := appCfg.ServiceName
	if serviceName == "" {
		serviceName = "identity"
	}

	serviceVersion := appCfg.ServiceVersion
	if serviceVersion == "" {
		serviceVersion = "unknown"
	}

	loggerEntry.WithFields(logrus.Fields{
		"service": serviceName,
		"version": serviceVersion,
		"env":     appCfg.AppEnv,
	}).Info("service configuration loaded")

	metricsRegistry := metrics.NewRegistry(serviceName, appCfg.AppEnv, serviceVersion)
	mongoMetrics := metrics.NewMongoMetrics(metricsRegistry)
	readinessMetrics := metrics.NewReadinessGauge(metricsRegistry)
	grpcMetrics := metrics.NewGRPCServerMetrics(metricsRegistry)

	mongoClient, err := db.MongoDBConnect(ctx, mongoCfg, options.Client().SetMonitor(mongoMetrics.Monitor()))
	if err != nil {
		loggerEntry.Fatalf("MongoDB connect failed: %v", err)
	}

	loggerEntry.Info("MongoDB connected successfully")

	mongoReadiness := db.NewMongoReadiness(mongoClient, mongoCfg.HealthCheckTimeout)
	mongoReadiness.CloseGate("MongoDB migrations in progress")
	readinessMetrics.Set("mongo", mongoReadiness.Ready())

	g.Go(func() error {
		ticker := time.NewTicker(mongoCfg.HealthCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				_ = mongoReadiness.CheckNow(ctx)
				readinessMetrics.Set("mongo", mongoReadiness.Ready())
			}
		}
	})

	host, _ := os.Hostname()
	owner := migrator.DefaultOwnerID(host)

	mgr := migrator.NewManager(mongoClient.Database(mongoCfg.DatabaseName), owner, migrator.ManagerConfig{
		LockKey:          "identityservice:migrations",
		MigrationTimeout: mongoCfg.MigrationTimeout,
		LeaseFor:         mongoCfg.MigrationLeaseForTimeout,
		PollInterval:     mongoCfg.MigrationPollInterval,
		OpTimeout:        mongoCfg.MigrationServiceTimeout,
		Logger:           loggerEntry,
		FailFast:         true,
		WaitForLeader:    true,
	})

	g.Go(func() error {
		if err := mgr.Run(ctx, migrations.List()); err != nil {
			loggerEntry.Errorf("MongoDB migrations failed, keeping service in degraded mode: %v", err)
			mongoReadiness.CloseGate("MongoDB migrations failed: " + err.Error())
			readinessMetrics.Set("mongo", mongoReadiness.Ready())

			return nil
		}

		mongoReadiness.OpenGate()
		readinessMetrics.Set("mongo", mongoReadiness.Ready())

		if err := mongoReadiness.CheckNow(ctx); err != nil {
			loggerEntry.Warnf("MongoDB readiness check after migrations failed: %v", err)
		}

		readinessMetrics.Set("mongo", mongoReadiness.Ready())

		return nil
	})

	g.Go(func() error {
		<-ctx.Done()

		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		return mongoClient.Disconnect(stopCtx)
	})

	adminRepo := repository.NewIdentityAdminRepository(mongoClient, mongoCfg)
	authRepo := repository.NewIdentityAuthRepository(mongoClient, mongoCfg)
	oauthRepo := repository.NewIdentityOAuthRepository(mongoClient, mongoCfg)
	rbacRepo := repository.NewIdentityRBACRepository(mongoClient, mongoCfg)
	adminSvc := service.NewIdentityAdminService(adminRepo, rbacRepo)
	authSvc := service.NewIdentityAuthService(authRepo, rbacRepo, authCfg)
	oauthSvc := service.NewIdentityOAuthService(authRepo, oauthRepo, rbacRepo, authSvc, appCfg.GetOAuthConfig(), appCfg.AppEnv)
	rbacSvc := service.NewRBACService(rbacRepo)

	authKeyRotator := service.NewAuthKeyRotator(
		mongoClient.Database(mongoCfg.DatabaseName),
		authRepo,
		owner,
		service.AuthKeyRotatorConfig{
			RotationInterval: authCfg.KeyRotationInterval,
			RetireAfter:      authCfg.KeyRetireAfter,
		},
		logrus.WithField("scope", "auth-key-rotation"),
	)

	grpcSrv, grpcLn, err := transport.StartGRPCServer(appCfg.GetGRPCConfig(), adminSvc, authSvc, oauthSvc, rbacSvc, mongoReadiness, grpcMetrics)
	if err != nil {
		loggerEntry.Fatalf("gRPC server init failed: %v", err)
	}

	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", metricsRegistry.Handler())

	metricsSrv, metricsLn, err := metrics.StartMetricsServer(appCfg.GetMetricsConfig(), metricsMux)
	if err != nil {
		_ = grpcLn.Close()
		loggerEntry.Fatalf("metrics server init failed: %v", err)
	}

	healthSrv, healthLn, err := transport.StartHealthServer(appCfg.GetHealthConfig())
	if err != nil {
		_ = grpcLn.Close()

		loggerEntry.Fatalf("health server init failed: %v", err)
	}

	g.Go(func() error {
		loggerEntry.Infof("gRPC server serving on %s...", grpcLn.Addr().String())

		if err := grpcSrv.Serve(grpcLn); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("gRPC serve failed: %w", err)
		}

		return nil
	})

	g.Go(func() error {
		loggerEntry.Infof("health server serving on %s...", healthSrv.Addr)

		if err := healthSrv.Serve(healthLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("health serve failed: %w", err)
		}

		return nil
	})

	g.Go(func() error {
		loggerEntry.Infof("metrics server serving on %s...", metricsSrv.Addr)

		if err := metricsSrv.Serve(metricsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("metrics serve failed: %w", err)
		}

		return nil
	})

	g.Go(func() error {
		ticker := time.NewTicker(authCfg.KeyRotationTickInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				authKeyRotator.Tick(ctx)
			}
		}
	})

	g.Go(func() error {
		<-ctx.Done()

		loggerEntry.Trace("attempting graceful shutdown...")

		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		grpcSrv.GracefulStop()
		_ = healthSrv.Shutdown(stopCtx)
		_ = metricsSrv.Shutdown(stopCtx)

		loggerEntry.Info("clean service shutdown complete")
		return nil
	})

	if err := g.Wait(); err != nil {
		loggerEntry.Errorf("service stopped with error: %v", err)

		os.Exit(1)
	}

	loggerEntry.Info("service stopped gracefully")
}
