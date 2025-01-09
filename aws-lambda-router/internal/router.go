package internal

import (
	"context"
	"fmt"

	"github.com/wundergraph/cosmo/router/core"
	"github.com/wundergraph/cosmo/router/pkg/authentication"
	"github.com/wundergraph/cosmo/router/pkg/config"
	"github.com/wundergraph/cosmo/router/pkg/cors"
	"github.com/wundergraph/cosmo/router/pkg/execution_config"
	"github.com/wundergraph/cosmo/router/pkg/metric"
	"github.com/wundergraph/cosmo/router/pkg/trace"
	"go.uber.org/zap"
)

type Option func(*RouterConfig)

type RouterConfig struct {
	ConfigPath           string
	RouterConfigPath     string
	TelemetryServiceName string
	RouterOpts           []core.Option
	GraphApiToken        string
	HttpPort             string
	EnableTelemetry      bool
	Stage                string
	TraceSampleRate      float64
	Logger               *zap.Logger
}

func NewRouter(opts ...Option) (*core.Router, error) {
	ctx := context.Background()
	rc := &RouterConfig{}

	for _, opt := range opts {
		opt(rc)
	}

	if rc.Logger == nil {
		rc.Logger = zap.NewNop()
	}

	logger := rc.Logger

	routerConfig, err := execution_config.FromFile(rc.RouterConfigPath)
	if err != nil {
		logger.Fatal("Could not read execution config", zap.Error(err), zap.String("path", rc.RouterConfigPath))
	}

	routerOpts := []core.Option{
		core.WithLogger(logger),
		core.WithPlayground(true),
		core.WithIntrospection(true),
		core.WithQueryPlans(true),
		core.WithStaticExecutionConfig(routerConfig),
		core.WithAwsLambdaRuntime(),
		core.WithGraphApiToken(rc.GraphApiToken),
	}

	configYaml, err := config.LoadConfig(rc.ConfigPath, "")
	if err != nil {
		logger.Fatal("Could not load config from YAML", zap.Error(err), zap.String("path", rc.ConfigPath))
	}

	if configYaml != nil {
		logger.Info("Using configuration from config.yaml")
		cfg := &configYaml.Config

		routerOpts = append(routerOpts,
			core.WithListenerAddr(cfg.ListenAddr),
			core.WithOverrideRoutingURL(cfg.OverrideRoutingURL),
			core.WithOverrides(cfg.Overrides),
			core.WithLogger(logger),
			core.WithIntrospection(cfg.IntrospectionEnabled),
			core.WithQueryPlans(cfg.QueryPlansEnabled),
			core.WithPlayground(cfg.PlaygroundEnabled),
			core.WithGraphApiToken(cfg.Graph.Token),
			core.WithPersistedOperationsConfig(cfg.PersistedOperationsConfig),
			core.WithAutomatedPersistedQueriesConfig(cfg.AutomaticPersistedQueries),
			core.WithApolloCompatibilityFlagsConfig(cfg.ApolloCompatibilityFlags),
			core.WithStorageProviders(cfg.StorageProviders),
			core.WithGraphQLPath(cfg.GraphQLPath),
			core.WithModulesConfig(cfg.Modules),
			core.WithGracePeriod(cfg.GracePeriod),
			core.WithPlaygroundPath(cfg.PlaygroundPath),
			core.WithHealthCheckPath(cfg.HealthCheckPath),
			core.WithLivenessCheckPath(cfg.LivenessCheckPath),
			core.WithGraphQLMetrics(&core.GraphQLMetricsConfig{
				Enabled:           cfg.GraphqlMetrics.Enabled,
				CollectorEndpoint: cfg.GraphqlMetrics.CollectorEndpoint,
			}),
			core.WithAnonymization(&core.IPAnonymizationConfig{
				Enabled: cfg.Compliance.AnonymizeIP.Enabled,
				Method:  core.IPAnonymizationMethod(cfg.Compliance.AnonymizeIP.Method),
			}),
			core.WithClusterName(cfg.Cluster.Name),
			core.WithInstanceID(cfg.InstanceID),
			core.WithReadinessCheckPath(cfg.ReadinessCheckPath),
			core.WithHeaderRules(cfg.Headers),
			core.WithRouterTrafficConfig(&cfg.TrafficShaping.Router),
			core.WithFileUploadConfig(&cfg.FileUpload),
			core.WithSubgraphTransportOptions(core.NewSubgraphTransportOptions(cfg.TrafficShaping)),
			core.WithSubgraphRetryOptions(
				cfg.TrafficShaping.All.BackoffJitterRetry.Enabled,
				cfg.TrafficShaping.All.BackoffJitterRetry.MaxAttempts,
				cfg.TrafficShaping.All.BackoffJitterRetry.MaxDuration,
				cfg.TrafficShaping.All.BackoffJitterRetry.Interval,
			),
			core.WithCors(&cors.Config{
				Enabled:          cfg.CORS.Enabled,
				AllowOrigins:     cfg.CORS.AllowOrigins,
				AllowMethods:     cfg.CORS.AllowMethods,
				AllowCredentials: cfg.CORS.AllowCredentials,
				AllowHeaders:     cfg.CORS.AllowHeaders,
				MaxAge:           cfg.CORS.MaxAge,
			}),
			core.WithTLSConfig(&core.TlsConfig{
				Enabled:  cfg.TLS.Server.Enabled,
				CertFile: cfg.TLS.Server.CertFile,
				KeyFile:  cfg.TLS.Server.KeyFile,
				ClientAuth: &core.TlsClientAuthConfig{
					CertFile: cfg.TLS.Server.ClientAuth.CertFile,
					Required: cfg.TLS.Server.ClientAuth.Required,
				},
			}),
			core.WithDevelopmentMode(cfg.DevelopmentMode),
			core.WithTracing(core.TraceConfigFromTelemetry(&cfg.Telemetry)),
			core.WithMetrics(core.MetricConfigFromTelemetry(&cfg.Telemetry)),
			core.WithTelemetryAttributes(cfg.Telemetry.Attributes),
			core.WithEngineExecutionConfig(cfg.EngineExecutionConfiguration),
			core.WithCacheControlPolicy(cfg.CacheControl),
			core.WithSecurityConfig(cfg.SecurityConfiguration),
			core.WithAuthorizationConfig(&cfg.Authorization),
			core.WithWebSocketConfiguration(&cfg.WebSocket),
			core.WithSubgraphErrorPropagation(cfg.SubgraphErrorPropagation),
			core.WithLocalhostFallbackInsideDocker(cfg.LocalhostFallbackInsideDocker),
			core.WithCDN(cfg.CDN),
			core.WithEvents(cfg.Events),
			core.WithRateLimitConfig(&cfg.RateLimit),
			core.WithClientHeader(cfg.ClientHeader),
			core.WithCacheWarmupConfig(&cfg.CacheWarmup),
		)

		var authenticators []authentication.Authenticator
		for i, auth := range cfg.Authentication.Providers {
			if auth.JWKS != nil {
				name := auth.Name
				if name == "" {
					name = fmt.Sprintf("jwks-#%d", i)
				}
				providerLogger := logger.With(zap.String("provider_name", name))
				tokenDecoder, err := authentication.NewJwksTokenDecoder(ctx, providerLogger, auth.JWKS.URL, auth.JWKS.RefreshInterval)
				if err != nil {
					providerLogger.Error("Could not create JWKS token decoder", zap.Error(err))
					return nil, err
				}
				opts := authentication.HttpHeaderAuthenticatorOptions{
					Name:                name,
					URL:                 auth.JWKS.URL,
					HeaderNames:         auth.JWKS.HeaderNames,
					HeaderValuePrefixes: auth.JWKS.HeaderValuePrefixes,
					TokenDecoder:        tokenDecoder,
				}
				authenticator, err := authentication.NewHttpHeaderAuthenticator(opts)
				if err != nil {
					providerLogger.Error("Could not create HttpHeader authenticator", zap.Error(err))
					return nil, err
				}
				authenticators = append(authenticators, authenticator)

				if cfg.WebSocket.Authentication.FromInitialPayload.Enabled {
					opts := authentication.WebsocketInitialPayloadAuthenticatorOptions{
						TokenDecoder:        tokenDecoder,
						Key:                 cfg.WebSocket.Authentication.FromInitialPayload.Key,
						HeaderValuePrefixes: auth.JWKS.HeaderValuePrefixes,
					}
					authenticator, err = authentication.NewWebsocketInitialPayloadAuthenticator(opts)
					if err != nil {
						providerLogger.Error("Could not create WebsocketInitialPayload authenticator", zap.Error(err))
						return nil, err
					}
					authenticators = append(authenticators, authenticator)
				}
			}
		}

		if len(authenticators) > 0 {
			routerOpts = append(routerOpts, core.WithAccessController(core.NewAccessController(authenticators, cfg.Authorization.RequireAuthentication)))
		}
	} else {
		logger.Info("No configuration file found, skipping YAML-based configuration", zap.String("path", rc.ConfigPath))
	}

	if rc.HttpPort != "" {
		routerOpts = append(routerOpts, core.WithListenerAddr(":"+rc.HttpPort))
	}

	if rc.EnableTelemetry {
		routerOpts = append(routerOpts,
			core.WithGraphQLMetrics(&core.GraphQLMetricsConfig{
				Enabled:           true,
				CollectorEndpoint: "https://cosmo-metrics.wundergraph.com",
			}),
			core.WithMetrics(&metric.Config{
				Name:    rc.TelemetryServiceName,
				Version: Version,
				OpenTelemetry: metric.OpenTelemetry{
					Enabled: true,
				},
			}),
			core.WithTracing(&trace.Config{
				Enabled: true,
				Name:    rc.TelemetryServiceName,
				Version: Version,
				Sampler: rc.TraceSampleRate,
				Propagators: []trace.Propagator{
					trace.PropagatorTraceContext,
				},
			}),
		)
	}

	if rc.Stage != "" {
		routerOpts = append(routerOpts,
			core.WithGraphQLWebURL(fmt.Sprintf("/%s%s", rc.Stage, "/graphql")),
		)
	}

	r, err := core.NewRouter(append(rc.RouterOpts, routerOpts...)...)
	if err != nil {
		logger.Fatal("Could not create router", zap.Error(err))
	}

	return r, nil
}

func WithConfigFilePath(path string) Option {
	return func(r *RouterConfig) {
		r.ConfigPath = path
	}
}

func WithRouterConfigPath(path string) Option {
	return func(r *RouterConfig) {
		r.RouterConfigPath = path
	}
}

func WithTelemetryServiceName(name string) Option {
	return func(r *RouterConfig) {
		r.TelemetryServiceName = name
	}
}

func WithRouterOpts(opts ...core.Option) Option {
	return func(r *RouterConfig) {
		r.RouterOpts = append(r.RouterOpts, opts...)
	}
}

func WithGraphApiToken(token string) Option {
	return func(r *RouterConfig) {
		r.GraphApiToken = token
	}
}

func WithHttpPort(port string) Option {
	return func(r *RouterConfig) {
		r.HttpPort = port
	}
}

func WithEnableTelemetry(enable bool) Option {
	return func(r *RouterConfig) {
		r.EnableTelemetry = enable
	}
}

func WithStage(stage string) Option {
	return func(r *RouterConfig) {
		r.Stage = stage
	}
}

func WithTraceSampleRate(rate float64) Option {
	return func(r *RouterConfig) {
		r.TraceSampleRate = rate
	}
}

func WithLogger(logger *zap.Logger) Option {
	return func(r *RouterConfig) {
		r.Logger = logger
	}
}
