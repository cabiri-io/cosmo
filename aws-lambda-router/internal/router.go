package internal

import (
	"context"
	"fmt"
	"os"

	"github.com/wundergraph/cosmo/router/core"
	"github.com/wundergraph/cosmo/router/pkg/authentication"
	"github.com/wundergraph/cosmo/router/pkg/config"
	"github.com/wundergraph/cosmo/router/pkg/cors"
	"github.com/wundergraph/cosmo/router/pkg/execution_config"
	"github.com/wundergraph/cosmo/router/pkg/logging"
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
		logger.Error("Could not read execution config", zap.Error(err), zap.String("path", rc.RouterConfigPath))
		return nil, err
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
		logger.Error("Could not load config from YAML", zap.Error(err), zap.String("path", rc.ConfigPath))
		return nil, err
	}

	if configYaml != nil {
		logger.Info("Using configuration from config.yaml")
		cfg := &configYaml.Config

		// Supports same configuration options as router/cmd/instance.go:NewRouter

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
			core.WithPlaygroundConfig(cfg.PlaygroundConfig),
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

		if cfg.AccessLogs.Enabled {
			c := &core.AccessLogsConfig{
				Attributes:         cfg.AccessLogs.Router.Fields,
				SubgraphEnabled:    cfg.AccessLogs.Subgraphs.Enabled,
				SubgraphAttributes: cfg.AccessLogs.Subgraphs.Fields,
			}

			if cfg.AccessLogs.Output.File.Enabled {
				f, err := logging.NewLogFile(cfg.AccessLogs.Output.File.Path)
				if err != nil {
					return nil, fmt.Errorf("could not create log file: %w", err)
				}
				if cfg.AccessLogs.Buffer.Enabled {
					bl, err := logging.NewJSONZapBufferedLogger(logging.BufferedLoggerOptions{
						WS:            f,
						BufferSize:    int(cfg.AccessLogs.Buffer.Size.Uint64()),
						FlushInterval: cfg.AccessLogs.Buffer.FlushInterval,
						Development:   cfg.DevelopmentMode,
						Level:         zap.InfoLevel,
						Pretty:        !cfg.JSONLog,
					})
					if err != nil {
						return nil, fmt.Errorf("could not create buffered logger: %w", err)
					}
					c.Logger = bl.Logger
				} else {
					c.Logger = logging.NewZapAccessLogger(f, cfg.DevelopmentMode, !cfg.JSONLog)
				}
			} else if cfg.AccessLogs.Output.Stdout.Enabled {

				if cfg.AccessLogs.Buffer.Enabled {
					bl, err := logging.NewJSONZapBufferedLogger(logging.BufferedLoggerOptions{
						WS:            os.Stdout,
						BufferSize:    int(cfg.AccessLogs.Buffer.Size.Uint64()),
						FlushInterval: cfg.AccessLogs.Buffer.FlushInterval,
						Development:   cfg.DevelopmentMode,
						Level:         zap.InfoLevel,
						Pretty:        !cfg.JSONLog,
					})
					if err != nil {
						return nil, fmt.Errorf("could not create buffered logger: %w", err)
					}
					c.Logger = bl.Logger
				} else {
					c.Logger = logging.NewZapAccessLogger(os.Stdout, cfg.DevelopmentMode, !cfg.JSONLog)
				}
			}

			routerOpts = append(routerOpts, core.WithAccessLogs(c))
		}

		authenticators, err := setupAuthenticators(ctx, logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("could not setup authenticators: %w", err)
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
		logger.Error("Could not create router", zap.Error(err))
		return nil, err
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

func setupAuthenticators(ctx context.Context, logger *zap.Logger, cfg *config.Config) ([]authentication.Authenticator, error) {
	jwtConf := cfg.Authentication.JWT
	if len(jwtConf.JWKS) == 0 {
		// No JWT authenticators configured
		return nil, nil
	}

	var authenticators []authentication.Authenticator
	configs := make([]authentication.JWKSConfig, 0, len(jwtConf.JWKS))

	for _, jwks := range cfg.Authentication.JWT.JWKS {
		configs = append(configs, authentication.JWKSConfig{
			URL:               jwks.URL,
			RefreshInterval:   jwks.RefreshInterval,
			AllowedAlgorithms: jwks.Algorithms,
		})
	}

	tokenDecoder, err := authentication.NewJwksTokenDecoder(ctx, logger, configs)
	if err != nil {
		return nil, err
	}

	// create a map for the `httpHeaderAuthenticator`
	headerSourceMap := map[string][]string{
		jwtConf.HeaderName: {jwtConf.HeaderValuePrefix},
	}

	// The `websocketInitialPayloadAuthenticator` has one key and uses a flat list of prefixes
	prefixSet := make(map[string]struct{})

	for _, s := range jwtConf.HeaderSources {
		if s.Type != "header" {
			continue
		}

		for _, prefix := range s.ValuePrefixes {
			headerSourceMap[s.Name] = append(headerSourceMap[s.Name], prefix)
			prefixSet[prefix] = struct{}{}
		}

	}

	opts := authentication.HttpHeaderAuthenticatorOptions{
		Name:                 "jwks",
		HeaderSourcePrefixes: headerSourceMap,
		TokenDecoder:         tokenDecoder,
	}

	authenticator, err := authentication.NewHttpHeaderAuthenticator(opts)
	if err != nil {
		logger.Error("Could not create HttpHeader authenticator", zap.Error(err))
		return nil, err
	}

	authenticators = append(authenticators, authenticator)

	if cfg.WebSocket.Authentication.FromInitialPayload.Enabled {
		headerPrefixes := make([]string, 0, len(prefixSet))
		for prefix := range prefixSet {
			headerPrefixes = append(headerPrefixes, prefix)
		}

		opts := authentication.WebsocketInitialPayloadAuthenticatorOptions{
			TokenDecoder:        tokenDecoder,
			Key:                 cfg.WebSocket.Authentication.FromInitialPayload.Key,
			HeaderValuePrefixes: headerPrefixes,
		}
		authenticator, err = authentication.NewWebsocketInitialPayloadAuthenticator(opts)
		if err != nil {
			logger.Error("Could not create WebsocketInitialPayload authenticator", zap.Error(err))
			return nil, err
		}
		authenticators = append(authenticators, authenticator)
	}

	return authenticators, nil
}
