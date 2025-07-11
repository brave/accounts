package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/brave/accounts/controllers"
	"github.com/brave/accounts/datastore"
	_ "github.com/brave/accounts/docs"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/docgen"
	"github.com/prometheus/client_golang/prometheus"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	_ "github.com/joho/godotenv/autoload"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	routesFlag             = flag.Bool("routes", false, "Generate router documentation")
	listenFlag             = flag.String("listen", ":8080", "Use specific address and port for listening")
	prometheusListenFlag   = flag.String("prom-listen", ":9090", "Use specific address and port for listening for Prometheus server")
	startWebhookSenderFlag = flag.Bool("start-webhook-sender", false, "Start the webhook event sender")
	startKeyServiceFlag    = flag.Bool("start-key-service", false, "Start the server key service")

	devEndpointsEnabled = os.Getenv(devEndpointsEnabledEnv) == "true"
	environment         = os.Getenv(environmentEnv)
)

const (
	logPrettyEnv              = "LOG_PRETTY"
	logLevelEnv               = "LOG_LEVEL"
	passwordAuthEnabledEnv    = "PASSWORD_AUTH_ENABLED"
	emailAuthEnabledEnv       = "EMAIL_AUTH_ENABLED"
	accountDeletionEnabledEnv = "ACCOUNT_DELETION_ENABLED"
	devEndpointsEnabledEnv    = "DEV_ENDPOINTS_ENABLED"
	allowedOriginsEnv         = "ALLOWED_ORIGINS"
	environmentEnv            = "ENVIRONMENT"
)

func addSwaggerToRouter(r *chi.Mux) {
	if devEndpointsEnabled {
		r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("/swagger/doc.json")))
	}
}

func startKeyService(jwtService *services.JWTService, opaqueService *services.OpaqueService, twoFAService *services.TwoFAService, environment string) {
	// Initialize controllers
	serverKeysController := controllers.NewServerKeysController(opaqueService, jwtService, twoFAService)

	prometheusRegistry := prometheus.NewRegistry()
	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.LoggerMiddleware(prometheusRegistry))
	r.Mount("/v2/server_keys", serverKeysController.Router(middleware.KeyServiceMiddleware(environment)))
	addSwaggerToRouter(r)

	util.StartPrometheusServer(prometheusRegistry, *prometheusListenFlag)

	log.Info().Msgf("Server listening on %v", *listenFlag)
	if err := http.ListenAndServe(*listenFlag, r); err != nil {
		log.Panic().Err(err).Msg("Failed to start server")
	}
}

// @title Brave Accounts Service
// @externalDocs.description OpenAPI
// @externalDocs.url https://swagger.io/resources/open-api/
func main() {
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if logLevel := os.Getenv(logLevelEnv); logLevel != "" {
		if level, err := zerolog.ParseLevel(logLevel); err == nil {
			zerolog.SetGlobalLevel(level)
		}
	}

	if os.Getenv(logPrettyEnv) == "true" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	}

	switch environment {
	case util.DevelopmentEnv, util.StagingEnv, util.ProductionEnv:
		// Valid environment
	default:
		log.Panic().Msgf("Invalid environment: %s. Must be one of: %s, %s, %s",
			environment,
			util.DevelopmentEnv,
			util.StagingEnv,
			util.ProductionEnv)
	}
	passwordAuthEnabled := os.Getenv(passwordAuthEnabledEnv) == "true"
	emailAuthEnabled := os.Getenv(emailAuthEnabledEnv) == "true"
	accountDeletionEnabled := os.Getenv(accountDeletionEnabledEnv) == "true"
	allowedOrigins := strings.Split(os.Getenv(allowedOriginsEnv), ",")

	if !passwordAuthEnabled && !emailAuthEnabled {
		log.Panic().Msg("At least one authentication method must be enabled via PASSWORD_AUTH_ENABLED or EMAIL_AUTH_ENABLED env vars")
	}

	minSessionVersion := datastore.EmailAuthSessionVersion
	if passwordAuthEnabled && !emailAuthEnabled {
		minSessionVersion = datastore.PasswordAuthSessionVersion
	}

	datastore, err := datastore.NewDatastore(minSessionVersion, *startKeyServiceFlag, false)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init datastore")
	}

	if *startWebhookSenderFlag {
		if err = services.NewWebhookService(datastore).StartProcessingEvents(); err != nil {
			log.Panic().Err(err).Msg("Webhook sender failed")
		}
		return
	}

	jwtService, err := services.NewJWTService(datastore, *startKeyServiceFlag)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init JWT util")
	}

	opaqueService, err := services.NewOpaqueService(datastore, *startKeyServiceFlag)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init OPAQUE service")
	}

	twoFAService := services.NewTwoFAService(datastore, *startKeyServiceFlag)

	if *startKeyServiceFlag {
		startKeyService(jwtService, opaqueService, twoFAService, environment)
		return
	}

	datastore.StartVerificationEventListener()

	i18nBundle, err := util.CreateI18nBundle()
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init i18n bundle")
	}

	sesService, err := services.NewSESService(i18nBundle, environment)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init SES util")
	}
	verificationService := services.NewVerificationService(datastore, jwtService, sesService, passwordAuthEnabled, emailAuthEnabled)

	prometheusRegistry := prometheus.NewRegistry()

	servicesKeyMiddleware := middleware.ServicesKeyMiddleware(environment)
	// authMiddleware will ensure a valid session is present with the "accounts" service name
	authMiddleware := middleware.AuthMiddleware(jwtService, datastore, minSessionVersion, true, true)
	// validateAuthMiddleware will ensure a valid session is present with any service name
	validateAuthMiddleware := middleware.AuthMiddleware(jwtService, datastore, minSessionVersion, false, true)
	// verificationMiddleware will ensure a valid verification token is present
	verificationMiddleware := middleware.VerificationAuthMiddleware(jwtService, datastore, true)
	// optionalVerificationMiddleware will validate an optional verification token; the request will continue without a verification token
	optionalVerificationMiddleware := middleware.VerificationAuthMiddleware(jwtService, datastore, false)

	r := chi.NewRouter()

	authController := controllers.NewAuthController(opaqueService, jwtService, twoFAService, datastore, sesService)
	verificationController := controllers.NewVerificationController(datastore, verificationService)
	sessionsController := controllers.NewSessionsController(datastore)
	userKeysController := controllers.NewUserKeysController(datastore)
	accountsController := controllers.NewAccountsController(opaqueService, jwtService, twoFAService, datastore, verificationService)

	r.Use(middleware.LoggerMiddleware(prometheusRegistry))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{"POST", "GET"},
	}))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		//nolint:errcheck
		w.Write([]byte("Brave Accounts Service"))
	})

	r.Route("/v2", func(r chi.Router) {
		r.With(servicesKeyMiddleware).Mount("/auth", authController.Router(authMiddleware, validateAuthMiddleware, passwordAuthEnabled))
		if passwordAuthEnabled {
			r.With(servicesKeyMiddleware).Mount("/accounts", accountsController.Router(verificationMiddleware, optionalVerificationMiddleware, authMiddleware, accountDeletionEnabled))
		}
		r.Mount("/verify", verificationController.Router(verificationMiddleware, servicesKeyMiddleware, devEndpointsEnabled))
		r.With(servicesKeyMiddleware).Mount("/sessions", sessionsController.Router(authMiddleware))
		r.With(servicesKeyMiddleware).Mount("/keys", userKeysController.Router(authMiddleware))
	})

	addSwaggerToRouter(r)

	if *routesFlag {
		fmt.Println(docgen.MarkdownRoutesDoc(r, docgen.MarkdownOpts{
			ProjectPath: "github.com/brave/accounts",
		}))
		return
	}

	util.StartPrometheusServer(prometheusRegistry, *prometheusListenFlag)

	log.Info().Msgf("Server listening on %v", *listenFlag)
	if err := http.ListenAndServe(*listenFlag, r); err != nil {
		log.Panic().Err(err).Msg("Failed to start server")
	}
}
