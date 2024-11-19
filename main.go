package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/brave-experiments/accounts/controllers"
	"github.com/brave-experiments/accounts/datastore"
	_ "github.com/brave-experiments/accounts/docs"
	"github.com/brave-experiments/accounts/middleware"
	"github.com/brave-experiments/accounts/services"
	"github.com/brave-experiments/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/docgen"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/swaggo/http-swagger/v2"

	_ "github.com/joho/godotenv/autoload"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	routesFlag             = flag.Bool("routes", false, "Generate router documentation")
	startWebhookSenderFlag = flag.Bool("start-webhook-sender", false, "Start the webhook event sender")
)

const (
	logPrettyEnv           = "LOG_PRETTY"
	logLevelEnv            = "LOG_LEVEL"
	serveSwaggerEnv        = "SERVE_SWAGGER"
	passwordAuthEnabledEnv = "PASSWORD_AUTH_ENABLED"
	emailAuthDisabledEnv   = "EMAIL_AUTH_DISABLED"
	devEndpointsEnabledEnv = "DEV_ENDPOINTS_ENABLED"
)

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

	passwordAuthEnabled := os.Getenv(passwordAuthEnabledEnv) == "true"
	emailAuthDisabled := os.Getenv(emailAuthDisabledEnv) == "true"
	devEndpointsEnabled := os.Getenv(devEndpointsEnabledEnv) == "true"

	minSessionVersion := datastore.EmailAuthSessionVersion
	if passwordAuthEnabled && emailAuthDisabled {
		minSessionVersion = datastore.PasswordAuthSessionVersion
	}

	datastore, err := datastore.NewDatastore(minSessionVersion, false)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init datastore")
	}

	if *startWebhookSenderFlag {
		services.NewWebhookService(datastore).StartProcessingEvents()
		return
	}

	jwtService, err := services.NewJWTService(datastore)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init JWT util")
	}

	i18nBundle, err := util.CreateI18nBundle()
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init i18n bundle")
	}

	sesService, err := services.NewSESService(i18nBundle)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init SES util")
	}

	opaqueService, err := services.NewOpaqueService(datastore)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init OPAQUE service")
	}

	prometheusRegistry := prometheus.NewRegistry()

	servicesKeyMiddleware := middleware.ServicesKeyMiddleware()
	authMiddleware := middleware.AuthMiddleware(jwtService, datastore, minSessionVersion)
	verificationMiddleware := middleware.VerificationAuthMiddleware(jwtService, datastore)

	r := chi.NewRouter()

	authController := controllers.NewAuthController(opaqueService, jwtService, datastore)
	accountsController := controllers.NewAccountsController(opaqueService, jwtService, datastore)
	verificationController := controllers.NewVerificationController(datastore, jwtService, sesService, passwordAuthEnabled, emailAuthDisabled)
	sessionsController := controllers.NewSessionsController(datastore)
	userKeysController := controllers.NewUserKeysController(datastore)

	r.Use(middleware.LoggerMiddleware(prometheusRegistry))

	r.Route("/v2", func(r chi.Router) {
		r.With(servicesKeyMiddleware).Mount("/auth", authController.Router(authMiddleware, passwordAuthEnabled))
		if passwordAuthEnabled {
			r.With(servicesKeyMiddleware).Mount("/accounts", accountsController.Router(verificationMiddleware, authMiddleware))
		}
		r.Mount("/verify", verificationController.Router(verificationMiddleware, servicesKeyMiddleware, devEndpointsEnabled))
		r.With(servicesKeyMiddleware).Mount("/sessions", sessionsController.Router(authMiddleware))
		r.With(servicesKeyMiddleware).Mount("/keys", userKeysController.Router(authMiddleware))
	})

	if os.Getenv(serveSwaggerEnv) == "true" {
		r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("http://localhost:8080/swagger/doc.json")))
	}

	if *routesFlag {
		fmt.Println(docgen.MarkdownRoutesDoc(r, docgen.MarkdownOpts{
			ProjectPath: "github.com/brave-experiments/accounts",
		}))
		return
	}

	go func() {
		r := chi.NewRouter()
		r.Handle("/metrics", promhttp.HandlerFor(prometheusRegistry, promhttp.HandlerOpts{}))
		log.Info().Msg("Prometheus server listening on port 9090")
		if err := http.ListenAndServe(":9090", r); err != nil {
			log.Panic().Err(err).Msg("Failed to start Prometheus server")
		}
	}()

	log.Info().Msg("Server listening on port 8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Panic().Err(err).Msg("Failed to start server")
	}
}
