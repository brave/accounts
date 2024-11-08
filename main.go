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
	"github.com/swaggo/http-swagger/v2"

	_ "github.com/joho/godotenv/autoload"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var routes = flag.Bool("routes", false, "Generate router documentation")

const (
	logPrettyEnv           = "LOG_PRETTY"
	logLevelEnv            = "LOG_LEVEL"
	serveSwaggerEnv        = "SERVE_SWAGGER"
	passwordAuthEnabledEnv = "PASSWORD_AUTH_ENABLED"
	emailAuthDisabledEnv   = "EMAIL_AUTH_DISABLED"
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

	minSessionVersion := 1
	if passwordAuthEnabled && emailAuthDisabled {
		minSessionVersion = 2
	}

	datastore, err := datastore.NewDatastore(minSessionVersion)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init datastore")
	}

	jwtService, err := services.NewJWTService(datastore)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init JWT util")
	}

	i18nBundle, err := util.CreateI18nBundle()
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init i18n bundle")
	}

	sesUtil, err := util.NewSESUtil(i18nBundle)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init SES util")
	}

	opaqueService, err := services.NewOpaqueService(datastore)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init OPAQUE service")
	}

	restrictiveAuthMiddleware := middleware.AuthMiddleware(jwtService, datastore, minSessionVersion)
	permissiveAuthMiddleware := middleware.AuthMiddleware(jwtService, datastore, 0)
	verificationAuthMiddleware := middleware.VerificationAuthMiddleware(jwtService, datastore)

	r := chi.NewRouter()

	authController := controllers.NewAuthController(opaqueService, jwtService, datastore)
	accountsController := controllers.NewAccountsController(opaqueService, jwtService, datastore)
	verificationController := controllers.NewVerificationController(datastore, jwtService, sesUtil, passwordAuthEnabled, emailAuthDisabled)
	sessionsController := controllers.NewSessionsController(datastore)

	r.Use(middleware.LoggerMiddleware)

	r.Route("/v2", func(r chi.Router) {
		r.Mount("/auth", authController.Router(restrictiveAuthMiddleware))
		if passwordAuthEnabled {
			r.Mount("/accounts", accountsController.Router(permissiveAuthMiddleware, verificationAuthMiddleware))
		}
		r.Mount("/verify", verificationController.Router(verificationAuthMiddleware))
		r.Mount("/sessions", sessionsController.Router(restrictiveAuthMiddleware))
	})

	if os.Getenv(serveSwaggerEnv) == "true" {
		r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("http://localhost:8080/swagger/doc.json")))
	}

	if *routes {
		fmt.Println(docgen.MarkdownRoutesDoc(r, docgen.MarkdownOpts{
			ProjectPath: "github.com/brave-experiments/accounts",
		}))
		return
	}

	log.Info().Msg("Server listening on port 8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Panic().Err(err).Msg("Failed to start server")
	}
}
