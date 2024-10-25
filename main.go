package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

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

const logPrettyEnv = "LOG_PRETTY"
const logLevelEnv = "LOG_LEVEL"
const serveSwaggerEnv = "SERVE_SWAGGER"
const passwordAuthEnabledEnv = "PASSWORD_AUTH_ENABLED"

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
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	passwordAuthEnabled := os.Getenv(passwordAuthEnabledEnv) == "true"

	datastore, err := datastore.NewDatastore()
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init datastore")
	}

	jwtUtil, err := util.NewJWTUtil()
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init JWT util")
	}

	sesUtil, err := util.NewSESUtil()
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init SES util")
	}

	opaqueService, err := services.NewOpaqueService(datastore)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to init OPAQUE service")
	}

	authMiddleware := middleware.AuthMiddleware(jwtUtil, datastore)
	verificationAuthMiddleware := middleware.VerificationAuthMiddleware(jwtUtil, datastore)

	r := chi.NewRouter()

	authController := controllers.NewAuthController(opaqueService)
	accountsController := controllers.NewAccountsController(opaqueService, jwtUtil, datastore)
	verificationController := controllers.NewVerificationController(datastore, jwtUtil, sesUtil, passwordAuthEnabled)
	sessionsController := controllers.NewSessionsController(datastore)

	r.Use(middleware.LoggerMiddleware)

	r.Route("/v2", func(r chi.Router) {
		r.Mount("/auth", authController.Router(authMiddleware))
		if passwordAuthEnabled {
			r.Mount("/accounts", accountsController.Router(authMiddleware, verificationAuthMiddleware))
		}
		r.Mount("/verify", verificationController.Router(verificationAuthMiddleware))
		r.Mount("/sessions", sessionsController.Router(authMiddleware))
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
