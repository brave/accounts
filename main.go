package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/brave-experiments/accounts/controllers"
	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/middleware"
	"github.com/brave-experiments/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/docgen"

	_ "github.com/joho/godotenv/autoload"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var routes = flag.Bool("routes", false, "Generate router documentation")

const logPrettyEnv = "LOG_PRETTY"

func main() {
	flag.Parse()

	if os.Getenv(logPrettyEnv) != "" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

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

	authMiddleware := middleware.AuthMiddleware(jwtUtil, datastore)

	r := chi.NewRouter()

	authController := controllers.NewAuthController(datastore, jwtUtil, sesUtil)
	sessionsController := controllers.NewSessionsController(datastore)

	r.Route("/accounts", func(r chi.Router) {
		r.Mount("/", authController.Router(authMiddleware))
		r.Mount("/sessions", sessionsController.Router(authMiddleware))
	})

	if *routes {
		fmt.Println(docgen.MarkdownRoutesDoc(r, docgen.MarkdownOpts{
			ProjectPath: "github.com/brave-experiments/accounts",
		}))
		return
	}

	log.Printf("Server listening on port 8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Panic().Err(err).Msg("Failed to start server")
	}
}
