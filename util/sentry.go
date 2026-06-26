package util

import (
	"net/http"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

const (
	SentryDSNEnv = "SENTRY_DSN"

	sentryFlushTimeout = 5 * time.Second
)

// InitSentry initializes the Sentry SDK using the DSN from the SENTRY_DSN
// environment variable.
//
// In the production and staging environments the DSN is required and a missing
// value will cause a panic. In all other environments an empty DSN simply
// disables Sentry.
//
// It returns a flush function that should be deferred by the caller to ensure
// buffered events are delivered before the program exits. The flush function is
// safe to call even when Sentry was not configured.
func InitSentry(environment string) func() {
	dsn := os.Getenv(SentryDSNEnv)

	if dsn == "" {
		if environment == ProductionEnv || environment == StagingEnv {
			log.Panic().Msgf("%s must be set in the %s and %s environments", SentryDSNEnv, ProductionEnv, StagingEnv)
		}
		log.Info().Msgf("%s not set, skipping Sentry initialization", SentryDSNEnv)
		return func() {}
	}

	if err := sentry.Init(sentry.ClientOptions{
		Dsn:            dsn,
		Environment:    environment,
		SendDefaultPII: false,
	}); err != nil {
		log.Panic().Err(err).Msg("Failed to init Sentry")
	}

	return func() {
		sentry.Flush(sentryFlushTimeout)
	}
}

// MaybeAddSentryDebugEndpoint registers a /debug-sentry endpoint that captures a
// test message, allowing Sentry configuration to be verified. The endpoint is
// only added in the development environment.
func MaybeAddSentryDebugEndpoint(r chi.Router, environment string) {
	if environment != DevelopmentEnv {
		return
	}

	r.Get("/debug-sentry", func(w http.ResponseWriter, r *http.Request) {
		if hub := sentry.GetHubFromContext(r.Context()); hub != nil {
			hub.CaptureMessage("It works!")
		}
		w.Header().Set("Content-Type", "text/plain")
		//nolint:errcheck
		w.Write([]byte("Sentry test message captured"))
	})
}
