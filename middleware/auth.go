package middleware

import (
	"context"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/rs/zerolog/log"
)

type contextKey string

const (
	ContextSession            = contextKey("session")
	ContextSessionServiceName = contextKey("sessionServiceName")
	ContextVerification       = contextKey("verification")

	braveServicesKeyEnv    = "BRAVE_SERVICES_KEY"
	braveServicesKeyHeader = "brave-key"
)

func AuthMiddleware(jwtService *services.JWTService, ds *datastore.Datastore, minSessionVersion int, enforceAccountsServiceName bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := util.ExtractAuthToken(r)
			if err != nil {
				util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
				return
			}

			sessionID, serviceName, err := jwtService.ValidateAuthToken(token)
			if err != nil {
				util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
				return
			}

			session, err := ds.GetSession(sessionID)
			if err != nil {
				if errors.Is(err, datastore.ErrSessionNotFound) {
					util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
					return
				}
				util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
				return
			}

			if session.Version < minSessionVersion {
				util.RenderErrorResponse(w, r, http.StatusForbidden, util.ErrOutdatedSession)
				return
			}

			if enforceAccountsServiceName && serviceName != util.AccountsServiceName {
				util.RenderErrorResponse(w, r, http.StatusForbidden, util.ErrInvalidTokenAudience)
				return
			}

			// Store session in context
			ctx := context.WithValue(
				context.WithValue(r.Context(), ContextSession, session),
				ContextSessionServiceName,
				serviceName,
			)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func VerificationAuthMiddleware(jwtService *services.JWTService, ds *datastore.Datastore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := util.ExtractAuthToken(r)
			if err != nil {
				util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
				return
			}

			verificationID, err := jwtService.ValidateVerificationToken(token)
			if err != nil {
				util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
				return
			}

			verification, err := ds.GetVerificationStatus(verificationID)
			if err != nil {
				if errors.Is(err, util.ErrVerificationNotFound) {
					util.RenderErrorResponse(w, r, http.StatusNotFound, err)
					return
				}
				util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
				return
			}

			// Store verification in context
			ctx := context.WithValue(r.Context(), ContextVerification, verification)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ServicesKeyMiddleware(env string) func(http.Handler) http.Handler {
	servicesKeys := strings.FieldsFunc(os.Getenv(braveServicesKeyEnv), func(r rune) bool {
		return r == ','
	})
	if len(servicesKeys) < 1 && env == util.ProductionEnv {
		log.Panic().Msgf("%s must contain at least one key in production environment", braveServicesKeyEnv)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If services key is configured, verify the request header
			if len(servicesKeys) > 0 {
				headerKey := r.Header.Get(braveServicesKeyHeader)
				if !slices.Contains(servicesKeys, headerKey) {
					util.RenderErrorResponse(w, r, http.StatusUnauthorized, util.ErrInvalidServicesKey)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func KeyServiceMiddleware() func(http.Handler) http.Handler {
	secret := os.Getenv(util.KeyServiceSecretEnv)
	if secret == "" {
		log.Panic().Msgf("%s key cannot be empty in production environment", util.KeyServiceSecretEnv)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headerSecret := r.Header.Get(util.KeyServiceSecretHeader)
			if headerSecret != secret {
				util.RenderErrorResponse(w, r, http.StatusUnauthorized, util.ErrInvalidServicesKey)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
