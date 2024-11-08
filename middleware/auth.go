package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/services"
	"github.com/brave-experiments/accounts/util"
)

const ContextSession = "session"
const ContextVerification = "verification"

func AuthMiddleware(jwtService *services.JWTService, ds *datastore.Datastore, minSessionVersion int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := util.ExtractAuthToken(r)
			if err != nil {
				util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
				return
			}

			sessionID, err := jwtService.ValidateAuthToken(token)
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
				util.RenderErrorResponse(w, r, http.StatusForbidden, errors.New("outdated session"))
				return
			}

			// Store session in context
			ctx := context.WithValue(r.Context(), ContextSession, session)
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
				if errors.Is(err, datastore.ErrVerificationNotFound) {
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
