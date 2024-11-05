package middleware

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/util"
)

const ContextSession = "session"
const ContextVerification = "verification"

func AuthMiddleware(jwtUtil *util.JWTUtil, ds *datastore.Datastore, minSessionVersion int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := util.ExtractAuthToken(r)
			if err != nil {
				util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
				return
			}

			sessionID, err := jwtUtil.ValidateAuthToken(token)
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

			if session.ExpiresAt != nil {
				if time.Now().After(*session.ExpiresAt) {
					util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
					return
				}
			} else if session.Version < minSessionVersion {
				// Using `else if` to exclude checking versions for ephemeral sessions
				// i.e. non-Brave Premium sessions using email auth
				// Ephemeral sessions are exceptions to the session version check
				util.RenderErrorResponse(w, r, http.StatusForbidden, errors.New("outdated session"))
				return
			}

			// Store session in context
			ctx := context.WithValue(r.Context(), ContextSession, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func VerificationAuthMiddleware(jwtUtil *util.JWTUtil, ds *datastore.Datastore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := util.ExtractAuthToken(r)
			if err != nil {
				util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
				return
			}

			verificationID, err := jwtUtil.ValidateVerificationToken(token)
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
