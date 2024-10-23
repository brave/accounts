package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/util"
)

const ContextSession = "session"

func AuthMiddleware(jwtUtil *util.JWTUtil, ds *datastore.Datastore) func(http.Handler) http.Handler {
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

			// Store session in context
			ctx := context.WithValue(r.Context(), ContextSession, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
