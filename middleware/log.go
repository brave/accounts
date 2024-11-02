package middleware

import (
	"net/http"

	"github.com/rs/zerolog/log"
)

func LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Msg("Start request")
		next.ServeHTTP(w, r)
		log.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Msg("Request finish")
	})
}
