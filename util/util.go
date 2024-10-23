package util

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/render"
	"github.com/rs/zerolog/log"
)

type ErrorResponse struct {
	Status int
	Error  string
}

func (e *ErrorResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.Status)
	return nil
}

func RenderErrorResponse(w http.ResponseWriter, r *http.Request, status int, err error) {
	var errStr string
	if status == http.StatusInternalServerError {
		errStr = "Internal server error"
		log.Error().
			Err(err).
			Str("path", r.URL.Path).
			Str("method", r.Method).
			Msg("internal server error")
	} else {
		errStr = err.Error()
	}
	render.Render(w, r, &ErrorResponse{
		Status: status,
		Error:  errStr,
	})
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("failed to generate random string: %w", err))
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

func ExtractAuthToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("invalid authorization header")
	}

	return strings.TrimPrefix(authHeader, "Bearer "), nil
}
