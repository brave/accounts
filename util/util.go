package util

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/render"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// @Description Standard error response
type ErrorResponse struct {
	// HTTP status code
	Status int `json:"status"`
	// Error message
	Error string `json:"error"`
}

func (e *ErrorResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.Status)
	return nil
}

func RenderErrorResponse(w http.ResponseWriter, r *http.Request, status int, err error) {
	var errStr string
	if status != http.StatusBadRequest && status != http.StatusNotFound {
		errStr = http.StatusText(status)
		logLevel := zerolog.ErrorLevel
		if status != http.StatusInternalServerError {
			logLevel = zerolog.DebugLevel
		}
		log.WithLevel(logLevel).
			Err(err).
			Str("path", r.URL.Path).
			Str("method", r.Method).
			Msg(errStr)
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
