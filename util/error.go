package util

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	// Account errors, prefixed with '11'
	ErrRegistrationStateNotFound   = NewExposedError(11001, "registration state not found")
	ErrRegistrationStateExpired    = NewExposedError(11002, "registration state has expired")
	ErrEmailNotVerified            = NewExposedError(11003, "email not verified")
	ErrIncorrectVerificationIntent = NewExposedError(11004, "incorrect verification intent")

	// Key errors, prefixed with '12'
	ErrKeyNotFound = NewExposedError(12001, "key not found")

	// Verification errors, prefixed with '13'
	ErrTooManyVerifications = NewExposedError(13001, "too many pending verification requests for email")
	ErrVerificationNotFound = NewExposedError(13002, "verification not found or invalid id/code")
	ErrIntentNotAllowed     = NewExposedError(13003, "intent not allowed")
	ErrAccountExists        = NewExposedError(13004, "account already exists")
	ErrAccountDoesNotExist  = NewExposedError(13005, "account does not exist")

	// Auth errors, prefixed with '14'
	ErrAKEStateNotFound     = NewExposedError(14001, "AKE state not found")
	ErrAKEStateExpired      = NewExposedError(14002, "AKE state has expired")
	ErrOutdatedSession      = NewExposedError(14003, "outdated session")
	ErrIncorrectCredentials = NewExposedError(14004, "incorrect credentials")

	// Misc errors, prefixed with '15'
	ErrInvalidServicesKey = NewExposedError(15005, "invalid services key")
)

// ExposedError represents an error that is safe to expose to API clients
type ExposedError struct {
	// Error code
	Code int
	// Details of the error
	Details string
}

func (e *ExposedError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Details)
}

func NewExposedError(code int, details string) *ExposedError {
	return &ExposedError{
		Code:    code,
		Details: details,
	}
}

// @Description Standard error response
type ErrorResponse struct {
	// Error code
	Code *int `json:"code"`
	// HTTP status code
	Status int `json:"status"`
	// Error message
	Error string `json:"error"`
}

func RenderErrorResponse(w http.ResponseWriter, r *http.Request, status int, err error) {
	response := ErrorResponse{
		Status: status,
	}

	var exposedErr *ExposedError
	var validationErr validator.ValidationErrors
	logLevel := zerolog.DebugLevel

	if errors.As(err, &exposedErr) {
		response.Error = exposedErr.Details
		response.Code = &exposedErr.Code
	} else if errors.As(err, &validationErr) {
		response.Error = err.Error()
	} else {
		logLevel = zerolog.ErrorLevel
		response.Error = http.StatusText(status)
	}

	if status == http.StatusInternalServerError {
		logLevel = zerolog.ErrorLevel
		response.Error = http.StatusText(status)
	}

	log.WithLevel(logLevel).
		Err(err).
		Str("path", r.URL.Path).
		Str("method", r.Method).
		Msg(err.Error())

	render.Status(r, status)
	render.JSON(w, r, response)
}
