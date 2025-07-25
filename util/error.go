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
	ErrEmailNotVerified            = NewExposedError(11003, "email not verified")
	ErrIncorrectVerificationIntent = NewExposedError(11004, "incorrect verification intent")
	ErrNewAccountEmailRequired     = NewExposedError(11005, "newAccountEmail is required when no verification token is provided")

	// Key errors, prefixed with '12'
	ErrKeyNotFound = NewExposedError(12001, "key not found")

	// Verification errors, prefixed with '13'
	ErrTooManyVerifications           = NewExposedError(13001, "too many pending verification requests for email")
	ErrVerificationNotFound           = NewExposedError(13002, "verification not found or invalid id/code")
	ErrIntentNotAllowed               = NewExposedError(13003, "intent not allowed")
	ErrAccountExists                  = NewExposedError(13004, "account already exists")
	ErrAccountDoesNotExist            = NewExposedError(13005, "account does not exist")
	ErrEmailDomainNotSupported        = NewExposedError(13006, "email domain is not supported")
	ErrFailedToSendEmailInvalidFormat = NewExposedError(13007, "failed to send email due to invalid format")

	// Auth errors, prefixed with '14'
	ErrInterimPasswordStateNotFound = NewExposedError(14001, "interim password state not found")
	ErrInterimPasswordStateExpired  = NewExposedError(14002, "interim password state has expired")
	ErrOutdatedSession              = NewExposedError(14003, "outdated session")
	ErrIncorrectCredentials         = NewExposedError(14004, "incorrect credentials")
	ErrIncorrectEmail               = NewExposedError(14005, "incorrect email")
	ErrIncorrectPassword            = NewExposedError(14006, "incorrect password")
	ErrInvalidTokenAudience         = NewExposedError(14007, "invalid token audience")
	ErrBadTOTPCode                  = NewExposedError(14008, "invalid TOTP code")
	ErrInterimPasswordStateMismatch = NewExposedError(14009, "interim password state mismatch")
	ErrBadRecoveryKey               = NewExposedError(14010, "invalid recovery key")
	ErrTOTPAlreadyEnabled           = NewExposedError(14011, "TOTP authentication is already enabled for this account")
	ErrTOTPCodeAlreadyUsed          = NewExposedError(14012, "TOTP code has already been used")
	ErrEmailVerificationRequired    = NewExposedError(14013, "email verification required")

	// Misc errors, prefixed with '15'
	ErrInvalidServicesKey = NewExposedError(15001, "invalid services key")
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
