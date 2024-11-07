package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/middleware"
	"github.com/brave-experiments/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	qsVerifyID                = "verify_id"
	qsVerifyCode              = "verify_code"
	authTokenIntent           = "auth_token"
	verificationIntent        = "verification"
	registrationIntent        = "registration"
	resetIntent               = "reset"
	premiumAuthRedirectURLEnv = "PREMIUM_AUTH_REDIRECT_URL"

	accountsServiceName              = "accounts"
	premiumServiceName               = "premium"
	inboxAliasesServiceName          = "inbox-aliases"
	premiumSessionExpirationDuration = 10 * time.Minute
)

var ErrIntentNotAllowed = errors.New("intent not allowed")
var ErrAccountExists = errors.New("account already exists")
var ErrAccountDoesNotExist = errors.New("account does not exist")

type VerificationController struct {
	datastore              *datastore.Datastore
	validate               *validator.Validate
	jwtUtil                *util.JWTUtil
	sesUtil                *util.SESUtil
	passwordAuthEnabled    bool
	emailAuthDisabled      bool
	premiumAuthRedirectURL string
}

// @Description	Request to initialize email verification
type VerifyInitRequest struct {
	// Email address to verify
	Email string `json:"email" validate:"required,email,ascii" example:"test@example.com"`
	// Purpose of verification (e.g., get auth token, simple verification, registration)
	Intent string `json:"intent" validate:"required,oneof=auth_token verification registration reset" example:"registration"`
	// Service requesting the verification
	Service string `json:"service" validate:"required,oneof=accounts premium inbox-aliases" example:"accounts"`
	// Locale for verification email
	Locale string `json:"language" validate:"max=8" example:"en-US"`
}

// @Description	Response containing verification check token
type VerifyInitResponse struct {
	// JWT token for checking verification status
	VerificationToken *string `json:"verificationToken"`
}

// @Description	Request for getting auth token after verification
type VerifyResultRequest struct {
	// Whether to wait for verification to complete
	Wait bool `json:"wait"`
}

// @Description	Response containing auth token
type VerifyResultResponse struct {
	// JWT auth token, null if verification incomplete or if password setup is required
	AuthToken *string `json:"authToken"`
	// Email verification status
	Verified bool `json:"verified"`
	// Email associated wiith the verification
	Email string `json:"email"`
}

// @Description Request parameters for verification completion
type VerifyCompleteRequest struct {
	// Unique verification identifier
	ID uuid.UUID `json:"id" validate:"required"`
	// Verification code sent to user
	Code string `json:"code" validate:"required"`
}

// @Description	Response containing validated token details
type ValidateTokenResponse struct {
	// Email address associated with the account
	Email string `json:"email"`
	// UUID of the account
	AccountID string `json:"accountId"`
	// UUID of the session associated with the account
	SessionID string `json:"sessionId"`
}

func NewVerificationController(datastore *datastore.Datastore, jwtUtil *util.JWTUtil, sesUtil *util.SESUtil, passwordAuthEnabled bool, emailAuthDisabled bool) *VerificationController {
	premiumAuthRedirectURL := os.Getenv(premiumAuthRedirectURLEnv)
	if premiumAuthRedirectURL == "" {
		log.Fatal().Msg("PREMIUM_AUTH_REDIRECT_URL environment variable is required")
	}

	return &VerificationController{
		datastore:              datastore,
		validate:               validator.New(validator.WithRequiredStructEnabled()),
		jwtUtil:                jwtUtil,
		sesUtil:                sesUtil,
		passwordAuthEnabled:    passwordAuthEnabled,
		emailAuthDisabled:      emailAuthDisabled,
		premiumAuthRedirectURL: premiumAuthRedirectURL,
	}
}

func (vc *VerificationController) Router(verificationAuthMiddleware func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()

	r.Post("/init", vc.VerifyInit)
	r.Post("/complete", vc.VerifyComplete)
	r.With(verificationAuthMiddleware).Post("/result", vc.VerifyQueryResult)

	return r
}

// @Summary Initialize email verification
// @Description Starts email verification process by sending a verification email
// @Description One of the following intents must be provided with the request:
// @Description - `auth_token`: After verification, create an account if one does not exist, and generate an auth token. The token will be available via the "query result" endpoint.
// @Description - `verification`: After verification, do not create an account, but indicate that the email was verified in the "query result" response. Do not allow registration after verification.
// @Description - `registration`: After verification, indicate that the email was verified in the "query result" response. An account may be created by setting a password.
// @Description - `reset`: After verification, indicate that the email was verified in the "query result" response. A password may be set for the existing account.
// @Description
// @Description One of the following service names must be provided with the request: `inbox-aliases`, `accounts`, `premium`.
// @Tags Email verification
// @Accept json
// @Produce json
// @Param request body VerifyInitRequest true "Verification request params"
// @Success 200 {object} VerifyInitResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/verify/init [post]
func (vc *VerificationController) VerifyInit(w http.ResponseWriter, r *http.Request) {
	var requestData VerifyInitRequest
	if err := render.DecodeJSON(r.Body, &requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	if err := vc.validate.Struct(requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	intentAllowed := true
	switch requestData.Intent {
	case authTokenIntent:
		if vc.emailAuthDisabled || requestData.Service != inboxAliasesServiceName {
			intentAllowed = false
		}
	case verificationIntent:
		if requestData.Service != inboxAliasesServiceName && requestData.Service != premiumServiceName {
			intentAllowed = false
		}
	case registrationIntent, resetIntent:
		if !vc.passwordAuthEnabled || requestData.Service != accountsServiceName {
			intentAllowed = false
		}
	default:
		intentAllowed = false
	}
	if !intentAllowed {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, ErrIntentNotAllowed)
		return
	}

	if requestData.Intent == registrationIntent || requestData.Intent == resetIntent {
		accountExists, err := vc.datastore.AccountExists(requestData.Email)
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}
		if requestData.Intent == registrationIntent && accountExists {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, ErrAccountExists)
			return
		}
		if requestData.Intent == resetIntent && !accountExists {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, ErrAccountDoesNotExist)
			return
		}
	}

	verification, err := vc.datastore.CreateVerification(requestData.Email, requestData.Service, requestData.Intent)
	if err != nil {
		if errors.Is(err, datastore.ErrTooManyVerifications) {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	var verificationToken *string
	if requestData.Intent == authTokenIntent || requestData.Intent == verificationIntent || requestData.Intent == registrationIntent || requestData.Intent == resetIntent {
		token, err := vc.jwtUtil.CreateVerificationToken(verification.ID, datastore.VerificationExpiration)
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}
		verificationToken = &token
	}

	if err := vc.sesUtil.SendVerificationEmail(
		r.Context(),
		requestData.Email,
		verification.ID.String(),
		verification.Code,
		requestData.Locale,
	); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, fmt.Errorf("failed to send verification email: %w", err))
		return
	}

	response := VerifyInitResponse{
		VerificationToken: verificationToken,
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// @Summary Complete email verification
// @Description Completes the email verification process
// @Tags Email verification
// @Accept json
// @Produce json
// @Param request body VerifyCompleteRequest true "Verify completion params"
// @Success 204 "Email verification successful"
// @Failure 400 {string} string "Missing/invalid verification parameters"
// @Failure 404 {string} string "Verification not found"
// @Failure 500 {string} string "Internal server error"
// @Router /v2/verify/complete [post]
func (vc *VerificationController) VerifyComplete(w http.ResponseWriter, r *http.Request) {
	var requestData VerifyCompleteRequest
	if err := render.DecodeJSON(r.Body, &requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	if err := vc.validate.Struct(requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	// Update verification status
	if err := vc.datastore.UpdateVerificationStatus(requestData.ID, requestData.Code); err != nil {
		if errors.Is(err, datastore.ErrVerificationNotFound) {
			util.RenderErrorResponse(w, r, http.StatusNotFound, err)
			return
		}
		log.Err(err).Msg("failed to update verification status")
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// @Summary Query result of verification
// @Description Provides the status of a pending or successful verification.
// @Description If the wait option is set to true, the server will up to 20 seconds for verification. Feel free
// @Description to call this endpoint repeatedly to wait for verification.
// @Tags Email verification
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + verification token"
// @Param request body VerifyResultRequest true "Auth token request params"
// @Success 200 {object} VerifyResultResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/verify/result [post]
func (vc *VerificationController) VerifyQueryResult(w http.ResponseWriter, r *http.Request) {
	var requestData VerifyResultRequest
	if err := render.DecodeJSON(r.Body, &requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	verification := r.Context().Value(middleware.ContextVerification).(*datastore.Verification)

	responseData := VerifyResultResponse{
		Email: verification.Email,
	}

	if !verification.Verified && requestData.Wait {
		verified, err := vc.datastore.WaitOnVerification(r.Context(), verification.ID)
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}
		verification.Verified = verified
	}

	if !verification.Verified {
		render.Status(r, http.StatusOK)
		render.JSON(w, r, responseData)
		return
	}

	var authToken *string
	if verification.Intent == authTokenIntent {
		if err := vc.datastore.DeleteVerification(verification.ID); err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}

		account, err := vc.datastore.GetOrCreateAccount(verification.Email)
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}

		session, err := vc.datastore.CreateSession(account.ID, datastore.EmailAuthSessionVersion, nil)
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}

		authTokenResult, err := vc.jwtUtil.CreateAuthToken(session.ID)
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}
		authToken = &authTokenResult
	}

	responseData.AuthToken = authToken
	responseData.Verified = true

	render.Status(r, http.StatusOK)
	render.JSON(w, r, responseData)
}
