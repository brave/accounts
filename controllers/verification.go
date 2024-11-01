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
	authTokenRedirectIntent   = "auth_token_redirect"
	verificationIntent        = "verification"
	premiumAuthRedirectURLEnv = "PREMIUM_AUTH_REDIRECT_URL"

	accountsServiceName              = "accounts"
	premiumServiceName               = "premium"
	inboxAliasesServiceName          = "inbox-aliases"
	premiumSessionExpirationDuration = 10 * time.Minute
)

var ErrIntentNotAllowed = errors.New("intent not allowed")

type VerificationController struct {
	datastore              *datastore.Datastore
	validate               *validator.Validate
	jwtUtil                *util.JWTUtil
	sesUtil                *util.SESUtil
	passwordAuthEnabled    bool
	premiumAuthRedirectURL string
}

// @Description	Request to initialize email verification
type VerifyInitRequest struct {
	// Email address to verify
	Email string `json:"email" validate:"required,email,ascii" example:"test@example.com"`
	// Purpose of verification (e.g., get auth token, get auth token & redirect, simple verification)
	Intent string `json:"intent" validate:"required,oneof=auth_token auth_token_redirect verification" example:"verification"`
	// Service requesting the verification
	Service string `json:"service" validate:"required,oneof=accounts premium inbox-aliases" example:"accounts"`
}

// @Description	Response containing verification check token
type VerifyInitResponse struct {
	// JWT token for checking verification status
	VerificationToken string `json:"verificationToken"`
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

// @Description	Response containing validated token details
type ValidateTokenResponse struct {
	// Email address associated with the account
	Email string `json:"email"`
	// UUID of the account
	AccountID string `json:"accountId"`
	// UUID of the session associated with the account
	SessionID string `json:"sessionId"`
}

func NewVerificationController(datastore *datastore.Datastore, jwtUtil *util.JWTUtil, sesUtil *util.SESUtil, passwordAuthEnabled bool) *VerificationController {
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
		premiumAuthRedirectURL: premiumAuthRedirectURL,
	}
}

func (vc *VerificationController) Router(verificationAuthMiddleware func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()

	r.Post("/init", vc.VerifyInit)
	r.Get("/complete", vc.VerifyComplete)
	r.With(verificationAuthMiddleware).Post("/result", vc.VerifyQueryResult)

	return r
}

// @Summary Initialize email verification
// @Description Starts email verification process by sending a verification email
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
		if vc.passwordAuthEnabled || requestData.Service != inboxAliasesServiceName {
			intentAllowed = false
		}
	case authTokenRedirectIntent:
		if requestData.Service != premiumServiceName {
			intentAllowed = false
		}
	case verificationIntent:
		if requestData.Service != inboxAliasesServiceName && requestData.Service != accountsServiceName {
			intentAllowed = false
		}
	default:
		intentAllowed = false
	}
	if !intentAllowed {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, ErrIntentNotAllowed)
		return
	}

	verification, err := vc.datastore.CreateVerification(requestData.Email, requestData.Service, requestData.Intent)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	verificationToken, err := vc.jwtUtil.CreateVerificationToken(verification.ID, datastore.VerificationExpiration)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	if err := vc.sesUtil.SendVerificationEmail(
		r.Context(),
		requestData.Email,
		verification.ID.String(),
		verification.Code,
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

func (vc *VerificationController) deleteVerificationAndGetAuthToken(w http.ResponseWriter, r *http.Request, verification *datastore.Verification, expiration *time.Duration) *string {
	if err := vc.datastore.DeleteVerification(verification.ID); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return nil
	}

	account, err := vc.datastore.GetOrCreateAccount(verification.Email)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return nil
	}

	session, err := vc.datastore.CreateSession(account.ID, nil, expiration)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return nil
	}

	authTokenResult, err := vc.jwtUtil.CreateAuthToken(session.ID, expiration)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return nil
	}
	return &authTokenResult
}

// @Summary Complete email verification
// @Description Completes the email verification process
// @Tags Email verification
// @Produce text/plain
// @Param verify_id query string true "Verification ID"
// @Param verify_code query string true "Verification code"
// @Success 200 {string} string "Email verification successful"
// @Failure 400 {string} string "Missing/invalid verification parameters"
// @Failure 404 {string} string "Verification not found"
// @Failure 500 {string} string "Internal server error"
// @Router /v2/verify/complete [get]
func (vc *VerificationController) VerifyComplete(w http.ResponseWriter, r *http.Request) {
	verifyID := r.URL.Query().Get(qsVerifyID)
	verifyToken := r.URL.Query().Get(qsVerifyCode)

	if verifyID == "" || verifyToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		render.PlainText(w, r, "Missing verification id or token")
		return
	}

	// Parse UUID
	id, err := uuid.Parse(verifyID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.PlainText(w, r, "Invalid verification id format")
		return
	}

	verification, err := vc.datastore.GetVerificationStatus(id)
	if err != nil {
		if errors.Is(err, datastore.ErrVerificationNotFound) {
			w.WriteHeader(http.StatusNotFound)
			render.PlainText(w, r, err.Error())
			return
		}
		log.Err(err).Msg("failed to get verification status")
		w.WriteHeader(http.StatusInternalServerError)
		render.PlainText(w, r, "Internal server error")
		return
	}

	if verification.Intent == authTokenRedirectIntent {
		var expiration *time.Duration
		if verification.Service == premiumServiceName {
			expirationClone := premiumSessionExpirationDuration
			expiration = &expirationClone
		}
		authToken := vc.deleteVerificationAndGetAuthToken(w, r, verification, expiration)
		if authToken == nil {
			return
		}
		redirectURL := vc.premiumAuthRedirectURL + *authToken
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	// Update verification status
	err = vc.datastore.UpdateVerificationStatus(id, verifyToken)
	if err != nil {
		log.Err(err).Msg("failed to update verification status")
		w.WriteHeader(http.StatusInternalServerError)
		render.PlainText(w, r, "Internal server error")
		return
	}

	w.WriteHeader(http.StatusOK)
	render.PlainText(w, r, "Email verification successful")
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

	var responseData VerifyResultResponse

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
		authToken = vc.deleteVerificationAndGetAuthToken(w, r, verification, nil)
		if authToken == nil {
			return
		}
	}

	response := VerifyResultResponse{
		AuthToken: authToken,
		Verified:  true,
		Email:     verification.Email,
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}
