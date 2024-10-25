package controllers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/middleware"
	"github.com/brave-experiments/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

const (
	qsVerifyID   = "verify_id"
	qsVerifyCode = "verify_code"
)

type AuthController struct {
	datastore *datastore.Datastore
	validate  *validator.Validate
	jwtUtil   *util.JWTUtil
	sesUtil   *util.SESUtil
}

// @Description	Request to initialize email verification
type VerifyInitRequest struct {
	// Email address to verify
	Email string `json:"email" validate:"required,email,ascii" example:"test@example.com"`
}

// @Description	Response containing verification check token
type VerifyInitResponse struct {
	// JWT token for checking verification status
	VerificationToken string `json:"verificationToken"`
}

// @Description	Request for getting auth token after verification
type VerifyGetAuthTokenRequest struct {
	// Whether to wait for verification to complete
	Wait bool `json:"wait"`
}

// @Description	Response containing auth token
type VerifyGetAuthTokenResponse struct {
	// JWT auth token, null if verification incomplete
	AuthToken *string `json:"authToken"`
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

func NewAuthController(datastore *datastore.Datastore, jwtUtil *util.JWTUtil, sesUtil *util.SESUtil) *AuthController {
	return &AuthController{
		datastore: datastore,
		validate:  validator.New(validator.WithRequiredStructEnabled()),
		jwtUtil:   jwtUtil,
		sesUtil:   sesUtil,
	}
}

func (ac *AuthController) Router(authMiddleware func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()

	r.Post("/verify/init", ac.VerifyInit)
	r.Get("/verify/complete", ac.VerifyComplete)
	r.Post("/verify/auth", ac.VerifyGetAuthToken)
	r.With(authMiddleware).Get("/auth/validate", ac.Validate)

	return r
}

// @Summary Initialize email verification
// @Description Starts email verification process by sending a verification email
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body VerifyInitRequest true "Verification request params"
// @Success 200 {object} VerifyInitResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/verify/init [post]
func (ac *AuthController) VerifyInit(w http.ResponseWriter, r *http.Request) {
	var requestData VerifyInitRequest
	if err := render.DecodeJSON(r.Body, &requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	if err := ac.validate.Struct(requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	verification, err := ac.datastore.CreateVerification(requestData.Email)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	verificationToken, err := ac.jwtUtil.CreateVerificationToken(verification.ID, datastore.VerificationExpiration)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	if err := ac.sesUtil.SendVerificationEmail(
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

// @Summary Complete email verification
// @Description Completes the email verification process
// @Tags Auth
// @Produce text/plain
// @Param verify_id query string true "Verification ID"
// @Param verify_code query string true "Verification code"
// @Success 200 {string} string "Email verification successful"
// @Failure 400 {string} string "Missing/invalid verification parameters"
// @Failure 404 {string} string "Verification not found"
// @Failure 500 {string} string "Internal server error"
// @Router /v2/verify/complete [get]
func (ac *AuthController) VerifyComplete(w http.ResponseWriter, r *http.Request) {
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

	// Update verification status
	err = ac.datastore.UpdateVerificationStatus(id, verifyToken)
	if err != nil {
		if errors.Is(err, datastore.ErrVerificationNotFound) {
			w.WriteHeader(http.StatusNotFound)
			render.PlainText(w, r, err.Error())
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		render.PlainText(w, r, "Internal server error")
		return
	}

	w.WriteHeader(http.StatusOK)
	render.PlainText(w, r, "Email verification successful")
}

// @Summary Get authentication token
// @Description Exchanges a verify check token for an auth token after successful verification.
// @Description If the wait option is set to true, the server will up to 20 seconds for verification. Feel free
// @Description to call this endpoint repeatedly to wait for verification.
// @Tags Auth
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + verification token"
// @Param request body VerifyGetAuthTokenRequest true "Auth token request params"
// @Success 200 {object} VerifyGetAuthTokenResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/verify/auth [post]
func (ac *AuthController) VerifyGetAuthToken(w http.ResponseWriter, r *http.Request) {
	// Extract and validate token
	tokenString, err := util.ExtractAuthToken(r)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
		return
	}

	verificationID, err := ac.jwtUtil.ValidateVerificationToken(tokenString)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
		return
	}

	var requestData VerifyGetAuthTokenRequest
	if err := render.DecodeJSON(r.Body, &requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	var responseData VerifyGetAuthTokenResponse

	verification, err := ac.datastore.GetVerificationStatus(r.Context(), verificationID, requestData.Wait)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}
	if !verification.Verified {
		render.Status(r, http.StatusOK)
		render.JSON(w, r, responseData)
		return
	}

	if err = ac.datastore.DeleteVerification(verificationID); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	account, err := ac.datastore.GetOrCreateAccount(verification.Email)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	session, err := ac.datastore.CreateSession(account.ID, nil)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	authToken, err := ac.jwtUtil.CreateAuthToken(session.ID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	response := VerifyGetAuthTokenResponse{
		AuthToken: &authToken,
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// @Summary Validate auth token
// @Description Validates an auth token and returns session details
// @Tags Auth
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Success 200 {object} ValidateTokenResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/auth/validate [get]
func (ac *AuthController) Validate(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.Session)

	response := ValidateTokenResponse{
		Email:     session.Account.Email,
		AccountID: session.AccountID.String(),
		SessionID: session.ID.String(),
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}
