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

type VerificationController struct {
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

func NewVerificationController(datastore *datastore.Datastore, jwtUtil *util.JWTUtil, sesUtil *util.SESUtil) *VerificationController {
	return &VerificationController{
		datastore: datastore,
		validate:  validator.New(validator.WithRequiredStructEnabled()),
		jwtUtil:   jwtUtil,
		sesUtil:   sesUtil,
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

	verification, err := vc.datastore.CreateVerification(requestData.Email)
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

	// Update verification status
	err = vc.datastore.UpdateVerificationStatus(id, verifyToken)
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

// @Summary Query result of verification
// @Description Exchanges a verify check token for an auth token after successful verification.
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

	if err := vc.datastore.DeleteVerification(verification.ID); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	account, err := vc.datastore.GetOrCreateAccount(verification.Email)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	session, err := vc.datastore.CreateSession(account.ID, nil)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	authToken, err := vc.jwtUtil.CreateAuthToken(session.ID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	response := VerifyResultResponse{
		AuthToken: &authToken,
		Verified:  true,
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}
