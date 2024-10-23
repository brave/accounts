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
	urlParamVerifyID    = "verify_id"
	urlParamVerifyToken = "verify_token"
)

type AuthController struct {
	datastore *datastore.Datastore
	validate  *validator.Validate
	jwtUtil   *util.JWTUtil
	sesUtil   *util.SESUtil
}

type VerifyInitRequest struct {
	Email       string  `validate:"required,email,ascii"`
	SessionName *string `validate:"omitempty,max=35,ascii"`
}

type VerifyInitResponse struct {
	VerifyCheckToken string
}

type VerifyGetAuthTokenRequest struct {
	Wait bool
}

type VerifyGetAuthTokenResponse struct {
	AuthToken *string
}

type ValidateTokenResponse struct {
	Email     string
	AccountID string
	SessionID string
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
	r.With(authMiddleware).Post("/validate", ac.Validate)

	return r
}

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

	verification, err := ac.datastore.CreateVerification(requestData.Email, requestData.SessionName)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	verifyCheckToken, err := ac.jwtUtil.CreateVerifyCheckToken(verification.ID, datastore.VerificationExpiration)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	if err := ac.sesUtil.SendVerificationEmail(
		r.Context(),
		requestData.Email,
		requestData.SessionName,
		verification.ID.String(),
		verifyCheckToken,
	); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, fmt.Errorf("failed to send verification email: %w", err))
		return
	}

	response := VerifyInitResponse{
		VerifyCheckToken: verifyCheckToken,
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

func (ac *AuthController) VerifyComplete(w http.ResponseWriter, r *http.Request) {
	verifyID := chi.URLParam(r, urlParamVerifyID)
	verifyToken := chi.URLParam(r, urlParamVerifyToken)

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

func (ac *AuthController) VerifyGetAuthToken(w http.ResponseWriter, r *http.Request) {
	// Extract and validate token
	tokenString, err := util.ExtractAuthToken(r)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
		return
	}

	verificationID, err := ac.jwtUtil.ValidateVerifyCheckToken(tokenString)
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

	session, err := ac.datastore.CreateSession(account.ID, verification.SessionName)
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
