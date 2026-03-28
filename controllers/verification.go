package controllers

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"slices"
	"time"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/templates"
	"github.com/brave/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/rs/zerolog/log"
)

const (
	localStackSESEndpoint = "http://localhost:4566/_aws/ses"
	maxEmailAttempts      = 4
)

type VerificationController struct {
	datastore           *datastore.Datastore
	verificationService *services.VerificationService
}

// @Description	Request to initialize email verification
type VerifyInitRequest struct {
	// Email address to verify
	Email string `json:"email" validate:"required,email,ascii" example:"test@example.com"`
	// Purpose of verification (e.g., get auth token, simple verification)
	Intent string `json:"intent" validate:"required,oneof=auth_token verification reset_password change_password" example:"reset_password"`
	// Service requesting the verification
	Service string `json:"service" validate:"required,oneof=accounts premium email-aliases" example:"accounts"`
	// Locale for verification email
	Locale string `json:"locale" validate:"max=20" example:"en-US"`
}

// @Description	Response containing verification check token
type VerifyInitResponse struct {
	// JWT token for checking verification status
	VerificationToken *string `json:"verificationToken"`
	// Expiry timestamp of the verification token
	VerificationTokenExpiresAt time.Time `json:"verificationTokenExpiresAt"`
}

// @Description	Response containing auth token
type VerifyCompleteResponse struct {
	// JWT auth token, null if verification incomplete or if password setup is required
	AuthToken *string `json:"authToken"`
	// Email associated with the verification
	Email *string `json:"email,omitempty"`
	// Name of service requesting verification
	Service string `json:"service"`
}

// @Description Request body for verification completion
type VerifyCompleteRequest struct {
	// 6-character base32 verification code
	Code string `json:"code" validate:"required,min=6,max=10"`
}

// @Description Request for resending verification email
type VerifyResendRequest struct {
	// Locale for verification email
	Locale string `json:"locale" validate:"max=20" example:"en-US"`
}

// @Description Response containing the result of a verification
type VerifyResultResponse struct {
	// Whether the email has been verified
	Verified bool `json:"verified"`
	// Email associated with the verification
	Email string `json:"email"`
	// Name of service requesting verification
	Service string `json:"service"`
}

type localStackEmails struct {
	Messages []interface{} `json:"messages"`
}

func NewVerificationController(datastore *datastore.Datastore, verificationService *services.VerificationService) *VerificationController {
	return &VerificationController{
		datastore:           datastore,
		verificationService: verificationService,
	}
}

func (vc *VerificationController) Router(verificationAuthMiddleware func(http.Handler) http.Handler, servicesKeyMiddleware func(http.Handler) http.Handler, optionalAuthMiddleware func(http.Handler) http.Handler, devEndpointsEnabled bool) chi.Router {
	r := chi.NewRouter()

	r.With(servicesKeyMiddleware).With(optionalAuthMiddleware).Post("/init", vc.VerifyInit)
	r.With(servicesKeyMiddleware).With(verificationAuthMiddleware).Post("/complete", vc.VerifyComplete)
	r.With(servicesKeyMiddleware).With(verificationAuthMiddleware).Get("/result", vc.VerifyResult)
	if devEndpointsEnabled {
		r.Get("/email_viewer", vc.EmailViewer)
	}
	r.With(servicesKeyMiddleware).With(verificationAuthMiddleware).Post("/resend", vc.VerifyResend)
	r.With(servicesKeyMiddleware).With(verificationAuthMiddleware).Delete("/", vc.VerifyDelete)

	return r
}

// @Summary Initialize email verification
// @Description Starts email verification process by sending a verification email
// @Description One of the following intents must be provided with the request:
// @Description - `auth_token`: After verification, create an account if one does not exist, and generate an auth token. The token will be available via the "query result" endpoint.
// @Description - `verification`: After verification, do not create an account, but indicate that the email was verified in the "query result" response. Do not allow registration after verification.
// @Description - `reset_password`: After verification, indicate that the email was verified in the "query result" response. A password may be set for the existing account.
// @Description - `change_password`: After verification, indicate that the email was verified in the "query result" response. A password may be changed for the existing account. Requires a valid auth session.
// @Description
// @Description One of the following service names must be provided with the request: `email-aliases`, `accounts`, `premium`.
// @Tags Email verification
// @Accept json
// @Produce json
// @Param Authorization header string false "Bearer + auth token (required for change_password intent)"
// @Param BraveServiceKey header string false "Brave services key (if one is configured)"
// @Param request body VerifyInitRequest true "Verification request params"
// @Success 200 {object} VerifyInitResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/verify/init [post]
func (vc *VerificationController) VerifyInit(w http.ResponseWriter, r *http.Request) {
	session, _ := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)
	var requestData VerifyInitRequest
	if !util.DecodeJSONAndValidate(w, r, &requestData) {
		return
	}

	locale := util.GetRequestLocale(requestData.Locale, r)

	// Initialize verification
	verification, verificationToken, err := vc.verificationService.InitializeVerification(
		r.Context(),
		requestData.Email,
		requestData.Intent,
		requestData.Service,
		session,
	)

	if err != nil {
		if errors.Is(err, util.ErrTooManyVerifications) ||
			errors.Is(err, util.ErrIntentNotAllowed) ||
			errors.Is(err, util.ErrEmailDomainNotSupported) ||
			errors.Is(err, util.ErrAccountExists) ||
			errors.Is(err, util.ErrAccountDoesNotExist) {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	// Send verification email
	if err := vc.verificationService.SendVerificationEmail(r.Context(), verification, locale); err != nil {
		if errors.Is(err, util.ErrFailedToSendEmailInvalidFormat) {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, &VerifyInitResponse{
		VerificationToken:          verificationToken,
		VerificationTokenExpiresAt: time.Now().Add(datastore.VerificationExpiration),
	})
}

// @Summary Delete verification for registration
// @Description Deletes a pending verification.
// @Description Also deletes any unverified account associated with the verification email.
// @Tags Email verification
// @Param Authorization header string true "Bearer + verification token"
// @Param BraveServiceKey header string false "Brave services key (if one is configured)"
// @Success 204 "Verification deleted successfully"
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/verify [delete]
func (vc *VerificationController) VerifyDelete(w http.ResponseWriter, r *http.Request) {
	verification := r.Context().Value(middleware.ContextVerification).(*datastore.Verification)

	// Accounts is the sole service that can create verifications with a registration intent
	if verification.Intent != datastore.RegistrationIntent || verification.Service != util.AccountsServiceName {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, util.ErrIntentNotAllowed)
		return
	}

	if verification.Verified {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, util.ErrEmailAlreadyVerified)
		return
	}

	if err := vc.datastore.DeleteVerification(verification.ID); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	if err := vc.datastore.DeleteAccountIfUnverified(verification.Email); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// @Summary Complete email verification
// @Description Completes the email verification process
// @Tags Email verification
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + verification token"
// @Param BraveServiceKey header string false "Brave services key (if one is configured)"
// @Param request body VerifyCompleteRequest true "Verify completion params"
// @Success 200 {object} VerifyCompleteResponse
// @Failure 400 {object} util.ErrorResponse "Missing/invalid verification parameters"
// @Failure 404 {object} util.ErrorResponse "Verification not found"
// @Failure 500 {object} util.ErrorResponse "Internal server error"
// @Router /v2/verify/complete [post]
func (vc *VerificationController) VerifyComplete(w http.ResponseWriter, r *http.Request) {
	verification := r.Context().Value(middleware.ContextVerification).(*datastore.Verification)

	var requestData VerifyCompleteRequest
	if !util.DecodeJSONAndValidate(w, r, &requestData) {
		return
	}

	result, err := vc.verificationService.CompleteVerification(verification, requestData.Code, r.UserAgent())

	if err != nil {
		if errors.Is(err, util.ErrMaxCodeAttempts) || errors.Is(err, util.ErrInvalidCode) || errors.Is(err, util.ErrEmailAlreadyVerified) {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
			return
		}
		log.Err(err).Msg("failed to complete verification")
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, VerifyCompleteResponse{
		AuthToken: result.AuthToken,
		Email:     result.Email,
		Service:   result.Service,
	})
}

// @Summary Query result of verification
// @Description Returns the current verification status and associated details
// @Tags Email verification
// @Produce json
// @Param Authorization header string true "Bearer + verification token"
// @Param BraveServiceKey header string false "Brave services key (if one is configured)"
// @Success 200 {object} VerifyResultResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 404 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/verify/result [get]
func (vc *VerificationController) VerifyResult(w http.ResponseWriter, r *http.Request) {
	verification := r.Context().Value(middleware.ContextVerification).(*datastore.Verification)

	render.Status(r, http.StatusOK)
	render.JSON(w, r, VerifyResultResponse{
		Verified: verification.Verified,
		Email:    verification.Email,
		Service:  verification.Service,
	})
}

// @Summary View sent emails in LocalStack SES
// @Description Retrieves and displays emails sent through LocalStack SES endpoint
// @Tags Development
// @Produce html
// @Success 200 {string} string "HTML page displaying emails"
// @Failure 500 {object} util.ErrorResponse "Internal Server Error"
// @Router /v2/verify/email_viewer [get]
func (vc *VerificationController) EmailViewer(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(localStackSESEndpoint)
	if err != nil {
		http.Error(w, "Failed to fetch emails", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	var data localStackEmails
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		http.Error(w, "Failed to parse email data", http.StatusInternalServerError)
		return
	}

	slices.Reverse(data.Messages)

	tmpl, err := template.New("email_viewer").Parse(templates.EmailViewerTemplateContent)
	if err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
		return
	}

	var bodyContent bytes.Buffer
	if err := tmpl.Execute(&bodyContent, data); err != nil {
		http.Error(w, "Failed to execute template", http.StatusInternalServerError)
	}

	render.HTML(w, r, bodyContent.String())
}

// @Summary Resend verification email
// @Description Resends the verification email for a pending verification
// @Tags Email verification
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + verification token"
// @Param BraveServiceKey header string false "Brave services key (if one is configured)"
// @Param request body VerifyResendRequest true "Resend request params"
// @Success 204 "Email resent successfully"
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/verify/resend [post]
func (vc *VerificationController) VerifyResend(w http.ResponseWriter, r *http.Request) {
	verification := r.Context().Value(middleware.ContextVerification).(*datastore.Verification)

	var requestData VerifyResendRequest
	if !util.DecodeJSONAndValidate(w, r, &requestData) {
		return
	}

	if verification.Verified {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, util.ErrEmailAlreadyVerified)
		return
	}

	if verification.EmailAttempts >= maxEmailAttempts {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, util.ErrMaxEmailAttempts)
		return
	}

	if err := vc.datastore.IncrementVerificationEmailAttempts(verification.ID); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	locale := util.GetRequestLocale(requestData.Locale, r)
	if err := vc.verificationService.SendVerificationEmail(r.Context(), verification, locale); err != nil {
		_ = vc.datastore.DecrementVerificationEmailAttempts(verification.ID)

		if errors.Is(err, util.ErrFailedToSendEmailInvalidFormat) {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
