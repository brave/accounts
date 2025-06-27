package controllers

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"slices"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/templates"
	"github.com/brave/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	localStackSESEndpoint = "http://localhost:4566/_aws/ses"
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
	Locale string `json:"locale" validate:"max=8" example:"en-US"`
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
	Email *string `json:"email,omitempty"`
	// Name of service requesting verification
	Service string `json:"service"`
}

// @Description Request parameters for verification completion
type VerifyCompleteRequest struct {
	// Unique verification identifier
	ID uuid.UUID `json:"id" validate:"required"`
	// Verification code sent to user
	Code string `json:"code" validate:"required,ascii"`
}

// @Description Response for verification completion
type VerifyCompleteResponse struct {
	// JWT token for checking verification status
	VerificationToken *string `json:"verificationToken"`
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
	r.Get("/complete", vc.VerifyValidCheck)
	r.Post("/complete", vc.VerifyComplete)
	if devEndpointsEnabled {
		r.Get("/complete_fe", vc.VerifyCompleteFrontend)
		r.Get("/email_viewer", vc.EmailViewer)
	}
	r.With(servicesKeyMiddleware).With(verificationAuthMiddleware).Post("/result", vc.VerifyQueryResult)

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
// @Param Brave-Key header string false "Brave services key (if one is configured)"
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

	if requestData.Locale == "" {
		requestData.Locale = r.Header.Get("Accept-Language")
	}

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
	if err := vc.verificationService.SendVerificationEmail(r.Context(), verification, requestData.Locale); err != nil {
		if errors.Is(err, util.ErrFailedToSendEmailInvalidFormat) {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, &VerifyInitResponse{
		VerificationToken: verificationToken,
	})
}

// @Summary Check verification code validity
// @Description Checks if email verification code is valid and still pending
// @Tags Email verification
// @Accept json
// @Produce json
// @Param id query string true "Verification ID"
// @Param code query string true "Verification code"
// @Success 204 "Verification is pending"
// @Failure 400 {string} string "Missing/invalid verification parameters"
// @Failure 404 {string} string "Verification not found or expired"
// @Failure 500 {string} string "Internal server error"
// @Router /v2/verify/complete [get]
func (vc *VerificationController) VerifyValidCheck(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, errors.New("invalid verification id"))
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, errors.New("missing verification code"))
		return
	}

	err = vc.datastore.EnsureVerificationCodeIsPending(id, code)
	if err != nil {
		if errors.Is(err, util.ErrVerificationNotFound) {
			util.RenderErrorResponse(w, r, http.StatusNotFound, err)
			return
		}
		log.Err(err).Msg("failed to check verification status")
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
// @Param request body VerifyCompleteRequest true "Verify completion params"
// @Success 200 {object} VerifyCompleteResponse
// @Failure 400 {string} string "Missing/invalid verification parameters"
// @Failure 404 {string} string "Verification not found"
// @Failure 500 {string} string "Internal server error"
// @Router /v2/verify/complete [post]
func (vc *VerificationController) VerifyComplete(w http.ResponseWriter, r *http.Request) {
	var requestData VerifyCompleteRequest
	if !util.DecodeJSONAndValidate(w, r, &requestData) {
		return
	}

	result, err := vc.verificationService.CompleteVerification(requestData.ID, requestData.Code)

	if err != nil {
		if errors.Is(err, util.ErrVerificationNotFound) {
			util.RenderErrorResponse(w, r, http.StatusNotFound, err)
			return
		}
		log.Err(err).Msg("failed to update verification status")
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, &VerifyCompleteResponse{
		VerificationToken: result.VerificationToken,
		Service:           result.Verification.Service,
	})
}

// @Summary Query result of verification
// @Description Provides the status of a pending or successful verification.
// @Description If the wait option is set to true, the server will up to 20 seconds for verification. Feel free
// @Description to call this endpoint repeatedly to wait for verification.
// @Tags Email verification
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + verification token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
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

	// Delegate to service
	result, err := vc.verificationService.GetVerificationResult(
		r.Context(),
		verification,
		requestData.Wait,
		r.UserAgent(),
	)

	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, VerifyResultResponse{
		AuthToken: result.AuthToken,
		Verified:  result.Verified,
		Email:     result.Email,
		Service:   result.Service,
	})
}

// @Summary Display default verification completion frontend
// @Description Returns the HTML page for completing email verification
// @Tags Development
// @Produce html
// @Success 200 {string} string "HTML content"
// @Router /v2/verify/complete_fe [get]
func (vc *VerificationController) VerifyCompleteFrontend(w http.ResponseWriter, r *http.Request) {
	render.HTML(w, r, templates.DefaultVerifyFrontendContent)
}

// @Summary View sent emails in LocalStack SES
// @Description Retrieves and displays emails sent through LocalStack SES endpoint
// @Tags Development
// @Produce html
// @Success 200 {string} string "HTML page displaying emails"
// @Failure 500 {string} string "Internal Server Error"
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
