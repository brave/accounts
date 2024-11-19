package controllers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/middleware"
	"github.com/brave-experiments/accounts/services"
	"github.com/brave-experiments/accounts/templates"
	"github.com/brave-experiments/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	accountsServiceName     = "accounts"
	premiumServiceName      = "premium"
	inboxAliasesServiceName = "inbox-aliases"

	localStackSESEndpoint = "http://localhost:4566/_aws/ses"
)

type VerificationController struct {
	datastore           *datastore.Datastore
	jwtService          *services.JWTService
	sesService          services.SES
	passwordAuthEnabled bool
	emailAuthDisabled   bool
}

// @Description	Request to initialize email verification
type VerifyInitRequest struct {
	// Email address to verify
	Email string `json:"email" validate:"required,email,ascii" example:"test@example.com"`
	// Purpose of verification (e.g., get auth token, simple verification, registration)
	Intent string `json:"intent" validate:"required,oneof=auth_token verification registration set_password" example:"registration"`
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
	// Name of service requesting verification
	Service string `json:"service"`
}

// @Description Request parameters for verification completion
type VerifyCompleteRequest struct {
	// Unique verification identifier
	ID uuid.UUID `json:"id" validate:"required"`
	// Verification code sent to user
	Code string `json:"code" validate:"required"`
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

func NewVerificationController(datastore *datastore.Datastore, jwtService *services.JWTService, sesService services.SES, passwordAuthEnabled bool, emailAuthDisabled bool) *VerificationController {
	return &VerificationController{
		datastore:           datastore,
		jwtService:          jwtService,
		sesService:          sesService,
		passwordAuthEnabled: passwordAuthEnabled,
		emailAuthDisabled:   emailAuthDisabled,
	}
}

func (vc *VerificationController) Router(verificationAuthMiddleware func(http.Handler) http.Handler, servicesKeyMiddleware func(http.Handler) http.Handler, devEndpointsEnabled bool) chi.Router {
	r := chi.NewRouter()

	r.With(servicesKeyMiddleware).Post("/init", vc.VerifyInit)
	r.Post("/complete", vc.VerifyComplete)
	if devEndpointsEnabled {
		r.Get("/complete_fe", vc.VerifyCompleteFrontend)
		r.Get("/email_viewer", vc.EmailViewer)
	}
	r.With(servicesKeyMiddleware).With(verificationAuthMiddleware).Post("/result", vc.VerifyQueryResult)

	return r
}

func (vc *VerificationController) maybeCreateVerificationToken(verification *datastore.Verification, isCompletion bool) (*string, error) {
	// Do not generate verification token immediately for Premium verifications
	// We'll create it later in the completion endpoint, so it can be passed to the Premium site upon redirect
	shouldCreateOnCompletion := verification.Service == premiumServiceName && verification.Intent == datastore.VerificationIntent
	if shouldCreateOnCompletion != isCompletion {
		return nil, nil
	}
	token, err := vc.jwtService.CreateVerificationToken(verification.ID, datastore.VerificationExpiration, verification.Service)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// @Summary Initialize email verification
// @Description Starts email verification process by sending a verification email
// @Description One of the following intents must be provided with the request:
// @Description - `auth_token`: After verification, create an account if one does not exist, and generate an auth token. The token will be available via the "query result" endpoint.
// @Description - `verification`: After verification, do not create an account, but indicate that the email was verified in the "query result" response. Do not allow registration after verification.
// @Description - `registration`: After verification, indicate that the email was verified in the "query result" response. An account may be created by setting a password.
// @Description - `set_password`: After verification, indicate that the email was verified in the "query result" response. A password may be set for the existing account.
// @Description
// @Description One of the following service names must be provided with the request: `inbox-aliases`, `accounts`, `premium`.
// @Tags Email verification
// @Accept json
// @Produce json
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Param request body VerifyInitRequest true "Verification request params"
// @Success 200 {object} VerifyInitResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/verify/init [post]
func (vc *VerificationController) VerifyInit(w http.ResponseWriter, r *http.Request) {
	var requestData VerifyInitRequest
	if !util.DecodeJSONAndValidate(w, r, &requestData) {
		return
	}

	intentAllowed := true
	switch requestData.Intent {
	case datastore.AuthTokenIntent:
		if vc.emailAuthDisabled || requestData.Service != inboxAliasesServiceName {
			intentAllowed = false
		}
	case datastore.VerificationIntent:
		if requestData.Service != inboxAliasesServiceName && requestData.Service != premiumServiceName {
			intentAllowed = false
		}
	case datastore.RegistrationIntent, datastore.SetPasswordIntent:
		if !vc.passwordAuthEnabled || requestData.Service != accountsServiceName {
			intentAllowed = false
		}
	default:
		intentAllowed = false
	}
	if !intentAllowed {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, util.ErrIntentNotAllowed)
		return
	}

	if requestData.Intent == datastore.RegistrationIntent || requestData.Intent == datastore.SetPasswordIntent {
		accountExists, err := vc.datastore.AccountExists(requestData.Email)
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}
		if requestData.Intent == datastore.RegistrationIntent && accountExists {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, util.ErrAccountExists)
			return
		}
		if requestData.Intent == datastore.SetPasswordIntent && !accountExists {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, util.ErrAccountDoesNotExist)
			return
		}
	}

	verification, err := vc.datastore.CreateVerification(requestData.Email, requestData.Service, requestData.Intent)
	if err != nil {
		if errors.Is(err, util.ErrTooManyVerifications) {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	verificationToken, err := vc.maybeCreateVerificationToken(verification, false)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	if err := vc.sesService.SendVerificationEmail(
		r.Context(),
		requestData.Email,
		verification,
		requestData.Locale,
	); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, fmt.Errorf("failed to send verification email: %w", err))
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, &VerifyInitResponse{
		VerificationToken: verificationToken,
	})
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

	// Update verification status
	verification, err := vc.datastore.UpdateAndGetVerificationStatus(requestData.ID, requestData.Code)
	if err != nil {
		if errors.Is(err, util.ErrVerificationNotFound) {
			util.RenderErrorResponse(w, r, http.StatusNotFound, err)
			return
		}
		log.Err(err).Msg("failed to update verification status")
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	verificationToken, err := vc.maybeCreateVerificationToken(verification, true)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, &VerifyCompleteResponse{
		VerificationToken: verificationToken,
		Service:           verification.Service,
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

	responseData := VerifyResultResponse{
		Email:   verification.Email,
		Service: verification.Service,
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
	if verification.Intent == datastore.AuthTokenIntent {
		if err := vc.datastore.DeleteVerification(verification.ID); err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}

		account, err := vc.datastore.GetOrCreateAccount(verification.Email)
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}

		session, err := vc.datastore.CreateSession(account.ID, datastore.EmailAuthSessionVersion, r.UserAgent())
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}

		authTokenResult, err := vc.jwtService.CreateAuthToken(session.ID)
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
	defer resp.Body.Close()

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
