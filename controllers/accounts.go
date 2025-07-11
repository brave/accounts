package controllers

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	opaqueMsg "github.com/bytemare/opaque/message"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
)

type AccountsController struct {
	opaqueService       *services.OpaqueService
	jwtService          *services.JWTService
	twoFAService        *services.TwoFAService
	ds                  *datastore.Datastore
	verificationService *services.VerificationService
}

// @Description Response for password setup or change
type PasswordFinalizeResponse struct {
	// Authentication token (only present if resetting/changing password)
	AuthToken *string `json:"authToken"`
	// Indicates to the client whether 2FA verification will be required before password setup is complete
	RequiresTwoFA bool `json:"requiresTwoFA"`
	// Indicates to the client whether email verification will be required before password setup is complete
	RequiresEmailVerification bool `json:"requiresEmailVerification"`
}

// @Description Request to register a new account
type RegistrationRequest struct {
	// Serialized OPAQUE registration request
	BlindedMessage string `json:"blindedMessage" validate:"required"`
	// Whether to serialize the response into binary/hex
	SerializeResponse bool `json:"serializeResponse"`
	// Email for new account creation (required if no verification token)
	NewAccountEmail *string `json:"newAccountEmail" validate:"omitempty,email"`
}

// @Description Response for registering a new account
type RegistrationResponse struct {
	// Evaluated message of the OPAQUE registration response
	EvaluatedMessage *string `json:"evaluatedMessage,omitempty"`
	// PKS of the OPAQUE registration response
	Pks *string `json:"pks,omitempty"`
	// Serialized OPAQUE registration response
	SerializedResponse *string `json:"serializedResponse,omitempty"`
	// JWT token for checking verification status (only present when registering a new account)
	VerificationToken *string `json:"verificationToken,omitempty"`
}

// @Description OPAQUE registration record for a new account
type RegistrationRecord struct {
	// Public key of registation record
	PublicKey *string `json:"publicKey" validate:"required_without=SerializedRecord"`
	// Masking key of registation record
	MaskingKey *string `json:"maskingKey" validate:"required_without=SerializedRecord"`
	// Envelope of registation record
	Envelope *string `json:"envelope" validate:"required_without=SerializedRecord"`
	// Serialized registration record
	SerializedRecord *string `json:"serializedRecord" validate:"required_without_all=PublicKey MaskingKey Envelope"`
	// Locale for verification email (optional, falls back to Accept-Language header)
	Locale string `json:"locale" validate:"max=8" example:"en-US"`
}

// @Description Request to initialize 2FA setup
type TwoFAInitRequest struct {
	// Whether to generate a QR code
	GenerateQR bool `json:"generateQR"`
}

// @Description Response for 2FA initialization
type TwoFAInitResponse struct {
	// TOTP URI for manual entry
	URI string `json:"uri"`
	// QR code as base64 encoded PNG (only if requested)
	QRCode *string `json:"qrCode,omitempty"`
}

// @Description Request to finalize 2FA setup
type TwoFAFinalizeRequest struct {
	// TOTP verification code
	Code string `json:"code" validate:"required,len=6"`
}

// @Description Response for finalized 2FA setup
type TwoFAFinalizeResponse struct {
	// Recovery key for 2FA backup, only present when first enabling 2FA
	RecoveryKey *string `json:"recoveryKey"`
}

// @Description Response for recovery key operations
type RecoveryKeyResponse struct {
	// Secret key for disabling 2FA in the event the authenticator is lost
	RecoveryKey string `json:"recoveryKey"`
}

func (req *RegistrationRequest) ToOpaqueRequest(opaqueService *services.OpaqueService) (*opaqueMsg.RegistrationRequest, error) {
	blindedMessage, err := hex.DecodeString(req.BlindedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode blinded message: %w", err)
	}
	blindedMessageElement := opaqueService.NewElement()
	if err = blindedMessageElement.UnmarshalBinary(blindedMessage); err != nil {
		return nil, fmt.Errorf("failed to decode blinded message to element: %w", err)
	}

	return &opaqueMsg.RegistrationRequest{
		BlindedMessage: blindedMessageElement,
	}, nil
}

func (rec *RegistrationRecord) ToOpaqueRecord(opaqueService *services.OpaqueService) (*opaqueMsg.RegistrationRecord, error) {
	if rec.SerializedRecord != nil {
		serializedBin, err := hex.DecodeString(*rec.SerializedRecord)
		if err != nil {
			return nil, fmt.Errorf("failed to decode serialized record hex: %w", err)
		}
		deserializer, err := opaqueService.BinaryDeserializer()
		if err != nil {
			return nil, err
		}
		opaqueRec, err := deserializer.RegistrationRecord(serializedBin)
		if err != nil {
			return nil, err
		}
		return opaqueRec, nil
	}
	publicKey, err := hex.DecodeString(*rec.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	publicKeyElement := opaqueService.NewElement()
	if err = publicKeyElement.UnmarshalBinary(publicKey); err != nil {
		return nil, fmt.Errorf("failed to decode public key to element: %w", err)
	}

	maskingKey, err := hex.DecodeString(*rec.MaskingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode masking key: %w", err)
	}

	envelope, err := hex.DecodeString(*rec.Envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to decode envelope: %w", err)
	}

	return &opaqueMsg.RegistrationRecord{
		PublicKey:  publicKeyElement,
		MaskingKey: maskingKey,
		Envelope:   envelope,
	}, nil
}

func FromOpaqueRegistrationResponse(opaqueResp *opaqueMsg.RegistrationResponse, useBinary bool) (*RegistrationResponse, error) {
	if useBinary {
		serializedBin := hex.EncodeToString(opaqueResp.Serialize())
		return &RegistrationResponse{
			SerializedResponse: &serializedBin,
		}, nil
	}
	evalMsgBin, err := opaqueResp.EvaluatedMessage.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize evaluated message: %w", err)
	}
	pksBin, err := opaqueResp.Pks.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize pks: %w", err)
	}
	evalMsg := hex.EncodeToString(evalMsgBin)
	pks := hex.EncodeToString(pksBin)

	return &RegistrationResponse{
		EvaluatedMessage: &evalMsg,
		Pks:              &pks,
	}, nil
}

func NewAccountsController(opaqueService *services.OpaqueService, jwtService *services.JWTService, twoFAService *services.TwoFAService, ds *datastore.Datastore, verificationService *services.VerificationService) *AccountsController {
	return &AccountsController{
		opaqueService:       opaqueService,
		jwtService:          jwtService,
		twoFAService:        twoFAService,
		ds:                  ds,
		verificationService: verificationService,
	}
}

func (ac *AccountsController) Router(verificationMiddleware func(http.Handler) http.Handler, optionalVerificationMiddleware func(http.Handler) http.Handler, authMiddleware func(http.Handler) http.Handler, accountDeletionEnabled bool) chi.Router {
	r := chi.NewRouter()

	r.With(optionalVerificationMiddleware).Post("/password/init", ac.SetupPasswordInit)
	r.With(verificationMiddleware).Post("/password/finalize", ac.SetupPasswordFinalize)
	r.With(verificationMiddleware).Post("/password/finalize_2fa", ac.SetupPasswordFinalize2FA)
	r.With(authMiddleware).Get("/2fa", ac.GetTwoFASettings)
	r.With(authMiddleware).Post("/2fa/totp/init", ac.SetupTOTPInit)
	r.With(authMiddleware).Post("/2fa/totp/finalize", ac.SetupTOTPFinalize)
	r.With(authMiddleware).Delete("/2fa/totp", ac.DisableTOTP)
	r.With(authMiddleware).Post("/2fa/recovery", ac.RegenerateRecoveryKey)
	r.With(authMiddleware).Delete("/2fa/recovery", ac.DeleteRecoveryKey)
	if accountDeletionEnabled {
		r.With(authMiddleware).Delete("/", ac.DeleteAccount)
	}

	return r
}

func checkVerificationStatusAndIntent(w http.ResponseWriter, r *http.Request, verification *datastore.Verification) bool {
	if verification.Intent == datastore.SetPasswordIntent && !verification.Verified {
		util.RenderErrorResponse(w, r, http.StatusForbidden, util.ErrEmailNotVerified)
		return false
	}

	if verification.Intent != datastore.RegistrationIntent && verification.Intent != datastore.SetPasswordIntent {
		util.RenderErrorResponse(w, r, http.StatusForbidden, util.ErrIncorrectVerificationIntent)
		return false
	}
	return true
}

// @Summary Initialize password setup
// @Description Start the password setup process using OPAQUE protocol.
// @Description If `serializeResponse` is set to true, the `serializedResponse` field will be populated
// @Description in the response, with other fields omitted.
// @Description Either provide a verification token for resetting/changing password OR include `newAccountEmail` for new account creation.
// @Tags Accounts
// @Accept json
// @Produce json
// @Param Authorization header string false "Bearer + verification token (optional if newAccountEmail is provided)"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Param request body RegistrationRequest true "Registration request"
// @Success 200 {object} RegistrationResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 403 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/password/init [post]
func (ac *AccountsController) SetupPasswordInit(w http.ResponseWriter, r *http.Request) {
	verification, _ := r.Context().Value(middleware.ContextVerification).(*datastore.Verification)

	var requestData RegistrationRequest
	if !util.DecodeJSONAndValidate(w, r, &requestData) {
		return
	}

	var verificationToken *string
	if verification != nil {
		// If verification is present, check its status and intent
		if !checkVerificationStatusAndIntent(w, r, verification) {
			return
		}
	} else {
		// No verification token provided, check for newAccountEmail
		if requestData.NewAccountEmail == nil || *requestData.NewAccountEmail == "" {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, util.ErrNewAccountEmailRequired)
			return
		}

		var err error
		// Create a new verification for registration
		verification, verificationToken, err = ac.verificationService.InitializeVerification(
			r.Context(),
			*requestData.NewAccountEmail,
			datastore.RegistrationIntent,
			util.AccountsServiceName,
		)
		if err != nil {
			if errors.Is(err, util.ErrTooManyVerifications) ||
				errors.Is(err, util.ErrIntentNotAllowed) ||
				errors.Is(err, util.ErrEmailDomainNotSupported) ||
				errors.Is(err, util.ErrAccountExists) ||
				errors.Is(err, util.ErrAccountDoesNotExist) ||
				errors.Is(err, util.ErrNewAccountEmailRequired) {
				util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
				return
			}
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}
	}

	opaqueReq, err := requestData.ToOpaqueRequest(ac.opaqueService)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	opaqueResponse, err := ac.opaqueService.SetupPasswordInit(verification.Email, opaqueReq)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	response, err := FromOpaqueRegistrationResponse(opaqueResponse, requestData.SerializeResponse)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	// Include verification token if a new verification was created
	response.VerificationToken = verificationToken

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

func (ac *AccountsController) createSessionAfterPasswordSetup(accountID uuid.UUID, userAgent string, verificationID uuid.UUID) (string, error) {
	if err := ac.ds.DeleteAllSessions(accountID); err != nil {
		return "", fmt.Errorf("failed to delete existing sessions: %w", err)
	}

	session, err := ac.ds.CreateSession(accountID, datastore.PasswordAuthSessionVersion, userAgent)
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	authToken, err := ac.jwtService.CreateAuthToken(session.ID, nil, util.AccountsServiceName)
	if err != nil {
		return "", fmt.Errorf("failed to create auth token: %w", err)
	}

	if err := ac.ds.DeleteVerification(verificationID); err != nil {
		return "", fmt.Errorf("failed to delete verification: %w", err)
	}

	return authToken, nil
}

// @Summary Finalize password setup
// @Description Complete the password setup process and return auth token.
// @Description Either `publicKey`, `maskingKey` and `envelope` must be provided together,
// @Description or `serializedRecord` must be provided.
// @Tags Accounts
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + verification token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Param request body RegistrationRecord true "Registration record"
// @Success 200 {object} PasswordFinalizeResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 403 {object} util.ErrorResponse
// @Failure 404 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/password/finalize [post]
func (ac *AccountsController) SetupPasswordFinalize(w http.ResponseWriter, r *http.Request) {
	verification := r.Context().Value(middleware.ContextVerification).(*datastore.Verification)

	if !checkVerificationStatusAndIntent(w, r, verification) {
		return
	}

	var requestData RegistrationRecord
	if !util.DecodeJSONAndValidate(w, r, &requestData) {
		return
	}

	opaqueRecord, err := requestData.ToOpaqueRecord(ac.opaqueService)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	registrationState, err := ac.opaqueService.SetupPasswordFinalize(verification.Email, opaqueRecord)
	if err != nil {
		switch {
		case errors.Is(err, util.ErrInterimPasswordStateNotFound):
			util.RenderErrorResponse(w, r, http.StatusNotFound, err)
		case errors.Is(err, util.ErrInterimPasswordStateExpired):
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		default:
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		}
		return
	}

	var authToken *string
	if !registrationState.RequiresTwoFA && verification.Intent != datastore.RegistrationIntent {
		newAuthToken, err := ac.createSessionAfterPasswordSetup(*registrationState.AccountID, r.UserAgent(), verification.ID)
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}
		authToken = &newAuthToken
	}

	// Send verification email if this is a registration intent
	if verification.Intent == datastore.RegistrationIntent {
		locale := requestData.Locale
		if locale == "" {
			locale = r.Header.Get("Accept-Language")
		}
		if err := ac.verificationService.SendVerificationEmail(r.Context(), verification, locale); err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, &PasswordFinalizeResponse{
		AuthToken:                 authToken,
		RequiresTwoFA:             registrationState.RequiresTwoFA,
		RequiresEmailVerification: verification.Intent == datastore.RegistrationIntent,
	})
}

// @Summary Finalize password setup with 2FA
// @Description Complete the password setup process after 2FA verification. If a recovery key is used, 2FA will be disabled.
// @Tags Accounts
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + verification token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Param request body services.TwoFAAuthRequest true "2FA verification request"
// @Success 200 {object} LoginFinalize2FAResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/password/finalize_2fa [post]
func (ac *AccountsController) SetupPasswordFinalize2FA(w http.ResponseWriter, r *http.Request) {
	verification := r.Context().Value(middleware.ContextVerification).(*datastore.Verification)

	if !checkVerificationStatusAndIntent(w, r, verification) {
		return
	}

	var requestData services.TwoFAAuthRequest
	if !util.DecodeJSONAndValidate(w, r, &requestData) {
		return
	}

	registrationState, err := ac.ds.GetRegistrationState(verification.Email, true)
	if err != nil {
		if errors.Is(err, util.ErrInterimPasswordStateMismatch) {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
			return
		}
		if errors.Is(err, util.ErrInterimPasswordStateNotFound) || errors.Is(err, util.ErrInterimPasswordStateExpired) {
			util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	if err := ac.twoFAService.ProcessChallenge(registrationState, &requestData); err != nil {
		if errors.Is(err, util.ErrBadTOTPCode) || errors.Is(err, util.ErrBadRecoveryKey) {
			util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	if err := ac.ds.DeleteInterimPasswordState(registrationState.ID); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	if err := ac.ds.UpdateOpaqueRegistration(*registrationState.AccountID, registrationState.OprfSeedID, registrationState.State); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	authToken, err := ac.createSessionAfterPasswordSetup(*registrationState.AccountID, r.UserAgent(), verification.ID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, &LoginFinalize2FAResponse{
		AuthToken:     authToken,
		TwoFADisabled: requestData.RecoveryKey != nil,
	})
}

// @Summary Initialize TOTP 2FA setup
// @Description Start the TOTP 2FA setup process by generating a TOTP key and URL.
// @Description Optionally generates a QR code if requested.
// @Tags Accounts
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Param request body TwoFAInitRequest true "2FA initialization request"
// @Success 200 {object} TwoFAInitResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/2fa/totp/init [post]
func (ac *AccountsController) SetupTOTPInit(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)

	var requestData TwoFAInitRequest
	if !util.DecodeJSONAndValidate(w, r, &requestData) {
		return
	}

	// Check if TOTP is already enabled
	twoFADetails, err := ac.ds.GetTwoFADetails(session.AccountID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	if twoFADetails.TOTP {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, util.ErrTOTPAlreadyEnabled)
		return
	}

	key, err := ac.twoFAService.GenerateAndStoreTOTPKey(session.AccountID, session.Email)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	response := TwoFAInitResponse{
		URI: key.URL(),
	}

	if requestData.GenerateQR {
		qrCode, err := ac.twoFAService.GenerateTOTPQRCode(key)
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}
		response.QRCode = &qrCode
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// @Summary Finalize TOTP 2FA setup
// @Description Complete the TOTP 2FA setup process by validating a TOTP code and enabling 2FA for the account.
// @Tags Accounts
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Param request body TwoFAFinalizeRequest true "2FA finalization request"
// @Success 200 {object} TwoFAFinalizeResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/2fa/totp/finalize [post]
func (ac *AccountsController) SetupTOTPFinalize(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)

	var requestData TwoFAFinalizeRequest
	if !util.DecodeJSONAndValidate(w, r, &requestData) {
		return
	}

	if err := ac.twoFAService.ValidateTOTPCode(session.AccountID, requestData.Code); err != nil {
		if errors.Is(err, util.ErrBadTOTPCode) {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		} else {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		}
		return
	}

	if err := ac.ds.SetTOTPSetting(session.AccountID, true); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	// Check if recovery key already exists
	hasRecoveryKey, err := ac.ds.HasRecoveryKey(session.AccountID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	var response TwoFAFinalizeResponse

	// Only generate a recovery key if one doesn't exist
	if !hasRecoveryKey {
		// Generate and store a recovery key
		recoveryKey, err := ac.twoFAService.GenerateAndStoreRecoveryKey(session.AccountID)
		if err != nil {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
			return
		}

		response.RecoveryKey = &recoveryKey
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// @Summary Delete account
// @Description Deletes the authenticated account and all associated data
// @Tags Accounts
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Success 204 "No Content"
// @Failure 401 {object} util.ErrorResponse
// @Failure 403 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts [delete]
func (ac *AccountsController) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)

	if err := ac.twoFAService.DeleteTOTPKey(session.AccountID); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	// Delete the account with all associated data
	if err := ac.ds.DeleteAccount(session.AccountID); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	if err := ac.ds.NotifyAccountDeletionEvent(session.AccountID); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusNoContent)
	render.NoContent(w, r)
}

// @Summary Get 2FA settings
// @Description Returns the 2FA methods enabled for the authenticated account and related timestamps
// @Tags Accounts
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Success 200 {object} datastore.TwoFADetails
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/2fa [get]
func (ac *AccountsController) GetTwoFASettings(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)

	twoFADetails, err := ac.ds.GetTwoFADetails(session.AccountID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, twoFADetails)
}

// @Summary Disable TOTP 2FA
// @Description Disables TOTP 2FA for the account and deletes the associated TOTP key
// @Tags Accounts
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Success 204 "No Content"
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/2fa/totp [delete]
func (ac *AccountsController) DisableTOTP(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)

	if err := ac.twoFAService.DisableTwoFA(session.AccountID); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusNoContent)
	render.NoContent(w, r)
}

// @Summary Regenerate 2FA recovery key
// @Description Generates a new 2FA recovery key for the account, replacing any existing key
// @Tags Accounts
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Success 200 {object} RecoveryKeyResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/2fa/recovery [post]
func (ac *AccountsController) RegenerateRecoveryKey(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)

	// Generate and store a new recovery key
	recoveryKey, err := ac.twoFAService.GenerateAndStoreRecoveryKey(session.AccountID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, &RecoveryKeyResponse{
		RecoveryKey: recoveryKey,
	})
}

// @Summary Delete 2FA recovery key
// @Description Deletes the 2FA recovery key for the account
// @Tags Accounts
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Success 204 "No Content"
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/2fa/recovery [delete]
func (ac *AccountsController) DeleteRecoveryKey(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)

	// Delete the recovery key
	if err := ac.ds.SetRecoveryKey(session.AccountID, nil); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusNoContent)
	render.NoContent(w, r)
}
