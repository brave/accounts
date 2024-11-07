package controllers

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/middleware"
	"github.com/brave-experiments/accounts/services"
	"github.com/brave-experiments/accounts/util"
	opaqueMsg "github.com/bytemare/opaque/message"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

var ErrEmailNotVerified = errors.New("email not verified")
var ErrIncorrectVerificationIntent = errors.New("incorrect verification intent")

type AccountsController struct {
	opaqueService *services.OpaqueService
	validate      *validator.Validate
	jwtUtil       *util.JWTUtil
	ds            *datastore.Datastore
}

// @Description Response for password setup or change
type PasswordFinalizeResponse struct {
	// Authentication token
	AuthToken string `json:"authToken"`
}

// @Description Request to register a new account
type RegistrationRequest struct {
	// Serialized OPAQUE registration request
	BlindedMessage string `json:"blindedMessage" validate:"required"`
	// Whether to serialize the response into binary/hex
	SerializeResponse bool `json:"serializeResponse"`
}

// @Description Response for registering a new account
type RegistrationResponse struct {
	// Evaluated message of the OPAQUE registration response
	EvaluatedMessage *string `json:"evaluatedMessage,omitempty"`
	// PKS of the OPAQUE registration response
	Pks *string `json:"pks,omitempty"`
	// Serialized OPAQUE registration response
	SerializedResponse *string `json:"serializedResponse,omitempty"`
}

// @Description OPAQUE registration record for a new account
type RegistrationRecord struct {
	// Public key of registation record
	PublicKey *string `json:"publicKey" validate:"required_without=SerializedRecord"`
	// Masking key of registation record
	MaskingKey *string `json:"maskingKey" validate:"required_without=SerializedRecord"`
	// Envelope of registation record
	Envelope *string `json:"envelope" validate:"required_without=SerializedRecord"`
	// Optional name of the new session
	SessionName *string `json:"sessionName" validate:"omitempty,max=50"`
	// Serialized registration record
	SerializedRecord *string `json:"serializedRecord" validate:"required_without_all=PublicKey MaskingKey Envelope"`
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

func NewAccountsController(opaqueService *services.OpaqueService, jwtUtil *util.JWTUtil, ds *datastore.Datastore) *AccountsController {
	return &AccountsController{
		opaqueService: opaqueService,
		validate:      validator.New(validator.WithRequiredStructEnabled()),
		jwtUtil:       jwtUtil,
		ds:            ds,
	}
}

func (ac *AccountsController) Router(permissiveAuthMiddleware func(http.Handler) http.Handler, verificationAuthMiddleware func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()

	r.With(verificationAuthMiddleware).Post("/setup/init", ac.SetupPasswordInit)
	r.With(verificationAuthMiddleware).Post("/setup/finalize", ac.SetupPasswordFinalize)
	r.With(permissiveAuthMiddleware).Post("/change_pwd/init", ac.ChangePasswordInit)
	r.With(permissiveAuthMiddleware).Post("/change_pwd/finalize", ac.ChangePasswordFinalize)

	return r
}

func (ac *AccountsController) setupPasswordInitHelper(email string, w http.ResponseWriter, r *http.Request) {
	var requestData RegistrationRequest
	if err := render.DecodeJSON(r.Body, &requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	if err := ac.validate.Struct(requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	opaqueReq, err := requestData.ToOpaqueRequest(ac.opaqueService)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	opaqueResponse, err := ac.opaqueService.SetupPasswordInit(email, opaqueReq)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	response, err := FromOpaqueRegistrationResponse(opaqueResponse, requestData.SerializeResponse)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

func (ac *AccountsController) setupPasswordFinalizeHelper(email string, w http.ResponseWriter, r *http.Request) *PasswordFinalizeResponse {
	var requestData RegistrationRecord
	if err := render.DecodeJSON(r.Body, &requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return nil
	}

	if err := ac.validate.Struct(requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return nil
	}

	opaqueRecord, err := requestData.ToOpaqueRecord(ac.opaqueService)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return nil
	}

	account, err := ac.opaqueService.SetupPasswordFinalize(email, opaqueRecord)
	if err != nil {
		switch {
		case errors.Is(err, datastore.ErrRegistrationStateNotFound):
			util.RenderErrorResponse(w, r, http.StatusNotFound, err)
		case errors.Is(err, datastore.ErrRegistrationStateExpired):
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		default:
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		}
		return nil
	}

	session, err := ac.ds.CreateSession(account.ID, datastore.PasswordAuthSessionVersion, requestData.SessionName)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return nil
	}

	authToken, err := ac.jwtUtil.CreateAuthToken(session.ID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return nil
	}

	return &PasswordFinalizeResponse{
		AuthToken: authToken,
	}
}

func checkVerificationStatusAndIntent(w http.ResponseWriter, r *http.Request, verification *datastore.Verification) bool {
	if !verification.Verified {
		util.RenderErrorResponse(w, r, http.StatusForbidden, ErrEmailNotVerified)
		return false
	}

	if verification.Intent != registrationIntent && verification.Intent != resetIntent {
		util.RenderErrorResponse(w, r, http.StatusForbidden, ErrIncorrectVerificationIntent)
		return false
	}
	return true
}

// @Summary Initialize password setup
// @Description Start the password setup process using OPAQUE protocol.
// @Description If `serializeResponse` is set to true, the `serializedResponse` field will be populated
// @Description in the response, with other fields omitted.
// @Tags Accounts
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + verification token"
// @Param request body RegistrationRequest true "Registration request"
// @Success 200 {object} RegistrationResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 403 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/setup/init [post]
func (ac *AccountsController) SetupPasswordInit(w http.ResponseWriter, r *http.Request) {
	verification := r.Context().Value(middleware.ContextVerification).(*datastore.Verification)

	if !checkVerificationStatusAndIntent(w, r, verification) {
		return
	}

	ac.setupPasswordInitHelper(verification.Email, w, r)
}

// @Summary Finalize password setup
// @Description Complete the password setup process and return auth token.
// @Description Either `publicKey`, `maskingKey` and `envelope` must be provided together,
// @Description or `serializedRecord` must be provided.
// @Tags Accounts
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + verification token"
// @Param request body RegistrationRecord true "Registration record"
// @Success 200 {object} PasswordFinalizeResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 403 {object} util.ErrorResponse
// @Failure 404 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/setup/finalize [post]
func (ac *AccountsController) SetupPasswordFinalize(w http.ResponseWriter, r *http.Request) {
	verification := r.Context().Value(middleware.ContextVerification).(*datastore.Verification)

	if !checkVerificationStatusAndIntent(w, r, verification) {
		return
	}

	response := ac.setupPasswordFinalizeHelper(verification.Email, w, r)
	if response == nil {
		return
	}

	if err := ac.ds.DeleteVerification(verification.ID); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// @Summary Initialize password change
// @Description Start the password change process using OPAQUE protocol.
// @Description This endpoint should also be used to upgrade a Phase 1 account to a Phase 2 account.
// @Description If `serializeResponse` is set to true, the `serializedResponse` field will be populated
// @Description in the response, with other fields omitted.
// @Tags Accounts
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param request body RegistrationRequest true "Registration request"
// @Success 200 {object} RegistrationResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/change_pwd/init [post]
func (ac *AccountsController) ChangePasswordInit(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.Session)

	ac.setupPasswordInitHelper(session.Account.Email, w, r)
}

// @Summary Finalize password setup
// @Description Complete the password change process and return auth token
// @Description Either `publicKey`, `maskingKey` and `envelope` must be provided together,
// @Description or `serializedRecord` must be provided.
// @Tags Accounts
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param request body RegistrationRecord true "Registration record"
// @Success 200 {object} PasswordFinalizeResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 404 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/accounts/change_pwd/finalize [post]
func (ac *AccountsController) ChangePasswordFinalize(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.Session)

	response := ac.setupPasswordFinalizeHelper(session.Account.Email, w, r)
	if response == nil {
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}
