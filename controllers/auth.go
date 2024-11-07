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

type AuthController struct {
	opaqueService *services.OpaqueService
	validate      *validator.Validate
	jwtUtil       *util.JWTUtil
	ds            *datastore.Datastore
}

// @Description Request for account login
type LoginInitRequest struct {
	// Email address of the account
	Email string `json:"email" validate:"required,email,ascii" example:"test@example.com"`
	// Blinded message component of KE1
	BlindedMessage *string `json:"blindedMessage" validate:"required_without=SerializedKE1"`
	// Client ephemeral public key of KE1
	EpkU *string `json:"clientEphemeralPublicKey" validate:"required_without=SerializedKE1"`
	// Client nonce of KE1
	NonceU *string `json:"clientNonce" validate:"required_without=SerializedKE1"`
	// Serialized KE1 message
	SerializedKE1 *string `json:"serializedKE1" validate:"required_without_all=BlindedMessage EpkU NonceU"`
}

// @Description Response for account login
type LoginInitResponse struct {
	// Interim authentication token for future login finalization
	AkeToken string `json:"akeToken"`
	// Evaluated message component of KE2
	EvaluatedMessage *string `json:"evaluatedMessage,omitempty"`
	// Server masking nonce of KE2
	MaskingNonce *string `json:"maskingNonce,omitempty"`
	// Server masked response of KE2
	MaskedResponse *string `json:"maskedResponse,omitempty"`
	// Server ephemeral public key of KE2
	EpkS *string `json:"serverEphemeralPublicKey,omitempty"`
	// Server nonce of KE2
	NonceS *string `json:"serverNonce,omitempty"`
	// Server MAC of KE2
	Mac *string `json:"serverMac,omitempty"`
	// Serialized KE2 message
	SerializedKE2 *string `json:"serializedKE2,omitempty"`
}

// @Description Request to finalize login
type LoginFinalizeRequest struct {
	// Client MAC of KE3
	Mac *string `json:"clientMac" validate:"required"`
	// Optional name for the new session
	SessionName *string `json:"sessionName"`
}

// @Description Response containing auth token after successful login
type LoginFinalizeResponse struct {
	// Authentication token for future requests
	AuthToken string `json:"authToken"`
}

func (req *LoginInitRequest) ToOpaqueKE1(opaqueService *services.OpaqueService) (*opaqueMsg.KE1, error) {
	if req.SerializedKE1 != nil {
		serializedBin, err := hex.DecodeString(*req.SerializedKE1)
		if err != nil {
			return nil, fmt.Errorf("failed to decode serialized KE1 hex: %w", err)
		}
		deserializer, err := opaqueService.BinaryDeserializer()
		if err != nil {
			return nil, err
		}
		opaqueMsg, err := deserializer.KE1(serializedBin)
		if err != nil {
			return nil, err
		}
		return opaqueMsg, nil
	}
	blindedMessage, err := hex.DecodeString(*req.BlindedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode blinded message: %w", err)
	}
	epk, err := hex.DecodeString(*req.EpkU)
	if err != nil {
		return nil, fmt.Errorf("failed to decode epk: %w", err)
	}
	nonce, err := hex.DecodeString(*req.NonceU)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}
	blindedMessageElement := opaqueService.NewElement()
	epkElement := opaqueService.NewElement()
	if err = blindedMessageElement.UnmarshalBinary(blindedMessage); err != nil {
		return nil, fmt.Errorf("failed to decode blinded message to element: %w", err)
	}
	if err = epkElement.UnmarshalBinary(epk); err != nil {
		return nil, fmt.Errorf("failed to decode epk to element: %w", err)
	}

	return &opaqueMsg.KE1{
		CredentialRequest: &opaqueMsg.CredentialRequest{
			BlindedMessage: blindedMessageElement,
		},
		ClientPublicKeyshare: epkElement,
		ClientNonce:          nonce,
	}, nil
}

func FromOpaqueKE2(opaqueResp *opaqueMsg.KE2, akeToken string, useBinary bool) (*LoginInitResponse, error) {
	if useBinary {
		serializedBin := hex.EncodeToString(opaqueResp.Serialize())
		return &LoginInitResponse{
			AkeToken:      akeToken,
			SerializedKE2: &serializedBin,
		}, nil
	}
	evalMsgBin, err := opaqueResp.EvaluatedMessage.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize evaluated message: %w", err)
	}
	epkBin, err := opaqueResp.ServerPublicKeyshare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize evaluated message: %w", err)
	}
	evalMsg := hex.EncodeToString(evalMsgBin)
	maskNonce := hex.EncodeToString(opaqueResp.MaskingNonce)
	maskResp := hex.EncodeToString(opaqueResp.MaskedResponse)
	epk := hex.EncodeToString(epkBin)
	nonce := hex.EncodeToString(opaqueResp.ServerNonce)
	mac := hex.EncodeToString(opaqueResp.ServerMac)

	return &LoginInitResponse{
		AkeToken:         akeToken,
		EvaluatedMessage: &evalMsg,
		MaskingNonce:     &maskNonce,
		MaskedResponse:   &maskResp,
		EpkS:             &epk,
		NonceS:           &nonce,
		Mac:              &mac,
	}, nil
}

func (req *LoginFinalizeRequest) ToOpaqueKE3(opaqueService *services.OpaqueService) (*opaqueMsg.KE3, error) {
	mac, err := hex.DecodeString(*req.Mac)
	if err != nil {
		return nil, fmt.Errorf("failed to decode mac: %w", err)
	}
	return &opaqueMsg.KE3{
		ClientMac: mac,
	}, nil
}

func NewAuthController(opaqueService *services.OpaqueService, jwtUtil *util.JWTUtil, ds *datastore.Datastore) *AuthController {
	return &AuthController{
		opaqueService: opaqueService,
		validate:      validator.New(validator.WithRequiredStructEnabled()),
		jwtUtil:       jwtUtil,
		ds:            ds,
	}
}

func (ac *AuthController) Router(authMiddleware func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()

	r.With(authMiddleware).Get("/validate", ac.Validate)
	r.Post("/login/init", ac.LoginInit)
	r.Post("/login/finalize", ac.LoginFinalize)

	return r
}

// @Summary Validate auth token
// @Description Validates an auth token and returns session details
// @Tags Auth
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Success 200 {object} ValidateTokenResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 403 {object} util.ErrorResponse
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

// @Summary Initialize login
// @Description First step of OPAQUE login flow, generates KE2 message.
// @Description Either `blindedMessage`, `clientEphemeralPublicKey` and `clientNonce` must be provided together,
// @Description or `serializedKE1` must be provided.
// @Description If the latter is provided, `serializedKE2` will be included in the response with other
// @Description KE2 fields omitted.
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body LoginInitRequest true "login init request"
// @Success 200 {object} LoginInitResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/auth/login/init [post]
func (ac *AuthController) LoginInit(w http.ResponseWriter, r *http.Request) {
	var requestData LoginInitRequest
	if err := render.DecodeJSON(r.Body, &requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	if err := ac.validate.Struct(requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	opaqueReq, err := requestData.ToOpaqueKE1(ac.opaqueService)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	ke2, akeState, err := ac.opaqueService.LoginInit(requestData.Email, opaqueReq)
	if err != nil {
		if errors.Is(err, services.ErrIncorrectCredentials) {
			util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	akeToken, err := ac.jwtUtil.CreateEphemeralAKEToken(akeState.ID, datastore.AkeStateExpiration)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	response, err := FromOpaqueKE2(ke2, akeToken, requestData.SerializedKE1 != nil)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// @Summary Finalize login
// @Description Final step of login flow, verifies KE3 message and creates session.
// @Tags Auth
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + ake token"
// @Param request body LoginFinalizeRequest true "login finalize request"
// @Success 200 {object} LoginFinalizeResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/auth/login/finalize [post]
func (ac *AuthController) LoginFinalize(w http.ResponseWriter, r *http.Request) {
	token, err := util.ExtractAuthToken(r)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	akeStateID, err := ac.jwtUtil.ValidateEphemeralAKEToken(token)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
		return
	}

	var requestData LoginFinalizeRequest
	if err := render.DecodeJSON(r.Body, &requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	if err := ac.validate.Struct(requestData); err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	opaqueReq, err := requestData.ToOpaqueKE3(ac.opaqueService)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	accountID, err := ac.opaqueService.LoginFinalize(akeStateID, opaqueReq)
	if err != nil {
		if errors.Is(err, services.ErrIncorrectCredentials) ||
			errors.Is(err, datastore.ErrAKEStateNotFound) ||
			errors.Is(err, datastore.ErrAKEStateExpired) {
			util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	session, err := ac.ds.CreateSession(*accountID, datastore.PasswordAuthSessionVersion, requestData.SessionName)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	authToken, err := ac.jwtUtil.CreateAuthToken(session.ID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}
	response := LoginFinalizeResponse{
		AuthToken: authToken,
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}
