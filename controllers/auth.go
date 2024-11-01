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

type KE1 struct {
	Email          string  `json:"email" validate:"required,email,ascii" example:"test@example.com"`
	BlindedMessage *string `json:"blindedMessage" validate:"required_without=SerializedKE1"`
	EpkU           *string `json:"clientEphemeralPublicKey" validate:"required_without=SerializedKE1"`
	NonceU         *string `json:"clientNonce" validate:"required_without=SerializedKE1"`
	SerializedKE1  *string `json:"serializedKE1" validate:"required_without_all=BlindedMessage EpkU NonceU"`
}

type KE2 struct {
	AkeToken         string  `json:"akeToken"`
	EvaluatedMessage *string `json:"evaluatedMessage,omitempty"`
	MaskingNonce     *string `json:"maskingNonce,omitempty"`
	MaskedResponse   *string `json:"maskedResponse,omitempty"`
	EpkS             *string `json:"serverEphemeralPublicKey,omitempty"`
	NonceS           *string `json:"serverNonce,omitempty"`
	Mac              *string `json:"serverMac,omitempty"`
	SerializedKE2    *string `json:"serializedKE2,omitempty"`
}

type KE3 struct {
	Mac           *string `json:"clientMac" validate:"required_without=SerializedKE3"`
	SerializedKE3 *string `json:"serializedKE3" validate:"required_without=Mac"`
	SessionName   *string `json:"sessionName"`
}

type LoginFinalizeResponse struct {
	AuthToken string `json:"authToken"`
}

func (req *KE1) ToOpaqueKE1(opaqueService *services.OpaqueService) (*opaqueMsg.KE1, error) {
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

func FromOpaqueKE2(opaqueResp *opaqueMsg.KE2, akeToken string, useBinary bool) (*KE2, error) {
	if useBinary {
		serializedBin := hex.EncodeToString(opaqueResp.Serialize())
		return &KE2{
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

	return &KE2{
		AkeToken:         akeToken,
		EvaluatedMessage: &evalMsg,
		MaskingNonce:     &maskNonce,
		MaskedResponse:   &maskResp,
		EpkS:             &epk,
		NonceS:           &nonce,
		Mac:              &mac,
	}, nil
}

func (req *KE3) ToOpaqueKE3(opaqueService *services.OpaqueService) (*opaqueMsg.KE3, error) {
	if req.SerializedKE3 != nil {
		serializedBin, err := hex.DecodeString(*req.SerializedKE3)
		if err != nil {
			return nil, fmt.Errorf("failed to decode serialized KE1 hex: %w", err)
		}
		deserializer, err := opaqueService.BinaryDeserializer()
		if err != nil {
			return nil, err
		}
		opaqueMsg, err := deserializer.KE3(serializedBin)
		if err != nil {
			return nil, err
		}
		return opaqueMsg, nil
	}
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
// @Description First step of OPAQUE login flow, generates KE2 message
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body KE1 true "KE1 message"
// @Success 200 {object} KE2
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/auth/login/init [post]
func (ac *AuthController) LoginInit(w http.ResponseWriter, r *http.Request) {
	var requestData KE1
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
// @Description Final step of login flow, verifies KE3 message and creates session
// @Tags Auth
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + ake token"
// @Param request body KE3 true "KE3 message"
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

	var requestData KE3
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

	session, err := ac.ds.CreateSession(*accountID, requestData.SessionName)
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
