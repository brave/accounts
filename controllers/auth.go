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
	Email          string `json:"email" validate:"required,email,ascii" example:"test@example.com"`
	BlindedMessage string `json:"blindedMessage" validate:"required"`
	EpkU           string `json:"clientEphemeralPublicKey" validate:"required"`
	NonceU         string `json:"clientNonce" validate:"required"`
}

type KE2 struct {
	AkeToken         string `json:"akeToken"`
	EvaluatedMessage string `json:"evaluatedMessage"`
	MaskingNonce     string `json:"maskingNonce"`
	MaskedResponse   string `json:"maskedResponse"`
	EpkS             string `json:"serverEphemeralPublicKey"`
	NonceS           string `json:"serverNonce"`
	Mac              string `json:"serverMac"`
}

type KE3 struct {
	Mac         string  `json:"clientMac" validate:"required"`
	SessionName *string `json:"sessionName"`
}

type LoginFinalizeResponse struct {
	AuthToken string `json:"authToken"`
}

func (req *KE1) ToOpaqueKE1(opaqueService *services.OpaqueService) (*opaqueMsg.KE1, error) {
	blindedMessage, err := hex.DecodeString(req.BlindedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode blinded message: %w", err)
	}
	epk, err := hex.DecodeString(req.EpkU)
	if err != nil {
		return nil, fmt.Errorf("failed to decode epk: %w", err)
	}
	nonce, err := hex.DecodeString(req.NonceU)
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
		EpkU:   epkElement,
		NonceU: nonce,
	}, nil
}

func FromOpaqueKE2(opaqueResp *opaqueMsg.KE2) (*KE2, error) {
	evalMsgBin, err := opaqueResp.EvaluatedMessage.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize evaluated message: %w", err)
	}
	epkBin, err := opaqueResp.EpkS.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize evaluated message: %w", err)
	}
	return &KE2{
		EvaluatedMessage: hex.EncodeToString(evalMsgBin),
		MaskingNonce:     hex.EncodeToString(opaqueResp.MaskingNonce),
		MaskedResponse:   hex.EncodeToString(opaqueResp.MaskedResponse),
		EpkS:             hex.EncodeToString(epkBin),
		NonceS:           hex.EncodeToString(opaqueResp.NonceS),
		Mac:              hex.EncodeToString(opaqueResp.Mac),
	}, nil
}

func (req *KE3) ToOpaqueKE3() (*opaqueMsg.KE3, error) {
	mac, err := hex.DecodeString(req.Mac)
	if err != nil {
		return nil, fmt.Errorf("failed to decode mac: %w", err)
	}
	return &opaqueMsg.KE3{
		Mac: mac,
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
	r.With(authMiddleware).Post("/login/init", ac.LoginInit)
	r.With(authMiddleware).Post("/login/finalize", ac.LoginInit)

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
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	akeToken, err := ac.jwtUtil.CreateEphemeralAKEToken(akeState.ID, datastore.AkeStateExpiration)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	response, err := FromOpaqueKE2(ke2)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}
	response.AkeToken = akeToken

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

	opaqueReq, err := requestData.ToOpaqueKE3()
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
