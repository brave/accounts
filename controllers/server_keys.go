package controllers

import (
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

type ServerKeysController struct {
	opaqueService *services.OpaqueService
	jwtService    *services.JWTService
}

// JWTCreateRequest represents the request body for creating a JWT token
type JWTCreateRequest struct {
	// Claims represents the JWT claims to be included in the token
	Claims map[string]interface{} `json:"claims" validate:"required"`
}

// JWTCreateResponse represents the response body containing the created JWT token
type JWTCreateResponse struct {
	// Token is the signed JWT token string
	Token string `json:"token"`
}

// OPRFSeedRequest represents the request body for deriving an OPRF client seed
type OPRFSeedRequest struct {
	// CredentialIdentifier is the unique identifier used to derive the OPRF seed
	CredentialIdentifier string `json:"credentialIdentifier" validate:"required"`
	// SeedID optionally specifies which server OPRF seed to use (defaults to latest)
	SeedID *int `json:"seedId"`
}

// OPRFSeedResponse represents the response body containing the derived OPRF client seed
type OPRFSeedResponse struct {
	// ClientSeed is the hex-encoded derived OPRF client seed
	ClientSeed string `json:"clientSeed"`
	// SeedID is the ID of the server OPRF seed that was used
	SeedID int `json:"seedId"`
}

func NewServerKeysController(opaqueService *services.OpaqueService, jwtService *services.JWTService) *ServerKeysController {
	return &ServerKeysController{
		opaqueService: opaqueService,
		jwtService:    jwtService,
	}
}

func (sc *ServerKeysController) Router(keyServiceMiddleware func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()

	r.Use(keyServiceMiddleware)
	r.Post("/jwt", sc.CreateJWT)
	r.Post("/oprf_seed", sc.DeriveOPRFKey)

	return r
}

// @Summary Create JWT
// @Description Creates a JWT with provided claims using server signing key
// @Tags Server Keys (server-side use only)
// @Accept json
// @Produce json
// @Param Key-Service-Secret header string true "Key service secret"
// @Param request body JWTCreateRequest true "JWT claims"
// @Success 200 {object} JWTCreateResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/server_keys/jwt [post]
func (sc *ServerKeysController) CreateJWT(w http.ResponseWriter, r *http.Request) {
	var request JWTCreateRequest
	if !util.DecodeJSONAndValidate(w, r, &request) {
		return
	}

	// Sign token with provided claims
	token, err := sc.jwtService.CreateToken(request.Claims)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, JWTCreateResponse{
		Token: token,
	})
}

// @Summary Derive OPRF Key
// @Description Derives an OPRF key using HKDF and the server OPRF seed
// @Tags Server Keys (server-side use only)
// @Accept json
// @Produce json
// @Param Key-Service-Secret header string true "Key service secret"
// @Param request body OPRFSeedRequest true "OPRF key derivation info"
// @Success 200 {object} OPRFSeedResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/server_keys/oprf_seed [post]
func (sc *ServerKeysController) DeriveOPRFKey(w http.ResponseWriter, r *http.Request) {
	var request OPRFSeedRequest
	if !util.DecodeJSONAndValidate(w, r, &request) {
		return
	}

	derivedSeed, seedID, err := sc.opaqueService.DeriveOPRFClientSeed(request.CredentialIdentifier, request.SeedID)
	if err != nil {
		if errors.Is(err, services.ErrOPRFSeedNotAvailable) {
			util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, OPRFSeedResponse{
		ClientSeed: hex.EncodeToString(derivedSeed),
		SeedID:     seedID,
	})
}
