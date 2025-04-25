package controllers

import (
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
)

type ServerKeysController struct {
	opaqueService *services.OpaqueService
	jwtService    *services.JWTService
	twoFAService  *services.TwoFAService
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

// TOTPGenerateRequest represents the request body for TOTP key operations
type TOTPGenerateRequest struct {
	// AccountID is the UUID of the account for which to generate/delete a TOTP key
	AccountID uuid.UUID `json:"accountId" validate:"required"`
	// Email is the email address for the account (used for TOTP generation)
	Email string `json:"email" validate:"required,email"`
}

// TOTPGenerateResponse represents the response body containing the generated TOTP key
type TOTPGenerateResponse struct {
	// URI is the URI of the TOTP key QR code
	URI string `json:"uri"`
}

// TOTPValidateRequest represents the request body for validating a TOTP code
type TOTPValidateRequest struct {
	// AccountID is the UUID of the account to validate against
	AccountID uuid.UUID `json:"accountId" validate:"required"`
	// Code is the TOTP code to validate
	Code string `json:"code" validate:"required"`
}

func NewServerKeysController(opaqueService *services.OpaqueService, jwtService *services.JWTService, twoFAService *services.TwoFAService) *ServerKeysController {
	return &ServerKeysController{
		opaqueService: opaqueService,
		jwtService:    jwtService,
		twoFAService:  twoFAService,
	}
}

func (sc *ServerKeysController) Router(keyServiceMiddleware func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()

	r.Use(keyServiceMiddleware)
	r.Post("/jwt", sc.CreateJWT)
	r.Post("/oprf_seed", sc.DeriveOPRFKey)
	r.Post("/totp", sc.CreateTOTPKey)
	r.Post("/totp/validate", sc.ValidateTOTPCode)
	r.Delete("/totp/{accountId}", sc.DeleteTOTPKey)

	return r
}

// @Summary Create JWT
// @Description Creates a JWT with provided claims using server signing key
// @Tags Server Keys (server-side use only)
// @Accept json
// @Produce json
// @Param Key-Service-Secret header string false "Key service secret"
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
// @Param Key-Service-Secret header string false "Key service secret"
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

// @Summary Create TOTP Key
// @Description Creates a TOTP key for an account using secure random generation
// @Tags Server Keys (server-side use only)
// @Accept json
// @Produce json
// @Param Key-Service-Secret header string false "Key service secret"
// @Param request body TOTPGenerateRequest true "TOTP key generation request"
// @Success 200 {object} TOTPGenerateResponse
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/server_keys/totp [post]
func (sc *ServerKeysController) CreateTOTPKey(w http.ResponseWriter, r *http.Request) {
	var request TOTPGenerateRequest
	if !util.DecodeJSONAndValidate(w, r, &request) {
		return
	}

	// Generate TOTP key for the specified account
	key, err := sc.twoFAService.GenerateAndStoreTOTPKey(request.AccountID, request.Email)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	response := TOTPGenerateResponse{
		URI: key.URL(),
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// @Summary Validate TOTP Code
// @Description Validates a TOTP code for an account
// @Tags Server Keys (server-side use only)
// @Accept json
// @Produce json
// @Param Key-Service-Secret header string false "Key service secret"
// @Param request body TOTPValidateRequest true "Validation request"
// @Success 204 "Success"
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 403 {object} util.ErrorResponse
// @Failure 404 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/server_keys/totp/validate [post]
func (sc *ServerKeysController) ValidateTOTPCode(w http.ResponseWriter, r *http.Request) {
	var request TOTPValidateRequest
	if !util.DecodeJSONAndValidate(w, r, &request) {
		return
	}

	// Validate TOTP code for the specified account
	err := sc.twoFAService.ValidateTOTPCode(request.AccountID, request.Code)
	if err != nil {
		if errors.Is(err, util.ErrKeyNotFound) {
			util.RenderErrorResponse(w, r, http.StatusNotFound, err)
		} else if errors.Is(err, util.ErrBadTOTPCode) {
			util.RenderErrorResponse(w, r, http.StatusUnauthorized, err)
		} else {
			util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// @Summary Delete TOTP Key
// @Description Deletes a TOTP key for an account
// @Tags Server Keys (server-side use only)
// @Accept json
// @Produce json
// @Param Key-Service-Secret header string false "Key service secret"
// @Param accountId path string true "Account ID"
// @Success 204 "Success"
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 404 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/server_keys/totp/{accountId} [delete]
func (sc *ServerKeysController) DeleteTOTPKey(w http.ResponseWriter, r *http.Request) {
	accountId, err := uuid.Parse(chi.URLParam(r, "accountId"))
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	// Delete TOTP key for the specified account
	err = sc.twoFAService.DeleteTOTPKey(accountId)
	if err != nil {
		if errors.Is(err, util.ErrKeyNotFound) {
			util.RenderErrorResponse(w, r, http.StatusNotFound, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
