package controllers

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
)

const keyNameURLParam = "name"

// UserKey represents the HTTP request format for a key
type UserKeyStoreRequest struct {
	// Name identifies the type of key (wrapping_key or sync_enc_seed)
	Name string `json:"name" validate:"required,oneof=wrapping_key sync_enc_seed"`
	// KeyMaterial contains the encrypted key data as hex bytes
	KeyMaterial string `json:"keyMaterial" validate:"required,min=16,max=128"`
}

// UserKey represents the HTTP response format for a key
type UserKey struct {
	// Name identifies the type of key (wrapping_key or sync_enc_seed)
	Name string `json:"name"`
	// KeyMaterial contains the encrypted key data as hex bytes
	KeyMaterial string `json:"keyMaterial"`
	// UpdatedAt is the timestamp when the key was last updated
	UpdatedAt time.Time `json:"updatedAt"`
}

// ToUserKey converts a UserKeyRequest to a UserKey
func (r *UserKeyStoreRequest) ToDBUserKey(accountID uuid.UUID) (*datastore.DBUserKey, error) {
	encKey, err := hex.DecodeString(r.KeyMaterial)
	if err != nil {
		return nil, fmt.Errorf("invalid hex encoding: %w", err)
	}

	return &datastore.DBUserKey{
		AccountID:   accountID,
		Name:        r.Name,
		KeyMaterial: encKey,
		UpdatedAt:   time.Now().UTC(),
	}, nil
}

// FromDBUserKey converts a datastore.DBUserKey to a UserKey
func FromDBUserKey(dbKey *datastore.DBUserKey) UserKey {
	return UserKey{
		Name:        dbKey.Name,
		KeyMaterial: hex.EncodeToString(dbKey.KeyMaterial),
		UpdatedAt:   dbKey.UpdatedAt,
	}
}

type UserKeysController struct {
	ds *datastore.Datastore
}

func NewUserKeysController(ds *datastore.Datastore) *UserKeysController {
	return &UserKeysController{
		ds: ds,
	}
}

func (uc *UserKeysController) Router(authMiddleware func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()
	r.Use(authMiddleware)

	r.Get("/", uc.ListKeys)
	r.Get("/{name}", uc.GetKey)
	r.Post("/", uc.SaveKey)

	return r
}

// @Summary List user keys
// @Description Get all keys for the authenticated user
// @Tags User keys
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Success 200 {array} UserKey
// @Failure 401 {object} util.ErrorResponse
// @Failure 403 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/keys [get]
func (uc *UserKeysController) ListKeys(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)

	keys, err := uc.ds.GetUserKeys(session.AccountID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	response := make([]UserKey, len(keys))
	for i := range keys {
		response[i] = FromDBUserKey(&keys[i])
	}

	render.JSON(w, r, response)
}

// @Summary Get user key
// @Description Get a specific key by name for the authenticated user
// @Tags User keys
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Param name path string true "Key name"
// @Success 200 {object} UserKey
// @Failure 401 {object} util.ErrorResponse
// @Failure 403 {object} util.ErrorResponse
// @Failure 404 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/keys/{name} [get]
func (uc *UserKeysController) GetKey(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)
	name := chi.URLParam(r, keyNameURLParam)

	key, err := uc.ds.GetUserKey(session.AccountID, name)
	if err != nil {
		if errors.Is(err, util.ErrKeyNotFound) {
			util.RenderErrorResponse(w, r, http.StatusNotFound, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.JSON(w, r, FromDBUserKey(key))
}

// @Summary Save user key
// @Description Save a new key or update existing key for the authenticated user
// @Tags User keys
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Param Brave-Key header string false "Brave services key (if one is configured)"
// @Param key body UserKeyStoreRequest true "Key to save"
// @Success 204 "Key saved"
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 403 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/keys [post]
func (uc *UserKeysController) SaveKey(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)

	var requestData UserKeyStoreRequest
	if !util.DecodeJSONAndValidate(w, r, &requestData) {
		return
	}

	dbKey, err := requestData.ToDBUserKey(session.AccountID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	if err := uc.ds.StoreUserKey(dbKey); err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.NoContent(w, r)
}
