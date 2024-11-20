package controllers_test

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brave-experiments/accounts/controllers"
	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/middleware"
	"github.com/brave-experiments/accounts/services"
	"github.com/brave-experiments/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UserKeysTestSuite struct {
	suite.Suite
	ds        *datastore.Datastore
	account   *datastore.Account
	router    *chi.Mux
	authToken string
}

func (suite *UserKeysTestSuite) SetupTest() {
	var err error
	suite.ds, err = datastore.NewDatastore(datastore.PasswordAuthSessionVersion, true)
	require.NoError(suite.T(), err)

	jwtService, err := services.NewJWTService(suite.ds)
	require.NoError(suite.T(), err)

	suite.account, err = suite.ds.GetOrCreateAccount("test@example.com")
	require.NoError(suite.T(), err)

	otherAccount, err := suite.ds.GetOrCreateAccount("test2@example.com")
	require.NoError(suite.T(), err)

	otherTestKey := datastore.DBUserKey{
		AccountID:    otherAccount.ID,
		Name:         "wrapping_key",
		EncryptedKey: []byte("test key 10"),
		UpdatedAt:    time.Now().UTC(),
	}
	err = suite.ds.StoreUserKey(&otherTestKey)
	require.NoError(suite.T(), err)

	controller := controllers.NewUserKeysController(suite.ds)
	authMiddleware := middleware.AuthMiddleware(jwtService, suite.ds, datastore.EmailAuthSessionVersion)

	session, err := suite.ds.CreateSession(suite.account.ID, datastore.PasswordAuthSessionVersion, "")
	require.NoError(suite.T(), err)
	suite.authToken, err = jwtService.CreateAuthToken(session.ID)
	require.NoError(suite.T(), err)

	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/keys", controller.Router(authMiddleware))
}

func TestUserKeysTestSuite(t *testing.T) {
	suite.Run(t, new(UserKeysTestSuite))
}

func (suite *UserKeysTestSuite) TestListKeys() {
	// Store some test keys
	updatedTime := time.Now().UTC().Truncate(time.Millisecond)
	testKeys := []datastore.DBUserKey{
		{
			AccountID:    suite.account.ID,
			Name:         "wrapping_key",
			EncryptedKey: []byte("test key 1"),
			UpdatedAt:    updatedTime,
		},
		{
			AccountID:    suite.account.ID,
			Name:         "sync_enc_seed",
			EncryptedKey: []byte("test key 2"),
			UpdatedAt:    updatedTime,
		},
	}

	for _, key := range testKeys {
		err := suite.ds.StoreUserKey(&key)
		require.NoError(suite.T(), err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/keys", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	var responseKeys []controllers.UserKey
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &responseKeys)

	assert.Len(suite.T(), responseKeys, len(testKeys))
	for i, testKey := range testKeys {
		assert.Equal(suite.T(), testKey.Name, responseKeys[i].Name)
		assert.Equal(suite.T(), hex.EncodeToString(testKey.EncryptedKey), responseKeys[i].EncryptedKey)
		assert.Equal(suite.T(), testKey.UpdatedAt, responseKeys[i].UpdatedAt)
	}
}

func (suite *UserKeysTestSuite) TestGetKey() {
	testKey := &datastore.DBUserKey{
		AccountID:    suite.account.ID,
		Name:         "wrapping_key",
		EncryptedKey: []byte("test key"),
		UpdatedAt:    time.Now().UTC().Truncate(time.Millisecond),
	}
	err := suite.ds.StoreUserKey(testKey)
	require.NoError(suite.T(), err)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys/wrapping_key", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	var responseKey controllers.UserKey
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &responseKey)

	assert.Equal(suite.T(), testKey.Name, responseKey.Name)
	assert.Equal(suite.T(), hex.EncodeToString(testKey.EncryptedKey), responseKey.EncryptedKey)
	assert.Equal(suite.T(), testKey.UpdatedAt, responseKey.UpdatedAt)
}

func (suite *UserKeysTestSuite) TestSaveKey() {
	requestBody := controllers.UserKeyStoreRequest{
		Name:         "wrapping_key",
		EncryptedKey: "0123456789abcdef",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	assert.Equal(suite.T(), http.StatusNoContent, resp.Code)

	// Verify key was stored
	key, err := suite.ds.GetUserKey(suite.account.ID, "wrapping_key")
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "wrapping_key", key.Name)
}

func (suite *UserKeysTestSuite) TestSaveKeyInvalidKeyName() {
	requestBody := controllers.UserKeyStoreRequest{
		Name:         "bad_key_name",
		EncryptedKey: "0123456789abcdef",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	assert.Equal(suite.T(), http.StatusBadRequest, resp.Code)
}

func (suite *UserKeysTestSuite) TestSaveKeyInvalidHex() {
	requestBody := controllers.UserKeyStoreRequest{
		Name:         "wrapping_key",
		EncryptedKey: "invalid hex",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	assert.Equal(suite.T(), http.StatusBadRequest, resp.Code)
}

func (suite *UserKeysTestSuite) TestGetKeyNotFound() {
	req := httptest.NewRequest(http.MethodGet, "/v2/keys/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	assert.Equal(suite.T(), http.StatusNotFound, resp.Code)
}
