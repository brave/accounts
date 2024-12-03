package controllers_test

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brave/accounts/controllers"
	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/go-chi/chi/v5"
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
	suite.Require().NoError(err)

	jwtService, err := services.NewJWTService(suite.ds)
	suite.Require().NoError(err)

	suite.account, err = suite.ds.GetOrCreateAccount("test@example.com")
	suite.Require().NoError(err)

	otherAccount, err := suite.ds.GetOrCreateAccount("test2@example.com")
	suite.Require().NoError(err)

	otherTestKey := datastore.DBUserKey{
		AccountID:   otherAccount.ID,
		Name:        "wrapping_key",
		KeyMaterial: []byte("test key 10"),
		UpdatedAt:   time.Now().UTC(),
	}
	err = suite.ds.StoreUserKey(&otherTestKey)
	suite.Require().NoError(err)

	controller := controllers.NewUserKeysController(suite.ds)
	authMiddleware := middleware.AuthMiddleware(jwtService, suite.ds, datastore.EmailAuthSessionVersion)

	session, err := suite.ds.CreateSession(suite.account.ID, datastore.PasswordAuthSessionVersion, "")
	suite.Require().NoError(err)
	suite.authToken, err = jwtService.CreateAuthToken(session.ID)
	suite.Require().NoError(err)

	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/keys", controller.Router(authMiddleware))
}

func (suite *UserKeysTestSuite) TearDownTest() {
	suite.ds.Close()
}

func TestUserKeysTestSuite(t *testing.T) {
	suite.Run(t, new(UserKeysTestSuite))
}

func (suite *UserKeysTestSuite) TestListKeys() {
	// Store some test keys
	updatedTime := time.Now().UTC().Truncate(time.Millisecond)
	testKeys := []datastore.DBUserKey{
		{
			AccountID:   suite.account.ID,
			Name:        "wrapping_key",
			KeyMaterial: []byte("test key 1"),
			UpdatedAt:   updatedTime,
		},
		{
			AccountID:   suite.account.ID,
			Name:        "sync_enc_seed",
			KeyMaterial: []byte("test key 2"),
			UpdatedAt:   updatedTime,
		},
	}

	for _, key := range testKeys {
		err := suite.ds.StoreUserKey(&key)
		suite.Require().NoError(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/keys", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusOK, resp.Code)

	var responseKeys []controllers.UserKey
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &responseKeys)

	suite.Len(responseKeys, len(testKeys))
	for i, testKey := range testKeys {
		suite.Equal(testKey.Name, responseKeys[i].Name)
		suite.Equal(hex.EncodeToString(testKey.KeyMaterial), responseKeys[i].KeyMaterial)
		suite.Equal(testKey.UpdatedAt, responseKeys[i].UpdatedAt)
	}
}

func (suite *UserKeysTestSuite) TestGetKey() {
	testKey := &datastore.DBUserKey{
		AccountID:   suite.account.ID,
		Name:        "wrapping_key",
		KeyMaterial: []byte("test key"),
		UpdatedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
	err := suite.ds.StoreUserKey(testKey)
	suite.Require().NoError(err)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys/wrapping_key", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusOK, resp.Code)

	var responseKey controllers.UserKey
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &responseKey)

	suite.Equal(testKey.Name, responseKey.Name)
	suite.Equal(hex.EncodeToString(testKey.KeyMaterial), responseKey.KeyMaterial)
	suite.Equal(testKey.UpdatedAt, responseKey.UpdatedAt)
}

func (suite *UserKeysTestSuite) TestSaveKey() {
	requestBody := controllers.UserKeyStoreRequest{
		Name:        "wrapping_key",
		KeyMaterial: "0123456789abcdef",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusNoContent, resp.Code)

	// Verify key was stored
	key, err := suite.ds.GetUserKey(suite.account.ID, "wrapping_key")
	suite.Require().NoError(err)
	suite.Equal("wrapping_key", key.Name)
}

func (suite *UserKeysTestSuite) TestSaveKeyInvalidKeyName() {
	requestBody := controllers.UserKeyStoreRequest{
		Name:        "bad_key_name",
		KeyMaterial: "0123456789abcdef",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusBadRequest, resp.Code)
}

func (suite *UserKeysTestSuite) TestSaveKeyInvalidHex() {
	requestBody := controllers.UserKeyStoreRequest{
		Name:        "wrapping_key",
		KeyMaterial: "invalid hex",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusBadRequest, resp.Code)
}

func (suite *UserKeysTestSuite) TestGetKeyNotFound() {
	req := httptest.NewRequest(http.MethodGet, "/v2/keys/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusNotFound, resp.Code)
}
