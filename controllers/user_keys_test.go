package controllers_test

import (
	"encoding/hex"
	"fmt"
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
	suite.ds, err = datastore.NewDatastore(datastore.PasswordAuthSessionVersion, false, true)
	suite.Require().NoError(err)

	jwtService, err := services.NewJWTService(suite.ds, false)
	suite.Require().NoError(err)

	suite.account, err = suite.ds.GetOrCreateAccount("test@example.com")
	suite.Require().NoError(err)
	err = suite.ds.UpdateAccountLastEmailVerifiedAt(suite.account.ID)
	suite.Require().NoError(err)

	otherAccount, err := suite.ds.GetOrCreateAccount("test2@example.com")
	suite.Require().NoError(err)
	err = suite.ds.UpdateAccountLastEmailVerifiedAt(otherAccount.ID)
	suite.Require().NoError(err)

	otherTestKey := datastore.DBUserKey{
		AccountID:   otherAccount.ID,
		Service:     "accounts",
		KeyName:     "wrapping_key",
		KeyMaterial: []byte("test key 10"),
		UpdatedAt:   time.Now().UTC(),
	}
	err = suite.ds.StoreUserKey(&otherTestKey)
	suite.Require().NoError(err)

	controller := controllers.NewUserKeysController(suite.ds)
	authMiddleware := middleware.AuthMiddleware(jwtService, suite.ds, datastore.EmailAuthSessionVersion, true, true)

	session, err := suite.ds.CreateSession(suite.account.ID, datastore.PasswordAuthSessionVersion, "")
	suite.Require().NoError(err)
	suite.authToken, err = jwtService.CreateAuthToken(session.ID, nil, util.AccountsServiceName)
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
			Service:     "accounts",
			KeyName:     "wrapping_key",
			KeyMaterial: []byte("test key 1"),
			UpdatedAt:   updatedTime,
		},
		{
			AccountID:   suite.account.ID,
			Service:     "sync",
			KeyName:     "enc_seed",
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
		suite.Equal(testKey.Service, responseKeys[i].Service)
		suite.Equal(testKey.KeyName, responseKeys[i].KeyName)
		suite.Equal(hex.EncodeToString(testKey.KeyMaterial), responseKeys[i].KeyMaterial)
		suite.Equal(1, responseKeys[i].SerialNumber) // New keys start at 1
		suite.Equal(testKey.UpdatedAt, responseKeys[i].UpdatedAt)
	}
}

func (suite *UserKeysTestSuite) TestGetKey() {
	testKey := &datastore.DBUserKey{
		AccountID:   suite.account.ID,
		Service:     "accounts",
		KeyName:     "wrapping_key",
		KeyMaterial: []byte("test key"),
		UpdatedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
	err := suite.ds.StoreUserKey(testKey)
	suite.Require().NoError(err)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys/accounts/wrapping_key", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusOK, resp.Code)

	var responseKey controllers.UserKey
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &responseKey)

	suite.Equal(testKey.Service, responseKey.Service)
	suite.Equal(testKey.KeyName, responseKey.KeyName)
	suite.Equal(hex.EncodeToString(testKey.KeyMaterial), responseKey.KeyMaterial)
	suite.Equal(1, responseKey.SerialNumber) // New key starts at 1
	suite.Equal(testKey.UpdatedAt, responseKey.UpdatedAt)

	// Test that the key cannot be retrieved using a different service name
	req = httptest.NewRequest(http.MethodGet, "/v2/keys/sync/wrapping_key", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp = util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusNotFound, resp.Code)
}

func (suite *UserKeysTestSuite) TestSaveKey() {
	requestBody := controllers.UserKeyStoreRequest{
		Service:     "accounts",
		KeyName:     "wrapping_key",
		KeyMaterial: "0123456789abcdef",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusNoContent, resp.Code)

	// Verify key was stored
	key, err := suite.ds.GetUserKey(suite.account.ID, "accounts", "wrapping_key")
	suite.Require().NoError(err)
	suite.Equal("accounts", key.Service)
	suite.Equal("wrapping_key", key.KeyName)
}

func (suite *UserKeysTestSuite) TestSaveKeyInvalidService() {
	requestBody := controllers.UserKeyStoreRequest{
		Service:     "invalid_service",
		KeyName:     "wrapping_key",
		KeyMaterial: "0123456789abcdef",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusBadRequest, resp.Code)
}

func (suite *UserKeysTestSuite) TestSaveKeyInvalidHex() {
	requestBody := controllers.UserKeyStoreRequest{
		Service:     "accounts",
		KeyName:     "wrapping_key",
		KeyMaterial: "invalid hex",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusBadRequest, resp.Code)
}

func (suite *UserKeysTestSuite) TestSaveKeyNameTooLong() {
	requestBody := controllers.UserKeyStoreRequest{
		Service:     "accounts",
		KeyName:     "this_key_name_is_way_too_long_and_exceeds_the_thirty_two_character_limit",
		KeyMaterial: "0123456789abcdef",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusBadRequest, resp.Code)
}

func (suite *UserKeysTestSuite) TestGetKeyNotFound() {
	req := httptest.NewRequest(http.MethodGet, "/v2/keys/accounts/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusNotFound, resp.Code)
}

func (suite *UserKeysTestSuite) createMaxKeys(service string) {
	requestBody := controllers.UserKeyStoreRequest{
		Service:     service,
		KeyMaterial: "0123456789abcdef",
	}

	for i := 0; i < datastore.MaxUserKeysPerService; i++ {
		requestBody.KeyName = fmt.Sprintf("test_key_%d", i)

		req := util.CreateJSONTestRequest("/v2/keys", requestBody)
		req.Header.Set("Authorization", "Bearer "+suite.authToken)
		resp := util.ExecuteTestRequest(req, suite.router)

		suite.Equal(http.StatusNoContent, resp.Code)
	}
}

func (suite *UserKeysTestSuite) TestSaveKeyLimitExceeded() {
	// First, store some keys for a different service to ensure per-service isolation
	suite.createMaxKeys("sync")

	// Now store MaxUserKeysPerService keys for the accounts service
	suite.createMaxKeys("accounts")

	// Try to store one more key for accounts service - should fail
	requestBody := controllers.UserKeyStoreRequest{
		Service:     "accounts",
		KeyName:     "key_excess",
		KeyMaterial: "0123456789abcdef",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrMaxUserKeysExceeded.Code)
}

func (suite *UserKeysTestSuite) TestUpdateExistingKey() {
	// Store MaxUserKeysPerService keys for accounts service
	suite.createMaxKeys("accounts")

	// Update the first key - should succeed
	requestBody := controllers.UserKeyStoreRequest{
		Service:     "accounts",
		KeyName:     "test_key_0",
		KeyMaterial: "fedcba9876543210",
	}

	req := util.CreateJSONTestRequest("/v2/keys", requestBody)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusNoContent, resp.Code)

	// Verify the key was updated
	req = httptest.NewRequest(http.MethodGet, "/v2/keys/accounts/test_key_0", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp = util.ExecuteTestRequest(req, suite.router)

	suite.Equal(http.StatusOK, resp.Code)

	var responseKey controllers.UserKey
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &responseKey)

	suite.Equal(requestBody.Service, responseKey.Service)
	suite.Equal(requestBody.KeyName, responseKey.KeyName)
	suite.Equal(requestBody.KeyMaterial, responseKey.KeyMaterial)
	suite.Equal(2, responseKey.SerialNumber) // Should be 2 since key was updated
}

func (suite *UserKeysTestSuite) TestSerialNumberIncrement() {
	// Create two keys with the same name but different services
	accountsKey := controllers.UserKeyStoreRequest{
		Service:     "accounts",
		KeyName:     "test_serial",
		KeyMaterial: "0123456789abcdef",
	}

	emailAliasesKey := controllers.UserKeyStoreRequest{
		Service:     "email-aliases",
		KeyName:     "test_serial",
		KeyMaterial: "fedcba9876543210",
	}

	// Store the accounts key
	req := util.CreateJSONTestRequest("/v2/keys", accountsKey)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNoContent, resp.Code)

	// Store the email-aliases key
	req = util.CreateJSONTestRequest("/v2/keys", emailAliasesKey)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNoContent, resp.Code)

	// Retrieve both keys and verify they both have serial number 1
	req = httptest.NewRequest(http.MethodGet, "/v2/keys/accounts/test_serial", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var accountsResponse controllers.UserKey
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &accountsResponse)
	suite.Equal(1, accountsResponse.SerialNumber)
	suite.Equal("0123456789abcdef", accountsResponse.KeyMaterial)

	req = httptest.NewRequest(http.MethodGet, "/v2/keys/email-aliases/test_serial", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var emailAliasesResponse controllers.UserKey
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &emailAliasesResponse)
	suite.Equal(1, emailAliasesResponse.SerialNumber)
	suite.Equal("fedcba9876543210", emailAliasesResponse.KeyMaterial)

	// Update the accounts key
	accountsKey.KeyMaterial = "1111111111111111"
	req = util.CreateJSONTestRequest("/v2/keys", accountsKey)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNoContent, resp.Code)

	// Verify accounts key serial number incremented to 2
	req = httptest.NewRequest(http.MethodGet, "/v2/keys/accounts/test_serial", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &accountsResponse)
	suite.Equal(2, accountsResponse.SerialNumber)
	suite.Equal("1111111111111111", accountsResponse.KeyMaterial)

	// Verify email-aliases key is unchanged with serial number still 1
	req = httptest.NewRequest(http.MethodGet, "/v2/keys/email-aliases/test_serial", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &emailAliasesResponse)
	suite.Equal(1, emailAliasesResponse.SerialNumber)
	suite.Equal("fedcba9876543210", emailAliasesResponse.KeyMaterial)

	// Update the email-aliases key
	emailAliasesKey.KeyMaterial = "2222222222222222"
	req = util.CreateJSONTestRequest("/v2/keys", emailAliasesKey)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNoContent, resp.Code)

	// Verify email-aliases key serial number incremented to 2
	req = httptest.NewRequest(http.MethodGet, "/v2/keys/email-aliases/test_serial", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &emailAliasesResponse)
	suite.Equal(2, emailAliasesResponse.SerialNumber)
	suite.Equal("2222222222222222", emailAliasesResponse.KeyMaterial)

	// Verify accounts key is still unchanged with serial number 2
	req = httptest.NewRequest(http.MethodGet, "/v2/keys/accounts/test_serial", nil)
	req.Header.Set("Authorization", "Bearer "+suite.authToken)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &accountsResponse)
	suite.Equal(2, accountsResponse.SerialNumber)
	suite.Equal("1111111111111111", accountsResponse.KeyMaterial)
}
