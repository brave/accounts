package controllers_test

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/brave/accounts/controllers"
	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/bytemare/opaque"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AuthTestSuite struct {
	suite.Suite
	ds           *datastore.Datastore
	jwtService   *services.JWTService
	account      *datastore.Account
	controller   *controllers.AuthController
	router       *chi.Mux
	opaqueConfig *opaque.Configuration
}

func (suite *AuthTestSuite) SetupTest() {
	var err error
	os.Setenv("OPAQUE_SECRET_KEY", "4355f8e6f9ec41649fbcdbcca5075a97dafc4c8d8eb8cc2ba286be7b1c938d05")
	os.Setenv("OPAQUE_PUBLIC_KEY", "98584585210c1f310e9d0aeb9ac1384b7d51808cfaf21b17b5e3dc8d35dbfb00")
	os.Setenv("OPAQUE_FAKE_RECORD", "false")

	suite.ds, err = datastore.NewDatastore(datastore.EmailAuthSessionVersion, true)
	require.NoError(suite.T(), err)
	suite.jwtService, err = services.NewJWTService(suite.ds)
	require.NoError(suite.T(), err)
	opaqueService, err := services.NewOpaqueService(suite.ds)
	require.NoError(suite.T(), err)
	suite.controller = controllers.NewAuthController(opaqueService, suite.jwtService, suite.ds, &MockSESService{})

	suite.account, err = suite.ds.GetOrCreateAccount("test@example.com")
	require.NoError(suite.T(), err)

	suite.opaqueConfig = opaqueService.Config
	opaqueClient, err := opaque.NewClient(opaqueService.Config)
	require.NoError(suite.T(), err)
	registrationReq := opaqueClient.RegistrationInit([]byte("testtest1"))
	registrationResp, err := opaqueService.SetupPasswordInit(suite.account.Email, registrationReq)
	require.NoError(suite.T(), err)
	registrationRec, _ := opaqueClient.RegistrationFinalize(registrationResp, opaque.ClientRegistrationFinalizeOptions{
		ClientIdentity: []byte(suite.account.Email),
	})
	_, err = opaqueService.SetupPasswordFinalize(suite.account.Email, registrationRec)
	require.NoError(suite.T(), err)

	suite.SetupRouter(true)
}

func (suite *AuthTestSuite) SetupRouter(passwordAuthEnabled bool) {
	authMiddleware := middleware.AuthMiddleware(suite.jwtService, suite.ds, datastore.EmailAuthSessionVersion)

	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/auth", suite.controller.Router(authMiddleware, passwordAuthEnabled))
}

func (suite *AuthTestSuite) createLoginFinalizeRequest(opaqueClient *opaque.Client, serializedKE2Hex string) controllers.LoginFinalizeRequest {
	serializedKE2, err := hex.DecodeString(serializedKE2Hex)
	require.NoError(suite.T(), err)
	ke2, err := opaqueClient.Deserialize.KE2(serializedKE2)
	require.NoError(suite.T(), err)
	ke3, _, err := opaqueClient.GenerateKE3(ke2, opaque.GenerateKE3Options{
		ClientIdentity: []byte(suite.account.Email),
	})
	require.NoError(suite.T(), err)
	serializedKE3 := hex.EncodeToString(ke3.Serialize())
	return controllers.LoginFinalizeRequest{
		Mac: &serializedKE3,
	}
}

func (suite *AuthTestSuite) TestAuthValidate() {
	// Create test account session
	session, err := suite.ds.CreateSession(suite.account.ID, datastore.EmailAuthSessionVersion, "")
	require.NoError(suite.T(), err)
	token, err := suite.jwtService.CreateAuthToken(session.ID)
	require.NoError(suite.T(), err)

	// Set up request with session context
	req := httptest.NewRequest("GET", "/v2/auth/validate", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	var parsedResp controllers.ValidateTokenResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)

	assert.Equal(suite.T(), suite.account.Email, parsedResp.Email)
	assert.Equal(suite.T(), suite.account.ID.String(), parsedResp.AccountID)
	assert.Equal(suite.T(), session.ID.String(), parsedResp.SessionID)

	updatedAccount, err := suite.ds.GetOrCreateAccount("test@example.com")
	require.NoError(suite.T(), err)

	assert.Greater(suite.T(), updatedAccount.LastUsedAt, suite.account.LastUsedAt)
}

func (suite *AuthTestSuite) TestAuthValidateBadToken() {
	sessionID, err := uuid.NewV7()
	require.NoError(suite.T(), err)
	token, err := suite.jwtService.CreateAuthToken(sessionID)
	require.NoError(suite.T(), err)

	// Set up request with session context
	req := httptest.NewRequest("GET", "/v2/auth/validate", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)
}

func (suite *AuthTestSuite) TestAuthLogin() {
	opaqueClient, err := opaque.NewClient(suite.opaqueConfig)
	require.NoError(suite.T(), err)

	ke1 := opaqueClient.GenerateKE1([]byte("testtest1"))
	serializedKE1 := hex.EncodeToString(ke1.Serialize())
	loginReq := controllers.LoginInitRequest{
		Email:         suite.account.Email,
		SerializedKE1: &serializedKE1,
	}

	req := util.CreateJSONTestRequest("/v2/auth/login/init", loginReq)

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	var parsedResp controllers.LoginInitResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	require.NotNil(suite.T(), parsedResp.SerializedKE2)
	assert.NotEmpty(suite.T(), parsedResp.AkeToken)

	loginFinalReq := suite.createLoginFinalizeRequest(opaqueClient, *parsedResp.SerializedKE2)

	req = util.CreateJSONTestRequest("/v2/auth/login/finalize", loginFinalReq)
	req.Header.Set("Authorization", "Bearer "+parsedResp.AkeToken)

	resp = util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	var parsedFinalResp controllers.LoginFinalizeResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedFinalResp)
	assert.NotEmpty(suite.T(), parsedFinalResp.AuthToken)

	req = httptest.NewRequest("GET", "/v2/auth/validate", nil)
	req.Header.Add("Authorization", "Bearer "+parsedFinalResp.AuthToken)

	resp = util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusOK, resp.Code)
}

func (suite *AuthTestSuite) TestAuthLoginNoAKEToken() {
	opaqueClient, err := opaque.NewClient(suite.opaqueConfig)
	require.NoError(suite.T(), err)

	ke1 := opaqueClient.GenerateKE1([]byte("testtest1"))
	serializedKE1 := hex.EncodeToString(ke1.Serialize())
	loginReq := controllers.LoginInitRequest{
		Email:         suite.account.Email,
		SerializedKE1: &serializedKE1,
	}

	req := util.CreateJSONTestRequest("/v2/auth/login/init", loginReq)

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	var parsedResp controllers.LoginInitResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	require.NotNil(suite.T(), parsedResp.SerializedKE2)

	loginFinalReq := suite.createLoginFinalizeRequest(opaqueClient, *parsedResp.SerializedKE2)

	req = util.CreateJSONTestRequest("/v2/auth/login/finalize", loginFinalReq)

	resp = util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)
}

func (suite *AuthTestSuite) TestAuthLoginNonexistentEmail() {
	opaqueClient, err := opaque.NewClient(suite.opaqueConfig)
	require.NoError(suite.T(), err)

	ke1 := opaqueClient.GenerateKE1([]byte("testtest1"))
	serializedKE1 := hex.EncodeToString(ke1.Serialize())
	loginReq := controllers.LoginInitRequest{
		Email:         "nonexistent@example.com",
		SerializedKE1: &serializedKE1,
	}

	req := util.CreateJSONTestRequest("/v2/auth/login/init", loginReq)

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrIncorrectEmail.Code)
}

func (suite *AuthTestSuite) TestAuthLoginExpiredAKEToken() {
	opaqueClient, err := opaque.NewClient(suite.opaqueConfig)
	require.NoError(suite.T(), err)

	ke1 := opaqueClient.GenerateKE1([]byte("testtest1"))
	serializedKE1 := hex.EncodeToString(ke1.Serialize())
	loginReq := controllers.LoginInitRequest{
		Email:         suite.account.Email,
		SerializedKE1: &serializedKE1,
	}

	req := util.CreateJSONTestRequest("/v2/auth/login/init", loginReq)

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	var parsedResp controllers.LoginInitResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	require.NotNil(suite.T(), parsedResp.SerializedKE2)
	assert.NotEmpty(suite.T(), parsedResp.AkeToken)

	akeStateID, err := suite.jwtService.ValidateEphemeralAKEToken(parsedResp.AkeToken)
	require.NoError(suite.T(), err)

	err = suite.ds.DB.Model(&datastore.AKEState{}).Where("id = ?", akeStateID).Update("created_at", time.Now().Add(-30*time.Minute)).Error
	require.NoError(suite.T(), err)

	loginFinalReq := suite.createLoginFinalizeRequest(opaqueClient, *parsedResp.SerializedKE2)

	req = util.CreateJSONTestRequest("/v2/auth/login/finalize", loginFinalReq)
	req.Header.Set("Authorization", "Bearer "+parsedResp.AkeToken)

	resp = util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrAKEStateExpired.Code)
}

func (suite *AuthTestSuite) TestPasswordAuthEndpointsDisabled() {
	// Setup router with password auth disabled
	suite.SetupRouter(false)

	// Try accessing password auth endpoints, expect 404s
	resp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/auth/login/init", nil), suite.router)
	suite.Equal(404, resp.Code)

	resp = util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/auth/login/finalize", nil), suite.router)
	suite.Equal(404, resp.Code)

	// Validate endpoint should still work
	resp = util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/auth/validate", nil), suite.router)
	suite.NotEqual(404, resp.Code)
}

func (suite *AuthTestSuite) TestPasswordAuthEndpointsEnabled() {
	// Setup router with password auth enabled
	suite.SetupRouter(true)

	// Try accessing password auth endpoints, expect not-404s
	resp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/auth/login/init", nil), suite.router)
	suite.NotEqual(404, resp.Code)

	resp = util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/auth/login/finalize", nil), suite.router)
	suite.NotEqual(404, resp.Code)

	// Validate endpoint should work
	resp = util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/auth/validate", nil), suite.router)
	suite.NotEqual(404, resp.Code)
}

func TestAuthTestSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}
