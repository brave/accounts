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
	"github.com/bytemare/opaque"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

type AuthTestSuite struct {
	suite.Suite
	useKeyService bool
	ds            *datastore.Datastore
	keyServiceDs  *datastore.Datastore
	jwtService    *services.JWTService
	account       *datastore.Account
	controller    *controllers.AuthController
	router        *chi.Mux
	opaqueConfig  *opaque.Configuration
}

func NewAuthTestSuite(useKeyService bool) *AuthTestSuite {
	return &AuthTestSuite{
		useKeyService: useKeyService,
	}
}

func (suite *AuthTestSuite) SetupTest() {
	var err error
	suite.T().Setenv("OPAQUE_SECRET_KEY", "4355f8e6f9ec41649fbcdbcca5075a97dafc4c8d8eb8cc2ba286be7b1c938d05")
	suite.T().Setenv("OPAQUE_PUBLIC_KEY", "98584585210c1f310e9d0aeb9ac1384b7d51808cfaf21b17b5e3dc8d35dbfb00")
	suite.T().Setenv("OPAQUE_FAKE_RECORD", "false")

	suite.ds, err = datastore.NewDatastore(datastore.EmailAuthSessionVersion, false, true)
	suite.Require().NoError(err)

	if suite.useKeyService {
		initKeyServiceForTest(suite.T(), &suite.keyServiceDs, suite.ds)
	}

	suite.jwtService, err = services.NewJWTService(suite.ds, false)
	suite.Require().NoError(err)
	opaqueService, err := services.NewOpaqueService(suite.ds, false)
	suite.Require().NoError(err)
	suite.controller = controllers.NewAuthController(opaqueService, suite.jwtService, suite.ds, &MockSESService{})

	suite.account, err = suite.ds.GetOrCreateAccount("test@example.com")
	suite.Require().NoError(err)

	suite.opaqueConfig = opaqueService.Config
	opaqueClient, err := opaque.NewClient(opaqueService.Config)
	suite.Require().NoError(err)
	registrationReq := opaqueClient.RegistrationInit([]byte("testtest1"))
	registrationResp, err := opaqueService.SetupPasswordInit(suite.account.Email, registrationReq)
	suite.Require().NoError(err)
	registrationRec, _ := opaqueClient.RegistrationFinalize(registrationResp, opaque.ClientRegistrationFinalizeOptions{
		ClientIdentity: []byte(suite.account.Email),
	})
	_, err = opaqueService.SetupPasswordFinalize(suite.account.Email, registrationRec)
	suite.Require().NoError(err)

	suite.SetupRouter(true)
}

func (suite *AuthTestSuite) TearDownTest() {
	suite.ds.Close()
	if suite.keyServiceDs != nil {
		suite.keyServiceDs.Close()
	}
	util.TestKeyServiceRouter = nil
}

func (suite *AuthTestSuite) SetupRouter(passwordAuthEnabled bool) {
	permissiveAuthMiddleware := middleware.AuthMiddleware(suite.jwtService, suite.ds, datastore.EmailAuthSessionVersion, false)
	authMiddleware := middleware.AuthMiddleware(suite.jwtService, suite.ds, datastore.EmailAuthSessionVersion, true)

	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/auth", suite.controller.Router(authMiddleware, permissiveAuthMiddleware, passwordAuthEnabled))
}

func (suite *AuthTestSuite) createLoginFinalizeRequest(opaqueClient *opaque.Client, serializedKE2Hex string) controllers.LoginFinalizeRequest {
	serializedKE2, err := hex.DecodeString(serializedKE2Hex)
	suite.Require().NoError(err)
	ke2, err := opaqueClient.Deserialize.KE2(serializedKE2)
	suite.Require().NoError(err)
	ke3, _, err := opaqueClient.GenerateKE3(ke2, opaque.GenerateKE3Options{
		ClientIdentity: []byte(suite.account.Email),
	})
	suite.Require().NoError(err)
	serializedKE3 := hex.EncodeToString(ke3.Serialize())
	return controllers.LoginFinalizeRequest{
		Mac: &serializedKE3,
	}
}

func (suite *AuthTestSuite) TestAuthValidate() {
	// Create test account session
	session, err := suite.ds.CreateSession(suite.account.ID, datastore.EmailAuthSessionVersion, "")
	suite.Require().NoError(err)
	token, err := suite.jwtService.CreateAuthToken(session.ID, nil, util.AccountsServiceName)
	suite.Require().NoError(err)

	childToken, err := suite.jwtService.CreateAuthToken(session.ID, nil, util.EmailAliasesServiceName)
	suite.Require().NoError(err)

	// Set up request with session context
	req := httptest.NewRequest("GET", "/v2/auth/validate", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedResp controllers.ValidateTokenResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)

	suite.Equal(suite.account.Email, parsedResp.Email)
	suite.Equal(suite.account.ID.String(), parsedResp.AccountID)
	suite.Equal(session.ID.String(), parsedResp.SessionID)
	suite.Equal(util.AccountsServiceName, parsedResp.Service)

	updatedAccount, err := suite.ds.GetOrCreateAccount("test@example.com")
	suite.Require().NoError(err)

	suite.Greater(updatedAccount.LastUsedAt, suite.account.LastUsedAt)

	req = httptest.NewRequest("GET", "/v2/auth/validate", nil)
	req.Header.Add("Authorization", "Bearer "+childToken)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)

	suite.Equal(suite.account.Email, parsedResp.Email)
	suite.Equal(suite.account.ID.String(), parsedResp.AccountID)
	suite.Equal(session.ID.String(), parsedResp.SessionID)
	suite.Equal(util.EmailAliasesServiceName, parsedResp.Service)
}

func (suite *AuthTestSuite) TestAuthValidateBadToken() {
	sessionID, err := uuid.NewV7()
	suite.Require().NoError(err)
	token, err := suite.jwtService.CreateAuthToken(sessionID, nil, util.AccountsServiceName)
	suite.Require().NoError(err)

	// Set up request with session context
	req := httptest.NewRequest("GET", "/v2/auth/validate", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusUnauthorized, resp.Code)
}

func (suite *AuthTestSuite) TestAuthLogin() {
	opaqueClient, err := opaque.NewClient(suite.opaqueConfig)
	suite.Require().NoError(err)

	ke1 := opaqueClient.GenerateKE1([]byte("testtest1"))
	serializedKE1 := hex.EncodeToString(ke1.Serialize())
	loginReq := controllers.LoginInitRequest{
		Email:         suite.account.Email,
		SerializedKE1: &serializedKE1,
	}

	req := util.CreateJSONTestRequest("/v2/auth/login/init", loginReq)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedResp controllers.LoginInitResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	suite.NotNil(parsedResp.SerializedKE2)
	suite.NotEmpty(parsedResp.AkeToken)

	loginFinalReq := suite.createLoginFinalizeRequest(opaqueClient, *parsedResp.SerializedKE2)

	req = util.CreateJSONTestRequest("/v2/auth/login/finalize", loginFinalReq)
	req.Header.Set("Authorization", "Bearer "+parsedResp.AkeToken)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedFinalResp controllers.LoginFinalizeResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedFinalResp)
	suite.NotEmpty(parsedFinalResp.AuthToken)

	req = httptest.NewRequest("GET", "/v2/auth/validate", nil)
	req.Header.Add("Authorization", "Bearer "+parsedFinalResp.AuthToken)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)
}

func (suite *AuthTestSuite) TestAuthLoginNoAKEToken() {
	opaqueClient, err := opaque.NewClient(suite.opaqueConfig)
	suite.Require().NoError(err)

	ke1 := opaqueClient.GenerateKE1([]byte("testtest1"))
	serializedKE1 := hex.EncodeToString(ke1.Serialize())
	loginReq := controllers.LoginInitRequest{
		Email:         suite.account.Email,
		SerializedKE1: &serializedKE1,
	}

	req := util.CreateJSONTestRequest("/v2/auth/login/init", loginReq)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedResp controllers.LoginInitResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	suite.NotNil(parsedResp.SerializedKE2)

	loginFinalReq := suite.createLoginFinalizeRequest(opaqueClient, *parsedResp.SerializedKE2)

	req = util.CreateJSONTestRequest("/v2/auth/login/finalize", loginFinalReq)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusUnauthorized, resp.Code)
}

func (suite *AuthTestSuite) TestAuthLoginNonexistentEmail() {
	opaqueClient, err := opaque.NewClient(suite.opaqueConfig)
	suite.Require().NoError(err)

	ke1 := opaqueClient.GenerateKE1([]byte("testtest1"))
	serializedKE1 := hex.EncodeToString(ke1.Serialize())
	loginReq := controllers.LoginInitRequest{
		Email:         "nonexistent@example.com",
		SerializedKE1: &serializedKE1,
	}

	req := util.CreateJSONTestRequest("/v2/auth/login/init", loginReq)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusUnauthorized, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrIncorrectEmail.Code)
}

func (suite *AuthTestSuite) TestAuthLoginExpiredAKEToken() {
	opaqueClient, err := opaque.NewClient(suite.opaqueConfig)
	suite.Require().NoError(err)

	ke1 := opaqueClient.GenerateKE1([]byte("testtest1"))
	serializedKE1 := hex.EncodeToString(ke1.Serialize())
	loginReq := controllers.LoginInitRequest{
		Email:         suite.account.Email,
		SerializedKE1: &serializedKE1,
	}

	req := util.CreateJSONTestRequest("/v2/auth/login/init", loginReq)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedResp controllers.LoginInitResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	suite.NotNil(parsedResp.SerializedKE2)
	suite.NotEmpty(parsedResp.AkeToken)

	akeStateID, err := suite.jwtService.ValidateEphemeralAKEToken(parsedResp.AkeToken)
	suite.Require().NoError(err)

	err = suite.ds.DB.Model(&datastore.AKEState{}).Where("id = ?", akeStateID).Update("created_at", time.Now().Add(-30*time.Minute)).Error
	suite.Require().NoError(err)

	loginFinalReq := suite.createLoginFinalizeRequest(opaqueClient, *parsedResp.SerializedKE2)

	req = util.CreateJSONTestRequest("/v2/auth/login/finalize", loginFinalReq)
	req.Header.Set("Authorization", "Bearer "+parsedResp.AkeToken)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusUnauthorized, resp.Code)
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

func (suite *AuthTestSuite) TestCreateServiceToken() {
	// Create test session and token
	session, err := suite.ds.CreateSession(suite.account.ID, datastore.EmailAuthSessionVersion, "")
	suite.Require().NoError(err)
	token, err := suite.jwtService.CreateAuthToken(session.ID, nil, util.AccountsServiceName)
	suite.Require().NoError(err)

	// Test creating email-aliases service token
	req := util.CreateJSONTestRequest("/v2/auth/service_token", controllers.CreateServiceTokenRequest{
		Service: util.EmailAliasesServiceName,
	})
	req.Header.Set("Authorization", "Bearer "+token)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedResp controllers.CreateServiceTokenResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	suite.NotEmpty(parsedResp.AuthToken)

	// Parse and verify the auth token
	parser := jwt.NewParser()
	claims := make(jwt.MapClaims)
	_, _, err = parser.ParseUnverified(parsedResp.AuthToken, &claims)
	suite.NoError(err)

	// Check expiration time (14 days from now)
	expectedExp := time.Now().Add(14 * 24 * time.Hour).Unix()
	suite.InDelta(expectedExp, claims["exp"].(float64), 60) // Allow 60 seconds tolerance

	// Verify audience
	suite.Equal(util.EmailAliasesServiceName, claims["aud"])

	// Validate the created service token
	validateReq := httptest.NewRequest("GET", "/v2/auth/validate", nil)
	validateReq.Header.Add("Authorization", "Bearer "+parsedResp.AuthToken)
	validateResp := util.ExecuteTestRequest(validateReq, suite.router)
	suite.Equal(http.StatusOK, validateResp.Code)

	var validateParsedResp controllers.ValidateTokenResponse
	util.DecodeJSONTestResponse(suite.T(), validateResp.Body, &validateParsedResp)
	suite.Equal(suite.account.Email, validateParsedResp.Email)
	suite.Equal(suite.account.ID.String(), validateParsedResp.AccountID)
	suite.Equal(session.ID.String(), validateParsedResp.SessionID)
	suite.Equal(util.EmailAliasesServiceName, validateParsedResp.Service)

	req = util.CreateJSONTestRequest("/v2/auth/service_token", controllers.CreateServiceTokenRequest{
		Service: util.EmailAliasesServiceName,
	})
	req.Header.Set("Authorization", "Bearer "+parsedResp.AuthToken)
	// Test unauthorized request using a service token instead of an accounts auth token
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusForbidden, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrInvalidTokenAudience.Code)

	// Test TLD in 'strict' list
	ruAccount, err := suite.ds.GetOrCreateAccount("test@example.ru")
	suite.Require().NoError(err)
	session, err = suite.ds.CreateSession(ruAccount.ID, datastore.EmailAuthSessionVersion, "")
	suite.Require().NoError(err)
	token, err = suite.jwtService.CreateAuthToken(session.ID, nil, util.AccountsServiceName)
	suite.Require().NoError(err)

	req = util.CreateJSONTestRequest("/v2/auth/service_token", controllers.CreateServiceTokenRequest{
		Service: util.EmailAliasesServiceName,
	})
	req.Header.Set("Authorization", "Bearer "+token)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrEmailDomainNotSupported.Code)
}

func TestAuthTestSuite(t *testing.T) {
	t.Run("NoKeyService", func(t *testing.T) {
		suite.Run(t, NewAuthTestSuite(false))
	})
	t.Run("WithKeyService", func(t *testing.T) {
		suite.Run(t, NewAuthTestSuite(true))
	})
}
