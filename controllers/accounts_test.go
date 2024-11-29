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
	"github.com/stretchr/testify/suite"
)

type AccountsTestSuite struct {
	suite.Suite
	ds           *datastore.Datastore
	jwtService   *services.JWTService
	router       *chi.Mux
	opaqueClient *opaque.Client
	controller   *controllers.AccountsController
}

func (suite *AccountsTestSuite) SetupTest() {
	var err error
	os.Setenv("OPAQUE_SECRET_KEY", "4355f8e6f9ec41649fbcdbcca5075a97dafc4c8d8eb8cc2ba286be7b1c938d05")
	os.Setenv("OPAQUE_PUBLIC_KEY", "98584585210c1f310e9d0aeb9ac1384b7d51808cfaf21b17b5e3dc8d35dbfb00")

	suite.ds, err = datastore.NewDatastore(datastore.EmailAuthSessionVersion, true)
	suite.Require().NoError(err)
	suite.jwtService, err = services.NewJWTService(suite.ds)
	suite.Require().NoError(err)
	opaqueService, err := services.NewOpaqueService(suite.ds)
	suite.Require().NoError(err)
	suite.controller = controllers.NewAccountsController(opaqueService, suite.jwtService, suite.ds)

	suite.opaqueClient, err = opaque.NewClient(opaqueService.Config)
	suite.Require().NoError(err)

	suite.SetupRouter(true)
}

func (suite *AccountsTestSuite) TearDownTest() {
	suite.ds.Close()
}

func (suite *AccountsTestSuite) SetupRouter(accountDeletionEnabled bool) {
	authMiddleware := middleware.AuthMiddleware(suite.jwtService, suite.ds, datastore.EmailAuthSessionVersion)
	verificationAuthMiddleware := middleware.VerificationAuthMiddleware(suite.jwtService, suite.ds)
	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/accounts", suite.controller.Router(verificationAuthMiddleware, authMiddleware, accountDeletionEnabled))
}

func (suite *AccountsTestSuite) TestSetPassword() {
	// Create verification
	verification, err := suite.ds.CreateVerification("test@example.com", "accounts", "registration")
	suite.Require().NoError(err)
	_, err = suite.ds.UpdateAndGetVerificationStatus(verification.ID, verification.Code)
	suite.Require().NoError(err)

	// Get verification token
	token, err := suite.jwtService.CreateVerificationToken(verification.ID, time.Minute*30, verification.Service)
	suite.Require().NoError(err)

	registrationReq := suite.opaqueClient.RegistrationInit([]byte("testtest1"))

	// Test password init
	req := util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
		BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
		SerializeResponse: true,
	})
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedResp controllers.RegistrationResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	suite.NotNil(parsedResp.SerializedResponse)
	serializedRegistationResp, err := hex.DecodeString(*parsedResp.SerializedResponse)
	suite.Require().NoError(err)
	registrationResp, err := suite.opaqueClient.Deserialize.RegistrationResponse(serializedRegistationResp)
	suite.Require().NoError(err)

	registrationRecord, _ := suite.opaqueClient.RegistrationFinalize(registrationResp, opaque.ClientRegistrationFinalizeOptions{
		ClientIdentity: []byte(verification.Email),
	})
	serializedRecord := hex.EncodeToString(registrationRecord.Serialize())

	// Test password finalize
	req = util.CreateJSONTestRequest("/v2/accounts/password/finalize", controllers.RegistrationRecord{
		SerializedRecord: &serializedRecord,
	})
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedFinalizeResp controllers.PasswordFinalizeResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedFinalizeResp)
	suite.NotEmpty(parsedFinalizeResp.AuthToken)

	// Validate auth token
	sessionID, err := suite.jwtService.ValidateAuthToken(parsedFinalizeResp.AuthToken)
	suite.NoError(err)
	suite.NotNil(sessionID)

	account, err := suite.ds.GetAccount(nil, verification.Email)
	suite.Require().NoError(err)
	suite.NotNil(account.OprfSeedID)
	suite.NotEmpty(account.OpaqueRegistration)

	// Should not be able to set password again
	req = util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
		BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
		SerializeResponse: true,
	})
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNotFound, resp.Code)
}

func (suite *AccountsTestSuite) TestSetPasswordBadIntents() {
	intents := []string{"verification", "auth_token"}

	for _, intent := range intents {
		verification, err := suite.ds.CreateVerification("test@example.com", "accounts", intent)
		suite.Require().NoError(err)
		_, err = suite.ds.UpdateAndGetVerificationStatus(verification.ID, verification.Code)
		suite.Require().NoError(err)

		token, err := suite.jwtService.CreateVerificationToken(verification.ID, time.Minute*30, verification.Service)
		suite.Require().NoError(err)

		registrationReq := suite.opaqueClient.RegistrationInit([]byte("testtest1"))

		req := util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
			BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
			SerializeResponse: true,
		})
		req.Header.Set("Authorization", "Bearer "+token)

		resp := util.ExecuteTestRequest(req, suite.router)
		suite.Equal(http.StatusForbidden, resp.Code)
		util.AssertErrorResponseCode(suite.T(), resp, util.ErrIncorrectVerificationIntent.Code)
	}
}

func (suite *AccountsTestSuite) TestSetPasswordUnverifiedEmail() {
	// Create unverified verification
	verification, err := suite.ds.CreateVerification("test@example.com", "accounts", "password_setup")
	suite.Require().NoError(err)

	// Get verification token
	token, err := suite.jwtService.CreateVerificationToken(verification.ID, time.Minute*30, verification.Service)
	suite.Require().NoError(err)

	registrationReq := suite.opaqueClient.RegistrationInit([]byte("testtest1"))

	// Test password init with unverified email
	req := util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
		BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
		SerializeResponse: true,
	})
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusForbidden, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrEmailNotVerified.Code)
}

func (suite *AccountsTestSuite) TestDeleteAccount() {
	// Create test account
	account, err := suite.ds.GetOrCreateAccount("test@example.com")
	suite.Require().NoError(err)
	// Create test account session
	session, err := suite.ds.CreateSession(account.ID, datastore.EmailAuthSessionVersion, "")
	suite.Require().NoError(err)
	token, err := suite.jwtService.CreateAuthToken(session.ID)
	suite.Require().NoError(err)

	// Test account deletion
	req := httptest.NewRequest("DELETE", "/v2/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNoContent, resp.Code)

	var sessionCount int64
	err = suite.ds.DB.Model(&datastore.Session{}).Where("id = ?", session.ID).Count(&sessionCount).Error
	suite.Require().NoError(err)
	suite.Equal(int64(0), sessionCount)

	var accountCount int64
	err = suite.ds.DB.Model(&datastore.Account{}).Where("id = ?", account.ID).Count(&accountCount).Error
	suite.Require().NoError(err)
	suite.Equal(int64(0), accountCount)
}

func (suite *AccountsTestSuite) TestAccountDeletionEndpointDisabled() {
	// Setup router with account deletion disabled
	suite.SetupRouter(false)

	// Try accessing delete endpoint, expect 404
	req := httptest.NewRequest("DELETE", "/v2/accounts", nil)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(404, resp.Code)

	// Password setup endpoints should still work
	initReq := httptest.NewRequest("POST", "/v2/accounts/password/init", nil)
	resp = util.ExecuteTestRequest(initReq, suite.router)
	suite.NotEqual(404, resp.Code)

	finalizeReq := httptest.NewRequest("POST", "/v2/accounts/password/finalize", nil)
	resp = util.ExecuteTestRequest(finalizeReq, suite.router)
	suite.NotEqual(404, resp.Code)
}

func (suite *AccountsTestSuite) TestAccountDeletionEndpointEnabled() {
	// Setup router with account deletion enabled
	suite.SetupRouter(true)

	// Try accessing delete endpoint, expect not-404
	req := httptest.NewRequest("DELETE", "/v2/accounts", nil)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.NotEqual(404, resp.Code)

	// Password setup endpoints should work
	initReq := httptest.NewRequest("POST", "/v2/accounts/password/init", nil)
	resp = util.ExecuteTestRequest(initReq, suite.router)
	suite.NotEqual(404, resp.Code)

	finalizeReq := httptest.NewRequest("POST", "/v2/accounts/password/finalize", nil)
	resp = util.ExecuteTestRequest(finalizeReq, suite.router)
	suite.NotEqual(404, resp.Code)
}

func TestAccountsTestSuite(t *testing.T) {
	suite.Run(t, new(AccountsTestSuite))
}
