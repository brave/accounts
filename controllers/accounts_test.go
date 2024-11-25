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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AccountsTestSuite struct {
	suite.Suite
	ds           *datastore.Datastore
	jwtService   *services.JWTService
	router       *chi.Mux
	opaqueClient *opaque.Client
}

func (suite *AccountsTestSuite) SetupTest() {
	var err error
	os.Setenv("OPAQUE_SECRET_KEY", "4355f8e6f9ec41649fbcdbcca5075a97dafc4c8d8eb8cc2ba286be7b1c938d05")
	os.Setenv("OPAQUE_PUBLIC_KEY", "98584585210c1f310e9d0aeb9ac1384b7d51808cfaf21b17b5e3dc8d35dbfb00")

	suite.ds, err = datastore.NewDatastore(datastore.EmailAuthSessionVersion, true)
	require.NoError(suite.T(), err)
	suite.jwtService, err = services.NewJWTService(suite.ds)
	require.NoError(suite.T(), err)
	opaqueService, err := services.NewOpaqueService(suite.ds)
	require.NoError(suite.T(), err)
	controller := controllers.NewAccountsController(opaqueService, suite.jwtService, suite.ds)

	suite.opaqueClient, err = opaque.NewClient(opaqueService.Config)
	require.NoError(suite.T(), err)

	authMiddleware := middleware.AuthMiddleware(suite.jwtService, suite.ds, datastore.EmailAuthSessionVersion)
	verificationAuthMiddleware := middleware.VerificationAuthMiddleware(suite.jwtService, suite.ds)

	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/accounts", controller.Router(verificationAuthMiddleware, authMiddleware))
}

func (suite *AccountsTestSuite) TestSetPassword() {
	// Create verification
	verification, err := suite.ds.CreateVerification("test@example.com", "accounts", "registration")
	require.NoError(suite.T(), err)
	_, err = suite.ds.UpdateAndGetVerificationStatus(verification.ID, verification.Code)
	require.NoError(suite.T(), err)

	// Get verification token
	token, err := suite.jwtService.CreateVerificationToken(verification.ID, time.Minute*30, verification.Service)
	require.NoError(suite.T(), err)

	registrationReq := suite.opaqueClient.RegistrationInit([]byte("testtest1"))

	// Test password init
	req := util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
		BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
		SerializeResponse: true,
	})
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	var parsedResp controllers.RegistrationResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	assert.NotNil(suite.T(), parsedResp.SerializedResponse)
	serializedRegistationResp, err := hex.DecodeString(*parsedResp.SerializedResponse)
	require.NoError(suite.T(), err)
	registrationResp, err := suite.opaqueClient.Deserialize.RegistrationResponse(serializedRegistationResp)
	require.NoError(suite.T(), err)

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
	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	var parsedFinalizeResp controllers.PasswordFinalizeResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedFinalizeResp)
	assert.NotEmpty(suite.T(), parsedFinalizeResp.AuthToken)

	// Validate auth token
	sessionID, err := suite.jwtService.ValidateAuthToken(parsedFinalizeResp.AuthToken)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), sessionID)

	account, err := suite.ds.GetAccount(nil, verification.Email)
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), account.OprfSeedID)
	assert.NotEmpty(suite.T(), account.OpaqueRegistration)

	// Should not be able to set password again
	req = util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
		BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
		SerializeResponse: true,
	})
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusNotFound, resp.Code)
}

func (suite *AccountsTestSuite) TestSetPasswordBadIntents() {
	intents := []string{"verification", "auth_token"}

	for _, intent := range intents {
		verification, err := suite.ds.CreateVerification("test@example.com", "accounts", intent)
		require.NoError(suite.T(), err)
		_, err = suite.ds.UpdateAndGetVerificationStatus(verification.ID, verification.Code)
		require.NoError(suite.T(), err)

		token, err := suite.jwtService.CreateVerificationToken(verification.ID, time.Minute*30, verification.Service)
		require.NoError(suite.T(), err)

		registrationReq := suite.opaqueClient.RegistrationInit([]byte("testtest1"))

		req := util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
			BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
			SerializeResponse: true,
		})
		req.Header.Set("Authorization", "Bearer "+token)

		resp := util.ExecuteTestRequest(req, suite.router)
		assert.Equal(suite.T(), http.StatusForbidden, resp.Code)
		util.AssertErrorResponseCode(suite.T(), resp, util.ErrIncorrectVerificationIntent.Code)
	}
}

func (suite *AccountsTestSuite) TestSetPasswordUnverifiedEmail() {
	// Create unverified verification
	verification, err := suite.ds.CreateVerification("test@example.com", "accounts", "password_setup")
	require.NoError(suite.T(), err)

	// Get verification token
	token, err := suite.jwtService.CreateVerificationToken(verification.ID, time.Minute*30, verification.Service)
	require.NoError(suite.T(), err)

	registrationReq := suite.opaqueClient.RegistrationInit([]byte("testtest1"))

	// Test password init with unverified email
	req := util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
		BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
		SerializeResponse: true,
	})
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusForbidden, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrEmailNotVerified.Code)
}

func (suite *AccountsTestSuite) TestDeleteAccount() {
	// Create test account
	account, err := suite.ds.GetOrCreateAccount("test@example.com")
	require.NoError(suite.T(), err)
	// Create test account session
	session, err := suite.ds.CreateSession(account.ID, datastore.EmailAuthSessionVersion, "")
	require.NoError(suite.T(), err)
	token, err := suite.jwtService.CreateAuthToken(session.ID)
	require.NoError(suite.T(), err)

	// Test account deletion
	req := httptest.NewRequest("DELETE", "/v2/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusNoContent, resp.Code)

	var sessionCount int64
	err = suite.ds.DB.Model(&datastore.Session{}).Where("id = ?", session.ID).Count(&sessionCount).Error
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(0), sessionCount)

	var accountCount int64
	err = suite.ds.DB.Model(&datastore.Account{}).Where("id = ?", account.ID).Count(&accountCount).Error
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(0), accountCount)
}

func TestAccountsTestSuite(t *testing.T) {
	suite.Run(t, new(AccountsTestSuite))
}
