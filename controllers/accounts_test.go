package controllers_test

import (
	"encoding/base32"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brave/accounts/controllers"
	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/bytemare/opaque"
	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/suite"
)

type AccountsTestSuite struct {
	suite.Suite
	useKeyService bool
	ds            *datastore.Datastore
	keyServiceDs  *datastore.Datastore
	jwtService    *services.JWTService
	router        *chi.Mux
	opaqueClient  *opaque.Client
	controller    *controllers.AccountsController
}

func NewAccountsTestSuite(useKeyService bool) *AccountsTestSuite {
	return &AccountsTestSuite{
		useKeyService: useKeyService,
	}
}

func (suite *AccountsTestSuite) SetupTest() {
	var err error
	suite.T().Setenv("OPAQUE_SECRET_KEY", "4355f8e6f9ec41649fbcdbcca5075a97dafc4c8d8eb8cc2ba286be7b1c938d05")
	suite.T().Setenv("OPAQUE_PUBLIC_KEY", "98584585210c1f310e9d0aeb9ac1384b7d51808cfaf21b17b5e3dc8d35dbfb00")

	suite.ds, err = datastore.NewDatastore(datastore.EmailAuthSessionVersion, false, true)
	suite.Require().NoError(err)

	if suite.useKeyService {
		initKeyServiceForTest(suite.T(), &suite.keyServiceDs, suite.ds)
	}

	suite.jwtService, err = services.NewJWTService(suite.ds, false)
	suite.Require().NoError(err)
	opaqueService, err := services.NewOpaqueService(suite.ds, false)
	suite.Require().NoError(err)
	twoFAService := services.NewTwoFAService(suite.ds, false)
	suite.controller = controllers.NewAccountsController(opaqueService, suite.jwtService, twoFAService, suite.ds)

	suite.opaqueClient, err = opaque.NewClient(opaqueService.Config)
	suite.Require().NoError(err)

	suite.SetupRouter(true)
}

func (suite *AccountsTestSuite) TearDownTest() {
	suite.ds.Close()
	if suite.keyServiceDs != nil {
		suite.keyServiceDs.Close()
		suite.keyServiceDs = nil
	}
	util.TestKeyServiceRouter = nil
}

func (suite *AccountsTestSuite) SetupRouter(accountDeletionEnabled bool) {
	authMiddleware := middleware.AuthMiddleware(suite.jwtService, suite.ds, datastore.EmailAuthSessionVersion, true)
	verificationAuthMiddleware := middleware.VerificationAuthMiddleware(suite.jwtService, suite.ds)
	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/accounts", suite.controller.Router(verificationAuthMiddleware, authMiddleware, accountDeletionEnabled))
}

func (suite *AccountsTestSuite) createAuthSession() (string, *datastore.Account) {
	// Create test account
	account, err := suite.ds.GetOrCreateAccount("test@example.com")
	suite.Require().NoError(err)
	// Create test account session
	session, err := suite.ds.CreateSession(account.ID, datastore.EmailAuthSessionVersion, "")
	suite.Require().NoError(err)
	token, err := suite.jwtService.CreateAuthToken(session.ID, nil, util.AccountsServiceName)
	suite.Require().NoError(err)

	return token, account
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
	sessionID, _, err := suite.jwtService.ValidateAuthToken(parsedFinalizeResp.AuthToken)
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
	token, account := suite.createAuthSession()

	// Test account deletion
	req := httptest.NewRequest("DELETE", "/v2/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNoContent, resp.Code)

	var sessionCount int64
	err := suite.ds.DB.Model(&datastore.Session{}).Where("account_id = ?", account.ID).Count(&sessionCount).Error
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

func (suite *AccountsTestSuite) TestGet2FASettings() {
	token, account := suite.createAuthSession()

	// Test getting 2FA settings
	req := httptest.NewRequest("GET", "/v2/accounts/2fa", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var settings datastore.TwoFADetails
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &settings)
	suite.False(settings.TOTP)
	suite.Nil(settings.TOTPEnabledAt)
	suite.Nil(settings.RecoveryKeyCreatedAt)

	// Enable 2FA
	err := suite.ds.SetTOTPSetting(account.ID, true)
	suite.Require().NoError(err)

	// Test getting updated 2FA settings
	req = httptest.NewRequest("GET", "/v2/accounts/2fa", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	util.DecodeJSONTestResponse(suite.T(), resp.Body, &settings)
	suite.True(settings.TOTP)
	suite.NotNil(settings.TOTPEnabledAt)
	suite.Nil(settings.RecoveryKeyCreatedAt)
}

func (suite *AccountsTestSuite) TestTOTPSetupAndFinalize() {
	token, account := suite.createAuthSession()

	// Test initializing TOTP setup
	initReq := util.CreateJSONTestRequest("/v2/accounts/2fa/totp/init", controllers.TwoFAInitRequest{
		GenerateQR: true,
	})
	initReq.Header.Set("Authorization", "Bearer "+token)
	initResp := util.ExecuteTestRequest(initReq, suite.router)
	suite.Equal(http.StatusOK, initResp.Code)

	var initParsedResp controllers.TwoFAInitResponse
	util.DecodeJSONTestResponse(suite.T(), initResp.Body, &initParsedResp)
	suite.Require().NotEmpty(initParsedResp.URI)
	suite.Require().NotNil(initParsedResp.QRCode)
	suite.NotEmpty(*initParsedResp.QRCode)

	// Parse the TOTP URI to extract the secret
	key, err := otp.NewKeyFromURL(initParsedResp.URI)
	suite.Require().NoError(err)
	suite.Equal("Brave Account", key.Issuer())
	suite.Equal("test@example.com", key.AccountName())
	suite.Equal(otp.AlgorithmSHA1, key.Algorithm())
	suite.True(strings.HasPrefix(initParsedResp.URI, "otpauth://totp/Brave%20Account"))

	validCode, err := totp.GenerateCode(key.Secret(), time.Now().UTC())
	suite.Require().NoError(err)

	// Test finalizing TOTP setup with invalid codes
	invalidCodes := []string{
		"000000",
		"ABCDEF",
		validCode + "0",
		"0" + validCode,
	}

	for _, invalidCode := range invalidCodes {
		finalizeReq := util.CreateJSONTestRequest("/v2/accounts/2fa/totp/finalize", controllers.TwoFAFinalizeRequest{
			Code: invalidCode,
		})
		finalizeReq.Header.Set("Authorization", "Bearer "+token)
		finalizeResp := util.ExecuteTestRequest(finalizeReq, suite.router)
		suite.Equal(http.StatusBadRequest, finalizeResp.Code)
		if invalidCode == "000000" {
			util.AssertErrorResponseCode(suite.T(), finalizeResp, util.ErrBadTOTPCode.Code)
		}
	}

	finalizeReq := util.CreateJSONTestRequest("/v2/accounts/2fa/totp/finalize", controllers.TwoFAFinalizeRequest{
		Code: validCode,
	})
	finalizeReq.Header.Set("Authorization", "Bearer "+token)
	finalizeResp := util.ExecuteTestRequest(finalizeReq, suite.router)
	suite.Equal(http.StatusOK, finalizeResp.Code)

	var finalizeParsedResp controllers.TwoFAFinalizeResponse
	util.DecodeJSONTestResponse(suite.T(), finalizeResp.Body, &finalizeParsedResp)
	suite.Require().NotNil(finalizeParsedResp.RecoveryKey)
	suite.Len(*finalizeParsedResp.RecoveryKey, 32)
	suite.NotEmpty(*finalizeParsedResp.RecoveryKey)

	_, err = base32.StdEncoding.DecodeString(*finalizeParsedResp.RecoveryKey)
	suite.Require().NoError(err)

	// Verify 2FA is now enabled
	updatedAccount, err := suite.ds.GetAccount(nil, account.Email)
	suite.Require().NoError(err)
	suite.True(updatedAccount.IsTwoFAEnabled())
	suite.NotNil(updatedAccount.RecoveryKeyHash)
	suite.True(util.VerifyRecoveryKeyHash(*finalizeParsedResp.RecoveryKey, updatedAccount.RecoveryKeyHash))

	// Test initializing TOTP when it's already enabled
	initReq = util.CreateJSONTestRequest("/v2/accounts/2fa/totp/init", controllers.TwoFAInitRequest{
		GenerateQR: true,
	})
	initReq.Header.Set("Authorization", "Bearer "+token)
	initResp = util.ExecuteTestRequest(initReq, suite.router)
	suite.Equal(http.StatusBadRequest, initResp.Code)
	util.AssertErrorResponseCode(suite.T(), initResp, util.ErrTOTPAlreadyEnabled.Code)
}

func (suite *AccountsTestSuite) TestDisableTOTP() {
	token, account := suite.createAuthSession()

	// Enable 2FA first
	err := suite.ds.SetTOTPSetting(account.ID, true)
	suite.Require().NoError(err)

	// Generate and store a recovery key
	recoveryKey := "MFZWIZTBONSWM53BONSWMYLTMVTGC43F"
	err = suite.ds.SetRecoveryKey(account.ID, &recoveryKey)
	suite.Require().NoError(err)

	// Verify timestamps are set
	details, err := suite.ds.GetTwoFADetails(account.ID)
	suite.Require().NoError(err)
	suite.NotNil(details.TOTPEnabledAt)
	suite.NotNil(details.RecoveryKeyCreatedAt)

	// Test disabling TOTP
	disableReq := httptest.NewRequest("DELETE", "/v2/accounts/2fa/totp", nil)
	disableReq.Header.Set("Authorization", "Bearer "+token)
	disableResp := util.ExecuteTestRequest(disableReq, suite.router)
	suite.Equal(http.StatusNoContent, disableResp.Code)

	// Verify 2FA is now disabled
	updatedAccount, err := suite.ds.GetAccount(nil, account.Email)
	suite.Require().NoError(err)
	suite.False(updatedAccount.IsTwoFAEnabled())
	suite.Nil(updatedAccount.RecoveryKeyHash)

	// Verify timestamps are cleared
	details, err = suite.ds.GetTwoFADetails(account.ID)
	suite.Require().NoError(err)
	suite.Nil(details.TOTPEnabledAt)
	suite.Nil(details.RecoveryKeyCreatedAt)
}

func (suite *AccountsTestSuite) TestRecoveryKeyEndpoints() {
	token, account := suite.createAuthSession()

	// Test regenerate recovery key
	req := util.CreateJSONTestRequest("/v2/accounts/2fa/recovery", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	// Verify response contains a recovery key
	var keyResp controllers.RecoveryKeyResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &keyResp)
	suite.NotEmpty(keyResp.RecoveryKey)

	// Verify recovery key was stored
	hasKey, err := suite.ds.HasRecoveryKey(account.ID)
	suite.Require().NoError(err)
	suite.True(hasKey)

	// Verify timestamp was set
	details, err := suite.ds.GetTwoFADetails(account.ID)
	suite.Require().NoError(err)
	suite.NotNil(details.RecoveryKeyCreatedAt)

	firstCreatedAt := details.RecoveryKeyCreatedAt

	req = util.CreateJSONTestRequest("/v2/accounts/2fa/recovery", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	details, err = suite.ds.GetTwoFADetails(account.ID)
	suite.Require().NoError(err)
	// Ensure createdAt is updated
	suite.NotEqual(*details.RecoveryKeyCreatedAt, *firstCreatedAt)

	// Test delete recovery key
	req = httptest.NewRequest("DELETE", "/v2/accounts/2fa/recovery", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNoContent, resp.Code)

	// Verify recovery key was deleted
	hasKey, err = suite.ds.HasRecoveryKey(account.ID)
	suite.Require().NoError(err)
	suite.False(hasKey)

	// Verify timestamp was cleared
	details, err = suite.ds.GetTwoFADetails(account.ID)
	suite.Require().NoError(err)
	suite.Nil(details.RecoveryKeyCreatedAt)

	req = util.CreateJSONTestRequest("/v2/accounts/2fa/recovery", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)
}

func TestAccountsTestSuite(t *testing.T) {
	t.Run("NoKeyService", func(t *testing.T) {
		suite.Run(t, NewAccountsTestSuite(false))
	})
	t.Run("WithKeyService", func(t *testing.T) {
		suite.Run(t, NewAccountsTestSuite(true))
	})
}
