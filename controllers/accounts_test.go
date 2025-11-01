package controllers_test

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AccountsTestSuite struct {
	suite.Suite
	useKeyService       bool
	ds                  *datastore.Datastore
	keyServiceDs        *datastore.Datastore
	jwtService          *services.JWTService
	twoFAService        *services.TwoFAService
	sesMock             *MockSESService
	verificationService *services.VerificationService
	router              *chi.Mux
	opaqueClient        *opaque.Client
	controller          *controllers.AccountsController
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
	suite.twoFAService = services.NewTwoFAService(suite.ds, false)
	suite.sesMock = &MockSESService{}
	suite.verificationService = services.NewVerificationService(suite.ds, suite.jwtService, suite.sesMock, true, true)
	suite.controller = controllers.NewAccountsController(opaqueService, suite.jwtService, suite.twoFAService, suite.ds, suite.verificationService, suite.sesMock)

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
	authMiddleware := middleware.AuthMiddleware(suite.jwtService, suite.ds, datastore.EmailAuthSessionVersion, true, true)
	verificationAuthMiddleware := middleware.VerificationAuthMiddleware(suite.jwtService, suite.ds, true)
	permissiveVerificationAuthMiddleware := middleware.VerificationAuthMiddleware(suite.jwtService, suite.ds, false)
	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/accounts", suite.controller.Router(verificationAuthMiddleware, permissiveVerificationAuthMiddleware, authMiddleware, accountDeletionEnabled))
}

func (suite *AccountsTestSuite) createAuthSession() (string, *datastore.Account) {
	// Create test account
	account, err := suite.ds.GetOrCreateAccount("test@example.com")
	suite.Require().NoError(err)
	err = suite.ds.UpdateAccountLastEmailVerifiedAt(account.ID)
	suite.Require().NoError(err)

	// Create test account session
	session, err := suite.ds.CreateSession(account.ID, datastore.EmailAuthSessionVersion, "")
	suite.Require().NoError(err)
	token, err := suite.jwtService.CreateAuthToken(session.ID, nil, util.AccountsServiceName)
	suite.Require().NoError(err)

	return token, account
}

func createWebAuthnCredentialResponse(t *testing.T, authenticator virtualwebauthn.Authenticator, credential virtualwebauthn.Credential, challenge interface{}) *protocol.CredentialCreationResponse {
	rp := createWebAuthnRelyingParty()

	// Marshal the credential creation options to JSON for virtualwebauthn
	attestationOptionsJSON, err := json.Marshal(challenge)
	require.NoError(t, err)

	// Parse attestation options and create response using virtualwebauthn
	parsedAttestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(attestationOptionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedAttestationOptions)

	// Unmarshal the attestation response to get the credential creation response
	var credentialCreationResponse protocol.CredentialCreationResponse
	err = json.Unmarshal([]byte(attestationResponse), &credentialCreationResponse)
	require.NoError(t, err)

	return &credentialCreationResponse
}

func createWebAuthnRelyingParty() virtualwebauthn.RelyingParty {
	return virtualwebauthn.RelyingParty{
		Name:   "Brave Account",
		ID:     services.GetWebAuthnRPID(),
		Origin: services.GetWebAuthnOrigins()[0],
	}
}

func addWebAuthnCredential(t *testing.T, twoFAService *services.TwoFAService, ds *datastore.Datastore, authenticator virtualwebauthn.Authenticator, account *datastore.Account, credentialName string) virtualwebauthn.Credential {
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Create a WebAuthn registration challenge via service
	creation, registrationID, err := twoFAService.CreateWebAuthnRegistrationChallenge(account.ID, account.Email)
	require.NoError(t, err)

	// Create the credential response using the helper
	credentialCreationResponse := createWebAuthnCredentialResponse(t, authenticator, credential, creation)

	// Finalize the registration via service
	_, err = twoFAService.FinalizeWebAuthnCredentialRegistration(account.ID, account.Email, registrationID, credentialName, credentialCreationResponse)
	require.NoError(t, err)

	// Enable WebAuthn setting
	err = ds.SetWebAuthnSetting(account.ID, true)
	require.NoError(t, err)

	return credential
}

func (suite *AccountsTestSuite) addWebAuthnCredential(authenticator virtualwebauthn.Authenticator, account *datastore.Account, credentialName string) virtualwebauthn.Credential {
	return addWebAuthnCredential(suite.T(), suite.twoFAService, suite.ds, authenticator, account, credentialName)
}

func (suite *AccountsTestSuite) createTestUserKeys(accountID uuid.UUID) {
	err := suite.ds.StoreUserKey(&datastore.DBUserKey{
		AccountID:   accountID,
		Service:     "accounts",
		KeyName:     "key1",
		KeyMaterial: []byte{1, 2, 3},
	})
	suite.Require().NoError(err)
	err = suite.ds.StoreUserKey(&datastore.DBUserKey{
		AccountID:   accountID,
		Service:     "accounts",
		KeyName:     "key2",
		KeyMaterial: []byte{4, 5, 6},
	})
	suite.Require().NoError(err)
}

func (suite *AccountsTestSuite) TestResetPassword() {
	// Create account and store some test user keys
	account, err := suite.ds.GetOrCreateAccount("test@example.com")
	suite.Require().NoError(err)

	suite.createTestUserKeys(account.ID)

	// Create a second account with test user keys to verify they are not deleted
	secondAccount, err := suite.ds.GetOrCreateAccount("second@example.com")
	suite.Require().NoError(err)
	suite.createTestUserKeys(secondAccount.ID)

	// Create verification with reset_password intent
	verification, err := suite.ds.CreateVerification("test@example.com", "accounts", "reset_password")
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
	suite.Nil(parsedResp.VerificationToken) // No verification token for reset_password intent
	serializedRegistationResp, err := hex.DecodeString(*parsedResp.SerializedResponse)
	suite.Require().NoError(err)
	registrationResp, err := suite.opaqueClient.Deserialize.RegistrationResponse(serializedRegistationResp)
	suite.Require().NoError(err)

	registrationRecord, _ := suite.opaqueClient.RegistrationFinalize(registrationResp, opaque.ClientRegistrationFinalizeOptions{
		ClientIdentity: []byte(verification.Email),
	})
	serializedRecord := hex.EncodeToString(registrationRecord.Serialize())

	suite.sesMock.On("SendPasswordChangeNotification", mock.Anything, verification.Email, mock.Anything).Return(nil).Once()

	// Test password finalize
	req = util.CreateJSONTestRequest("/v2/accounts/password/finalize", controllers.RegistrationRecord{
		SerializedRecord: &serializedRecord,
		// This setting should be ignored
		InvalidateSessions: false,
	})
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedFinalizeResp controllers.PasswordFinalizeResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedFinalizeResp)
	suite.NotNil(parsedFinalizeResp.AuthToken)
	suite.True(parsedFinalizeResp.SessionsInvalidated)

	// Validate auth token
	sessionID, _, err := suite.jwtService.ValidateAuthToken(*parsedFinalizeResp.AuthToken)
	suite.NoError(err)
	suite.NotNil(sessionID)

	account, err = suite.ds.GetAccount(nil, verification.Email)
	suite.Require().NoError(err)
	suite.NotNil(account.OprfSeedID)
	suite.NotEmpty(account.OpaqueRegistration)
	suite.Nil(account.LastEmailVerifiedAt)

	// Should not be able to set password again
	req = util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
		BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
		SerializeResponse: true,
	})
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNotFound, resp.Code)

	// Verify that all user keys were deleted during password reset
	finalKeys, err := suite.ds.GetUserKeys(account.ID)
	suite.Require().NoError(err)
	suite.Equal(0, len(finalKeys), "User keys should be deleted during password reset")

	// Verify that user keys for the second account were NOT deleted
	secondAccountKeys, err := suite.ds.GetUserKeys(secondAccount.ID)
	suite.Require().NoError(err)
	suite.Equal(2, len(secondAccountKeys), "User keys for second account should NOT be deleted during first account's password reset")
}

func (suite *AccountsTestSuite) TestRegistration() {
	// Email with 'strict' TLD should be allowed for registration
	email := "newuser@example.ru"
	registrationReq := suite.opaqueClient.RegistrationInit([]byte("testtest1"))

	// Test password init with newAccountEmail (no verification token)
	req := util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
		BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
		SerializeResponse: true,
		NewAccountEmail:   &email,
	})
	// No Authorization header for registration

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedResp controllers.RegistrationResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	suite.NotNil(parsedResp.SerializedResponse)
	suite.NotNil(parsedResp.VerificationToken) // Verification token should be present for registration
	suite.NotEmpty(*parsedResp.VerificationToken)

	// Validate the verification token
	verificationID, err := suite.jwtService.ValidateVerificationToken(*parsedResp.VerificationToken)
	suite.NoError(err)
	suite.NotNil(verificationID)

	// Check that verification was created with registration intent
	verification, err := suite.ds.GetVerificationStatus(verificationID)
	suite.Require().NoError(err)
	suite.Equal(email, verification.Email)
	suite.Equal("accounts", verification.Service)
	suite.Equal(datastore.RegistrationIntent, verification.Intent)

	serializedRegistationResp, err := hex.DecodeString(*parsedResp.SerializedResponse)
	suite.Require().NoError(err)
	registrationResp, err := suite.opaqueClient.Deserialize.RegistrationResponse(serializedRegistationResp)
	suite.Require().NoError(err)

	registrationRecord, _ := suite.opaqueClient.RegistrationFinalize(registrationResp, opaque.ClientRegistrationFinalizeOptions{
		ClientIdentity: []byte(email),
	})
	serializedRecord := hex.EncodeToString(registrationRecord.Serialize())

	suite.sesMock.On("SendVerificationEmail", mock.Anything, email, mock.Anything, "").Return(nil).Once()

	// Test password finalize with verification token
	req = util.CreateJSONTestRequest("/v2/accounts/password/finalize", controllers.RegistrationRecord{
		SerializedRecord: &serializedRecord,
		// This setting should be ignored
		InvalidateSessions: true,
	})
	req.Header.Set("Authorization", "Bearer "+*parsedResp.VerificationToken)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedFinalizeResp controllers.PasswordFinalizeResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedFinalizeResp)
	suite.Nil(parsedFinalizeResp.AuthToken) // No auth token until email is verified
	suite.True(parsedFinalizeResp.RequiresEmailVerification)
	suite.Nil(parsedFinalizeResp.TwoFAOptions)
	suite.False(parsedFinalizeResp.SessionsInvalidated)

	// Verify account was created but not verified
	account, err := suite.ds.GetAccount(nil, email)
	suite.Require().NoError(err)
	suite.NotNil(account.OprfSeedID)
	suite.NotEmpty(account.OpaqueRegistration)
	suite.Nil(account.LastEmailVerifiedAt) // Email not verified yet

	// Simulate email verification using verification service
	_, err = suite.verificationService.CompleteVerification(verification.ID, verification.Code)
	suite.Require().NoError(err)

	// Check that account is now verified
	account, err = suite.ds.GetAccount(nil, email)
	suite.Require().NoError(err)
	suite.NotNil(account.LastEmailVerifiedAt) // Email should now be verified

	// Get verification result to trigger session creation (simulates the verification result endpoint)
	verification, err = suite.ds.GetVerificationStatus(verification.ID)
	suite.Require().NoError(err)
	verificationResult, err := suite.verificationService.GetVerificationResult(context.Background(), verification, false, "test-user-agent")
	suite.Require().NoError(err)
	suite.True(verificationResult.Verified)
	suite.NotNil(verificationResult.AuthToken)

	// Check that the session created has the correct version (PasswordAuthSessionVersion)
	sessionID, _, err := suite.jwtService.ValidateAuthToken(*verificationResult.AuthToken)
	suite.Require().NoError(err)

	session, err := suite.ds.GetSession(sessionID)
	suite.Require().NoError(err)
	suite.Equal(datastore.PasswordAuthSessionVersion, session.Version)

	suite.sesMock.AssertExpectations(suite.T())
}

func (suite *AccountsTestSuite) TestRegistrationAccountAlreadyExists() {
	email := "existing@example.com"

	// Create an existing account
	_, err := suite.ds.GetOrCreateAccount(email)
	suite.Require().NoError(err)

	registrationReq := suite.opaqueClient.RegistrationInit([]byte("testtest1"))

	// Test password init with newAccountEmail for existing account
	req := util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
		BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
		SerializeResponse: true,
		NewAccountEmail:   &email,
	})
	// No Authorization header for registration

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrAccountExists.Code)
}

func (suite *AccountsTestSuite) TestRegistrationUnsupportedEmail() {
	email := "test@example.kp" // .kp domain should be unsupported
	registrationReq := suite.opaqueClient.RegistrationInit([]byte("testtest1"))

	// Test password init with unsupported email domain
	req := util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
		BlindedMessage:    hex.EncodeToString(registrationReq.Serialize()),
		SerializeResponse: true,
		NewAccountEmail:   &email,
	})
	// No Authorization header for registration

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrEmailDomainNotSupported.Code)
}

func (suite *AccountsTestSuite) TestChangePassword() {
	sessionInvalidationSettings := []bool{true, false}

	for i, sessionInvalidation := range sessionInvalidationSettings {
		// Create an account directly using datastore
		email := fmt.Sprintf("test-change-%d@example.com", i)
		account, err := suite.ds.GetOrCreateAccount(email)
		suite.Require().NoError(err)

		err = suite.ds.SetAccountLocaleIfMissing(account.ID, "fr-FR")
		suite.Require().NoError(err)

		// Store some test user keys to verify they are NOT deleted during password change
		suite.createTestUserKeys(account.ID)

		// Verify keys were stored
		initialKeys, err := suite.ds.GetUserKeys(account.ID)
		suite.Require().NoError(err)
		suite.Equal(2, len(initialKeys))

		// Create sessions to verify session invalidation or lack thereof
		for range 3 {
			_, err := suite.ds.CreateSession(account.ID, datastore.EmailAuthSessionVersion, "")
			suite.Require().NoError(err)
		}

		changeVerification, err := suite.ds.CreateVerification(email, "accounts", "change_password")
		suite.Require().NoError(err)
		_, err = suite.ds.UpdateAndGetVerificationStatus(changeVerification.ID, changeVerification.Code)
		suite.Require().NoError(err)

		changeToken, err := suite.jwtService.CreateVerificationToken(changeVerification.ID, time.Minute*30, changeVerification.Service)
		suite.Require().NoError(err)

		changeRegistrationReq := suite.opaqueClient.RegistrationInit([]byte("newpassword"))

		req := util.CreateJSONTestRequest("/v2/accounts/password/init", controllers.RegistrationRequest{
			BlindedMessage:    hex.EncodeToString(changeRegistrationReq.Serialize()),
			SerializeResponse: true,
		})
		req.Header.Set("Authorization", "Bearer "+changeToken)

		resp := util.ExecuteTestRequest(req, suite.router)
		suite.Equal(http.StatusOK, resp.Code)

		var parsedResp controllers.RegistrationResponse
		util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
		suite.NotNil(parsedResp.SerializedResponse)
		suite.Nil(parsedResp.VerificationToken) // No verification token for change_password intent

		serializedChangeResp, err := hex.DecodeString(*parsedResp.SerializedResponse)
		suite.Require().NoError(err)
		changeResp, err := suite.opaqueClient.Deserialize.RegistrationResponse(serializedChangeResp)
		suite.Require().NoError(err)

		changeRecord, _ := suite.opaqueClient.RegistrationFinalize(changeResp, opaque.ClientRegistrationFinalizeOptions{
			ClientIdentity: []byte(email),
		})
		serializedChangeRecord := hex.EncodeToString(changeRecord.Serialize())

		suite.sesMock.On("SendPasswordChangeNotification", mock.Anything, email, "fr-FR").Return(nil).Once()

		// Test password change finalize with session invalidation
		req = util.CreateJSONTestRequest("/v2/accounts/password/finalize", controllers.RegistrationRecord{
			SerializedRecord:   &serializedChangeRecord,
			InvalidateSessions: sessionInvalidation,
		})
		req.Header.Set("Authorization", "Bearer "+changeToken)

		resp = util.ExecuteTestRequest(req, suite.router)
		suite.Equal(http.StatusOK, resp.Code)

		var changeFinalizeResp controllers.PasswordFinalizeResponse
		util.DecodeJSONTestResponse(suite.T(), resp.Body, &changeFinalizeResp)
		suite.Nil(changeFinalizeResp.TwoFAOptions)
		suite.False(changeFinalizeResp.RequiresEmailVerification)
		suite.Equal(sessionInvalidation, changeFinalizeResp.SessionsInvalidated)

		suite.sesMock.AssertExpectations(suite.T())

		// Verify the account still exists and password was changed
		updatedAccount, err := suite.ds.GetAccount(nil, email)
		suite.Require().NoError(err)
		suite.NotNil(updatedAccount.OprfSeedID)
		suite.NotEmpty(updatedAccount.OpaqueRegistration)

		sessions, err := suite.ds.ListSessions(account.ID)
		suite.Require().NoError(err)
		if sessionInvalidation {
			suite.Equal(1, len(sessions))
			suite.NotNil(changeFinalizeResp.AuthToken)
		} else {
			suite.Equal(3, len(sessions))
			suite.Nil(changeFinalizeResp.AuthToken)
		}

		// Verify that user keys were NOT deleted during password change
		finalKeys, err := suite.ds.GetUserKeys(account.ID)
		suite.Require().NoError(err)
		suite.Equal(2, len(finalKeys), "User keys should NOT be deleted during password change")
	}
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
	intents := []string{"reset_password", "change_password"}

	for _, intent := range intents {
		// Create unverified verification
		verification, err := suite.ds.CreateVerification("test@example.com", "accounts", intent)
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

	var settings datastore.TwoFAConfiguration
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &settings)
	suite.False(settings.TOTP)
	suite.Nil(settings.TOTPEnabledAt)
	suite.Nil(settings.RecoveryKeyCreatedAt)
	suite.False(settings.WebAuthn)
	suite.Nil(settings.WebAuthnEnabledAt)
	suite.Nil(settings.WebAuthnCredentials)

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
	suite.False(settings.WebAuthn)
	suite.Nil(settings.WebAuthnEnabledAt)
	suite.Nil(settings.WebAuthnCredentials)

	// Add WebAuthn credentials
	authenticator := virtualwebauthn.NewAuthenticator()
	suite.addWebAuthnCredential(authenticator, account, "YubiKey 5C")
	suite.addWebAuthnCredential(authenticator, account, "Touch ID")

	// Test getting settings with WebAuthn credentials
	req = httptest.NewRequest("GET", "/v2/accounts/2fa", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	util.DecodeJSONTestResponse(suite.T(), resp.Body, &settings)
	suite.True(settings.TOTP)
	suite.NotNil(settings.TOTPEnabledAt)
	suite.True(settings.WebAuthn)
	suite.NotNil(settings.WebAuthnEnabledAt)
	suite.Require().NotNil(settings.WebAuthnCredentials)
	suite.Len(settings.WebAuthnCredentials, 2)

	// Verify credential names
	credentialNames := []string{}
	for _, cred := range settings.WebAuthnCredentials {
		credentialNames = append(credentialNames, cred.Name)
	}
	suite.Contains(credentialNames, "YubiKey 5C")
	suite.Contains(credentialNames, "Touch ID")
}

func (suite *AccountsTestSuite) TestTOTPSetupAndFinalize() {
	token, account := suite.createAuthSession()

	// Test initializing TOTP setup
	initReq := util.CreateJSONTestRequest("/v2/accounts/2fa/totp/init", controllers.TOTPInitRequest{
		GenerateQR: true,
	})
	initReq.Header.Set("Authorization", "Bearer "+token)
	initResp := util.ExecuteTestRequest(initReq, suite.router)
	suite.Equal(http.StatusOK, initResp.Code)

	var initParsedResp controllers.TOTPInitResponse
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
		finalizeReq := util.CreateJSONTestRequest("/v2/accounts/2fa/totp/finalize", controllers.TOTPFinalizeRequest{
			Code: invalidCode,
		})
		finalizeReq.Header.Set("Authorization", "Bearer "+token)
		finalizeResp := util.ExecuteTestRequest(finalizeReq, suite.router)
		suite.Equal(http.StatusBadRequest, finalizeResp.Code)
		if invalidCode == "000000" {
			util.AssertErrorResponseCode(suite.T(), finalizeResp, util.ErrBadTOTPCode.Code)
		}
	}

	finalizeReq := util.CreateJSONTestRequest("/v2/accounts/2fa/totp/finalize", controllers.TOTPFinalizeRequest{
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
	suite.True(updatedAccount.TOTPEnabled)
	suite.False(updatedAccount.WebAuthnEnabled)
	suite.NotNil(updatedAccount.RecoveryKeyHash)
	suite.True(util.VerifyRecoveryKeyHash(*finalizeParsedResp.RecoveryKey, updatedAccount.RecoveryKeyHash))

	// Test initializing TOTP when it's already enabled
	initReq = util.CreateJSONTestRequest("/v2/accounts/2fa/totp/init", controllers.TOTPInitRequest{
		GenerateQR: true,
	})
	initReq.Header.Set("Authorization", "Bearer "+token)
	initResp = util.ExecuteTestRequest(initReq, suite.router)
	suite.Equal(http.StatusBadRequest, initResp.Code)
	util.AssertErrorResponseCode(suite.T(), initResp, util.ErrTOTPAlreadyEnabled.Code)
}

func (suite *AccountsTestSuite) TestWebAuthnSetupAndFinalize() {
	token, account := suite.createAuthSession()

	authenticator := virtualwebauthn.NewAuthenticator()
	credentialNames := []string{"YubiKey 5C", "Touch ID"}
	var recoveryKey *string

	for i, credentialName := range credentialNames {
		credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

		initReq := httptest.NewRequest("POST", "/v2/accounts/2fa/webauthn/init", nil)
		initReq.Header.Set("Authorization", "Bearer "+token)
		initResp := util.ExecuteTestRequest(initReq, suite.router)
		suite.Equal(http.StatusOK, initResp.Code)

		var initParsedResp controllers.WebAuthnRegistrationInitResponse
		util.DecodeJSONTestResponse(suite.T(), initResp.Body, &initParsedResp)
		suite.Require().NotEmpty(initParsedResp.RegistrationID)
		suite.Require().NotNil(initParsedResp.Request)
		suite.Require().NotNil(initParsedResp.Request.Response)
		suite.NotEmpty(initParsedResp.Request.Response.Challenge)
		suite.Equal("Brave Account", initParsedResp.Request.Response.RelyingParty.Name)

		// Create the credential response using the helper
		credentialCreationResponse := createWebAuthnCredentialResponse(suite.T(), authenticator, credential, initParsedResp.Request)

		finalizeReq := util.CreateJSONTestRequest("/v2/accounts/2fa/webauthn/finalize", controllers.WebAuthnRegistrationFinalizeRequest{
			RegistrationID: initParsedResp.RegistrationID,
			Name:           credentialName,
			Response:       credentialCreationResponse,
		})
		finalizeReq.Header.Set("Authorization", "Bearer "+token)
		finalizeResp := util.ExecuteTestRequest(finalizeReq, suite.router)
		suite.Equal(http.StatusOK, finalizeResp.Code)

		var finalizeParsedResp controllers.TwoFAFinalizeResponse
		util.DecodeJSONTestResponse(suite.T(), finalizeResp.Body, &finalizeParsedResp)

		if i == 0 {
			// Recovery key should only be generated for first credential
			suite.Require().NotNil(finalizeParsedResp.RecoveryKey)
			suite.Len(*finalizeParsedResp.RecoveryKey, 32)
			recoveryKey = finalizeParsedResp.RecoveryKey
		} else {
			// No recovery key for subsequent credentials
			suite.Nil(finalizeParsedResp.RecoveryKey)
		}

		// Verify correct number of credentials after each registration
		credentials, err := suite.ds.GetWebAuthnCredentials(account.ID)
		suite.Require().NoError(err)
		suite.Require().Len(credentials, i+1)
	}

	// Verify WebAuthn is enabled and recovery key is set
	updatedAccount, err := suite.ds.GetAccount(nil, account.Email)
	suite.Require().NoError(err)
	suite.True(updatedAccount.WebAuthnEnabled)
	suite.NotNil(updatedAccount.RecoveryKeyHash)
	suite.True(util.VerifyRecoveryKeyHash(*recoveryKey, updatedAccount.RecoveryKeyHash))

	// Verify both credentials are saved with correct names
	credentials, err := suite.ds.GetWebAuthnCredentials(account.ID)
	suite.Require().NoError(err)
	suite.Require().Len(credentials, 2)

	savedNames := []string{credentials[0].Name, credentials[1].Name}
	for _, expectedName := range credentialNames {
		suite.Contains(savedNames, expectedName)
	}
}

func (suite *AccountsTestSuite) TestWebAuthnCredentialLimit() {
	token, account := suite.createAuthSession()

	authenticator := virtualwebauthn.NewAuthenticator()

	// Add 10 credentials (the limit) using the helper function
	for i := 0; i < 10; i++ {
		suite.addWebAuthnCredential(authenticator, account, fmt.Sprintf("Key %d", i+1))
	}

	// Try to add an 11th credential via the endpoint - should fail
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	initReq := httptest.NewRequest("POST", "/v2/accounts/2fa/webauthn/init", nil)
	initReq.Header.Set("Authorization", "Bearer "+token)
	initResp := util.ExecuteTestRequest(initReq, suite.router)
	suite.Equal(http.StatusOK, initResp.Code)

	var initParsedResp controllers.WebAuthnRegistrationInitResponse
	util.DecodeJSONTestResponse(suite.T(), initResp.Body, &initParsedResp)
	suite.Require().NotNil(initParsedResp.Request)

	credentialCreationResponse := createWebAuthnCredentialResponse(suite.T(), authenticator, credential, initParsedResp.Request)

	finalizeReq := util.CreateJSONTestRequest("/v2/accounts/2fa/webauthn/finalize", controllers.WebAuthnRegistrationFinalizeRequest{
		RegistrationID: initParsedResp.RegistrationID,
		Name:           "Key 11",
		Response:       credentialCreationResponse,
	})
	finalizeReq.Header.Set("Authorization", "Bearer "+token)
	finalizeResp := util.ExecuteTestRequest(finalizeReq, suite.router)
	suite.Equal(http.StatusBadRequest, finalizeResp.Code)
	util.AssertErrorResponseCode(suite.T(), finalizeResp, util.ErrMaxWebAuthnCredentialsExceeded.Code)

	// Verify we still have only 10 credentials
	credentials, err := suite.ds.GetWebAuthnCredentials(account.ID)
	suite.Require().NoError(err)
	suite.Require().Len(credentials, 10)
}

func (suite *AccountsTestSuite) TestWebAuthnRegistrationStateErrors() {
	token, _ := suite.createAuthSession()

	authenticator := virtualwebauthn.NewAuthenticator()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Create an init request to get a registration state
	initReq := httptest.NewRequest("POST", "/v2/accounts/2fa/webauthn/init", nil)
	initReq.Header.Set("Authorization", "Bearer "+token)
	initResp := util.ExecuteTestRequest(initReq, suite.router)
	suite.Equal(http.StatusOK, initResp.Code)

	var initParsedResp controllers.WebAuthnRegistrationInitResponse
	util.DecodeJSONTestResponse(suite.T(), initResp.Body, &initParsedResp)

	credentialCreationResponse := createWebAuthnCredentialResponse(suite.T(), authenticator, credential, initParsedResp.Request)

	// Test with non-existing registration ID
	nonExistingID := uuid.New()
	finalizeReq := util.CreateJSONTestRequest("/v2/accounts/2fa/webauthn/finalize", controllers.WebAuthnRegistrationFinalizeRequest{
		RegistrationID: nonExistingID.String(),
		Name:           "Test Key",
		Response:       credentialCreationResponse,
	})
	finalizeReq.Header.Set("Authorization", "Bearer "+token)
	finalizeResp := util.ExecuteTestRequest(finalizeReq, suite.router)
	suite.Equal(http.StatusBadRequest, finalizeResp.Code)
	util.AssertErrorResponseCode(suite.T(), finalizeResp, util.ErrInterimWebAuthnStateNotFound.Code)

	// Update the created_at timestamp to make it expired using raw SQL
	err := suite.ds.DB.Exec(
		"UPDATE interim_webauthn_registration_states SET created_at = $1 WHERE id = $2",
		time.Now().UTC().Add(-10*time.Minute),
		initParsedResp.RegistrationID,
	).Error
	suite.Require().NoError(err)

	// Try to finalize with the expired state
	finalizeReq = util.CreateJSONTestRequest("/v2/accounts/2fa/webauthn/finalize", controllers.WebAuthnRegistrationFinalizeRequest{
		RegistrationID: initParsedResp.RegistrationID,
		Name:           "Test Key",
		Response:       credentialCreationResponse,
	})
	finalizeReq.Header.Set("Authorization", "Bearer "+token)
	finalizeResp = util.ExecuteTestRequest(finalizeReq, suite.router)
	suite.Equal(http.StatusBadRequest, finalizeResp.Code)
	util.AssertErrorResponseCode(suite.T(), finalizeResp, util.ErrInterimWebAuthnStateExpired.Code)
}

func (suite *AccountsTestSuite) TestDeleteWebAuthnCredential() {
	token, account := suite.createAuthSession()

	authenticator := virtualwebauthn.NewAuthenticator()

	// Add two WebAuthn credentials directly via service
	credential1 := suite.addWebAuthnCredential(authenticator, account, "YubiKey 5C")
	credential2 := suite.addWebAuthnCredential(authenticator, account, "Touch ID")

	// Verify both credentials exist
	credentials, err := suite.ds.GetWebAuthnCredentials(account.ID)
	suite.Require().NoError(err)
	suite.Require().Len(credentials, 2)

	// Verify WebAuthn is enabled
	account, err = suite.ds.GetAccount(nil, account.Email)
	suite.Require().NoError(err)
	suite.True(account.WebAuthnEnabled)

	// Delete the first credential via endpoint
	credential1IDHex := hex.EncodeToString(credential1.ID)
	deleteReq := httptest.NewRequest("DELETE", "/v2/accounts/2fa/webauthn/"+credential1IDHex, nil)
	deleteReq.Header.Set("Authorization", "Bearer "+token)
	deleteResp := util.ExecuteTestRequest(deleteReq, suite.router)
	suite.Equal(http.StatusNoContent, deleteResp.Code)

	// Verify first credential was deleted
	credentials, err = suite.ds.GetWebAuthnCredentials(account.ID)
	suite.Require().NoError(err)
	suite.Require().Len(credentials, 1)

	// Verify WebAuthn is still enabled
	account, err = suite.ds.GetAccount(nil, account.Email)
	suite.Require().NoError(err)
	suite.True(account.WebAuthnEnabled)

	// Delete the second credential via endpoint
	credential2IDHex := hex.EncodeToString(credential2.ID)
	deleteReq = httptest.NewRequest("DELETE", "/v2/accounts/2fa/webauthn/"+credential2IDHex, nil)
	deleteReq.Header.Set("Authorization", "Bearer "+token)
	deleteResp = util.ExecuteTestRequest(deleteReq, suite.router)
	suite.Equal(http.StatusNoContent, deleteResp.Code)

	// Verify second credential was deleted
	credentials, err = suite.ds.GetWebAuthnCredentials(account.ID)
	suite.Require().NoError(err)
	suite.Require().Len(credentials, 0)

	// Verify WebAuthn is now disabled
	account, err = suite.ds.GetAccount(nil, account.Email)
	suite.Require().NoError(err)
	suite.False(account.WebAuthnEnabled)
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
	details, err := suite.ds.GetTwoFAConfiguration(account.ID)
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
	suite.False(updatedAccount.TOTPEnabled)
	suite.False(updatedAccount.WebAuthnEnabled)
	suite.Nil(updatedAccount.RecoveryKeyHash)

	// Verify timestamps are cleared
	details, err = suite.ds.GetTwoFAConfiguration(account.ID)
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
	details, err := suite.ds.GetTwoFAConfiguration(account.ID)
	suite.Require().NoError(err)
	suite.NotNil(details.RecoveryKeyCreatedAt)

	firstCreatedAt := details.RecoveryKeyCreatedAt

	req = util.CreateJSONTestRequest("/v2/accounts/2fa/recovery", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	details, err = suite.ds.GetTwoFAConfiguration(account.ID)
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
	details, err = suite.ds.GetTwoFAConfiguration(account.ID)
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
