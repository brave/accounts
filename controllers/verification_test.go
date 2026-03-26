package controllers_test

import (
	"context"
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
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type VerificationTestSuite struct {
	suite.Suite
	useKeyService       bool
	ds                  *datastore.Datastore
	keyServiceDs        *datastore.Datastore
	sesMock             *MockSESService
	jwtService          *services.JWTService
	verificationService *services.VerificationService
	router              *chi.Mux
}

func NewVerificationTestSuite(useKeyService bool) *VerificationTestSuite {
	return &VerificationTestSuite{
		useKeyService: useKeyService,
	}
}

func (suite *VerificationTestSuite) SetupController(passwordAuthEnabled bool, emailAuthEnabled bool) {
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
	suite.sesMock = &MockSESService{}
	suite.verificationService = services.NewVerificationService(suite.ds, suite.jwtService, suite.sesMock, passwordAuthEnabled, emailAuthEnabled)
	controller := controllers.NewVerificationController(suite.ds, suite.verificationService)

	verificationAuthMiddleware := middleware.VerificationAuthMiddleware(suite.jwtService, suite.ds, true)
	servicesKeyMiddleware := middleware.ServicesKeyMiddleware(util.DevelopmentEnv)
	optionalAuthMiddleware := middleware.AuthMiddleware(suite.jwtService, suite.ds, datastore.EmailAuthSessionVersion, true, false)

	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/verify", controller.Router(verificationAuthMiddleware, servicesKeyMiddleware, optionalAuthMiddleware, false))
}

func (suite *VerificationTestSuite) TearDownTest() {
	suite.ds.Close()
	if suite.keyServiceDs != nil {
		suite.keyServiceDs.Close()
		suite.keyServiceDs = nil
	}
	util.TestKeyServiceRouter = nil
}

type MockSESService struct {
	mock.Mock
}

func (m *MockSESService) SendVerificationEmail(ctx context.Context, email string, verification *datastore.Verification, locale string) error {
	args := m.Called(ctx, email, verification, locale)
	return args.Error(0)
}

func (m *MockSESService) SendSimilarEmailAlert(ctx context.Context, email string, locale string) error {
	args := m.Called(ctx, email, locale)
	return args.Error(0)
}

func (m *MockSESService) SendPasswordChangeNotification(ctx context.Context, email string, locale string) error {
	args := m.Called(ctx, email, locale)
	return args.Error(0)
}

func (suite *VerificationTestSuite) TestVerifyInit() {
	suite.SetupController(false, true)

	body := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "auth_token",
		Service: "email-aliases",
		Locale:  "en-US",
	}

	req := util.CreateJSONTestRequest("/v2/verify/init", body)
	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedResp controllers.VerifyInitResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	suite.Require().NotNil(parsedResp.VerificationToken)
	suite.WithinDuration(time.Now().Add(datastore.VerificationExpiration), parsedResp.VerificationTokenExpiresAt, 5*time.Second)

	_, err := suite.jwtService.ValidateVerificationToken(*parsedResp.VerificationToken)
	suite.NoError(err)

	suite.sesMock.AssertExpectations(suite.T())
}

func (suite *VerificationTestSuite) TestVerifyInitTooMany() {
	suite.SetupController(false, true)

	body := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "auth_token",
		Service: "email-aliases",
		Locale:  "en-US",
	}

	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Times(3)

	// use range
	for i := 0; i < 3; i++ {
		resp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", body), suite.router)
		suite.Equal(http.StatusOK, resp.Code)

		var parsedResp controllers.VerifyInitResponse
		util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
		suite.NotNil(parsedResp.VerificationToken)

		_, err := suite.jwtService.ValidateVerificationToken(*parsedResp.VerificationToken)
		suite.NoError(err)
	}
	for i := 0; i < 3; i++ {
		resp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", body), suite.router)
		suite.Equal(http.StatusBadRequest, resp.Code)

		util.AssertErrorResponseCode(suite.T(), resp, util.ErrTooManyVerifications.Code)
	}

	suite.sesMock.AssertExpectations(suite.T())
}

func (suite *VerificationTestSuite) TestVerifyInitUnsupportedEmail() {
	suite.SetupController(true, true)

	suite.sesMock.On("SendVerificationEmail", mock.Anything, mock.Anything, mock.Anything, "en-US").Return(nil).Maybe()

	// Test bravealias.com domain
	body := controllers.VerifyInitRequest{
		Email:   "test@bravealias.com",
		Intent:  "auth_token",
		Service: "email-aliases",
		Locale:  "en-US",
	}
	resp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", body), suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrEmailDomainNotSupported.Code)

	// Test 'strict' TLDs for email-aliases service
	body.Email = "test@example.ru"
	resp = util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", body), suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrEmailDomainNotSupported.Code)

	body.Email = "test@example.kp"
	resp = util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", body), suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrEmailDomainNotSupported.Code)
}

func (suite *VerificationTestSuite) TestVerifyInitIntentNotAllowed() {
	testCases := []struct {
		intent              string
		service             string
		passwordAuthEnabled bool
	}{
		{
			intent:              "auth_token",
			service:             "email-aliases",
			passwordAuthEnabled: true,
		},
		{
			intent:              "reset_password",
			service:             "accounts",
			passwordAuthEnabled: false,
		},
	}

	for _, tc := range testCases {
		suite.SetupController(tc.passwordAuthEnabled, !tc.passwordAuthEnabled) // password auth enabled, email auth disabled

		body := controllers.VerifyInitRequest{
			Email:   "test@example.com",
			Service: tc.service,
			Intent:  tc.intent,
			Locale:  "en-US",
		}

		resp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", body), suite.router)
		suite.Equal(http.StatusBadRequest, resp.Code)
		util.AssertErrorResponseCode(suite.T(), resp, util.ErrIntentNotAllowed.Code)
	}
}

func (suite *VerificationTestSuite) TestVerifyInitBadIntent() {
	suite.SetupController(true, false)

	// Test registration intent - should fail because registration intent
	// should only be used internally by the accounts service, not via direct verification init
	body := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "registration",
		Service: "accounts",
		Locale:  "en-US",
	}

	resp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", body), suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
}

func (suite *VerificationTestSuite) TestVerifyComplete() {
	suite.SetupController(false, true)

	testCases := []struct {
		intent              string
		service             string
		shouldHaveAuthToken bool
	}{
		{
			intent:              "auth_token",
			service:             "email-aliases",
			shouldHaveAuthToken: true,
		},
		{
			intent:              "verification",
			service:             "email-aliases",
			shouldHaveAuthToken: false,
		},
	}

	for _, tc := range testCases {
		suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

		initBody := controllers.VerifyInitRequest{
			Email:   "test@example.com",
			Intent:  tc.intent,
			Service: tc.service,
			Locale:  "en-US",
		}

		initResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", initBody), suite.router)
		suite.Equal(http.StatusOK, initResp.Code)

		var parsedInitResp controllers.VerifyInitResponse
		util.DecodeJSONTestResponse(suite.T(), initResp.Body, &parsedInitResp)
		suite.Require().NotNil(parsedInitResp.VerificationToken)

		verificationID, err := suite.jwtService.ValidateVerificationToken(*parsedInitResp.VerificationToken)
		suite.NoError(err)

		verification, err := suite.ds.GetVerificationStatus(verificationID)
		suite.NoError(err)

		// First attempt - should succeed
		completeBody := controllers.VerifyCompleteRequest{
			Code: verification.Code,
		}
		completeReq := util.CreateJSONTestRequest("/v2/verify/complete", completeBody)
		completeReq.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
		completeResp := util.ExecuteTestRequest(completeReq, suite.router)
		suite.Equal(http.StatusOK, completeResp.Code)

		var result controllers.VerifyCompleteResponse
		util.DecodeJSONTestResponse(suite.T(), completeResp.Body, &result)
		suite.Equal(tc.service, result.Service)
		expectedEmail := "test@example.com"
		suite.Equal(&expectedEmail, result.Email)

		if tc.shouldHaveAuthToken {
			suite.Require().NotNil(result.AuthToken)
			sessionID, _, err := suite.jwtService.ValidateAuthToken(*result.AuthToken)
			suite.NoError(err)
			session, err := suite.ds.GetSession(sessionID)
			suite.NoError(err)
			suite.Require().NotNil(session)
			suite.Equal(datastore.EmailAuthSessionVersion, session.Version)
		} else {
			suite.Nil(result.AuthToken)
		}

		// Second attempt
		completeReq = util.CreateJSONTestRequest("/v2/verify/complete", completeBody)
		completeReq.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
		completeResp = util.ExecuteTestRequest(completeReq, suite.router)
		if tc.shouldHaveAuthToken {
			// auth_token/registration: re-issues auth token from existing session
			suite.Equal(http.StatusOK, completeResp.Code)
			var result2 controllers.VerifyCompleteResponse
			util.DecodeJSONTestResponse(suite.T(), completeResp.Body, &result2)
			suite.Require().NotNil(result2.AuthToken)
			sessionID2, _, err := suite.jwtService.ValidateAuthToken(*result2.AuthToken)
			suite.NoError(err)
			// Same session as the first attempt
			firstSessionID, _, _ := suite.jwtService.ValidateAuthToken(*result.AuthToken)
			suite.Equal(firstSessionID, sessionID2)
		} else {
			suite.Equal(http.StatusBadRequest, completeResp.Code)
			util.AssertErrorResponseCode(suite.T(), completeResp, util.ErrEmailAlreadyVerified.Code)
		}
	}

	suite.sesMock.AssertExpectations(suite.T())
}

func (suite *VerificationTestSuite) TestVerifyCompleteWithHyphen() {
	suite.SetupController(false, true)

	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

	initBody := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "auth_token",
		Service: "email-aliases",
		Locale:  "en-US",
	}

	initResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", initBody), suite.router)
	suite.Equal(http.StatusOK, initResp.Code)

	var parsedInitResp controllers.VerifyInitResponse
	util.DecodeJSONTestResponse(suite.T(), initResp.Body, &parsedInitResp)
	suite.Require().NotNil(parsedInitResp.VerificationToken)

	verificationID, err := suite.jwtService.ValidateVerificationToken(*parsedInitResp.VerificationToken)
	suite.NoError(err)

	verification, err := suite.ds.GetVerificationStatus(verificationID)
	suite.NoError(err)

	// Insert a hyphen in the middle and lowercase to exercise normalization.
	mangled := strings.ToLower(verification.Code[:3]) + "-" + strings.ToLower(verification.Code[3:])
	completeBody := controllers.VerifyCompleteRequest{Code: mangled}
	completeReq := util.CreateJSONTestRequest("/v2/verify/complete", completeBody)
	completeReq.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
	completeResp := util.ExecuteTestRequest(completeReq, suite.router)
	suite.Equal(http.StatusOK, completeResp.Code)

	suite.sesMock.AssertExpectations(suite.T())
}

func (suite *VerificationTestSuite) TestVerifyResult() {
	suite.SetupController(false, true)

	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

	initBody := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "verification",
		Service: "email-aliases",
		Locale:  "en-US",
	}

	initResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", initBody), suite.router)
	suite.Equal(http.StatusOK, initResp.Code)

	var parsedInitResp controllers.VerifyInitResponse
	util.DecodeJSONTestResponse(suite.T(), initResp.Body, &parsedInitResp)
	suite.Require().NotNil(parsedInitResp.VerificationToken)

	verificationToken := *parsedInitResp.VerificationToken
	verificationID, err := suite.jwtService.ValidateVerificationToken(verificationToken)
	suite.Require().NoError(err)

	verification, err := suite.ds.GetVerificationStatus(verificationID)
	suite.Require().NoError(err)

	// Before completion - result should show not verified
	resultReq := httptest.NewRequest(http.MethodGet, "/v2/verify/result", nil)
	resultReq.Header.Set("Authorization", "Bearer "+verificationToken)
	resultResp := util.ExecuteTestRequest(resultReq, suite.router)
	suite.Equal(http.StatusOK, resultResp.Code)

	var result controllers.VerifyResultResponse
	util.DecodeJSONTestResponse(suite.T(), resultResp.Body, &result)
	suite.False(result.Verified)
	suite.Equal("test@example.com", result.Email)
	suite.Equal("email-aliases", result.Service)

	// Complete verification
	completeBody := controllers.VerifyCompleteRequest{Code: verification.Code}
	completeReq := util.CreateJSONTestRequest("/v2/verify/complete", completeBody)
	completeReq.Header.Set("Authorization", "Bearer "+verificationToken)
	completeResp := util.ExecuteTestRequest(completeReq, suite.router)
	suite.Equal(http.StatusOK, completeResp.Code)

	// After completion - result should show verified
	resultReq = httptest.NewRequest(http.MethodGet, "/v2/verify/result", nil)
	resultReq.Header.Set("Authorization", "Bearer "+verificationToken)
	resultResp = util.ExecuteTestRequest(resultReq, suite.router)
	suite.Equal(http.StatusOK, resultResp.Code)

	util.DecodeJSONTestResponse(suite.T(), resultResp.Body, &result)
	suite.True(result.Verified)
	suite.Equal("test@example.com", result.Email)
	suite.Equal("email-aliases", result.Service)

	suite.sesMock.AssertExpectations(suite.T())
}

func (suite *VerificationTestSuite) TestVerifyCompleteWrongCode() {
	suite.SetupController(false, true)

	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

	initBody := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "auth_token",
		Service: "email-aliases",
		Locale:  "en-US",
	}

	initResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", initBody), suite.router)
	suite.Equal(http.StatusOK, initResp.Code)

	var parsedInitResp controllers.VerifyInitResponse
	util.DecodeJSONTestResponse(suite.T(), initResp.Body, &parsedInitResp)
	suite.Require().NotNil(parsedInitResp.VerificationToken)

	verificationID, err := suite.jwtService.ValidateVerificationToken(*parsedInitResp.VerificationToken)
	suite.NoError(err)

	verification, err := suite.ds.GetVerificationStatus(verificationID)
	suite.NoError(err)

	// Submit 10 wrong codes - each should increment code_attempts
	for i := 1; i <= 10; i++ {
		completeBody := controllers.VerifyCompleteRequest{Code: "AAAAAA"}
		completeReq := util.CreateJSONTestRequest("/v2/verify/complete", completeBody)
		completeReq.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
		completeResp := util.ExecuteTestRequest(completeReq, suite.router)

		suite.Equal(http.StatusBadRequest, completeResp.Code)
		util.AssertErrorResponseCode(suite.T(), completeResp, util.ErrInvalidCode.Code)

		updated, err := suite.ds.GetVerificationStatus(verification.ID)
		suite.Require().NoError(err)
		suite.Equal(int16(i), updated.CodeAttempts)
	}

	// Any further attempt should be rejected once max attempts is reached
	completeBody := controllers.VerifyCompleteRequest{Code: verification.Code}
	completeReq := util.CreateJSONTestRequest("/v2/verify/complete", completeBody)
	completeReq.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
	completeResp := util.ExecuteTestRequest(completeReq, suite.router)
	suite.Equal(http.StatusBadRequest, completeResp.Code)
	util.AssertErrorResponseCode(suite.T(), completeResp, util.ErrMaxCodeAttempts.Code)

	suite.sesMock.AssertExpectations(suite.T())
}

func (suite *VerificationTestSuite) TestVerificationExpiry() {
	// Setup initial verification request
	suite.SetupController(false, true)
	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

	initBody := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "verification",
		Service: "email-aliases",
		Locale:  "en-US",
	}

	// Initialize verification
	initResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", initBody), suite.router)
	suite.Equal(http.StatusOK, initResp.Code)

	var parsedInitResp controllers.VerifyInitResponse
	util.DecodeJSONTestResponse(suite.T(), initResp.Body, &parsedInitResp)
	suite.Require().NotNil(parsedInitResp.VerificationToken)

	verificationID, err := suite.jwtService.ValidateVerificationToken(*parsedInitResp.VerificationToken)
	suite.NoError(err)

	// Manually set verification to expired state (31 minutes ago)
	err = suite.ds.DB.Model(&datastore.Verification{}).
		Where("id = ?", verificationID).
		Update("created_at", time.Now().UTC().Add(-31*time.Minute)).Error
	suite.NoError(err)

	// Query verification status - should be expired
	completeBody := controllers.VerifyCompleteRequest{Code: "AAAAAA"}
	completeReq := util.CreateJSONTestRequest("/v2/verify/complete", completeBody)
	completeReq.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
	completeResp := util.ExecuteTestRequest(completeReq, suite.router)

	// Should return not found due to expired verification
	suite.Equal(http.StatusNotFound, completeResp.Code)
}

func (suite *VerificationTestSuite) TestVerifyInitChangePasswordRequiresAuth() {
	suite.SetupController(true, false)

	email := "test@example.com"
	account, err := suite.ds.GetOrCreateAccount(email)
	suite.Require().NoError(err)
	err = suite.ds.UpdateAccountLastEmailVerifiedAt(account.ID)
	suite.Require().NoError(err)

	// Test change_password intent without auth - should fail with ErrIntentNotAllowed
	body := controllers.VerifyInitRequest{
		Email:   email,
		Intent:  "change_password",
		Service: "accounts",
		Locale:  "en-US",
	}

	resp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", body), suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrIntentNotAllowed.Code)

	// Test change_password intent with valid auth session
	session, err := suite.ds.CreateSession(account.ID, datastore.PasswordAuthSessionVersion, "")
	suite.Require().NoError(err)
	token, err := suite.jwtService.CreateAuthToken(session.ID, nil, util.AccountsServiceName)
	suite.Require().NoError(err)

	suite.sesMock.On("SendVerificationEmail", mock.Anything, email, mock.Anything, "en-US").Return(nil).Once()

	// Test change_password intent with mismatched email - should fail with ErrIntentNotAllowed
	body.Email = "different@example.com"
	req := util.CreateJSONTestRequest("/v2/verify/init", body)
	req.Header.Set("Authorization", "Bearer "+token)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrIntentNotAllowed.Code)

	body.Email = email
	req = util.CreateJSONTestRequest("/v2/verify/init", body)
	req.Header.Set("Authorization", "Bearer "+token)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	suite.sesMock.AssertExpectations(suite.T())
}

func (suite *VerificationTestSuite) TestVerifyResend() {
	suite.SetupController(false, true)

	initBody := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "verification",
		Service: "email-aliases",
		Locale:  "en-US",
	}

	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Times(4)

	initResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", initBody), suite.router)
	suite.Equal(http.StatusOK, initResp.Code)

	var parsedInitResp controllers.VerifyInitResponse
	util.DecodeJSONTestResponse(suite.T(), initResp.Body, &parsedInitResp)
	suite.Require().NotNil(parsedInitResp.VerificationToken)

	verificationToken := *parsedInitResp.VerificationToken
	verificationID, err := suite.jwtService.ValidateVerificationToken(verificationToken)
	suite.Require().NoError(err)

	verification, err := suite.ds.GetVerificationStatus(verificationID)
	suite.NoError(err)
	suite.Equal(int16(1), verification.EmailAttempts)

	resendBody := controllers.VerifyResendRequest{
		Locale: "en-US",
	}

	for i := 2; i <= 6; i++ {
		req := util.CreateJSONTestRequest("/v2/verify/resend", resendBody)
		req.Header.Set("Authorization", "Bearer "+verificationToken)
		resp := util.ExecuteTestRequest(req, suite.router)

		if i <= 4 {
			suite.Equal(http.StatusNoContent, resp.Code)
			verification, err = suite.ds.GetVerificationStatus(verificationID)
			suite.NoError(err)
			suite.Equal(int16(i), verification.EmailAttempts)
		} else {
			suite.Equal(http.StatusBadRequest, resp.Code)
			util.AssertErrorResponseCode(suite.T(), resp, util.ErrMaxEmailAttempts.Code)
		}
	}

	// Complete verification then attempt resend
	completeBody := controllers.VerifyCompleteRequest{Code: verification.Code}
	completeReq := util.CreateJSONTestRequest("/v2/verify/complete", completeBody)
	completeReq.Header.Set("Authorization", "Bearer "+verificationToken)
	completeResp := util.ExecuteTestRequest(completeReq, suite.router)
	suite.Equal(http.StatusOK, completeResp.Code)

	req := util.CreateJSONTestRequest("/v2/verify/resend", resendBody)
	req.Header.Set("Authorization", "Bearer "+verificationToken)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrEmailAlreadyVerified.Code)

	suite.sesMock.AssertExpectations(suite.T())
}

func (suite *VerificationTestSuite) TestVerifyDelete() {
	suite.SetupController(true, true)

	email := "test@example.com"
	// Use InitializeVerification to create a registration verification
	verification, verificationToken, err := suite.verificationService.InitializeVerification(
		suite.T().Context(),
		email,
		"registration",
		"accounts",
		nil,
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(verificationToken)

	// Manually create an unverified account for this email
	account, err := suite.ds.GetOrCreateAccount(email)
	suite.Require().NoError(err)
	suite.Nil(account.LastEmailVerifiedAt)

	// Delete verification
	req := httptest.NewRequest(http.MethodDelete, "/v2/verify", nil)
	req.Header.Set("Authorization", "Bearer "+*verificationToken)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNoContent, resp.Code)

	// Verify verification was deleted
	_, err = suite.ds.GetVerificationStatus(verification.ID)
	suite.ErrorIs(err, util.ErrVerificationNotFound)

	// Verify account was deleted
	_, err = suite.ds.GetAccount(nil, email)
	suite.ErrorIs(err, datastore.ErrAccountNotFound)
}

func (suite *VerificationTestSuite) TestVerifyDeleteForbidden() {
	suite.SetupController(true, false)

	// Use InitializeVerification to create an auth_token verification
	_, verificationToken, err := suite.verificationService.InitializeVerification(
		suite.T().Context(),
		"test@example.com",
		"verification",
		"email-aliases",
		nil,
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(*verificationToken)

	// Delete verification - should be bad request for auth_token intent
	req := httptest.NewRequest(http.MethodDelete, "/v2/verify", nil)
	req.Header.Set("Authorization", "Bearer "+*verificationToken)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrIntentNotAllowed.Code)
}

func (suite *VerificationTestSuite) TestVerifyDeleteAlreadyVerified() {
	suite.SetupController(true, true)

	// Use InitializeVerification to create a registration verification
	verification, verificationToken, err := suite.verificationService.InitializeVerification(
		suite.T().Context(),
		"test@example.com",
		"registration",
		"accounts",
		nil,
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(verificationToken)

	// Manually mark verification as verified in datastore
	err = suite.ds.DB.Model(&datastore.Verification{}).Where("id = ?", verification.ID).Update("verified", true).Error
	suite.Require().NoError(err)

	// Delete verification - should be bad request for already verified
	req := httptest.NewRequest(http.MethodDelete, "/v2/verify", nil)
	req.Header.Set("Authorization", "Bearer "+*verificationToken)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusBadRequest, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrEmailAlreadyVerified.Code)
}

func TestVerificationTestSuite(t *testing.T) {
	t.Run("NoKeyService", func(t *testing.T) {
		suite.Run(t, NewVerificationTestSuite(false))
	})
	t.Run("WithKeyService", func(t *testing.T) {
		suite.Run(t, NewVerificationTestSuite(true))
	})
}
