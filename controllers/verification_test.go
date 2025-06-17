package controllers_test

import (
	"context"
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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type VerificationTestSuite struct {
	suite.Suite
	useKeyService bool
	ds            *datastore.Datastore
	keyServiceDs  *datastore.Datastore
	sesMock       *MockSESService
	jwtService    *services.JWTService
	router        *chi.Mux
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
	verificationService := services.NewVerificationService(suite.ds, suite.jwtService, suite.sesMock, passwordAuthEnabled, emailAuthEnabled)
	controller := controllers.NewVerificationController(suite.ds, verificationService)

	verificationAuthMiddleware := middleware.VerificationAuthMiddleware(suite.jwtService, suite.ds, true)
	servicesKeyMiddleware := middleware.ServicesKeyMiddleware(util.DevelopmentEnv)

	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/verify", controller.Router(verificationAuthMiddleware, servicesKeyMiddleware, false))
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
			intent:              "set_password",
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

func (suite *VerificationTestSuite) TestVerifyValidCheck() {
	suite.SetupController(true, false)

	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

	// Initialize verification
	initBody := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "verification",
		Service: "accounts",
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

	// Check valid verification - should return 204
	checkURL := fmt.Sprintf("/v2/verify/complete?id=%s&code=%s", verification.ID, verification.Code)
	checkReq := httptest.NewRequest(http.MethodGet, checkURL, nil)
	checkResp := util.ExecuteTestRequest(checkReq, suite.router)
	suite.Equal(http.StatusNoContent, checkResp.Code)

	// Should not be able to check with invalid code - should return 404
	badCheckURL := fmt.Sprintf("/v2/verify/complete?id=%s&code=%s", verification.ID, "abc123")
	checkReq = httptest.NewRequest(http.MethodGet, badCheckURL, nil)
	checkResp = util.ExecuteTestRequest(checkReq, suite.router)
	suite.Equal(http.StatusNotFound, checkResp.Code)

	// Complete verification
	completeBody := controllers.VerifyCompleteRequest{
		ID:   verification.ID,
		Code: verification.Code,
	}
	completeResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/complete", completeBody), suite.router)
	suite.Equal(http.StatusOK, completeResp.Code)

	// Check after completion - should return 404
	checkReq = httptest.NewRequest(http.MethodGet, checkURL, nil)
	checkResp = util.ExecuteTestRequest(checkReq, suite.router)
	suite.Equal(http.StatusNotFound, checkResp.Code)
	util.AssertErrorResponseCode(suite.T(), checkResp, util.ErrVerificationNotFound.Code)

	// Check with invalid ID - should return 400
	checkURL = fmt.Sprintf("/v2/verify/complete?id=invalid&code=%s", verification.Code)
	checkReq = httptest.NewRequest(http.MethodGet, checkURL, nil)
	checkResp = util.ExecuteTestRequest(checkReq, suite.router)
	suite.Equal(http.StatusBadRequest, checkResp.Code)

	// Check with missing code - should return 400
	checkURL = fmt.Sprintf("/v2/verify/complete?id=%s", verification.ID)
	checkReq = httptest.NewRequest(http.MethodGet, checkURL, nil)
	checkResp = util.ExecuteTestRequest(checkReq, suite.router)
	suite.Equal(http.StatusBadRequest, checkResp.Code)
}

func (suite *VerificationTestSuite) TestVerifyComplete() {
	suite.SetupController(true, false)

	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

	initBody := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "verification",
		Service: "accounts",
		Locale:  "en-US",
	}

	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

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
		ID:   verification.ID,
		Code: verification.Code,
	}

	completeResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/complete", completeBody), suite.router)
	suite.Equal(http.StatusOK, completeResp.Code)
	var parsedResp controllers.VerifyCompleteResponse
	util.DecodeJSONTestResponse(suite.T(), completeResp.Body, &parsedResp)
	suite.Equal(verification.Service, parsedResp.Service)

	// Second attempt - should fail
	completeResp = util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/complete", completeBody), suite.router)
	suite.Equal(http.StatusNotFound, completeResp.Code)
	util.AssertErrorResponseCode(suite.T(), completeResp, util.ErrVerificationNotFound.Code)
}

func (suite *VerificationTestSuite) TestVerifyQueryResult() {
	suite.SetupController(false, true)

	testCases := []struct {
		intent                         string
		service                        string
		shouldHaveAuthToken            bool
		verificationUsableMoreThanOnce bool
	}{
		{
			intent:                         "auth_token",
			service:                        "email-aliases",
			shouldHaveAuthToken:            true,
			verificationUsableMoreThanOnce: false,
		},
		{
			intent:                         "verification",
			service:                        "email-aliases",
			shouldHaveAuthToken:            false,
			verificationUsableMoreThanOnce: true,
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

		// First query - should be unverified
		req := controllers.VerifyResultRequest{
			Wait: false,
		}
		request := util.CreateJSONTestRequest("/v2/verify/result", req)
		request.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
		resp := util.ExecuteTestRequest(request, suite.router)
		suite.Equal(http.StatusOK, resp.Code)

		var result controllers.VerifyResultResponse
		util.DecodeJSONTestResponse(suite.T(), resp.Body, &result)
		suite.False(result.Verified)
		suite.Nil(result.Email)
		suite.Equal(tc.service, result.Service)
		suite.Nil(result.AuthToken)

		// Complete verification
		completeReq := controllers.VerifyCompleteRequest{
			ID:   verification.ID,
			Code: verification.Code,
		}
		completeResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/complete", completeReq), suite.router)
		suite.Equal(http.StatusOK, completeResp.Code)

		// Second query - should be verified
		request = util.CreateJSONTestRequest("/v2/verify/result", req)
		request.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
		resp = util.ExecuteTestRequest(request, suite.router)
		suite.Equal(http.StatusOK, resp.Code)

		expectedEmail := "test@example.com"
		util.DecodeJSONTestResponse(suite.T(), resp.Body, &result)
		suite.True(result.Verified)
		suite.Equal(&expectedEmail, result.Email)
		suite.Equal(tc.service, result.Service)
		if tc.shouldHaveAuthToken {
			suite.NotNil(result.AuthToken)

			sessionID, _, err := suite.jwtService.ValidateAuthToken(*result.AuthToken)
			suite.NoError(err)
			session, err := suite.ds.GetSession(sessionID)
			suite.NoError(err)
			suite.Require().NotNil(session)
			suite.Equal(session.Version, 1)
		} else {
			suite.Nil(result.AuthToken)
		}

		// Third query - should work or be blocked depending on test case
		request = util.CreateJSONTestRequest("/v2/verify/result", req)
		request.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
		resp = util.ExecuteTestRequest(request, suite.router)

		if tc.verificationUsableMoreThanOnce {
			suite.Equal(http.StatusOK, resp.Code)

			util.DecodeJSONTestResponse(suite.T(), resp.Body, &result)
			suite.True(result.Verified)
			suite.Equal(&expectedEmail, result.Email)
			suite.Equal(tc.service, result.Service)
		} else {
			suite.Equal(http.StatusNotFound, resp.Code)
		}
	}
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
	req := controllers.VerifyResultRequest{
		Wait: false,
	}
	request := util.CreateJSONTestRequest("/v2/verify/result", req)
	request.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
	resp := util.ExecuteTestRequest(request, suite.router)

	// Should return not found due to expired verification
	suite.Equal(http.StatusNotFound, resp.Code)
}

func TestVerificationTestSuite(t *testing.T) {
	t.Run("NoKeyService", func(t *testing.T) {
		suite.Run(t, NewVerificationTestSuite(false))
	})
	t.Run("WithKeyService", func(t *testing.T) {
		suite.Run(t, NewVerificationTestSuite(true))
	})
}
