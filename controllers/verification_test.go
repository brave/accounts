package controllers_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/brave-experiments/accounts/controllers"
	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/middleware"
	"github.com/brave-experiments/accounts/services"
	"github.com/brave-experiments/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type VerificationTestSuite struct {
	suite.Suite
	ds         *datastore.Datastore
	sesMock    *MockSESService
	jwtService *services.JWTService
	router     *chi.Mux
}

func (suite *VerificationTestSuite) SetupController(passwordAuthEnabled bool, emailAuthEnabled bool) {
	var err error
	suite.ds, err = datastore.NewDatastore(datastore.EmailAuthSessionVersion, true)
	require.NoError(suite.T(), err)
	suite.jwtService, err = services.NewJWTService(suite.ds)
	require.NoError(suite.T(), err)
	suite.sesMock = &MockSESService{}
	controller := controllers.NewVerificationController(suite.ds, suite.jwtService, suite.sesMock, passwordAuthEnabled, emailAuthEnabled)

	verificationAuthMiddleware := middleware.VerificationAuthMiddleware(suite.jwtService, suite.ds)
	servicesKeyMiddleware := middleware.ServicesKeyMiddleware()

	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/verify", controller.Router(verificationAuthMiddleware, servicesKeyMiddleware, false))
}

type MockSESService struct {
	mock.Mock
}

func (m *MockSESService) SendVerificationEmail(ctx context.Context, email string, verification *datastore.Verification, locale string) error {
	args := m.Called(ctx, email, verification, locale)
	return args.Error(0)
}

func (suite *VerificationTestSuite) TestVerifyInit() {
	suite.SetupController(false, true)

	body := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "auth_token",
		Service: "inbox-aliases",
		Locale:  "en-US",
	}

	req := util.CreateJSONTestRequest("/v2/verify/init", body)
	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	var parsedResp controllers.VerifyInitResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	require.NotNil(suite.T(), parsedResp.VerificationToken)

	_, err := suite.jwtService.ValidateVerificationToken(*parsedResp.VerificationToken)
	assert.NoError(suite.T(), err)

	suite.sesMock.AssertExpectations(suite.T())
}

func (suite *VerificationTestSuite) TestVerifyInitTooMany() {
	suite.SetupController(false, true)

	body := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "auth_token",
		Service: "inbox-aliases",
		Locale:  "en-US",
	}

	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Times(3)

	// use range
	for i := 0; i < 3; i++ {
		resp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", body), suite.router)
		assert.Equal(suite.T(), http.StatusOK, resp.Code)

		var parsedResp controllers.VerifyInitResponse
		util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
		assert.NotNil(suite.T(), parsedResp.VerificationToken)

		_, err := suite.jwtService.ValidateVerificationToken(*parsedResp.VerificationToken)
		assert.NoError(suite.T(), err)
	}
	for i := 0; i < 3; i++ {
		resp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", body), suite.router)
		assert.Equal(suite.T(), http.StatusBadRequest, resp.Code)

		util.AssertErrorResponseCode(suite.T(), resp, util.ErrTooManyVerifications.Code)
	}

	suite.sesMock.AssertExpectations(suite.T())
}

func (suite *VerificationTestSuite) TestVerifyInitIntentNotAllowed() {
	testCases := []struct {
		intent              string
		service             string
		passwordAuthEnabled bool
	}{
		{
			intent:              "auth_token",
			service:             "inbox-aliases",
			passwordAuthEnabled: true,
		},
		{
			intent:              "verification",
			service:             "accounts",
			passwordAuthEnabled: true,
		},
		{
			intent:              "registration",
			service:             "premium",
			passwordAuthEnabled: true,
		},
		{
			intent:              "registration",
			service:             "inbox-aliases",
			passwordAuthEnabled: true,
		},
		{
			intent:              "registration",
			service:             "inbox-aliases",
			passwordAuthEnabled: true,
		},
		{
			intent:              "registration",
			service:             "premium",
			passwordAuthEnabled: true,
		},
		{
			intent:              "registration",
			service:             "accounts",
			passwordAuthEnabled: false,
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
		assert.Equal(suite.T(), http.StatusBadRequest, resp.Code)
		util.AssertErrorResponseCode(suite.T(), resp, util.ErrIntentNotAllowed.Code)
	}
}

func (suite *VerificationTestSuite) TestVerifyComplete() {
	suite.SetupController(true, false)

	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

	initBody := controllers.VerifyInitRequest{
		Email:   "test@example.com",
		Intent:  "registration",
		Service: "accounts",
		Locale:  "en-US",
	}

	suite.sesMock.On("SendVerificationEmail", mock.Anything, "test@example.com", mock.Anything, "en-US").Return(nil).Once()

	initResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/init", initBody), suite.router)
	assert.Equal(suite.T(), http.StatusOK, initResp.Code)

	var parsedInitResp controllers.VerifyInitResponse
	util.DecodeJSONTestResponse(suite.T(), initResp.Body, &parsedInitResp)
	require.NotNil(suite.T(), parsedInitResp.VerificationToken)

	verificationID, err := suite.jwtService.ValidateVerificationToken(*parsedInitResp.VerificationToken)
	assert.NoError(suite.T(), err)

	verification, err := suite.ds.GetVerificationStatus(verificationID)
	assert.NoError(suite.T(), err)

	// First attempt - should succeed
	completeBody := controllers.VerifyCompleteRequest{
		ID:   verification.ID,
		Code: verification.Code,
	}

	completeResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/complete", completeBody), suite.router)
	assert.Equal(suite.T(), http.StatusOK, completeResp.Code)
	var parsedResp controllers.VerifyCompleteResponse
	util.DecodeJSONTestResponse(suite.T(), completeResp.Body, &parsedResp)
	assert.Equal(suite.T(), verification.Service, parsedResp.Service)

	// Second attempt - should fail
	completeResp = util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/complete", completeBody), suite.router)
	assert.Equal(suite.T(), http.StatusNotFound, completeResp.Code)
	util.AssertErrorResponseCode(suite.T(), completeResp, util.ErrVerificationNotFound.Code)
}

func (suite *VerificationTestSuite) TestVerifyQueryResult() {
	suite.SetupController(false, true)

	testCases := []struct {
		intent              string
		service             string
		shouldHaveAuthToken bool
	}{
		{
			intent:              "auth_token",
			service:             "inbox-aliases",
			shouldHaveAuthToken: true,
		},
		{
			intent:              "verification",
			service:             "inbox-aliases",
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
		assert.Equal(suite.T(), http.StatusOK, initResp.Code)

		var parsedInitResp controllers.VerifyInitResponse
		util.DecodeJSONTestResponse(suite.T(), initResp.Body, &parsedInitResp)
		require.NotNil(suite.T(), parsedInitResp.VerificationToken)

		verificationID, err := suite.jwtService.ValidateVerificationToken(*parsedInitResp.VerificationToken)
		assert.NoError(suite.T(), err)

		verification, err := suite.ds.GetVerificationStatus(verificationID)
		assert.NoError(suite.T(), err)

		// First query - should be unverified
		req := controllers.VerifyResultRequest{
			Wait: false,
		}
		request := util.CreateJSONTestRequest("/v2/verify/result", req)
		request.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
		resp := util.ExecuteTestRequest(request, suite.router)
		assert.Equal(suite.T(), http.StatusOK, resp.Code)

		var result controllers.VerifyResultResponse
		util.DecodeJSONTestResponse(suite.T(), resp.Body, &result)
		assert.False(suite.T(), result.Verified)
		assert.Equal(suite.T(), "test@example.com", result.Email)
		assert.Equal(suite.T(), tc.service, result.Service)
		assert.Nil(suite.T(), result.AuthToken)

		// Complete verification
		completeReq := controllers.VerifyCompleteRequest{
			ID:   verification.ID,
			Code: verification.Code,
		}
		completeResp := util.ExecuteTestRequest(util.CreateJSONTestRequest("/v2/verify/complete", completeReq), suite.router)
		assert.Equal(suite.T(), http.StatusOK, completeResp.Code)

		// Second query - should be verified
		request = util.CreateJSONTestRequest("/v2/verify/result", req)
		request.Header.Set("Authorization", "Bearer "+*parsedInitResp.VerificationToken)
		resp = util.ExecuteTestRequest(request, suite.router)
		assert.Equal(suite.T(), http.StatusOK, resp.Code)

		util.DecodeJSONTestResponse(suite.T(), resp.Body, &result)
		assert.True(suite.T(), result.Verified)
		assert.Equal(suite.T(), "test@example.com", result.Email)
		assert.Equal(suite.T(), tc.service, result.Service)
		if tc.shouldHaveAuthToken {
			assert.NotNil(suite.T(), result.AuthToken)

			sessionID, err := suite.jwtService.ValidateAuthToken(*result.AuthToken)
			assert.NoError(suite.T(), err)
			session, err := suite.ds.GetSession(sessionID)
			assert.NoError(suite.T(), err)
			require.NotNil(suite.T(), session)
			assert.Equal(suite.T(), session.Version, 1)
		} else {
			assert.Nil(suite.T(), result.AuthToken)
		}
	}
}

func TestVerificationTestSuite(t *testing.T) {
	suite.Run(t, new(VerificationTestSuite))
}
