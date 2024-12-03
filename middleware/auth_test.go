package middleware_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type MiddlewareTestSuite struct {
	suite.Suite
	ds         *datastore.Datastore
	jwtService *services.JWTService
	account    *datastore.Account
}

func TestMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(MiddlewareTestSuite))
}

func (suite *MiddlewareTestSuite) SetupTest() {
	var err error
	suite.ds, err = datastore.NewDatastore(datastore.EmailAuthSessionVersion, false, true)
	suite.Require().NoError(err)

	suite.jwtService, err = services.NewJWTService(suite.ds, false)
	suite.Require().NoError(err)

	suite.account, err = suite.ds.GetOrCreateAccount("test@example.com")
	suite.Require().NoError(err)
}

func (suite *MiddlewareTestSuite) TestAuthMiddleware() {
	// Create middleware
	mw := middleware.AuthMiddleware(suite.jwtService, suite.ds, 1)

	// Create test token
	session, err := suite.ds.CreateSession(suite.account.ID, datastore.EmailAuthSessionVersion, "")
	suite.Require().NoError(err)
	token, err := suite.jwtService.CreateAuthToken(session.ID)
	suite.Require().NoError(err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxSession := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)
		suite.Equal(ctxSession.ID, session.ID)
		suite.Equal(ctxSession.Email, suite.account.Email)
		w.WriteHeader(http.StatusOK)
	})

	// Test valid request
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp := util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusOK, resp.Code)

	// Test invalid token
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	resp = util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusUnauthorized, resp.Code)

	noneToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":1}`)) + "." + strings.Split(token, ".")[1] + "." + strings.Split(token, ".")[2]

	// Test alg=none token
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+noneToken)
	resp = util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusUnauthorized, resp.Code)

	// Test missing token
	req = httptest.NewRequest("GET", "/", nil)
	resp = util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusUnauthorized, resp.Code)

	// Test outdated session version
	mw = middleware.AuthMiddleware(suite.jwtService, suite.ds, 2)
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp = util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusForbidden, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrOutdatedSession.Code)
}

func (suite *MiddlewareTestSuite) TestServicesKeyMiddleware() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Set services key
	testKey := "test-key"
	os.Setenv("BRAVE_SERVICES_KEY", testKey)
	defer os.Unsetenv("BRAVE_SERVICES_KEY")

	mw := middleware.ServicesKeyMiddleware(util.ProductionEnv)

	// Test valid key
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("brave-key", testKey)
	resp := util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusOK, resp.Code)

	// Test invalid key
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("brave-key", "wrong-key")
	resp = util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusUnauthorized, resp.Code)

	// Test missing key
	req = httptest.NewRequest("GET", "/", nil)
	resp = util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusUnauthorized, resp.Code)
}

func (suite *MiddlewareTestSuite) TestVerificationAuthMiddleware() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verification := r.Context().Value(middleware.ContextVerification).(*datastore.Verification)
		assert.NotNil(suite.T(), verification)
		w.WriteHeader(http.StatusOK)
	})

	// Create middleware
	mw := middleware.VerificationAuthMiddleware(suite.jwtService, suite.ds)

	// Create test verification
	verification, err := suite.ds.CreateVerification("test@example.com", "inbox-aliases", "verification")
	suite.Require().NoError(err)
	token, err := suite.jwtService.CreateVerificationToken(verification.ID, time.Minute*30, verification.Service)
	suite.Require().NoError(err)

	// Test valid request
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp := util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusOK, resp.Code)

	// Test expired verification
	err = suite.ds.DB.Model(&datastore.Verification{}).Where("id = ?", verification.ID).Update("created_at", time.Now().Add(-45*time.Minute)).Error
	suite.Require().NoError(err)

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp = util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusNotFound, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrVerificationNotFound.Code)

	// Test invalid token
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	resp = util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusUnauthorized, resp.Code)

	// Test missing token
	req = httptest.NewRequest("GET", "/", nil)
	resp = util.ExecuteTestRequest(req, mw(handler))
	suite.Equal(http.StatusUnauthorized, resp.Code)
}
