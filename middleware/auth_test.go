package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	suite.ds, err = datastore.NewDatastore(datastore.EmailAuthSessionVersion, true)
	require.NoError(suite.T(), err)

	suite.jwtService, err = services.NewJWTService(suite.ds)
	require.NoError(suite.T(), err)

	suite.account, err = suite.ds.GetOrCreateAccount("test@example.com")
	require.NoError(suite.T(), err)
}

func (suite *MiddlewareTestSuite) TestAuthMiddleware() {
	// Create middleware
	mw := middleware.AuthMiddleware(suite.jwtService, suite.ds, 1)

	// Create test token
	session, err := suite.ds.CreateSession(suite.account.ID, datastore.EmailAuthSessionVersion, "")
	require.NoError(suite.T(), err)
	token, err := suite.jwtService.CreateAuthToken(session.ID)
	require.NoError(suite.T(), err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxSession := r.Context().Value(middleware.ContextSession).(*datastore.SessionWithAccountInfo)
		assert.Equal(suite.T(), ctxSession.ID, session.ID)
		assert.Equal(suite.T(), ctxSession.Email, suite.account.Email)
		w.WriteHeader(http.StatusOK)
	})

	// Test valid request
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp := util.ExecuteTestRequest(req, mw(handler))
	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	// Test invalid token
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	resp = util.ExecuteTestRequest(req, mw(handler))
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)

	// Test missing token
	req = httptest.NewRequest("GET", "/", nil)
	resp = util.ExecuteTestRequest(req, mw(handler))
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)

	// Test outdated session version
	mw = middleware.AuthMiddleware(suite.jwtService, suite.ds, 2)
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp = util.ExecuteTestRequest(req, mw(handler))
	assert.Equal(suite.T(), http.StatusForbidden, resp.Code)
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

	mw := middleware.ServicesKeyMiddleware()

	// Test valid key
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("brave-key", testKey)
	resp := util.ExecuteTestRequest(req, mw(handler))
	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	// Test invalid key
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("brave-key", "wrong-key")
	resp = util.ExecuteTestRequest(req, mw(handler))
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)

	// Test missing key
	req = httptest.NewRequest("GET", "/", nil)
	resp = util.ExecuteTestRequest(req, mw(handler))
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)
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
	require.NoError(suite.T(), err)
	token, err := suite.jwtService.CreateVerificationToken(verification.ID, time.Minute*30, verification.Service)
	require.NoError(suite.T(), err)

	// Test valid request
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp := util.ExecuteTestRequest(req, mw(handler))
	assert.Equal(suite.T(), http.StatusOK, resp.Code)

	// Test expired verification
	err = suite.ds.DB.Model(&datastore.Verification{}).Where("id = ?", verification.ID).Update("created_at", time.Now().Add(-45*time.Minute)).Error
	require.NoError(suite.T(), err)

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp = util.ExecuteTestRequest(req, mw(handler))
	assert.Equal(suite.T(), http.StatusNotFound, resp.Code)
	util.AssertErrorResponseCode(suite.T(), resp, util.ErrVerificationNotFound.Code)

	// Test invalid token
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	resp = util.ExecuteTestRequest(req, mw(handler))
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)

	// Test missing token
	req = httptest.NewRequest("GET", "/", nil)
	resp = util.ExecuteTestRequest(req, mw(handler))
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)
}
