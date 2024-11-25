package controllers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brave/accounts/controllers"
	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type SessionsTestSuite struct {
	suite.Suite
	ds           *datastore.Datastore
	jwtService   *services.JWTService
	router       *chi.Mux
	mainAccount  *datastore.Account
	otherAccount *datastore.Account
	sessions     []*datastore.Session
}

func TestSessionsTestSuite(t *testing.T) {
	suite.Run(t, new(SessionsTestSuite))
}

func (suite *SessionsTestSuite) SetupTest() {
	var err error
	suite.ds, err = datastore.NewDatastore(datastore.PasswordAuthSessionVersion, true)
	require.NoError(suite.T(), err)

	suite.jwtService, err = services.NewJWTService(suite.ds)
	require.NoError(suite.T(), err)
	controller := controllers.NewSessionsController(suite.ds)

	// Create middleware
	authMiddleware := middleware.AuthMiddleware(suite.jwtService, suite.ds, 1)

	// Setup router
	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/sessions", controller.Router(authMiddleware))

	// Create test accounts
	suite.mainAccount, err = suite.ds.GetOrCreateAccount("test@example.com")
	require.NoError(suite.T(), err)
	suite.otherAccount, err = suite.ds.GetOrCreateAccount("other@example.com")
	require.NoError(suite.T(), err)

	_, err = suite.ds.CreateSession(suite.otherAccount.ID, datastore.PasswordAuthSessionVersion, "other")
	require.NoError(suite.T(), err)
	suite.sessions = nil
	for i := 0; i < 2; i++ {
		session, err := suite.ds.CreateSession(suite.mainAccount.ID, datastore.PasswordAuthSessionVersion, "test")
		require.NoError(suite.T(), err)
		suite.sessions = append(suite.sessions, session)
	}
}

func (suite *SessionsTestSuite) TestListSessions() {
	// Get auth token
	token, err := suite.jwtService.CreateAuthToken(suite.sessions[0].ID)
	require.NoError(suite.T(), err)

	// Test list sessions
	req := httptest.NewRequest("GET", "/v2/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusOK, resp.Code)
	var sessions []datastore.Session
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &sessions)
	assert.Len(suite.T(), sessions, 2)
	for i, s := range sessions {
		assert.Equal(suite.T(), suite.sessions[i].ID, s.ID)
		assert.Equal(suite.T(), "test", s.UserAgent)
	}
}

func (suite *SessionsTestSuite) TestDeleteSession() {
	// Get auth token
	token, err := suite.jwtService.CreateAuthToken(suite.sessions[1].ID)
	require.NoError(suite.T(), err)

	// Test delete session
	req := httptest.NewRequest("DELETE", "/v2/sessions/"+suite.sessions[0].ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusNoContent, resp.Code)

	// Verify session was deleted
	var sessionCount int64
	suite.ds.DB.Model(&datastore.Session{}).Where("id = ?", suite.sessions[0].ID).Count(&sessionCount)
	assert.Equal(suite.T(), int64(0), sessionCount)

	// Test delete non-existent session
	req = httptest.NewRequest("DELETE", "/v2/sessions/"+suite.sessions[0].ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusNotFound, resp.Code)
}

func (suite *SessionsTestSuite) TestSessionsUnauthorized() {
	// Test list sessions without auth
	req := httptest.NewRequest("GET", "/v2/sessions", nil)
	resp := util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)

	// Test delete session without auth
	req = httptest.NewRequest("DELETE", "/v2/sessions/"+suite.sessions[0].ID.String(), nil)
	resp = util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)

	// Test with invalid auth token
	req = httptest.NewRequest("GET", "/v2/sessions", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	resp = util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.Code)

	// Test another account deleting a session that does not belong to account
	otherSession, err := suite.ds.CreateSession(suite.otherAccount.ID, datastore.PasswordAuthSessionVersion, "test")
	require.NoError(suite.T(), err)
	token, err := suite.jwtService.CreateAuthToken(otherSession.ID)
	require.NoError(suite.T(), err)
	req = httptest.NewRequest("DELETE", "/v2/sessions/"+suite.sessions[0].ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	assert.Equal(suite.T(), http.StatusNotFound, resp.Code)
}
