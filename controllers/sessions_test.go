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
	suite.Require().NoError(err)

	suite.jwtService, err = services.NewJWTService(suite.ds)
	suite.Require().NoError(err)
	controller := controllers.NewSessionsController(suite.ds)

	// Create middleware
	authMiddleware := middleware.AuthMiddleware(suite.jwtService, suite.ds, 1)

	// Setup router
	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/sessions", controller.Router(authMiddleware))

	// Create test accounts
	suite.mainAccount, err = suite.ds.GetOrCreateAccount("test@example.com")
	suite.Require().NoError(err)
	suite.otherAccount, err = suite.ds.GetOrCreateAccount("other@example.com")
	suite.Require().NoError(err)

	_, err = suite.ds.CreateSession(suite.otherAccount.ID, datastore.PasswordAuthSessionVersion, "other")
	suite.Require().NoError(err)
	suite.sessions = nil
	for i := 0; i < 2; i++ {
		session, err := suite.ds.CreateSession(suite.mainAccount.ID, datastore.PasswordAuthSessionVersion, "test")
		suite.Require().NoError(err)
		suite.sessions = append(suite.sessions, session)
	}
}

func (suite *SessionsTestSuite) TestListSessions() {
	// Get auth token
	token, err := suite.jwtService.CreateAuthToken(suite.sessions[0].ID)
	suite.Require().NoError(err)

	// Test list sessions
	req := httptest.NewRequest("GET", "/v2/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)
	var sessions []datastore.Session
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &sessions)
	suite.Len(sessions, 2)
	for i, s := range sessions {
		suite.Equal(suite.sessions[i].ID, s.ID)
		suite.Equal("test", s.UserAgent)
	}
}

func (suite *SessionsTestSuite) TestDeleteSession() {
	// Get auth token
	token, err := suite.jwtService.CreateAuthToken(suite.sessions[1].ID)
	suite.Require().NoError(err)

	// Test delete session
	req := httptest.NewRequest("DELETE", "/v2/sessions/"+suite.sessions[0].ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNoContent, resp.Code)

	// Verify session was deleted
	var sessionCount int64
	suite.ds.DB.Model(&datastore.Session{}).Where("id = ?", suite.sessions[0].ID).Count(&sessionCount)
	suite.Equal(int64(0), sessionCount)

	// Test delete non-existent session
	req = httptest.NewRequest("DELETE", "/v2/sessions/"+suite.sessions[0].ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNotFound, resp.Code)
}

func (suite *SessionsTestSuite) TestSessionsUnauthorized() {
	// Test list sessions without auth
	req := httptest.NewRequest("GET", "/v2/sessions", nil)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusUnauthorized, resp.Code)

	// Test delete session without auth
	req = httptest.NewRequest("DELETE", "/v2/sessions/"+suite.sessions[0].ID.String(), nil)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusUnauthorized, resp.Code)

	// Test with invalid auth token
	req = httptest.NewRequest("GET", "/v2/sessions", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusUnauthorized, resp.Code)

	// Test another account deleting a session that does not belong to account
	otherSession, err := suite.ds.CreateSession(suite.otherAccount.ID, datastore.PasswordAuthSessionVersion, "test")
	suite.Require().NoError(err)
	token, err := suite.jwtService.CreateAuthToken(otherSession.ID)
	suite.Require().NoError(err)
	req = httptest.NewRequest("DELETE", "/v2/sessions/"+suite.sessions[0].ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusNotFound, resp.Code)
}
