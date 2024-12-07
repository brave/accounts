package controllers_test

import (
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/brave/accounts/controllers"
	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

const headerSecret = "test-secret"

type ServerKeysTestSuite struct {
	suite.Suite
	ds         *datastore.Datastore
	jwtService *services.JWTService
	router     *chi.Mux
}

func (suite *ServerKeysTestSuite) SetupTest() {
	suite.T().Setenv("OPAQUE_SECRET_KEY", "4355f8e6f9ec41649fbcdbcca5075a97dafc4c8d8eb8cc2ba286be7b1c938d05")
	suite.T().Setenv("OPAQUE_PUBLIC_KEY", "98584585210c1f310e9d0aeb9ac1384b7d51808cfaf21b17b5e3dc8d35dbfb00")
	suite.T().Setenv(util.KeyServiceSecretEnv, headerSecret)

	var err error
	suite.ds, err = datastore.NewDatastore(datastore.EmailAuthSessionVersion, false, true)
	suite.Require().NoError(err)

	opaqueService, err := services.NewOpaqueService(suite.ds, true)
	suite.Require().NoError(err)

	suite.jwtService, err = services.NewJWTService(suite.ds, true)
	suite.Require().NoError(err)

	controller := controllers.NewServerKeysController(opaqueService, suite.jwtService)

	keyServiceMiddleware := middleware.KeyServiceMiddleware()

	suite.router = chi.NewRouter()
	suite.router.Mount("/v2/server_keys", controller.Router(keyServiceMiddleware))
}

func (suite *ServerKeysTestSuite) TearDownTest() {
	suite.ds.Close()
}

func TestServerKeysTestSuite(t *testing.T) {
	suite.Run(t, new(ServerKeysTestSuite))
}

func (suite *ServerKeysTestSuite) TestCreateJWT() {
	expectedSessionID, err := uuid.NewV7()
	suite.Require().NoError(err)
	claims := map[string]interface{}{
		"session_id": expectedSessionID,
	}

	body := controllers.JWTCreateRequest{
		Claims: claims,
	}

	req := util.CreateJSONTestRequest("/v2/server_keys/jwt", body)
	req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedResp controllers.JWTCreateResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)
	suite.NotEmpty(parsedResp.Token)

	// Validate the token
	sessionID, err := suite.jwtService.ValidateAuthToken(parsedResp.Token)
	suite.Require().NoError(err)
	suite.Equal(expectedSessionID, sessionID)
}

func (suite *ServerKeysTestSuite) TestDeriveOPRFKey() {
	body := controllers.OPRFSeedRequest{
		CredentialIdentifier: "test@example.com",
	}

	// First call
	req := util.CreateJSONTestRequest("/v2/server_keys/oprf_seed", body)
	req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var firstResp controllers.OPRFSeedResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &firstResp)

	firstSeed, err := hex.DecodeString(firstResp.ClientSeed)
	suite.Require().NoError(err)
	suite.NotEmpty(firstSeed)
	suite.Equal(1, firstResp.SeedID)

	// Second call with same credential ID
	req = util.CreateJSONTestRequest("/v2/server_keys/oprf_seed", body)
	req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var secondResp controllers.OPRFSeedResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &secondResp)

	secondSeed, err := hex.DecodeString(secondResp.ClientSeed)
	suite.Require().NoError(err)
	suite.NotEmpty(secondSeed)
	suite.Equal(1, secondResp.SeedID)

	// Verify both calls return same result
	suite.Equal(firstSeed, secondSeed)

	// Call with different credential ID
	body.CredentialIdentifier = "different@example.com"
	req = util.CreateJSONTestRequest("/v2/server_keys/oprf_seed", body)
	req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var thirdResp controllers.OPRFSeedResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &thirdResp)

	thirdSeed, err := hex.DecodeString(thirdResp.ClientSeed)
	suite.Require().NoError(err)
	suite.NotEmpty(thirdSeed)
	suite.Equal(1, thirdResp.SeedID)

	// Verify different credential ID produces different result
	suite.NotEqual(firstSeed, thirdSeed)
}

func (suite *ServerKeysTestSuite) TestDeriveOPRFKeyWithSeedID() {
	body := controllers.OPRFSeedRequest{
		CredentialIdentifier: "test@example.com",
		SeedID:               &[]int{1}[0],
	}

	req := util.CreateJSONTestRequest("/v2/server_keys/oprf_seed", body)
	req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusOK, resp.Code)

	var parsedResp controllers.OPRFSeedResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &parsedResp)

	decodedSeed, err := hex.DecodeString(parsedResp.ClientSeed)
	suite.NoError(err)
	suite.NotEmpty(decodedSeed)
	suite.Equal(1, parsedResp.SeedID)
}

func (suite *ServerKeysTestSuite) TestUnauthorizedAccess() {
	// Test JWT endpoint
	jwtBody := controllers.JWTCreateRequest{
		Claims: map[string]interface{}{"test": "claim"},
	}
	req := util.CreateJSONTestRequest("/v2/server_keys/jwt", jwtBody)
	req.Header.Add(util.KeyServiceSecretHeader, "bad-secret")
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusUnauthorized, resp.Code)

	// Test OPRF endpoint
	oprfBody := controllers.OPRFSeedRequest{
		CredentialIdentifier: "test@example.com",
	}
	req = util.CreateJSONTestRequest("/v2/server_keys/oprf_seed", oprfBody)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusUnauthorized, resp.Code)
}
