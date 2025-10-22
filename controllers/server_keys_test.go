package controllers_test

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"testing"

	"github.com/brave/accounts/controllers"
	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
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

	twoFAService := services.NewTwoFAService(suite.ds, true)

	controller := controllers.NewServerKeysController(opaqueService, suite.jwtService, twoFAService)

	keyServiceMiddleware := middleware.KeyServiceMiddleware("test")

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
	sessionID, _, err := suite.jwtService.ValidateAuthToken(parsedResp.Token)
	suite.Require().NoError(err)
	suite.Equal(expectedSessionID, sessionID)
}

func (suite *ServerKeysTestSuite) TestDeriveOPRFKey() {
	body := controllers.OPRFSeedRequest{
		CredentialIdentifier: "test@example.com",
		IP:                   "127.0.0.1",
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
		IP:                   "127.0.0.1",
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
		IP:                   "127.0.0.1",
	}
	req = util.CreateJSONTestRequest("/v2/server_keys/oprf_seed", oprfBody)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusUnauthorized, resp.Code)
}

func (suite *ServerKeysTestSuite) TestRateLimitOPRF() {
	// Test rate limiting by IP with random credentials
	testIP := "192.168.1.100"

	// Make requests up to the rate limit with same IP but different credentials
	for i := 0; i < controllers.RateLimitMaxRequestsPerMinute; i++ {
		oprfBody := controllers.OPRFSeedRequest{
			CredentialIdentifier: uuid.New().String() + "@example.com",
			IP:                   testIP,
		}
		req := util.CreateJSONTestRequest("/v2/server_keys/oprf_seed", oprfBody)
		req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
		resp := util.ExecuteTestRequest(req, suite.router)
		suite.Equal(http.StatusOK, resp.Code)
	}

	// Next request should be rate limited
	oprfBody := controllers.OPRFSeedRequest{
		CredentialIdentifier: uuid.New().String() + "@example.com",
		IP:                   testIP,
	}
	req := util.CreateJSONTestRequest("/v2/server_keys/oprf_seed", oprfBody)
	req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusTooManyRequests, resp.Code)

	var errorResp util.ErrorResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &errorResp)
	suite.Equal(http.StatusTooManyRequests, errorResp.Status)

	// Test rate limiting by credential identifier with random IPs
	credentialID := "ratelimit-cred@example.com"

	// Make requests up to the rate limit with same credential but different IPs
	for i := 0; i < controllers.RateLimitMaxRequestsPerMinute; i++ {
		oprfBody2 := controllers.OPRFSeedRequest{
			CredentialIdentifier: credentialID,
			IP:                   fmt.Sprintf("192.168.2.%d", i+1),
		}
		req := util.CreateJSONTestRequest("/v2/server_keys/oprf_seed", oprfBody2)
		req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
		resp := util.ExecuteTestRequest(req, suite.router)
		suite.Equal(http.StatusOK, resp.Code)
	}

	// Next request should be rate limited
	oprfBody2 := controllers.OPRFSeedRequest{
		CredentialIdentifier: credentialID,
		IP:                   "192.168.3.1",
	}
	req = util.CreateJSONTestRequest("/v2/server_keys/oprf_seed", oprfBody2)
	req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusTooManyRequests, resp.Code)

	util.DecodeJSONTestResponse(suite.T(), resp.Body, &errorResp)
	suite.Equal(http.StatusTooManyRequests, errorResp.Status)
}

func (suite *ServerKeysTestSuite) TestRateLimitTOTP() {
	// Test rate limiting by IP with random account IDs
	testIP := "192.168.1.102"

	// Make requests up to the rate limit with same IP but different accounts
	for i := 0; i < controllers.RateLimitMaxRequestsPerMinute; i++ {
		accountID := uuid.New()

		// Generate a TOTP key for testing
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "Test",
			AccountName: fmt.Sprintf("test%d@example.com", i),
		})
		suite.Require().NoError(err)
		err = suite.ds.StoreTOTPKey(accountID, key)
		suite.Require().NoError(err)

		totpBody := controllers.TOTPValidateRequest{
			AccountID: accountID,
			Code:      "123456",
			IP:        testIP,
		}

		req := util.CreateJSONTestRequest("/v2/server_keys/totp/validate", totpBody)
		req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
		resp := util.ExecuteTestRequest(req, suite.router)
		// These should fail with Unauthorized due to invalid code, not rate limit
		suite.Equal(http.StatusUnauthorized, resp.Code)
	}

	// Next request should be rate limited before validation
	accountID := uuid.New()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Test",
		AccountName: "test-extra@example.com",
	})
	suite.Require().NoError(err)
	err = suite.ds.StoreTOTPKey(accountID, key)
	suite.Require().NoError(err)

	totpBody := controllers.TOTPValidateRequest{
		AccountID: accountID,
		Code:      "123456",
		IP:        testIP,
	}
	req := util.CreateJSONTestRequest("/v2/server_keys/totp/validate", totpBody)
	req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
	resp := util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusTooManyRequests, resp.Code)

	var errorResp util.ErrorResponse
	util.DecodeJSONTestResponse(suite.T(), resp.Body, &errorResp)
	suite.Equal(http.StatusTooManyRequests, errorResp.Status)

	// Test rate limiting by account ID with random IPs
	accountID2 := uuid.New()

	// Generate a TOTP key for testing
	key2, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Test",
		AccountName: "test-account@example.com",
	})
	suite.Require().NoError(err)
	err = suite.ds.StoreTOTPKey(accountID2, key2)
	suite.Require().NoError(err)

	// Make requests up to the rate limit with same account but different IPs
	for i := 0; i < controllers.RateLimitMaxRequestsPerMinute; i++ {
		totpBody2 := controllers.TOTPValidateRequest{
			AccountID: accountID2,
			Code:      "123456",
			IP:        fmt.Sprintf("192.168.3.%d", i+1),
		}
		req := util.CreateJSONTestRequest("/v2/server_keys/totp/validate", totpBody2)
		req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
		resp := util.ExecuteTestRequest(req, suite.router)
		suite.Equal(http.StatusUnauthorized, resp.Code)
	}

	// Next request should be rate limited
	totpBody2 := controllers.TOTPValidateRequest{
		AccountID: accountID2,
		Code:      "123456",
		IP:        "192.168.4.1",
	}
	req = util.CreateJSONTestRequest("/v2/server_keys/totp/validate", totpBody2)
	req.Header.Add(util.KeyServiceSecretHeader, headerSecret)
	resp = util.ExecuteTestRequest(req, suite.router)
	suite.Equal(http.StatusTooManyRequests, resp.Code)

	util.DecodeJSONTestResponse(suite.T(), resp.Body, &errorResp)
	suite.Equal(http.StatusTooManyRequests, errorResp.Status)
}
