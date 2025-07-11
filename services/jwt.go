package services

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/util"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	sessionIdClaim      = "session_id"
	verificationIdClaim = "verification_id"
	loginStateIdClaim   = "login_state_id"

	audClaim = "aud" // Audience
	expClaim = "exp" // Expiration time
	iatClaim = "iat" // Issued at time
	kidClaim = "kid" // Key ID

	ChildAuthTokenExpirationTime = time.Hour * 24 * 14
)

type JWTService struct {
	ds               *datastore.Datastore
	keys             map[int]*datastore.JWTKey
	currentKeyID     int
	keyServiceClient *util.KeyServiceClient
	isKeyService     bool
}

func NewJWTService(ds *datastore.Datastore, isKeyService bool) (*JWTService, error) {
	var keyServiceClient *util.KeyServiceClient

	// Only create a client if we're not the key service and KEY_SERVICE_URL is set
	if !isKeyService && os.Getenv(util.KeyServiceURLEnv) != "" {
		keyServiceClient = util.NewKeyServiceClient()
	}

	keys, err := ds.GetOrCreateJWTKeys(isKeyService || keyServiceClient != nil, isKeyService || keyServiceClient == nil)
	if err != nil {
		return nil, err
	}

	currentKeyID := 0
	for id := range keys {
		if id > currentKeyID {
			currentKeyID = id
		}
	}

	return &JWTService{
		ds:               ds,
		keys:             keys,
		currentKeyID:     currentKeyID,
		keyServiceClient: keyServiceClient,
		isKeyService:     isKeyService,
	}, nil
}

func (j *JWTService) getKeyServiceJWTToken(claims jwt.MapClaims) (string, error) {
	type jwtCreateRequest struct {
		Claims map[string]interface{} `json:"claims"`
	}

	type jwtCreateResponse struct {
		Token string `json:"token"`
	}

	reqBody := jwtCreateRequest{
		Claims: claims,
	}

	var response jwtCreateResponse
	if err := j.keyServiceClient.MakeRequest(http.MethodPost, "/v2/server_keys/jwt", reqBody, &response); err != nil {
		return "", err
	}

	return response.Token, nil
}

func (j *JWTService) CreateToken(claims jwt.MapClaims) (string, error) {
	if j.keyServiceClient != nil {
		return j.getKeyServiceJWTToken(claims)
	}
	var method jwt.SigningMethod
	var key interface{}
	if j.isKeyService {
		method = jwt.SigningMethodES256
		key = j.keys[j.currentKeyID].ECDSASecretKey
	} else {
		method = jwt.SigningMethodHS256
		key = j.keys[j.currentKeyID].SecretKey
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header[kidClaim] = j.currentKeyID
	return token.SignedString(key)
}

func (j *JWTService) CreateVerificationToken(verificationID uuid.UUID, expiration time.Duration, serviceName string) (string, error) {
	now := time.Now()
	return j.CreateToken(jwt.MapClaims{
		verificationIdClaim: verificationID.String(),
		expClaim:            now.Add(expiration).Unix(),
		iatClaim:            now.Unix(),
		audClaim:            serviceName,
	})
}

func (j *JWTService) CreateAuthToken(sessionID uuid.UUID, expiration *time.Duration, serviceName string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		sessionIdClaim: sessionID.String(),
		iatClaim:       now.Unix(),
		audClaim:       serviceName,
	}

	if expiration != nil {
		claims[expClaim] = now.Add(*expiration).Unix()
	}

	return j.CreateToken(claims)
}

func (j *JWTService) CreateEphemeralLoginToken(loginStateID uuid.UUID, expiration time.Duration) (string, error) {
	now := time.Now()
	return j.CreateToken(jwt.MapClaims{
		loginStateIdClaim: loginStateID.String(),
		expClaim:          now.Add(expiration).Unix(),
		iatClaim:          now.Unix(),
	})
}

func (j *JWTService) parseToken(tokenString string, claimKey string) (uuid.UUID, string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if j.isKeyService || j.keyServiceClient != nil {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		} else {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		}
		keyID := token.Header[kidClaim]
		if keyID == nil {
			return nil, fmt.Errorf("missing key id claim")
		}

		keyIDFloat, ok := keyID.(float64)
		if !ok {
			return nil, fmt.Errorf("invalid key id type")
		}

		key, exists := j.keys[int(keyIDFloat)]
		if !exists {
			return nil, fmt.Errorf("key not found")
		}

		if key.ECDSAPublicKey != nil {
			return key.ECDSAPublicKey, nil
		}

		return key.SecretKey, nil
	})

	if err != nil {
		return uuid.Nil, "", fmt.Errorf("invalid token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		idStr, ok := claims[claimKey].(string)
		if !ok {
			return uuid.Nil, "", fmt.Errorf("%s claim not found", claimKey)
		}
		var audStr string
		audRaw, exists := claims[audClaim]
		if exists {
			audStr = audRaw.(string)
		}
		id, err := uuid.Parse(idStr)
		return id, audStr, err
	}

	return uuid.Nil, "", fmt.Errorf("invalid token claims")
}

func (j *JWTService) ValidateVerificationToken(tokenString string) (uuid.UUID, error) {
	verificationID, _, err := j.parseToken(tokenString, verificationIdClaim)
	return verificationID, err
}

func (j *JWTService) ValidateAuthToken(tokenString string) (uuid.UUID, string, error) {
	return j.parseToken(tokenString, sessionIdClaim)
}

func (j *JWTService) ValidateEphemeralLoginToken(tokenString string) (uuid.UUID, error) {
	loginStateID, _, err := j.parseToken(tokenString, loginStateIdClaim)
	return loginStateID, err
}
