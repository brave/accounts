package services

import (
	"fmt"
	"time"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	sessionIdClaim      = "session_id"
	verificationIdClaim = "verification_id"
	akeStateIdClaim     = "ake_state_id"

	audClaim = "aud" // Audience
	expClaim = "exp" // Expiration time
	iatClaim = "iat" // Issued at time
	kidClaim = "kid" // Key ID
)

type JWTService struct {
	ds           *datastore.Datastore
	keys         map[int][]byte
	currentKeyID int
}

func NewJWTService(ds *datastore.Datastore) (*JWTService, error) {
	keys, err := ds.GetOrCreateJWTKeys()
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
		ds,
		keys,
		currentKeyID,
	}, nil
}

func (j *JWTService) createToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header[kidClaim] = j.currentKeyID
	return token.SignedString(j.keys[j.currentKeyID])
}

func (j *JWTService) CreateVerificationToken(verificationID uuid.UUID, expiration time.Duration, serviceName string) (string, error) {
	now := time.Now()
	return j.createToken(jwt.MapClaims{
		verificationIdClaim: verificationID.String(),
		expClaim:            now.Add(expiration).Unix(),
		iatClaim:            now.Unix(),
		audClaim:            serviceName,
	})
}

func (j *JWTService) CreateAuthToken(sessionID uuid.UUID) (string, error) {
	return j.createToken(jwt.MapClaims{
		sessionIdClaim: sessionID.String(),
		iatClaim:       time.Now().Unix(),
	})
}

func (j *JWTService) CreateEphemeralAKEToken(akeStateID uuid.UUID, expiration time.Duration) (string, error) {
	now := time.Now()
	return j.createToken(jwt.MapClaims{
		akeStateIdClaim: akeStateID.String(),
		expClaim:        now.Add(expiration).Unix(),
		iatClaim:        now.Unix(),
	})
}

func (j *JWTService) parseToken(tokenString string, claimKey string) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
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

		return key, nil
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		idStr, ok := claims[claimKey].(string)
		if !ok {
			return uuid.Nil, fmt.Errorf("%s claim not found", claimKey)
		}
		return uuid.Parse(idStr)
	}

	return uuid.Nil, fmt.Errorf("invalid token claims")
}

func (j *JWTService) ValidateVerificationToken(tokenString string) (uuid.UUID, error) {
	return j.parseToken(tokenString, verificationIdClaim)
}

func (j *JWTService) ValidateAuthToken(tokenString string) (uuid.UUID, error) {
	return j.parseToken(tokenString, sessionIdClaim)
}

func (j *JWTService) ValidateEphemeralAKEToken(tokenString string) (uuid.UUID, error) {
	return j.parseToken(tokenString, akeStateIdClaim)
}
