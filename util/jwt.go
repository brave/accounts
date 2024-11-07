package util

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	sessionIdClaim      = "session_id"
	verificationIdClaim = "verification_id"
	akeStateIdClaim     = "ake_state_id"
	jwtKeyEnv           = "JWT_KEY"
)

type JWTUtil struct {
	key []byte
}

func NewJWTUtil() (*JWTUtil, error) {
	key := os.Getenv(jwtKeyEnv)
	if key == "" {
		return nil, fmt.Errorf("missing JWT key environment variable: %s", jwtKeyEnv)
	}

	return &JWTUtil{
		key: []byte(key),
	}, nil
}

func (j *JWTUtil) createToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.key)
}

func (j *JWTUtil) CreateVerificationToken(verificationID uuid.UUID, expiration time.Duration) (string, error) {
	return j.createToken(jwt.MapClaims{
		verificationIdClaim: verificationID.String(),
		"exp":               time.Now().Add(expiration).Unix(),
		"iat":               time.Now().Unix(),
	})
}

func (j *JWTUtil) CreateAuthToken(sessionID uuid.UUID) (string, error) {
	return j.createToken(jwt.MapClaims{
		sessionIdClaim: sessionID.String(),
		"iat":          time.Now().Unix(),
	})
}

func (j *JWTUtil) CreateEphemeralAKEToken(akeStateID uuid.UUID, expiration time.Duration) (string, error) {
	return j.createToken(jwt.MapClaims{
		akeStateIdClaim: akeStateID.String(),
		"exp":           time.Now().Add(expiration).Unix(),
		"iat":           time.Now().Unix(),
	})
}

func (j *JWTUtil) parseToken(tokenString string, claimKey string) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.key, nil
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

func (j *JWTUtil) ValidateVerificationToken(tokenString string) (uuid.UUID, error) {
	return j.parseToken(tokenString, verificationIdClaim)
}

func (j *JWTUtil) ValidateAuthToken(tokenString string) (uuid.UUID, error) {
	return j.parseToken(tokenString, sessionIdClaim)
}

func (j *JWTUtil) ValidateEphemeralAKEToken(tokenString string) (uuid.UUID, error) {
	return j.parseToken(tokenString, akeStateIdClaim)
}
