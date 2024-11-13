package util

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New(validator.WithRequiredStructEnabled())

func GenerateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("failed to generate random string: %w", err))
	}
	return base64.URLEncoding.EncodeToString(b)
}

func ExtractAuthToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("invalid authorization header")
	}

	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

func NormalizeEmail(email string) *string {
	// Split email into local part and domain
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil
	}

	// Check if it's a Gmail address
	if !strings.EqualFold(parts[1], "gmail.com") {
		return nil
	}

	// Remove dots and everything after + in local part
	localPart := parts[0]
	if plusIndex := strings.Index(localPart, "+"); plusIndex != -1 {
		localPart = localPart[:plusIndex]
	}
	localPart = strings.ReplaceAll(localPart, ".", "")

	// Construct normalized email
	normalized := strings.ToLower(localPart + "@gmail.com")
	return &normalized
}

func DecodeJSONAndValidate(w http.ResponseWriter, r *http.Request, data interface{}) bool {
	if err := render.DecodeJSON(r.Body, &data); err != nil {
		RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return false
	}

	if err := validate.Struct(data); err != nil {
		RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return false
	}
	return true
}
