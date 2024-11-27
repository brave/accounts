package util

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
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

func isGmail(domain string) bool {
	return strings.EqualFold(domain, "gmail.com") || strings.EqualFold(domain, "googlemail.com")
}

func FullyNormalizeEmail(email string) *string {
	// Split email into local part and domain
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil
	}

	// Check if it's a Gmail address
	if !isGmail(parts[1]) {
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

func PartiallyNormalizeEmail(email string) string {
	// Split email into local part and domain
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	// Check if it's a Gmail address
	if !isGmail(parts[1]) {
		return email
	}

	return strings.ToLower(email)
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

func validatePGChannelName(channelName string) error {
	if !regexp.MustCompile(`^[\w-_]+$`).MatchString(channelName) {
		return fmt.Errorf("channel name must contain only alphanumeric characters and hyphens")
	}
	return nil
}

func ListenOnPGChannel(ctx context.Context, conn *pgxpool.Conn, channelName string) error {
	if err := validatePGChannelName(channelName); err != nil {
		return err
	}
	_, err := conn.Exec(ctx, "LISTEN \""+channelName+"\"")
	return err
}

func UnlistenOnPGChannel(ctx context.Context, conn *pgxpool.Conn, channelName string) error {
	if err := validatePGChannelName(channelName); err != nil {
		return err
	}
	_, err := conn.Exec(ctx, "UNLISTEN \""+channelName+"\"")
	return err
}
