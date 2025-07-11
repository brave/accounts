package util

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/argon2"
)

var (
	validate                      = validator.New(validator.WithRequiredStructEnabled())
	TestKeyServiceRouter *chi.Mux = nil
)

const (
	DevelopmentEnv = "development"
	StagingEnv     = "staging"
	ProductionEnv  = "production"

	AccountsServiceName     = "accounts"
	PremiumServiceName      = "premium"
	EmailAliasesServiceName = "email-aliases"

	KeyServiceSecretEnv    = "KEY_SERVICE_SECRET"
	KeyServiceSecretHeader = "key-service-secret"
	KeyServiceURLEnv       = "KEY_SERVICE_URL"

	recoveryKeyArgonTime       = 1
	recoveryKeyArgonMemory     = 64 * 1024
	recoveryKeyArgonThreads    = 4
	recoveryKeyArgonKeyLength  = 32
	recoveryKeyArgonSaltLength = 16
	recoveryKeyFullHashLength  = recoveryKeyArgonKeyLength + recoveryKeyArgonSaltLength
)

func GenerateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("failed to generate random string: %w", err))
	}
	return base64.URLEncoding.EncodeToString(b)
}

func generateRecoveryKeyHash(recoveryKey string, salt []byte) []byte {
	uppercaseKey := strings.TrimSpace(strings.ToUpper(recoveryKey))
	return argon2.IDKey(
		[]byte(uppercaseKey),
		salt,
		recoveryKeyArgonTime,
		recoveryKeyArgonMemory,
		recoveryKeyArgonThreads,
		recoveryKeyArgonKeyLength,
	)
}

func HashRecoveryKey(recoveryKey string) ([]byte, error) {
	// Create random salt
	salt := make([]byte, recoveryKeyArgonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := generateRecoveryKeyHash(recoveryKey, salt)

	// Combine salt and hash
	result := make([]byte, recoveryKeyFullHashLength)
	copy(result, salt)
	copy(result[recoveryKeyArgonSaltLength:], hash)

	return result, nil
}

func VerifyRecoveryKeyHash(recoveryKey string, storedHash []byte) bool {
	if len(storedHash) != recoveryKeyFullHashLength {
		// Invalid stored hash format
		return false
	}

	salt := storedHash[:recoveryKeyArgonSaltLength]
	expectedHash := storedHash[recoveryKeyArgonSaltLength:]

	computedHash := generateRecoveryKeyHash(recoveryKey, salt)

	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
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

func IsEmailAllowed(email string, checkStrictCountries bool) bool {
	lowerEmail := strings.ToLower(email)
	// Check if email ends with @bravealias.com
	if strings.HasSuffix(lowerEmail, "@bravealias.com") {
		return false
	}

	// Always block these TLDs
	unsupportedTLDs := []string{".kp", ".tz"}
	for _, tld := range unsupportedTLDs {
		if strings.HasSuffix(lowerEmail, tld) {
			return false
		}
	}

	if checkStrictCountries {
		restrictedTLDs := []string{".cu", ".ir", ".sy", ".by", ".md", ".ru", ".ve"}
		for _, tld := range restrictedTLDs {
			if strings.HasSuffix(lowerEmail, tld) {
				return false
			}
		}
	}

	return true
}

// Simplify email address according to provider-specific
// rules. To be used for recovery/login assistance flows only.
func SimplifyEmail(email string) *string {
	// Split email into local part and domain
	parts := strings.Split(email, "@")

	// Check if it's a Gmail address
	if !isGmail(parts[len(parts)-1]) {
		return nil
	}

	email = CanonicalizeEmail(email)
	parts = strings.Split(email, "@")

	// Remove dots and everything after + in local part
	localPart := strings.Join(parts[:len(parts)-1], "@")
	if plusIndex := strings.Index(localPart, "+"); plusIndex != -1 {
		localPart = localPart[:plusIndex]
	}
	localPart = strings.ReplaceAll(localPart, ".", "")

	// Construct simplified email
	simplified := strings.ToLower(localPart + "@gmail.com")
	return &simplified
}

// Canonicalize email for general email address storage.
func CanonicalizeEmail(email string) string {
	// Split email into local part and domain
	parts := strings.Split(email, "@")
	lastIndex := len(parts) - 1
	parts[lastIndex] = strings.ToLower(parts[lastIndex])

	// Check if it's a GMail address
	// If GMail, convert local part to lowercase since it's not case-sensitive
	if isGmail(parts[len(parts)-1]) {
		for i := 0; i < len(parts)-1; i++ {
			parts[i] = strings.ToLower(parts[i])
		}
	}

	return strings.Join(parts, "@")
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

func StartPrometheusServer(registry *prometheus.Registry, listen string) {
	go func() {
		r := chi.NewRouter()
		r.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		log.Info().Msgf("Prometheus server listening on port %v", listen)
		if err := http.ListenAndServe(listen, r); err != nil {
			log.Panic().Err(err).Msg("Failed to start Prometheus server")
		}
	}()
}

// KeyServiceClient is used to communicate with the key service
type KeyServiceClient struct {
	url    string
	secret string
}

// NewKeyServiceClient creates a new client for interacting with the key service
func NewKeyServiceClient() *KeyServiceClient {
	secret := os.Getenv(KeyServiceSecretEnv)
	if secret == "" {
		log.Panic().Msgf("%v must be provided if using key service", KeyServiceSecretEnv)
	}
	return &KeyServiceClient{
		url:    os.Getenv(KeyServiceURLEnv),
		secret: secret,
	}
}

// MakeRequest sends a request to the key service with the given path and body,
// unmarshaling the response into the provided response interface
func (k *KeyServiceClient) MakeRequest(method string, path string, body interface{}, response interface{}) error {
	// Marshal request body
	var jsonBody []byte
	var err error
	if body != nil {
		jsonBody, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
	}

	// Create HTTP request
	req, err := http.NewRequest(method, k.url+path, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add key service secret header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(KeyServiceSecretHeader, k.secret)

	// Make request
	var respBody io.Reader
	var status int
	if TestKeyServiceRouter != nil {
		resp := httptest.NewRecorder()
		TestKeyServiceRouter.ServeHTTP(resp, req)

		status = resp.Code

		respBody = resp.Body
	} else {
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to make key service request: %w", err)
		}
		defer resp.Body.Close() //nolint:errcheck

		status = resp.StatusCode

		respBody = resp.Body
	}

	if status == http.StatusUnauthorized {
		var exposedError ExposedError
		if err := json.NewDecoder(respBody).Decode(&exposedError); err != nil {
			return fmt.Errorf("failed to decode unauthorized response: %w", err)
		}
		// This error must be forwarded to the TwoFAService
		// in order to process the error case correctly
		if exposedError.Code == ErrBadTOTPCode.Code {
			return ErrBadTOTPCode
		}
	}

	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("key service returned status %d", status)
	}

	// No need to decode if response is nil or status is NoContent
	if response == nil || status == http.StatusNoContent {
		return nil
	}

	if err := json.NewDecoder(respBody).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

func GetRequestLocale(explicitLocale string, r *http.Request) string {
	locale := explicitLocale
	if locale == "" {
		// Use header as fallback
		locale = r.Header.Get("Accept-Language")
	}

	if len(locale) > 20 {
		return locale[:20]
	}
	return locale
}
