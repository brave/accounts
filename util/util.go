package util

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
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
)

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

func MakeKeyServiceRequest(keyServiceURL string, keyServiceSecret string, path string, body interface{}, response interface{}) error {
	// Marshal request body
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest(http.MethodPost, keyServiceURL+path, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add key service secret header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(KeyServiceSecretHeader, keyServiceSecret)

	// Make request
	var respBody io.Reader
	if TestKeyServiceRouter != nil {
		resp := httptest.NewRecorder()
		TestKeyServiceRouter.ServeHTTP(resp, req)

		if resp.Code != http.StatusOK {
			return fmt.Errorf("key service returned status %d", resp.Code)
		}

		respBody = resp.Body
	} else {
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to make key service request: %w", err)
		}
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("key service returned status %d", resp.StatusCode)
		}

		respBody = resp.Body
	}
	if err := json.NewDecoder(respBody).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}
