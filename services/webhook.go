package services

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/brave/accounts/util"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	deletionWebhookURLsEnv = "DELETION_WEBHOOK_URLS"
	webhookTimeout         = 10 * time.Second
	webhookTokenExpiration = 60 * time.Second
)

type deletionWebhook struct {
	serviceName string
	url         string
}

// WebhookService handles calling external webhooks
type WebhookService struct {
	webhooks   []deletionWebhook
	jwtService *JWTService
	client     *http.Client
}

// NewWebhookService creates a new WebhookService, parsing the DELETION_WEBHOOK_URLS env var
func NewWebhookService(jwtService *JWTService) *WebhookService {
	var webhooks []deletionWebhook
	rawWebhooks := strings.FieldsFunc(os.Getenv(deletionWebhookURLsEnv), func(r rune) bool {
		return r == ','
	})
	for _, entry := range rawWebhooks {
		serviceName, webhookURL, found := strings.Cut(strings.TrimSpace(entry), "=")
		serviceName = strings.TrimSpace(serviceName)
		webhookURL = strings.TrimSpace(webhookURL)
		if !found || serviceName == "" || webhookURL == "" {
			log.Panic().Msgf("malformed %s entry: %s", deletionWebhookURLsEnv, entry)
		}

		switch serviceName {
		case util.AccountsServiceName, util.PremiumServiceName, util.EmailAliasesServiceName:
		default:
			log.Panic().Msgf("invalid service name in %s: %s", deletionWebhookURLsEnv, serviceName)
		}

		webhooks = append(webhooks, deletionWebhook{
			serviceName: serviceName,
			url:         webhookURL,
		})
	}

	return &WebhookService{
		webhooks:   webhooks,
		jwtService: jwtService,
		client:     &http.Client{Timeout: webhookTimeout},
	}
}

// CallDeletionWebhooks calls each configured deletion webhook URL with the DELETE
// method, authenticating with a service token minted for each service and forwarding
// the Brave services key header received with the original request
func (s *WebhookService) CallDeletionWebhooks(r *http.Request, sessionID uuid.UUID) error {
	for _, webhook := range s.webhooks {
		expiration := webhookTokenExpiration
		token, err := s.jwtService.CreateAuthToken(sessionID, &expiration, webhook.serviceName)
		if err != nil {
			return fmt.Errorf("failed to create deletion webhook auth token for service %s: %w", webhook.serviceName, err)
		}

		req, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, webhook.url, nil)
		if err != nil {
			return fmt.Errorf("failed to create deletion webhook request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(util.BraveServicesKeyHeader, r.Header.Get(util.BraveServicesKeyHeader))

		resp, err := s.client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to call deletion webhook: %w", err)
		}
		if err := resp.Body.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close deletion webhook response body")
		}

		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("deletion webhook returned status %d", resp.StatusCode)
		}
	}
	return nil
}
