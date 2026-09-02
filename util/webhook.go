package util

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	deletionWebhookURLsEnv = "DELETION_WEBHOOK_URLS"
	webhookTimeout         = 10 * time.Second
)

// WebhookUtil handles calling external webhooks
type WebhookUtil struct {
	deletionWebhookURLs []string
	client              *http.Client
}

// NewWebhookUtil creates a new WebhookUtil, parsing the DELETION_WEBHOOK_URLS env var
func NewWebhookUtil() *WebhookUtil {
	return &WebhookUtil{
		deletionWebhookURLs: strings.FieldsFunc(os.Getenv(deletionWebhookURLsEnv), func(r rune) bool {
			return r == ','
		}),
		client: &http.Client{Timeout: webhookTimeout},
	}
}

// CallDeletionWebhooks calls each configured deletion webhook URL with the DELETE
// method, forwarding the Authorization and Brave services key headers received
// with the original request
func (u *WebhookUtil) CallDeletionWebhooks(r *http.Request) error {
	for _, webhookURL := range u.deletionWebhookURLs {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, webhookURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create deletion webhook request: %w", err)
		}

		req.Header.Set("Authorization", r.Header.Get("Authorization"))
		req.Header.Set(BraveServicesKeyHeader, r.Header.Get(BraveServicesKeyHeader))

		resp, err := u.client.Do(req)
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
