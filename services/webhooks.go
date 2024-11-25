package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/brave/accounts/datastore"
	"github.com/rs/zerolog/log"
)

const (
	retryInterval             = 10 * time.Second
	backoffMultiplierInterval = 10 * time.Second
	maxBackoff                = 3 * time.Minute
)

type WebhookService struct {
	webhookKeys map[string]string
	ds          *datastore.Datastore
}

func NewWebhookService(ds *datastore.Datastore) *WebhookService {
	keys := make(map[string]string)
	if urls := os.Getenv(datastore.WebhookKeysEnv); urls != "" {
		pairs := strings.Split(urls, ",")
		for _, pair := range pairs {
			if parts := strings.Split(strings.TrimSpace(pair), "="); len(parts) == 2 {
				keys[parts[0]] = parts[1]
			}
		}
	}
	return &WebhookService{
		webhookKeys: keys,
		ds:          ds,
	}
}

func (w *WebhookService) StartProcessingEvents() error {
	listener, err := w.ds.NewWebhookEventListener()
	if err != nil {
		return err
	}

	existingEvents, err := w.ds.GetPendingEvents(false)
	if err != nil {
		return err
	}

	for _, event := range existingEvents {
		go w.processEvent(event.ID)
	}

	// Start periodic retry checker
	go w.retryFailedEvents()

	log.Info().Msg("Listening for webhook events")
	for {
		eventID, err := listener.WaitForEvent()
		if err != nil {
			return err
		}
		go w.processEvent(eventID)
	}
}

func (w *WebhookService) processEvent(eventID int64) {
	event, err := w.ds.GetPendingEvent(eventID)
	if err != nil {
		log.Error().Err(err).Msg("failed to get pending event")
		return
	}

	if err := w.sendWebhook(event); err != nil {
		log.Error().Err(err).Str("url", event.URL).Msg("failed to send webhook event")
		if err := w.ds.IncrementAttemptsCount(eventID); err != nil {
			log.Error().Err(err).Msg("failed to increment attempt count")
		}
		return
	}

	_ = w.ds.DeletePendingEvent(eventID)
}

func (s *WebhookService) sendWebhook(event *datastore.PendingWebhookEvent) error {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, event.URL, bytes.NewReader(eventJSON))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Key", s.webhookKeys[event.URL])

	log.Debug().Str("url", event.URL).Msg("sending webhook event")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("webhook request failed with status: %d", resp.StatusCode)
	}

	return nil
}

func (w *WebhookService) retryFailedEvents() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		events, err := w.ds.GetPendingEvents(true)
		if err != nil {
			return
		}

		for _, event := range events {
			backoff := min(time.Duration(math.Pow(2, float64(event.Attempts)))*backoffMultiplierInterval, maxBackoff)
			if time.Since(event.UpdatedAt.UTC()) < backoff {
				continue
			}

			go w.processEvent(event.ID)
		}
	}
}
