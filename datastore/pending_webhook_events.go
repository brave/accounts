package datastore

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/brave/accounts/util"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"gorm.io/gorm"
)

const (
	WebhookKeysEnv           = "WEBHOOK_KEYS"
	webhookEventsChannel     = "webhook_events"
	accountDeletionEventType = "account_deleted"
)

// PendingWebhookEvent represents a webhook event that needs to be sent to a URL
// It tracks the event data, destination URL, number of delivery attempts, and timestamps
type PendingWebhookEvent struct {
	// Unique identifier for the webhook event
	ID int64 `json:"-"`
	// Type of event
	EventType string `json:"type"`
	// JSON-encoded event payload
	Details interface{} `gorm:"serializer:json" json:"details"`
	// Destination URL for the webhook
	URL string `json:"-"`
	// Number of times delivery has been attempted
	Attempts int `json:"-"`
	// Timestamp when the event was created (managed by database)
	CreatedAt time.Time `gorm:"<-:false" json:"-"`
	// Timestamp of the last update (managed by database)
	UpdatedAt time.Time `gorm:"autoUpdateTime:false" json:"-"`
}

// AccountDeletionEventDetails represents the payload for an account deletion webhook event
type AccountDeletionEventDetails struct {
	// Email address of the deleted account
	Email string `json:"email"`
	// Unique identifier of the deleted account
	AccountID uuid.UUID `json:"accountId"`
}

// WebhookEventListener handles Postgres notifications for webhook events
type WebhookEventListener struct {
	// Postgres connection for listening to notifications
	conn *pgx.Conn
}

func (d *Datastore) notifyEvent(eventType string, details interface{}) error {
	for webhookURL := range d.webhookUrls {
		webhookEvent := PendingWebhookEvent{
			EventType: eventType,
			Details:   details,
			URL:       webhookURL,
			UpdatedAt: time.Now().UTC(),
		}
		if err := d.DB.Create(&webhookEvent).Error; err != nil {
			return fmt.Errorf("failed to create webhook event: %w", err)
		}
		if err := d.DB.Exec(
			"SELECT pg_notify(?, ?)",
			webhookEventsChannel,
			fmt.Sprintf("%d", webhookEvent.ID),
		).Error; err != nil {
			return fmt.Errorf("failed to send notification: %w", err)
		}
	}
	return nil
}

func (d *Datastore) NotifyAccountDeletionEvent(email string, accountID uuid.UUID) error {
	return d.notifyEvent(accountDeletionEventType, AccountDeletionEventDetails{
		Email:     email,
		AccountID: accountID,
	})
}

func (d *Datastore) NewWebhookEventListener() (*WebhookEventListener, error) {
	ctx := context.Background()
	conn, err := pgx.ConnectConfig(ctx, d.dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	err = util.ListenOnPGChannel(ctx, conn, webhookEventsChannel)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on channel: %w", err)
	}
	return &WebhookEventListener{conn}, nil
}

func (l *WebhookEventListener) WaitForEvent() (int64, error) {
	notification, err := l.conn.WaitForNotification(context.Background())
	if err != nil {
		return 0, fmt.Errorf("error waiting for notification: %w", err)
	}

	eventID := notification.Payload
	id, err := strconv.ParseInt(eventID, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid event ID received: %w", err)
	}

	return id, nil
}

func (d *Datastore) GetPendingEvent(eventID int64) (*PendingWebhookEvent, error) {
	var event PendingWebhookEvent
	if err := d.DB.First(&event, eventID).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch pending event: %w", err)
	}
	return &event, nil
}

func (d *Datastore) IncrementAttemptsCount(eventID int64) error {
	result := d.DB.Model(&PendingWebhookEvent{}).
		Where("id = ?", eventID).
		Updates(map[string]interface{}{
			"attempts":   gorm.Expr("attempts + 1"),
			"updated_at": time.Now().UTC(),
		})

	if result.Error != nil {
		return fmt.Errorf("failed to increment attempts count: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("event not found")
	}

	return nil
}

func (d *Datastore) GetPendingEvents(failedOnly bool) ([]PendingWebhookEvent, error) {
	var events []PendingWebhookEvent
	var err error
	if failedOnly {
		err = d.DB.Where("attempts > 0").Find(&events).Error
	} else {
		err = d.DB.Find(&events).Error
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch events: %w", err)
	}
	return events, nil
}

func (d *Datastore) DeletePendingEvent(eventID int64) error {
	result := d.DB.Delete(&PendingWebhookEvent{}, eventID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete pending event: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("event not found")
	}

	return nil
}
