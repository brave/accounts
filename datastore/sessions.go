package datastore

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Session struct {
	// Session UUID
	ID uuid.UUID `json:"id"`
	// AccountID is excluded from JSON
	AccountID uuid.UUID `json:"-"`
	// Optional session name
	SessionName *string `json:"sessionName"`
	// The accounts "phase" the session was created in
	Version int `json:"-"`
	// Expiration timestamp
	ExpiresAt *time.Time `json:"expiresAt"`
	// Session creation timestamp
	CreatedAt time.Time `json:"createdAt" gorm:"<-:false"`
	// Account is excluded from JSON
	Account Account `json:"-"`
}

var ErrSessionNotFound = errors.New("session not found")

func (d *Datastore) CreateSession(accountID uuid.UUID, sessionVersion int, sessionName *string, expiration *time.Duration) (*Session, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	session := Session{
		ID:          id,
		AccountID:   accountID,
		SessionName: sessionName,
		Version:     sessionVersion,
	}

	if expiration != nil {
		expiresAt := time.Now().Add(*expiration).UTC()
		session.ExpiresAt = &expiresAt
	}

	if err := d.db.Create(&session).Error; err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &session, nil
}

func (d *Datastore) ListSessions(accountID uuid.UUID, minSessionVersion *int) ([]Session, error) {
	var sessions []Session
	if minSessionVersion == nil {
		minSessionVersion = &d.minSessionVersion
	}
	if err := d.db.Where("account_id = ? AND version >= ? AND expires_at IS NULL", accountID, *minSessionVersion).Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	return sessions, nil
}

func (d *Datastore) GetSession(sessionID uuid.UUID) (*Session, error) {
	var session Session
	if err := d.db.Preload("Account").First(&session, "id = ?", sessionID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

func (d *Datastore) DeleteSession(sessionID uuid.UUID, accountID uuid.UUID) error {
	result := d.db.Delete(&Session{}, "id = ? AND account_id = ?", sessionID, accountID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete session: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (d *Datastore) DeleteAllSessions(accountID uuid.UUID) error {
	result := d.db.Delete(&Session{}, "account_id = ?", accountID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete all sessions: %w", result.Error)
	}
	return nil
}
