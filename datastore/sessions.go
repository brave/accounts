package datastore

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	EmailAuthSessionVersion    = 1
	PasswordAuthSessionVersion = 2
)

// Session represents a user's authenticated session in the system
type Session struct {
	// Session UUID
	ID uuid.UUID `json:"id"`
	// AccountID is excluded from JSON
	AccountID uuid.UUID `json:"-"`
	// User agent of client
	UserAgent string `json:"userAgent"`
	// The accounts "phase" the session was created in
	Version int `json:"-"`
	// Session creation timestamp
	CreatedAt time.Time `json:"createdAt" gorm:"<-:false"`
}

// SessionWithAccountInfo extends the basic session data with additional user account details
type SessionWithAccountInfo struct {
	// Session UUID
	ID uuid.UUID `json:"id"`
	// AccountID is excluded from JSON
	AccountID uuid.UUID `json:"-"`
	// The accounts "phase" the session was created in
	Version int `json:"-"`
	// Account email
	Email string
	// Account last usage time
	LastUsedAt time.Time
}

var ErrSessionNotFound = errors.New("session not found")

func (d *Datastore) CreateSession(accountID uuid.UUID, sessionVersion int, userAgent string) (*Session, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	session := Session{
		ID:        id,
		AccountID: accountID,
		UserAgent: userAgent,
		Version:   sessionVersion,
	}

	if err := d.DB.Create(&session).Error; err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &session, nil
}

func (d *Datastore) ListSessions(accountID uuid.UUID) ([]Session, error) {
	var sessions []Session
	if err := d.DB.Where("account_id = ? AND version >= ?", accountID, &d.minSessionVersion).Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	return sessions, nil
}

func (d *Datastore) GetSession(sessionID uuid.UUID) (*SessionWithAccountInfo, error) {
	var session SessionWithAccountInfo
	if err := d.DB.Table("sessions").
		Select(`
			sessions.id,
			sessions.account_id,
			sessions.version,
			accounts.email,
			accounts.last_used_at
		`).
		Joins("JOIN accounts ON sessions.account_id = accounts.id").
		Where("sessions.id = ?", sessionID).
		First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

func (d *Datastore) DeleteSession(sessionID uuid.UUID, accountID uuid.UUID) error {
	result := d.DB.Delete(&Session{}, "id = ? AND account_id = ?", sessionID, accountID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete session: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (d *Datastore) DeleteAllSessions(accountID uuid.UUID) error {
	result := d.DB.Delete(&Session{}, "account_id = ?", accountID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete all sessions: %w", result.Error)
	}
	return nil
}
