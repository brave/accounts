package datastore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/brave-experiments/accounts/util"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"gorm.io/gorm"
)

type Verification struct {
	ID        uuid.UUID
	Email     string
	Code      string
	Verified  bool
	CreatedAt time.Time `gorm:"<-:false"`
}

const (
	codeLength             = 60
	verifyWaitMaxDuration  = 20 * time.Second
	VerificationExpiration = 30 * time.Minute
)

var ErrVerificationNotFound = errors.New("verification not found or invalid token")

func generateNotificationChannel(id uuid.UUID) string {
	return fmt.Sprintf("verification_%s", id.String())
}

// CreateVerification creates a new verification record
func (d *Datastore) CreateVerification(email string) (*Verification, error) {
	code := util.GenerateRandomString(codeLength)

	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	verification := Verification{
		ID:       id,
		Email:    strings.TrimSpace(email),
		Code:     code,
		Verified: false,
	}

	if err := d.db.Create(&verification).Error; err != nil {
		return nil, fmt.Errorf("error creating verification: %w", err)
	}

	return &verification, nil
}

// UpdateVerificationStatus updates the verification status for a given email
func (d *Datastore) UpdateVerificationStatus(id uuid.UUID, code string) error {
	result := d.db.Model(&Verification{}).
		Where("id = ? AND code = ?", id, code).
		Update("verified", true)

	if result.Error != nil {
		return fmt.Errorf("error updating verification status: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrVerificationNotFound
	}

	// Send notification
	if err := d.db.Exec(
		"SELECT pg_notify(?, ?)",
		generateNotificationChannel(id),
		"1",
	).Error; err != nil {
		return fmt.Errorf("failed to send notification: %w", err)
	}

	return nil
}

// GetVerificationStatus checks if email is verified with given token
func (d *Datastore) GetVerificationStatus(ctx context.Context, id uuid.UUID, wait bool) (*Verification, error) {
	// Check current status first
	var verification Verification
	result := d.db.Where("id = ? AND created_at > ?", id, time.Now().Add(-VerificationExpiration)).First(&verification)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrVerificationNotFound
		}
		return nil, fmt.Errorf("error fetching verification: %w", result.Error)
	}

	if verification.Verified {
		return &verification, nil
	}

	if !wait {
		return &verification, nil
	}

	// Setup notification listening
	conn, err := pgx.ConnectConfig(ctx, d.dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	defer conn.Close(ctx)

	channelName := generateNotificationChannel(id)
	_, err = conn.Exec(ctx, "LISTEN \""+channelName+"\"")
	if err != nil {
		return nil, fmt.Errorf("failed to listen on channel: %w", err)
	}
	defer conn.Exec(ctx, "UNLISTEN "+channelName)

	// Wait for notification with timeout
	ctx, cancel := context.WithTimeout(ctx, verifyWaitMaxDuration)
	defer cancel()

	_, err = conn.WaitForNotification(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return &verification, nil
		}
		return nil, fmt.Errorf("error waiting for notification: %w", err)
	}

	verification.Verified = true
	return &verification, nil
}

func (d *Datastore) DeleteVerification(id uuid.UUID) error {
	result := d.db.Delete(&Verification{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete verification: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrVerificationNotFound
	}

	return nil
}
