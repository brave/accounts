package datastore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/brave/accounts/util"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Verification represents an email verification record and its status
type Verification struct {
	// ID uniquely identifies the verification request
	ID uuid.UUID
	// Email stores the address to be verified
	Email string
	// Code contains the verification code sent to the user
	Code string
	// Verified indicates whether the email has been successfully verified
	Verified bool
	// Service identifies the actor that initiated the verification
	Service string
	// Intent describes the purpose of the verification
	Intent string
	// CreatedAt records when the verification was initiated
	CreatedAt time.Time `gorm:"<-:update"`
}

const (
	AuthTokenIntent    = "auth_token"
	VerificationIntent = "verification"
	RegistrationIntent = "registration"
	SetPasswordIntent  = "set_password"

	codeLength              = 32
	verifyWaitMaxDuration   = 20 * time.Second
	VerificationExpiration  = 30 * time.Minute
	maxPendingVerifications = 3
)

func generateNotificationChannel(id uuid.UUID) string {
	return fmt.Sprintf("verification_%s", id.String())
}

// CreateVerification creates a new verification record
func (d *Datastore) CreateVerification(email string, service string, intent string) (*Verification, error) {
	code := util.GenerateRandomString(codeLength)

	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	email = util.PartiallyNormalizeEmail(email)
	verification := Verification{
		ID:       id,
		Email:    email,
		Code:     code,
		Service:  service,
		Intent:   intent,
		Verified: false,
	}

	var existingCount int64
	if err := d.DB.Model(&Verification{}).
		Where("email = ? AND verified = false AND created_at > ?",
			email,
			time.Now().Add(-VerificationExpiration)).
		Count(&existingCount).Error; err != nil {
		return nil, fmt.Errorf("error counting verifications: %w", err)
	}

	if existingCount >= maxPendingVerifications {
		return nil, util.ErrTooManyVerifications
	}
	if err := d.DB.Create(&verification).Error; err != nil {
		return nil, fmt.Errorf("error creating verification: %w", err)
	}

	return &verification, nil
}

// UpdateVerificationStatus updates the verification status for a given email
func (d *Datastore) UpdateAndGetVerificationStatus(id uuid.UUID, code string) (*Verification, error) {
	result := d.DB.Model(&Verification{}).
		Where("id = ? AND code = ? AND verified = false", id, code).
		Update("verified", true)

	if result.Error != nil {
		return nil, fmt.Errorf("error updating verification status: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return nil, util.ErrVerificationNotFound
	}

	// Send notification
	if err := d.DB.Exec(
		"SELECT pg_notify(?, ?)",
		generateNotificationChannel(id),
		"1",
	).Error; err != nil {
		return nil, fmt.Errorf("failed to send notification: %w", err)
	}

	return d.GetVerificationStatus(id)
}

// GetVerificationStatus checks if email is verified with given token
func (d *Datastore) GetVerificationStatus(id uuid.UUID) (*Verification, error) {
	var verification Verification
	if err := d.DB.First(&verification, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, util.ErrVerificationNotFound
		}
		return nil, fmt.Errorf("error fetching verification: %w", err)
	}

	if time.Since(verification.CreatedAt) > VerificationExpiration {
		if err := d.DB.Delete(&verification).Error; err != nil {
			return nil, fmt.Errorf("error deleting expired verification: %w", err)
		}
		return nil, util.ErrVerificationNotFound
	}

	return &verification, nil
}

func (d *Datastore) WaitOnVerification(ctx context.Context, id uuid.UUID) (bool, error) {
	// Setup notification listening
	conn, err := d.listenPool.Acquire(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to acquire database conn from pool: %w", err)
	}
	defer conn.Release()

	channelName := generateNotificationChannel(id)
	err = util.ListenOnPGChannel(ctx, conn, channelName)
	if err != nil {
		return false, fmt.Errorf("failed to listen on channel: %w", err)
	}
	//nolint:errcheck
	defer util.UnlistenOnPGChannel(ctx, conn, channelName)

	// Check the database to see if the verification status changed
	// while setting up the listener.
	var verification Verification
	result := d.DB.Select("verified").Where("id = ?", id).First(&verification)
	if result.Error != nil {
		return false, result.Error
	}
	if verification.Verified {
		return true, nil
	}

	// Wait for notification with timeout
	ctx, cancel := context.WithTimeout(ctx, verifyWaitMaxDuration)
	defer cancel()

	_, err = conn.Conn().WaitForNotification(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return false, nil
		}
		return false, fmt.Errorf("error waiting for notification: %w", err)
	}

	return true, nil
}

func (d *Datastore) DeleteVerification(id uuid.UUID) error {
	result := d.DB.Delete(&Verification{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete verification: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return util.ErrVerificationNotFound
	}

	return nil
}
