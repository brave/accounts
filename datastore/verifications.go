package datastore

import (
	"crypto/rand"
	"encoding/base32"
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
	// EmailAttempts tracks the number of times the verification email has been sent
	EmailAttempts int16
	// CodeAttempts tracks the number of wrong-code submission attempts
	CodeAttempts int16
	// CreatedAt records when the verification was initiated
	CreatedAt time.Time `gorm:"<-:update"`
}

const (
	AuthTokenIntent      = "auth_token"
	VerificationIntent   = "verification"
	RegistrationIntent   = "registration"
	ResetPasswordIntent  = "reset_password"
	ChangePasswordIntent = "change_password"

	codeLength              = 6
	VerificationExpiration  = 30 * time.Minute
	maxPendingVerifications = 3
	MaxCodeAttempts         = 10
)

// CreateVerification creates a new verification record
func (d *Datastore) CreateVerification(email string, service string, intent string) (*Verification, error) {
	b := make([]byte, codeLength)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate random code: %w", err)
	}
	code := base32.StdEncoding.EncodeToString(b)[:codeLength]

	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	email = util.CanonicalizeEmail(email)
	verification := Verification{
		ID:            id,
		Email:         email,
		Code:          code,
		Service:       service,
		Intent:        intent,
		EmailAttempts: 1,
		Verified:      false,
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

// MarkVerificationAsComplete marks the verification as verified
func (d *Datastore) MarkVerificationAsComplete(id uuid.UUID) error {
	result := d.DB.Model(&Verification{}).
		Where("id = ?", id).
		Update("verified", true)

	if result.Error != nil {
		return fmt.Errorf("error updating verification status: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return util.ErrVerificationNotFound
	}

	return nil
}

// GetVerificationStatus fetches the verification record by ID, returning an error if expired or not found
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

func (d *Datastore) IncrementVerificationEmailAttempts(id uuid.UUID) error {
	result := d.DB.Model(&Verification{}).
		Where("id = ?", id).
		Update("email_attempts", gorm.Expr("email_attempts + 1"))

	if result.Error != nil {
		return fmt.Errorf("error incrementing email attempts: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return util.ErrVerificationNotFound
	}

	return nil
}

func (d *Datastore) DecrementVerificationEmailAttempts(id uuid.UUID) error {
	result := d.DB.Model(&Verification{}).
		Where("id = ?", id).
		Update("email_attempts", gorm.Expr("email_attempts - 1"))

	if result.Error != nil {
		return fmt.Errorf("error decrementing email attempts: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return util.ErrVerificationNotFound
	}

	return nil
}

func (d *Datastore) IncrementVerificationCodeAttempts(id uuid.UUID) error {
	result := d.DB.Model(&Verification{}).
		Where("id = ?", id).
		Update("code_attempts", gorm.Expr("code_attempts + 1"))

	if result.Error != nil {
		return fmt.Errorf("error incrementing code attempts: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return util.ErrVerificationNotFound
	}

	return nil
}
