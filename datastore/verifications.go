package datastore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/brave/accounts/util"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	// NewSessionID stores the session ID after verification with a registration/auth token intent is complete
	NewSessionID *uuid.UUID
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

	VerificationExpiration  = 15 * time.Minute
	maxPendingVerifications = 3
	MaxCodeAttempts         = 5
)

const (
	codeAlphabetFull  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234679" // 32 chars
	codeAlphabetDigit = "234679"                           // 6 chars
	codePattern       = "FFDFFD"                           // F = Full, D = Digit
)

func generateVerificationCode(pattern string) (string, error) {
	if len(pattern) == 0 {
		return "", fmt.Errorf("code pattern must not be empty")
	}
	out := make([]byte, len(pattern))
	for i, char := range pattern {
		var alphabet string
		switch char {
		case 'F':
			alphabet = codeAlphabetFull
		case 'D':
			alphabet = codeAlphabetDigit
		default:
			return "", fmt.Errorf("invalid code pattern char %q", char)
		}
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random code: %w", err)
		}
		// Map random number to char in alphabet for the current position
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}

// CreateVerification creates a new verification record
func (d *Datastore) CreateVerification(email string, service string, intent string) (*Verification, error) {
	code, err := generateVerificationCode(codePattern)
	if err != nil {
		return nil, err
	}

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

func (d *Datastore) SetVerificationNewSessionID(id uuid.UUID, sessionID uuid.UUID) error {
	result := d.DB.Model(&Verification{}).
		Where("id = ?", id).
		Update("new_session_id", sessionID)

	if result.Error != nil {
		return fmt.Errorf("failed to set new session id: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return util.ErrVerificationNotFound
	}

	return nil
}

func (d *Datastore) DeleteVerificationsByNewSessionID(sessionID uuid.UUID) error {
	result := d.DB.Delete(&Verification{}, "new_session_id = ?", sessionID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete verifications by session id: %w", result.Error)
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

func (d *Datastore) IncrementVerificationCodeAttempts(id uuid.UUID) (int16, error) {
	var verification Verification
	result := d.DB.Model(&verification).
		Clauses(clause.Returning{Columns: []clause.Column{{Name: "code_attempts"}}}).
		Where("id = ?", id).
		Update("code_attempts", gorm.Expr("code_attempts + 1"))

	if result.Error != nil {
		return 0, fmt.Errorf("error incrementing code attempts: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return 0, util.ErrVerificationNotFound
	}

	return verification.CodeAttempts, nil
}
