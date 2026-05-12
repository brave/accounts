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
	// IsInvalidated indicates whether the verification has been invalidated
	IsInvalidated bool
	// CreatedAt records when the verification was initiated
	CreatedAt time.Time `gorm:"<-:update"`
}

const (
	VerificationIntent   = "verification"
	RegistrationIntent   = "registration"
	ResetPasswordIntent  = "reset_password"
	ChangePasswordIntent = "change_password"

	VerificationExpiration  = 15 * time.Minute
	maxPendingVerifications = 3
	maxDailyVerifications   = 10
	MaxCodeAttempts         = 5
)

func (d *Datastore) validVerificationModel(v *Verification) *gorm.DB {
	if v == nil {
		v = &Verification{}
	}
	return d.DB.Model(v).Where("is_invalidated = false")
}

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

	// Serialize concurrent verification creation for the same email so the
	// pending/daily count checks below cannot race with concurrent inserts.
	err = d.DB.Transaction(func(tx *gorm.DB) error {
		// Take a transaction-scoped advisory lock keyed on the email; released on commit/rollback.
		if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtext(?)::bigint)", email).Error; err != nil {
			return fmt.Errorf("error acquiring verification lock: %w", err)
		}

		// Enforce daily cap across all verifications for this email
		var dailyCount int64
		if err := tx.Model(&Verification{}).
			Where("email = ? AND created_at >= ?", email, time.Now().UTC().Add(-24 * time.Hour)).
			Count(&dailyCount).Error; err != nil {
			return fmt.Errorf("error counting daily verifications: %w", err)
		}

		if dailyCount >= maxDailyVerifications {
			return util.ErrDailyVerificationLimitReached
		}

		// Reject if too many unverified verifications are still pending
		var existingCount int64
		if err := d.validVerificationModel(nil).
			Where("email = ? AND verified = false AND created_at > ?",
				email,
				time.Now().UTC().Add(-VerificationExpiration)).
			Count(&existingCount).Error; err != nil {
			return fmt.Errorf("error counting verifications: %w", err)
		}

		if existingCount >= maxPendingVerifications {
			return util.ErrTooManyVerifications
		}

		if err := tx.Create(&verification).Error; err != nil {
			return fmt.Errorf("error creating verification: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &verification, nil
}

// MarkVerificationAsComplete marks the verification as verified
func (d *Datastore) MarkVerificationAsComplete(id uuid.UUID) error {
	result := d.validVerificationModel(nil).
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

// GetVerificationStatus fetches the verification record by ID, returning an error if expired, invalidated, or not found
func (d *Datastore) GetVerificationStatus(id uuid.UUID) (*Verification, error) {
	var verification Verification
	if err := d.validVerificationModel(nil).First(&verification, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, util.ErrVerificationNotFound
		}
		return nil, fmt.Errorf("error fetching verification: %w", err)
	}

	if time.Since(verification.CreatedAt) > VerificationExpiration {
		return nil, util.ErrVerificationNotFound
	}

	return &verification, nil
}

func (d *Datastore) InvalidateVerification(id uuid.UUID) error {
	result := d.validVerificationModel(nil).
		Where("id = ?", id).
		Update("is_invalidated", true)
	if result.Error != nil {
		return fmt.Errorf("failed to invalidate verification: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return util.ErrVerificationNotFound
	}

	return nil
}

func (d *Datastore) SetVerificationNewSessionID(id uuid.UUID, sessionID uuid.UUID) error {
	result := d.validVerificationModel(nil).
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

func (d *Datastore) InvalidateVerificationsByNewSessionID(sessionID uuid.UUID) error {
	result := d.validVerificationModel(nil).
		Where("new_session_id = ?", sessionID).
		Update("is_invalidated", true)
	if result.Error != nil {
		return fmt.Errorf("failed to invalidate verifications by session id: %w", result.Error)
	}

	return nil
}

func (d *Datastore) IncrementVerificationEmailAttempts(id uuid.UUID) error {
	result := d.validVerificationModel(nil).
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
	result := d.validVerificationModel(nil).
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
	result := d.validVerificationModel(&verification).
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
