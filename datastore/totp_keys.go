package datastore

import (
	"fmt"
	"time"

	"github.com/brave/accounts/util"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"gorm.io/gorm"
)

// TOTPKey represents a TOTP key in the database
type TOTPKey struct {
	// AccountID is the UUID of the account that owns this TOTP key
	AccountID uuid.UUID `json:"-" gorm:"primaryKey;table:totp_keys"`
	// Key contains the TOTP key material as text
	Key string `json:"key"`
	// CreatedAt is the timestamp when the key was created
	CreatedAt time.Time `json:"createdAt" gorm:"<-:false"`
}

// GenerateAndStoreTOTPKey creates a new TOTP key for an account and stores it
func (d *Datastore) GenerateAndStoreTOTPKey(accountID uuid.UUID, email string) (*otp.Key, error) {
	// Generate TOTP key
	key, err := d.totpUtil.GenerateKey(email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Store in database
	totpKey := &TOTPKey{
		AccountID: accountID,
		Key:       key.Secret(),
	}

	result := d.DB.Save(totpKey)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to store TOTP key: %w", result.Error)
	}

	return key, nil
}

// ValidateTOTPCode checks if the provided code is valid for the specified account
func (d *Datastore) ValidateTOTPCode(accountID uuid.UUID, code string) error {
	var key TOTPKey
	result := d.DB.Where("account_id = ?", accountID).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return util.ErrKeyNotFound
		}
		return fmt.Errorf("failed to retrieve TOTP key: %w", result.Error)
	}

	if !d.totpUtil.ValidateCode(key.Key, code) {
		return util.ErrBadTOTPCode
	}
	return nil
}

// DeleteTOTPKey deletes a TOTP key from the database
func (d *Datastore) DeleteTOTPKey(accountID uuid.UUID) error {
	result := d.DB.Where("account_id = ?", accountID).Delete(&TOTPKey{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete TOTP key: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return util.ErrKeyNotFound
	}
	return nil
}
