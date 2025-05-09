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

// StoreTOTPKey stores a TOTP key for an account
func (d *Datastore) StoreTOTPKey(accountID uuid.UUID, key *otp.Key) error {
	totpKey := &TOTPKey{
		AccountID: accountID,
		Key:       key.Secret(),
	}

	result := d.DB.Save(totpKey)
	if result.Error != nil {
		return fmt.Errorf("failed to store TOTP key: %w", result.Error)
	}

	return nil
}

// GetTOTPKey retrieves the TOTP key string for an account
func (d *Datastore) GetTOTPKey(accountID uuid.UUID) (string, error) {
	var key TOTPKey
	result := d.DB.Where("account_id = ?", accountID).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return "", util.ErrKeyNotFound
		}
		return "", fmt.Errorf("failed to retrieve TOTP key: %w", result.Error)
	}

	return key.Key, nil
}

// DeleteTOTPKey deletes a TOTP key from the database
func (d *Datastore) DeleteTOTPKey(accountID uuid.UUID) error {
	result := d.DB.Where("account_id = ?", accountID).Delete(&TOTPKey{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete TOTP key: %w", result.Error)
	}
	return nil
}
