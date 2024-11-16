package datastore

import (
	"fmt"
	"time"

	"github.com/brave-experiments/accounts/util"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DBUserKey represents a key in the database
type DBUserKey struct {
	// AccountID is the UUID of the account that owns this key
	AccountID uuid.UUID `json:"-" gorm:"primaryKey"`
	// Name identifies the type of key (wrapping_key, sync_enc_seed, or sync_device_seed)
	Name string `json:"name" gorm:"primaryKey"`
	// EncryptedKey contains the encrypted key data as bytes
	EncryptedKey []byte `json:"encryptedKey"`
	// UpdatedAt is the timestamp when the key was last updated
	UpdatedAt time.Time `json:"updatedAt" gorm:"autoUpdateTime:false"`
}

// TableName overrides the default table name for DBUserKey
func (DBUserKey) TableName() string {
	return "user_keys"
}

// StoreUserKey saves a user key to the database
func (d *Datastore) StoreUserKey(key *DBUserKey) error {
	result := d.DB.Save(key)
	if result.Error != nil {
		return fmt.Errorf("failed to store user key: %w", result.Error)
	}
	return nil
}

// GetUserKey retrieves a user key from the database
func (d *Datastore) GetUserKey(accountID uuid.UUID, name string) (*DBUserKey, error) {
	var key DBUserKey
	result := d.DB.Where("account_id = ? AND name = ?", accountID, name).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, util.ErrKeyNotFound
		}
		return nil, fmt.Errorf("failed to retrieve user key: %w", result.Error)
	}
	return &key, nil
}

// GetUserKeys retrieves all keys for an account
func (d *Datastore) GetUserKeys(accountID uuid.UUID) ([]DBUserKey, error) {
	var keys []DBUserKey
	result := d.DB.Where("account_id = ?", accountID).Find(&keys)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to retrieve user keys: %w", result.Error)
	}
	return keys, nil
}
