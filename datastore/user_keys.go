package datastore

import (
	"fmt"
	"time"

	"github.com/brave/accounts/util"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const MaxUserKeysPerService = 2

// DBUserKey represents a key in the database
type DBUserKey struct {
	// AccountID is the UUID of the account that owns this key
	AccountID uuid.UUID `json:"-" gorm:"primaryKey"`
	// Service identifies the service this key is for
	Service string `json:"service" gorm:"primaryKey"`
	// KeyName identifies the name of the key within the service
	KeyName string `json:"keyName" gorm:"primaryKey"`
	// KeyMaterial contains the encrypted key data as bytes
	KeyMaterial []byte `json:"keyMaterial"`
	// SerialNumber is incremented each time the key is overwritten
	SerialNumber int `json:"serialNumber" gorm:"default:1"`
	// UpdatedAt is the timestamp when the key was last updated
	UpdatedAt time.Time `json:"updatedAt" gorm:"autoUpdateTime:false"`
}

// TableName overrides the default table name for DBUserKey
func (DBUserKey) TableName() string {
	return "user_keys"
}

// StoreUserKey saves a user key to the database
func (d *Datastore) StoreUserKey(key *DBUserKey) error {
	return d.DB.Transaction(func(tx *gorm.DB) error {
		updated, err := d.updateExistingKeyTx(tx, key)
		if err != nil {
			return err
		}
		if updated {
			return nil
		}
		return d.insertNewKeyTx(tx, key)
	})
}

// updateExistingKeyTx attempts to update an existing key atomically
func (d *Datastore) updateExistingKeyTx(tx *gorm.DB, key *DBUserKey) (bool, error) {
	result := tx.Model(&DBUserKey{}).
		Where("account_id = ? AND service = ? AND key_name = ?",
			key.AccountID, key.Service, key.KeyName).
		Updates(map[string]interface{}{
			"key_material":  key.KeyMaterial,
			"updated_at":    key.UpdatedAt,
			"serial_number": gorm.Expr("serial_number + 1"),
		})
	if result.Error != nil {
		return false, fmt.Errorf("failed to update existing key: %w", result.Error)
	}
	return result.RowsAffected > 0, nil
}

// insertNewKeyTx inserts a new key after enforcing the per-service limit
func (d *Datastore) insertNewKeyTx(tx *gorm.DB, key *DBUserKey) error {
	var count int64
	result := tx.Model(&DBUserKey{}).
		Where("account_id = ? AND service = ?", key.AccountID, key.Service).
		Count(&count)
	if result.Error != nil {
		return fmt.Errorf("failed to check existing user keys: %w", result.Error)
	}

	if count >= MaxUserKeysPerService {
		return util.ErrMaxUserKeysExceeded
	}

	if err := tx.Create(key).Error; err != nil {
		return fmt.Errorf("failed to insert new key: %w", err)
	}
	return nil
}

// GetUserKey retrieves a user key from the database
func (d *Datastore) GetUserKey(accountID uuid.UUID, service string, keyName string) (*DBUserKey, error) {
	var key DBUserKey
	result := d.DB.Where("account_id = ? AND service = ? AND key_name = ?", accountID, service, keyName).First(&key)
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

// DeleteAllUserKeys deletes all keys for an account
func (d *Datastore) DeleteAllUserKeys(accountID uuid.UUID) error {
	result := d.DB.Where("account_id = ?", accountID).Delete(&DBUserKey{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete user keys: %w", result.Error)
	}
	return nil
}
