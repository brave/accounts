package datastore

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/brave-experiments/accounts/util"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrAccountNotFound = errors.New("account not found")

const lastUsedUpdateInterval = time.Minute * 30

// Account defines a Brave Account
type Account struct {
	// Unique identifier for the account
	ID uuid.UUID
	// Email address associated with the account
	Email string
	// Normalized email address associated with the account
	NormalizedEmail *string `json:"-"`
	// Optional reference to the OPRF seed used for password hashing
	OprfSeedID *int `json:"-"`
	// Serialized OPAQUE protocol registration data
	OpaqueRegistration []byte `json:"-"`
	// Timestamp when the account was last used (with a MOE of 30 minutes)
	LastUsedAt time.Time `gorm:"<-:update"`
	// Timestamp when the account was created
	CreatedAt time.Time `gorm:"<-:false"`
}

func (d *Datastore) GetAccount(tx *gorm.DB, email string) (*Account, error) {
	var account Account
	if tx == nil {
		tx = d.db
	}
	result := tx.Where("email = ?", email).First(&account)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("error fetching account: %w", result.Error)
	}
	return &account, nil
}

func (d *Datastore) AccountExists(email string) (bool, error) {
	var exists bool
	result := d.db.Model(&Account{}).
		Select("1").
		Where("email = ?", strings.TrimSpace(email)).
		Limit(1).
		Find(&exists)

	if result.Error != nil {
		return false, fmt.Errorf("error checking account existence: %w", result.Error)
	}
	return exists, nil
}

func (d *Datastore) GetOrCreateAccount(email string) (*Account, error) {
	var account *Account

	err := d.db.Transaction(func(tx *gorm.DB) error {
		var err error
		account, err = d.GetAccount(tx, email)

		if err != nil {
			if errors.Is(err, ErrAccountNotFound) {
				err = nil
			} else {
				return err
			}
		} else {
			return nil
		}

		id, err := uuid.NewV7()
		if err != nil {
			return err
		}

		account = &Account{
			ID:              id,
			Email:           email,
			NormalizedEmail: util.NormalizeEmail(email),
		}

		if err := tx.Create(account).Error; err != nil {
			return fmt.Errorf("error creating account: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return account, nil
}

// split into two methods for seed id and registration. use the struct for updates!
func (d *Datastore) UpdateOpaqueRegistration(accountID uuid.UUID, oprfSeedID int, opaqueRegistration []byte) error {
	result := d.db.Model(&Account{}).
		Where("id = ?", accountID).
		Updates(Account{
			OprfSeedID:         &oprfSeedID,
			OpaqueRegistration: opaqueRegistration,
			CreatedAt:          time.Now(),
		})

	if result.Error != nil {
		return fmt.Errorf("failed to update account keys: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("account not found")
	}

	return nil
}

func (d *Datastore) DeleteAccount(accountID uuid.UUID) error {
	result := d.db.Delete(&Account{}, "id = ?", accountID)
	if result.Error != nil {
		return fmt.Errorf("error deleting account: %w", result.Error)
	}

	return nil
}

func (d *Datastore) MaybeUpdateAccountLastUsed(accountID uuid.UUID, lastUsedTime time.Time) error {
	if time.Since(lastUsedTime) < lastUsedUpdateInterval {
		return nil
	}

	result := d.db.Model(&Account{}).
		Where("id = ?", accountID).
		Update("last_used_at", time.Now().UTC())

	if result.Error != nil {
		return fmt.Errorf("error updating account last used: %w", result.Error)
	}

	return nil
}
