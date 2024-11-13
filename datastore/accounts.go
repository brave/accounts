package datastore

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Account struct {
	ID                 uuid.UUID
	Email              string
	OprfSeedID         *int   `json:"-"`
	OpaqueRegistration []byte `json:"-"`
	CreatedAt          time.Time
}

var ErrAccountNotFound = errors.New("account not found")

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
			ID:    id,
			Email: email,
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
