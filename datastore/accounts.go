package datastore

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Account struct {
	ID        uuid.UUID
	Email     string
	CreatedAt time.Time `gorm:"<-:false"`
}

func (d *Datastore) GetOrCreateAccount(email string) (*Account, error) {
	var account Account

	err := d.db.Transaction(func(tx *gorm.DB) error {
		result := tx.Where("email = ?", email).First(&account)
		if result.Error == nil {
			return nil
		}

		if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return fmt.Errorf("error fetching account: %w", result.Error)
		}

		id, err := uuid.NewV7()
		if err != nil {
			return err
		}

		account.ID = id
		account.Email = email

		if err := tx.Create(&account).Error; err != nil {
			return fmt.Errorf("error creating account: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &account, nil
}
