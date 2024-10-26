package datastore

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

const registrationStateExpiration = 30 * time.Second

var ErrRegistrationStateNotFound = errors.New("Registration state not found")
var ErrRegistrationStateExpired = errors.New("Registration state has expired")

type RegistrationState struct {
	Email      string `gorm:"primaryKey"`
	OprfSeedID int
	CreatedAt  time.Time `gorm:"<-:false"`
}

func (d *Datastore) GetRegistrationStateSeedID(email string) (int, error) {
	var state RegistrationState
	if err := d.db.First(&state, "email = ?", email).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, ErrRegistrationStateNotFound
		}
		return 0, fmt.Errorf("failed to get registration state: %w", err)
	}

	var err error
	if time.Since(state.CreatedAt) > registrationStateExpiration {
		err = ErrRegistrationStateExpired
	}

	if dbErr := d.db.Delete(&state).Error; dbErr != nil {
		return 0, fmt.Errorf("failed to delete registration state: %w", dbErr)
	}

	if err != nil {
		return 0, err
	}

	return state.OprfSeedID, nil
}

func (d *Datastore) UpsertRegistrationState(email string, oprfSeedID int) error {
	state := RegistrationState{
		Email:      email,
		OprfSeedID: oprfSeedID,
	}
	result := d.db.Save(&state)

	if result.Error != nil {
		return fmt.Errorf("failed to upsert registration state: %w", result.Error)
	}
	return nil
}
