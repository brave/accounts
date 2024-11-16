package datastore

import (
	"errors"
	"fmt"
	"time"

	"github.com/brave-experiments/accounts/util"
	"gorm.io/gorm"
)

const registrationStateExpiration = 30 * time.Second

type RegistrationState struct {
	Email      string `gorm:"primaryKey"`
	OprfSeedID int
	CreatedAt  time.Time `gorm:"<-:false"`
}

func (d *Datastore) GetRegistrationStateSeedID(email string) (int, error) {
	var state RegistrationState
	if err := d.DB.First(&state, "email = ?", email).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, util.ErrRegistrationStateNotFound
		}
		return 0, fmt.Errorf("failed to get registration state: %w", err)
	}

	var err error
	if time.Since(state.CreatedAt) > registrationStateExpiration {
		err = util.ErrRegistrationStateExpired
	}

	if dbErr := d.DB.Delete(&state).Error; dbErr != nil {
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
	result := d.DB.Save(&state)

	if result.Error != nil {
		return fmt.Errorf("failed to upsert registration state: %w", result.Error)
	}
	return nil
}
