package datastore

import (
	"errors"
	"fmt"
	"time"

	"github.com/brave/accounts/util"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const AkeStateExpiration = 30 * time.Second

// AKEState represents the state of an Authenticated Key Exchange operation
type AKEState struct {
	// ID uniquely identifies the AKE state instance
	ID uuid.UUID `json:"id"`
	// AccountID links to the associated account
	AccountID *uuid.UUID `json:"-"`
	// OprfSeedID references the seed used for the Oblivious PRF
	OprfSeedID int `json:"-"`
	// State stores the serialized AKE state data
	State []byte `json:"-"`
	// CreatedAt records when this AKE state was initialized
	CreatedAt time.Time `json:"createdAt" gorm:"<-:update"`
}

func (d *Datastore) CreateAKEState(accountID *uuid.UUID, state []byte, oprfSeedID int) (*AKEState, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	akeState := AKEState{
		ID:         id,
		AccountID:  accountID,
		OprfSeedID: oprfSeedID,
		State:      state,
	}

	if err := d.DB.Create(&akeState).Error; err != nil {
		return nil, fmt.Errorf("failed to create AKE state: %w", err)
	}

	return &akeState, nil
}

func (d *Datastore) GetAKEState(akeStateID uuid.UUID) (*AKEState, error) {
	var akeState AKEState
	if err := d.DB.First(&akeState, "id = ?", akeStateID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, util.ErrAKEStateNotFound
		}
		return nil, fmt.Errorf("failed to get AKE state: %w", err)
	}

	var err error
	// Check if AKE state has expired
	if time.Since(akeState.CreatedAt) > AkeStateExpiration {
		err = util.ErrAKEStateExpired
	}

	if dbErr := d.DB.Delete(&AKEState{}, "id = ?", akeStateID).Error; dbErr != nil {
		return nil, fmt.Errorf("failed to delete AKE state: %w", dbErr)
	}

	if err != nil {
		return nil, err
	}

	return &akeState, nil
}
