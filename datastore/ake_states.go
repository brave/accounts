package datastore

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const akeStateExpiration = 30 * time.Second

var ErrAKEStateNotFound = errors.New("AKE state not found")
var ErrAKEStateExpired = errors.New("AKE state has expired")

type AKEState struct {
	ID        uuid.UUID `json:"id"`
	AccountID uuid.UUID `json:"-"`
	State     []byte    `json:"-"`
	CreatedAt time.Time `json:"createdAt" gorm:"<-:false"`
}

func (d *Datastore) CreateAKEState(accountID uuid.UUID, state []byte) (*AKEState, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	akeState := AKEState{
		ID:        id,
		AccountID: accountID,
		State:     state,
	}

	if err := d.db.Create(&akeState).Error; err != nil {
		return nil, fmt.Errorf("failed to create AKE state: %w", err)
	}

	return &akeState, nil
}

func (d *Datastore) DeleteAKEState(akeStateID uuid.UUID) error {
	result := d.db.Delete(&AKEState{}, "id = ?", akeStateID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete AKE state: %w", result.Error)
	}

	return nil
}

func (d *Datastore) GetAKEState(akeStateID uuid.UUID) (*AKEState, error) {
	var akeState AKEState
	if err := d.db.First(&akeState, "id = ?", akeStateID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAKEStateNotFound
		}
		return nil, fmt.Errorf("failed to get AKE state: %w", err)
	}

	// Check if AKE state has expired
	if time.Since(akeState.CreatedAt) > akeStateExpiration {
		if err := d.DeleteAKEState(akeStateID); err != nil {
			return nil, fmt.Errorf("failed to delete expired AKE state: %w", err)
		}
		return nil, ErrAKEStateExpired
	}

	return &akeState, nil
}
