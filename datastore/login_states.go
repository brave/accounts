package datastore

import (
	"errors"
	"fmt"
	"time"

	"github.com/brave/accounts/util"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	LoginStateExpiration = 30 * time.Second
	TwoFALoginExpiration = 5 * time.Minute
)

// LoginState represents the state of an Authenticated Key Exchange operation
type LoginState struct {
	// ID uniquely identifies the login state instance
	ID uuid.UUID `json:"id"`
	// AccountID links to the associated account
	AccountID *uuid.UUID `json:"-"`
	// Email associated with the account
	Email string `json:"-"`
	// OprfSeedID references the seed used for the Oblivious PRF
	OprfSeedID int `json:"-"`
	// State stores the serialized AKE state data
	State []byte `json:"-"`
	// AwaitingTwoFA indicates whether the login is awaiting two-factor authentication
	AwaitingTwoFA bool `json:"-" gorm:"column:awaiting_twofa"`
	// RequiresTwoFA indicates whether the account requires two-factor authentication
	RequiresTwoFA bool `json:"-" gorm:"column:requires_twofa"`
	// CreatedAt records when this login state was initialized
	CreatedAt time.Time `json:"createdAt" gorm:"<-:update"`
}

func (d *Datastore) CreateLoginState(accountID *uuid.UUID, email string, state []byte, oprfSeedID int, requiresTwoFA bool) (*LoginState, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	loginState := LoginState{
		ID:            id,
		AccountID:     accountID,
		Email:         email,
		OprfSeedID:    oprfSeedID,
		State:         state,
		RequiresTwoFA: requiresTwoFA,
	}

	if err := d.DB.Create(&loginState).Error; err != nil {
		return nil, fmt.Errorf("failed to create login state: %w", err)
	}

	return &loginState, nil
}

func (d *Datastore) MarkLoginStateAsAwaitingTwoFA(loginStateID uuid.UUID) error {
	return d.DB.Model(&LoginState{}).Where("id = ?", loginStateID).Update("awaiting_twofa", true).Error
}

func (d *Datastore) deleteLoginState(loginStateID uuid.UUID) error {
	result := d.DB.Delete(&LoginState{}, "id = ?", loginStateID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete login state: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return util.ErrLoginStateNotFound
	}
	return nil
}

func (d *Datastore) GetLoginState(loginStateID uuid.UUID, forTwoFA bool) (*LoginState, error) {
	var loginState LoginState
	if err := d.DB.First(&loginState, "id = ?", loginStateID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, util.ErrLoginStateNotFound
		}
		return nil, fmt.Errorf("failed to get login state: %w", err)
	}

	// Verify that the 2FA state matches the expected operation
	if forTwoFA != loginState.AwaitingTwoFA {
		return nil, util.ErrLoginStateMismatch
	}

	var err error
	// Check if login state has expired - use different expiration time for 2FA
	expirationTime := LoginStateExpiration
	if loginState.AwaitingTwoFA {
		expirationTime = TwoFALoginExpiration
	}

	if time.Since(loginState.CreatedAt) > expirationTime {
		err = util.ErrLoginStateExpired
	}

	// If this is a 2FA verification, delete the login state
	// If 2FA is not required, delete the login state so that it cannot be used again
	if forTwoFA || !loginState.RequiresTwoFA {
		if dbErr := d.deleteLoginState(loginStateID); dbErr != nil {
			return nil, fmt.Errorf("failed to delete login state: %w", dbErr)
		}
	}

	if err != nil {
		return nil, err
	}

	return &loginState, nil
}
