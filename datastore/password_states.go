package datastore

import (
	"errors"
	"fmt"
	"time"

	"github.com/brave/accounts/util"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	NormalStateExpiration = 30 * time.Second
	TwoFAStateExpiration  = 5 * time.Minute
)

// InterimPasswordState represents the state of an OPAQUE Authenticated Key Exchange or Registration operation
type InterimPasswordState struct {
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
	// IsRegistration indicates whether the state is for a registration operation
	IsRegistration bool `json:"-" gorm:"column:is_registration"`
	// WebAuthnChallenge stores the WebAuthn session data for login challenge
	WebAuthnChallenge *webauthn.SessionData `json:"-" gorm:"column:webauthn_challenge;serializer:json"`
	// CreatedAt records when this login state was initialized
	CreatedAt time.Time `json:"createdAt" gorm:"<-:update"`
}

func (d *Datastore) CreateLoginState(accountID *uuid.UUID, email string, state []byte, oprfSeedID int, requiresTwoFA bool) (*InterimPasswordState, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	loginState := InterimPasswordState{
		ID:             id,
		AccountID:      accountID,
		Email:          util.CanonicalizeEmail(email),
		OprfSeedID:     oprfSeedID,
		State:          state,
		RequiresTwoFA:  requiresTwoFA,
		IsRegistration: false,
	}

	if err := d.DB.Create(&loginState).Error; err != nil {
		return nil, fmt.Errorf("failed to create login state: %w", err)
	}

	return &loginState, nil
}

func (d *Datastore) CreateRegistrationState(accountID uuid.UUID, email string, oprfSeedID int, requiresTwoFA bool) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	state := InterimPasswordState{
		ID:             id,
		AccountID:      &accountID,
		Email:          util.CanonicalizeEmail(email),
		OprfSeedID:     oprfSeedID,
		RequiresTwoFA:  requiresTwoFA,
		IsRegistration: true,
	}

	if err := d.DB.Create(&state).Error; err != nil {
		return fmt.Errorf("failed to create registration state: %w", err)
	}

	return nil
}

func (d *Datastore) UpdateInterimPasswordState(stateID uuid.UUID, state []byte) error {
	return d.DB.Model(&InterimPasswordState{}).Where("id = ?", stateID).Update("state", state).Error
}

func (d *Datastore) MarkInterimPasswordStateAsAwaitingTwoFA(stateID uuid.UUID) error {
	return d.DB.Model(&InterimPasswordState{}).Where("id = ?", stateID).Update("awaiting_twofa", true).Error
}

func (d *Datastore) SetInterimPasswordStateWebAuthnChallenge(stateID uuid.UUID, sessionData *webauthn.SessionData) error {
	return d.DB.Model(&InterimPasswordState{}).Where("id = ?", stateID).Update("webauthn_challenge", sessionData).Error
}

func (d *Datastore) DeleteInterimPasswordState(stateID uuid.UUID) error {
	return d.DB.Delete(&InterimPasswordState{}, "id = ?", stateID).Error
}

func (d *Datastore) processInterimPasswordState(state *InterimPasswordState, forTwoFA bool) error {
	// Verify that the 2FA state matches the expected operation
	if forTwoFA != state.AwaitingTwoFA {
		return util.ErrInterimPasswordStateMismatch
	}

	// Check if login state has expired - use different expiration time for 2FA
	expirationTime := NormalStateExpiration
	if state.AwaitingTwoFA {
		expirationTime = TwoFAStateExpiration
	}

	if time.Since(state.CreatedAt) > expirationTime {
		return util.ErrInterimPasswordStateExpired
	}

	// If 2FA is not required, delete the login state so that it cannot be used again
	if !state.RequiresTwoFA {
		if dbErr := d.DeleteInterimPasswordState(state.ID); dbErr != nil {
			return fmt.Errorf("failed to delete login state: %w", dbErr)
		}
	}

	return nil
}

func (d *Datastore) GetLoginState(loginStateID uuid.UUID, forTwoFA bool) (*InterimPasswordState, error) {
	var state InterimPasswordState
	if err := d.DB.First(&state, "id = ? AND is_registration = FALSE", loginStateID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, util.ErrInterimPasswordStateNotFound
		}
		return nil, fmt.Errorf("failed to get login state: %w", err)
	}

	if state.AwaitingTwoFA && !state.RequiresTwoFA {
		// This should never happen, but checking in case there is a bug elsewhere
		return nil, util.ErrInterimPasswordStateMismatch
	}

	if err := d.processInterimPasswordState(&state, forTwoFA); err != nil {
		return nil, err
	}

	return &state, nil
}

func (d *Datastore) GetRegistrationState(email string, forTwoFA bool) (*InterimPasswordState, error) {
	var state InterimPasswordState
	if err := d.DB.Order("created_at DESC").First(&state, "email = ? AND is_registration = TRUE", util.CanonicalizeEmail(email)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, util.ErrInterimPasswordStateNotFound
		}
		return nil, fmt.Errorf("failed to get registration state: %w", err)
	}

	if state.AccountID == nil {
		return nil, fmt.Errorf("registration state has no account ID")
	}

	if err := d.processInterimPasswordState(&state, forTwoFA); err != nil {
		return nil, err
	}

	return &state, nil
}
