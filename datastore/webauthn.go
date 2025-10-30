package datastore

import (
	"fmt"
	"time"

	"github.com/brave/accounts/util"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type DBWebAuthnCredential struct {
	AccountID  uuid.UUID            `gorm:"primaryKey" json:"-"`
	ID         []byte               `gorm:"primaryKey" json:"id"`
	Credential *webauthn.Credential `gorm:"serializer:json" json:"-"`
	Name       string               `json:"name"`
	CreatedAt  time.Time            `gorm:"<-:false" json:"createdAt"`
}

func (DBWebAuthnCredential) TableName() string {
	return "webauthn_credentials"
}

type InterimWebAuthnRegistrationState struct {
	ID          uuid.UUID `gorm:"primaryKey"`
	AccountID   uuid.UUID
	SessionData *webauthn.SessionData `gorm:"serializer:json"`
	CreatedAt   time.Time             `gorm:"<-:false"`
}

func (InterimWebAuthnRegistrationState) TableName() string {
	return "interim_webauthn_registration_states"
}

func (d *Datastore) SaveWebAuthnCredential(accountID uuid.UUID, credentialName string, credential *webauthn.Credential) error {
	dbCredential := DBWebAuthnCredential{
		AccountID:  accountID,
		ID:         credential.ID,
		Credential: credential,
		Name:       credentialName,
	}

	if err := d.DB.Save(&dbCredential).Error; err != nil {
		return fmt.Errorf("failed to save webauthn credential: %w", err)
	}

	return nil
}

func (d *Datastore) GetWebAuthnCredentials(accountID uuid.UUID) ([]DBWebAuthnCredential, error) {
	var dbCredentials []DBWebAuthnCredential

	if err := d.DB.Where("account_id = ?", accountID).Find(&dbCredentials).Error; err != nil {
		return nil, fmt.Errorf("failed to get webauthn credentials: %w", err)
	}

	return dbCredentials, nil
}

func (d *Datastore) DeleteWebAuthnCredential(accountID uuid.UUID, credentialID []byte) error {
	result := d.DB.Delete(&DBWebAuthnCredential{}, "account_id = ? AND id = ?", accountID, credentialID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete webauthn credential: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return util.ErrWebAuthnCredentialNotFound
	}

	return nil
}

func (d *Datastore) CreateInterimWebAuthnState(accountID uuid.UUID, sessionData *webauthn.SessionData) (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to generate uuid: %w", err)
	}

	state := InterimWebAuthnRegistrationState{
		ID:          id,
		AccountID:   accountID,
		SessionData: sessionData,
	}

	if err := d.DB.Create(&state).Error; err != nil {
		return uuid.Nil, fmt.Errorf("failed to create interim webauthn state: %w", err)
	}

	return state.ID, nil
}

func (d *Datastore) GetAndDeleteInterimWebAuthnState(accountID uuid.UUID, stateID uuid.UUID) (*InterimWebAuthnRegistrationState, error) {
	var state InterimWebAuthnRegistrationState

	// Get the state first
	if err := d.DB.Where("id = ? AND account_id = ?", stateID, accountID).First(&state).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, util.ErrInterimWebAuthnStateNotFound
		}
		return nil, fmt.Errorf("failed to get interim webauthn state: %w", err)
	}

	// Delete it
	if err := d.DB.Delete(&state).Error; err != nil {
		return nil, fmt.Errorf("failed to delete interim webauthn state: %w", err)
	}

	return &state, nil
}
