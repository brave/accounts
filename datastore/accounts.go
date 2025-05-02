package datastore

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/brave/accounts/util"
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
	// Simplified email address used in the account recovery flow only
	SimplifiedEmail *string `json:"-"`
	// Optional reference to the OPRF seed used for password hashing
	OprfSeedID *int `json:"-"`
	// Serialized OPAQUE protocol registration data
	OpaqueRegistration []byte `json:"-"`
	// Timestamp when the account was last used (with a MOE of 30 minutes)
	LastUsedAt time.Time `gorm:"<-:update"`
	// Timestamp when the account was last verified via email
	LastEmailVerifiedAt time.Time `gorm:"<-:update"`
	// TOTPEnabled indicates whether the account has TOTP enabled
	TOTPEnabled bool `json:"-"`
	// Recovery key hash
	RecoveryKeyHash []byte `json:"-"`
	// Timestamp when the account was created
	CreatedAt time.Time `gorm:"<-:false"`
}

// TwoFAOptions represents the 2FA methods enabled for an account
type TwoFAOptions struct {
	// TOTP indicates whether Time-based One-Time Password is enabled
	TOTP bool `json:"totp"`
}

func (d *Datastore) GetAccount(tx *gorm.DB, email string) (*Account, error) {
	var account Account
	if tx == nil {
		tx = d.DB
	}
	result := tx.Where("email = ?", util.CanonicalizeEmail(email)).First(&account)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("error fetching account: %w", result.Error)
	}
	return &account, nil
}

func (d *Datastore) GetAccountsBySimplifiedEmail(email string) ([]Account, error) {
	var accounts []Account
	simplifiedEmail := util.SimplifyEmail(email)
	if simplifiedEmail == nil {
		return nil, ErrAccountNotFound
	}
	result := d.DB.Where("simplified_email = ?", simplifiedEmail).Find(&accounts)
	if result.Error != nil {
		return nil, fmt.Errorf("error fetching accounts by simplified email: %w", result.Error)
	}
	return accounts, nil
}

func (d *Datastore) AccountExists(email string) (bool, error) {
	var exists bool
	result := d.DB.Model(&Account{}).
		Select("1").
		Where("email = ?", util.CanonicalizeEmail(email)).
		Limit(1).
		Find(&exists)

	if result.Error != nil {
		return false, fmt.Errorf("error checking account existence: %w", result.Error)
	}
	return exists, nil
}

func (d *Datastore) GetOrCreateAccount(email string) (*Account, error) {
	var account *Account

	err := d.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		account, err = d.GetAccount(tx, email)

		if err != nil {
			if !errors.Is(err, ErrAccountNotFound) {
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
			Email:           util.CanonicalizeEmail(email),
			SimplifiedEmail: util.SimplifyEmail(email),
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
	result := d.DB.Model(&Account{}).
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
	result := d.DB.Delete(&Account{}, "id = ?", accountID)
	if result.Error != nil {
		return fmt.Errorf("error deleting account: %w", result.Error)
	}

	return nil
}

func (d *Datastore) MaybeUpdateAccountLastUsed(accountID uuid.UUID, lastUsedTime time.Time) error {
	if time.Since(lastUsedTime) < lastUsedUpdateInterval {
		return nil
	}

	result := d.DB.Model(&Account{}).
		Where("id = ?", accountID).
		Update("last_used_at", time.Now().UTC())

	if result.Error != nil {
		return fmt.Errorf("error updating account last used: %w", result.Error)
	}

	return nil
}

func (d *Datastore) UpdateAccountLastEmailVerifiedAt(accountID uuid.UUID) error {
	result := d.DB.Model(&Account{}).
		Where("id = ?", accountID).
		Update("last_email_verified_at", time.Now().UTC())

	if result.Error != nil {
		return fmt.Errorf("error updating account last verification time: %w", result.Error)
	}

	return nil
}

func (d *Datastore) SetTOTPSetting(accountID uuid.UUID, enabled bool) error {
	result := d.DB.Model(&Account{}).
		Where("id = ?", accountID).
		Update("totp_enabled", enabled)

	if result.Error != nil {
		return fmt.Errorf("error updating TOTP setting for account: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrAccountNotFound
	}

	return nil
}

func (d *Datastore) SetRecoveryKey(accountID uuid.UUID, recoveryKey *string) error {
	var recoveryKeyHash []byte
	if recoveryKey != nil {
		recoveryKeyHash = util.HashRecoveryKey(*recoveryKey)
	}
	result := d.DB.Model(&Account{}).
		Where("id = ?", accountID).
		Update("recovery_key_hash", recoveryKeyHash)

	if result.Error != nil {
		return fmt.Errorf("error updating recovery key hash for account: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrAccountNotFound
	}

	return nil
}

func (d *Datastore) CheckRecoveryKey(accountID uuid.UUID, recoveryKey string) error {
	var account Account
	result := d.DB.Model(&account).
		Select("recovery_key_hash").
		Where("id = ?", accountID).
		Limit(1).
		Find(&account)

	if result.Error != nil {
		return fmt.Errorf("error fetching recovery key hash: %w", result.Error)
	}

	if account.RecoveryKeyHash == nil || !bytes.Equal(util.HashRecoveryKey(recoveryKey), account.RecoveryKeyHash) {
		return util.ErrBadRecoveryKey
	}

	return nil
}

func (d *Datastore) HasRecoveryKey(accountID uuid.UUID) (bool, error) {
	var exists bool
	result := d.DB.Model(&Account{}).
		Select("1").
		Where("id = ? AND recovery_key_hash IS NOT NULL", accountID).
		Limit(1).
		Find(&exists)

	if result.Error != nil {
		return false, fmt.Errorf("error checking recovery key existence: %w", result.Error)
	}
	return exists, nil
}

func (d *Datastore) GetEnabledTwoFAOptions(accountID uuid.UUID) (*TwoFAOptions, error) {
	var options TwoFAOptions
	result := d.DB.Model(&Account{}).
		Select("totp_enabled as totp").
		Where("id = ?", accountID).
		First(&options)

	if result.Error != nil {
		return nil, fmt.Errorf("error fetching 2FA options: %w", result.Error)
	}

	return &options, nil
}
