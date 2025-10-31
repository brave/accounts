package datastore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/brave/accounts/util"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	LastEmailVerifiedAt *time.Time `gorm:"<-:update"`
	// Locale preference for the account (e.g., "en-US", "es-ES")
	Locale *string `json:"-"`
	// TOTPEnabled indicates whether the account has TOTP enabled
	TOTPEnabled bool `json:"-"`
	// Timestamp when TOTP was enabled
	TOTPEnabledAt *time.Time `json:"-"`
	// Recovery key hash
	RecoveryKeyHash []byte `json:"-"`
	// Timestamp when the recovery key was created
	RecoveryKeyCreatedAt *time.Time `json:"-"`
	// WebAuthn user handle (64 random bytes)
	WebAuthnID []byte `json:"-" gorm:"column:webauthn_id"`
	// WebAuthnEnabled indicates whether the account has WebAuthn enabled
	WebAuthnEnabled bool `json:"-" gorm:"column:webauthn_enabled"`
	// Timestamp when WebAuthn was enabled
	WebAuthnEnabledAt *time.Time `json:"-" gorm:"column:webauthn_enabled_at"`
	// Timestamp when the account was created
	CreatedAt time.Time `gorm:"<-:false"`
}

// TwoFAConfiguration represents the 2FA methods enabled for an account and related timestamps
type TwoFAConfiguration struct {
	// TOTP indicates whether Time-based One-Time Password is enabled
	TOTP bool `json:"totp"`
	// TOTPEnabledAt indicates when TOTP was enabled
	TOTPEnabledAt *time.Time `json:"totpEnabledAt,omitempty"`
	// WebAuthn indicates whether WebAuthn is enabled
	WebAuthn bool `json:"webAuthn" gorm:"column:webauthn"`
	// WebAuthnEnabledAt indicates when WebAuthn was enabled
	WebAuthnEnabledAt *time.Time `json:"webAuthnEnabledAt,omitempty" gorm:"column:webauthn_enabled_at"`
	// WebAuthnCredentials is a list of registered WebAuthn credentials
	WebAuthnCredentials []DBWebAuthnCredential `json:"webAuthnCredentials,omitempty" gorm:"-"`
	// RecoveryKeyCreatedAt indicates when the recovery key was created
	RecoveryKeyCreatedAt *time.Time `json:"recoveryKeyCreatedAt,omitempty"`
}

func (d *Datastore) GetAccount(tx *gorm.DB, email string) (*Account, error) {
	var account Account
	if tx == nil {
		tx = d.DB
	}
	result := tx.Omit("webauthn_id").Where("email = ?", util.CanonicalizeEmail(email)).First(&account)
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

func (d *Datastore) UpdateOpaqueRegistration(accountID uuid.UUID, oprfSeedID int, opaqueRegistration []byte) error {
	result := d.DB.Model(&Account{}).
		Where("id = ?", accountID).
		Updates(Account{
			OprfSeedID:         &oprfSeedID,
			OpaqueRegistration: opaqueRegistration,
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

func (d *Datastore) SetWebAuthnSetting(accountID uuid.UUID, enabled bool) error {
	var enabledAt *time.Time

	if enabled {
		now := time.Now().UTC()
		enabledAt = &now
	}

	result := d.DB.Model(&Account{}).
		Where("id = ?", accountID).
		Updates(map[string]interface{}{
			"webauthn_enabled":    enabled,
			"webauthn_enabled_at": enabledAt,
		})

	if result.Error != nil {
		return fmt.Errorf("error updating WebAuthn setting for account: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrAccountNotFound
	}

	return nil
}

func (d *Datastore) SetTOTPSetting(accountID uuid.UUID, enabled bool) error {
	var enabledAt *time.Time

	if enabled {
		now := time.Now().UTC()
		enabledAt = &now
	}

	result := d.DB.Model(&Account{}).
		Where("id = ?", accountID).
		Updates(map[string]interface{}{
			"totp_enabled":    enabled,
			"totp_enabled_at": enabledAt,
		})

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
	var createdAt *time.Time
	var err error

	if recoveryKey != nil {
		if len(*recoveryKey) != 32 {
			return fmt.Errorf("recovery key must be 32 characters")
		}
		recoveryKeyHash, err = util.HashRecoveryKey(*recoveryKey)
		if err != nil {
			return fmt.Errorf("error hashing recovery key: %w", err)
		}
		now := time.Now().UTC()
		createdAt = &now
	}

	result := d.DB.Model(&Account{}).
		Where("id = ?", accountID).
		Updates(map[string]interface{}{
			"recovery_key_hash":       recoveryKeyHash,
			"recovery_key_created_at": createdAt,
		})

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

	if account.RecoveryKeyHash == nil || !util.VerifyRecoveryKeyHash(recoveryKey, account.RecoveryKeyHash) {
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

func (d *Datastore) GetTwoFAConfiguration(accountID uuid.UUID) (*TwoFAConfiguration, error) {
	var details TwoFAConfiguration
	result := d.DB.Model(&Account{}).
		Select("totp_enabled as totp, totp_enabled_at, webauthn_enabled as webauthn, webauthn_enabled_at, recovery_key_created_at").
		Where("id = ?", accountID).
		First(&details)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("error fetching 2FA details: %w", result.Error)
	}

	// Fetch WebAuthn credentials
	credentials, err := d.GetWebAuthnCredentials(accountID)
	if err != nil {
		return nil, fmt.Errorf("error fetching WebAuthn credentials: %w", err)
	}

	details.WebAuthnCredentials = credentials

	return &details, nil
}

func (d *Datastore) SetAccountLocaleIfMissing(accountID uuid.UUID, locale string) error {
	if locale == "" {
		return nil // Don't set empty locale
	}

	result := d.DB.Model(&Account{}).
		Where("id = ? AND locale IS NULL", accountID).
		Update("locale", locale)

	if result.Error != nil {
		return fmt.Errorf("error setting account locale: %w", result.Error)
	}

	return nil
}

func (d *Datastore) GetAccountLocale(accountID uuid.UUID) (*string, error) {
	var account Account
	result := d.DB.Select("locale").Where("id = ?", accountID).First(&account)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("error fetching account locale: %w", result.Error)
	}

	return account.Locale, nil
}

// GetOrCreateWebAuthnID returns the WebAuthn ID for an account, creating it if it doesn't exist
func (d *Datastore) GetOrCreateWebAuthnID(accountID uuid.UUID) ([]byte, error) {
	var webauthnID []byte

	err := d.DB.Transaction(func(tx *gorm.DB) error {
		var account Account
		result := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("webauthn_id").
			Where("id = ?", accountID).
			First(&account)

		if result.Error != nil {
			return fmt.Errorf("error fetching account webauthn_id: %w", result.Error)
		}

		// If webauthn_id already exists, return it
		if account.WebAuthnID != nil {
			webauthnID = account.WebAuthnID
			return nil
		}

		// Generate a new 64-byte random ID
		webauthnID = make([]byte, 64)
		if _, err := rand.Read(webauthnID); err != nil {
			return fmt.Errorf("failed to generate webauthn_id: %w", err)
		}

		// Update the account with the new webauthn_id
		result = tx.Model(&Account{}).Where("id = ?", accountID).Update("webauthn_id", webauthnID)
		if result.Error != nil {
			return fmt.Errorf("error updating account webauthn_id: %w", result.Error)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return webauthnID, nil
}
