package services

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"os"
	"strconv"
	"time"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/util"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
)

const (
	totpIssuerEnv = "TOTP_ISSUER"
	totpQRSizeEnv = "TOTP_QR_SIZE"
	defaultIssuer = "Brave"
	defaultQRSize = 256
)

// TwoFAService provides methods for managing two-factor authentication
type TwoFAService struct {
	// issuer is the name of the issuer for TOTP keys
	issuer string
	// qrSize is the size in pixels for generated QR codes
	qrSize int
	// ds is the datastore instance for persistent storage
	ds *datastore.Datastore
}

// NewTwoFAService creates a new TwoFAService instance with configuration from environment
func NewTwoFAService(ds *datastore.Datastore) *TwoFAService {
	issuer := os.Getenv(totpIssuerEnv)
	if issuer == "" {
		issuer = defaultIssuer
	}

	qrSize := defaultQRSize
	if sizeStr := os.Getenv(totpQRSizeEnv); sizeStr != "" {
		size, err := strconv.Atoi(sizeStr)
		if err != nil || size <= 0 {
			log.Panic().Err(err).Msgf("invalid TOTP QR size: %s", sizeStr)
		}
		qrSize = size
	}

	return &TwoFAService{
		issuer: issuer,
		qrSize: qrSize,
		ds:     ds,
	}
}

// GenerateAndStoreTOTPKey creates and stores a new TOTP key for an account
func (t *TwoFAService) GenerateAndStoreTOTPKey(accountID uuid.UUID, email string) (*otp.Key, error) {
	opts := totp.GenerateOpts{
		Issuer:      t.issuer,
		AccountName: email,
	}

	key, err := totp.Generate(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	if err := t.ds.StoreTOTPKey(accountID, key); err != nil {
		return nil, fmt.Errorf("failed to store TOTP key: %w", err)
	}

	return key, nil
}

// ValidateTOTPCode checks if the provided code is valid for the specified account
func (t *TwoFAService) ValidateTOTPCode(accountID uuid.UUID, code string) error {
	secret, err := t.ds.GetTOTPKey(accountID)
	if err != nil {
		return err
	}

	// Standard validation with one period of time drift in either direction
	opts := totp.ValidateOpts{
		Skew:   1,
		Digits: otp.DigitsSix,
	}
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), opts)
	if err != nil {
		return fmt.Errorf("failed to validate TOTP code: %w", err)
	}
	if !valid {
		return util.ErrBadTOTPCode
	}
	return nil
}

// DeleteKeys deletes all keys for an account
func (t *TwoFAService) DeleteKeys(accountID uuid.UUID) error {
	return t.ds.DeleteTOTPKey(accountID)
}

// GenerateTOTPQRCode generates a QR code image for a TOTP key and returns it as a base64 encoded PNG string
func (t *TwoFAService) GenerateTOTPQRCode(key *otp.Key) (string, error) {
	// Generate QR code image with the configured size
	img, err := key.Image(t.qrSize, t.qrSize)
	if err != nil {
		return "", err
	}

	// Encode as PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}

	// Convert to base64
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return "data:image/png;base64," + encoded, nil
}
