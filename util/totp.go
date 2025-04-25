package util

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"os"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
)

const (
	TOTPIssuerEnv = "TOTP_ISSUER"
	TOTPQRSizeEnv = "TOTP_QR_SIZE"
	DefaultIssuer = "Brave"
	DefaultQRSize = 256
)

// TOTPUtil provides methods for generating and validating TOTP keys
type TOTPUtil struct {
	// Issuer is the name of the issuer for TOTP keys
	Issuer string
	// QRSize is the size in pixels for generated QR codes
	QRSize int
}

// NewTOTPUtil creates a new TOTPUtil instance with configuration from environment
func NewTOTPUtil() *TOTPUtil {
	issuer := os.Getenv(TOTPIssuerEnv)
	if issuer == "" {
		issuer = DefaultIssuer
	}

	qrSize := DefaultQRSize
	if sizeStr := os.Getenv(TOTPQRSizeEnv); sizeStr != "" {
		size, err := strconv.Atoi(sizeStr)
		if err != nil || size <= 0 {
			log.Panic().Err(err).Msgf("invalid TOTP QR size: %s", sizeStr)
		}
		qrSize = size
	}

	return &TOTPUtil{
		Issuer: issuer,
		QRSize: qrSize,
	}
}

// GenerateKey creates a new TOTP key with standard parameters
func (t *TOTPUtil) GenerateKey(email string) (*otp.Key, error) {
	// Generate TOTP key with standard parameters
	opts := totp.GenerateOpts{
		Issuer:      t.Issuer,
		AccountName: email,
	}

	return totp.Generate(opts)
}

// ValidateCode checks if the provided code is valid for the given TOTP key with a time window
func (t *TOTPUtil) ValidateCode(secret string, code string) bool {
	// Standard validation with one period of time drift in either direction
	opts := totp.ValidateOpts{
		Skew:   1,
		Digits: otp.DigitsSix,
	}
	valid, _ := totp.ValidateCustom(code, secret, time.Now().UTC(), opts)
	return valid
}

// GenerateQRCode generates a QR code image for a TOTP key and returns it as a base64 encoded PNG string
func (t *TOTPUtil) GenerateQRCode(key *otp.Key) (string, error) {
	// Generate QR code image with the configured size
	img, err := key.Image(t.QRSize, t.QRSize)
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
