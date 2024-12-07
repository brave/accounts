package datastore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const hmacKeySize = 64

// JWTKey represents a JSON Web Token signing key stored in the database
type JWTKey struct {
	// ID is the unique identifier for the JWT key
	ID int
	// SecretKey contains the raw bytes of the signing key
	SecretKey []byte
	// PublicKey contains the raw bytes of the verification key
	PublicKey []byte
	// CreatedAt stores the timestamp when the key was created (read-only)
	CreatedAt time.Time `gorm:"<-:false"`
	// ECDSASecretKey is the decoded secret key, if public key crypto is being used
	ECDSASecretKey *ecdsa.PrivateKey `gorm:"-"`
	// ECDSAPublicKey is the decoded public key, if public key crypto is being used
	ECDSAPublicKey *ecdsa.PublicKey `gorm:"-"`
}

func encodeECDSAPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	// Marshal private key to DER format
	derKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return derKey, nil
}

func decodeECDSAPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	// Parse DER formatted private key
	key, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return key, nil
}

func encodeECDSAPublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	// Marshal public key to DER format
	derKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return derKey, nil
}

func decodeECDSAPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	// Parse DER formatted public key
	key, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Type assert to ecdsa.PublicKey
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ECDSA public key")
	}

	return ecKey, nil
}

func (d *Datastore) GetOrCreateJWTKeys(usePublicKeyCrypto bool, create bool) (map[int]*JWTKey, error) {
	var keys []JWTKey

	err := d.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("LOCK TABLE jwt_keys IN ACCESS EXCLUSIVE MODE").Error; err != nil {
			return fmt.Errorf("error acquiring table lock: %w", err)
		}

		if err := tx.Find(&keys).Error; err != nil {
			return fmt.Errorf("error fetching JWT keys: %w", err)
		}
		if len(keys) == 0 && create {
			var secretKey []byte
			var publicKey []byte
			if usePublicKeyCrypto {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return fmt.Errorf("failed to generate ES256 key: %w", err)
				}
				secretKey, err = encodeECDSAPrivateKey(key)
				if err != nil {
					return fmt.Errorf("failed to encode ES256 key: %w", err)
				}
				publicKey, err = encodeECDSAPublicKey(&key.PublicKey)
				if err != nil {
					return fmt.Errorf("failed to encode ES256 key: %w", err)
				}
			} else {
				secretKey = make([]byte, hmacKeySize)
				if _, err := rand.Read(secretKey); err != nil {
					panic(fmt.Errorf("failed to generate random jwt key: %w", err))
				}
			}

			newKey := JWTKey{
				SecretKey: secretKey,
				PublicKey: publicKey,
			}

			if err := tx.Create(&newKey).Error; err != nil {
				return fmt.Errorf("error creating JWT key: %w", err)
			}

			keys = append(keys, newKey)
			log.Info().Int("key_id", newKey.ID).Msg("created initial JWT key")
		}

		return nil
	})

	keyMap := make(map[int]*JWTKey)
	for _, key := range keys {
		if usePublicKeyCrypto {
			if key.SecretKey != nil {
				secretKey, err := decodeECDSAPrivateKey(key.SecretKey)
				if err != nil {
					return nil, fmt.Errorf("failed to decode secret key: %w", err)
				}
				key.ECDSASecretKey = secretKey
			}

			if key.PublicKey != nil {
				publicKey, err := decodeECDSAPublicKey(key.PublicKey)
				if err != nil {
					return nil, fmt.Errorf("failed to decode public key: %w", err)
				}
				key.ECDSAPublicKey = publicKey
			}
		}
		keyMap[key.ID] = &key
	}

	if err != nil {
		return nil, err
	}

	return keyMap, nil
}
