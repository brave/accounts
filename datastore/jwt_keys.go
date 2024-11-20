package datastore

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const keySize = 64

// JWTKey represents a JSON Web Token signing key stored in the database
type JWTKey struct {
	// ID is the unique identifier for the JWT key
	ID int
	// Key contains the raw bytes of the signing key
	Key []byte
	// CreatedAt stores the timestamp when the key was created (read-only)
	CreatedAt time.Time `gorm:"<-:false"`
}

func (d *Datastore) GetOrCreateJWTKeys() (map[int][]byte, error) {
	var keys []JWTKey

	err := d.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("LOCK TABLE jwt_keys IN ACCESS EXCLUSIVE MODE").Error; err != nil {
			return fmt.Errorf("error acquiring table lock: %w", err)
		}

		if err := tx.Find(&keys).Error; err != nil {
			return fmt.Errorf("error fetching JWT keys: %w", err)
		}

		if len(keys) == 0 {
			key := make([]byte, keySize)
			if _, err := rand.Read(key); err != nil {
				panic(fmt.Errorf("failed to generate random jwt key: %w", err))
			}
			newKey := JWTKey{
				Key: key,
			}

			if err := tx.Create(&newKey).Error; err != nil {
				return fmt.Errorf("error creating JWT key: %w", err)
			}

			keys = append(keys, newKey)
			log.Info().Int("key_id", newKey.ID).Msg("created initial JWT key")
		}

		return nil
	})

	keyMap := make(map[int][]byte)
	for _, key := range keys {
		keyMap[key.ID] = key.Key
	}

	if err != nil {
		return nil, err
	}

	return keyMap, nil
}
