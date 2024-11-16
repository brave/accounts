package datastore

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

type OPRFSeed struct {
	ID        int
	Seed      []byte
	CreatedAt time.Time `gorm:"<-:false"`
}

func (d *Datastore) GetOrCreateOPRFSeeds(seedGenerator func() []byte) (map[int][]byte, error) {
	var seeds []OPRFSeed

	err := d.DB.Transaction(func(tx *gorm.DB) error {
		// Acquire table lock at start of transaction
		// so we don't create more than one seed if multiple
		// replicas are operating.
		if err := tx.Exec("LOCK TABLE oprf_seeds IN ACCESS EXCLUSIVE MODE").Error; err != nil {
			return fmt.Errorf("error acquiring table lock: %w", err)
		}

		// Try to get all existing seeds
		if err := tx.Find(&seeds).Error; err != nil {
			return fmt.Errorf("error fetching OPRF seeds: %w", err)
		}

		// If no seeds exist, create first one
		if len(seeds) == 0 {
			newSeed := OPRFSeed{
				Seed: seedGenerator(),
			}

			if err := tx.Create(&newSeed).Error; err != nil {
				return fmt.Errorf("error creating OPRF seed: %w", err)
			}

			seeds = append(seeds, newSeed)
			log.Info().Int("seed_id", newSeed.ID).Msg("created initial OPRF seed")
		}

		return nil
	})

	seedMap := make(map[int][]byte)
	for _, seed := range seeds {
		seedMap[seed.ID] = seed.Seed
	}

	if err != nil {
		return nil, err
	}

	return seedMap, nil
}
