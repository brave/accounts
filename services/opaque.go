package services

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/bytemare/crypto"
	"github.com/bytemare/opaque"
	opaqueMsg "github.com/bytemare/opaque/message"
)

const (
	opaqueSecretKeyEnv = "OPAQUE_SECRET_KEY"
	opaquePublicKeyEnv = "OPAQUE_PUBLIC_KEY"
)

type OpaqueService struct {
	ds            *datastore.Datastore
	oprfSeeds     map[int][]byte
	currentSeedId int
	secretKey     []byte
	publicKey     []byte
	config        *opaque.Configuration
}

func NewOpaqueService(ds *datastore.Datastore) (*OpaqueService, error) {
	secretKeyHex := os.Getenv(opaqueSecretKeyEnv)
	if secretKeyHex == "" {
		return nil, fmt.Errorf("%s environment variable not set", opaqueSecretKeyEnv)
	}

	publicKeyHex := os.Getenv(opaquePublicKeyEnv)
	if publicKeyHex == "" {
		return nil, fmt.Errorf("%s environment variable not set", opaquePublicKeyEnv)
	}

	secretKey, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret key hex: %w", err)
	}

	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key hex: %w", err)
	}

	config := opaque.DefaultConfiguration()
	oprfSeeds, err := ds.GetOrCreateOPRFSeeds(config.GenerateOPRFSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create oprf seeds: %w", err)
	}

	currentSeedId := 0
	for k := range oprfSeeds {
		if k > currentSeedId {
			currentSeedId = k
		}
	}

	return &OpaqueService{ds, oprfSeeds, currentSeedId, secretKey, publicKey, config}, nil
}

func (o *OpaqueService) SetupPasswordInit(email string, request *opaqueMsg.RegistrationRequest) (*opaqueMsg.RegistrationResponse, error) {
	server, err := opaque.NewServer(o.config)
	if err != nil {
		return nil, fmt.Errorf("failed to init opaque server: %w", err)
	}

	publicKeyElement := o.NewElement()
	if err = publicKeyElement.UnmarshalBinary(o.publicKey); err != nil {
		return nil, fmt.Errorf("failed to decode public key during password init: %w", err)
	}

	seedID := o.currentSeedId

	if err = o.ds.UpsertRegistrationState(email, seedID); err != nil {
		return nil, err
	}

	return server.RegistrationResponse(request, publicKeyElement, []byte(email), o.oprfSeeds[seedID]), nil
}

func (o *OpaqueService) SetupPasswordFinalize(email string, registration *opaqueMsg.RegistrationRecord) (*datastore.Account, error) {
	seedID, err := o.ds.GetRegistrationStateSeedID(email)
	if err != nil {
		return nil, err
	}

	account, err := o.ds.GetOrCreateAccount(email)
	if err != nil {
		return nil, fmt.Errorf("failed to get account when setting password: %w", err)
	}

	if err := o.ds.DeleteAllSessions(account.ID); err != nil {
		return nil, err
	}

	err = o.ds.UpdateOpaqueRegistration(account.ID, seedID, registration.Serialize())
	if err != nil {
		return nil, err
	}

	return account, nil
}

func (o *OpaqueService) NewElement() *crypto.Element {
	return o.config.OPRF.Group().NewElement()
}
