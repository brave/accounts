package services

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/bytemare/crypto"
	"github.com/bytemare/opaque"
	opaqueMsg "github.com/bytemare/opaque/message"
	"github.com/google/uuid"
)

const (
	opaqueSecretKeyEnv  = "OPAQUE_SECRET_KEY"
	opaquePublicKeyEnv  = "OPAQUE_PUBLIC_KEY"
	opaqueFakeRecordEnv = "OPAQUE_FAKE_RECORD"
)

var ErrIncorrectCredentials = errors.New("incorrect credentials")

type OpaqueService struct {
	ds                *datastore.Datastore
	oprfSeeds         map[int][]byte
	currentSeedId     int
	secretKey         []byte
	publicKey         []byte
	config            *opaque.Configuration
	fakeRecordEnabled bool
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

	fakeRecordEnabled := os.Getenv(opaqueFakeRecordEnv) == "true"

	currentSeedId := 0
	for k := range oprfSeeds {
		if k > currentSeedId {
			currentSeedId = k
		}
	}

	return &OpaqueService{ds, oprfSeeds, currentSeedId, secretKey, publicKey, config, fakeRecordEnabled}, nil
}

func (o *OpaqueService) NewElement() *crypto.Element {
	return o.config.OPRF.Group().NewElement()
}

func (o *OpaqueService) newOpaqueServer(seedID int) (*opaque.Server, error) {
	server, err := opaque.NewServer(o.config)
	if err != nil {
		return nil, fmt.Errorf("failed to init opaque server: %w", err)
	}
	if err = server.SetKeyMaterial(nil, o.secretKey, o.publicKey, o.oprfSeeds[seedID]); err != nil {
		return nil, fmt.Errorf("failed to set key material for opaque server: %w", err)
	}
	return server, nil
}

func (o *OpaqueService) SetupPasswordInit(email string, request *opaqueMsg.RegistrationRequest) (*opaqueMsg.RegistrationResponse, error) {
	seedID := o.currentSeedId

	server, err := o.newOpaqueServer(seedID)
	if err != nil {
		return nil, err
	}

	publicKeyElement := o.NewElement()
	if err = publicKeyElement.UnmarshalBinary(o.publicKey); err != nil {
		return nil, fmt.Errorf("failed to decode public key during password init: %w", err)
	}

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

func (o *OpaqueService) LoginInit(email string, ke1 *opaqueMsg.KE1) (*opaqueMsg.KE2, *datastore.AKEState, error) {
	account, err := o.ds.GetAccount(nil, email)
	if err != nil {
		if errors.Is(err, datastore.ErrAccountNotFound) {
			err = nil
		} else {
			return nil, nil, fmt.Errorf("failed to get account during login init: %w", err)
		}
	}

	if account == nil && !o.fakeRecordEnabled {
		return nil, nil, ErrIncorrectCredentials
	}

	useFakeRecord := account == nil || account.OpaqueRegistration == nil || account.OprfSeedID == nil

	seedID := o.currentSeedId
	if !useFakeRecord {
		seedID = *account.OprfSeedID
	}

	server, err := o.newOpaqueServer(seedID)
	if err != nil {
		return nil, nil, err
	}

	var opaqueRecord *opaque.ClientRecord
	if useFakeRecord {
		// Get fake record and continue with process to prevent
		// client enumeration attacks
		opaqueRecord, err = o.config.GetFakeRecord([]byte(email))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get fake opaque registration: %w", err)
		}
	} else {
		deserializer, err := o.config.Deserializer()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get opaque deserializer: %w", err)
		}
		opaqueRegistration, err := deserializer.RegistrationRecord(account.OpaqueRegistration)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to deserialize opaque registration: %w", err)
		}
		opaqueRecord = &opaque.ClientRecord{
			RegistrationRecord:   opaqueRegistration,
			CredentialIdentifier: []byte(email),
			ClientIdentity:       []byte(email),
		}
	}

	ke2, err := server.LoginInit(ke1, opaqueRecord)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ke2: %w", err)
	}

	var accountID *uuid.UUID
	if !useFakeRecord {
		accountID = &account.ID
	}
	akeState, err := o.ds.CreateAKEState(accountID, server.SerializeState(), seedID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store AKE state: %w", err)
	}

	return ke2, akeState, nil
}

func (o *OpaqueService) LoginFinalize(akeStateID uuid.UUID, ke3 *opaqueMsg.KE3) (*uuid.UUID, error) {
	akeState, err := o.ds.GetAKEState(akeStateID)
	if err != nil {
		return nil, err
	}

	server, err := o.newOpaqueServer(akeState.OprfSeedID)
	if err != nil {
		return nil, err
	}

	if err = server.SetAKEState(akeState.State); err != nil {
		return nil, fmt.Errorf("failed to set AKE state for login finalize: %w", err)
	}

	if err = server.LoginFinish(ke3); err != nil {
		return nil, ErrIncorrectCredentials
	}

	if akeState.AccountID == nil {
		return nil, ErrIncorrectCredentials
	}

	return akeState.AccountID, nil
}
