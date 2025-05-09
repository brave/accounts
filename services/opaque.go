package services

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/util"
	"github.com/bytemare/ecc"
	"github.com/bytemare/opaque"
	opaqueMsg "github.com/bytemare/opaque/message"
	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

const (
	opaqueSecretKeyEnv  = "OPAQUE_SECRET_KEY"
	opaquePublicKeyEnv  = "OPAQUE_PUBLIC_KEY"
	opaqueFakeRecordEnv = "OPAQUE_FAKE_RECORD"
)

var (
	ErrOPRFSeedNotAvailable = errors.New("OPRF seed not available")
)

type OpaqueService struct {
	ds                *datastore.Datastore
	oprfSeeds         map[int][]byte
	currentSeedID     *int
	secretKey         []byte
	publicKey         []byte
	Config            *opaque.Configuration
	fakeRecordEnabled bool
	keyServiceURL     string
	keyServiceSecret  string
	isKeyService      bool
}

func NewOpaqueService(ds *datastore.Datastore, isKeyService bool) (*OpaqueService, error) {
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

	keyServiceURL := os.Getenv(util.KeyServiceURLEnv)

	var oprfSeeds map[int][]byte
	var currentSeedID *int
	keyServiceSecret := os.Getenv(util.KeyServiceSecretEnv)
	if isKeyService || keyServiceURL == "" {
		// only create OPRF seeds if we're running the key service
		// or if a key service is not being used
		oprfSeeds, err = ds.GetOrCreateOPRFSeeds(config.GenerateOPRFSeed)
		if err != nil {
			return nil, fmt.Errorf("failed to get/create oprf seeds: %w", err)
		}
		currentSeedID = &[]int{0}[0]
		for k := range oprfSeeds {
			if k > *currentSeedID {
				currentSeedID = &k
			}
		}
	} else if keyServiceSecret == "" {
		return nil, fmt.Errorf("%v must be provided if using key service", util.KeyServiceSecretEnv)
	}

	fakeRecordEnabled := os.Getenv(opaqueFakeRecordEnv) == "true"

	return &OpaqueService{ds, oprfSeeds, currentSeedID, secretKey, publicKey, config, fakeRecordEnabled, keyServiceURL, keyServiceSecret, isKeyService}, nil
}

func (o *OpaqueService) DeriveOPRFClientSeed(credentialIdentifier string, oprfSeedID *int) ([]byte, int, error) {
	// If no seed ID provided, use current seed ID
	seedID := o.currentSeedID
	if oprfSeedID != nil {
		seedID = oprfSeedID
	}

	// Get OPRF seed for the specified ID
	seed, ok := o.oprfSeeds[*seedID]
	if !ok {
		return nil, *seedID, ErrOPRFSeedNotAvailable
	}

	h := hkdf.Expand(sha512.New, seed, []byte(credentialIdentifier))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(h, derivedKey); err != nil {
		return nil, *seedID, fmt.Errorf("failed to derive key: %w", err)
	}
	return derivedKey, *seedID, nil
}

func (o *OpaqueService) NewElement() *ecc.Element {
	return o.Config.OPRF.Group().NewElement()
}

func (o *OpaqueService) BinaryDeserializer() (*opaque.Deserializer, error) {
	return o.Config.Deserializer()
}

func (o *OpaqueService) getKeyServiceClientOPRFSeed(credIdentifier string, seedID *int) ([]byte, int, error) {
	type oprfSeedRequest struct {
		CredentialIdentifier string `json:"credentialIdentifier"`
		SeedID               *int   `json:"seedId"`
	}

	type oprfSeedResponse struct {
		ClientSeed string `json:"clientSeed"`
		SeedID     int    `json:"seedId"`
	}

	reqBody := oprfSeedRequest{
		CredentialIdentifier: credIdentifier,
		SeedID:               seedID,
	}

	var response oprfSeedResponse
	if err := util.MakeKeyServiceRequest(o.keyServiceURL, o.keyServiceSecret, "/v2/server_keys/oprf_seed", reqBody, &response); err != nil {
		return nil, 0, err
	}

	clientSeed, err := hex.DecodeString(response.ClientSeed)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decode key material: %w", err)
	}

	return clientSeed, response.SeedID, nil
}

func (o *OpaqueService) newOpaqueServer(credIdentifier string, seedID *int) (*opaque.Server, int, error) {
	if seedID == nil && o.currentSeedID != nil {
		seedID = o.currentSeedID
	}
	server, err := opaque.NewServer(o.Config)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to init opaque server: %w", err)
	}
	if !o.isKeyService && o.keyServiceURL != "" {
		clientSeed, serverSeedID, err := o.getKeyServiceClientOPRFSeed(credIdentifier, seedID)
		if err != nil {
			return nil, 0, err
		}
		if err = server.SetKeyMaterial(nil, o.secretKey, o.publicKey, nil, clientSeed); err != nil {
			return nil, 0, fmt.Errorf("failed to set key material for opaque server: %w", err)
		}
		seedID = &serverSeedID
	} else {
		if err = server.SetKeyMaterial(nil, o.secretKey, o.publicKey, o.oprfSeeds[*seedID], nil); err != nil {
			return nil, 0, fmt.Errorf("failed to set key material for opaque server: %w", err)
		}
	}
	return server, *seedID, nil
}

func (o *OpaqueService) SetupPasswordInit(email string, request *opaqueMsg.RegistrationRequest) (*opaqueMsg.RegistrationResponse, error) {
	server, seedID, err := o.newOpaqueServer(email, nil)
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

	return server.RegistrationResponse(request, []byte(email))
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
		if !errors.Is(err, datastore.ErrAccountNotFound) {
			return nil, nil, fmt.Errorf("failed to get account during login init: %w", err)
		}
	}

	if account == nil && !o.fakeRecordEnabled {
		return nil, nil, util.ErrIncorrectEmail
	}

	useFakeRecord := account == nil || account.OpaqueRegistration == nil || account.OprfSeedID == nil

	var seedID *int
	if !useFakeRecord {
		seedID = account.OprfSeedID
	}

	server, serverSeedID, err := o.newOpaqueServer(email, seedID)
	if err != nil {
		return nil, nil, err
	}
	seedID = &serverSeedID

	var opaqueRecord *opaque.ClientRecord
	if useFakeRecord {
		// Get fake record and continue with process to prevent
		// client enumeration attacks
		opaqueRecord, err = o.Config.GetFakeRecord([]byte(email))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get fake opaque registration: %w", err)
		}
	} else {
		deserializer, err := o.Config.Deserializer()
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

	ke2, err := server.GenerateKE2(ke1, opaqueRecord)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ke2: %w", err)
	}

	var accountID *uuid.UUID
	if !useFakeRecord {
		accountID = &account.ID
	}
	akeState, err := o.ds.CreateAKEState(accountID, email, server.SerializeState(), *seedID)
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

	server, _, err := o.newOpaqueServer(akeState.Email, &akeState.OprfSeedID)
	if err != nil {
		return nil, err
	}

	if err = server.SetAKEState(akeState.State); err != nil {
		return nil, fmt.Errorf("failed to set AKE state for login finalize: %w", err)
	}

	if err = server.LoginFinish(ke3); err != nil {
		if o.fakeRecordEnabled {
			return nil, util.ErrIncorrectCredentials
		} else {
			return nil, util.ErrIncorrectPassword
		}
	}

	if akeState.AccountID == nil {
		return nil, util.ErrIncorrectCredentials
	}

	return akeState.AccountID, nil
}
