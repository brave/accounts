package services

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	keyServiceClient  *util.KeyServiceClient
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

	var keyServiceClient *util.KeyServiceClient
	var oprfSeeds map[int][]byte
	var currentSeedID *int

	// Only create a client if we're not the key service and KEY_SERVICE_URL is set
	if !isKeyService && os.Getenv(util.KeyServiceURLEnv) != "" {
		keyServiceClient = util.NewKeyServiceClient()
	}

	if isKeyService || keyServiceClient == nil {
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
	}

	fakeRecordEnabled := os.Getenv(opaqueFakeRecordEnv) == "true"

	return &OpaqueService{
		ds:                ds,
		oprfSeeds:         oprfSeeds,
		currentSeedID:     currentSeedID,
		secretKey:         secretKey,
		publicKey:         publicKey,
		Config:            config,
		fakeRecordEnabled: fakeRecordEnabled,
		keyServiceClient:  keyServiceClient,
		isKeyService:      isKeyService,
	}, nil
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
	if err := o.keyServiceClient.MakeRequest(http.MethodPost, "/v2/server_keys/oprf_seed", reqBody, &response); err != nil {
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
	if o.keyServiceClient != nil {
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

	account, err := o.ds.GetOrCreateAccount(email)
	if err != nil {
		return nil, fmt.Errorf("failed to get account when setting password: %w", err)
	}

	if err = o.ds.CreateRegistrationState(account.ID, account.Email, seedID, account.TOTPEnabled, account.WebAuthnEnabled); err != nil {
		return nil, err
	}

	return server.RegistrationResponse(request, []byte(email))
}

func (o *OpaqueService) SetupPasswordFinalize(email string, registration *opaqueMsg.RegistrationRecord) (*datastore.InterimPasswordState, error) {
	registrationState, err := o.ds.GetRegistrationState(email, false)
	if err != nil {
		return nil, err
	}

	if registrationState.IsTwoFAEnabled() {
		if err = o.ds.UpdateInterimPasswordState(registrationState.ID, registration.Serialize()); err != nil {
			// nolint:errcheck
			o.ds.DeleteInterimPasswordState(registrationState.ID)
			return nil, err
		}
		if err = o.ds.MarkInterimPasswordStateAsAwaitingTwoFA(registrationState.ID); err != nil {
			// nolint:errcheck
			o.ds.DeleteInterimPasswordState(registrationState.ID)
			return nil, err
		}
	} else {
		err = o.ds.UpdateOpaqueRegistration(*registrationState.AccountID, registrationState.OprfSeedID, registration.Serialize())
		if err != nil {
			// nolint:errcheck
			o.ds.DeleteInterimPasswordState(registrationState.ID)
			return nil, err
		}
	}

	return registrationState, nil
}

func (o *OpaqueService) LoginInit(email string, ke1 *opaqueMsg.KE1) (*opaqueMsg.KE2, *datastore.InterimPasswordState, error) {
	account, err := o.ds.GetAccount(nil, email)
	if err != nil {
		if !errors.Is(err, datastore.ErrAccountNotFound) {
			return nil, nil, fmt.Errorf("failed to get account during login init: %w", err)
		}
	}

	if account == nil && !o.fakeRecordEnabled {
		return nil, nil, util.ErrIncorrectEmail
	}

	if account != nil && account.LastEmailVerifiedAt == nil {
		return nil, nil, util.ErrEmailNotVerified
	}

	email = util.CanonicalizeEmail(email)

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
	totpEnabled := false
	webAuthnEnabled := false
	if !useFakeRecord {
		accountID = &account.ID
		totpEnabled = account.TOTPEnabled
		webAuthnEnabled = account.WebAuthnEnabled
	}
	akeState, err := o.ds.CreateLoginState(accountID, email, server.SerializeState(), *seedID, totpEnabled, webAuthnEnabled)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store AKE state: %w", err)
	}

	return ke2, akeState, nil
}

func (o *OpaqueService) LoginFinalize(loginStateID uuid.UUID, ke3 *opaqueMsg.KE3) (*datastore.InterimPasswordState, error) {
	loginState, err := o.ds.GetLoginState(loginStateID, false)
	if err != nil {
		return nil, err
	}

	server, _, err := o.newOpaqueServer(loginState.Email, &loginState.OprfSeedID)
	if err != nil {
		// nolint:errcheck
		o.ds.DeleteInterimPasswordState(loginState.ID)
		return nil, err
	}

	if err = server.SetAKEState(loginState.State); err != nil {
		// nolint:errcheck
		o.ds.DeleteInterimPasswordState(loginState.ID)
		return nil, fmt.Errorf("failed to set AKE state for login finalize: %w", err)
	}

	if err = server.LoginFinish(ke3); err != nil {
		// nolint:errcheck
		o.ds.DeleteInterimPasswordState(loginState.ID)
		if o.fakeRecordEnabled {
			return nil, util.ErrIncorrectCredentials
		} else {
			return nil, util.ErrIncorrectPassword
		}
	}

	if loginState.AccountID == nil {
		// nolint:errcheck
		o.ds.DeleteInterimPasswordState(loginState.ID)
		return nil, util.ErrIncorrectCredentials
	}

	// If 2FA is required, mark the state as awaiting 2FA
	if loginState.IsTwoFAEnabled() {
		if err := o.ds.MarkInterimPasswordStateAsAwaitingTwoFA(loginState.ID); err != nil {
			// nolint:errcheck
			o.ds.DeleteInterimPasswordState(loginState.ID)
			return nil, fmt.Errorf("failed to mark login state as awaiting 2FA: %w", err)
		}
		loginState.AwaitingTwoFA = true
	}

	return loginState, nil
}
