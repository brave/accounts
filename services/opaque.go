package services

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/util"
	"github.com/bytemare/ecc"
	"github.com/bytemare/hash"
	"github.com/bytemare/opaque"
	opaqueMsg "github.com/bytemare/opaque/message"
	"github.com/google/uuid"
)

const (
	opaqueSecretKeyEnv  = "OPAQUE_SECRET_KEY"
	opaquePublicKeyEnv  = "OPAQUE_PUBLIC_KEY"
	opaqueFakeRecordEnv = "OPAQUE_FAKE_RECORD"
	// seedLength is the default length in bytes used for seeds (internal.SeedLength from opaque)
	seedLength = 32
	// deriveKeyPairTag is the OPRF hash-to-scalar dst (tag.DeriveKeyPair from opaque)
	deriveKeyPairTag = "OPAQUE-DeriveKeyPair"
	// expandOPRFTag is the tag for KDF expand (tag.ExpandOPRF from opaque)
	expandOPRFTag = "OprfKey"
)

var (
	ErrOPRFSeedNotAvailable = errors.New("OPRF seed not available")
)

type OpaqueService struct {
	ds                *datastore.Datastore
	oprfSeeds         map[int][]byte
	currentSeedID     *int
	Config            *opaque.Configuration
	fakeRecordEnabled bool
	keyServiceClient  *util.KeyServiceClient
	server            *opaque.Server
}

func newOpaqueServer(config *opaque.Configuration, oprfSeeds map[int][]byte, currentSeedID *int) (*opaque.Server, error) {
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

	secretKeyScalar, err := opaque.DeserializeScalar(config.AKE.Group(), secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize secret key: %w", err)
	}

	server, err := opaque.NewServer(config)
	if err != nil {
		return nil, fmt.Errorf("failed to init opaque server: %w", err)
	}

	// globalSeed will end up being nil if a key service is present,
	// since the "frontend" web service does not have access to global seeds.
	var globalSeed []byte
	if currentSeedID != nil {
		globalSeed = oprfSeeds[*currentSeedID]
	}

	serverKeyMaterial := &opaque.ServerKeyMaterial{
		PrivateKey:     secretKeyScalar,
		PublicKeyBytes: publicKey,
		OPRFGlobalSeed: globalSeed,
	}

	if err := server.SetKeyMaterial(serverKeyMaterial); err != nil {
		return nil, fmt.Errorf("failed to set key material: %w", err)
	}

	return server, nil
}

func NewOpaqueService(ds *datastore.Datastore, isKeyService bool) (*OpaqueService, error) {
	config := opaque.DefaultConfiguration()

	var keyServiceClient *util.KeyServiceClient
	var oprfSeeds map[int][]byte
	var currentSeedID *int
	var server *opaque.Server
	var err error

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

	if !isKeyService {
		server, err = newOpaqueServer(config, oprfSeeds, currentSeedID)
		if err != nil {
			return nil, err
		}
	}

	fakeRecordEnabled := os.Getenv(opaqueFakeRecordEnv) == "true"

	return &OpaqueService{
		ds:                ds,
		oprfSeeds:         oprfSeeds,
		currentSeedID:     currentSeedID,
		Config:            config,
		fakeRecordEnabled: fakeRecordEnabled,
		keyServiceClient:  keyServiceClient,
		server:            server,
	}, nil
}

func (o *OpaqueService) DeriveOPRFClientKey(credentialIdentifier string, oprfSeedID *int) (*ecc.Scalar, int, error) {
	if credentialIdentifier == "" {
		return nil, 0, errors.New("credentialIdentifier cannot be empty")
	}

	// If no seed ID provided, use current seed ID
	seedID := o.currentSeedID
	if oprfSeedID != nil {
		seedID = oprfSeedID
	}

	// Get OPRF seed for the specified ID
	globalSeed, ok := o.oprfSeeds[*seedID]
	if !ok {
		return nil, *seedID, ErrOPRFSeedNotAvailable
	}

	// Derive client-specific OPRF key using KDF.Expand and OPRF.DeriveKey
	// This matches the logic in opaque/server.go deriveOPRFKey
	kdf := hash.FromCrypto(o.Config.KDF).GetHashFunction()
	info := append([]byte(credentialIdentifier), []byte(expandOPRFTag)...)
	seed := kdf.HKDFExpand(globalSeed, info, seedLength)
	clientKey := o.Config.OPRF.OPRF().DeriveKey(seed, []byte(deriveKeyPairTag))

	return clientKey, *seedID, nil
}

func (o *OpaqueService) NewElement() *ecc.Element {
	return o.Config.OPRF.Group().NewElement()
}

func (o *OpaqueService) BinaryDeserializer() (*opaque.Deserializer, error) {
	return o.Config.Deserializer()
}

func (o *OpaqueService) getKeyServiceClientOPRFKey(credIdentifier string, seedID *int, clientAddr string) (*ecc.Scalar, int, error) {
	type oprfKeyRequest struct {
		CredentialIdentifier string `json:"credentialIdentifier"`
		SeedID               *int   `json:"seedId"`
		IP                   string `json:"ip"`
	}

	type oprfKeyResponse struct {
		ClientKey string `json:"clientKey"`
		SeedID    int    `json:"seedId"`
	}

	// Extract IP from addr (remove port if present)
	ip, _, err := net.SplitHostPort(clientAddr)
	if err != nil {
		// If no port, use the addr as-is
		ip = clientAddr
	}

	reqBody := oprfKeyRequest{
		CredentialIdentifier: credIdentifier,
		SeedID:               seedID,
		IP:                   ip,
	}

	var response oprfKeyResponse
	if err := o.keyServiceClient.MakeRequest(http.MethodPost, "/v2/server_keys/oprf_seed", reqBody, &response); err != nil {
		return nil, 0, err
	}

	clientKeyBytes, err := hex.DecodeString(response.ClientKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decode key material: %w", err)
	}

	clientKey, err := opaque.DeserializeScalar(o.Config.OPRF.Group(), clientKeyBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to deserialize client OPRF key: %w", err)
	}

	return clientKey, response.SeedID, nil
}

func (o *OpaqueService) getOPRFKeyAndSeedID(credIdentifier string, storedSeedID *int, clientAddr string) (*ecc.Scalar, int, error) {
	// storedSeedID will be nil if setting a new password, use the latest seed for the exchange.
	// If a key service is utilized, the latest seed will not be available, since the "frontend" web service does not
	// have access to seeds. The key service will return the latest seed ID when the client-specific OPRF
	// key is derived.
	if storedSeedID == nil && o.currentSeedID != nil {
		storedSeedID = o.currentSeedID
	}

	var clientOPRFKey *ecc.Scalar
	var err error
	var seedID int

	if o.keyServiceClient != nil {
		clientOPRFKey, seedID, err = o.getKeyServiceClientOPRFKey(credIdentifier, storedSeedID, clientAddr)
		if err != nil {
			return nil, 0, err
		}
	} else {
		clientOPRFKey, _, err = o.DeriveOPRFClientKey(credIdentifier, storedSeedID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to derive client OPRF key: %w", err)
		}
		seedID = *storedSeedID
	}

	return clientOPRFKey, seedID, nil
}

func (o *OpaqueService) SetupPasswordInit(email string, request *opaqueMsg.RegistrationRequest, clientAddr string) (*opaqueMsg.RegistrationResponse, error) {
	clientOPRFKey, seedID, err := o.getOPRFKeyAndSeedID(email, nil, clientAddr)
	if err != nil {
		return nil, err
	}

	account, err := o.ds.GetOrCreateAccount(email)
	if err != nil {
		return nil, fmt.Errorf("failed to get account when setting password: %w", err)
	}

	if err = o.ds.CreateRegistrationState(account.ID, account.Email, seedID, account.IsTwoFAEnabled()); err != nil {
		return nil, err
	}

	response, err := o.server.RegistrationResponse(request, []byte(email), clientOPRFKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate registration response: %w", err)
	}

	return response, nil
}

func (o *OpaqueService) SetupPasswordFinalize(email string, registration *opaqueMsg.RegistrationRecord) (*datastore.InterimPasswordState, error) {
	registrationState, err := o.ds.GetRegistrationState(email, false)
	if err != nil {
		return nil, err
	}

	if registrationState.RequiresTwoFA {
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

func (o *OpaqueService) LoginInit(email string, ke1 *opaqueMsg.KE1, clientAddr string) (*opaqueMsg.KE2, *datastore.InterimPasswordState, error) {
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

	clientOPRFKey, serverSeedID, err := o.getOPRFKeyAndSeedID(email, seedID, clientAddr)
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

	serverOpts := &opaque.ServerOptions{
		ClientOPRFKey: clientOPRFKey,
	}

	ke2, serverOutput, err := o.server.GenerateKE2(ke1, opaqueRecord, serverOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ke2: %w", err)
	}

	var accountID *uuid.UUID
	isTwoFAEnabled := false
	if !useFakeRecord {
		accountID = &account.ID
		isTwoFAEnabled = account.IsTwoFAEnabled()
	}

	akeState, err := o.ds.CreateLoginState(accountID, email, serverOutput.ClientMAC, *seedID, isTwoFAEnabled)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store AKE state: %w", err)
	}

	return ke2, akeState, nil
}

func (o *OpaqueService) LoginFinalize(loginStateID uuid.UUID, ke3 *opaqueMsg.KE3, clientAddr string) (*datastore.InterimPasswordState, error) {
	loginState, err := o.ds.GetLoginState(loginStateID, false)
	if err != nil {
		return nil, err
	}

	if err = o.server.LoginFinish(ke3, loginState.State); err != nil {
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
	if loginState.RequiresTwoFA {
		if err := o.ds.MarkInterimPasswordStateAsAwaitingTwoFA(loginState.ID); err != nil {
			// nolint:errcheck
			o.ds.DeleteInterimPasswordState(loginState.ID)
			return nil, fmt.Errorf("failed to mark login state as awaiting 2FA: %w", err)
		}
		loginState.AwaitingTwoFA = true
	}

	return loginState, nil
}
