package services

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/util"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
)

const (
	twoFAIssuerEnv               = "TWOFA_ISSUER"
	totpQRSizeEnv                = "TOTP_QR_SIZE"
	webAuthnRPIDEnv              = "WEBAUTHN_RP_ID"
	webAuthnOriginsEnv           = "WEBAUTHN_ORIGINS"
	defaultIssuer                = "Brave Account"
	defaultQRSize                = 256
	webAuthnMediationRequirement = protocol.MediationDefault
)

var totpCodeRegex = regexp.MustCompile(`^\d{6}$`)

// TwoFAOptions represents the available two-factor authentication options
type TwoFAOptions struct {
	// Indicates if TOTP is enabled and available
	TOTPEnabled bool `json:"totpEnabled"`
	// WebAuthn challenge for authentication (if WebAuthn is enabled)
	WebAuthnRequest interface{} `json:"webAuthnRequest"`
}

// TwoFAAuthRequest represents a request to authenticate with 2FA
type TwoFAAuthRequest struct {
	// WebAuthn credential assertion response
	WebAuthnResponse *protocol.CredentialAssertionResponse `json:"webAuthnResponse,omitempty" validate:"required_without_all=TOTPCode RecoveryKey,excluded_with_all=TOTPCode RecoveryKey"`
	// TOTP verification code
	TOTPCode *string `json:"totpCode,omitempty" validate:"required_without_all=WebAuthnResponse RecoveryKey,excluded_with_all=WebAuthnResponse RecoveryKey"`
	// Recovery key for 2FA bypass
	RecoveryKey *string `json:"recoveryKey,omitempty" validate:"required_without_all=WebAuthnResponse TOTPCode,excluded_with_all=WebAuthnResponse TOTPCode"`
	// Whether to invalidate existing sessions (only applicable when changing password)
	InvalidateSessions bool `json:"invalidateSessions"`
}

// TwoFAService provides methods for managing two-factor authentication
type TwoFAService struct {
	// issuer is the name of the issuer for TOTP keys
	issuer string
	// qrSize is the size in pixels for generated QR codes
	qrSize int
	// ds is the datastore instance for persistent storage
	ds *datastore.Datastore
	// keyServiceClient is the client used to communicate with the key service
	keyServiceClient *util.KeyServiceClient
	// isKeyService indicates whether this instance is the key service
	isKeyService bool
	// webAuthn is the WebAuthn instance for credential operations
	webAuthn *webauthn.WebAuthn
}

// GetWebAuthnRPID returns the WebAuthn Relying Party ID from environment or derives it from BASE_URL
func GetWebAuthnRPID() string {
	if envRPID := os.Getenv(webAuthnRPIDEnv); envRPID != "" {
		return envRPID
	}

	baseURL := util.GetBaseURL()
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		log.Panic().Err(err).Msg("failed to parse base URL for WebAuthn RP ID")
	}
	hostname := parsedURL.Hostname()
	if hostname == "" {
		log.Panic().Msg("no hostname found in base URL for WebAuthn RP ID")
	}
	return hostname
}

// GetWebAuthnOrigins returns the WebAuthn origins from environment or defaults to BASE_URL
func GetWebAuthnOrigins() []string {
	if originsStr := os.Getenv(webAuthnOriginsEnv); originsStr != "" {
		return strings.Split(strings.TrimSpace(originsStr), ",")
	}
	return []string{util.GetBaseURL()}
}

// NewTwoFAService creates a new TwoFAService instance with configuration from environment
func NewTwoFAService(ds *datastore.Datastore, isKeyService bool) *TwoFAService {
	issuer := os.Getenv(twoFAIssuerEnv)
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

	// Create a client if we're not the key service and KEY_SERVICE_URL is set
	var client *util.KeyServiceClient
	if !isKeyService && os.Getenv(util.KeyServiceURLEnv) != "" {
		client = util.NewKeyServiceClient()
	}

	rpID := GetWebAuthnRPID()
	origins := GetWebAuthnOrigins()

	webAuthnConfig := &webauthn.Config{
		RPDisplayName: issuer,
		RPID:          rpID,
		RPOrigins:     origins,
	}

	wa, err := webauthn.New(webAuthnConfig)
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize WebAuthn")
	}

	return &TwoFAService{
		issuer:           issuer,
		qrSize:           qrSize,
		ds:               ds,
		keyServiceClient: client,
		isKeyService:     isKeyService,
		webAuthn:         wa,
	}
}

// DisableTwoFA disables two-factor authentication for an account
func (t *TwoFAService) DisableTwoFA(accountID uuid.UUID) error {
	// Disable TOTP
	if err := t.ds.SetTOTPSetting(accountID, false); err != nil {
		return err
	}

	if err := t.DeleteTOTPKey(accountID); err != nil {
		return err
	}

	// Disable WebAuthn
	if err := t.ds.SetWebAuthnSetting(accountID, false); err != nil {
		return err
	}

	if err := t.ds.DeleteAllWebAuthnCredentials(accountID); err != nil {
		return err
	}

	// Delete recovery key
	if err := t.ds.SetRecoveryKey(accountID, nil); err != nil {
		return err
	}

	return nil
}

// PrepareChallenge prepares 2FA options based on the password state
func (t *TwoFAService) PrepareChallenge(state *datastore.InterimPasswordState) (*TwoFAOptions, error) {
	options := &TwoFAOptions{
		TOTPEnabled: state.TOTPEnabled,
	}

	if state.WebAuthnEnabled {
		challenge, err := t.CreateWebAuthnLoginChallenge(state)
		if err != nil {
			return nil, err
		}
		options.WebAuthnRequest = challenge
	}

	return options, nil
}

// ProcessChallenge verifies either WebAuthn response, TOTP code, or recovery key for an account
func (t *TwoFAService) ProcessChallenge(loginState *datastore.InterimPasswordState, req *TwoFAAuthRequest) error {
	if req.WebAuthnResponse != nil {
		// Verify WebAuthn credential
		_, err := t.VerifyWebAuthnCredential(loginState, req.WebAuthnResponse)
		if err != nil {
			return err
		}
	} else if req.TOTPCode != nil {
		// Verify TOTP code
		if err := t.ValidateTOTPCode(*loginState.AccountID, *req.TOTPCode); err != nil {
			return err
		}
	} else if req.RecoveryKey != nil {
		// Verify recovery key
		if err := t.ds.CheckRecoveryKey(*loginState.AccountID, *req.RecoveryKey); err != nil {
			return err
		}
		if err := t.DisableTwoFA(*loginState.AccountID); err != nil {
			return err
		}
	}

	if err := t.ds.DeleteInterimPasswordState(loginState.ID); err != nil {
		return err
	}

	return nil
}

// GenerateAndStoreTOTPKey creates and stores a new TOTP key for an account
func (t *TwoFAService) GenerateAndStoreTOTPKey(accountID uuid.UUID, email string) (*otp.Key, error) {
	if t.keyServiceClient != nil {
		return t.makeKeyServiceTOTPGenerateRequest(accountID, email)
	}

	// Otherwise, generate and store the key locally
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

// makeKeyServiceTOTPGenerateRequest sends a request to the key service to generate and store a TOTP key
func (t *TwoFAService) makeKeyServiceTOTPGenerateRequest(accountID uuid.UUID, email string) (*otp.Key, error) {
	type totpGenerateRequest struct {
		AccountID uuid.UUID `json:"accountId"`
		Email     string    `json:"email"`
	}

	type totpGenerateResponse struct {
		URI string `json:"uri"`
	}

	reqBody := totpGenerateRequest{
		AccountID: accountID,
		Email:     email,
	}

	var response totpGenerateResponse
	if err := t.keyServiceClient.MakeRequest(http.MethodPost, "/v2/server_keys/totp", reqBody, &response); err != nil {
		return nil, err
	}

	// Parse the URI to create an OTP key
	key, err := otp.NewKeyFromURL(response.URI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TOTP key URI: %w", err)
	}

	return key, nil
}

// ValidateTOTPCode checks if the provided code is valid for the specified account
func (t *TwoFAService) ValidateTOTPCode(accountID uuid.UUID, code string) error {
	if t.keyServiceClient != nil {
		if err := t.makeKeyServiceValidateRequest(accountID, code); err != nil {
			return err
		}
	} else {
		if !totpCodeRegex.MatchString(code) {
			return util.ErrBadTOTPCode
		}

		// Otherwise, validate the code locally
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
	}

	if !t.isKeyService {
		// Check if code was already used and store it if not
		if err := t.ds.CheckAndStoreTOTPCodeUsed(accountID, code); err != nil {
			return err
		}
	}

	return nil
}

// makeKeyServiceValidateRequest sends a request to the key service to validate a TOTP code
func (t *TwoFAService) makeKeyServiceValidateRequest(accountID uuid.UUID, code string) error {
	type totpValidateRequest struct {
		AccountID uuid.UUID `json:"accountId"`
		Code      string    `json:"code"`
	}

	reqBody := totpValidateRequest{
		AccountID: accountID,
		Code:      code,
	}

	var response struct{}
	return t.keyServiceClient.MakeRequest(http.MethodPost, "/v2/server_keys/totp/validate", reqBody, &response)
}

// DeleteTOTPKey deletes a TOTP key for an account
func (t *TwoFAService) DeleteTOTPKey(accountID uuid.UUID) error {
	if t.keyServiceClient != nil {
		return t.makeKeyServiceDeleteRequest(accountID)
	}

	// Otherwise, delete the key locally
	return t.ds.DeleteTOTPKey(accountID)
}

// makeKeyServiceDeleteRequest sends a request to the key service to delete a TOTP key
func (t *TwoFAService) makeKeyServiceDeleteRequest(accountID uuid.UUID) error {
	return t.keyServiceClient.MakeRequest(
		http.MethodDelete,
		fmt.Sprintf("/v2/server_keys/totp/%s", accountID.String()),
		nil,
		nil)
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

// GenerateAndStoreRecoveryKey generates a 32-character recovery key
// and stores its hash in the database for the specified account
func (t *TwoFAService) GenerateAndStoreRecoveryKey(accountID uuid.UUID) (string, error) {
	const keyLength = 32                 // each base32 character encodes 5 bits
	const randLength = keyLength * 5 / 8 // 32 chars * 5 bits/char / 8 bits/byte = 20 bytes

	// Generate random bytes
	buffer := make([]byte, randLength)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode as base32
	recoveryKey := strings.ToUpper(base32.StdEncoding.EncodeToString(buffer)[:keyLength])

	// Store the recovery key hash
	if err := t.ds.SetRecoveryKey(accountID, &recoveryKey); err != nil {
		return "", fmt.Errorf("failed to store recovery key: %w", err)
	}

	return recoveryKey, nil
}

// webAuthnUser implements the webauthn.User interface for WebAuthn operations
type webAuthnUser struct {
	id          []byte
	email       string
	credentials []webauthn.Credential
}

func newWebAuthnUser(ds *datastore.Datastore, accountID uuid.UUID, email string) (*webAuthnUser, error) {
	webauthnID, err := ds.GetOrCreateWebAuthnID(accountID)
	if err != nil {
		return nil, err
	}

	dbCredentials, err := ds.GetWebAuthnCredentials(accountID)
	if err != nil {
		return nil, err
	}

	credentials := make([]webauthn.Credential, len(dbCredentials))
	for i, dbCred := range dbCredentials {
		credentials[i] = *dbCred.Credential
	}

	return &webAuthnUser{
		id:          webauthnID,
		email:       email,
		credentials: credentials,
	}, nil
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return u.id
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.email
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	return u.email
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// CreateWebAuthnRegistrationChallenge creates a new WebAuthn registration challenge
func (t *TwoFAService) CreateWebAuthnRegistrationChallenge(accountID uuid.UUID, email string) (*protocol.CredentialCreation, uuid.UUID, error) {
	user, err := newWebAuthnUser(t.ds, accountID, email)
	if err != nil {
		return nil, uuid.Nil, err
	}

	opts := []webauthn.RegistrationOption{
		webauthn.WithExclusions(webauthn.Credentials(user.credentials).CredentialDescriptors()),
		webauthn.WithExtensions(map[string]any{"credProps": true}),
	}

	creation, session, err := t.webAuthn.BeginMediatedRegistration(user, webAuthnMediationRequirement, opts...)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("failed to begin registration: %w", err)
	}

	// Store the session data
	registrationID, err := t.ds.CreateInterimWebAuthnState(accountID, session)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("failed to store registration state: %w", err)
	}

	return creation, registrationID, nil
}

// FinalizeWebAuthnCredentialRegistration completes the WebAuthn registration process
func (t *TwoFAService) FinalizeWebAuthnCredentialRegistration(accountID uuid.UUID, email string, registrationID uuid.UUID, credentialName string, response *protocol.CredentialCreationResponse) (*webauthn.Credential, error) {
	// Load the session data
	state, err := t.ds.GetAndDeleteInterimWebAuthnState(accountID, registrationID)
	if err != nil {
		return nil, fmt.Errorf("failed to load registration state: %w", err)
	}

	user, err := newWebAuthnUser(t.ds, accountID, email)
	if err != nil {
		return nil, err
	}

	// Parse the credential creation response
	parsedResponse, err := response.Parse()
	if err != nil {
		return nil, util.ErrBadWebAuthnResponse
	}

	credential, err := t.webAuthn.CreateCredential(user, *state.SessionData, parsedResponse)
	if err != nil {
		return nil, util.ErrBadWebAuthnResponse
	}

	// Save the credential
	if err := t.ds.SaveWebAuthnCredential(accountID, credential, &credentialName); err != nil {
		return nil, fmt.Errorf("failed to save credential: %w", err)
	}

	return credential, nil
}

// CreateWebAuthnLoginChallenge creates a new WebAuthn login challenge for multi-factor authentication
func (t *TwoFAService) CreateWebAuthnLoginChallenge(state *datastore.InterimPasswordState) (*protocol.CredentialAssertion, error) {
	user, err := newWebAuthnUser(t.ds, *state.AccountID, state.Email)
	if err != nil {
		return nil, err
	}

	assertion, session, err := t.webAuthn.BeginMediatedLogin(user, webAuthnMediationRequirement)
	if err != nil {
		return nil, fmt.Errorf("failed to begin login: %w", err)
	}

	// Store the session data in the interim password state
	if err := t.ds.SetInterimPasswordStateWebAuthnChallenge(state.ID, session); err != nil {
		return nil, fmt.Errorf("failed to store webauthn challenge: %w", err)
	}

	return assertion, nil
}

// VerifyWebAuthnCredential verifies a WebAuthn credential challenge response
func (t *TwoFAService) VerifyWebAuthnCredential(state *datastore.InterimPasswordState, response *protocol.CredentialAssertionResponse) (*webauthn.Credential, error) {
	user, err := newWebAuthnUser(t.ds, *state.AccountID, state.Email)
	if err != nil {
		return nil, err
	}

	// Parse the credential assertion response
	parsedResponse, err := response.Parse()
	if err != nil {
		return nil, util.ErrBadWebAuthnResponse
	}

	validatedCredential, err := t.webAuthn.ValidateLogin(user, *state.WebAuthnChallenge, parsedResponse)
	if err != nil {
		return nil, util.ErrBadWebAuthnResponse
	}

	if err := t.ds.SaveWebAuthnCredential(*state.AccountID, validatedCredential, nil); err != nil {
		return nil, fmt.Errorf("failed to update credential: %w", err)
	}

	return validatedCredential, nil
}
