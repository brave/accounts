package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/util"
)

type VerificationService struct {
	datastore           *datastore.Datastore
	jwtService          *JWTService
	sesService          SES
	passwordAuthEnabled bool
	emailAuthEnabled    bool
}

type VerificationResult struct {
	AuthToken *string
	Email     *string
	Service   string
}

func NewVerificationService(datastore *datastore.Datastore, jwtService *JWTService, sesService SES, passwordAuthEnabled bool, emailAuthEnabled bool) *VerificationService {
	return &VerificationService{
		datastore:           datastore,
		jwtService:          jwtService,
		sesService:          sesService,
		passwordAuthEnabled: passwordAuthEnabled,
		emailAuthEnabled:    emailAuthEnabled,
	}
}

func (vs *VerificationService) InitializeVerification(ctx context.Context, email, intent, service string, session *datastore.SessionWithAccountInfo) (*datastore.Verification, *string, error) {
	// Validate intent
	intentAllowed := true
	switch intent {
	case datastore.AuthTokenIntent:
		if !vs.emailAuthEnabled || service != util.EmailAliasesServiceName {
			intentAllowed = false
		}
	case datastore.VerificationIntent:
		// All services are allowed to verify email addresses
		intentAllowed = true
	case datastore.RegistrationIntent, datastore.ResetPasswordIntent:
		if !vs.passwordAuthEnabled || service != util.AccountsServiceName {
			intentAllowed = false
		}
	case datastore.ChangePasswordIntent:
		if !vs.passwordAuthEnabled || service != util.AccountsServiceName {
			intentAllowed = false
		}
		// A valid auth session is required because we allow the user to choose whether
		// they wish to invalidate all sessions. We do not want to present this option
		// for any other intent (i.e. password resets, where session invalidation is mandatory to reduce attack risk).
		if session == nil || session.Email != util.CanonicalizeEmail(email) {
			intentAllowed = false
		}
	default:
		intentAllowed = false
	}
	if !intentAllowed {
		return nil, nil, util.ErrIntentNotAllowed
	}

	// Validate email
	if !util.IsEmailAllowed(email, service) {
		return nil, nil, util.ErrEmailDomainNotSupported
	}

	// Validate account requirements
	if intent == datastore.RegistrationIntent || intent == datastore.ResetPasswordIntent || intent == datastore.ChangePasswordIntent {
		accountExists, err := vs.datastore.AccountExists(email)
		if err != nil {
			return nil, nil, err
		}
		if intent == datastore.RegistrationIntent && accountExists {
			return nil, nil, util.ErrAccountExists
		}
		if (intent == datastore.ResetPasswordIntent || intent == datastore.ChangePasswordIntent) && !accountExists {
			return nil, nil, util.ErrAccountDoesNotExist
		}
	}

	// Create verification
	verification, err := vs.datastore.CreateVerification(email, service, intent)
	if err != nil {
		return nil, nil, err
	}

	// Create verification token if needed
	token, err := vs.jwtService.CreateVerificationToken(verification.ID, datastore.VerificationExpiration, verification.Service)
	if err != nil {
		return nil, nil, err
	}

	return verification, &token, nil
}

func (vs *VerificationService) SendVerificationEmail(ctx context.Context, verification *datastore.Verification, locale string) error {
	// Send verification email
	if err := vs.sesService.SendVerificationEmail(ctx, verification.Email, verification, locale); err != nil {
		if errors.Is(err, util.ErrFailedToSendEmailInvalidFormat) {
			if vs.datastore.DeleteVerification(verification.ID) != nil {
				// Don't override the more descriptive error code and let cron handle the cleanup
				_ = true
			}
			return err
		}
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	return nil
}

func (vs *VerificationService) CompleteVerification(verification *datastore.Verification, code string, userAgent string) (*VerificationResult, error) {
	if verification.Verified {
		return nil, util.ErrEmailAlreadyVerified
	}

	if verification.CodeAttempts >= datastore.MaxCodeAttempts {
		return nil, util.ErrMaxCodeAttempts
	}

	if err := vs.datastore.IncrementVerificationCodeAttempts(verification.ID); err != nil {
		return nil, err
	}

	if strings.ToUpper(code) != verification.Code {
		return nil, util.ErrInvalidCode
	}

	result := VerificationResult{
		Service: verification.Service,
	}

	var err error
	var authToken *string
	var account *datastore.Account
	if verification.Intent == datastore.AuthTokenIntent || verification.Intent == datastore.RegistrationIntent {
		if err := vs.datastore.DeleteVerification(verification.ID); err != nil {
			return nil, err
		}

		account, err = vs.datastore.GetOrCreateAccount(verification.Email)
		if err != nil {
			return nil, err
		}

		sessionVersion := datastore.EmailAuthSessionVersion
		if verification.Intent == datastore.RegistrationIntent {
			sessionVersion = datastore.PasswordAuthSessionVersion
		}
		session, err := vs.datastore.CreateSession(account.ID, sessionVersion, userAgent)
		if err != nil {
			return nil, err
		}

		expirationDuration := ChildAuthTokenExpirationTime
		authTokenResult, err := vs.jwtService.CreateAuthToken(session.ID, &expirationDuration, verification.Service)
		if err != nil {
			return nil, err
		}
		authToken = &authTokenResult
	} else {
		if err := vs.datastore.MarkVerificationAsComplete(verification.ID); err != nil {
			return nil, err
		}

		account, err = vs.datastore.GetAccount(nil, verification.Email)
		if err != nil && err != datastore.ErrAccountNotFound {
			return nil, err
		}
	}

	if account != nil {
		if err = vs.datastore.UpdateAccountLastEmailVerifiedAt(account.ID); err != nil {
			return nil, err
		}
	}

	result.AuthToken = authToken
	result.Email = &verification.Email

	return &result, nil
}
