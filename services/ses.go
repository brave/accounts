package services

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	htmlTemplate "html/template"
	"os"
	"slices"
	"strconv"
	textTemplate "text/template"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/templates"
	"github.com/brave/accounts/util"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/rs/zerolog/log"
)

const (
	fromAddressEnv = "EMAIL_FROM_ADDRESS"
	awsEndpointEnv = "AWS_ENDPOINT"
	configSetEnv   = "SES_CONFIG_SET"
	sesRoleEnv     = "SES_ROLE"

	defaultFromAddress = "noreply@brave.com"
	expiresHeaderName  = "X-Expires-At"
)

var defaultEmailHeaders = []types.MessageHeader{
	{Name: aws.String("X-Auto-Response-Suppress"), Value: aws.String("All")}, // Suppress out-of-office auto-replies
}

type SESService struct {
	client              *sesv2.Client
	verifyHTMLTemplate  *htmlTemplate.Template
	verifyTextTemplate  *textTemplate.Template
	generalHTMLTemplate *htmlTemplate.Template
	generalTextTemplate *textTemplate.Template
	fromAddress         string
	configSet           string
	i18nBundle          *i18n.Bundle
}

type SES interface {
	SendVerificationEmail(ctx context.Context, email string, verification *datastore.Verification, locale string) error
	SendSimilarEmailAlert(ctx context.Context, email string, locale string) error
	SendPasswordChangeNotification(ctx context.Context, email string, locale string) error
}

type emailFields struct {
	Subject           string
	Greeting          string
	Disregard         string
	Signature         string
	Copyright         string
	AllRightsReserved string
	PrivacyPolicy     string
	TermsOfUse        string
	DownloadBrave     string
	ContactSupport    string
}

type verifyEmailFields struct {
	emailFields
	VerificationCode string
	Instructions     string
	CodeLabel        string
	ExpiryDisclaimer string
}

type similarEmailFields struct {
	emailFields
	Message string
}

func newEmailFields(localizer *i18n.Localizer, subjectMessageID string) (emailFields, string) {
	subject, tag, err := localizer.LocalizeWithTag(&i18n.LocalizeConfig{MessageID: subjectMessageID})
	if err != nil {
		panic(err)
	}
	return emailFields{
		Subject:           subject,
		Greeting:          localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailGreeting"}),
		Disregard:         localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailDisregard"}),
		Signature:         localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailSignature"}),
		Copyright:         localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailCopyright", TemplateData: map[string]string{"Year": strconv.Itoa(time.Now().Year())}}),
		AllRightsReserved: localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailAllRightsReserved"}),
		PrivacyPolicy:     localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailPrivacyPolicy"}),
		TermsOfUse:        localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailTermsOfUse"}),
		DownloadBrave:     localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailDownloadBrave"}),
		ContactSupport:    localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailContactSupport"}),
	}, tag.String()
}

func NewSESService(i18nBundle *i18n.Bundle, env string) (*SESService, error) {
	// Create AWS config
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	sesRole := os.Getenv(sesRoleEnv)
	if sesRole != "" {
		stsClient := sts.NewFromConfig(cfg)
		roleProvider := stscreds.NewAssumeRoleProvider(stsClient, sesRole)
		cfg, err = config.LoadDefaultConfig(context.Background(), config.WithCredentialsProvider(roleProvider))
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
	}

	// Create SES client
	client := sesv2.NewFromConfig(cfg, func(o *sesv2.Options) {
		awsEndpoint := os.Getenv(awsEndpointEnv)
		if awsEndpoint != "" {
			o.BaseEndpoint = &awsEndpoint
		}
	})

	verifyHtmlTmpl, err := htmlTemplate.New("verify_html").Parse(templates.VerifyHTMLTemplateContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}
	verifyTextTmpl, err := textTemplate.New("verify_text").Parse(templates.VerifyTextTemplateContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}
	generalHtmlTmpl, err := htmlTemplate.New("general_html").Parse(templates.GeneralEmailHTMLTemplateContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}
	generalTextTmpl, err := textTemplate.New("general_text").Parse(templates.GeneralEmailTextTemplateContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	fromAddress := os.Getenv(fromAddressEnv)
	if fromAddress == "" {
		fromAddress = defaultFromAddress
	}
	fromAddress = fmt.Sprintf("Brave Software <%v>", fromAddress)

	configSet := os.Getenv(configSetEnv)

	return &SESService{
		client,
		verifyHtmlTmpl,
		verifyTextTmpl,
		generalHtmlTmpl,
		generalTextTmpl,
		fromAddress,
		configSet,
		i18nBundle,
	}, nil
}

func (s *SESService) sendEmail(ctx context.Context, email string, locale string, subject string, contents interface{}, htmlTemplate *htmlTemplate.Template, textTemplate *textTemplate.Template) error {
	var htmlContent, textContent bytes.Buffer
	if err := htmlTemplate.Execute(&htmlContent, contents); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	if err := textTemplate.Execute(&textContent, contents); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	htmlContentString := htmlContent.String()
	textContentString := textContent.String()

	message := &types.Message{
		Body: &types.Body{
			Html: &types.Content{
				Data: &htmlContentString,
			},
			Text: &types.Content{
				Data: &textContentString,
			},
		},
		Subject: &types.Content{
			Data: &subject,
		},
	}

	message.Headers = append(slices.Clone(defaultEmailHeaders), types.MessageHeader{
		Name:  aws.String("Content-Language"),
		Value: aws.String(locale),
	})

	input := &sesv2.SendEmailInput{
		Content: &types.EmailContent{
			Simple: message,
		},
		Destination: &types.Destination{
			ToAddresses: []string{util.CanonicalizeEmail(email)},
		},
		FromEmailAddress: &s.fromAddress,
	}

	if s.configSet != "" {
		input.ConfigurationSetName = &s.configSet
	}

	_, err := s.client.SendEmail(ctx, input)
	if err != nil {
		var badReqErr *types.BadRequestException
		if errors.As(err, &badReqErr) {
			return util.ErrFailedToSendEmailInvalidFormat
		}
		return fmt.Errorf("failed to send email: %w", err)
	}
	return nil
}

func (s *SESService) SendVerificationEmail(ctx context.Context, email string, verification *datastore.Verification, locale string) error {
	localizer := i18n.NewLocalizer(s.i18nBundle, locale)

	var subjectMessageID string
	var instructionsMessageID string
	switch verification.Intent {
	case datastore.AuthTokenIntent:
		subjectMessageID = "LoginEmailSubject"
		instructionsMessageID = "LoginEmailInstructions"
	case datastore.VerificationIntent:
		subjectMessageID = "VerifyEmailSubject"
		instructionsMessageID = "VerifyEmailInstructions"
	case datastore.RegistrationIntent:
		subjectMessageID = "RegistrationEmailSubject"
		instructionsMessageID = "RegistrationEmailInstructions"
	case datastore.ResetPasswordIntent, datastore.ChangePasswordIntent:
		subjectMessageID = "SetPasswordEmailSubject"
		instructionsMessageID = "SetPasswordEmailInstructions"
	}

	fields, effectiveLocale := newEmailFields(localizer, subjectMessageID)
	data := verifyEmailFields{
		emailFields:      fields,
		VerificationCode: verification.Code,
		Instructions:     localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: instructionsMessageID}),
		CodeLabel:        localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailCode"}),
		ExpiryDisclaimer: localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailExpiryDisclaimer"}),
	}

	if err := s.sendEmail(ctx, email, effectiveLocale, data.Subject, &data, s.verifyHTMLTemplate, s.verifyTextTemplate); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Debug().Str("verification_code", verification.Code).Msg("Sent verification code")

	return nil
}

func (s *SESService) SendSimilarEmailAlert(ctx context.Context, email string, locale string) error {
	localizer := i18n.NewLocalizer(s.i18nBundle, locale)

	fields, effectiveLocale := newEmailFields(localizer, "SimilarEmailSubject")
	data := similarEmailFields{
		emailFields: fields,
		Message:     localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "SimilarEmailLoginMessage", TemplateData: map[string]string{"Email": email}}),
	}

	if err := s.sendEmail(ctx, email, effectiveLocale, data.Subject, &data, s.generalHTMLTemplate, s.generalTextTemplate); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (s *SESService) SendPasswordChangeNotification(ctx context.Context, email string, locale string) error {
	localizer := i18n.NewLocalizer(s.i18nBundle, locale)

	fields, effectiveLocale := newEmailFields(localizer, "PasswordChangeNotificationSubject")
	data := similarEmailFields{
		emailFields: fields,
		Message:     localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "PasswordChangeNotificationMessage"}),
	}

	if err := s.sendEmail(ctx, email, effectiveLocale, data.Subject, &data, s.generalHTMLTemplate, s.generalTextTemplate); err != nil {
		return fmt.Errorf("failed to send password change notification email: %w", err)
	}

	return nil
}
