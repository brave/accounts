package services

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	htmlTemplate "html/template"
	"os"
	"strconv"
	textTemplate "text/template"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/templates"
	"github.com/brave/accounts/util"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/rs/zerolog/log"
)

const (
	fromAddressEnv       = "EMAIL_FROM_ADDRESS"
	baseURLEnv           = "BASE_URL"
	verifyFrontendURLEnv = "VERIFY_FRONTEND_URL"
	awsEndpointEnv       = "AWS_ENDPOINT"
	configSetEnv         = "SES_CONFIG_SET"
	sesRoleEnv           = "SES_ROLE"

	defaultFromAddress = "noreply@brave.com"
	defaultBaseURL     = "http://localhost:8080"
)

type SESService struct {
	client              *ses.Client
	verifyHTMLTemplate  *htmlTemplate.Template
	verifyTextTemplate  *textTemplate.Template
	generalHTMLTemplate *htmlTemplate.Template
	generalTextTemplate *textTemplate.Template
	fromAddress         string
	baseURL             string
	frontendURL         string
	configSet           string
	i18nBundle          *i18n.Bundle
}

type SES interface {
	SendVerificationEmail(ctx context.Context, email string, verification *datastore.Verification, locale string) error
	SendSimilarEmailAlert(ctx context.Context, email string, locale string) error
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
	VerifyURL          string
	Instructions       string
	Action             string
	VerifyActionBackup string
	ExpiryDisclaimer   string
}

type similarEmailFields struct {
	emailFields
	Message string
}

func newEmailFields(localizer *i18n.Localizer, subjectMessageID string) emailFields {
	return emailFields{
		Subject:           localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: subjectMessageID}),
		Greeting:          localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailGreeting"}),
		Disregard:         localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailDisregard"}),
		Signature:         localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailSignature"}),
		Copyright:         localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailCopyright", TemplateData: map[string]string{"Year": strconv.Itoa(time.Now().Year())}}),
		AllRightsReserved: localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailAllRightsReserved"}),
		PrivacyPolicy:     localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailPrivacyPolicy"}),
		TermsOfUse:        localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailTermsOfUse"}),
		DownloadBrave:     localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailDownloadBrave"}),
		ContactSupport:    localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailContactSupport"}),
	}
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
	client := ses.NewFromConfig(cfg, func(o *ses.Options) {
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

	baseURL := os.Getenv(baseURLEnv)
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	configSet := os.Getenv(configSetEnv)

	frontendURL := os.Getenv(verifyFrontendURLEnv)
	if frontendURL == "" && env == util.ProductionEnv {
		return nil, fmt.Errorf("%s env var must be specified in production", verifyFrontendURLEnv)
	}

	return &SESService{
		client,
		verifyHtmlTmpl,
		verifyTextTmpl,
		generalHtmlTmpl,
		generalTextTmpl,
		fromAddress,
		baseURL,
		frontendURL,
		configSet,
		i18nBundle,
	}, nil
}

func (s *SESService) sendEmail(ctx context.Context, email string, subject string, contents interface{}, htmlTemplate *htmlTemplate.Template, textTemplate *textTemplate.Template) error {
	var htmlContent, textContent bytes.Buffer
	if err := htmlTemplate.Execute(&htmlContent, contents); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	if err := textTemplate.Execute(&textContent, contents); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	htmlContentString := htmlContent.String()
	textContentString := textContent.String()

	input := &ses.SendEmailInput{
		Destination: &types.Destination{
			ToAddresses: []string{email},
		},
		Message: &types.Message{
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
		},
		Source: &s.fromAddress,
	}
	if s.configSet != "" {
		input.ConfigurationSetName = &s.configSet
	}

	_, err := s.client.SendEmail(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	return nil
}

func (s *SESService) SendVerificationEmail(ctx context.Context, email string, verification *datastore.Verification, locale string) error {
	frontendURL := s.frontendURL
	if frontendURL == "" {
		frontendURL = s.baseURL + "/v2/verify/complete_fe"
	}
	verifyURL := fmt.Sprintf("%s?id=%s&code=%s", frontendURL, verification.ID.String(), verification.Code)

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
	case datastore.SetPasswordIntent:
		subjectMessageID = "SetPasswordEmailSubject"
		instructionsMessageID = "SetPasswordEmailInstructions"
	}

	data := verifyEmailFields{
		emailFields:        newEmailFields(localizer, subjectMessageID),
		VerifyURL:          verifyURL,
		Instructions:       localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: instructionsMessageID}),
		Action:             localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailAction"}),
		VerifyActionBackup: localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailActionBackup"}),
		ExpiryDisclaimer:   localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailExpiryDisclaimer"}),
	}

	if err := s.sendEmail(ctx, email, data.Subject, &data, s.verifyHTMLTemplate, s.verifyTextTemplate); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Debug().Str("verify_url", verifyURL).Msg("Sent verification link")

	return nil
}

func (s *SESService) SendSimilarEmailAlert(ctx context.Context, email string, locale string) error {
	localizer := i18n.NewLocalizer(s.i18nBundle, locale)

	data := similarEmailFields{
		emailFields: newEmailFields(localizer, "SimilarEmailSubject"),
		Message:     localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "SimilarEmailLoginMessage", TemplateData: map[string]string{"Email": email}}),
	}

	if err := s.sendEmail(ctx, email, data.Subject, &data, s.generalHTMLTemplate, s.generalTextTemplate); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
