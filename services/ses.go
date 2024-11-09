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
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/templates"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/rs/zerolog/log"
)

const (
	fromAddressEnv       = "EMAIL_FROM_ADDRESS"
	baseURLEnv           = "BASE_URL"
	verifyFrontendURLEnv = "VERIFY_FRONTEND_URL"
	awsEndpointEnv       = "AWS_ENDPOINT"

	defaultFromAddress = "noreply@brave.com"
	defaultBaseURL     = "http://localhost:8080"
)

type SESService struct {
	client             *ses.Client
	verifyHTMLTemplate *htmlTemplate.Template
	verifyTextTemplate *textTemplate.Template
	fromAddress        string
	baseURL            string
	frontendURL        string
	i18nBundle         *i18n.Bundle
}

type verifyEmailFields struct {
	VerifyURL          string
	Subject            string
	Greeting           string
	Instructions       string
	Action             string
	Disregard          string
	Signature          string
	VerifyActionBackup string
	ExpiryDisclaimer   string
	Copyright          string
	AllRightsReserved  string
	PrivacyPolicy      string
	TermsOfUse         string
	DownloadBrave      string
	ContactSupport     string
}

func NewSESService(i18nBundle *i18n.Bundle) (*SESService, error) {
	// Create AWS config
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create SES client
	client := ses.NewFromConfig(cfg, func(o *ses.Options) {
		awsEndpoint := os.Getenv(awsEndpointEnv)
		if awsEndpoint != "" {
			o.BaseEndpoint = &awsEndpoint
		}
	})

	htmlTmpl, err := htmlTemplate.New("verify_html").Parse(templates.VerifyHTMLTemplateContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}
	textTmpl, err := textTemplate.New("verify_text").Parse(templates.VerifyTextTemplateContent)
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

	frontendURL := os.Getenv(baseURLEnv)

	return &SESService{
		client,
		htmlTmpl,
		textTmpl,
		fromAddress,
		baseURL,
		frontendURL,
		i18nBundle,
	}, nil
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
		VerifyURL:          verifyURL,
		Subject:            localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: subjectMessageID}),
		Greeting:           localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailGreeting"}),
		Instructions:       localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: instructionsMessageID}),
		Action:             localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailAction"}),
		Disregard:          localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailDisregard"}),
		Signature:          localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailSignature"}),
		VerifyActionBackup: localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailActionBackup"}),
		ExpiryDisclaimer:   localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailExpiryDisclaimer"}),
		Copyright:          localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailCopyright", TemplateData: map[string]string{"Year": strconv.Itoa(time.Now().Year())}}),
		AllRightsReserved:  localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailAllRightsReserved"}),
		PrivacyPolicy:      localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailPrivacyPolicy"}),
		TermsOfUse:         localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailTermsOfUse"}),
		DownloadBrave:      localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailDownloadBrave"}),
		ContactSupport:     localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "EmailContactSupport"}),
	}

	var htmlContent, textContent bytes.Buffer
	if err := s.verifyHTMLTemplate.Execute(&htmlContent, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	if err := s.verifyTextTemplate.Execute(&textContent, data); err != nil {
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
				Data: &data.Subject,
			},
		},
		Source: &s.fromAddress,
	}

	_, err := s.client.SendEmail(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Debug().Str("verify_url", verifyURL).Msg("Sent verification link")

	return nil
}
