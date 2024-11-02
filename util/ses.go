package util

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/brave-experiments/accounts/templates"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/rs/zerolog/log"
)

const (
	fromAddressEnv = "EMAIL_FROM_ADDRESS"
	baseURLEnv     = "BASE_URL"
	awsEndpointEnv = "AWS_ENDPOINT"

	defaultFromAddress = "noreply@brave.com"
	defaultBaseURL     = "http://localhost:8080"

	verifySubject = "Verify your email address"
)

type SESUtil struct {
	client         *ses.Client
	verifyTemplate *template.Template
	fromAddress    string
	baseURL        string
	i18nBundle     *i18n.Bundle
}

func NewSESUtil(i18nBundle *i18n.Bundle) (*SESUtil, error) {
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

	tmpl, err := template.New("verify").Parse(templates.VerifyTemplateContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	fromAddress := os.Getenv(fromAddressEnv)
	if fromAddress == "" {
		fromAddress = defaultFromAddress
	}

	baseURL := os.Getenv(baseURLEnv)
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	return &SESUtil{
		client,
		tmpl,
		fromAddress,
		baseURL,
		i18nBundle,
	}, nil
}

type verifyEmailData struct {
	VerifyURL            string
	Subject              string
	Title                string
	Greeting             string
	Instructions         string
	Button               string
	Ignore               string
	Signature            string
	FallbackInstructions string
}

func (s *SESUtil) SendVerificationEmail(ctx context.Context, email string, verificationID string, verificationCode string, locale string) error {
	verifyURL := fmt.Sprintf("%s/v2/verify/complete?verify_id=%s&verify_code=%s", s.baseURL, verificationID, verificationCode)
	localizer := i18n.NewLocalizer(s.i18nBundle, locale)
	data := verifyEmailData{
		VerifyURL:            verifyURL,
		Subject:              localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailSubject"}),
		Title:                localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailTitle"}),
		Greeting:             localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailGreeting"}),
		Instructions:         localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailInstructions", TemplateData: map[string]string{"Email": email}}),
		Button:               localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailButton"}),
		Ignore:               localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailIgnore"}),
		Signature:            localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailSignature"}),
		FallbackInstructions: localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "VerifyEmailFallbackInstructions"}),
	}

	log.Debug().Str("verify_url", verifyURL).Msg("Sent verification link")

	var bodyContent bytes.Buffer
	if err := s.verifyTemplate.Execute(&bodyContent, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	bodyContentString := bodyContent.String()
	subject := verifySubject

	input := &ses.SendEmailInput{
		Destination: &types.Destination{
			ToAddresses: []string{email},
		},
		Message: &types.Message{
			Body: &types.Body{
				Html: &types.Content{
					Data: &bodyContentString,
				},
			},
			Subject: &types.Content{
				Data: &subject,
			},
		},
		Source: &s.fromAddress,
	}

	_, err := s.client.SendEmail(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
