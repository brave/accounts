package util

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/brave/accounts/templates"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

func CreateI18nBundle() (*i18n.Bundle, error) {
	i18nBundle := i18n.NewBundle(language.English)
	i18nBundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	if _, err := i18nBundle.ParseMessageFileBytes(templates.StringsEnToml, "en.toml"); err != nil {
		return nil, fmt.Errorf("failed to load en strings: %w", err)
	}
	return i18nBundle, nil
}
