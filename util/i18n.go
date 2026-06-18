package util

import (
	"fmt"
	"io/fs"
	"slices"

	"github.com/BurntSushi/toml"
	"github.com/brave/accounts/templates"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

func CreateI18nBundle() (*i18n.Bundle, error) {
	i18nBundle := i18n.NewBundle(language.English)
	i18nBundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)

	files, err := fs.Glob(templates.StringsFS, "strings/*.toml")
	if err != nil {
		return nil, fmt.Errorf("failed to list locale strings: %w", err)
	}
	if !slices.Contains(files, "strings/en.toml") {
		return nil, fmt.Errorf("required en.toml strings not found")
	}
	for _, file := range files {
		if _, err := i18nBundle.LoadMessageFileFS(templates.StringsFS, file); err != nil {
			return nil, fmt.Errorf("failed to load %s strings: %w", file, err)
		}
	}
	return i18nBundle, nil
}
