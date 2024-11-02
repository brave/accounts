package templates

import _ "embed"

//go:embed verify.tmpl
var VerifyTemplateContent string

//go:embed strings/en.toml
var StringsEnToml []byte
