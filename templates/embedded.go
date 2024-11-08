package templates

import _ "embed"

//go:embed verify.tmpl
var VerifyTemplateContent string

//go:embed verify_fe.html
var DefaultVerifyFrontendContent string

//go:embed strings/en.toml
var StringsEnToml []byte
