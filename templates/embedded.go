package templates

import _ "embed"

//go:embed verify_html.tmpl
var VerifyHTMLTemplateContent string

//go:embed verify_text.tmpl
var VerifyTextTemplateContent string

//go:embed email_general_html.tmpl
var GeneralEmailHTMLTemplateContent string

//go:embed email_general_text.tmpl
var GeneralEmailTextTemplateContent string

//go:embed verify_fe.html
var DefaultVerifyFrontendContent string

//go:embed email_viewer.tmpl
var EmailViewerTemplateContent string

//go:embed strings/en.toml
var StringsEnToml []byte
