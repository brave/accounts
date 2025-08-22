module github.com/brave/accounts

go 1.24.2

toolchain go1.24.4

require (
	github.com/BurntSushi/toml v1.4.0
	github.com/aws/aws-sdk-go-v2/config v1.28.0
	github.com/aws/aws-sdk-go-v2/credentials v1.17.41
	github.com/aws/aws-sdk-go-v2/feature/rds/auth v1.4.24
	github.com/aws/aws-sdk-go-v2/service/sesv2 v1.52.1
	github.com/aws/aws-sdk-go-v2/service/sts v1.32.2
	github.com/aws/smithy-go v1.22.5
	github.com/bytemare/ecc v0.9.0
	github.com/bytemare/opaque v0.0.0
	github.com/go-chi/chi/v5 v5.2.2
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/docgen v1.3.0
	github.com/go-playground/validator/v10 v10.22.1
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/golang-migrate/migrate/v4 v4.18.3
	github.com/google/uuid v1.6.0
	github.com/nicksnyder/go-i18n/v2 v2.4.1
	github.com/pquerna/otp v1.4.0
	github.com/prometheus/client_golang v1.20.5
	github.com/stretchr/testify v1.9.0
	github.com/swaggo/http-swagger/v2 v2.0.2
	github.com/swaggo/swag v1.16.4
	gorm.io/gorm v1.25.12
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	filippo.io/nistec v0.0.3 // indirect
	github.com/KyleBanks/depth v1.2.1 // indirect
	github.com/aws/aws-sdk-go-v2 v1.38.1 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/bytemare/hash v0.5.2 // indirect
	github.com/bytemare/hash2curve v0.5.4 // indirect
	github.com/bytemare/ksf v0.3.0 // indirect
	github.com/bytemare/secp256k1 v0.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/spec v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/gtank/ristretto255 v0.1.2 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.60.1 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/swaggo/files/v2 v2.0.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/tools v0.26.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/go-chi/render v1.0.3
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.7.1
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/joho/godotenv v1.5.1
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/rs/zerolog v1.33.0
	golang.org/x/crypto v0.38.0
	golang.org/x/sync v0.14.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0
	gorm.io/driver/postgres v1.5.9
)

replace github.com/bytemare/opaque v0.0.0 => github.com/brave-experiments/opaque v0.0.0-20250509213350-9e222393c642
