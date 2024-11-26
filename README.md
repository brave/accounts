# Brave Accounts Service

## Development setup

1. Copy `.env.example` to `.env`
2. Run `make run`

Visit http://localhost:8080/v2/verify/email_viewer to view sent verification emails.
Use `make clean-emails` to delete all sent emails.

Run `make test` to run the test suites.

View API documentation at http://localhost:8080/swagger/index.html.

## Environment variables

| Name | Required? | Description |
|------|-----------|-------------|
| DATABASE_URL | Yes | PostgreSQL database connection URL |
| EMAIL_FROM_ADDRESS | Yes | Email address used as sender for verification emails |
| BASE_URL | Yes | Base URL of the service |
| OPAQUE_SECRET_KEY | Yes | OPAQUE server secret key |
| OPAQUE_PUBLIC_KEY | Yes | OPAQUE server public key |
| PASSWORD_AUTH_ENABLED | Yes | Enable password authentication if set to 'true' |
| EMAIL_AUTH_ENABLED | Yes | Enable email `auth_token` authentication if set to 'true' |
| RDS_ROLE | Yes (if RDS is being used) | The AWS IAM role ARN to assume for RDS access |
| RDS_DATABASE_PORT | Yes (if RDS is being used) | The port number for the RDS database connection |
| RDS_WRITER_ENDPOINT | Yes (if RDS is being used) | The endpoint URL for the RDS writer instance |
| RDS_USER | Yes (if RDS is being used) | The username for RDS database authentication |
| RDS_DATABASE_NAME | Yes (if RDS is being used) | The name of the RDS database to connect to |
| AWS_REGION | Yes (if RDS is being used) | The AWS region where the RDS instance is deployed |
| AWS_ENDPOINT | No | Custom AWS endpoint for testing |
| LOG_PRETTY | No | Enable pretty logging format if set to 'true' |
| LOG_LEVEL | No | Logging level (default: info) |
| OPAQUE_FAKE_RECORD | No | Use OPAQUE fake record to prevent client enumeration attacks |
| VERIFY_FRONTEND_URL | No | Frontend URL to use in verification emails |
| BRAVE_SERVICES_KEY | No | Services key to check against (via the `Brave-Key` header) for all requests |
| WEBHOOK_KEYS | No | A list of URLs and corresponding API keys for sending account event webhooks, delimited by a comma. Each entry should use the following format: `webhook url=webhook api key` |
| DEV_ENDPOINTS_ENABLED | No | Enable the development-only endpoints |
| ALLOWED_ORIGINS | No | List of allowed origins for CORS, separated by comma |
| SES_CONFIG_SET | No | Configuration set name to use for SES emails |
| SES_ROLE | No | The AWS IAM role ARN to assume for SES access |
| ACCOUNT_DELETION_ENABLED | No | Enables account deletion endpoint |
