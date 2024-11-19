# Brave Accounts Service

## Development setup

1. Copy `.env.example` to `.env`
2. Run `make run`

Visit http://localhost:8080/v2/verify/email_viewer to view sent verification emails.
Use `make clean-emails` to delete all sent emails.

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
| AWS_ENDPOINT | No | Custom AWS endpoint for testing |
| LOG_PRETTY | No | Enable pretty logging format if set to 'true' |
| LOG_LEVEL | No | Logging level (default: info) |
| SERVE_SWAGGER | No | Serve Swagger UI if set to 'true' |
| OPAQUE_FAKE_RECORD | No | Use OPAQUE fake record to prevent client enumeration attacks |
| VERIFY_FRONTEND_URL | No | Frontend URL to use in verification emails |
| BRAVE_SERVICES_KEY | No | Services key to check against (via the `Brave-Key` header) for all requests |
| WEBHOOK_KEYS | No | A list of URLs and corresponding API keys for sending account event webhooks, delimited by a comma. Each entry should use the following format: `webhook url=webhook api key` |
| DEV_ENDPOINTS_ENABLED | No | Enable the development-only endpoints |
