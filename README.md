# Brave Accounts Service

## Development setup

1. Copy `.env.example` to `.env`
2. Run `docker compose up -d`
3. Run `go run .`

Use `make get-emails` to get the contents of sent verification emails.

View API documentation at http://localhost:8080/swagger/index.html.

## Environment variables

| Name | Required? | Description |
|------|-----------|-------------|
| DATABASE_URL | Yes | PostgreSQL database connection URL |
| EMAIL_FROM_ADDRESS | Yes | Email address used as sender for verification emails |
| BASE_URL | Yes | Base URL of the service |
| AWS_ENDPOINT | No | Custom AWS endpoint for testing |
| LOG_PRETTY | No | Enable pretty logging format if set to 'true' |
| LOG_LEVEL | No | Logging level (default: info) |
| SERVE_SWAGGER | No | Serve Swagger UI if set to 'true' |
| PASSWORD_AUTH_ENABLED | No | Enable password authentication if set to 'true' |
| OPAQUE_SECRET_KEY | Yes | OPAQUE server secret key |
| OPAQUE_PUBLIC_KEY | Yes | OPAQUE server public key |
| OPAQUE_FAKE_RECORD | No | OPAQUE fake record for rate limiting |
| JWT_KEY | Yes | Secret key for JWT signing |
| PREMIUM_AUTH_REDIRECT_URL | Yes | Redirect URL for premium service authentication |
