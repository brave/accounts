
all:
	go build

clear-emails:
	curl "http://localhost:4566/_aws/ses" | jq -r ".messages[].Id" | xargs -I % curl -X DELETE "http://localhost:4566/_aws/ses?id=%"

# Run `go install github.com/swaggo/swag/cmd/swag@latest` to use this
update-swagger:
	swag init

# Only works if EMAIL_AUTH_ENABLED is set to true
get-email-auth-token:
	VERIFICATION_TOKEN=`curl -s --json '{"email":"test@example.com","intent":"auth_token","service":"email-aliases"}' \
		http://localhost:8080/v2/verify/init | jq -r .verificationToken`; \
	echo -e "\033[0;32mClick on the verification link in the Accounts service logs...\033[0m"; \
	while [ -z "$$AUTH_TOKEN" ] || [ "$$AUTH_TOKEN" = "null" ]; do \
		AUTH_TOKEN=`curl -s --json '{"wait":true}' -H "Authorization: Bearer $$VERIFICATION_TOKEN" \
			http://localhost:8080/v2/verify/result | jq -r .authToken`; \
	done; \
	echo "auth token: $$AUTH_TOKEN"

lint:
	golangci-lint run

run:
	docker compose up -d postgres localstack
	swag init
	go run .

test:
	docker compose up -d postgres localstack
	swag init
	go test -p 1 -v ./...

# Run `go install github.com/air-verse/air@latest` to use this
dev:
	air

dev-key-service:
	air -- -start-key-service -listen :8081 -prom-listen :9091
