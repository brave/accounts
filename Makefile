
all:
	go build

get-emails:
	curl "http://localhost:4566/_aws/ses?email=noreply@brave.com" | jq

# Run `go install github.com/swaggo/swag/cmd/swag@latest` to use this
update-swagger:
	swag init

run:
	docker compose up -d
	go run .

# Run `go install github.com/air-verse/air@latest` to use this
dev:
	air
