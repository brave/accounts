
all:
	go build

clear-emails:
	curl "http://localhost:4566/_aws/ses" | jq -r ".messages[].Id" | xargs -I % curl -X DELETE "http://localhost:4566/_aws/ses?id=%"

# Run `go install github.com/swaggo/swag/cmd/swag@latest` to use this
update-swagger:
	swag init

lint:
	golangci-lint run

run:
	docker compose up -d postgres localstack
	go run .

test:
	go test -p 1 -v ./...

# Run `go install github.com/air-verse/air@latest` to use this
dev:
	air
