
all:
	go build

clear-emails:
	curl -X DELETE "http://localhost:4566/_aws/ses"

# Run `go install github.com/swaggo/swag/cmd/swag@latest` to use this
update-swagger:
	swag init --parseDependency

lint:
	golangci-lint run

run: update-swagger
	docker compose up -d postgres ses-local
	go run -race .

test: update-swagger
	docker compose up -d postgres ses-local
	go test -p 1 -v ./...

# Run `go install github.com/air-verse/air@latest` to use this
dev:
	air

dev-key-service:
	air -- -start-key-service -listen :8081 -prom-listen :9091
