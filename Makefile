
all:
	go build

get-emails:
	curl "http://localhost:4566/_aws/ses?email=noreply@brave.com" | jq

update-swagger:
	swag init

run:
	docker compose up -d
	go run .
