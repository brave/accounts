FROM public.ecr.aws/docker/library/golang:1.24-trixie as builder

WORKDIR /src
COPY . .

RUN go install github.com/swaggo/swag/cmd/swag@latest

RUN swag init
RUN go build

FROM public.ecr.aws/docker/library/debian:trixie-slim

COPY --from=builder /src/accounts /usr/local/bin/accounts

RUN apt-get update && apt-get install -y ca-certificates

EXPOSE 8080

CMD ["/usr/local/bin/accounts"]
