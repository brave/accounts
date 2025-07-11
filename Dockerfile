FROM public.ecr.aws/docker/library/golang:1.24-bookworm as builder

WORKDIR /src
COPY . .

RUN go install github.com/swaggo/swag/cmd/swag@latest

RUN swag init
RUN go build

FROM public.ecr.aws/docker/library/debian:bookworm-slim

COPY --from=builder /src/accounts /usr/local/bin/accounts

RUN apt update && apt install -y ca-certificates

EXPOSE 8080

CMD ["/usr/local/bin/accounts"]
