FROM golang:1-alpine AS builder

WORKDIR /app

COPY main.go .

RUN go build -o ses-v2-local main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/ses-v2-local .

EXPOSE 4566

CMD ["./ses-v2-local"]
