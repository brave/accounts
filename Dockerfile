FROM public.ecr.aws/docker/library/golang:1.23-bookworm as builder

WORKDIR /src
COPY . .

RUN go build

FROM public.ecr.aws/docker/library/debian:bookworm-slim

COPY --from=builder /src/accounts /usr/local/bin/accounts

EXPOSE 8080

CMD ["/usr/local/bin/accounts"]
