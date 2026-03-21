FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/agentity ./cmd/agentity
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/agentctl ./cmd/agentctl

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

RUN adduser -D -u 1000 agentity

COPY --from=builder /build/agentity /usr/local/bin/agentity
COPY --from=builder /build/agentctl /usr/local/bin/agentctl
COPY --from=builder /build/migrations /migrations

USER agentity

EXPOSE 8080

ENTRYPOINT ["agentity"]
CMD ["--dev"]
