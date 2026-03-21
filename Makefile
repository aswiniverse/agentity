.PHONY: build test run-dev docker-build docker-push migrate clean lint fmt

BINARY_SERVER=agentity
BINARY_CLI=agentctl
BUILD_DIR=./bin

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_SERVER) ./cmd/agentity
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_CLI) ./cmd/agentctl

test:
	go test -race -cover ./...

run-dev:
	go run ./cmd/agentity --dev --log-level debug

docker-build:
	docker build -t agentity:latest .

docker-push:
	docker push agentity:latest

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

migrate:
	@echo "Apply migrations using your preferred tool (e.g., golang-migrate, dbmate)"
	@echo "Example: migrate -path ./migrations -database \$$DATABASE_URL up"

clean:
	rm -rf $(BUILD_DIR)
	go clean -cache

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .
	goimports -w .

generate:
	go generate ./...

deps:
	go mod tidy
	go mod download
