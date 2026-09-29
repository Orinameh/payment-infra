.PHONY: help setup build test lint vuln migrate-up migrate-down migrate-status \
        migrate-create docker-build docker-up docker-down docker-nuke docker-logs run clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Install dependencies and tools
	go mod download && go mod tidy
	go install github.com/pressly/goose/v3/cmd/goose@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest

build: ## Build all binaries
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/api     ./cmd/api
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/worker  ./cmd/worker
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/migrate ./cmd/migrate

test: ## Run tests with race detector
	go test -race -count=1 ./...

test-integration: ## Run postgres-backed tests (needs migrations applied)
	TEST_DATABASE_URL="$(DATABASE_URL)" go test -race -count=1 ./internal/wallet/

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

migrate-up:
	goose -dir ./migrations postgres "$(DATABASE_URL)" up

migrate-down:
	goose -dir ./migrations postgres "$(DATABASE_URL)" down

migrate-status:
	goose -dir ./migrations postgres "$(DATABASE_URL)" status

migrate-create: ## make migrate-create NAME=add_foo
	goose -dir ./migrations -s create $(NAME) sql

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-nuke:
	docker compose down -v

docker-logs:
	docker compose logs -f api worker

clean:
	rm -rf bin coverage.out coverage.html