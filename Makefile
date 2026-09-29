.PHONY: help setup build test test-integration lint vuln migrate-up migrate-down \
        migrate-status migrate-create docker-build docker-up docker-down docker-nuke \
        docker-logs run clean

GOLANGCI_VERSION ?= v2.1.6
GOVULNCHECK_VERSION ?= latest
GOOSE_VERSION ?= v3.28.0

# Tool binaries resolve to GOPATH/bin explicitly: `go install` drops
# them there, which is often absent from non-interactive PATHs (the
# exact reason `make lint`/`make vuln` failed after installing).
GOBIN := $(shell go env GOPATH)/bin
GOLANGCI := $(GOBIN)/golangci-lint
GOVULNCHECK := $(GOBIN)/govulncheck
GOOSE := $(GOBIN)/goose

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Install dependencies and tools (pinned versions)
	go mod download && go mod tidy
	go install github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

build: ## Build all binaries into ./bin
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/api     ./cmd/api
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/worker  ./cmd/worker
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/migrate ./cmd/migrate

test: ## Run tests with race detector
	go test -race -count=1 ./...

test-integration: ## Run postgres-backed tests (needs DATABASE_URL with migrations applied)
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is required" && exit 1)
	TEST_DATABASE_URL="$(DATABASE_URL)" go test -race -count=1 ./internal/wallet/

lint: ## Lint (auto-installs golangci-lint if missing)
	@test -x $(GOLANGCI) || go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	$(GOLANGCI) run ./...

vuln: ## Vulnerability scan (auto-installs govulncheck if missing)
	@test -x $(GOVULNCHECK) || go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GOVULNCHECK) ./...

# Migrations run through ./cmd/migrate (embedded SQL), not the external
# goose binary, so ./migrations/embed.go never confuses the runner.
migrate-up: ## Apply all pending migrations (needs DATABASE_URL)
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is required" && exit 1)
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/migrate up

migrate-down: ## Roll back the last migration (needs DATABASE_URL)
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is required" && exit 1)
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/migrate down

migrate-status: ## Show migration status (needs DATABASE_URL)
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is required" && exit 1)
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/migrate status

migrate-create: ## Create a migration: make migrate-create NAME=add_foo
	@test -n "$(NAME)" || (echo "NAME is required: make migrate-create NAME=add_foo" && exit 1)
	@test -x $(GOOSE) || go install github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION)
	$(GOOSE) -dir ./migrations -s create $(NAME) sql

docker-build: ## Build compose images
	docker compose build

docker-up: ## Start the full stack
	docker compose up -d

docker-down: ## Stop the stack (keep volumes)
	docker compose down

docker-nuke: ## Stop the stack and delete volumes
	docker compose down -v

docker-logs: ## Follow api and worker logs
	docker compose logs -f api worker

run: build ## Build and run the API locally (needs DATABASE_URL)
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is required" && exit 1)
	./bin/api

clean: ## Remove build artifacts
	rm -rf bin coverage.out coverage.html
