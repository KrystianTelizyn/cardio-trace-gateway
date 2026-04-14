# Override at invoke time, e.g. `make build IMAGE=my-registry/gateway:0.2.0`.
UV ?= uv
IMAGE ?= cardio-trace-gateway:dev
COMPOSE ?= docker compose
COMPOSE_FILE ?= docker-compose.yml

.DEFAULT_GOAL := help

.PHONY: help sync dev build compose-up compose-down compose-logs test test-integration

help: ## Show available targets
	@echo "Targets:"
	@grep -E '^[a-zA-Z0-9_.-]+:.*##' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*## "}; {printf "  %-22s %s\n", $$1, $$2}'
	@echo ""
	@echo "Variables: IMAGE=$(IMAGE) COMPOSE_FILE=$(COMPOSE_FILE)"

sync: ## Install/sync Python dependencies (including dev group)
	$(UV) sync --group dev

dev: ## Start FastAPI in development mode (reload, local only)
	$(UV) run fastapi dev src/app/main.py

build: ## Build the production Docker image
	docker build -t $(IMAGE) .

compose-up: ## Run Docker Compose (default file: docker-compose.yml; override with COMPOSE_FILE=)
	$(COMPOSE) -f $(COMPOSE_FILE) up

compose-down: ## Stop and remove Docker Compose containers
	$(COMPOSE) -f $(COMPOSE_FILE) down

compose-logs: ## Follow Docker Compose service logs
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f

test: ## Run unit/contract tests (skips @pytest.mark.integration)
	$(UV) run pytest -m "not integration"

test-integration: ## Run integration tests (same as CI; needs RUN_INTEGRATION=1 and .env secrets)
	RUN_INTEGRATION=1 $(UV) run pytest --no-cov -m integration
