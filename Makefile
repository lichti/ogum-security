.DEFAULT_GOAL := help

COMPOSE := docker compose
BACKEND  := $(COMPOSE) exec backend
FRONTEND := $(COMPOSE) exec frontend

# ── Help ──────────────────────────────────────────────────────────────────────
.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-28s\033[0m %s\n", $$1, $$2}'

# ── Environment ───────────────────────────────────────────────────────────────
.PHONY: env
env: ## Copy .env.example → .env (skip if already exists)
	@test -f .env && echo ".env already exists — skipping" || (cp .env.example .env && echo ".env created from .env.example")

# ── Docker — Infrastructure ───────────────────────────────────────────────────
.PHONY: build
build: ## Build all Docker images
	$(COMPOSE) build

.PHONY: build-no-cache
build-no-cache: ## Build all Docker images without layer cache
	$(COMPOSE) build --no-cache

.PHONY: up
up: ## Start full stack (detached)
	$(COMPOSE) up -d

.PHONY: up-infra
up-infra: ## Start only infrastructure services (ArangoDB, Redis, Redpanda, Qdrant)
	$(COMPOSE) up -d arangodb redis redpanda qdrant

.PHONY: up-backend
up-backend: ## Start infrastructure + backend + worker
	$(COMPOSE) up -d arangodb redis redpanda qdrant backend worker celery-beat

.PHONY: up-frontend
up-frontend: ## Start frontend only (assumes backend is already up)
	$(COMPOSE) up -d frontend

.PHONY: down
down: ## Stop all containers
	$(COMPOSE) down

.PHONY: down-volumes
down-volumes: ## Stop all containers and remove volumes (destructive — resets all data)
	$(COMPOSE) down -v

.PHONY: restart
restart: ## Restart all containers
	$(COMPOSE) restart

.PHONY: restart-backend
restart-backend: ## Restart backend + worker
	$(COMPOSE) restart backend worker celery-beat

# ── Logs ─────────────────────────────────────────────────────────────────────
.PHONY: logs
logs: ## Tail logs for all services
	$(COMPOSE) logs -f

.PHONY: logs-backend
logs-backend: ## Tail backend API logs
	$(COMPOSE) logs -f backend

.PHONY: logs-worker
logs-worker: ## Tail Celery worker logs
	$(COMPOSE) logs -f worker

.PHONY: logs-frontend
logs-frontend: ## Tail frontend logs
	$(COMPOSE) logs -f frontend

# ── Shells ───────────────────────────────────────────────────────────────────
.PHONY: shell-backend
shell-backend: ## Open a shell in the backend container
	$(BACKEND) bash

.PHONY: shell-frontend
shell-frontend: ## Open a shell in the frontend container
	$(FRONTEND) sh

.PHONY: shell-arango
shell-arango: ## Open arangosh in the ArangoDB container
	docker exec -it ogum-arangodb arangosh --server.password $${ARANGO_PASSWORD:-changeme}

# ── Backend — Code Quality ────────────────────────────────────────────────────
.PHONY: lint
lint: ## Run ruff linter on backend
	cd backend && poetry run ruff check .

.PHONY: format
format: ## Auto-format backend code with ruff
	cd backend && poetry run ruff format .

.PHONY: format-check
format-check: ## Check formatting without applying changes
	cd backend && poetry run ruff format --check .

.PHONY: typecheck
typecheck: ## Run mypy type checker on backend
	cd backend && poetry run mypy app/

.PHONY: check
check: lint format-check typecheck ## Run all code quality checks (lint + format + types)

# ── Backend — Tests ───────────────────────────────────────────────────────────
.PHONY: test
test: ## Run all backend tests (unit + integration + security)
	cd backend && poetry run pytest --cov=app --cov-report=term-missing

.PHONY: test-unit
test-unit: ## Run unit tests only (no external dependencies)
	cd backend && poetry run pytest -m unit --cov=app --cov-report=term-missing -v

.PHONY: test-integration
test-integration: ## Run integration tests (requires ArangoDB + Redis running)
	cd backend && poetry run pytest -m integration --cov=app --cov-report=term-missing -v

.PHONY: test-security
test-security: ## Run security/isolation tests (requires ArangoDB running)
	cd backend && poetry run pytest -m security -v

.PHONY: test-ci
test-ci: ## Run integration + security tests (CI mode — expects services in env)
	cd backend && poetry run pytest -m "integration or security" --cov=app --cov-report=xml

# ── Dev Seed ──────────────────────────────────────────────────────────────────
.PHONY: seed
seed: ## Seed demo findings into dev-tenant (requires ArangoDB running)
	cd backend && poetry run python scripts/seed_demo.py --tenant dev-tenant

.PHONY: seed-clear
seed-clear: ## Clear and re-seed demo findings for dev-tenant
	cd backend && poetry run python scripts/seed_demo.py --tenant dev-tenant --clear

.PHONY: seed-tenant
seed-tenant: ## Seed a specific tenant: make seed-tenant TENANT=my-tenant
	cd backend && poetry run python scripts/seed_demo.py --tenant $(TENANT)

# ── Frontend — Code Quality ───────────────────────────────────────────────────
.PHONY: fe-lint
fe-lint: ## Run ESLint on frontend
	cd frontend && npm run lint

.PHONY: fe-typecheck
fe-typecheck: ## Run TypeScript type check on frontend
	cd frontend && npx tsc --noEmit

.PHONY: fe-check
fe-check: fe-lint fe-typecheck ## Run all frontend code quality checks

# ── Frontend — Tests ──────────────────────────────────────────────────────────
.PHONY: fe-test
fe-test: ## Run frontend component tests (Jest + RTL)
	cd frontend && npm run test -- --coverage

.PHONY: fe-test-watch
fe-test-watch: ## Run frontend tests in watch mode
	cd frontend && npm run test -- --watch

.PHONY: fe-build
fe-build: ## Build frontend for production
	cd frontend && npm run build

# ── Agent — Go ────────────────────────────────────────────────────────────────
.PHONY: agent-vet
agent-vet: ## Run go vet on agent
	cd agent && go vet ./...

.PHONY: agent-build
agent-build: ## Build agent binary
	cd agent && go build ./...

.PHONY: agent-test
agent-test: ## Run agent tests
	cd agent && go test ./...

# ── Combined ──────────────────────────────────────────────────────────────────
.PHONY: test-all
test-all: test fe-test agent-test ## Run all tests across backend, frontend, and agent

.PHONY: check-all
check-all: check fe-check agent-vet ## Run all code quality checks across all services

# ── Dependencies ──────────────────────────────────────────────────────────────
.PHONY: install
install: ## Install all backend and frontend dependencies
	cd backend && poetry install
	cd frontend && npm ci

.PHONY: install-backend
install-backend: ## Install backend Python dependencies
	cd backend && poetry install

.PHONY: install-frontend
install-frontend: ## Install frontend Node dependencies
	cd frontend && npm ci

.PHONY: update-deps
update-deps: ## Update and lock backend + frontend dependencies
	cd backend && poetry update
	cd frontend && npm update

# ── Security Audit ────────────────────────────────────────────────────────────
.PHONY: audit
audit: ## Run pip-audit on backend dependencies
	cd backend && pip-audit --requirement <(poetry export --without-hashes)

# ── Status ────────────────────────────────────────────────────────────────────
.PHONY: ps
ps: ## Show running container status
	$(COMPOSE) ps

.PHONY: health
health: ## Check health of all services
	@echo "=== ArangoDB ===" && curl -sf http://localhost:8529/_api/version | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"  version: {d['version']} — OK\")" || echo "  UNREACHABLE"
	@echo "=== Redis ===" && redis-cli ping 2>/dev/null && true || echo "  UNREACHABLE"
	@echo "=== Backend ===" && curl -sf http://localhost:8000/health | python3 -c "import sys,json; print(f\"  {json.load(sys.stdin)}\")" || echo "  UNREACHABLE"
	@echo "=== Frontend ===" && curl -sf http://localhost:3000 > /dev/null && echo "  OK" || echo "  UNREACHABLE"
