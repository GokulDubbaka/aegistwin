# ============================================================
# AegisTwin — Makefile
# All commands run from the project root.
# ============================================================

.PHONY: help up down restart logs status test lint migrate seed shell-backend shell-db push clean

COMPOSE = docker compose -f infra/docker-compose.yml --env-file .env
BACKEND_DIR = backend

##@ Quick Start
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\n\033[1mAegisTwin Makefile\033[0m\n\nUsage: make \033[36m<target>\033[0m\n\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Docker
up: ## Start all services (build if needed)
	@echo "\033[1;36m==> Starting AegisTwin stack...\033[0m"
	$(COMPOSE) up -d --build
	@echo ""
	@echo "\033[1;32m✓ AegisTwin is running:\033[0m"
	@echo "  Frontend  →  http://localhost:80"
	@echo "  API       →  http://localhost:8000"
	@echo "  API Docs  →  http://localhost:8000/docs"
	@echo "  Flower    →  http://localhost:5555"

up-dev: ## Start backend+db+redis only (for local frontend dev)
	@echo "\033[1;36m==> Starting backend services...\033[0m"
	$(COMPOSE) up -d db redis backend worker
	@echo "\033[1;32m✓ Backend running at http://localhost:8000\033[0m"
	@echo "\033[1;32m  Run: cd frontend && npm run dev\033[0m"

down: ## Stop all services
	$(COMPOSE) down

restart: ## Restart all services
	$(COMPOSE) restart

rebuild: ## Force rebuild all images
	$(COMPOSE) down
	$(COMPOSE) build --no-cache
	$(COMPOSE) up -d

logs: ## Tail logs from all services
	$(COMPOSE) logs -f

logs-backend: ## Tail backend logs only
	$(COMPOSE) logs -f backend

logs-worker: ## Tail Celery worker logs
	$(COMPOSE) logs -f worker

status: ## Show service health status
	$(COMPOSE) ps

##@ Database
migrate: ## Run Alembic migrations
	$(COMPOSE) exec backend sh -c "cd /app/backend && alembic upgrade head"

migrate-create: ## Create a new migration (usage: make migrate-create MSG="your message")
	$(COMPOSE) exec backend sh -c "cd /app/backend && alembic revision --autogenerate -m '$(MSG)'"

seed: ## Run demo seed (safe to run multiple times — idempotent)
	$(COMPOSE) exec backend sh -c "cd /app/backend && python -m app.seed.demo_seed"

shell-db: ## Open psql shell in database container
	$(COMPOSE) exec db psql -U ${POSTGRES_USER:-aegistwin} -d ${POSTGRES_DB:-aegistwin}

db-reset: ## ⚠ DROP and recreate the database (dev only)
	@echo "\033[1;31m⚠ This will DELETE all data. Ctrl+C to cancel...\033[0m"
	@sleep 3
	$(COMPOSE) exec db psql -U ${POSTGRES_USER:-aegistwin} -d postgres -c "DROP DATABASE IF EXISTS aegistwin;"
	$(COMPOSE) exec db psql -U ${POSTGRES_USER:-aegistwin} -d postgres -c "CREATE DATABASE aegistwin;"
	make migrate seed

##@ Testing
test: ## Run full backend test suite (62 tests)
	cd $(BACKEND_DIR) && python -m pytest ../backend/tests/ -v --tb=short

test-fast: ## Run tests without coverage (faster)
	cd $(BACKEND_DIR) && python -m pytest ../backend/tests/ -v --tb=short -x

test-coverage: ## Run tests with HTML coverage report
	cd $(BACKEND_DIR) && python -m pytest ../backend/tests/ -v --cov=app --cov-report=html --cov-report=term-missing

##@ Development
shell-backend: ## Open bash shell in running backend container
	$(COMPOSE) exec backend bash

lint: ## Run ruff linter
	cd $(BACKEND_DIR) && python -m ruff check app/ tests/

format: ## Auto-format with ruff
	cd $(BACKEND_DIR) && python -m ruff check --fix app/ tests/

typecheck: ## Run mypy type checker
	cd $(BACKEND_DIR) && python -m mypy app/

frontend-dev: ## Start Vite dev server (frontend only)
	cd frontend && npm run dev

frontend-install: ## Install frontend dependencies
	cd frontend && npm install

frontend-build: ## Build frontend production bundle
	cd frontend && npm run build

##@ Git
push: ## Commit and push all changes to GitHub
	git add -A
	git commit -m "chore: update infra, migrations, seed data"
	git push origin main

##@ Cleanup
clean: ## Remove Docker volumes (⚠ deletes all data)
	@echo "\033[1;31m⚠ Removing all volumes. Ctrl+C to cancel...\033[0m"
	@sleep 3
	$(COMPOSE) down -v
	docker system prune -f
