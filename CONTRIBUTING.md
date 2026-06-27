# Contributing to Ogum Security

Thank you for your interest in contributing. Ogum Security is built by security practitioners for security practitioners — contributions from people who understand the problem space make the platform better for everyone.

## Quick Links

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Adding Security Checks](#adding-security-checks)
- [Pull Request Process](#pull-request-process)
- [Commit Convention](#commit-convention)

---

## Development Setup

**Prerequisites:** Docker 24+, Docker Compose 2+, Python 3.13+, Node.js 20+, Go 1.23+

```bash
# 1. Clone the repo
git clone https://github.com/lichti/ogum-security.git
cd ogum-security

# 2. Copy environment file and fill in values
cp .env.example .env

# 3. Start the full local stack
docker compose up -d

# 4. Install backend dependencies
cd backend && pip install poetry && poetry install

# 5. Install frontend dependencies
cd ../frontend && npm install
```

The stack is now running at:
- **UI:** http://localhost:3000
- **API:** http://localhost:8000
- **API docs (Swagger):** http://localhost:8000/docs
- **ArangoDB UI:** http://localhost:8529

---

## Project Structure

```
ogum-security/
├── backend/        Python (FastAPI + Celery) — API and scan engines
├── frontend/       TypeScript (React 19 + Next.js 15) — Web console
├── agent/          Go + C/eBPF — Hybrid agent for on-premise
├── infra/          Terraform + Helm charts — Platform deployment
└── docs/           Public technical documentation
```

See [docs/architecture.md](docs/architecture.md) for an overview of how the modules interact.

---

## Running Tests

### Backend

```bash
cd backend

# Lint and type check first
poetry run ruff check .
poetry run mypy app/

# Fast loop during development — unit tests only (no Docker needed)
poetry run pytest -m unit

# Pre-push — unit + security + integration (requires ArangoDB + Redis running)
docker compose up -d arangodb redis
poetry run pytest -m "unit or integration or security"

# Full suite with coverage report
poetry run pytest --cov=app --cov-report=term-missing

# CI runs all of the above (coverage threshold enforced: 80%)
```

**Test layer breakdown:**

| Marker | Requires | When to run |
|---|---|---|
| `unit` | Nothing | Every save — instant feedback |
| `integration` | ArangoDB + Redis (Docker) | Before pushing |
| `security` | ArangoDB (Docker) | Before pushing — always blocking |
| `e2e` | Full Docker Compose stack | Before merging to main |

> **Non-negotiable:** Never mock ArangoDB or Redis in tests — always use real instances via Docker.
> Cloud provider APIs (boto3, azure-sdk, gcp) are always mocked at the SDK level using `moto` and `pytest-mock`.

### Frontend (component tests)

```bash
cd frontend
npm run lint
npm run test           # Jest + React Testing Library
npm run test:coverage  # with coverage report
```

### Frontend (E2E — Playwright)

```bash
# Requires full stack running
docker compose up -d

cd frontend
npx playwright install chromium
npx playwright test e2e/
```

### Go agent

```bash
cd agent
go vet ./...
go test ./...
```

---

## Adding Security Checks

Adding new security checks is one of the most impactful contributions. Ogum Security uses Prowler v5 `prowler-core` as the CSPM engine — new checks follow Prowler's check system (YAML + Python).

**Before adding a check:**
1. Search if the check already exists in [Prowler's check library](https://github.com/prowler-cloud/prowler/tree/main/prowler/providers)
2. If it does: consider contributing upstream to Prowler instead (broader impact)
3. If it doesn't: add it here with the Ogum extension mechanism

**Check structure (Prowler v5 convention):**
```
backend/app/checks/
└── aws/
    └── ec2/
        ├── ec2_imdsv2_required/
        │   ├── ec2_imdsv2_required.py     # Check logic
        │   └── ec2_imdsv2_required.metadata.json  # Metadata
        └── ...
```

**Testing your check:**
- Write a unit test in `backend/tests/checks/` with real API fixture data
- Test both the PASS and FAIL cases
- Verify the finding maps correctly to a compliance framework (CIS, NIST, etc.)

---

## Pull Request Process

1. **Fork** the repo and create a branch from `main`:
   ```bash
   git checkout -b feat/my-new-check
   ```

2. **Make your changes** following the coding standards below

3. **Run the test suite** locally before submitting

4. **Open a PR** with:
   - A clear title describing the change
   - What the change does and why
   - Link to any related issues
   - For new security checks: which resource type and which compliance framework

5. **CI must pass** — PRs with failing CI are not reviewed

6. **One approval** from a maintainer is required to merge

---

## Coding Standards

### Python (backend/)
- Strict PEP 8, explicit type annotations everywhere — no untyped `Any`
- Pydantic v2 for all API input/output models
- `async/await` natively in FastAPI handlers
- No mock database in tests — always use real ArangoDB via Docker

### TypeScript (frontend/)
- Next.js 15 App Router with Server Components where applicable
- Tailwind CSS only — no CSS-in-JS
- React Query for server state, Zustand for client state
- Design system tokens from `specs/ui-design.md` — do not invent new colors or spacing

### Go (agent/)
- `gofmt` mandatory
- All eBPF programs must pass the kernel Verifier
- No intermediate disk storage for event data — use `perf_ring_buffer`

### General
- No comments explaining **what** the code does — only **why** when non-obvious
- No credentials in code or committed files
- All external outputs (SIEM, integrations) follow the OCSF schema standard

---

## Commit Convention

Format: `type(scope): description`

| Type | When to use |
|---|---|
| `feat` | New feature or check |
| `fix` | Bug fix |
| `chore` | Maintenance, dependency updates, config |
| `docs` | Documentation only |
| `test` | Test additions or fixes |
| `refactor` | Code change without new feature or bug fix |

**Examples:**
```
feat(inventory): add AWS RDS discovery with multi-region support
fix(cspm): correctly parse IAM policy with wildcard conditions
chore(deps): update prowler-core to 5.32.0
docs(api): add OpenAPI examples for /inventory endpoints
```

**Rules:**
- Keep the description under 72 characters
- Use present tense ("add" not "added")
- Do not reference tooling, AI assistants, or internal processes in commit messages
- No co-author or generated-by footers

---

## Code of Conduct

Be direct, respectful, and focused on the problem. We're building security tooling for people who work hard to protect their organizations — low noise, high signal applies to contributions too.
