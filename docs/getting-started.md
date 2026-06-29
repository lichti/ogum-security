# Getting Started with Ogum Security

> **Status:** Early Development — this guide reflects the target experience for v1.0. Some features may not be available yet. Check the [roadmap](../README.md#roadmap) for current status.

## Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Docker | 24.0+ | Required for all services |
| Docker Compose | 2.20+ | Included with Docker Desktop |
| RAM | 8 GB | Full stack: ArangoDB + Redpanda + Ollama |
| Disk | 20 GB | ArangoDB data + Ollama model (~4 GB) |

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/lichti/ogum-security.git
cd ogum-security

# 2. Copy environment variables
cp .env.example .env

# 3. Edit .env — minimum required:
#   ARANGO_ROOT_PASSWORD=<strong-password>
#   SECRET_KEY=<random-64-char-string>
#   FIRST_ADMIN_EMAIL=you@example.com

# 4. Start the platform
docker compose up -d

# 5. Wait for services to initialize (~60 seconds for ArangoDB + Ollama model pull)
docker compose logs -f backend | grep "Application startup complete"
```

Open **http://localhost:3000** — you should see the Ogum Security login screen.

---

## Connecting Your First Cloud Account

### Using the Web Console (recommended)

1. Open **http://localhost:3000/inventory** — if no accounts are connected, you will see a "Connect Account" button.
2. Click **Connect Account** — the setup wizard opens.
3. Select your cloud provider (AWS, Azure, GCP, or Kubernetes).
4. Fill in the required fields (Account ID, regions, etc.) and click **Connect & Start Discovery**.
5. Discovery starts automatically in the background. Return to the Inventory page to see resources as they appear.

### Using the API

```bash
# Register an AWS account and start discovery
curl -X POST http://localhost:8000/api/v1/providers \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: dev-tenant" \
  -d '{
    "provider": "aws",
    "display_name": "My AWS Account",
    "account_id": "123456789012",
    "regions": ["us-east-1", "us-west-2"],
    "validate_connection": false
  }'

# List connected providers
curl http://localhost:8000/api/v1/providers \
  -H "X-Tenant-ID: dev-tenant"

# Check discovered resources
curl http://localhost:8000/api/v1/inventory \
  -H "X-Tenant-ID: dev-tenant"

# Export inventory as CSV
curl "http://localhost:8000/api/v1/inventory/export?format=csv" \
  -H "X-Tenant-ID: dev-tenant" \
  -o inventory.csv

# Export inventory as OCSF-inspired JSON
curl "http://localhost:8000/api/v1/inventory/export?format=json" \
  -H "X-Tenant-ID: dev-tenant" \
  -o inventory.json
```

---

### AWS — Cross-Account IAM Role Setup

Ogum uses a **Cross-Account IAM Role** to access your AWS account. This means:
- No long-lived access keys stored in Ogum
- Your AWS credentials stay in your AWS account
- You control exactly what Ogum can access

**Step 1: Create the IAM Role in your AWS account**

```bash
# Replace OGUM_ACCOUNT_ID with the AWS account where Ogum is running
# Replace EXTERNAL_ID with the value shown in the Ogum UI during setup
aws iam create-role \
  --role-name OgumSecurityRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<OGUM_ACCOUNT_ID>:role/OgumServiceRole" },
      "Action": "sts:AssumeRole",
      "Condition": { "StringEquals": { "sts:ExternalId": "<EXTERNAL_ID>" } }
    }]
  }'

# Attach the read-only managed policy (minimum for Inventory + CSPM)
aws iam attach-role-policy \
  --role-name OgumSecurityRole \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

**Step 2: Connect the account in Ogum**

1. Go to **Settings → Cloud Providers → Add Provider**
2. Select **AWS**
3. Enter your AWS Account ID and the Role ARN
4. Ogum validates the connection with a test call
5. First discovery starts automatically — takes 5–15 minutes depending on account size

---

## Your First Scan (CSPM)

Once discovery completes:

1. Go to **Inventory** — verify your resources appear
2. Go to **Findings** — Prowler v5 runs automatically after discovery
3. Filter by **Severity: CRITICAL** to see the most urgent issues
4. Click any finding to see: affected resource, compliance framework, and remediation guidance

---

## Understanding the Dashboard

| Widget | What it shows |
|---|---|
| **Threat Score** | Aggregate risk score (0–100) based on findings + attack paths |
| **Open Findings** | Total unresolved security issues across all providers |
| **Active Attack Paths** | Paths from internet-facing resources to sensitive data |
| **Compliance** | Pass/fail percentage per framework (CIS, NIST, SOC 2, etc.) |

---

## Configuration Reference

Key environment variables (see `.env.example` for all):

| Variable | Description | Default |
|---|---|---|
| `ARANGO_URL` | ArangoDB connection URL | `http://arangodb:8529` |
| `ARANGO_ROOT_PASSWORD` | ArangoDB root password | — (required) |
| `REDIS_URL` | Redis connection URL | `redis://redis:6379/0` |
| `SECRET_KEY` | JWT signing key (min 32 chars) | — (required) |
| `OLLAMA_URL` | Ollama API URL for local LLM | `http://ollama:11434` |
| `DISCOVERY_INTERVAL_CLOUD` | Cloud discovery interval (hours) | `6` |
| `DISCOVERY_INTERVAL_K8S` | K8s discovery interval (hours) | `1` |

---

## Architecture Overview

Ogum Security is built around a **graph-first** approach: every resource, identity, and finding is a node in a risk graph stored in ArangoDB.

```
Cloud APIs → Ogum.Inventory → ArangoDB Graph
                                    ↓
              Ogum.Static (CSPM) adds findings as nodes
              Ogum.Graph correlates findings into Attack Paths
              Ogum.AI generates remediation PRs
```

See [docs/architecture.md](architecture.md) for the full architecture overview.

---

## Next Steps

- [Connecting Azure and GCP](providers.md) *(coming soon)*
- [Setting up Slack alerts](integrations.md) *(coming soon)*
- [Understanding Attack Paths](attack-paths.md) *(coming soon)*
- [AI-powered remediation](remediation.md) *(coming soon)*
- [API Reference](api/) *(coming soon)*

---

## Troubleshooting

**ArangoDB fails to start:**
```bash
# Check logs
docker compose logs arangodb

# Common fix: increase Docker memory limit to 4GB minimum
```

**Ollama model not loading:**
```bash
# Pull the model manually
docker compose exec ollama ollama pull llama3:8b-instruct
```

**Discovery takes too long:**
Large AWS accounts (5,000+ resources) can take 15–30 minutes on first discovery.
Rate limiting from AWS IAM is common — Ogum retries automatically with backoff.
Monitor progress:
```bash
docker compose logs -f worker | grep "discover_aws"
```
