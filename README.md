<div align="center">

<img src="docs/assets/ogum-banner.png" alt="Ogum Security" width="100%" />

# Ogum Security

### Open-Source Cloud-Native Application Protection Platform

**Built for Everyone.**

[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](LICENSE)
[![Status: Early Development](https://img.shields.io/badge/Status-Early%20Development-yellow.svg)]()
[![Powered by Prowler](https://img.shields.io/badge/Powered%20by-Prowler%20v5-blue.svg)](https://github.com/prowler-cloud/prowler)
[![Follow the Build](https://img.shields.io/badge/Follow-the%20Build-brightgreen.svg)]()

[What is Ogum?](#-what-is-ogum-security) •
[Features](#-features) •
[Architecture](#-architecture) •
[Getting Started](#-getting-started) •
[Roadmap](#-roadmap) •
[Contributing](#-contributing) •
[Community](#-community)

</div>

---

## The Problem

Enterprise cloud security platforms — Wiz, Orca Security, Prisma Cloud — cost hundreds of thousands of dollars per year, lock your data into third-party infrastructure, and remain out of reach for most engineering teams.

Open-source alternatives (Prowler, Trivy, Falco) are excellent sensors. But they produce thousands of isolated alerts without the cross-context that turns raw findings into business decisions.

**Security teams are drowning in noise. Ogum Security changes that.**

---

## What is Ogum Security?

Ogum Security is an **open-source CNAPP** (Cloud-Native Application Protection Platform) that combines the best open-source security engines under a unified **contextual risk graph** — delivering the disruptive value of Wiz and Orca Security, self-hosted, with no licensing cost.

It is built on top of [Prowler v5](https://github.com/prowler-cloud/prowler) and extends it with:

- **Graph-based risk correlation** — connects isolated findings into visual Attack Paths
- **Side-Scanning (No Production Impact)** — reads VM disk snapshots, Lambda artifacts, and container filesystems without touching production workloads or installing agents
- **Near Real-Time detection** — from cloud event to alert in under 2 seconds
- **AI-powered remediation** — context-aware RAG generates corrective IaC code and opens Pull Requests automatically

> The philosophy: Prowler, Trivy, Checkov, and Falco are the **sensors**. Ogum Security is the **brain** that connects them.

---

## Features

### Unified Asset Inventory
Before scanning for anything, Ogum Security discovers and maps every resource across your cloud environments into a unified, searchable inventory — persisted as a graph in ArangoDB. This is the foundation everything else is built on.

Every EC2 instance, IAM Role, S3 bucket, Lambda function, Kubernetes pod, and network endpoint is catalogued with its relationships to other resources. The graph is structurally complete before a single security check runs.

### Multi-Cloud Coverage
Scan across **AWS, Azure, GCP, Kubernetes, OCI, Alibaba Cloud, GitHub, Microsoft 365, Cloudflare,** and **MongoDB Atlas** — all from a single platform.

### 1,700+ Ready-to-Use Security Checks
Inherited from Prowler v5 and extended, with native mapping to:

| Framework | Coverage |
|---|---|
| CIS Benchmarks | AWS, Azure, GCP, Kubernetes, GitHub |
| NIST 800-53 | Full control mapping |
| PCI DSS v4.0 | Requirements 1–12 |
| SOC 2 Type II | CC series |
| HIPAA | Technical safeguards |
| ISO/IEC 27001 | Annex A controls |
| GDPR / LGPD | Article-level mapping |
| DORA | ICT risk requirements |

### Attack Path Visualization
The core differentiator. Ogum Security crosses findings from multiple layers (network, compute, identity, data) and builds a **graph of real exploitable paths**.

Instead of listing 500 alerts, it shows:

```
Internet Gateway → EC2 (CVE-Critical) → IAM Admin Role → S3 Bucket [PII]
```

That's a **Toxic Combination** — an actual attack chain. Everything else is noise.

### Side-Scanning (No Production Impact)
Inspired by Orca Security's approach. Scans production workloads without installing agents or touching running processes:

- **Virtual Machines (AWS EC2, Azure VM):** creates an ephemeral disk snapshot, mounts it read-only in an isolated analyzer container, scans with Trivy + YARA + secret detectors, then destroys the snapshot immediately — zero CPU impact on production, zero agent installation
- **AWS Lambda:** extracts the deployment artifact via API, scans dependencies and source code in an isolated RAM disk — the function is never invoked
- **Kubernetes containers (runtime):** an ephemeral privileged DaemonSet reads `/proc/<PID>/root` from the host node — the target container never knows it was scanned. Note: this requires a DaemonSet with elevated permissions, not a fully agentless approach

### Near Real-Time Detection
```
CloudTrail / K8s Audit Logs → Vector.dev → Redpanda → Apache Flink CEP → Alert (< 2s)
```

Complex event correlation in memory. Detects multi-step attack patterns that individual log entries would miss.

High-confidence events require **both** a deviation from the per-principal behavioral baseline (typical actions, IPs, regions, user-agent) **and** a match against a known TTP — reducing noise instead of alerting on either condition alone.

### AI-Powered Remediation (Ogum.AI)
A RAG engine that:
1. Retrieves the relevant remediation guide and your infrastructure style from a vector database
2. Injects the actual attack path context from the graph
3. Generates corrective IaC code (Terraform, CloudFormation) tailored to your codebase
4. Opens a Pull Request on your GitHub/GitLab — **never touching production directly**

### Compliance Drift Monitoring
Continuous posture tracking per framework. If a developer opens a port at 3am, Ogum detects the compliance drift within seconds — before the next scheduled audit.

### CIEM — Identity Risk Analysis
- Privilege gap scoring: what a role *can* do vs. what it *actually* does (last 90 days)
- AssumeRole chaining detection: maps hidden privilege escalation paths across roles
- Least-privilege policy generation: Ogum.AI rewrites overpermissive IAM policies from scratch based on actual usage

### Cloud Detection and Response (Ogum.CDR)
When a threat is detected, Ogum doesn't just alert — it acts:

**Tier 1 — Automatic containment (< 10 seconds, no human needed):**
- Disable compromised IAM access key
- Block attacker IP in Security Group
- Apply Kubernetes NetworkPolicy deny-all on compromised pod
- Suspend Azure Entra ID user

**Tier 2 — Guided containment (human approval via Slack/Teams):**
High-impact actions — isolate EC2, terminate deployment, revoke org access — sent as interactive approval requests before executing.

**Forensics first:** before any destructive action, CloudTrail (last 90 min), EBS snapshots, and K8s container logs are captured to an immutable S3 WORM bucket.

> CDR is the only module that modifies cloud resources directly — and only when an active threat demands it. Misconfigurations go through GitOps. Active attackers don't wait for PRs.

### Hybrid Coverage with eBPF Agent
For on-premise servers, edge environments, or unsupported clouds — a lightweight Go + C agent using **eBPF** provides:
- Passive network lineage (no intrusive port scanning)
- Runtime command audit (`sys_enter_execve`)
- Host IAM equivalent (SSH key and sudoer monitoring)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                 Cloud APIs / K8s / On-Premise                    │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                ┌───────────────▼───────────────┐
                │        Ogum.Inventory          │  ← built first
                │   Asset Discovery & Graph      │
                │   Population (all providers)   │
                └───────────────┬───────────────┘
                                │ populates vertices + edges
┌───────────────────────────────▼──────────────────────────────────┐
│                     Ogum.Graph (ArangoDB)                        │
│              Resources · Identities · NetworkEndpoints           │
│              DataAssets · Vulnerabilities · Attack Paths         │
└──────┬──────────────────────────────────────────────────┬────────┘
       ↑                    ↑                             ↑
┌──────┴──────┐  ┌──────────┴───────┐  ┌────────────────┴────────┐
│Ogum.Static  │  │  Ogum.Dynamic    │  │      Ogum.Pulse         │
│Prowler v5   │  │  Side-Scanning   │  │  Redpanda + Flink CEP   │
│+ Checkov    │  │  VM/Lambda/K8s   │  │  NRT < 2s latency       │
└─────────────┘  └──────────────────┘  └─────────────────────────┘
       │ (misconfiguration)                         │ (active threat)
┌──────▼──────────────┐               ┌─────────────▼──────────────┐
│      Ogum.AI        │               │        Ogum.CDR            │
│  RAG + GitOps PRs   │               │  Tier 1: auto < 10s        │
│  never direct cloud │               │  Tier 2: Slack approval     │
└──────┬──────────────┘               └─────────────┬──────────────┘
       └────────────────────┬────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│               Ogum Security UI  ←  FastAPI Gateway               │
│         React 19 · Next.js 15 · React Flow Attack Path Canvas    │
└──────────────────────────────────────────────────────────────────┘
```

**Core stack:** Python 3.12+ · FastAPI · Prowler v5 (`prowler-core`) · ArangoDB · Redpanda · Apache Flink · React 19 · Next.js 15 · Go · eBPF · LangChain · Ollama

---

## Getting Started

> **Early Development Notice:** Ogum Security is actively being built. The stack below starts the infrastructure services. Application code is being developed incrementally — star and watch the repo to follow along.

### Prerequisites

- Docker & Docker Compose
- 8GB RAM minimum (16GB recommended for local Ollama)

### Start the Infrastructure

```bash
git clone https://github.com/ogum-security/ogum-security.git
cd ogum-security

cp .env.example .env
# Edit .env with your cloud credentials and configuration

docker compose up -d
```

This starts:
- **ArangoDB** — graph database (`:8529`)
- **Redis** — task queue and cache (`:6379`)
- **Redpanda** — Kafka-compatible message broker (`:9092`)
- **Qdrant** — vector database for RAG (`:6333`)
- **Ollama** — local LLM runtime (`:11434`)
- **Backend API** — FastAPI (`:8000`, `/docs` for Swagger)
- **Frontend** — Next.js console (`:3000`)

### Connect Your First Cloud Account

```bash
# 1. Register an AWS account and start discovery
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

# 2. View your inventory
open http://localhost:3000/inventory

# 3. Run a CSPM scan (Prowler v5 — 1,700+ checks)
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: dev-tenant" \
  -d '{"provider_id": "<provider_id>", "frameworks": ["CIS-AWS-2.0"]}'

# 4. Export findings as CSV
curl "http://localhost:8000/api/v1/findings/export?format=csv" \
  -H "X-Tenant-ID: dev-tenant" \
  -o findings.csv
```

---

## Roadmap

We are building this in public. Here is where we are and where we are going:

### Phase 1 — MVP ✅ Complete
> Full asset inventory + CSPM with 1,700+ checks + compliance dashboard + IaC scanning

- [x] Project structure and architecture
- [x] Docker Compose dev stack (ArangoDB, Redpanda, Qdrant, Ollama)
- [x] **Ogum.Inventory:** ArangoDB graph schema (resources, identities, network endpoints, data assets)
- [x] **Ogum.Inventory:** AWS asset discovery — built entirely from Prowler v5's full check catalog (single scan is the inventory pass, no separate native discovery)
- [x] **Ogum.Inventory:** Relationship edge creation (BELONGS_TO, ATTACHED_TO, ASSUMES_ROLE, MEMBER_OF, STS_ASSUMEROLE_ALLOW, STORES_SENSITIVE_DATA) derived from scan output, no extra cloud API calls
- [x] **Ogum.Inventory:** Multi-cloud discovery — Azure (VMs, VNets, NSGs, AKS, Storage, Key Vault), GCP (Compute, GCS, GKE), Kubernetes (Pods, Deployments, Services, Nodes)
- [x] **Ogum.Inventory:** Inventory REST API — filtering, pagination, full-text search, resource detail with graph edges
- [x] **Ogum.Inventory:** Inventory UI — searchable asset table with multi-select filters (provider, category, region, account), clickable summary cards, detail panel, skeleton loading
- [x] **Ogum.Inventory:** Scheduled auto-scan (Celery Beat every 6h, Redis distributed lock)
- [x] **Ogum.Inventory:** Provider onboarding wizard — connect AWS/Azure/GCP/K8s from the UI
- [x] **Ogum.Inventory:** Inventory export — CSV and OCSF-inspired JSON via streaming API
- [x] **Ogum.Inventory:** Tenant isolation — separate ArangoDB database per tenant, 5 security tests blocking in CI
- [x] **Ogum.Static:** FastAPI + Prowler v5 (`prowler-core`) — 1,700+ checks, multi-cloud
- [x] **Ogum.Static:** Scan orchestration via Celery workers (AWS, Azure, GCP, Kubernetes)
- [x] **Ogum.Static:** Findings API — filtering by provider, severity, framework, region; keyset pagination
- [x] **Ogum.Static:** Compliance posture dashboard (CIS, NIST 800-53, PCI DSS v4.0, SOC 2, ISO 27001)
- [x] **Ogum.Static:** Findings console — severity filters, detail panel, CLI remediation commands, mute/accept
- [x] **Ogum.Static:** IaC scanning with Checkov (Terraform, CloudFormation, Kubernetes manifests)
- [x] **Ogum.Static:** Findings export (CSV + OCSF JSON streaming)
- [x] **Ogum.Static:** Post-scan inventory enrichment — CSPM findings automatically populate resource graph
- [ ] Multi-tenant OIDC authentication (Ogum.Auth) — Phase 3

### Phase 2 — Alpha (In Progress 🔨)
> Attack paths, contextual risk, side-scanning, and CIEM. AI remediation next.

- [x] **Ogum.Graph:** Contextual Risk Scoring engine (0–100, severity × exposure × blast radius)
- [x] **Ogum.Graph:** Attack Path detection — AQL traversal up to 4 hops, Toxic Combination rules
- [x] **Ogum.Graph:** Attack Path list UI with risk score, entry→target route, severity grouping
- [x] **Ogum.Graph:** Attack Path canvas (React Flow) — custom node types, dagre layout, animated edges
- [x] **Ogum.Graph:** CIEM static analysis — dangerous IAM permissions (18 actions), AssumeRole chaining
- [x] **Ogum.Graph:** CIEM UI — identities list with risk score, permissions detail panel
- [x] **Ogum.Dynamic:** Agentless EC2 side-scanning — ephemeral EBS snapshots + Trivy + YARA + secret detection (Sprint 1)
- [ ] **Ogum.Dynamic:** EC2 side-scanning via EBS Direct API — eliminates volume/mount pipeline (Sprint 2)
- [ ] **Ogum.Dynamic:** AWS Lambda artifact scanning
- [ ] **Ogum.Dynamic:** Kubernetes runtime container scanning (DaemonSet)
- [ ] **Ogum.Dynamic:** SBOM generation (CycloneDX) + daily re-scan without new snapshots
- [ ] **Ogum.AI:** RAG remediation engine (LangChain + Ollama)
- [ ] **Ogum.AI:** GitOps PR auto-generation (GitHub/GitLab)
- [ ] **Ogum.Connect:** Jira bidirectional integration
- [ ] **Ogum.Connect:** Slack / MS Teams / Telegram alerts
- [ ] CIEM privilege gap (granted vs. used — requires CloudTrail data from Phase 3)

### Phase 3 — Beta (Planned 📋)
> Real-time detection, enterprise auth, SIEM connectors, and hybrid coverage

- [ ] Near Real-Time pipeline (Redpanda + Apache Flink CEP, < 2s latency)
- [ ] K8s Audit Log and CloudTrail streaming ingestion
- [ ] Falco runtime event integration
- [ ] Signal Score — per-principal behavioral baseline combined with TTP matching for high-confidence prioritization
- [ ] Cloud Detection and Response (Ogum.CDR) — Tier 1 auto-containment + Tier 2 Slack approval
- [ ] OIDC/SAML 2.0 with RBAC (PlatformAdmin, SecOps, DevOps, Auditor)
- [ ] AWS Security Hub bidirectional sync (ASFF format)
- [ ] SIEM forwarding: Splunk, Microsoft Sentinel, Datadog, OpenSearch
- [ ] eBPF agent for on-premise and unsupported environments
- [ ] HashiCorp Vault integration for secrets management
- [ ] Helm chart for production Kubernetes deployment
- [ ] Terraform module for one-click cloud deployment

---

## Contributing

**Ogum Security is being built in the open and we want your help.**

Whether you are a security engineer, cloud architect, backend developer, frontend developer, or technical writer — there is a place for you here.

### Ways to Contribute

- **Star this repository** — it helps others discover the project
- **Watch** — stay updated as we push new code and milestones
- **Open an Issue** — report bugs, request features, or ask questions
- **Submit a Pull Request** — check open issues tagged `good first issue`
- **Share** — tell your team, your network, your security community

### Development Setup

```bash
# Backend (Python)
cd backend
pip install poetry
poetry install
poetry run uvicorn app.main:app --reload --port 8000

# Frontend (Node.js)
cd frontend
npm install
npm run dev

# Agent (Go)
cd agent
go build ./cmd/...
```

See [docs/getting-started.md](docs/getting-started.md) for the full development guide.

### Security Checks and Compliance Rules

One of the fastest ways to contribute is adding new security checks or improving compliance mappings. Ogum Security leverages Prowler v5's check system — new checks are YAML + Python and do not require deep platform knowledge.

---

## Community

This project is in early development. We are building in public and would love for you to follow along.

- **GitHub Issues** — questions, bugs, feature requests: [open an issue](../../issues)
- **GitHub Discussions** — architecture ideas, use case sharing: [start a discussion](../../discussions)
- **Watch the repo** — get notified on every release and milestone

If you are building cloud security tooling, doing pentests, running a SecOps team, or just passionate about open-source security — **this is being built for you**.

---

## Why "Ogum"?

Ogum is the Yoruba deity of iron, technology, and the opening of paths — the one who clears the way forward. In the Afro-Brazilian tradition, Ogum is the warrior who protects and enables progress.

We chose the name because that is exactly what we want this tool to do: **clear the path** through the complexity of cloud security so every team — not just those who can afford enterprise licenses — can protect what they build.

---

## License

Ogum Security is released under the [MIT License](LICENSE).

You are free to use, modify, distribute, and build on top of it — commercially or otherwise — with no restrictions beyond attribution.

---

<div align="center">

**Built for Everyone. By the community. In the open.**

⭐ Star this repository if you believe cloud security should be accessible to all teams.

</div>
