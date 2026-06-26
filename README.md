<div align="center">

<img src="docs/assets/ogum-banner.png" alt="Ogum Security" width="100%" />

# Ogum Security

### Open-Source Cloud-Native Application Protection Platform

**Built for Everyone.**

[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](LICENSE)
[![Status: Early Development](https://img.shields.io/badge/Status-Early%20Development-yellow.svg)]()
[![Powered by Prowler](https://img.shields.io/badge/Powered%20by-Prowler%20v4-blue.svg)](https://github.com/prowler-cloud/prowler)
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

It is built on top of [Prowler v4](https://github.com/prowler-cloud/prowler) and extends it with:

- **Graph-based risk correlation** — connects isolated findings into visual Attack Paths
- **Agentless Side-Scanning** — reads VM disks, Lambda artifacts, and container filesystems without touching production workloads
- **Near Real-Time detection** — from cloud event to alert in under 2 seconds
- **AI-powered remediation** — context-aware RAG generates corrective IaC code and opens Pull Requests automatically

> The philosophy: Prowler, Trivy, Checkov, and Falco are the **sensors**. Ogum Security is the **brain** that connects them.

---

## Features

### Multi-Cloud Coverage
Scan across **AWS, Azure, GCP, Kubernetes, OCI, Alibaba Cloud, GitHub, Microsoft 365, Cloudflare,** and **MongoDB Atlas** — all from a single platform.

### 1,700+ Ready-to-Use Security Checks
Inherited from Prowler v4 and extended, with native mapping to:

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

### Agentless Side-Scanning
Inspired by Orca Security's approach:

- **Virtual Machines:** creates an ephemeral EBS snapshot, mounts it read-only in an isolated analyzer, scans with Trivy + YARA + secret detectors, then destroys the snapshot — zero agent installation, zero CPU impact on production
- **AWS Lambda:** extracts the deployment artifact via API, scans dependencies and source code for vulnerabilities and hardcoded secrets in an isolated RAM disk
- **Kubernetes containers (runtime):** a privileged DaemonSet reads `/proc/<PID>/root` from the host node — the target container never knows it was scanned

### Near Real-Time Detection
```
CloudTrail / K8s Audit Logs → Vector.dev → Redpanda → Apache Flink CEP → Alert (< 2s)
```

Complex event correlation in memory. Detects multi-step attack patterns that individual log entries would miss.

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

### Hybrid Coverage with eBPF Agent
For on-premise servers, edge environments, or unsupported clouds — a lightweight Go + C agent using **eBPF** provides:
- Passive network lineage (no intrusive port scanning)
- Runtime command audit (`sys_enter_execve`)
- Host IAM equivalent (SSH key and sudoer monitoring)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Ogum Security UI                         │
│              (React 19 + Next.js 15 + React Flow)               │
└────────────────────────────┬────────────────────────────────────┘
                             │ REST / WebSocket
┌────────────────────────────▼────────────────────────────────────┐
│                      FastAPI Gateway                            │
└──────┬──────────────────────────────────────────────────┬───────┘
       │                                                  │
┌──────▼──────┐  ┌──────────────┐  ┌──────────────┐  ┌───▼──────┐
│Ogum.Static  │  │ Ogum.Dynamic │  │  Ogum.Pulse  │  │ Ogum.AI  │
│Prowler v4   │  │Side-Scanning │  │  Redpanda +  │  │RAG+GitOps│
│+ Checkov    │  │VM/Lambda/K8s │  │  Flink CEP   │  │  Ollama  │
└──────┬──────┘  └──────┬───────┘  └──────┬───────┘  └───┬──────┘
       │                │                 │               │
       └────────────────▼─────────────────▼───────────────┘
                        │         Ogum.Graph
                        │      (ArangoDB Multi-Model)
                        │   Vertices + Edges = Attack Paths
                        └──────────────────────────────────
```

**Core stack:** Python 3.11 · FastAPI · Prowler v4 · ArangoDB · Redpanda · Apache Flink · React 19 · Next.js 15 · Go · eBPF · LangChain · Ollama

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

### Run Your First Scan (coming in Phase 1)

```bash
# Via API
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "accounts": ["123456789012"],
    "compliance_frameworks": ["CIS-AWS-2.0", "SOC2"]
  }'
```

---

## Roadmap

We are building this in public. Here is where we are and where we are going:

### Phase 1 — MVP (In Progress 🔨)
> Core scanning engine and compliance dashboard

- [x] Project structure and architecture
- [x] Docker Compose dev stack (ArangoDB, Redpanda, Qdrant, Ollama)
- [ ] FastAPI backend with Prowler v4 integration
- [ ] ArangoDB graph schema (resources, identities, vulnerabilities)
- [ ] Scan orchestration via Celery workers
- [ ] Findings API with filtering (provider, severity, framework)
- [ ] Multi-tenant OIDC authentication
- [ ] Compliance posture dashboard (CIS, NIST, PCI DSS, SOC 2)
- [ ] Next.js 15 findings console with remediation panel

### Phase 2 — Alpha (Planned 📋)
> Graph risk engine, side-scanning, and AI remediation

- [ ] Attack Path graph visualization (React Flow canvas)
- [ ] Toxic Combination detection (AQL traversal queries)
- [ ] Contextual Risk Scoring engine
- [ ] Agentless VM side-scanning (AWS EC2 EBS snapshots)
- [ ] AWS Lambda artifact scanning
- [ ] Kubernetes runtime container scanning (DaemonSet)
- [ ] Ogum.AI RAG remediation engine (LangChain + Ollama)
- [ ] GitOps PR auto-generation (GitHub/GitLab)
- [ ] CIEM: privilege gap analysis and escalation path detection
- [ ] Jira bidirectional integration
- [ ] Slack / MS Teams / Telegram alerts

### Phase 3 — Beta (Planned 📋)
> Real-time detection, enterprise auth, and hybrid coverage

- [ ] Near Real-Time pipeline (Redpanda + Apache Flink CEP)
- [ ] K8s Audit Log and CloudTrail streaming ingestion
- [ ] Falco runtime event integration
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

One of the fastest ways to contribute is adding new security checks or improving compliance mappings. Ogum Security leverages Prowler v4's check system — new checks are YAML + Python and do not require deep platform knowledge.

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
