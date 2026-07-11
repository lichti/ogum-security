# Ogum Security — Platform Overview

> This document provides a comprehensive overview of the Ogum Security platform: its purpose, architecture, modules, technology stack, data model, security model, and architectural decisions.

---

## Table of Contents

1. [Vision and Mission](#1-vision-and-mission)
2. [The Problem](#2-the-problem)
3. [The Solution](#3-the-solution)
4. [Personas and Target Market](#4-personas-and-target-market)
5. [Business Model](#5-business-model)
6. [Platform Architecture](#6-platform-architecture)
7. [System Modules](#7-system-modules)
8. [Technology Stack](#8-technology-stack)
9. [Data Model (ArangoDB)](#9-data-model-arangodb)
10. [Security and Multi-Tenancy](#10-security-and-multi-tenancy)
11. [Testing Strategy](#11-testing-strategy)
12. [Architectural Decisions (ADRs)](#12-architectural-decisions-adrs)
13. [References and Inspirations](#13-references-and-inspirations)

---

## 1. Vision and Mission

**Product:** Ogum Security — Open CNAPP ("Built for Everyone")

**Mission:** Democratize enterprise-grade cloud security through an open-source platform that combines the best open-source security engines under a graph-based contextual risk correlation layer.

**Tagline:** *"Built for Everyone"* — enterprise cloud security, accessible to everyone.

Ogum delivers the disruptive value of Wiz and Orca Security, self-hosted, under the MIT license, at zero licensing cost.

---

## 2. The Problem

Enterprise CNAPP tools like **Wiz, Orca Security, and Prisma Cloud** cost between $200,000 and $500,000 per year, require long contracts, and store sensitive security data on third-party infrastructure — a critical blocker for organizations with compliance and data residency requirements.

Existing open-source alternatives — **Prowler, Trivy, Falco** — are excellent individual sensors, but they do not deliver the **cross-domain risk context** that turns 1,000 alerts into actionable business decisions. Security teams know they have issues, but not which ones actually matter.

### The Existing Gap

```
Current open-source tools:               Enterprise tools:
──────────────────────────               ───────────────────────────
✅ Individual CSPM (Prowler)             ✅ Integrated CSPM
✅ CVE scanning (Trivy)                  ✅ Agentless Side-Scanning
✅ Runtime security (Falco)              ✅ Visual Attack Paths
❌ Contextual risk correlation           ✅ Contextual Risk Score
❌ Visual attack paths                   ✅ AI-powered remediation
❌ Automated remediation                 ✅ Integrated CDR
❌ Correlated resource graph             💰 $200k–500k/year
```

---

## 3. The Solution

Ogum Security integrates all pillars of an enterprise CNAPP into a single open-source platform:

| Pillar | Open-Source Engine | Enterprise Inspiration |
|---|---|---|
| CSPM + Compliance | Prowler v5 (`prowler-core`) | Prisma Cloud |
| Agentless Side-Scanning | Trivy + YARA + TruffleHog3 | Orca Security |
| Attack Paths | ArangoDB AQL Traversal | Wiz |
| Contextual Risk Score | Custom algorithm (Severity × Exposure × Blast Radius) | Wiz |
| NRT Detection | Redpanda + Apache Flink CEP | Prisma Cloud CIEM |
| AI-powered Remediation | LangChain + Ollama + Qdrant (RAG) | Wiz AI |
| Runtime Security | Falco + eBPF (Go/C) + YARA | Sysdig |
| Cloud Detection & Response | Custom engine (Tier 1 / Tier 2) | Lacework |

---

## 4. Personas and Target Market

### Beachhead Market

Security teams at organizations with **100–2,000 employees** that:
- Have 2–10 people dedicated to cloud security
- Need compliance (SOC 2, ISO 27001) for audits
- Cannot afford Wiz or Prisma Cloud
- Prefer self-hosted to keep infrastructure data internal

### Personas

| Persona | Role | Primary Pain | Primary Gain |
|---|---|---|---|
| **P1 — SecOps Engineer** | Primary user | 1,000+ findings with no impact context (alert fatigue) | Attack Paths surface the findings that matter + AI generates the fix PR |
| **P2 — DevOps / Cloud Engineer** | Secondary user | Receives security tickets without knowing what to do | Clear playbook + ready-to-review PR |
| **P3 — CISO / Head of Security** | Executive stakeholder | Must present security posture to board and auditors | Compliance dashboard by framework + aggregated ThreatScore |
| **P4 — External Auditor** | Reader | Must validate compliance controls during certification | Read-only access to framework reports, exportable to PDF |

---

## 5. Business Model

Ogum operates on three complementary pillars. **No features are excluded from the MIT release** — paid pillars monetize operations and expertise, not code.

### Pillar 1 — Self-Hosted MIT (free)

- 100% open-source (MIT license), zero licensing cost
- Organizations install and operate on their own infrastructure
- Purpose: organic adoption, community, and lead pipeline for pillars 2 and 3
- Distribution: GitHub, Docker Hub, Helm Chart

### Pillar 2 — Hosted SaaS (paid per tenant/month)

- Ogum operates the infrastructure (multi-tenant, physical ArangoDB database isolation)
- Includes: automated provisioning, managed backups, automatic updates, SLA, ticket-based support
- Target: organizations that want platform value without operational overhead

### Pillar 3 — Support and Consulting (paid per project)

- **Implementation:** installation and configuration of self-hosted Ogum
- **Training:** SecOps and DevOps team enablement
- **Security Assessments:** CSPM + Attack Paths delivered as a service using the platform
- **Custom Integrations:** specific integrations (corporate SIEM, custom ticketing, regional compliance frameworks)
- Target: mid-market organizations without in-house implementation capacity, security consultancies

> There are no features exclusive to paid plans. The code is always MIT. Pillars 2 and 3 monetize **delivery and expertise**, not code access.

---

## 6. Platform Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DATA SOURCES                                 │
│   AWS    Azure    GCP    Kubernetes    GitHub    M365    On-Premise  │
└────────────────────────┬────────────────────────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │   Ogum.Inventory    │  ← LAYER ZERO (implement first)
              │  Discovery + Graph  │    EC2, IAM, S3, RDS, Lambda, EKS,
              │    (ArangoDB)       │    VPC, Pods, ServiceAccounts...
              └──────┬──────┬───────┘
                     │      │ (populates vertices + edges)
          ┌──────────▼──┐ ┌─▼──────────┐ ┌───────────────┐
          │ Ogum.Static │ │Ogum.Dynamic│ │  Ogum.Pulse   │
          │ CSPM + IaC  │ │Side-Scan   │ │ NRT Pipeline  │
          │ Prowler v5  │ │EBS/Lambda  │ │ Redpanda+Flink│
          │ Checkov     │ │K8s /proc   │ │ CEP patterns  │
          └──────┬───────┘ └──────┬─────┘ └──────┬────────┘
                 │                │               │
          ┌──────▼────────────────▼───────────────▼──────┐
          │              Ogum.Graph (ArangoDB)            │
          │   resources  identities  findings  network    │
          │   data_assets  attack_paths  incidents        │
          └──────┬────────────────────────────────────────┘
                 │
         ┌───────┴────────┐
         │                │
   ┌─────▼──────┐  ┌──────▼──────┐
   │  Ogum.AI   │  │  Ogum.CDR   │
   │RAG+GitOps  │  │ Tier 1 auto │
   │LangChain   │  │ Tier 2 appr.│
   │Ollama+Qdrant│ │ < 10s resp. │
   │→ PR on IaC │  │→ Forensics  │
   └─────┬───────┘  └──────┬──────┘
         │                 │
   ┌─────▼─────────────────▼──────┐
   │         Ogum.Connect         │
   │   Slack  Teams  Jira  SIEM   │
   └─────────────┬────────────────┘
                 │
   ┌─────────────▼────────────────┐
   │    Ogum.UI (Next.js 15)      │
   │   + FastAPI Gateway          │
   └──────────────────────────────┘

   ┌──────────────────────────────┐
   │  Ogum.Agent (eBPF / Go)      │  ← DaemonSet or systemd on Linux hosts
   │  tcp_connect  execve  files  │    → publishes to Redpanda (agent-raw-events)
   └──────────────────────────────┘

   ┌──────────────────────────────┐
   │   Ogum.Auth (Cross-cutting)  │
   │  OIDC  SAML  JWT  RBAC      │
   │  Vault  Audit Log  Tenant   │
   └──────────────────────────────┘
```

### Architectural Principles

1. **Inventory-First:** the resource graph is the foundation. No other module operates without it.
2. **GitOps as the sole autocorrection vector:** Ogum.AI never modifies the cloud directly — it only opens PRs.
3. **CDR as the sole GitOps exception:** active threats require immediate containment — they cannot wait for a PR review cycle.
4. **Physical tenant isolation:** one ArangoDB database per tenant (`ogum_<tenant_id>`).
5. **Zero static credentials:** all secrets in HashiCorp Vault. JWT lifetime of 15 minutes.
6. **OCSF as the lingua franca:** all events and findings normalized to the Open Cybersecurity Schema Framework.

---

## 7. System Modules

### 7.0 Ogum.Inventory — Layer Zero

The foundation of the entire platform. Discovers and normalizes all infrastructure resources into a relationship graph in ArangoDB.

**Supported providers:** AWS, Azure, GCP, Kubernetes

**AWS resources discovered:** every resource type covered by a Prowler v5 check — EC2, IAM (Roles, Users, Groups, Policies), S3, RDS, Lambda, EKS, VPC, Security Groups, CloudFront, Route53, KMS, Secrets Manager, ECS, ECR, and more.

**How it works:**
1. Provider connected via IAM Role + AssumeRole (no static credentials)
2. A CSPM scan (Prowler v5's full check catalog) is the sole discovery pass for AWS — `run_cspm_scan(tenant_id, provider_id)` persists findings, then extracts resources/identities/data_assets straight from the scan output (`resource_metadata`)
3. Each resource → vertex in ArangoDB with normalized Pydantic schema
4. Edges derived from the same scan data, no extra AWS API calls: `BELONGS_TO`, `ATTACHED_TO`, `ASSUMES_ROLE`, `MEMBER_OF`, `STS_ASSUMEROLE_ALLOW`, `STORES_SENSITIVE_DATA`, `EXPOSED_TO`
5. Incremental re-discovery: upsert (not truncate), resources absent from a scan marked `status: deleted`
6. Celery Beat: automatic re-scan schedule (default: 6h)

**API:**
- `GET /api/v1/inventory` — paginated list with filters (provider, type, account, region, risk_score)
- `GET /api/v1/inventory/{resource_id}` — detail with relations and associated findings
- `GET /api/v1/inventory/stats` — counters by provider and resource type

---

### 7.1 Ogum.Static — CSPM + IaC

CSPM via Prowler v5 (`prowler-core` as a Python sub-package) and IaC scanning via Checkov.

**Providers:** AWS, Azure, GCP, Kubernetes, OCI, Alibaba, GitHub, M365, Cloudflare, MongoDB Atlas

**Compliance frameworks:** CIS-AWS-2.0, PCI DSS v4, SOC 2, ISO 27001, NIST 800-53, HIPAA, GDPR, LGPD

**How it works:**
1. `POST /api/v1/scans` triggers Celery task `run_cspm_scan(tenant_id, provider_id, frameworks)`
2. Prowler runs via Python sub-package (not subprocess), native OCSF output
3. Findings normalized and persisted with upsert (key: `{check_id}_{resource_arn}_{tenant_id}`)
4. `HAS_FINDING` edge created from the resource vertex to each finding
5. After scan: automatic risk score recalculation + attack path detection

**IaC Scanning (Checkov):**
- Supports Terraform, CloudFormation, Helm Charts
- Shallow clone of repository (token from Vault), analysis, immediate deletion
- Findings with `source: "iac"` — same findings view as CSPM with a distinctive badge

**Features:**
- Compliance dashboard per framework with % score and improvement trend
- Drift detection (current posture vs. previous scan)
- Detail panel: step-by-step remediation + copyable CLI command
- Export to CSV and JSON (OCSF)

---

### 7.2 Ogum.Dynamic — Agentless Side-Scanning

Deep content analysis of resources without installing anything in the production environment.

> **Architectural note:** EC2/Lambda are truly agentless (ephemeral snapshots). Kubernetes requires a privileged DaemonSet — this is a scanner with no impact on the target container, not agentless.

**Supported targets:**

| Target | Mechanism | Tools |
|---|---|---|
| EC2 (AWS) / Azure VM | Ephemeral EBS/Disk snapshot → read-only volume | Trivy, YARA, TruffleHog3 |
| AWS Lambda | Artifact download (ZIP/image) via API | Trivy (deps), TruffleHog3 (secrets) |
| Kubernetes containers | DaemonSet + `/proc/<PID>/root` (no container intrusion) | Trivy rootfs |
| Container Registry (ECR/ACR) | Image pull + layer analysis | Trivy image |

**EC2 scan lifecycle (mandatory):**
```
CreateSnapshot → CopySnapshot (if cross-region) → CreateVolume (read-only)
→ Mount at /mnt/target → Trivy + YARA + TruffleHog3 → Unmount
→ DeleteVolume → DeleteSnapshot ← ALWAYS (in finally{})
```

**What it detects:**
- OS and application dependency CVEs
- Hardcoded secrets and tokens on the filesystem
- Malware, webshells, and cryptominers (YARA rules)
- Vulnerable Lambda dependencies

**Automatic cleanup:** Celery Beat runs every 1h to delete orphaned snapshots tagged `ogum:scan=true` that are past their expiry.

---

### 7.3 Ogum.Graph — Attack Paths and Risk Score

The "brain" of the platform. Correlates resources, findings, and identities to detect attack paths that could compromise sensitive data.

**Risk Score (0–100) per resource:**
```
score = severity_base × exposure_factor × blast_radius_multiplier

severity_base:  CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1 (sum of findings)
exposure_factor: multiplier if public IP or internet-facing
blast_radius:   sensitive entities reachable in ≤ 3 graph hops
```

**Toxic Combination detection (AQL Traversal — max 4 hops, 10s timeout):**
- Internet-facing EC2 → IAM Role → S3 with sensitive data
- Public S3 Bucket containing credentials or secrets
- Overpermissioned Identity reaching a production database
- K8s pod with host network → node → cloud metadata endpoint

**CIEM (Cloud Infrastructure Entitlement Management):**
- Static analysis of dangerous IAM permissions: `iam:*`, `s3:*`, `iam:PassRole`, `sts:AssumeRole` without condition
- AssumeRole chaining detection: A assumes B that assumes C with AdministratorAccess
- Privilege gap (granted vs. used over 90 days) — available in Phase 3 with CloudTrail data

**Visualization (React Flow):**
- Interactive canvas with custom node types: EntryPointNode (red borders), TargetNode (yellow), IdentityNode (purple)
- Automatic layout via dagre/elk
- Left panel with attack path list grouped by severity
- Click on node → detail panel with resource metadata and associated findings

---

### 7.4 Ogum.Pulse — NRT Pipeline

Near-real-time threat detection pipeline. **SLA target: P95 < 2s** from cloud event to UI alert.

**Data flow:**
```
CloudTrail/EventBridge → SQS → [Ogum Ingestor] → Redpanda (raw-events)
                                                         ↓
Azure Activity Log → Event Hub ──────────────── Vector.dev (flatten)
K8s Audit Log → Webhook ──────────────────────────────   ↓
Falco → Falcosidekick ─────────────────────────── Flink OCSF Normalizer
Ogum.Agent → Redpanda (agent-raw-events) ──────────────  ↓
                                                   (normalized-events)
                                                         ↓
                                              Flink CEP Engine
                                                         ↓
                                              (threat-events)
                                                         ↓
                                            CDR Engine + Ogum.Connect
```

**Redpanda topics:**

| Topic | Content | Partitions | Retention |
|---|---|---|---|
| `raw-events` | Raw cloud provider events | 6 | 24h |
| `normalized-events` | OCSF normalized by Flink | 6 | 48h |
| `threat-events` | CEP-detected threats | 3 | 7 days |
| `agent-raw-events` | Ogum.Agent eBPF events | 12 | 4h |

**Built-in CEP patterns:**

| Pattern | Window | Severity |
|---|---|---|
| Reconnaissance (10+ ListAPI across 5 distinct services) | 5 min | HIGH |
| Privilege escalation (CreatePolicyVersion → AttachPolicy → AssumeRole) | 10 min | CRITICAL |
| Data exfiltration (50+ s3:GetObject on a never-before-accessed bucket) | 2 min | CRITICAL |
| Lateral movement (cross-account AssumeRole chaining) | 15 min | HIGH |
| K8s exec abuse (exec into privileged production pod) | 1 min | CRITICAL |
| Process behavioral anomaly (deviation from 30-day baseline) | 30 min | HIGH |

---

### 7.5 Ogum.AI — Intelligent Remediation and GitOps

RAG-powered AI that generates corrective Terraform/CloudFormation code and opens Pull Requests directly in the customer's IaC repository.

> **Inviolable principle:** Ogum.AI NEVER modifies the cloud directly. Every output is a Pull Request. The customer reviews, approves, and their CI/CD pipeline applies it.

**Remediation flow:**
```
Selected finding
       ↓
RAG Search (Qdrant) ← remediation knowledge base (50+ guides)
       ↓
Graph Context (AQL) ← attack paths that include the finding
       ↓
IaC Style Detection ← shallow repo clone (conventions, naming)
       ↓
LLM (Ollama/Llama-3 or OpenAI) ← generates minimal Terraform diff
       ↓
terraform validate + Checkov ← BLOCKING: failed? Stop here.
       ↓
GitHub/GitLab PR ← branch ogum/fix-{check_id}-{resource_id}
```

**Mandatory validation before any PR:**
- `terraform validate` must pass
- Checkov must find no CRITICAL/HIGH findings in the generated code
- If any validation fails → PR is not opened → errors returned to the user

**Components:**
- **Qdrant:** vector DB with remediation guide embeddings (`remediation_guides` collection)
- **LangChain:** orchestrator (RAG retriever + LLM + GitHub Tool + Jira Tool)
- **Ollama:** default local LLM (Llama-3-8B-Instruct) — no data leaves the infrastructure
- **Cloud LLM:** configurable per tenant (OpenAI, Anthropic — SaaS option)

**Chat interface:**
- Natural language queries about the tenant's actual infrastructure (graph data)
- Dynamic AQL queries generated by the LLM with access RESTRICTED to the tenant's database
- Custom document upload (PDFs, Markdown) indexed in Qdrant

---

### 7.6 Ogum.CDR — Cloud Detection and Response

Active threat containment. The sole exception to the platform's GitOps principle.

**Two response tiers:**

| Tier | Criterion | Execution | Latency | Examples |
|---|---|---|---|---|
| **Tier 1** | Reversible action, low blast radius | Automatic | < 10s | Disable IAM key, Block IP in SG, K8s NetworkPolicy deny-all, Suspend Entra user |
| **Tier 2** | High impact or irreversible | Requires SecOps approval via Slack/Teams | Human | Isolate EC2 in quarantine SG, Terminate pod/deployment, Terminate instance (with forensic snapshot) |

**Tier 2 flow:**
```
threat_event detected
       ↓
Mandatory forensic collection BEFORE any action:
  → CloudTrail of the last 90 minutes (WORM S3)
  → Forensic EBS snapshot (never auto-delete — this is evidence)
  → K8s logs (kubectl logs --previous)
       ↓
Slack/Teams: interactive message [✅ Approve] [❌ Reject]
       ↓  (30 min timeout → status: escalated — NEVER auto-executes)
Action executed with full timeline record in the incident
```

**`incidents` collection in ArangoDB:**
- `incident_id`, `status` (active/contained/resolved/false_positive), `severity`, `threat_type`
- `timeline[]`: each event with executor (auto or user_uuid), timestamp, result
- `actions_taken[]`: executed actions with tier, reversibility, original SGs (for manual rollback)
- `evidence[]`: CloudTrail S3 URI + forensic snapshot ID
- `mttr_seconds`: automatically calculated when the incident is marked as resolved

**YAML Playbooks:**
- Custom engine: `trigger → steps[]` mixing Tier 1/Tier 2 actions
- Failed step → logged in timeline, continues (does not abort the playbook)
- Dry-run available: simulates execution without doing anything
- Built-in playbooks: `compromised-iam-key`, `suspicious-ec2-activity`, `k8s-exec-abuse`

---

### 7.7 Ogum.Auth — Authentication and RBAC

Federated OIDC/SAML authentication and role-based access control.

**Authentication flow:**
```
Browser → GET /api/v1/auth/oidc/login?tenant_id={id}
       → Redirect to IdP (Google, Okta, Azure AD, Keycloak)
       → Callback with authorization_code
       → Exchange for id_token (validated: JWKS signature, iss, aud, nonce)
       → Ogum internal JWT (15 min) + refresh token (7 days, rotated)
       → HttpOnly Secure cookie (never localStorage)
```

**Roles and permissions:**

| Role | Can do |
|---|---|
| **PlatformAdmin** | Everything: provision tenants, manage users, configure OIDC, CDR, integrations |
| **SecOps** | Trigger scans, view findings/incidents, approve Tier 2, generate AI PRs, use chat |
| **DevOps** | View findings and inventory, use chat (read-only with limited actions) |
| **Auditor** | Read-only: findings, compliance, audit log, export reports |

**Token revocation:**
- Redis blocklist: `auth:blocklist:{jti}` with TTL = time until token expiry
- Immediate revocation: invalidated token → 401 in < 1ms on next request

**HashiCorp Vault:** all secrets (OAuth tokens, API keys, cloud credentials, OIDC client secrets) stored in Vault with AppRole per tenant. Zero credentials in ArangoDB.

**Append-only audit log:**
- `audit_log` ArangoDB collection with INSERT-only (no UPDATE/REMOVE via API)
- Captured actions: login, logout, role_changed, scan_triggered, finding_muted, cdr_action_executed, cdr_action_approved, pr_opened, export_generated
- Exportable in OCSF for external auditors

---

### 7.8 Ogum.Connect — Integrations

Notifications and integrations with collaboration tools and SIEMs.

**Base infrastructure:**
- Circuit Breaker (`pybreaker`): fail_max=5, reset_timeout=60s — integration failure does not affect Ogum
- Celery task with retry: 3 attempts with exponential backoff (5s, 15s, 45s)
- OCSF as the standard export format

**Supported integrations:**

| Integration | Phase | Features |
|---|---|---|
| **Slack** | 2 | Block Kit alerts, interactive buttons, CDR Tier 2 approval, OAuth App |
| **Microsoft Teams** | 2 | Adaptive Cards, Bot for Tier 2 approval |
| **Jira** | 2 | Automatic ticket creation, bidirectional status sync, severity labels |
| **Generic webhook** | 2 | HTTPS + HMAC signature, JSON or OCSF format |
| **Splunk HEC** | 3 | Batched OCSF events in `ogum:ocsf:finding` sourcetype |
| **Microsoft Sentinel** | 3 | DCR/DCE API, Azure AD auth, configurable stream |
| **Datadog** | 3 | Log Management API v2 with `ogum`, `severity` tags |
| **OpenSearch** | 3 | Bulk index with monthly indices, automatic index template |

---

### 7.9 Ogum.Agent — eBPF Runtime Security

Go + eBPF agent for runtime security monitoring on Linux hosts.

**Technical requirements:**
- Linux kernel ≥ 5.8 (eBPF ring buffer API)
- Go 1.23+ with `cilium/ebpf` library
- Maximum overhead: < 1% CPU, < 50MB RAM on the monitored host
- No persistent disk writes — only `perf_ring_buffer` in memory

**eBPF hooks:**

| Hook | Captures | Detects |
|---|---|---|
| `kprobe/tcp_connect` | pid, comm, src_ip, dst_ip, dst_port, container_id | Connections to threat intel IPs, RATs (port 4444/5555), volume-based exfiltration |
| `tracepoint/syscalls/sys_enter_execve` | pid, ppid, uid, comm, filename, argv[4] | Reverse shells, `curl\|sh`, chmod+execute in /tmp, cron injection |
| `kprobe/vfs_open` | pid, comm, filename, flags | Access to /.aws/credentials, /root/.ssh/, /etc/shadow, .pem files |
| `inotify` (userspace) | path, event_type | Modification of /etc/cron.d/, /etc/sudoers.d/, /root/.bashrc |

**Threat intelligence:**
- BPF Map `threat_ip_set` updated every 5 min with IPs from AbuseIPDB + OTX AlienVault
- Kernel-level lookup (not userspace) — zero overhead for non-listed IPs

**Authentication:**
- Vault AppRole with Secret ID rotated on each deploy
- Token automatically renewed at `TTL × 0.75`

**Deployment:**
- Kubernetes DaemonSet (Helm Chart at `infra/helm/ogum-agent/`)
- Linux packages: `.deb` and `.rpm` with systemd unit (`ogum-agent.service`)
- One-liner install: `curl https://install.ogum.security | sh`

---

## 8. Technology Stack

### Backend

| Component | Technology | Target version |
|---|---|---|
| Runtime | Python | 3.13+ |
| API Framework | FastAPI | ^0.115 |
| Data models | Pydantic v2 | ^2.7 |
| Task Queue | Celery | ^5.4 |
| CSPM Engine | prowler-core | ^5.31 |
| IaC Scanner | Checkov | ^3.x |
| RAG Orchestrator | LangChain | ^0.3 |
| Local LLM | Ollama (Llama-3-8B-Instruct) | latest |
| Dependency management | Poetry | ^1.8 |

### Databases and Messaging

| Component | Technology | Target version |
|---|---|---|
| Graph + documents | ArangoDB Community Edition | 3.12 |
| Vector DB | Qdrant | ^1.10 |
| NRT Broker | Redpanda | v23.3+ |
| Cache + Task Broker | Redis | 7+ |
| CEP Processing | Apache Flink (PyFlink) | 1.19 |
| Event normalization | Vector.dev | latest |
| Secrets | HashiCorp Vault | ^1.17 |

### Frontend

| Component | Technology |
|---|---|
| Framework | Next.js 15 (App Router) |
| Language | TypeScript |
| UI Components | shadcn/ui + Tailwind CSS |
| Graph visualization | @xyflow/react (React Flow v12) |
| Tables | TanStack Table |
| Server state | TanStack Query (React Query v5) |
| Component tests | Jest + React Testing Library |
| E2E tests | Playwright |

### eBPF Agent

| Component | Technology |
|---|---|
| Language | Go 1.23+ + C (eBPF programs) |
| eBPF library | github.com/cilium/ebpf |
| Kafka client | github.com/segmentio/kafka-go |
| Vault client | github.com/hashicorp/vault/api |
| Serialization | Protocol Buffers |
| eBPF compiler | clang/llvm |

---

## 9. Data Model (ArangoDB)

### Vertex Collections

| Collection | Represents | Key fields |
|---|---|---|
| `resources` | Infrastructure assets (EC2, S3, Lambda, pods…) | `provider`, `resource_type`, `arn`, `risk_score`, `in_attack_path` |
| `identities` | IAM Roles, Users, ServiceAccounts | `granted_actions[]`, `used_actions_90d[]`, `privilege_gap_score` |
| `vulnerabilities` | Findings (Prowler, CVE, secrets) | `check_id`, `severity`, `status`, `frameworks[]`, `source` |
| `network_endpoints` | Security Groups, open ports, IGWs | `protocol`, `port`, `cidr`, `is_public` |
| `data_assets` | S3 buckets, RDS, databases | `contains_pii`, `contains_pci`, `classification_tags[]` |
| `attack_paths` | Detected attack paths | `risk_score`, `is_toxic_combination`, `nodes[]`, `edges[]`, `hops` |
| `incidents` | CDR incidents | `status`, `timeline[]`, `actions_taken[]`, `evidence[]`, `mttr_seconds` |
| `audit_log` | Immutable action log | `actor_id`, `action`, `resource_type`, `result`, `ip_address` |
| `users` | Users per tenant | `sub` (IdP), `role`, `last_login` |
| `agents` | Registered Ogum.Agent instances | `hostname`, `status`, `hooks_active[]`, `last_heartbeat` |

### Edge Collections

| Edge | From | To | Represents |
|---|---|---|---|
| `EXPOSED_TO` | `network_endpoints` | `resources` | Resource exposed by a SG/firewall rule |
| `ASSUMES_ROLE` | `resources` | `identities` | EC2/Pod assumes an IAM Role |
| `HAS_FINDING` | `resources` | `vulnerabilities` | Resource has an associated finding |
| `STORES_SENSITIVE_DATA` | `identities` | `data_assets` | Identity has access to sensitive data |
| `ROUTES_TRAFFIC` | `network_endpoints` | `network_endpoints` | IGW → SG → ENI |
| `BELONGS_TO` | `resources` | `resources` | Resource belongs to another (pod → node → VPC) |
| `COMMUNICATED_WITH` | `resources` | `resources` | Network event detected by the agent |
| `DETECTED_ON` | `attack_paths` | `resources` | Attack path detected on a resource |

### Attack Path Query (AQL reference)

```aql
FOR ep IN network_endpoints
  FILTER ep.tenant_id == @tenant_id
  FILTER ep.is_public == true
  FOR v, e, p IN 1..4 OUTBOUND ep
    EXPOSED_TO, ASSUMES_ROLE, HAS_FINDING, STORES_SENSITIVE_DATA, ROUTES_TRAFFIC
    FILTER v._id LIKE "data_assets/%"
    FILTER v.contains_pii == true OR v.contains_pci == true
    SORT SUM(p.vertices[*].base_severity) DESC
    RETURN {
      attack_path: p.vertices[*].name,
      path_ids:    p.vertices[*]._id,
      risk_score:  SUM(p.vertices[*].base_severity),
      hops:        LENGTH(p.vertices) - 1
    }
```

**Performance constraints:** max_depth=4, timeout=10s, indexes on `tenant_id + risk_score`.

---

## 10. Security and Multi-Tenancy

### Tenant Isolation

The isolation model is **physical** — each tenant has its own ArangoDB database:

```
ArangoDB Instance
├── _system              ← global metadata (tenant list)
├── ogum_tenant-aaa-xxx  ← all collections for tenant A
├── ogum_tenant-bbb-yyy  ← all collections for tenant B
└── ogum_tenant-ccc-zzz  ← all collections for tenant C
```

**Why separate databases (instead of a `tenant_id` filter field):**
- A query bug in a shared collection → cross-tenant data leak
- Separate database: impossible to leak by bug — the client is connected to the wrong database and finds nothing
- Per-tenant backup, restore, and data deletion are native operations

**Database selection per request:**
```python
# In get_current_user (deps.py)
db = arango_client.db(f"ogum_{current_user.tenant_id}")
# Injected via Depends into ALL endpoints
```

### Cloud Credential Model

Ogum accesses customer infrastructure **without static credentials**:

1. **Discovery (read-only):** IAM Role with `ReadOnlyAccess` + Prowler-specific policies. Ogum assumes the role via `sts:AssumeRole` with a unique `ExternalId` per tenant.
2. **Side-Scanning (snapshot):** Additional IAM Role with snapshot permissions. Scope: `ec2:CreateSnapshot`, `ec2:DeleteSnapshot`, `ec2:CreateVolume`, `ec2:DeleteVolume`.
3. **CDR (write):** IAM Role with strict Permission Boundary. Minimum scope per action type (disable key, revoke SG rule). Credentials are separate from read credentials.

### JWT and Authentication

- Access token: HS256-signed JWT, 15 min TTL, fields: `sub`, `tenant_id`, `role`, `jti`
- Refresh token: 7 days, rotated on each use
- Revocation: Redis blocklist by `jti` — lookup < 1ms
- Cookies: `HttpOnly`, `Secure`, `SameSite=Strict` — never localStorage

### Security Tests (blocking in CI)

Failing any of these blocks the merge:
- Tenant A cannot access tenant B's data → 403
- Request without token → 401 on all protected endpoints
- Insufficient role → 403 (DevOps cannot trigger CDR Tier 2)
- CDR Tier 2 action without approval → `APPROVAL_REQUIRED` error
- Audit log entry created for every CDR action

---

## 11. Testing Strategy

### Test Layers

| Layer | What it covers | External deps | Speed |
|---|---|---|---|
| **Unit** | Pure logic, Pydantic models, algorithms | None | < 1s |
| **Integration** | API endpoints, Celery tasks, ArangoDB queries | Real ArangoDB + Redis | < 10s |
| **Security** | Tenant isolation, RBAC, CDR authorization | Real ArangoDB | < 10s |
| **E2E** | Critical user flows in browser (Playwright) | Full stack | < 60s |

### Non-Negotiable Rules

**ArangoDB: NEVER mock.** Use a real instance via Docker in all tests. Rationale: mock/prod divergence caused production failures that tests did not catch.

**Cloud APIs (boto3, azure-sdk, gcp): ALWAYS mock at the SDK level.** Use `moto` for AWS, `pytest-mock` for Azure/GCP. Fixture responses in `tests/fixtures/aws/`.

**Celery:** EAGER mode (`CELERY_TASK_ALWAYS_EAGER=True`) in unit tests; real worker in integration tests.

### Minimum Coverage (CI blocks below these thresholds)

| Module | Minimum coverage |
|---|---|
| `backend/app/services/` | 80% |
| `backend/app/api/` | 80% |
| `backend/app/models/` | 90% |
| `frontend/src/components/ui/` | 70% |
| `agent/pkg/` | 60% |

### pytest markers

```python
@pytest.mark.unit          # no external dependencies
@pytest.mark.integration   # requires ArangoDB + Redis
@pytest.mark.security      # tenant isolation and auth — BLOCKING in CI
@pytest.mark.e2e           # Playwright — full stack
```

---

## 12. Architectural Decisions (ADRs)

| ADR | Decision | Status |
|---|---|---|
| **ADR-001** | ArangoDB Community Edition for graph + documents | Accepted |
| **ADR-002** | `prowler-core` as Python sub-package, not subprocess or prowler-api | Accepted |
| **ADR-003** | GitOps as the sole autocorrection vector (Ogum.AI only opens PRs) | Accepted |
| **ADR-004** | Redpanda (Kafka-compatible) as NRT broker (no JVM, no Zookeeper) | Accepted |
| **ADR-005** | Business model: self-hosted MIT + Hosted SaaS + Support and Consulting | Accepted |
| **ADR-006** | CDR is the sole exception to the GitOps principle | Accepted |
| **ADR-007** | Qdrant as vector DB (vs. Milvus — lighter, better single-node for MVP) | Accepted |
| **ADR-008** | LangChain as RAG orchestrator (vs. LlamaIndex — Tool Use required for GitHub PR + Jira) | Accepted |
| **ADR-009** | Separate ArangoDB database per tenant (`ogum_<tenant_id>`) | Accepted |

### Documented Limitations

- **SmartGraphs (ArangoDB):** Enterprise feature — not available in Community Edition. For scale beyond 10M+ vertices per tenant, evaluate migration to Enterprise or manual sharding.
- **CIEM privilege gap:** "granted vs. used" analysis only available in Phase 3 (requires CloudTrail data via Ogum.Pulse). Static analysis of dangerous permissions is implemented in Phase 2.
- **K8s Side-Scanning:** requires a privileged DaemonSet — not agentless. Documented as "scanner with no impact on the target container."
- **Windows Server:** not supported by Ogum.Agent (eBPF is Linux-only).

---

## 13. References and Inspirations

### Tools Ogum Integrates

| Tool | Role in Ogum |
|---|---|
| [Prowler v5](https://github.com/prowler-cloud/prowler) | CSPM engine (prowler-core) |
| [Checkov](https://github.com/bridgecrewio/checkov) | IaC scanner |
| [Trivy](https://github.com/aquasecurity/trivy) | CVE scanning in side-scanning and containers |
| [YARA](https://github.com/VirusTotal/yara) | Malware detection in side-scanning |
| [TruffleHog3](https://github.com/trufflesecurity/trufflehog) | Exposed secrets detection |
| [Falco](https://github.com/falcosecurity/falco) | K8s runtime security (event source) |
| [cilium/ebpf](https://github.com/cilium/ebpf) | eBPF library for the Go agent |
| [LangChain](https://github.com/langchain-ai/langchain) | RAG orchestrator + Tool Use |
| [Ollama](https://github.com/ollama/ollama) | Local LLM (Llama-3) |
| [Qdrant](https://github.com/qdrant/qdrant) | Vector DB for RAG |
| [ArangoDB](https://github.com/arangodb/arangodb) | Risk graph + document store |
| [Redpanda](https://github.com/redpanda-data/redpanda) | Kafka-compatible NRT broker |
| [Apache Flink](https://github.com/apache/flink) | Complex Event Processing (CEP) |
| [Vector.dev](https://github.com/vectordotdev/vector) | Lightweight event normalization |

### Product Inspirations

| Product | What it inspired |
|---|---|
| **Wiz** | Visual attack paths, contextual risk score, toxic combinations |
| **Orca Security** | Agentless side-scanning via ephemeral snapshots |
| **Prisma Cloud** | Multi-cloud CSPM + CIEM + NRT pipeline |
| **Lacework** | CDR with playbooks and incident management |
| **Sysdig** | Runtime security with eBPF + Falco |

### Standards and Specifications

| Standard | Usage |
|---|---|
| [OCSF](https://schema.ocsf.io/) | Universal output format for findings and events |
| [SARIF](https://sarifweb.azurewebsites.net/) | IaC scan output for GitHub Security tab |
| [OIDC](https://openid.net/developers/how-connect-works/) | Federated authentication (Phase 1) |
| [SAML 2.0](https://www.oasis-open.org/standard/saml/) | Enterprise authentication (Phase 3) |
| [CIS AWS Foundations](https://www.cisecurity.org/benchmark/amazon_web_services) | Default compliance framework |
