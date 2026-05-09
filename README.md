# 🛡️ AegisTwin — Dual-Agent AI Cybersecurity Platform

> **Status:** Early-stage research prototype · Not production-ready for live red-teaming · Seeking contributors

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue)](https://www.python.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## 🎯 Vision

AegisTwin aspires to be an **autonomous, dual-agent AI cybersecurity platform** inspired by:

- **[HPTSA](https://arxiv.org/abs/2406.05498)** (Hierarchical Planning and Task-Specific Agents, UIUC 2024) — multi-agent architecture where a planning supervisor orchestrates specialist sub-agents for autonomous vulnerability discovery
- **[AISLE](https://aisle.com)** — AI Cyber Reasoning System that creates a digital twin of an organisation's software stack, autonomously finds exploitable vulnerabilities, generates patches, and raises verified PRs
- **Claude Mythos** — The concept of AI agents that reason about their own capabilities, maintain consistent epistemic state, and explain their decisions in auditable chains

**The core idea:** Two AI agents — an **Offensive Red Team** and a **Defensive Threat Hunter** — share a live *Company Digital Twin* (real asset inventory, CVE feeds, network topology). The red agent probes weaknesses; the blue agent detects the probes and hardens the defences. They race each other, producing measurable security posture improvements continuously.

---

## ✅ What We Have Actually Built

| Component | Status | Notes |
|-----------|--------|-------|
| FastAPI backend with JWT auth | ✅ Working | `/auth`, `/tenants`, `/assets`, `/findings` endpoints |
| PostgreSQL schema + Alembic migrations | ✅ Working | Multi-tenant isolation, immutable audit log trigger |
| React + Vite frontend dashboard | ✅ Working | 11 pages: Digital Twin, Attack Graph, Mission Control, etc. |
| Celery + Redis worker queue | ✅ Working | Background scan tasks dispatch correctly |
| Docker Compose full-stack | ✅ Working | `docker-compose up` starts all 5 services |
| Offensive agent scaffold | ✅ Scaffold | Agent class exists, LLM stub wired, tool broker defined |
| Defensive agent scaffold | ✅ Scaffold | Detection draft generation stub present |
| OSV.dev CVE integration | ✅ Working | Live dependency audit via public API |
| Dynamic fuzzer module | ✅ Working | HTTP fuzzing with TLS control |
| Attack graph engine | ✅ Scaffold | Node/edge model built, pathfinding not yet intelligent |
| Policy engine | ✅ Working | Scope enforcement, tenant isolation, read-only constraints |
| Deception fabric (honeypots) | ✅ Scaffold | Endpoint stubs present, no real decoy deployment |

---

## ❌ What We Have NOT Yet Achieved

### 1. Real Autonomous Agent Intelligence
The agents are **scaffolds with LLM stubs**. They do not yet:
- Autonomously select TTPs (Tactics, Techniques, Procedures) from the MITRE ATT&CK framework
- Plan multi-step attack chains without human guidance
- Learn from failed attempts and adapt strategy (no RL loop)

**Why:** Building a real HPTSA-style planning layer requires a fine-tuned or carefully prompted LLM that has been evaluated for cyber reasoning. We haven't validated any specific LLM for this task yet.

### 2. Verified Patch Generation (AISLE-style)
We detect CVEs but do not auto-generate or verify code patches. AISLE uses a CRS (Cyber Reasoning System) trained on exploit/patch pairs — a capability that takes 6–12 months of ML infrastructure work.

### 3. Live Network Integration
The Digital Twin is seeded with demo data. It cannot currently:
- Ingest live asset inventory from AWS/GCP/Azure via cloud APIs
- Pull real CVE matches for your actual dependency tree
- Connect to SIEM streams (Splunk, Elastic SIEM)

### 4. Red Agent ↔ Blue Agent Adversarial Loop
The two agents do not yet communicate or compete. The closed-loop "Red finds → Blue detects → system hardens" cycle is the end goal but is not running.

---

## 🚀 Quick Start

```bash
git clone https://github.com/GokulDubbaka/aegistwin.git
cd aegistwin
cp .env.example .env          # edit with your secrets
docker-compose -f infra/docker-compose.yml up --build
# Open http://localhost:5173
```

**Manual setup (without Docker):**
```bash
cd backend
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload

cd frontend
npm install
npm run dev
```

---

## 🤝 How You Can Help

We are actively seeking collaborators in these specific areas:

### 🧠 AI / ML
- **LLM reasoning for cyber tasks:** Help us design and evaluate prompts (or fine-tune a small model) that can reason about MITRE ATT&CK TTPs, plan multi-step attack chains, and explain decisions
- **Reinforcement Learning loop:** Design a reward function for the red/blue adversarial cycle — what does "better security posture" look like as a numerical signal?
- **Cyber knowledge graph:** Help build the semantic layer connecting CVEs → exploits → affected asset types → mitigations

### 🔒 Security Engineering
- **Real asset ingestion:** Integrate AWS Config, GCP Asset Inventory, Azure Resource Graph APIs so the Digital Twin reflects real infrastructure
- **SIEM connectors:** Write parsers for Splunk/Elastic/Sentinel alert formats
- **Exploit validation:** Help design a safe, sandboxed environment where the offensive agent can *actually* test payloads (CTF-style isolated lab)

### 🏗️ Backend / Infrastructure
- **Celery task hardening:** Distributed job queuing for large-scale parallel scans
- **Flower monitoring:** Fix the Celery Flower service configuration for production observability
- **Rate limiting & throttling:** Protect the API from scan abuse

### 🎨 Frontend
- **Attack graph visualisation:** The current D3 graph is static — needs live WebSocket updates
- **Real-time streaming dashboard:** Replace polling with WebSocket streams from the Celery workers

> Open an issue or start a Discussion if you want to contribute. All experience levels welcome.

---

## ⚠️ Ethics & Legal

AegisTwin is designed **strictly for authorised security testing**. The offensive agent will only operate within explicitly defined scope. The policy engine enforces this at code level. Never use this against systems you do not own or have written permission to test.

---

## 📄 License

MIT — see [LICENSE](LICENSE)
