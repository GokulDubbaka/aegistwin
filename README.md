<div align="center">

# 🛡️ AegisTwin

**Dual-agent AI cybersecurity platform: Offensive Red Team + Defensive Hunter sharing a live Company Digital Twin.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18%2B-61DAFB?logo=react)](https://react.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15%2B-336791?logo=postgresql)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](https://docker.com)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Red Team attacks. Blue Team hunts. Both share one living model of your company.*

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [API Docs](#-api-docs)

</div>

---

## ✨ Features

### 🔴 Offensive Agent (Red Team)
- **Autonomous mission planning** — AI generates and executes attack scenarios against the digital twin
- **Attack Path Graph** — Visual kill-chain mapping (Initial Access → Lateral Movement → Impact)
- **MITRE ATT&CK mapping** — Every finding tagged to technique IDs
- **Deception deployment** — Plants honeytokens, honey credentials, and canary documents

### 🔵 Defensive Agent (Blue Team)
- **Real-time threat detection** — Monitors the digital twin for anomalous patterns
- **Actor fingerprinting** — Clusters attacker behavior by timing, tool signatures, and TTP patterns
- **Detection drafts** — AI generates Sigma/YARA rules from live attack observations
- **Remediation queue** — Prioritized fix list with severity scoring and effort estimates

### 🏢 Shared Digital Twin
- **Asset inventory** — All company assets with criticality and data sensitivity scores
- **Risk engine** — Continuous attack surface scoring across all tenant assets
- **Tenant isolation** — Full multi-tenant architecture with row-level security
- **Audit log** — Immutable record of every agentic decision made

### 🖥️ Premium Dashboard
- Real-time charts (Recharts) with live P&L-style risk metrics
- Dark-mode cyberpunk UI built in React + TypeScript
- Pages: Dashboard · Digital Twin · Attack Path Graph · Findings · Offensive Missions · Deception Events · Defensive Hunter · Remediation Queue · Actor Fingerprints

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    React Frontend (Vite + TS)                │
│  Dashboard · DigitalTwin · AttackPathGraph · Findings · ...  │
└──────────────────────┬──────────────────────────────────────┘
                       │ REST API
┌──────────────────────▼──────────────────────────────────────┐
│              FastAPI Backend (Python 3.11)                   │
│                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │  Red Agent  │    │ Blue Agent  │    │ Risk Engine  │      │
│  │ (Offensive) │    │ (Defensive) │    │  (Scoring)   │      │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘      │
│         │                  │                  │              │
│  ┌──────▼──────────────────▼──────────────────▼──────┐      │
│  │            Digital Twin (Shared State)             │      │
│  │         Assets · Findings · Attack Paths           │      │
│  └──────────────────────────┬─────────────────────────┘      │
│                             │                                │
│  ┌──────────────────────────▼─────────────────────────┐      │
│  │       Tool Broker (Nmap · Metasploit · OSINT)      │      │
│  └────────────────────────────────────────────────────┘      │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│              PostgreSQL 15  +  Redis (Celery)                │
└─────────────────────────────────────────────────────────────┘
```

**Project structure:**
```
aegistwin/
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI app entry point
│   │   ├── api/              # REST endpoints (assets, tenants, detections, ...)
│   │   ├── agents/           # Red & Blue agent logic
│   │   ├── core/             # Config, policy engine
│   │   ├── db/               # SQLAlchemy models
│   │   ├── deception/        # Honeytoken / canary fabric
│   │   ├── detections/       # Blue team detection agent
│   │   ├── remediation/      # Fix queue generation
│   │   ├── risk/             # Attack surface scoring engine
│   │   ├── tool_broker/      # Security tool integrations
│   │   └── workers/          # Celery async task queue
│   └── alembic/              # Database migrations
├── frontend/
│   ├── src/
│   │   ├── pages/            # React page components
│   │   ├── api/              # API client + mock data
│   │   └── index.css         # Global cyberpunk design system
│   ├── eslint.config.js      # ESLint (flat config)
│   └── vite.config.ts
├── infra/
│   ├── docker-compose.yml    # ← Run with: docker compose -f infra/docker-compose.yml up --build
│   ├── init.sql              # Database initialization
│   ├── Dockerfile.backend
│   └── Dockerfile.frontend
├── docs/                     # Architecture diagrams
├── .env.example              # Environment template
└── Makefile                  # Dev commands (wraps docker compose)
```

---

## ⚡ Quick Start

### Prerequisites
- **Docker & Docker Compose** (recommended)  
  *or* Python 3.11+ + Node.js 18+ + PostgreSQL 15

### Option A: Docker (Recommended)

```bash
git clone https://github.com/GokulDubbaka/aegistwin.git
cd aegistwin

cp .env.example .env
# Edit .env with your values

# docker-compose.yml lives in infra/
docker compose -f infra/docker-compose.yml up --build
```

Open:
- **Frontend:** http://localhost:80
- **API Docs:** http://localhost:8000/docs

### Option B: Manual Setup

```bash
# 1. Backend
cd backend
pip install -r requirements.txt        # install dependencies
alembic upgrade head                   # run database migrations
uvicorn app.main:app --reload --port 8000

# 2. Frontend (new terminal)
cd frontend
npm install
npm run dev                            # starts on http://localhost:5173
```

> **Note:** For manual setup, set `DATABASE_URL` and `REDIS_URL` in your `.env` before running.

---

## ⚙️ Configuration

Copy `.env.example` to `.env`:

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `REDIS_URL` | ✅ | Redis for Celery task queue |
| `SECRET_KEY` | ✅ | JWT signing secret (generate with `openssl rand -hex 32`) |
| `ALLOWED_ORIGINS` | ✅ | CORS origins — use `http://localhost:5173` for manual, `http://localhost:80` for Docker |
| `LLM_PROVIDER` | Optional | `anthropic` or `openai` |
| `ANTHROPIC_API_KEY` | Optional | For AI-powered analysis |
| `OPENAI_API_KEY` | Optional | Alternative LLM provider |

---

## 📖 API Docs

Once running, visit:
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

Key endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/assets` | List all digital twin assets |
| `POST` | `/api/v1/missions` | Launch offensive mission |
| `GET` | `/api/v1/findings` | List all security findings |
| `GET` | `/api/v1/attack-paths` | Get attack path graph |
| `GET` | `/api/v1/detections` | List detection events |
| `POST` | `/api/v1/deception/deploy` | Deploy honeytoken |
| `GET` | `/api/v1/audit` | Immutable audit log |

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

## ⚠️ Legal Notice

AegisTwin is designed for **authorized security testing only**. Only use against systems you own or have explicit written permission to test. Unauthorized use against third-party systems is illegal and unethical.
