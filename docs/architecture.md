# AegisTwin Architecture

## System Overview

AegisTwin is a dual-agent cybersecurity platform where two AI agents — an Offensive Red-Team AI and a Defensive Hunter AI — share a unified data model called the **Company Digital Twin**.

```
┌─────────────────────────────────────────────────────┐
│                   AegisTwin Platform                 │
│                                                     │
│  ┌──────────────┐         ┌──────────────────────┐  │
│  │ Offensive AI │         │   Defensive Hunter   │  │
│  │  Red-Team    │         │        AI            │  │
│  └──────┬───────┘         └─────────┬────────────┘  │
│         │                           │               │
│         └──────────┬────────────────┘               │
│                    │                                │
│         ┌──────────▼──────────┐                    │
│         │  Company Digital    │                    │
│         │       Twin          │                    │
│         └──────────┬──────────┘                    │
│                    │                                │
│         ┌──────────▼──────────┐                    │
│         │  Attack Path Graph  │                    │
│         └─────────────────────┘                    │
└─────────────────────────────────────────────────────┘
```

## Module Reference

### `/backend/app/core/`
- **`config.py`** — Pydantic-settings configuration from environment
- **`policy.py`** — PolicyEngine: hard-codes permanently blocked action types and evaluates all agent actions

### `/backend/app/db/`
- **`session.py`** — SQLAlchemy async engine, session factory, and `get_db` FastAPI dependency
- **`models.py`** — All ORM models: Tenant, User, Asset, Engagement, OffensiveMission, Finding, AttackPathNode, AttackPathEdge, TelemetryEvent, ActorCluster, DeceptionItem, DeceptionEvent, DetectionDraft, RemediationTicket, AuditEvent

### `/backend/app/agents/offensive/`
- **`agent.py`** — Full offensive agent with 7 classes:
  - `OffensiveMissionPlanner` — top-level orchestrator
  - `ReconPlanner` — passive attack surface discovery
  - `VulnerabilityReasoner` — hypothesis generation (mock LLM)
  - `AttackPathBuilder` — graph construction
  - `SafeValidationPlanner` — 7-level safety ladder
  - `ProofOfImpactPlanner` — lab-only PoC planning
  - `OffensiveReportGenerator` — structured JSON report

### `/backend/app/agents/defensive/`
- **`agent.py`** — Full defensive agent with 8 classes:
  - `TelemetryIngestionAgent` — normalizes raw events
  - `BehaviorAnalyticsAgent` — detects behavioral anomalies
  - `FingerprintCorrelationEngine` — multi-dimensional fingerprinting
  - `AIAssistedAttackDetector` — detects AI-assisted attack patterns
  - `ThreatIntelCorrelator` — matches against mock TI database
  - `ActorClusterBuilder` — full pipeline → actor cluster
  - `ForensicTimelineBuilder` — chronological event timeline
  - `IncidentResponseRecommender` — prioritized IR steps
  - `DefensiveReportGenerator` — structured cluster report

### `/backend/app/risk/`
- **`engine.py`** — `RiskEngine` with 7-factor scoring formula

### `/backend/app/tool_broker/`
- **`broker.py`** — `ToolBroker` with policy enforcement + 8 mock adapters

### `/backend/app/deception/`
- **`fabric.py`** — `DeceptionFabric` for safe fake credential/token generation

### `/backend/app/detections/`
- **`agent.py`** — `DetectionEngineeringAgent` generating Sigma/WAF/SIEM drafts

### `/backend/app/remediation/`
- **`agent.py`** — `RemediationAgent` generating Jira/GitHub ticket payloads

### `/backend/app/api/`
- **`router.py`** — Mounts all sub-routers
- **`endpoints/`** — One file per domain area

### `/backend/app/workers/`
- **`celery_app.py`** — Celery configuration
- **`tasks.py`** — Background tasks for agent execution

## Data Flow: Offensive

```
POST /missions/{id}/run
  → OffensiveMissionPlanner.run_mission()
    → ReconPlanner.gather_signals()         (policy-checked, mock tools)
    → VulnerabilityReasoner.generate_hypotheses()
    → AttackPathBuilder.build()
    → SafeValidationPlanner.build_plan()
    → RiskEngine.score()
    → ProofOfImpactPlanner.plan()
    → OffensiveReportGenerator.generate()
  → Finding records created in DB
  → Report returned as JSON
```

## Data Flow: Defensive

```
POST /telemetry/ingest/bulk
  → TelemetryIngestionAgent.normalize() × N
  → TelemetryEvent records saved in DB
  → ActorClusterBuilder.build_cluster()
    → BehaviorAnalyticsAgent.analyze()
    → FingerprintCorrelationEngine.build_fingerprint()
    → AIAssistedAttackDetector.detect()
    → ThreatIntelCorrelator.correlate()
  → ActorCluster saved in DB
  → ForensicTimelineBuilder.build()
  → IncidentResponseRecommender.recommend()
  → DetectionEngineeringAgent.from_cluster() (if suspicious)
  → Full report returned
```

## Safety Architecture

The `PolicyEngine` is the central safety gate. It is called:
1. By every agent before any action
2. By the ToolBroker before any tool execution
3. Independently via `POST /missions/policy-check`

The policy engine has two layers:
1. **Always-blocked set** — 11 action types permanently blocked, hardcoded, no override
2. **Scope check** — target must be in `Engagement.allowed_targets`

See [safety_model.md](safety_model.md) for details.
