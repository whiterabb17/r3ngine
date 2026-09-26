# r3ngine — Core System Documentation

## Table of Contents

| Document | Description |
|---|---|
| [Architecture Overview](architecture-overview.md) | System architecture, containers, and components |
| [Temporal System](temporal-system.md) | Temporal workflows, activities, task queues, and worker configuration |
| [Scan Pipeline](scan-pipeline.md) | The 7-tier MasterScanWorkflow pipeline in detail |
| [Mailbox Verification](email-verification.md) | Reacher mailbox confirmation (replaces smtp-user-enum) |
| [MCP Access](mcp.md) | Agent/IDE MCP server, keys, sessions, singular tools / `tool_args`, follow-ups, `/mcp` sidecar |
| [Task Cancellation](task-cancellation.md) | How scan and subscan cancellation works |
| [Task Recovery](task-recovery.md) | Crash recovery and scan resumption via Temporal |
| [Plugin System](plugin-system.md) | Plugin architecture, installation, and Temporal integration |
| [Tool Distribution](tool-distribution.md) | Go Executor and tool subprocess management |
| [API Reference](api-reference.md) | Django REST API endpoints overview |
| [Database Models](database-models.md) | Core Django data model reference |
| [Scheduling](scheduling.md) | Temporal Schedules for periodic and clocked scans |
| [WebSockets](websockets.md) | Real-time updates via Django Channels |
| [LLM Integration](llm-integration.md) | AI/LLM features: impact assessment, APME, summaries |
| [Neo4j Integration](neo4j-integration.md) | Graph database integration and APME |
| [Configuration](configuration.md) | Environment variables and engine YAML configuration |
| [Docker Setup](docker-setup.md) | Container architecture and service definitions |

---

## Project Layout (Core — `web/`)

```
web/
├── reNgine/                    # Core Django application module
│   ├── settings.py             # Django settings
│   ├── tasks.py                # Legacy task functions (scan tools)
│   ├── temporal_activities.py  # Temporal activity definitions
│   ├── temporal_workflows.py   # Temporal workflow definitions
│   ├── temporal_client.py      # Temporal connection provider
│   ├── temporal_schedule_utils.py  # Schedule creation helpers
│   ├── definitions.py          # Global constants and tool definitions
│   ├── common_func.py          # Shared utility functions
│   ├── correlation.py          # Vulnerability correlation engine
│   ├── consumers.py            # WebSocket consumers (Django Channels)
│   ├── llm.py                  # LLM/AI integration
│   ├── parsers.py              # Tool output parsers
│   ├── utils/                  # Utility sub-package
│   │   ├── task.py             # Task execution helpers
│   │   ├── graph.py            # Neo4j graph utilities
│   │   ├── scan_cancellation.py # Scan abort helpers
│   │   ├── database.py         # DB utility functions
│   │   ├── opsec.py            # OPSEC/proxy utilities
│   │   └── waf.py              # WAF detection utilities
│   ├── stress/                 # Stress testing
│   └── osint/                  # OSINT tools
├── api/                        # Django REST API views
├── startScan/                  # Scan models (ScanHistory, Vulnerability, etc.)
├── targetApp/                  # Target and domain models
├── scanEngine/                 # Scan engine configurations
├── plugins/                    # Plugin management app
│   ├── models.py               # Plugin DB model
│   ├── orchestrator.py         # Legacy plugin orchestrator
│   ├── temporal_registry.py    # Dynamic Temporal plugin loader
│   └── utils.py                # Plugin installation utilities
├── executor/                   # Go Executor binary source (built as go-executor service)
├── apme/                       # Attack Path Modeling Engine
└── dashboard/                  # Dashboard views
```
