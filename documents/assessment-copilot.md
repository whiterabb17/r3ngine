# Assessment Copilot

Local, cybersecurity-focused co-pilot that runs **alongside** the stack and is
**separate** from the AI Hub / LLM Toolkit enrichment path.

## Purpose

Help operators during contracted assessments to:

1. Gather context from existing findings/assets (and indexed assessment memory)
2. Propose validations of findings
3. Propose **SAFE PoC** catalog demonstrations (prove impact)
4. Propose short- and long-term remediations
5. Propose targeted follow-up tool runs (existing engines/tools with `tool_args`)

Outputs land in **existing persistence** (`Vulnerability.agent_enrichment`,
`remediation`, `SafePocAttempt`, `FollowupPlan`, validation fields) so current
reporting picks them up. There is **no** separate client report generator in v1.

## Architecture

| Piece | Role |
|---|---|
| `assessment-ollama` | Local inference (compose profile `copilot`) — not Hub `ollama` |
| `assessment-copilot` | FastAPI sidecar: chat, RAG/memory index, constrained prompts |
| Django `copilot` app | Sessions, proposals, settings; `/api/copilot/*` gateway |
| Temporal | `IndexScanForCopilotActivity` after scan completion (best-effort) |

Approve on a proposal **delegates** to existing SAFE PoC / follow-up / enrich
paths — no parallel executor.

## Enable

```bash
make up-copilot          # enables COMPOSE_PROFILES=copilot in .env, then builds/starts
make update-copilot       # rebuild images; recreates containers only if they were running
make stop-copilot        # stops containers; profile stays enabled so `make up` brings them back
# or set COMPOSE_PROFILES=...,copilot in .env yourself
```

Pull a model into assessment-ollama, e.g.:

```bash
docker exec <assessment-ollama-container> ollama pull qwen2.5:7b-instruct
# Prefer also: WhiteRabbitNeo / Deep Hat for pentest vocabulary
```

Env (see `.env.example`):

- `ASSESSMENT_COPILOT_URL` (default `http://assessment-copilot:8091`)
- `ASSESSMENT_OLLAMA_URL` (default `http://assessment-ollama:11434`)
- `COPILOT_MODEL_DEFAULT`

## UI

- **Assessment dashboard** — Copilot tab with in-context panel
- **Global FAB** (bottom-right) — support-style box with:
  - **Chat** — save / switch conversations
  - **Proposals** — approve / reject queue
- **Settings → Assessment Copilot** — enable, memory scope, model id

## Memory scopes

Configurable per project: `project` | `org` | `global` | `tiered`.

## Hard gates

- SAFE PoC and status-changing writes require operator approve
- Co-pilot never auto-sets `validation_status=verified`
- No freeform exploits / Metasploit execution in v1

## Deferred (v2 TODOs)

- Metasploit skill pack / gated MSF auxiliary modules
- Fully autonomous runs
- Separate client-facing report generator
- Multi-user collaborative co-pilot sessions
- Cloud-hosted co-pilot
- Fine-tuning / weight updates
- Stricter auto-promotion privacy for global memory
