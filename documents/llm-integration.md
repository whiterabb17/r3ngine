# r3ngine — LLM Integration

## Overview

r3ngine integrates Large Language Models for automated security intelligence generation, including vulnerability impact assessment, attack path modeling, and report summaries.

**File:** `web/reNgine/llm.py`

---

## LLM Providers

r3ngine supports multiple LLM providers, configured via the admin UI:

| Provider | Models |
|---|---|
| OpenAI | GPT-4, GPT-4o, GPT-3.5-turbo |
| Anthropic | Claude 3 Opus, Claude 3 Sonnet, Claude 3 Haiku |
| Google | Gemini 1.5 Pro, Gemini 1.5 Flash |
| Ollama | Any locally-hosted model |

The active provider and model are stored in the `LLMConfig` database model.

---

## Feature: Impact Assessment (`GenerateImpactAssessmentActivity`)

### Purpose

Generates a human-readable security impact assessment for every vulnerability discovered in a scan. Runs as the third step in Tier 7 (post-processing).

### Workflow

1. Queries all `Vulnerability` records for the scan.
2. Groups vulnerabilities by severity.
3. For each group, sends a structured prompt to the configured LLM.
4. Saves the LLM-generated impact text to `Vulnerability.impact_statement`.

### Prompt Structure

```
You are a senior penetration tester writing an executive-level security impact assessment.

Target: {target_domain}
Vulnerability: {vulnerability_name}
Severity: {severity}
Evidence: {evidence_snippet}

Write a concise (2-3 sentence) impact statement explaining what this vulnerability means 
for the business and what an attacker could achieve.
```

---

## Feature: Vulnerability Severity Validation (`LLMSeverityValidator`)

### Purpose

Re-evaluates scanner findings (especially those misclassified as `Info` or `Low` by tools like WPScan or Nuclei due to missing CVSS metadata) using configured LLM providers. Analyzes vulnerability type, URL, CVE, CWE, description, and evidence against CVSS v3.1 / OWASP standards.

### Workflow

1. Triggered via `POST /api/listVulnerability/{id}/validate_severity/` from row context menu or expanded row detail view in the Vulnerability Table.
2. `LLMSeverityValidator` in `web/reNgine/llm.py` queries active `LLMConfig`.
3. Returns JSON containing `suggested_severity`, `suggested_cvss_score`, `confidence`, `reasoning`, and `key_factors`.
4. Frontend presents a comparison UI allowing the user to review, fine-tune, and accept the reclassified severity via `POST /api/listVulnerability/{id}/update_severity/`.

---

## Feature: Attack Path Modeling Engine (APME)

### Overview

APME uses LLM reasoning to construct attack chains — sequences of vulnerabilities and misconfigurations that an attacker would chain together to achieve a high-impact objective.

**Workflow:** `ApmeTaskWorkflow`  
**Activity:** `RunLlmApmeActivity`  
**Task Queue:** `python-orchestrator-queue`

### APME Module (`apme/`)

Located in `web/apme/`. The APME module:

1. Loads all vulnerabilities, exposed services, and credential findings for a scan.
2. Constructs a graph of possible attack paths (nodes = findings, edges = attack steps).
3. Sends the graph to the LLM with a structured prompt asking it to identify the most impactful attack chains.
4. Saves attack paths to the `AttackPath` and `AttackPathNode` models.
5. Syncs attack paths to Neo4j for graph visualization.

### `ApmeTaskWorkflow`

```python
@workflow.defn(name="ApmeTaskWorkflow")
class ApmeTaskWorkflow:
    async def run(self, scan_history_id: int, job_id: str = None) -> dict:
        return await workflow.execute_activity(
            "RunLlmApmeActivity",
            args=[scan_history_id, job_id],
            start_to_close_timeout=timedelta(hours=1),
            retry_policy=_RETRY_LLM,
            task_queue="python-orchestrator-queue",
        )
```

Retry policy `_RETRY_LLM` (3 attempts) handles LLM API rate limits and transient failures.

---

## Feature: Vulnerability Correlation

**File:** `web/reNgine/correlation.py`  
**Activity:** `CorrelateVulnerabilitiesActivity`

Runs after all vulnerability scanners complete. Groups related vulnerabilities, generates a unique deterministic `group_key` to suppress inside-scan duplicates, tracks vulnerability history across scans, and calculates a composite **Correlation Score** (0-100) using a multi-criteria weight matrix:

| Factor | Weight | Description |
|---|---|---|
| **Severity** | 40% | Derived from CVSS v3.1 base score when available, falling back to vulnerability severity. |
| **Multi-Tool Match** | 25% | Boosts score when findings are confirmed by multiple distinct scanner tools (e.g. Nuclei, Semgrep, Retire.js). |
| **Exploitability** | 20% | Incorporates CISA KEV catalog presence, EPSS score/percentile metrics, and explicit Proof of Concept exploit URLs. |
| **Asset Context** | 10% | Scaled based on the subdomain's configured criticality level (1 to 5). |
| **Temporal Factor** | 5% | Decays over time (from 1.0 down to 0.2) based on how many days have elapsed since the finding was first discovered. |

### Status Auto-Promotion
The correlation engine automatically promotes the finding's `validation_status` to `verified` if:
1. The correlation score is $\ge 90$ and at least 2 distinct tools confirmed the finding, or
2. The correlation score is $\ge 75$ and the CVE is listed in the CISA KEV catalog.

Otherwise, the status defaults to `unverified`.

---

## Feature: Risk Score Calculation

**Activity:** `CalculateRiskScoresActivity`

Computes a composite risk score for each `Vulnerability` based on the calculated correlation score, asset criticalities, and additional contextual telemetry. Final score is stored in `Vulnerability.risk_score` (0–100).

---

## LLM Configuration

### `LLMConfig` Model

| Field | Description |
|---|---|
| `provider` | `openai`, `anthropic`, `google`, `ollama` |
| `model` | Model identifier (e.g., `gpt-4o`) |
| `api_key` | API key (encrypted at rest) |
| `ollama_url` | Base URL for Ollama (default: `http://ollama:11434`) |
| `max_tokens` | Max token output per LLM call |
| `temperature` | Sampling temperature (0.0–1.0) |

### Enabling LLM Features

1. Navigate to **Settings > LLM Configuration** in the r3ngine admin UI.
2. Select the provider and enter the API key.
3. Enable the desired features: Impact Assessment, APME, Summaries.
4. The next scan will use LLM features automatically (Tier 7 runs regardless of task selection).

---

## Prompt Engineering

All prompts are centralized in `web/reNgine/llm.py`. Each prompt is designed to:
- Constrain the LLM to security-specific analysis.
- Request structured JSON output where possible (for programmatic parsing).
- Include context from the scan (target, tech stack, evidence snippets).

To modify or improve prompts, edit the `PROMPT_*` constants in `llm.py`.
