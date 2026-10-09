# MCP Access

r3ngine exposes a dedicated `/api/mcp/` allowlist so IDE agents can read recon data and queue allowed jobs. The TypeScript server lives in `r3ngine-mcp/` (same layout as `r3ngine-mobile` and `r3ngine-plugins`). It never receives Postgres, Redis, Neo4j, or scan-result credentials.

## Generate a key

1. Open **Settings → MCP Access**.
2. Sys-admins set transport: **stdio**, **HTTP**, or **both**.
3. Generate a named key. Copy the secret (`r3n_mcp_…`) immediately — it is shown once. The UI keeps only a public prefix.

## stdio (local IDE)

Paste into Cursor / Claude Desktop / VS Code. Examples are in `r3ngine-mcp/config/`.

```json
{
  "mcpServers": {
    "r3ngine": {
      "command": "npx",
      "args": ["-y", "r3ngine-mcp"],
      "env": {
        "R3NGINE_URL": "https://<this-host>",
        "R3NGINE_MCP_API_KEY": "<shown-once-secret>",
        "R3NGINE_CA_CERT": "<full-path-to-ca.crt>",
        "NODE_EXTRA_CA_CERTS": "<full-path-to-ca.crt>"
      }
    }
  }
}
```

stdio talks to Django `/api/mcp/` directly. The sidecar is not required.

## HTTP

When transport is `http` or `both`, nginx `/mcp` proxies to the `r3ngine-mcp` container on port 3100 (internal only).

```
URL: https://<this-host>/mcp
Header: Authorization: Bearer <shown-once-secret>
```

If transport is `stdio` only, HTTP MCP returns 403 even though the nginx location exists.

## Install locally

From r3ngine (clones `r3ngine-mcp/` if needed, then runs the Node setup):

```bash
node scripts/install-mcp.mjs --url https://<this-host> --key r3n_mcp_… --yes --write-cursor
```

Windows: `.\scripts\install-mcp.ps1 --url https://<this-host> --key r3n_mcp_… --yes`

To pull the latest sidecar, rebuild the local process, and refresh the Docker MCP
image/container for this stack:

```bash
node scripts/install-mcp.mjs --update
```

Install and `--update` both **build and start** the `r3ngine-mcp` compose service
(using `--profile mcp` on prod compose). If the container never existed, it is
created from the running stack’s compose project (or `docker/docker-compose.yml`).
Pass `--no-docker` to force a local/stdio-only setup.

From a checkout of r3ngine-mcp:

```bash
npm run setup -- --url https://<this-host> --key r3n_mcp_… --yes
npm run setup -- --update
```

The setup script installs dependencies, builds `dist/`, writes `.env`, opens a throwaway MCP session against `/api/mcp/` to prove the key works, smoke-starts the process, and can merge Cursor / VS Code / Claude Desktop config.

On a local checkout the installer uses the **full path** to **`secrets/certs/ca.crt`** and writes it into `.env` and MCP client env (`R3NGINE_CA_CERT` / `NODE_EXTRA_CA_CERTS`) so agents know where the cert is. It verifies TLS as the DNS name in **`secrets/certs/r3ngine.pem`** (your `DOMAIN_NAME`). Connecting to `https://127.0.0.1` is supported; the cert itself is issued for that domain, not the loopback IP.

If this machine does not have that file, setup tells you to copy `secrets/certs/ca.crt` from the r3ngine host and asks for the **full local path** (or pass `--ca C:\full\path\to\ca.crt`). Suggested destination: `r3ngine-mcp/certs/ca.crt`. Setup will not continue over HTTPS until agents have that path.

Unauthorized HTTP clients (missing or invalid API key) are rate-limited **in the sidecar** before r3ngine is contacted: **10 failures per IP per minute** by default (`MCP_UNAUTH_MAX`, `MCP_UNAUTH_WINDOW_MS`). Further attempts get `429` with `Retry-After`. Invalid keys are remembered for the same window so Django is not probed again.

## Sessions and audit

The MCP process opens a session and heartbeats every 30 seconds. **Settings → MCP Access** lists connected agents grouped by a fingerprint of provider + device (OS, IDE, hostname). Click a row for the redacted request/response chain. Click the **key name** to jump to that API key. **Ban** blocks that fingerprint from reconnecting even with a new session. Sys-admins can **Delete** an agent (this removes audit logs) and choose to **keep the ban** or **unban**. Heartbeats are not audited.

Click any tool call in the Audit table, or **Replay** on an audit-chain event, to open a stored overlay: the calling agent (provider, device, key), the request, and the returned payload. Replay is inspect-only — it never re-sends the call or starts, pauses, or retries a scan.

## What agents cannot do

Delete targets, vulns, users, or files. They cannot **delete** notes (create and update are allowed for pentester/sys-admin keys). They cannot list keys, read audit events, or revoke sessions — those stay in this UI. MCP keys do not authenticate on `/api/action/` delete routes.

Agents can queue allowed work including **subscans** (`r3ngine_start_subscan`) when the key’s role permits dispatch.

## Plugin-gated tools

MCP never opens `/api/plugins/{slug}/` to the sidecar. Thin `/api/mcp/` wrappers call plugin backends only when the plugin is **installed and enabled**.

1. **`r3ngine_list_plugins` / `r3ngine_get_plugin`** — always registered. Returns enabled plugins and each plugin’s `mcp_tools` from `manifest.yaml` (`mcp.tools`).
2. **`r3ngine_list_capabilities`** — includes a `plugins` array with the same enabled catalog.
3. **Plugin tools** (first wave: Active Directory) are registered by the sidecar **only after** session open discovers the slug. Host views still return `404` with `reason: plugin_not_installed | plugin_disabled | plugin_backend_missing` if the plugin is absent.

### Active Directory / BloodHound (plugin: `active_directory`)

BloodHound CE / SharpHound are **not** run by the platform. Agents use:

| Tool | Purpose |
|------|---------|
| `r3ngine_list_ad_assessments` / `r3ngine_get_ad_assessment` | Browse assessments |
| `r3ngine_start_ad_assessment` | Create + start ldapdomaindump/Certipy workflow phases |
| `r3ngine_ingest_ad_data` | Ingest BloodHound/SharpHound JSON or LDAP export (`content_base64` / `content`) |
| `r3ngine_list_ad_findings` | Findings (optional trusts/exposures via `include`) |
| `r3ngine_get_ad_attack_paths` | AD graph paths (`category`: da_paths, kerberoastable, …) — **not** APME |
| `r3ngine_get_ad_report` | Comprehensive JSON report for agents |

`r3ngine_get_attack_paths` / `r3ngine_get_attack_path` remain **APME** (web-recon). Prefer `r3ngine_get_ad_attack_paths` for AD identity paths.

### APME attack-path proposals

Path create/enrich/update/dismiss and APME queue are **propose → operator approve** (same human gate as follow-ups):

| Tool | Purpose |
|------|---------|
| `r3ngine_get_attack_paths` / `r3ngine_get_attack_path` | Read paths |
| `r3ngine_propose_attack_path` | Draft enrich/create/update/dismiss/trigger_apme/recalculate_apme |
| `r3ngine_list_attack_path_proposals` / `r3ngine_get_attack_path_proposal` | Browse proposals |
| `r3ngine_update_attack_path_proposal` | Edit while `proposed` |
| `r3ngine_approve_attack_path_proposal` / `r3ngine_abort_attack_path_proposal` | Operator yes only |

Direct `r3ngine_enrich_attack_path`, `r3ngine_trigger_apme`, and `r3ngine_recalculate_apme` return **410** and point agents at proposals. UI non-MCP APME endpoints are unchanged.

### SAFE PoC (catalog templates)

Benign proof-of-concept probes are **propose → operator approve → Temporal execute**. Agents pick a server catalog `template_id` only (no freeform payloads):

| Tool | Purpose |
|------|---------|
| `r3ngine_propose_safe_poc` | Draft marker/calc/authz/redirect/flag-canary attempt |
| `r3ngine_list_safe_pocs` / `r3ngine_get_safe_poc` | Browse attempts |
| `r3ngine_update_safe_poc` | Edit while `proposed` |
| `r3ngine_approve_safe_poc` / `r3ngine_abort_safe_poc` | Operator yes only |

Direct `r3ngine_run_safe_poc` returns **410**. Results nest under `Vulnerability.agent_enrichment.poc`. PoC success does **not** auto-set `verified`. Delegate to the `r3ngine-safe-poc` agent; see `r3ngine-mcp/skills/safe-poc/`.

### Credential Intelligence (plugin: `credential_intelligence`)

| Tool | Purpose |
|------|---------|
| `r3ngine_list_credential_tasks` / `r3ngine_get_credential_task` | Browse auth-testing tasks |
| `r3ngine_start_credential_task` | Create + run kerbrute/netexec/brutus/hashcat jobs |
| `r3ngine_list_discovered_credentials` | Credentials with **secrets redacted** |
| `r3ngine_list_hash_cracking` / `r3ngine_get_hash_cracking` / `r3ngine_start_hash_cracking` | Hashcat jobs (plaintext redacted) |

### Compliance Assessment (plugin: `compliance_assessment`)

| Tool | Purpose |
|------|---------|
| `r3ngine_list_compliance_assessments` / `r3ngine_get_compliance_assessment` | Browse assessments |
| `r3ngine_list_compliance_controls` | Control results for an assessment |
| `r3ngine_get_compliance_report` | Attestation JSON when present |
| `r3ngine_enrich_compliance_control` | AI remediation for a control |

### Burp Suite Integration (plugin: `burpsuite_integration`)

| Tool | Purpose |
|------|---------|
| `r3ngine_list_burp_issues` / `r3ngine_get_burp_issue` | Imported Burp findings |
| `r3ngine_get_burp_metrics` | Severity / unmatched rollup |
| `r3ngine_list_burp_sync_logs` | Sync history |
| `r3ngine_get_burp_health` | Live Burp API connectivity |
| `r3ngine_start_burp_sync` | Start import+correlate workflow |

**Not exposed via MCP:** `metasploit_integration`, `active_exploitation` (offensive craft), `email_security` / `exploit_readiness_layer` (no dedicated plugin HTTP surface for agents).

Other plugins can declare `mcp.tools` in their manifest and add matching `/api/mcp/` host views + sidecar registrars using the same gate.

## Detail tools

`list_*` and thin `get_scan` / `get_target` stay lean for browsing. When an agent needs rollups, relations, or scan task status, use the companion detail tools:

- `r3ngine_export_scan_for_ai` — **preferred for full scan analysis**: same Analyst Assist export as the scan-detail **Export for AI** button (markdown overview, triage prompt, structured bundle + manifest). Optional flags mirror the UI (`include_raw_outputs`, `include_timeline`, `include_sidecars`).
- `r3ngine_get_scan_detail` — finding counts, severity rollup, tasks grouped by status (initiated / running / success / failed / aborted)
- `r3ngine_get_target_detail`, `r3ngine_get_vulnerability_detail`, `r3ngine_get_subdomain_detail`, `r3ngine_get_endpoint_detail`, `r3ngine_get_exposure_detail`, `r3ngine_get_subscan_detail` — primary record plus capped related lists

Related lists are capped (20); scan activity buckets are capped (100 per status) with full counts in `task_summary`. Raw request/response, traceback, and `results_dir` stay omitted.

## Capabilities, singular tools, and follow-ups

Agents (and the Subdomains tab **Run single tool** modal) can:

1. **`r3ngine_list_capabilities` / `r3ngine_get_engine_detail`** — which pipeline tools and workflows are allowed for an asset kind / engine.
2. **`r3ngine_get_tool_args`** — host-local CLI schema for a tool (installed binary `--help`, versioned DB cache; seed fallback when the binary is missing). Call this before inventing flags.
3. **`r3ngine_run_tool`** — start one pipeline tool on a subdomain, endpoint, or URL. Optional `tool_args` must match the schema (denylisted retargeting / filesystem flags; no free-form shell). Timeline rows are namespaced `single_tool_<task>` so they never collide with master-scan claim / tier-retry / resume.
4. **Follow-up plans** — `propose` → optional `update` → operator `approve` / `abort` / `retry`; detail payloads may include capped `suggested_followups`.
5. **Attack-path proposals** — `r3ngine_propose_attack_path` → optional update → operator approve/abort (enrich/create/update/dismiss/APME queue).
6. **SAFE PoC** — `r3ngine_propose_safe_poc` → optional update → operator approve/abort (catalog templates only).
7. **OSINT staging** — `r3ngine_list_osint_staging` / `r3ngine_verify_osint_staging` with `agent_verified` badges in the UI.

Operators manage keys, sessions, and the audit chain in **Settings → MCP Access**. Sync installed binaries and refresh arg schemas on the web container with `manage.py sync_installed_tools` and `manage.py refresh_tool_arg_schemas` when tools are updated.

See also the [r3ngine-mcp README](../r3ngine-mcp/README.md).
