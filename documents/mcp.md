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
5. **OSINT staging** — `r3ngine_list_osint_staging` / `r3ngine_verify_osint_staging` with `agent_verified` badges in the UI.

Operators manage keys, sessions, and the audit chain in **Settings → MCP Access**. Sync installed binaries and refresh arg schemas on the web container with `manage.py sync_installed_tools` and `manage.py refresh_tool_arg_schemas` when tools are updated.

See also the [r3ngine-mcp README](../r3ngine-mcp/README.md).
