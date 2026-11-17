# Assessment Copilot — Metasploit (v2)

Allowlisted **auxiliary / post** recommendations and gated runs for Assessment Copilot.

## Ownership (MCP-style)

| Artifact | Lives in | Notes |
|----------|----------|--------|
| Canonical catalog | sibling [`r3ngine-copilot`](https://github.com/whiterabb17/r3ngine-copilot) `data/msf_aux_catalog.json` | Seeded into sidecar playbook memory on boot |
| Django allowlist | `web/copilot/data/msf_aux_catalog.json` | Vendored copy; refreshed by `make install-copilot` / `update-copilot` |
| Validation / Temporal / Trace | r3ngine `web/copilot/` | Never trust the model; gateway re-validates |
| Console UI | r3ngine-plugins `metasploit_integration` | Deep-link handoff only |

## Proposal shape

```proposal
{"type":"msf_module","summary":"...","details":{
  "module":"auxiliary/scanner/http/http_version",
  "options":{"RHOSTS":"target.example","RPORT":"443"},
  "mode":"recommend"|"run",
  "vulnerability_id":123,
  "rationale":"..."
}}
```

- `mode=recommend` — nests under `Vulnerability.agent_enrichment.msf_aux` (no Temporal).
- `mode=run` — creates `MsfAuxAttempt`, starts `MsfAuxWorkflow`, executes via **MSFRPC** on the Docker network.

## Plugin handoff

Proposal UI **Open in Metasploit** links to:

`/{projectSlug}/p/metasploit_integration?module=...&rhosts=...&rport=...`

Cross-repo: the plugin should read these query params to prefill the console. Core does not embed plugin code.

## Safety

- Only catalog `auxiliary/` / `post/` modules.
- Forbidden options: `PAYLOAD`, `LHOST`, `LPORT`, payload handlers, etc.
- `RHOSTS` must be in project/scan scope.
- Never auto-sets `validation_status=verified`.
- No MCP MSF tools.

## MSFRPC env

See `.env.example` (`MSF_RPC_HOST` / `MSF_RPC_URL` / `MSF_RPC_PASS`, …). If RPC is down, the attempt fails with an actionable error; recommend + handoff still work.
