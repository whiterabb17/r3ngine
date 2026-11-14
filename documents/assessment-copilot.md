# Assessment Copilot

Local, cybersecurity-focused co-pilot that runs **alongside** the stack. Chat /
proposals are separate from the AI Hub / LLM Toolkit enrichment path, but
**inference reuses the shared `ollama` service** (`r3ngine-ollama` image).

The sidecar lives in the sibling repo
[r3ngine-copilot](https://github.com/whiterabb17/r3ngine-copilot) (compose build
context `../r3ngine-copilot`). Django gateway, Trace, MSF gates, and UI stay in
**r3ngine** (same split as MCP).

## Purpose

1. Gather context from findings/assets and indexed assessment memory
2. Propose validations
3. Propose **SAFE PoC** catalog demonstrations
4. Propose short- and long-term remediations
5. Propose targeted follow-up tool runs
6. Recommend / gate allowlisted Metasploit **auxiliary/post** modules (v2)

Outputs land in existing persistence (`Vulnerability.agent_enrichment`,
`remediation`, `SafePocAttempt`, `FollowupPlan`, `MsfAuxAttempt`, Trace).

## Architecture

| Piece | Role |
|---|---|
| `ollama` | Shared local inference (profile `ollama`) — AI Hub + Copilot |
| `assessment-copilot` | FastAPI sidecar from `r3ngine-copilot` |
| Django `copilot` | Sessions, proposals, Trace, MSF aux gateway |
| Temporal | Copilot index + `MsfAuxWorkflow` (MSFRPC) |

## Enable

```bash
make install-copilot     # clone sibling if needed; sync MSF catalog; enable ollama+copilot; start
make up-copilot          # same entry (starts shared ollama if down)
make update-copilot      # pull sibling + sync catalog + rebuild
make stop-copilot        # stops assessment-copilot only (ollama stays up)
```

Install syncs `r3ngine-copilot/data/msf_aux_catalog.json` → `web/copilot/data/` so
Django validation does not depend on the sibling path at runtime.

```bash
docker exec <ollama-container> ollama pull qwen2.5:7b-instruct
```

Env: see `.env.example` (`ASSESSMENT_COPILOT_URL`, `ASSESSMENT_OLLAMA_URL`, `MSF_RPC_*`).

## UI

- Assessment dashboard Copilot tab
- Global FAB: **Chat**, **Proposals** (incl. Open in Metasploit), **Trace**
- Settings → Assessment Copilot

## Hard gates

- SAFE PoC / MSF run / status-changing writes require operator approve
- Never auto-sets `validation_status=verified`
- MSF: catalog aux/post only; see [assessment-copilot-msf.md](assessment-copilot-msf.md)

## Related

- [assessment-copilot-msf.md](assessment-copilot-msf.md)
- Sibling README: https://github.com/whiterabb17/r3ngine-copilot#readme
