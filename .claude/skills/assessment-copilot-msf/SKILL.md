---
name: assessment-copilot-msf
description: Guidance for Assessment Copilot Metasploit auxiliary/post recommendations and gated runs (no freeform exploits).
---

# Assessment Copilot MSF

Use when operators ask Copilot for Metasploit module recommendations or gated auxiliary runs.

## Rules

1. Only modules present in the allowlisted catalog (`web/copilot/data/msf_aux_catalog.json` / sibling `r3ngine-copilot/data/msf_aux_catalog.json`).
2. Classes: `auxiliary/` and `post/` only — never `exploit/`, `payload/`, `encoder/`.
3. Prefer `mode=recommend` unless the operator explicitly wants a gated run.
4. Emit a ```proposal``` block with `type=msf_module` and validated `module` + `options`.
5. Scope `RHOSTS` to assessment targets only.
6. Never craft msfvenom, meterpreter, shellcode, or freeform payloads.
7. Point operators to **Open in Metasploit** for interactive console work via the plugin.

## Handoff URL

`/{project}/p/metasploit_integration?module=<path>&rhosts=<host>&rport=<port>`
