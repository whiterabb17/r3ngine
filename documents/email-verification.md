# Mailbox verification

Reacher `check-if-email-exists` confirms whether addresses exist for the **scanned domain**. It replaced `smtp-user-enum` (VRFY/EXPN spraying against discovered SMTP hosts), which was noisy and unreliable on catch-all MX.

This is **main-platform** email security. It is not the `email_security` plugin. Hunter, theHarvester, h8mail, and the Discover Emails OSINT action are separate.

## Where it runs

`MasterScanWorkflow` → after Tier 2, if `port_scan` is enabled → `RunEmailSecurityActivity` (`python-orchestrator-queue`).

SPF, DMARC, DKIM, open-relay, STARTTLS, and cert checks still run first. Mailbox verification then talks to the domain **MX**, so it still runs when the port scan found no SMTP ports.

Activity timeouts: start-to-close **90 minutes**, heartbeat **10 minutes** (heartbeat thread every 30s).

Scan detail timeline: `InitializeScanTasksActivity` pre-creates a **Mailbox Verification** row (`name=check_if_email_exists`, tier 2) on master scans when `port_scan` is in the engine task list and mailbox verification is not disabled. Subscans do not get this row (`RunEmailSecurityActivity` is master-only). `RunEmailSecurityActivity` claims that row as running, attaches CLI `Command` rows, then marks success or failure even if SPF/SMTP work raises first. Retry from the timeline re-runs `RunEmailSecurityActivity`.

## File map

| File | Role |
|---|---|
| `web/reNgine/tasks/email_verification.py` | Candidates, CLI/HTTP verify, catch-all, persist, findings |
| `web/reNgine/tasks/email_security.py` | SPF/DMARC/DKIM/relay/STARTTLS/cert only |
| `web/reNgine/temporal/activities/__init__.py` | `_run_email_security_sync` calls `verify_domain_mailboxes` |
| `web/reNgine/task_plan.py` | Pre-populates the Mailbox Verification timeline item |
| `docker/web/Dockerfile` | Official `check_if_email_exists` v0.11.7 CLI |
| `web/tests/test_email_verification.py` | Unit tests (mocked, no live MX) |

## Process

1. Parse `email_security.mailbox_verification` from engine YAML (`enabled` defaults true).
2. If `http_url` is set, validate it (SSRF allowlist). On failure, **skip** (no CLI fallback). If unset, require `check_if_email_exists` on PATH.
3. Build candidates (capped at `max_candidates`, then clamped to remaining activity time). `_run_email_security_sync` measures elapsed SPF/DMARC/swaks work and passes `remaining_seconds`. Each check is billed as `timeout + 5s` CLI pad + `delay_ms`; two sentinels and 60s persist slack are reserved. If remaining time cannot cover the sentinels, the verifier skips (`timeout_budget`). When remaining time is unknown (unit tests), a 15-minute shared-work reserve is assumed.
   - emails already on this `ScanHistory` (first, so OSINT is not starved)
   - employee name patterns (`first@`, `f.last@`, `first.last@`, `flast@`, `firstl@`, `last@`)
   - remaining slots: `local@domain` from `/usr/src/wordlist/smtp-usernames.txt`
   - Drop any address whose host is not exactly the scanned domain.
4. Probe two random sentinels `r3n-nx-<hex>@domain`.
5. If MX is catch-all (`smtp.is_catch_all` or sentinel `is_reachable=safe`): write **MX Catch-All Configured** (severity 0), save nothing, stop.
6. Otherwise verify remaining candidates sequentially with `delay_ms`.
7. Persist `is_reachable=safe` onto the existing `Email` row when `address` matches case-insensitively (scan first, then global). Only create a new row via `save_email` (`source=mailbox_verify`) when none exists. Existing rows keep their source; verification fields go in `Email.metadata`.
8. If any safe hits: **Valid Mailboxes Confirmed** (severity 2), at most 20 addresses in the description.

```
verify_domain_mailboxes
  ├─ sentinels ── catch-all? ──► finding, return
  └─ candidates ── verify_address ── CLI or HTTP
                      └─ safe → save_email + metadata
```

## Backends

**CLI (default):** `check_if_email_exists [--proxy-host=HOST --proxy-port=PORT] <email>` as an argv list, `shell=False`, timeout `timeout+5` seconds. Operator SOCKS5 proxies (including TOR `socks5://tor:9050`) are selected via `get_random_proxy(socks5_only=True)` and passed as `--proxy-host` / `--proxy-port` / `--proxy-username`. `--proxy-password` is **not** put on argv (`run_command` stores the command string); the password is `PROXY_PASSWORD` in the subprocess environment. SOCKS4 and HTTP proxies are skipped (Reacher SMTP verify is SOCKS5-only). Outbound TCP/25 from the orchestrator must be open unless a SOCKS5 proxy is in use.

**Optional HTTP:** engine `http_url` is an origin only. The activity always `POST {origin}/v0/check_email` with `{"to_email": "..."}`, no redirects, TLS verify, 64 KiB body cap.

License: upstream CLI is AGPL-3.0. r3ngine ships the **unmodified** release binary. Do not vendor or patch Reacher source.

## Engine YAML

```yaml
email_security:
  mailbox_verification:
    enabled: true
    http_url: ""
    timeout: 15
    max_candidates: 200
    delay_ms: 250
```

## Error handling

| Failure | Behavior |
|---|---|
| `enabled: false` | Skip verifier (`skipped_reason=disabled`) |
| Wordlist missing | Continue with OSINT + employee patterns |
| CLI missing and no `http_url` | Skip (`binary_missing`); SPF/relay still saved |
| `http_url` fails allowlist | Skip (`bad_http_url`); **no** CLI fallback |
| Per-address timeout / bad JSON / HTTP 4xx–5xx | That address = `unknown`; continue |
| Catch-all | Stop loop; catch-all finding only |
| Temporal cancel | Stop between candidates (`skipped_reason=cancelled`); persist any `safe` hits already saved |
| Remaining activity time too small | Skip (`timeout_budget`); SPF/relay still saved |

Do not put raw CLI/HTTP bodies or SMTP transcripts in logs, exceptions, or vulnerability descriptions. Do not log proxy passwords.

## Security invariants

- Domain allowlist on every candidate and every `verify_address` call.
- Reject ASCII controls in addresses.
- No `shell=True`.
- Operator `http_url` is still parsed as a URL: `http`/`https` only, no userinfo, no `file`/`gopher`, no link-local metadata IP.
- Sequential checks + delay + cap + catch-all abort.
- SOCKS5 proxies use `--proxy-host` / `--proxy-port` on argv; proxy passwords stay in `PROXY_PASSWORD` (never Command-row argv).
- No new public API; this runs only inside the authenticated scan activity.

## Data written

| Store | Content |
|---|---|
| `Email.source` | `mailbox_verify` for newly confirmed rows; unchanged for Hunter/harvester/… |
| `Email.metadata` | `is_reachable`, `is_role_account`, `is_disposable`, `is_catch_all`, `mx_accepts_mail` |
| Vulnerability `source` | `email_security` |
| OSINT chip | `VERIFIED` for `mailbox_verify` |

## Tests

From the `web/` Django project:

```bash
python manage.py test tests.test_email_verification tests.test_email_security_internal -v 2
```

No live MX or SMTP in unit tests.

## Out of scope

- `r3ngine-plugins/email_security`
- Hunter, theHarvester, h8mail, holehe
- `web/reNgine/tasks/email_discovery.py` (Discover Emails button still uses its own SMTP RCPT helper)
