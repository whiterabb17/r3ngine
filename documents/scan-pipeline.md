# r3ngine — Scan Pipeline (MasterScanWorkflow)

## Overview

The `MasterScanWorkflow` is the primary scan orchestration workflow. It executes a complete reconnaissance and vulnerability assessment pipeline in 7 sequential tiers. Within each tier, compatible tasks run in parallel using `asyncio.gather()`.

---

## Workflow: `MasterScanWorkflow`

**File:** `web/reNgine/temporal_workflows.py`  
**Task Queue:** `python-orchestrator-queue`

### Input Context (`ctx`)

The workflow receives a `ctx` dict populated by `TargetProfilingActivity`:

| Key | Type | Description |
|---|---|---|
| `scan_history_id` | `int` | ScanHistory primary key |
| `engine_id` | `int` | ScanEngine primary key |
| `domain_id` | `int` | Target Domain primary key |
| `results_dir` | `str` | Container path for scan results |
| `tasks` | `list[str]` | Task names enabled for this engine |
| `yaml_configuration` | `dict` | Parsed engine YAML configuration |
| `hardware_profile` | `dict \| None` | Hardware profile resolved at scan start — only a fallback, see below |

---

## Hardware Profile (live per activity)

A `HardwareProfile` (`threads`, `rate_limit`, `delay`, `retries`) sets how hard a scan
works the host. Per resource limit: a value set in the tool's engine section wins, then the
profile, then the engine's global value (`apply_hardware_profile` in
`temporal/activities/core.py`). The engine editor always writes the global limits, so they
act as the fallback for engines scanned without a profile, not as an override of the one
picked for the scan. Timeouts stay with the engine.

The profile is **not** frozen for the life of the scan. Every activity builds a
`TemporalTaskProxy`, which loads the `ScanHistory` (with `hardware_profile` joined into the
same query) and calls `hardware_profile_context(scan)` (`tasks/scan_init.py`): the scan's own
profile, else the active default, else any active profile. Subscans resolve the profile of
their parent `ScanHistory`. `ctx['hardware_profile']` is used only when the scan row cannot be
loaded or no profile resolves any more; both cases log a warning. Workflows are untouched and
stay DB-free.

Consequences:

- Switching the profile of a pending, running or paused scan — or editing the values of the
  profile it uses — applies to every step that **starts** afterwards. Tools already running
  keep the settings they were launched with.
- Endpoint: `POST /api/action/scan/<scan_id>/hardware-profile/` with
  `{"hardware_profile_id": <id>}` (`SetScanHardwareProfile` in `api/views/scan.py`, same
  `HasPermission` + `PERM_INITATE_SCANS_SUBSCANS` as stop/pause). The profile must exist and be
  active (400 otherwise); an unknown scan returns 404.
- UI: the scan detail page shows a hardware profile selector next to STOP while the scan is
  pending, running or paused (`ScanHardwareProfileControl.tsx`).

---

## Tier-by-Tier Pipeline

### Step 0: Target Profiling

```
TargetProfilingActivity → (enriches ctx)
LoadCheckpointActivity  → (backward-compat no-op)
```

Validates the scan, sets up results directories, and enriches the context with target metadata.

---

### Tier 1: Discovery (Parallel)

All tasks run concurrently. The tier completes when **all** discovery tasks finish.

| Task Name | Activity | Duration |
|---|---|---|
| `subdomain_discovery` | `RunSubdomainDiscoveryActivity` | Up to 2 hours |
| `amass_intel_discovery` | `RunAmassIntelDiscoveryActivity` | Up to 2 hours |
| `firewall_vpn_scan` | `RunFirewallVPNScanActivity` | Up to 30 min |
| `osint` | `RunGenericTaskActivity` | Up to 2 hours |
| `spiderfoot_scan` | `RunGenericTaskActivity` | Up to 4 hours |
| `baddns` | `RunGenericTaskActivity` (special ctx) | Up to 2 hours |

After all futures complete: `ParseDiscoveryResultsActivity` logs subdomain counts.

**Pause point:** `_check_paused()` after Tier 1.

---

### Tier 2: HTTP Crawl + Network Scanning (Parallel)

Runs HTTP crawl, port scan, and Vigolium concurrently.

| Branch | Activities | Duration |
|---|---|---|
| HTTP Crawl | `SeedEndpointsForCrawlActivity` → `RunHTTPCrawlActivity` → `ParseHTTPCrawlResultsActivity` | Up to 3 hours |
| Port Scan | `RunPortScanActivity` | Up to 2 hours |
| Vigolium Discovery | `RunVigoliumDiscoveryActivity` | Up to 3 hours |

> **SeedEndpointsForCrawlActivity** pre-seeds the endpoint DB with known URLs before the crawl runs, ensuring initial coverage even if httpx hasn't seen them yet.

**Post–Tier 2: Email security** (`RunEmailSecurityActivity`, if `port_scan` is enabled)

SPF/DMARC/DKIM plus SMTP relay/STARTTLS/cert checks on discovered mail ports. Mailbox confirmation then runs against the domain MX via `check-if-email-exists` (see [Mailbox Verification](email-verification.md)). Catch-all MX aborts enumeration. This step does not use `smtp-user-enum`.

The scan detail timeline includes a **Mailbox Verification** item (`check_if_email_exists`, tier 2) so operators can see the Reacher CLI running. It is omitted when `email_security.mailbox_verification.enabled` is `false`.

---

### Tier 3: URL Fetching (Sequential)

Runs after Tier 2 (needs Tier 2 endpoint DB populated).

| Task | Activity | Duration |
|---|---|---|
| `fetch_url` | `RunFetchURLActivity` | Up to 2 hours |

Tools: `gau`, `gospider`, `waybackurls`, `hakrawler`, `katana`.

---

### Tier 4: Directory & File Fuzzing (Sequential)

Runs after Tier 3 (needs Tier 3 URLs).

| Task | Activity | Duration |
|---|---|---|
| `dir_file_fuzz` | `RunDirFileFuzzActivity` → `ParseFuzzResultsActivity` | Up to 4 hours |

Tools: `ffuf` (`run_ffuf`, on by default) fuzzes every target. `dirsearch` (`run_dirsearch`, off by
default) and `feroxbuster` (`run_feroxbuster`, off by default) are optional extra passes over the same
targets and wordlist, so enabling them repeats those requests. With all three off the step logs a
warning and does nothing. A singular `dir_file_fuzz` tool run always runs ffuf (its CLI arguments are
ffuf's), whatever `run_ffuf` says. When the wordlist contains dirsearch-style
`%EXT%` placeholders (the default `dicc`), ffuf and feroxbuster get an expanded copy in the scan
results dir (each `%EXT%` word once per extension, other words as-is) instead of `-e`/`--extensions`;
dirsearch keeps the original list and expands `%EXT%` itself.

Consolidation: `ParseEnumerationResultsActivity` logs total endpoint count.

**Pause point:** `_check_paused()` after Tier 4.

---

### Tier 5: Analysis (Parallel)

| Task | Activity | Duration |
|---|---|---|
| `web_api_discovery` | `RunWebAPIDiscoveryActivity` | Up to 1 hour |
| `waf_detection` | `RunWAFDetectionActivity` | Up to 30 min |
| `secret_scanning` | `RunSecretScanningActivity` | Up to 2 hours |
| Vigolium Analysis | `RunVigoliumAnalysisActivity` | Up to 2 hours |

After all: `ParseAnalysisResultsActivity`.

**Pause point:** `_check_paused()` after Tier 5.

---

### Tier 6: Security Assessment (Parallel)

| Task | Activity/Workflow | Duration |
|---|---|---|
| `vulnerability_scan` | `NucleiPlannerWorkflow` (child workflow) | Up to 10 hours |
| `screenshot` | `RunScreenshotActivity` | Up to 1 hour |
| `waf_bypass` | `RunWAFBypassActivity` | Up to 1 hour |
| `brute_force_scan` | `RunBruteForceScanActivity` | Up to 2 hours |

After all: `ParseAssessmentResultsActivity`.

> **`NucleiPlannerWorkflow`** is spawned as an independent child workflow with its own Temporal history, making vulnerability scan failures and retries independently traceable.

**Pause point:** `_check_paused()` after Tier 6.

---

### Tier 7: Post-Processing & Intelligence (Sequential — Mandatory)

These activities run **unconditionally** for every scan regardless of which tasks are enabled:

| Order | Activity | Duration |
|---|---|---|
| 1 | `CorrelateVulnerabilitiesActivity` | Up to 30 min |
| 2 | `CalculateRiskScoresActivity` | Up to 15 min |
| 3 | `GenerateImpactAssessmentActivity` | Up to 30 min |
| 4 | `SyncGraphActivity` | Up to 30 min |
| 5 | `RunGenericTaskActivity("run_apme")` | Up to 30 min |

---

### Final Step: Scan Completion

`SendScanNotificationActivity` sends email/Slack/webhook notifications that the scan completed.

---

## Pause/Resume Support

`MasterScanWorkflow` supports pausing at tier boundaries:

```python
@workflow.signal(name="pause")
def pause_workflow(self) -> None: ...

@workflow.signal(name="resume")  
def resume_workflow(self) -> None: ...
```

When paused, the workflow calls `await workflow.wait_condition(lambda: not self._paused)` at the next `_check_paused()` point. Temporal's event history ensures durability — no explicit checkpoint is written.

### Sending Signals

```python
client = await TemporalClientProvider.get_client()
handle = client.get_workflow_handle(workflow_id)
await handle.signal("pause")
await handle.signal("resume")
```

---

## NucleiPlannerWorkflow

Child workflow that orchestrates the full vulnerability scanning pipeline. Spawned from Tier 6.

### Tools Orchestrated (sequential within the child workflow)

| Order | Tool | Condition |
|---|---|---|
| 1 | Nuclei (per severity) | `run_nuclei: true` |
| 2 | CRLFuzz | `run_crlfuzz: true` |
| 3 | Dalfox | `run_dalfox: true` |
| 4 | S3Scanner | `run_s3scanner: true` |
| 5 | Acunetix | `run_acunetix: true` |
| 6 | CPanel Scanner | `cpanel_scanner.run_cpanel2shell: true` |
| 7 | WPScan | `run_wpscan: true` |
| 8 | React2Shell | `react_scanner.run_react2shell: true` |
| 9 | Semgrep | `leaks_and_secrets.run_semgrep: true` |
| 10 | Vigolium | `run_vigolium: true` |

Nuclei runs **per-severity** — one activity execution per severity level in `yaml_configuration.vulnerability_scan.nuclei.severity`.

---

## SubScanWorkflow

Used for scanning individual subdomains (not the full domain). Mirrors the MasterScanWorkflow tier structure.

Tasks are grouped by tier:
- **Tier 1:** Discovery (`subdomain_discovery`, `osint`, `baddns`, etc.)
- **Tier 2:** HTTP Crawl + Port Scan
- **Tier 3:** URL Fetching
- **Tier 4:** Directory Fuzzing
- **Tier 5:** Analysis
- **Tier 6:** Security Assessment (`vulnerability_scan`, `screenshot`, `waf_bypass`, `brute_force_scan`)

Post-scan (if `vulnerability_scan` ran): Correlation, Risk Scoring, APME.

All subscans are finalized via `FinalizeSubScanActivity` — one call per task type.
