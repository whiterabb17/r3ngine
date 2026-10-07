# Large-scan resilience: chunked fan-out and duplicate-host reduction

Status: plan for items 4 and 5; nothing of them is implemented. Line references are from 2026-10-05, taken before fixes (a) and (b) below landed, so line numbers in `master_scan.py`, `activities/core.py` and `utils/task.py` have moved.

## 0. Implementation status

Step 1 and step 2 (dir_file_fuzz) are implemented. Where the code differs from sections 3.1-3.6:

- **No child workflow.** `_run_chunked` in `workflows/_common.py` runs inline in `MasterScanWorkflow` Tier 4 and in `SingleTaskRetryWorkflow`, both behind `workflow.patched("chunked-dir-file-fuzz")`. Each batch carries only `(results_dir, task, index, activity_id)`. The plan (`plan.json`, versioned and scoped to the whole scan, one subdomain or a subscan) and a fresh `ctx.json` are kept in `{results_dir}/batches/<task>/`. `max_batches` is capped at 300. Because the master history stays small, `_isolated_tool` does not need to catch `ChildWorkflowError`.
- **Passes.** A batch stopped at its time limit with targets left runs again, up to three passes in total, while the budget lasts.
- **Step outcome.**
  - A batch that still has unfinished targets after its passes, or that failed, makes the step FAILED. Retry and recovery then pick it up, and the fuzz markers make them skip finished targets.
  - Batches never started because the budget ran out leave the step SUCCESS, with a note.
- **Follow-up crawl.** The fuzzer's trailing crawl runs once as `RunChunkedTaskFollowUpActivity`, through `_run_task`, so it gets the time-limit stop. It runs after `FinalizeChunkedTaskActivity` has set the row status, and it does not overwrite an ABORTED row.
- **Item 5, phase 1 (step 3) is implemented as well.**
  - `reNgine/host_dedup.py` holds the rules. `RunTargetDedupActivity` runs after Tier 2 (`workflow.patched("target-dedup")`) and appears as the "Target Deduplication" row. Its migration is `startScan/0070`.
  - The redirect rule counts only when a host's root redirects to the root of another live host of the scan, so apps behind one shared SSO host are not collapsed.
  - The batched fuzzer and the Acunetix submission skip the marked hosts.
  - The step is not run a second time after the crawl bridge.
- **Defaults.** `max_total_hours` defaults to 12, not 8. The budget is checked before each batch run, so the step can end up to one batch time limit later.

## 1. Summary

**Incident.** On a target with many live subdomains, Tier 4 `RunDirFileFuzzActivity` hit its 8h `start_to_close` on both attempts allowed by `_RETRY_LONG_SCAN`. That is about 16h of fuzzing thrown away. `MasterScanWorkflow` then failed, and Tiers 5-7 never ran: no WAF/secrets, no nuclei, no correlation, no APME.

Other single-activity tools grow the same way: vigolium discovery (7h observed), port scan (2.4h), web_api_discovery (2h), fetch_url, nuclei.

**Implemented alongside this plan:**
- **(a)** A tool failure in Tiers 1-6 no longer aborts the scan (`_isolated_tool` in `workflows/_common.py`).
- **(b)** `_run_task` stops a tool just before `start_to_close` and keeps the partial results (`_attempt_stop_time` in `activities/core.py`); `stream_command` kills the running tool and starts no new one once the task is stopping.

These limit the damage but not the cause. One activity still covers the whole surface, one slow host still costs the others their coverage, and a retry re-runs everything.

**This plan:**
- **Item 4, chunked fan-out.** Deterministic host batches, one activity per batch, with its own timeout and retries and bounded concurrency. A failure costs one batch, and a retry re-runs only unfinished batches.
- **Item 5, duplicate reduction.** Collapse hosts that serve the same site (same final URL, www/bare, identical response, parked page) before the heavy tiers. Every skip is listed in the timeline.

Chunking fixes isolation and timeouts, not total work: two parallel batches only halve the wall time. Item 5 and the per-target limits (`max_time`, paths per host) are what cut total work.

## 2. Current state

**Orchestration**
- **Tier 4.** `master_scan.py:505-521` runs `RunDirFileFuzzActivity` (8h, `_RETRY_LONG_SCAN` from `_common.py:19-24`), then `ParseFuzzResultsActivity`.
- **Failure path.** Any exception leaves `success=False` (`:710-715`), and Tier 7 runs only on success (`:719`).
- **Other heavy calls.** vigolium discovery `:332-347` (8h), port scan `:349-359` (6h, inside the Tier 2 `gather`), fetch_url `:416-426` (8h), web_api_discovery `:470-478` (4h), nuclei `:1063-1085` (6h per tag batch).
- **Existing fan-out patterns:**
  - `_fan_out_search_vulns` (`_common.py:139-176`): unbounded `gather(return_exceptions=True)`.
  - `NucleiPlannerWorkflow`: batches planned by an activity (`GatherNucleiTagsActivity`), run in sequence, stopped by a `workflow.now()` budget (`:1060-1072`, `NUCLEI_STAGE_BUDGET_HOURS` at `definitions.py:142`).
  - `SubScanWorkflow` (`subscan.py:64-67`): one host per subscan, each with a full `SubScan` record. Too heavy as a batch unit.
- **Worker capacity.** The Python worker has `max_concurrent_activities=10` shared by all scans (`run_temporal_orchestrator.py:777-785`), so fan-out width must stay small.

**Glue**
- **Activity.** `RunDirFileFuzzActivity` (`enumeration.py:307-326`) calls `_run_task(dir_file_fuzz)`.
- **Parameter passing.** `_run_task` (`core.py:396-582`) passes ctx keys that match task parameters (`hosts`, `urls`) automatically, and turns a `False` return into an exception (`:559-566`).
- **Row tracking.** `TemporalTaskProxy` claims the planned `ScanActivity` row by name (`core.py:192-297`). With `track=False` it creates no row but keeps `ctx['activity_id']`, so Command rows attach to the parent. The per-host nmap runs in `port_scan.py:213-235` already do this.
- **ctx size.** `SeedEndpointsForCrawlActivity` adds `seed_urls`, one URL per subdomain, to the ctx returned at `enumeration.py:76`. Every later activity input carries it.

**Target selection per tool**
- **dir_file_fuzz** (`tasks/fuzzing.py:680-714`):
  - Selection: alive endpoints (`get_http_urls`, `db_queries.py:222-301`), grouped by `scheme://netloc`, up to 10 directory paths of depth ≤2 per base. Each target is fuzzed in turn with the full wordlist, the extensions and recursion (default depth 2). `max_time` defaults to 0 (unbounded).
  - Existing hooks: `urls_override`, `prepare_only`, per-target `fuzz_done_<md5>.marker` (`:65-67`, `:733-736`, `:1029-1031`), Redis lock per target (`:751`).
  - Fixed names that collide in parallel: `dirsearch_{subdomain}.json` (`:829`), and the trailing `http_crawl` (`:1033-1035`) writes `httpx_input.txt` (`httpx_crawl.py:82`).
- **port_scan**: takes a `hosts` parameter or uses `get_subdomains()` (`port_scan.py:55-62`). Fixed files `input_subdomains_port_scan.txt` and `port_scan.txt`. naabu runs once; nmap then runs one host at a time.
- **fetch_url** (`crawl/url_fetch.py:24-75`): default alive URLs or `urls`. Fixed per-tool files `urls_{tool}.txt`, reused as a cache. One merge step builds `fetch_url.txt`, then dedup, gf and http_crawl. `collect_all_scan_urls` (`db_queries.py:304`) reads those files for nuclei. gau/waybackurls are passive and per domain; katana, gospider and hakrawler crawl actively.
- **web_api_discovery** (`crawl/api_discovery.py:152-230`): all alive URLs, deduplicated by pattern. Kiterunner already batches internally and skips subdomains that have a `kr_*.json`. arjun and linkfinder run per URL.
- **nuclei** (`tasks/vuln.py:288-296`): `collect_all_scan_urls` (all endpoints, not only alive), through unfurl/uro, already split by tag batch.
- **vigolium discovery** (`tasks/vigolium.py:605-643`): `https://<every subdomain>` while http_crawl is still running, written to one `discovery.jsonl`.

**Retry and timeline**
- `_TASK_TIER` (`task_plan.py:60-110`) plans one row per task. `SingleTaskRetryWorkflow` dispatches by name (`jobs.py:358-361`), allowed by `RETRYABLE_TASK_NAMES` (`task_plan.py:188-226`).
- `_unsuccessful_task_names` (`scan_init.py:761-785`) counts a name as failed only if no row with that name succeeded. Batch rows that share a name would therefore hide each other's failures.

**Item 5 data**
- **httpx flags** (`httpx_crawl.py:116`): `-cl -ct -rt -location -td -cname -cdn -probe` plus `--follow-redirects`, no `-hash`.
- **Redirect mapping is lost.** `process_httpx_response` (`persistence.py:86-160`) saves the endpoint at the final URL, under the final host's subdomain. The input URL is used only for the `is_default` check. A redirecting host therefore keeps `http_status=0`: endpoint-based tools skip it without saying so, subdomain-based ones do not.
- **Stored fields.** `Subdomain` (`models.py:213-242`): `http_url`, `http_status`, `content_length`, `page_title`, `webserver`, `cname`, `is_cdn`, `cdn_name`; `waf` only after Tier 5. `EndPoint` (`:416-440`) adds `is_redirect`. There is no final-URL field and no body hash.
- **www/bare rule.** Acunetix skips `www.X` when `X` is live (`acunetix.py:936-945`) and writes a Command row for each decision (`:630-650`).
- **Endpoint dedup.** `remove_duplicate_endpoints` (`persistence.py:23-83`) deletes duplicate endpoints, not hosts.

## 3. Item 4: chunked fan-out

### 3.1 Components

**`reNgine/chunking.py`** (pure leaf module)
- `plan_batches(targets, batch_size, max_batches) -> list[list[str]]`.
- Groups by host, so all URLs of a host stay in one batch. The dirsearch file name, the Redis key `fuzz:sig:{scan}:{subdomain_id}` and per-host politeness all depend on that.
- Sorts by host and packs greedily by URL weight. The effective batch size grows so the count never exceeds `max_batches`.
- Deterministic, unit tested without a database.

**`PlanChunkedTaskActivity(ctx, task) -> {activity_id, batch_count, target_count, skipped}`**
1. Claims the planned row through `TemporalTaskProxy` (sets it RUNNING).
2. Gets targets from the task's own selection (`dir_file_fuzz(prepare_only=True)`, `get_subdomains()`, …) and applies the Item 5 filter.
3. Writes `{results_dir}/batches/{task}/plan.json` atomically (mode `0o640`). An existing plan is reused, so retries and resumes get the same batches. Host lists never enter workflow history.
4. Writes one summary Command row.

**`RunChunkedTaskBatchActivity(ctx, task, i, n)`**
1. Returns at once if `done/{i:04d}` exists.
2. Otherwise runs `_run_task(task, {**ctx, track: False, activity_id: parent, batch_dir})` with the batch passed as explicit `urls_override` / `hosts` / `urls` kwargs, not stored in ctx.
3. Writes `batch i/n START (25 hosts: …)` and `DONE` or `FAILED` Command rows, and touches the done marker only on success. Heartbeats come from `_run_task`, and fix (b) applies per batch.

**`FinalizeChunkedTaskActivity(ctx, task, activity_id, results)`** (`@keep_alive`)
- Runs the per-tool merge (table in 3.5).
- Sets the parent row to SUCCESS, or to FAILED with a message such as `"3/17 batches failed (4, 9, 12); Retry re-runs only those"`, kept within the 300-character limit.

**`ChunkedTaskWorkflow`** (child, `workflows/chunked.py`)
- Plan → batches → Finalize, with id `f"{wf_id}-{run_id[:8]}-{task}"`.
- Used by both `MasterScanWorkflow` and `SingleTaskRetryWorkflow`. The same steps are also exposed as an inline helper `_run_chunked()` in `_common.py`.

### 3.2 Bounded, deterministic fan-out

```python
sem = asyncio.Semaphore(cfg.max_parallel)            # safe in temporalio 1.30 workflows
deadline = workflow.now() + timedelta(hours=cfg.max_total_hours)
async def _one(i: int) -> dict:
    async with sem:
        if workflow.now() >= deadline:
            return {"index": i, "status": "skipped_budget"}
        try:
            return await workflow.execute_activity(
                "RunChunkedTaskBatchActivity", args=[slim_ctx, task, i, n],
                start_to_close_timeout=cfg.batch_timeout,
                schedule_to_close_timeout=cfg.batch_timeout * 2 + timedelta(minutes=15),
                heartbeat_timeout=timedelta(minutes=15),
                retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
        except ActivityError as exc:
            return {"index": i, "status": "failed", "error": str(exc.cause or exc)[:200]}
results = await asyncio.gather(*[_one(i) for i in range(n)])
```

- **Ordering.** No bare `asyncio.wait` (its set ordering is not deterministic); use `workflow.wait` if a sliding window is ever needed.
- **Budget.** Batches not started before the budget runs out are reported as skipped, as the nuclei budget does.
- **Concurrency.** `max_parallel` defaults to 2 because of the 10-slot worker. The planner divides `rate_limit` by `max_parallel` (`split_rate_limit`), so the load on the target stays where it is today.
- **Idempotency.** Attempt 2 skips finished targets through the fuzz markers and the done marker.

### 3.3 Timeline: one parent row (recommended)

**One row per batch: rejected.**
- Rows sharing a name break `_unsuccessful_task_names`.
- Distinct names need new `_TASK_TIER`, `RETRYABLE_TASK_NAMES` and `retry_dispatch_name` entries.
- Up to 200 rows per tool floods the timeline.

**One parent row (`dir_file_fuzz`, the existing planned row): recommended.**
- The tier and title maps stay untouched.
- Batches run with `track=False` and the parent's `activity_id`, so all tool commands and batch rows appear in the existing task-detail overlay.
- `target_host` shows `"batch 7/17"` while running; no schema change.
- Any failed batch makes the parent FAILED, so the Retry button and auto-recovery work as today.

**Retry of a failed batch.** The `jobs.py:358-361` branch starts `ChunkedTaskWorkflow` with the same `plan.json` and done markers. Retrying the task therefore re-runs only the failed or skipped batches, with no new UI.

### 3.4 Determinism, versioning and history size

**Versioning.** Guard the new path with `workflow.patched("chunked-dir-file-fuzz")` in `master_scan.py` and `jobs.py`, with the old activity call in `else`.
- Histories that already ran Tier 4 replay the old call. Workflows that reach Tier 4 after the deploy take the new path.
- After the 7-day `execution_timeout` plus margin, use `deprecate_patch`, then remove the old branch.
- Each later tool gets its own patch id, following `web-api-to-tier-3b`.

**History limits.** About 50k events or 50MB per workflow (warning at 10k / 10MB), and 2MB per payload.
- Events are not the problem: about 3 per batch, so 600 for 200 batches.
- Payload is. Every batch carries the ctx, which is 9-26KB of YAML plus `seed_urls`. At 5,000 subdomains that is about 300KB, and 200 batches of it is 60MB, over the limit.
- **Mitigations:**
  1. Slim the batch ctx (drop `seed_urls` and keys `TemporalTaskProxy` never reads); host lists live in files.
  2. Run the fan-out in the child workflow, which adds only about 4 events to the master.
  3. Cap `max_batches` at 200 by default.

  With all three, continue-as-new is not needed. If the cap is lifted, continue-as-new every 500 batches with `(task, next_index, summary)`.

**Fix (a) scope.** Fix (a) must also catch `ChildWorkflowError`, or a failed chunked child still aborts the scan.

**Port scan exception.** Port scan runs inside the Tier 2 `gather`, and `master_scan.py:637-644` explains why a child workflow inside a `gather` can be orphaned. Port scan therefore uses the inline `_run_chunked()` or moves after the `gather`; decide in step 4.

### 3.5 Per-tool notes

| Tool | Batch input | Isolation | Merge in Finalize |
| --- | --- | --- | --- |
| dir_file_fuzz | `urls_override` grouped by host | `skip_post_crawl` inside batches | One `http_crawl` over all targets; then the existing Parse and gf activities |
| port_scan | `hosts` | input and output files under `batch_dir` | Concatenate `port_scan.txt`; `GetDiscoveredServicesActivity` unchanged |
| web_api_discovery | `urls` per host | already per subdomain; check arjun/linkfinder file names | None (DB); CPDE reads `kr_*.json` |
| vigolium discovery | targets file per batch | `discovery/batch_NNNN.jsonl` | Concatenate into `discovery.jsonl` (Tier 5 checks it) |
| fetch_url | `urls`, active crawlers only | `urls_{tool}.txt` under `batch_dir`; gau/wayback run once | Build `fetch_url.txt`, then dedup, gf and http_crawl once. The task must be split in two |
| nuclei | not chunked by host; tag batches + fix (b) suffice | — | Consumes the Item 5 list only |

### 3.6 Engine YAML (per tool section, optional)

```yaml
dir_file_fuzz:
  batching:
    enabled: true            # false = legacy single activity, kept for one release
    batch_size: 25           # hosts per batch
    max_batches: 200
    max_parallel: 2
    batch_timeout_minutes: 120
    max_total_hours: 8       # today's single-activity limit
    split_rate_limit: true
  max_time: 1800             # existing key; new default 30 min per target instead of unbounded
  max_paths_per_host: 10     # currently hard-coded at fuzzing.py:713
```

Suggested `batch_size` / `batch_timeout_minutes` for the other tools: port_scan 50 / 60, web_api_discovery 25 / 90, vigolium_discovery 50 / 120, fetch_url 50 / 120.

Each tool also needs updates to `scanEngine/reference/full_yaml_config.yaml`, the engine fixtures and its engine-editor section in `frontend/src/features/engines/components/sections/`.

## 4. Item 5: duplicate-host reduction

### 4.1 Grouping key

Computed per live subdomain; the first rule that matches wins.

1. **redirect.** Key is the final URL normalised to `scheme://host[:port]/path` (no query, lowercase host, no trailing slash). A host joins the group of the host its final URL is on.
2. **www.** `www.X` and `X`, both live. This is the Acunetix rule, moved to a shared `same_site_as()` helper in `common_func/`, which Acunetix then reuses.
3. **content.** Key `(status, content_length, normalize(title), webserver, body_sha256)`, with the hash coming from adding `-hash sha256` to httpx. Without a hash, a group needs at least `content_min_group` hosts (default 3), because two unrelated login pages can match on length and title.
4. **parked.** Title or body matches a curated list in `definitions.py` (nginx/IIS/Apache default pages, "domain for sale", registrar parking). One representative per (title, webserver).

**CDN/WAF is not a grouping key.**
- One CDN edge usually fronts different origins routed by vhost.
- Catch-all CDN pages (the same 403 or challenge on many hosts) are already caught by rule 3.
- `is_cdn` only lowers that host's batch rate (`cdn_rate_factor`, default 0.5). Port scan already uses `-exclude-cdn`.
- WAF data only exists after Tier 5.

**Representative**, in order: the host matching the final URL's host, then bare over www, then the shortest name, then lexicographic.

### 4.2 Storage and computation

- **http_crawl changes** (`persistence.py`, not one of the files being edited in parallel): `process_httpx_response` also records `final_url` on the *input* host's `Subdomain`, which is lost today. The httpx command gains `-hash sha256`.
- **Migration**, nullable fields on `Subdomain`: `final_url` (2000), `body_hash` (64), `dedup_key` (64, indexed), `duplicate_of` (FK self, SET_NULL), `dedup_reason` (redirect, www, content or parked).
- **`ComputeHostEquivalenceActivity`** (`activities/post_processing.py`):
  - Runs after `ParseHTTPCrawlResultsActivity` (`master_scan.py:321-328`), behind its own patch, and again after the crawl bridge.
  - Recomputes the whole scan in one `transaction.atomic()`, so it is idempotent.
  - Claims a new planned row `target_dedup` (Tier 2, "Target Deduplication") registered in `_TASK_TITLES`, `_TASK_TIER`, `_TIER1_TO_5` and `RETRYABLE_TASK_NAMES`.

### 4.3 Consumption and switches

`exclude_duplicate_hosts(urls_or_qs, ctx, tool)` in `common_func/db_queries.py` drops hosts with `duplicate_of` set when the tool is in `apply_to`.
- It never filters when `ctx['subdomain_id']` is set (subscans) or on a singular tool run.
- Callers: the Item 4 planner, `web_api_discovery`, `vigolium_analysis`/`vigolium_scan`, `collect_all_scan_urls` (nuclei) and the Acunetix submission.

```yaml
target_dedup:
  enabled: true
  group_by: [redirect, www]     # 'content' and 'parked' are opt-in until validated
  content_min_group: 3
  cdn_rate_factor: 0.5
  apply_to: [dir_file_fuzz, web_api_discovery, fetch_url, vulnerability_scan, vigolium_analysis, acunetix_submit]
```

port_scan is excluded on purpose, since ports belong to IPs, not sites. vigolium discovery cannot use the result because it runs before liveness is known.

### 4.4 Visibility

- The `target_dedup` row gets a Command row per skipped host, following the Acunetix `_record_submission` pattern: `SKIPPED a.example.test — same final URL as https://www.example.test/ (redirect)`, plus one summary row.
- Each consuming tool's plan row records how many duplicates it skipped.
- `duplicate_of` goes into the subdomain serializer, for a "duplicate of X" badge and filter in the frontend (themed through `useSemanticColors()`). This is an optional follow-up.

## 5. Rollout (each step behind its own patch id and config switch)

| # | Step | Effort | Main risk |
| --- | --- | --- | --- |
| 0 | Measure the incident: host and target counts, ctx size, history size (Temporal UI + DB) | S | — |
| 1 | `chunking.py`, Plan/Batch/Finalize activities, `ChunkedTaskWorkflow`, `_run_chunked`, ctx slimming, worker registration. Tests: planner determinism, done-marker idempotency, Finalize status, workflow-env test of the semaphore and budget, `test_activity_heartbeats.py` | M-L (3-4 d) | Starving the 10-slot worker; keep `max_parallel` ≤ 2 |
| 2 | dir_file_fuzz on chunking in `master_scan.py` and the `jobs.py` retry; `skip_post_crawl`, `max_time` default, `max_paths_per_host`, YAML and engine form | M (2-3 d) | A target cut short by fix (b) must not get a `fuzz_done` marker; agree on this with the fix (b) author |
| 3 | Item 5 phase 1: `final_url` capture, migration, equivalence activity (redirect + www), Command rows, wired into the fuzz planner and Acunetix | M (2-3 d) | Dropping a real app; low with the redirect and www rules |
| 4 | port_scan: per-batch files, inline fan-out inside the Tier 2 `gather`, nmap fallback per batch | M | Small change in naabu/nmap fallback behaviour |
| 5 | web_api_discovery batched by host; audit arjun/linkfinder output names | M | CPDE reads the files after the whole step |
| 6 | vigolium discovery: per-batch jsonl, merged in Finalize | M | `_discovery_produced_results` and the Tier 5 re-run logic |
| 7 | fetch_url: split crawl from post-processing, batch only the active crawlers | L | `urls_{tool}.txt` cache reuse and the inputs to `collect_all_scan_urls` |
| 8 | Item 5 phase 2: `-hash`, content and parked rules, nuclei and vigolium consumers, frontend badge | M | False positives; ship off, then enable after reviewing the `target_dedup` rows on 2-3 real scans |
| 9 | One release later: `deprecate_patch`, remove the legacy single-activity branches | S | — |

## 6. Open questions

1. What were the live host, alive endpoint and fuzz target counts in the incident scan? The `batch_size` and `max_time` defaults depend on them.
2. How does fix (b) report a truncated run (return value or proxy flag)? Batches must not mark unfinished targets as done.
3. Should the parent row use `PARTIALLY_COMPLETE_TASK` (4) for a partial result? Only FAILED triggers Retry and auto-recovery today, so this plan uses FAILED.
4. Should the worker's `max_concurrent_activities` be raised, or should chunked tools get a dedicated task queue?
5. Should a Retry re-plan to include hosts found since, or reuse `plan.json`? The plan reuses it: simpler and deterministic.
6. Should vigolium discovery move after http_crawl so Item 5 applies to it? That costs Tier 2 parallelism.
7. Is host chunking for nuclei wanted, or are tag batches, fix (b) and Item 5 enough?
