# Changelog

### [v3.6.3]

#### Enhanced

- **Nuclei Batch Tag Counting Optimization**:
  - Replaced the CLI-based `nuclei -tl` tag template counter with a lightning-fast native Python YAML parser. The previous implementation caused Out-Of-Memory (OOM) Docker kills and 30-second timeouts when enumerating 125,000+ templates. Batch template boundaries are now strictly adhered to and no longer crash the orchestration engine.
  - Custom templates uploaded via the UI (`NUCLEI_CUSTOM_TEMPLATE`) and secondary template paths (`NUCLEI_TEMPLATE`) are now dynamically discovered and injected into the count loop, fixing a bug where only the default path was sized.
  - Added an intelligence step to `GatherNucleiTagsActivity`: if previous scanners (e.g. Dalfox or S3Scanner) discovered vulnerabilities like XSS, LFI, or IDOR on the target, Nuclei automatically prepends the `xss`, `lfi`, or `idor` tags to its execution batch. Existing CVE IDs linked to the target also inject the `cve` tag.

#### Fixed

- **ffuf Proxy Compatibility**:
  - Filtered out `socks4` and `socks5` proxies when executing directory fuzzing with `ffuf` to resolve download errors where `ffuf` was rejecting SOCKS proxies format. If a SOCKS proxy is initially selected by the randomizer, `ffuf` will re-fetch and validate an HTTP/S proxy from the pool before executing.

- **CPDE SSL Verification**:
  - Disabled SSL certificate verification in the Custom Parameter Discovery Engine (CPDE) for JavaScript file downloads and OpenAPI schema probing. This fixes widespread download failures where scanning targets with self-signed certificates threw `[SSL: CERTIFICATE_VERIFY_FAILED]` errors and skipped intelligence extraction.

- **WPScan Reliability**:
  - Removed the randomized proxy assignment from the `wpscan --update` initial sequence. Bouncing the signature update through datacenter proxies frequently caused SSL/connection failures blocking WPScan from launching. Updates now always contact WPScan APIs directly.

### [v3.6.2]

#### Enhanced

- **Proxy Fetching & Validation System — Comprehensive Overhaul**:
  Fixed two compounding problems that caused many proxies to appear live at fetch time but be dead by scan time:

  **`check_proxy_robust` (reNgine/common_func.py)**:
  - Both IP-reflection endpoints (`api.ipify.org` + `ip-api.com`) are now checked in **parallel** via `ThreadPoolExecutor`, halving worst-case validation latency (the first success short-circuits the other).
  - Added **IPv4/IPv6 format validation** on the returned IP string using `ipaddress.ip_address()`. Captive-portal pages that return `{"ip": "Login Required"}` or HTML bodies no longer produce false positives.
  - Added opt-in **transparent-proxy detection**: when `OpSec.enable_transparent_proxy_detection=True`, the server's own outbound IP is detected once and any proxy that reports the same IP is rejected.
  - Default timeout raised from 5 s → **10 s** to reduce false negatives on slow SOCKS5 proxies.

  **`get_random_proxy` (reNgine/common_func.py)**:
  - **Freshness short-circuit**: if `Proxy.proxies_verified_at` is within the configured TTL (default 120 min), the batch-verified list is trusted directly and a random entry is returned with **zero re-validation overhead**. Previously every tool call triggered up to 125 s of sequential blocking.
  - When the list is stale, re-validation is now **fully parallel** (up to 50 workers; first live proxy wins, rest cancelled) instead of sequential with an arbitrary 25-cap.
  - Added module-level **`_failed_proxy_cache`** (in-process set): proxies that fail during a scan session are cached and skipped on subsequent calls within the same Celery worker, eliminating repeated timeout waits against already-dead entries.

  **`fetch_proxies_task` (reNgine/tasks.py)**:
  - Batch verification now passes `timeout=10` explicitly to `check_proxy_robust`.
  - After saving the live proxy list, `proxy_obj.proxies_verified_at = now()` is stamped so the freshness short-circuit in `get_random_proxy` is immediately active.

  **`ProxychainsWrapper.get_random_proxy` (reNgine/utils/opsec.py)**:
  - Replaced the old sequential 5-proxy cap with the same **parallel `ThreadPoolExecutor`** pattern used in `get_random_proxy`. All candidates are checked concurrently; first live line wins.

  **`Proxy` model (scanEngine/models.py)**:
  - Added `proxies_verified_at` (`DateTimeField`, nullable) — records when the stored list was last batch-verified.
  - Added `proxy_ttl_minutes` (`IntegerField`, default 120) — configurable TTL for the freshness short-circuit.

  **`OpSec` model (scanEngine/models.py)**:
  - Added `enable_transparent_proxy_detection` (`BooleanField`, default False) — opt-in transparent-proxy rejection.

  **Migration**: `scanEngine/migrations/0015_proxy_verified_at_opsec_transparent.py`

#### Fixed

- **Initiate New Targets modal theme compatibility**:
  Removed hardcoded dark backgrounds and hex colors from `AddTargetModal.tsx` and refactored it to use dynamic theme-aware properties and colors. The modal now renders with a matching background and correct text contrast on the v3 light theme.

- **Scan History drawer theme compatibility**:
  Removed hardcoded dark backgrounds and hex colors from `ScanHistoryDrawer.tsx` and updated components to use theme tokens and values. The drawer now displays with correct light/dark theme compliance and proper contrast.

- **`run_param_discovery_activity` (CPDE) — ScanActivity permanently stuck at RUNNING**:
  Refactored to use `_run_task`, which provides heartbeating, pre-flight abort-guard, and
  `SUCCESS_TASK`/`FAILED_TASK` status updates identical to every other activity. Previously the
  function called `param_discovery` directly with no try/except and never called
  `update_scan_activity`, leaving the `ScanActivity` row at `RUNNING_TASK` forever after
  completion. The no-URLs skip path now also marks the row `SUCCESS_TASK` instead of silently
  returning.

- **`run_search_vulns_activity` (CVE lookup) — all fan-out instances stuck at RUNNING**:
  Same root cause as CPDE: direct call to `search_vulns_scan` with no status update or
  heartbeat. Refactored to use `_run_task`. With 14+ concurrent instances per port scan, this
  left up to 14 `ScanActivity` rows permanently at `RUNNING_TASK`.

- **`web_api_discovery` — silent hang with no subprocess visible**:
  Three bugs in the per-URL loop caused `has_graphql_endpoint` and `has_jwt_tokens` to be
  called for every URL instead of once per subdomain, and LinkFinder to re-run for every URL
  of the same subdomain when its output file was empty:
  - Added `_graphql_gate_cache` (dict keyed by subdomain_name): `has_graphql_endpoint` issues
    a DB `iregex` query against all endpoint rows plus up to 6 network probes × 5 s timeout
    each. With 17 URLs the worst case was 17 × 2 call-sites × 30 s = **17 minutes of silent
    Python I/O** with no subprocess spawned. Now called at most once per subdomain; both the
    InQL and graphql-cop blocks share the same cache.
  - Added `_jwt_gate_cache` (dict keyed by subdomain_name): `has_jwt_tokens` issues 2 DB
    queries per call. Now called at most once per subdomain.
  - Added `processed_linkfinder_subdomains` (set): LinkFinder previously re-ran for every URL
    of the same subdomain when the output file was 0 bytes (no JS found). The primary dedup
    guard is now the set (matching Arjun and ParamSpider); `os.path.exists` remains as the
    Temporal retry guard for files written by a prior activity attempt.

- **Gate-check functions — silent blocking with no log output**:
  `has_graphql_endpoint`, `has_jwt_tokens`, and `has_openapi_spec` now log every DB query
  and every individual network probe (URL, status code or exception) so any future slowdown
  is immediately visible in the orchestrator log rather than appearing as a silent hang.

- **`nuclei_scan` — proxy concurrency cap prevents AdaptiveWaitGroup deadlock**:
  nuclei v3.9.0 deadlocks when concurrency is high and the proxy error rate exceeds ~60%.
  The scan 37 post-mortem confirmed this via a `nuclei-stacktrace-*.dump` showing goroutine 1
  stuck in `semaphore.Acquire` for 9 minutes during the `wordpress,wp,wp-plugin` batch.
  Added `NUCLEI_PROXY_MAX_CONCURRENCY = 10` and `NUCLEI_PROXY_MAX_RATE_LIMIT = 10` constants to
  `definitions.py`. When `proxies_file_path` is set and the file exists, `nuclei_scan()` now
  caps both values before building the command, logging a warning when a cap is applied.

- **`MasterScanWorkflow` — NucleiPlannerWorkflow failure is now isolated**:
  Previously, any failure in `NucleiPlannerWorkflow` (e.g. nuclei deadlock exhausting all
  retries) propagated as an unhandled exception, setting `success = False` and skipping all
  of Tier 7 (vulnerability correlation, risk scoring, Neo4j sync, notification). Scan 37
  had 8 of 9 nuclei batches complete successfully — those findings were never correlated.
  The `execute_child_workflow("NucleiPlannerWorkflow")` call is now wrapped in
  `try/except Exception`, with a `nuclei_failed` flag set on failure. Tier 7 runs
  regardless, processing whatever findings the completed batches wrote to the database.

- **`web_api_discovery` — null `endpoint_id` constraint violation from LinkFinder**:
  `save_endpoint()` returns `(None, False)` for off-domain URLs discovered by LinkFinder
  (CDN links, third-party assets). When such a URL also contained `?`, `save_parameter(None, …)`
  was called, hitting the `NOT NULL` constraint on `Parameter.endpoint_id`. The parameter loop
  now guards with `if endpoint is not None and '?' in full_url:`.

- **`web/.gitignore` — nuclei hang-monitor crash dumps no longer tracked**:
  nuclei's `-hang-monitor` flag writes `*-stacktrace-*.dump` and `crash-resume-file-*.dump`
  to the working directory on deadlock detection. Added three patterns (`*-stacktrace-*.dump`,
  `crash-resume-file-*.dump`, `*.dump`) to `web/.gitignore` so these diagnostic artifacts
  are never accidentally staged or committed.

#### CPDE Enhancements (Parameter Discovery)
- Added `url_param_collector.py` sub-module to `web/reNgine/cpde/`:
  reads `urls_*.txt` (Katana/gau/gospider/waybackurls), `arjun_*.json`,
  `ps_*.txt` (ParamSpider), `kr_*.json` (Kiterunner), and `lf_*.txt`
  (LinkFinder) output files from the scan results directory and converts
  them to CPDE-format findings for the correlation engine.
- Added noise blocklist to `correlation_engine.py`: Google Analytics
  `utm_*`, `_ga`/`_gl`/`_gid`, ad click IDs (`fbclid`, `gclid`,
  `msclkid`), and Cloudflare challenge tokens are now filtered from output
  regardless of confidence score. Blocklist can be disabled per-call with
  `apply_noise_filter=False`.
- CPDE `param_discovery` now correlates parameters from all discovered
  sources (JS AST, OpenAPI, + all tool output files) instead of only
  JavaScript files and OpenAPI schemas.

- **Intelligent Auth Form Extraction — Full Rewrite (`auth_discovery_tasks.py`)**:
  - Replaced the single-attempt, regex-based implementation with a robust two-helper architecture:
    - `_fetch_with_proxy_retry(url, proxy_list)` — tries up to 3 configured proxies in sequence, then falls back to a direct (no-proxy) 4th attempt. Raises only if all four attempts fail, eliminating the previous silent-drop behaviour that caused the feature to always fail when proxies were configured.
    - `_extract_login_forms(html_content, base_url)` — uses `BeautifulSoup` (already in requirements) to find `<form>` elements that contain password fields. Returns structured dicts per form with `action` (absolute URL, `urljoin`-resolved), `method` (GET/POST), `user_field`, `pass_field`, `hidden_fields` (CSRF tokens, nonces), and `all_fields`.
  - Fixed 9 bugs in the original implementation:
    1. **No proxy retry** — single `get_random_proxy()` call; any proxy failure silently skipped the endpoint. Fixed with 3-proxy rotation + direct fallback.
    2. **Fragile password-field detection** — `'type="password"' in content.lower()` missed `type=password` (unquoted), `type = "password"` (spaces), and `autocomplete="current-password"` (WebAuthn). Fixed via BeautifulSoup attribute access.
    3. **Input names from entire page** — regex matched all `name=` attributes site-wide, not just inside the login form. Fixed with per-`<form>` iteration.
    4. **Form `action` URL never captured** — always saved `ep.http_url` as target; the actual POST endpoint (e.g. `/api/auth/login`) was ignored. Fixed via `urljoin` resolution.
    5. **Protocol hardcoded as `'http'`** — HTTPS endpoints recorded with wrong protocol. Fixed using `urlparse(ep.http_url).scheme`.
    6. **F-string logging** — violated security Rule 2.1 (externally-controlled data in f-strings). Fixed to `%s`-style throughout.
    7. **Unused imports** — `import os`, `import json`, `from django.conf import settings` removed.
    8. **Hardcoded User-Agent** — `'Mozilla/5.0'` replaced with `get_random_user_agent()`.
    9. **Narrow keyword list** — expanded from 9 to 18 terms, adding `wp-login`, `wp-admin`, `dashboard`, `session`, `oauth`, `sso`, `saml`, `sign-in`.
  - Added SSRF protection: scheme validated (`http`/`https` only) before every fetch.
  - Added `http_status__isnull=False` guard and `select_related('subdomain')` to the endpoint queryset (null-status safety + N+1 fix).
  - Hidden fields (CSRF tokens, nonces) now captured and stored in `AuthCandidate.metadata['hidden_fields']` for use by the brute-force engine.
  - TOR mode respected: when `use_tor=True`, `get_random_proxy()` returns `socks5://tor:9050` which is used as the single proxy entry in the rotation.
  - 21 new tests in `web/tests/test_auth_discovery_tasks.py` covering proxy retry, form extraction, and orchestrator integration.

- **Scan Recovery Enhancement (`recover_stuck_scans`)**:
  - Extended the recovery candidates queryset to include `FAILED_TASK` scans in addition to `RUNNING_TASK`. Scans that were previously marked as failed due to a dead workflow are now picked up on the next orchestrator restart and re-queued.
  - Aborted scans (`ABORTED_TASK`) continue to be excluded from recovery.

- **Scan Task Plan — Always-Present Tier-7 Finalisation Tasks**:
  - `build_scan_task_plan` now unconditionally appends `correlate_vulnerabilities`, `calculate_risk_scores`, `generate_impact_assessment`, `sync_graph`, and `run_apme` to every scan plan, regardless of which scanning tiers are configured. Previously these were gated behind `'vulnerability_scan' in tasks`, meaning minimal-config scans never ran correlation or risk scoring.

- **Docker Build Image Size Optimization**:
  - Relocated the Exploit-DB/Searchsploit database (~359MB) from build-time to container runtime. It is now dynamically cloned at startup inside the `temporal-python-orchestrator` container and shared with other containers via a new named Docker volume `exploitdb`.
  - Added dynamic check-and-copy of the `.searchsploit_rc` configuration file within `RunSearchsploitAction` as a runtime safeguard.
  - Cleared intermediate build caches in the Dockerfile, including cleaning Python `uv` package cache (`uv cache clean`), cleaning Ruby gem cache (`rm -rf /var/lib/gems/*/cache/*.gem`), and cleaning the Playwright `apt` lists (`rm -rf /var/lib/apt/lists/*`), saving an additional ~1.34GB.

- **APME Task Errors & Neo4j Compatibility Fixes**:
  - Refactored `_dijkstra_query` in `pathfinder.py` to replace `apoc.algo.dijkstra` with a native Cypher variable-length path matching query. It dynamically filters relationships by confidence and calculates cost weights via `REDUCE`, avoiding procedure exceptions (like `NotFoundException` or `BufferError` resizing crashes) while properly supporting custom path weights.
  - Replaced the deprecated/illegal `size((n)--())` Cypher pattern function with modern `COUNT { (n)--() }` in `query_node_degree` to prevent syntax errors in Neo4j 5.x+.
  - Updated the relationship merging transaction helper to map and store all 18 constraint flags (e.g. `requires_docker`, `requires_drupal`) as relationship properties in Neo4j, eliminating DBMS `UnknownPropertyKeyWarning` messages during path queries.
  - Enhanced `Scorer._compute_recency` to robustly handle CVE published dates formatted as strings, datetimes, or dates (with safe fallbacks), preventing a Temporal recalculate_apme task crash (`TypeError: unsupported operand type(s) for -: 'datetime.date' and 'str'`).
  - Added comprehensive test coverage in `test_apme_enhancement2.py` validating string-formatted date scoring scenarios and fallbacks.

- **WPScan Parser & WPTaint Integration (Security & LLM Enrichment)**:
  - Refactored `parse_wpscan_results` to split the logic into 5 private helper functions: `_parse_interesting_findings`, `_parse_version`, `_parse_plugins`, `_parse_themes`, and `_parse_users`.
  - Added a dynamic catchall block in `_parse_interesting_findings` that extracts all unrecognized finding fields and formats them into a clean markdown description.
  - Rewrote `save_finding` to accept an explicit `severity` string argument and map it correctly to Django model `severity` integers via `NUCLEI_SEVERITY_MAP`.
  - Fixed three invocations of `stream_command` in `wptaint_tasks.py` to correctly consume the generator iterator and pass correct arguments instead of `self`.
  - Extended wp-taint plugin discovery to support three sources of WordPress plugin slugs (legacy `WordPress Plugin: {slug}`, `WordPress Plugin: {slug} - {vuln title}`, and `WordPress Plugin Detected: {slug}`) and HTTP URLs matching the pattern `/wp-content/plugins/([^/?#]+)/` from crawled or fuzz-discovered endpoints.
  - Ensured that new findings from both WPScan and WPTaint are dynamically passed through the LLM description generator (`get_vulnerability_gpt_report`) with full PII anonymization layer. Added checks to verify if a description/GPT has already been generated (`is_gpt_used=False`) before triggering the LLM call.
  - Added comprehensive tests in `test_wpscan.py` and `test_wptaint.py`.
  - Fixed `parse_wptaint_results` crashing with `'str' object has no attribute 'get'` for every plugin: `taint-scan` emits `{"summary": {...}, "results": [...], "errors": null}` but the parser was iterating the top-level dict (yielding string keys). Added `_CHECK_ID_MAP` mapping all 11 known `check_id` values to `(severity, canonical_name)` tuples with a keyword-based fallback for future rules, and rewrote the field extraction to use the actual schema (`check_id`, `extra.message`, `path`, `start.line`, `extra.dataflow_trace`). Validated against 256 findings across 12 plugins from a live scan.

- **WPScan Execution Reliability**:
  - Automatically runs `wpscan --update --no-banner` (with rotation proxies if configured) before starting the scan loop to ensure up-to-date vulnerability definition databases.
  - Strips the trailing slash of each target URL to normalize inputs.
  - Implements a retry mechanism (up to 3 retries, 4 total attempts) if WPScan aborts with an SSL certificate/metadata verification error (`SSL peer certificate or SSH remote key was not OK`).
  - Automatically executes the final retry attempt without the `--proxy` option to bypass potential proxy-induced SSL negotiation issues.

- **Offline Hash Cracking & Wordlist Customization (Credential Intelligence Plugin)**:
  - **Offline Cracking Engine**: Implemented containerized Hashcat support inside `credential_intelligence` viewset utilizing host Docker socket (`/var/run/docker.sock`).
  - **Dynamic Device Detection**: Container automatically requests NVIDIA GPU runtimes if present, and seamlessly falls back to CPU execution if no GPU drivers are detected.
  - **Flexible Parameter Customization**: Allowed users to fully customize cracking tasks with support for arbitrary integer hash types (`-m`), attack modes (`-a`), custom rules (`-r`), brute-force/mask patterns, custom charsets (`-1`, `-2`, `-3`, `-4`), increment modes, optimized kernels, and force runtimes.
  - **Database & Model Schema**: Refactored the plugin app config label to `credential_intelligence_backend` and updated meta labels to resolve dynamic migration issues. Added `HashCrackingTask` and `CrackedHash` (encrypted passphrases at rest) models.
  - **UI Interface Dashboard**: Created a tabbed glassmorphism offline cracking dashboard in the plugin UI with a log terminal window showing live container stdout and a cracked plaintexts table.
  - **Wordlist Management**: Developed a Custom Wordlists management tab to upload, list, and delete custom `.txt` wordlist files in the shared system volume.

- **Nuclei Proxy Rotation Support**:
  - Implemented dynamic creation of a `proxies.txt` file (populated with valid system proxies, excluding Tor/SOCKS routing endpoints) via `CreateProxyListActivity`.
  - Configured `NucleiPlannerWorkflow` to use this proxy list via the `-proxy` flag in Nuclei command execution, allowing Nuclei to rotate through available HTTP/S proxies when conducting vulnerability templates.
  - Added safe cleanup of the temporary proxy list via a `finally` block executing `CleanupProxyListActivity` regardless of scan success or failure.

- **Intelligent Tool Gating (Tier 5)**:
  - **JWT tool gate**: `jwt_tool` now only runs when JWT tokens have been detected in the current scan. Detection checks `Parameter` records with `is_auth_related=True` whose name matches known JWT patterns (`jwt`, `bearer`, `authorization`, `access_token`, `refresh_token`, `id_token`, `auth_token`), and `SecretLeak` records whose `secret_type` indicates a JWT or Bearer token. Scans against non-authenticated endpoints no longer waste time running JWT algorithm-confusion attacks.
  - **GraphQL tool gate**: Both `InQL` and `graphql-cop` now gate on confirmed GraphQL endpoint presence. The gate first checks existing `EndPoint` database records for URLs matching `/graphql` or `/graphiql` (zero network cost), then falls back to HEAD-probing 6 common GraphQL paths if the DB has no evidence. Tools are skipped with a clear log entry on non-GraphQL targets.
  - **OpenAPI discovery gate**: The CPDE OpenAPI discoverer now gates on `has_openapi_spec()` before calling the full `discover()` pipeline. The gate uses lightweight HEAD requests against the same 14 probe paths used by the discoverer itself, avoiding up to 14 full GET requests per host on targets that serve no API documentation.
  - Added `has_jwt_tokens()`, `has_graphql_endpoint()`, and `has_openapi_spec()` helper functions to `common_func.py` for reuse across the scan pipeline.

- **CPDE (Custom Parameter Discovery Engine) — End-to-End Fixes**:
  - **URL derivation fix**: The `RunParamDiscoveryActivity` no longer silently no-ops when `urls` is absent from the scan context. It now queries `EndPoint` records for the scan, falls back to domain name construction, and logs a warning with early return if still empty.
  - **Missing dependency**: Added `esprima==4.0.1` to `requirements.txt`; the JS AST analyzer was silently skipping all JavaScript analysis due to the missing import.
  - **Neo4j property mismatch**: Fixed 3 Cypher `MATCH` clauses in `graph_writer.py` that referenced `http_url` on `Endpoint` nodes — the graph stores `url`, causing all graph enrichment writes to silently match zero nodes.
  - **`get_neo4j_driver()` helper**: Added to `reNgine/utils/graph.py` so `cpde_tasks.py` can obtain a driver without re-implementing manager instantiation.
  - **Proxy sourcing**: Replaced direct `Proxy.objects.first()` access with `get_random_proxy()` from `common_func.py`, respecting TOR mode and the `use_proxy` scan flag.
  - **ParameterSerializer**: Replaced broken serializer (referenced non-existent `is_reflected`/`is_source`/`is_sink` fields) with correct CPDE fields and a nested `ParameterEndpointSerializer` so `endpoint.http_url` is returned instead of a bare PK integer.
  - **Parameters tab filtering**: Added 7 server-side filter parameters to `ParameterViewSet` (`param_location`, `is_auth_related`, `observed_in_js`, `observed_in_openapi`, `observed_in_graphql`, `confidence_min`, `data_type`) and a collapsible filter panel in the frontend `ParametersTab` component.
  - **Report integration**: `generate_report_task` now queries and passes `Parameter` records to all four report templates (`modern`, `enterprise`, `cyber_pro`, `default`), each with a gated Discovered Parameters table.

- **Vigolium Scanning Enhancement**:
  - Removed incorrect inline parsing of the `--known-issue-scan-severities` argument inside `vigolium_tasks.py`.
  - Configured vigolium globally at the container level (in both Python and Go temporal entrypoints) using `vigolium config set known_issue_scan.severities "critical,high,medium,low,info"` to ensure all severity levels are scanned by default.

- **HTTP Crawl Bridge & Technology Mapping Propagation**:
  - Added a second HTTP crawl task, `HTTP Crawl Bridge` (`http_crawl_bridge`), executed in between URL fetching and directory fuzzing.
  - Dynamically checks any endpoints that are dead or not alive, as well as all new/uncrawled endpoints, updating their status and mapping their technologies.
  - Removed the `endpoint.is_default` constraint when saving technology objects, enabling technologies discovered on *any* endpoint to propagate to `subdomain.technologies`.
  - Integrated the bridge task in both `MasterScanWorkflow` and `SubScanWorkflow` (Tier 3a).

- **Target Editing**:
  - Added a comprehensive **Edit Target** modal accessible directly from the Targets page, allowing full post-creation customization of every target parameter without deleting and recreating the entry.
  - **Edit button in each row**: A dedicated amber pencil (`✏`) icon button is now rendered inline per target row, alongside the existing Initiate Scan and 3-dot menu controls. "EDIT TARGET" also appears as the first item in the row's context menu.
  - **Comprehensive modal form**: The `EditTargetModal` exposes all editable `Domain` fields organized into sections — Identity (target name shown read-only, target type selector), Metadata (description, organization reassignment, HackerOne team handle), Scope Configuration (in-scope IPs/CIDRs, secondary domains), Advanced Scan Configuration (starting point path, excluded paths), and Continuous Monitoring (frequency, scan scope, engine).
  - **Backend REST endpoint**: New `POST /api/update/target/` endpoint (`UpdateTarget` APIView, `PERM_MODIFY_TARGETS` gated). Accepts all editable fields and correctly handles `excluded_paths` as either a JSON list or newline-delimited string. Organization reassignment is handled via the `Organization.domains` M2M relationship. Monitoring field changes automatically trigger `manage_monitoring_task()` to upsert or delete the corresponding Temporal schedule.
  - **React Query integration**: Added `useUpdateTarget` mutation hook that posts to the new endpoint and invalidates the `['domains', projectSlug]` query key on success, keeping the targets list in sync without a page refresh.

- **API Security Hardening**:
  - **Swagger/OpenAPI docs now require authentication**: Changed `permission_classes` from `AllowAny` to `IsAuthenticated` and set `public=False` on the schema view. Removed `/swagger/` and `/redoc/` from `LOGIN_REQUIRED_IGNORE_PATHS` — API docs are no longer publicly accessible to unauthenticated users.
  - **JWT refresh token blacklisting**: Enabled `rest_framework_simplejwt.token_blacklist` app and set `BLACKLIST_AFTER_ROTATION=True`. Rotated refresh tokens are now immediately invalidated in the database, preventing replay attacks with leaked refresh tokens.
  - **Swagger security scheme**: Added Bearer token security definition and session login/logout links to `SWAGGER_SETTINGS` so authenticated users can authorize and test API endpoints directly from the explorer.
  - **Dead ignore-path cleanup**: Removed the never-registered `/redoc/` entry from `LOGIN_REQUIRED_IGNORE_PATHS`.

- **SearchSploit & CVE LLM Target Attribution**: 
  - Added `host` and `port` assignment to `searchsploit_scan` to correctly attribute findings with an `http_url`. 
  - Integrated `LLMVulnerabilityReportGenerator` into `search_vulns_scan` and `searchsploit_scan`. Findings dynamically hit the LLM (if enabled) for risk assessments, map descriptions and mitigations, and cache results in the local `CveId` database.

- **Attack Path Modeling Engine (APME) UI & Rules Enhancement**:
  - **Tactical AI Path Explanations ("Explain This")**: Implemented an AI-powered tactical explainer that generates step-by-step intelligence breakdowns of attack vectors for both the React Web App and React Native Mobile App.
  - **Two-Way PII Protection**: Masked all private data (IP addresses, emails, hostnames) via the backend `PIIGate` wrapper before invoking the active LLM, restoring original values prior to client delivery.
  - **Caching & Persistence**: Stored the generated explanations directly inside the `potential_attack_chain` JSON database field under the `explanation` key to allow immediate retrieval on subsequent views without regeneration.
  - **Rules Engine Gaps**: Fixed a mismatch in the APME rules engine where `pivot_to_internal_discovery` targeted a capability subtype `"internal_discovery"` that was not declared in `NODE_TYPES["Capability"]` in `schema.py`. Added `"internal_discovery"` to the capability schema.
  - **Attack Rules Expansion**: Added rules for SSRF (`ssrf_to_cloud_access`, `ssrf_to_pivot`), LFI (`lfi_to_rce`, `lfi_to_data_exfil`), XXE (`xxe_to_data_exfil`, `xxe_to_ssrf`), XSS (`xss_to_auth_access`), and Open Redirect (`redirect_to_auth_access`).
  - **Enriched Step Nodes API**: Updated the backend path serialization (`serializer.py`) and orchestrator persistence flow (`orchestrator.py`) to resolve and serialize full node properties (type, subtype, name, cvss_score, severity, vuln_id) as `from_node` and `to_node` objects instead of only transmitting raw string IDs.
  - **Interactive Visual Timeline UI**: Replaced the simple vertical text row list of raw IDs with a visually stunning, responsive compromise chain timeline in `AttackPathsTab.tsx` and the React Native Mobile app. Features colors and icons matching node types (Asset, Vulnerability, Capability, Privilege, Credential), CVSS scores, step-by-step actions, and direct links to verify details.
  - **Description Truncation Fix**: Replaced the severe truncation (`noWrap`) on the finding descriptions with a clamped two-line preview in the collapsed card header and a full, multi-paragraph Executive Narrative display inside the expanded drill-down details view.
  - **On-Demand Recalculation**: Added a "RE-CALCULATE PATHS" button in the Web Attack Paths tab header and mobile Summary tab. It invokes the newly registered `RecalculateApmeWorkflow` Temporal workflow to rebuild the attack path modeling graph asynchronously and update local database entries.
  - **Schema Expansion (Enhancement 2)**: Extended node taxonomy with 23 new technology subtypes, 48 new vulnerability subtypes, and 13 new capability subtypes. Added `Technology` nodes with `USES_TECH` relationship edges to model software stack composition within the attack graph. Extended `TAXONOMY_MAP` with 50 new keyword mappings and 4 new vulnerability node properties for richer semantic resolution.
  - **Constraint Engine (11→22 gates)**: Doubled the constraint gate count from 11 to 22, adding 12 new technology-gate flags (`requires_docker`, `requires_drupal`, `requires_windows`, `requires_kubernetes`, `requires_active_directory`, etc.) that prevent infeasible attack steps from appearing in paths, reducing false-positive attack chains.
  - **Rules Library (76→179 rules)**: Expanded from 76 to 179 rules. Added 29 new rules to 5 existing category files (injection, server-side, auth, client-side, info-disclosure) and 8 entirely new category files: `network.yaml` (pivoting/lateral movement), `container.yaml` (container escapes/supply-chain), `active_directory.yaml` (AD attacks), `api.yaml` (API exploit chains), `email.yaml` (email-based pivots), `supply_chain.yaml` (dependency compromise), `dotnet.yaml` (.NET deserialization), `persistence.yaml` (persistence mechanisms).
  - **Scoring Overhaul (10-Factor Weights)**: Rebuilt the vulnerability scorer with 10 independently tunable factor weights (up from 6): EPSS probability weight (0.15), tiered KEV severity boost (1.2×/1.5×/2.0× by severity), confidence product multiplier, speculative path tier adjustment, ERL validation step guard, and constraint-22 cap enforcement.
  - **Pathfinder Improvements**: Implemented semantic path deduplication to eliminate structurally equivalent paths with different node orderings. Reduced DFS maximum depth from 8 to 6 hops. Added 2-step minimum hop filter to remove trivially short chains. Enforced fan-out cap at 12 successor nodes per step. Added DFS fallback when Dijkstra returns zero results on sparse graphs.

- **APME Resilience & Temporal Stability**:
  - **Pathfinder Entry Point Cap**: Capped pathfinder entry-point selection at 50 nodes per graph to prevent Cypher query explosion on large Neo4j installations.
  - **Neo4j Per-Query Timeout**: Added a 30-second timeout to all Neo4j path queries to prevent hung Temporal activity threads.
  - **Temporal Heartbeats in APME Pipeline**: Wired Temporal activity heartbeats through all 7 APME orchestrator pipeline steps, enabling heartbeat-based timeout detection and proper Temporal failure reporting.
  - **RecalculateApmeWorkflow Resilience**: Set 30-minute execution timeout and maximum 3 retries on `RecalculateApmeWorkflow` to prevent infinite retry loops on persistently failing graphs.
  - **Neo4j Heap Configuration**: Tuned Neo4j JVM heap to 768 MB initial / 1536 MB maximum (`NEO4J_server_memory_heap_initial__size=768m`, `NEO4J_server_memory_heap_max__size=1536m`) to fit safely within the 3 GB container memory limit.
  - **LLM Orchestrator M2M Fix**: Fixed `AttributeError: 'Subdomain' object has no attribute 'ip_address'` in `llm_orchestrator.py` — updated to use the M2M `ip_addresses` relationship with `prefetch_related` to correctly gather open ports for LLM context enrichment.


- **Custom Parameter Discovery Engine (CPDE)**:
  - Added the Custom Parameter Discovery Engine (CPDE) to allow users to define custom regular expressions and keyword matchers to extract sensitive or high-value parameters across scan results.
  - **Backend**: Added the `Parameter` model with `type` (`regex`/`string`), `severity`, and `description` fields. Implemented REST API endpoints (`/api/settings/parameters/`) for full CRUD management.
  - **Frontend Configuration**: Built a dedicated "Custom Parameters" panel in the Settings page for managing parameters.
  - **Scan Integration**: Scan results now include a "Parameters" tab detailing all discovered custom parameters, their occurrence counts, severity levels, and the specific endpoint URLs where they were found.

- **WP Taint Scan Integration**:
  - Integrated `wp-taint-scan` to automatically perform Static Application Security Testing (SAST) on discovered WordPress plugins.
  - The tool downloads plugin source code from the WordPress repository and runs taint analysis, parsing the results directly into the `Vulnerability` database.
  - Configured Temporal workflows to execute `wp-taint-scan` sequentially as the final tool against WordPress targets, ensuring maximum plugin discovery coverage.

- **CVE Enrichment Expansion (SploitScan & LLM Integration)**:
  - **SploitScan Integration**: Integrated the `sploitscan` CLI to pull real-world exploit evidence directly into the CVE pipeline. Automatically extracts ExploitDB, Metasploit, and GitHub Proof-of-Concept links, along with HackerOne Hacktivity statistics and overarching patching priority.
  - **Automated AI Risk Assessment**: Integrated the native `LLMVulnerabilityReportGenerator` into the enrichment flow. The system automatically prompts the active LLM (OpenAI, Anthropic, Gemini, or Ollama) with CVSS metrics and public exploit counts to generate a structured, context-rich risk assessment and mitigation strategy.
  - **Persistent Intelligence Cache**: Expanded the `CveId` model (Migration 0042) to permanently store `ai_risk_assessment`, `mitigation_ideas`, `public_exploits`, `hackerone_data`, and `patching_priority`, drastically reducing API calls and LLM token usage on subsequent scans.
  - **Daily EPSS Feed Synchronization**: Implemented a local `EpssFeedData` database table and a scheduled Temporal task (`sync_epss_data`) that fetches the daily EPSS CSV feed from FIRST/Cyentia at 8:00 AM. Local EPSS querying completely eliminates rate-limiting and 429 errors from the external EPSS API, resulting in near-instant enrichment during scans.

- **LLM Vulnerability Analysis & Tier 7 Enrichment**:
  - Fixed `parse_llm_vulnerability_report` to handle all LLM output styles (`Header:\ncontent`, `Header:\n\ncontent`, `Header: inline content`) — the previous `re.split(r':\n')` silently returned an empty dict on any response that did not place content on a new line immediately after the colon, causing an HTTP 500 "Failed to parse LLM response" error on the vulnerability analysis endpoint.
  - Fixed `get_vulnerability_gpt_report` to always update the specific requested vulnerability by ID before running the name/path bulk-update query. The previous `http_url__icontains=path` filter silently skipped findings with a `NULL` http_url because Django's `icontains` lookup does not match NULL columns.
  - Tier 7 Impact Assessment (`generate_impact_assessment`) now automatically calls `get_vulnerability_gpt_report` for every vulnerability that has not yet been LLM-enriched (`is_gpt_used=False`), populating `description`, `impact`, `remediation`, and `references` on the `Vulnerability` record during every full scan without manual intervention. The `LLMImpactGenerator` business-impact narrative is stored in `ImpactAssessment.potential_impact` only and no longer overwrites the richer structured GPT content on `Vulnerability.impact`.
  - Fixed naive `datetime.now()` usage in `test_stress_phase2.py` (replaced with `timezone.now()`) that generated Django `RuntimeWarning` on `ScanHistory.start_scan_date`, `StressTestResult.start_time`/`end_time`, and `StressTelemetryPoint.timestamp` fields when `USE_TZ=True` is active.

- **Temporal Activity Stabilizations**:
  - Fixed a `TypeError` signature mismatch in `_run_task` that crashed reconnaissance activities (such as `searchsploit_scan` and `wafw00f_scan`). The workflow engine now uses `inspect.signature` to intelligently inject Context (`ctx`) and descriptions only when supported by the underlying scanner function.

- **Ollama Orchestration UI & Backend Integration**:
  - Implemented dynamic Docker orchestration for the local Ollama LLM provider. The LLM Toolkit settings page now includes a built-in Docker container lifecycle manager, allowing users to start and stop the `ollama` container directly from the UI.
  - Developed `OllamaManager` using `docker.from_env()` to automatically pull, start, and manage the `ollama/ollama:latest` image inside the dynamically discovered `r3ngine` Docker network.
  - Added REST endpoints (`/ollama/service_status`, `/ollama/service_start`, `/ollama/service_stop`) and React Query hooks to seamlessly coordinate container state with the UI.
  - Designed the UI to prevent interactions like "Test Connection" or model selection when the service is stopped.

- **Metasploit Integration Terminal Stabilization (Plugin)**:
  - Fixed interactive console text formatting and squishing issues by ensuring properly structured PTY WebSockets handling in the Django Channels consumer.
  - Implemented a "Kill Instance" switch to quickly terminate and clean up hanging Metasploit container processes.
  - Migrated `msf_console` to the Docker SDK, ensuring spawned containers are properly labeled (`com.docker.compose.project: 'r3ngine'`) and attached to the project's native network.

- **LinkedIn Intelligence — Session-Based Authentication**:
  - Replaced the password-based `launch_persistent_context()` approach with a two-tier session model: Playwright `storage_state.json` tried first, LinkedIn session cookies injected from the API vault as fallback.
  - No password is ever stored in the database. The `password` field has been removed from `LinkedInCredentials` via migration `0017`. The model gains `cookies_json`, `state_file_path`, `last_validated_at`, and `is_valid` fields.
  - Authentication failures (expired state file, invalid cookies, LinkedIn bot challenges, MFA prompts) log a structured operator note and gracefully skip LinkedIn OSINT — the scan continues without interruption.
  - Added four REST API endpoints under `/api/linkedin/session/`: `upload/` (accepts `storage_state.json` multipart or raw `cookies_json` payload), `status/` (reports `is_valid`, `last_validated_at`, `has_state_file`, `has_cookies`), root `DELETE` (clears state file from disk and resets all session fields), and `helper/` (serves a downloadable standalone Python capture script).
  - The downloadable `linkedin_capture.py` helper script launches a headed Chromium browser on the user's local machine, waits for manual login (including MFA), and saves `storage_state.json` for upload. No credentials ever leave the user's machine.
  - All file-system operations on `state_file_path` enforce path-traversal protection (`_validate_state_path`) — both reads and writes are bounded to `{RENGINE_RESULTS}/context/linkedin/`.
  - Added `LinkedInSessionCard` React component: live status indicator (green/amber/red), file upload, session revocation, and helper script download — all via the API vault settings page.
  - 24 tests covering model fields, scraper authentication paths (storage_state, cookie injection, graceful fallback), all four API endpoints, and `run_linkedint` caller resilience.

- **Report Settings — 2-Column Layout & Found Parameters Toggle**:
  - Reorganized the Report Settings checkbox area into a two-column grid: left column holds "Ignore Information Vulnerabilities" and "Include Attack Surface Map"; right column holds "Include Attack Paths" and the new "Include Found Parameters".
  - Added **Include Found Parameters** checkbox, which gates whether discovered `Parameter` records are appended to the generated report. The flag is passed as `include_found_parameters` in the report generation request to `/scan/create_report/`.

- **Fix: Report Generation Respects `include_found_parameters` Checkbox** (`startScan/views.py`, `reNgine/report_tasks.py`):
  - Previously the "Include Found Parameters" checkbox in the report generation modal had no effect — `Parameter` records were always included in the report regardless of the user's selection.
  - Root cause: `create_report` was not persisting the `include_found_parameters` flag in `ScanReport.params`, so `generate_report_task` always ran the parameters queryset unconditionally.
  - Fixed by reading `include_found_parameters` from the GET request in `create_report` (defaulting `True` for backward-compat) and storing it in `ScanReport.params`. `generate_report_task` now reads the flag and gates the `Parameter` queryset behind `include_found_parameters`, producing reports without a parameters section when the box is unchecked.

- **Fix: Temporal Workflows No Longer Resume Aborted or Deleted Scans** (`reNgine/temporal_activities.py`):
  - After a container restart, Temporal replays durable workflows from its own history independently of Django's database. Scans that were aborted or deleted before the restart would continue executing, causing:
    - **Deleted scans**: `IntegrityError` FK violations (`scan_history_id` not present in `startScan_scanhistory`), triggering infinite Temporal retry loops.
    - **Aborted scans**: `TargetProfilingActivity` was unconditionally re-arming `scan_status` back to `RUNNING_TASK`, silently undoing the abort.
  - Root cause confirmed by container logs showing the `dalfox_xss_scan` activity for deleted scan #32 entering an infinite retry cycle after every restart.
  - Fixed with a two-layer guard using Temporal's `ApplicationError(non_retryable=True)`:
    - **Layer 1 — `TargetProfilingActivity`**: Acts as the primary lifecycle guard (first real activity every workflow runs). If `ScanHistory` does not exist or has `scan_status=ABORTED_TASK`, raises a non-retryable error to permanently terminate the workflow before any work is attempted. The unconditional re-arm of `ABORTED_TASK` status has been removed; only `FAILED_TASK`/other states are re-armed to `RUNNING_TASK`.
    - **Layer 2 — `_run_task` helper**: Pre-flight guard at the entry point of every activity function. Catches activities that were in-flight mid-scan at the time of abort/delete, preventing them from proceeding and entering retry loops.
    - **Layer 3 — `CheckScanAliveActivity` (child workflow guard)**: Child workflows (`NucleiPlannerWorkflow`, `SubScanWorkflow`) are replayed by Temporal independently of `MasterScanWorkflow` after a container restart, so they skip Layer 1 entirely. A new `CheckScanAliveActivity` is now called as the **first activity** in both child workflows. It performs the same abort/delete check and raises `ApplicationError(non_retryable=True)` to terminate the child workflow cleanly before any scan data is accessed. This closes the remaining gap in lifecycle guard coverage for replayed child workflows.
  - Orphaned `TemporalWorkflowExecution` DB records for aborted scans (scans 4 and 8) were reconciled and marked `CANCELLED`/`TERMINATED`. The actively-looping workflow for deleted scan 32 (`master-scan-32-run-0-f36d62b1-nuclei`) was cancelled directly via the Temporal API.
---

### [v3.5.0] - 2026-06-04

- **Python 3.12 Runtime Upgrade**:

  - Upgraded the container execution runtime from Python 3.10 to Python 3.12 to improve performance by ~25% and ensure support until October 2028.
  - Configured the trusted deadsnakes PPA signing keyring (`/usr/share/keyrings/deadsnakes.gpg`) to install `python3.12`, `python3.12-dev`, and `python3.12-venv` in the Ubuntu 22.04 base image.
  - Avoided installing the system `python3-pip` package (which forces default Python 3.10 installation) by bootstrapping Python 3.12's `ensurepip` module directly.
  - Linked pip wrappers and updated `update-alternatives` to redirect global `python`/`python3` and `pip`/`pip3` to 3.12.
  - Replaced the hardcoded Python 3.10 path inside `temporal-entrypoint.sh` (whatportis bugfix) with a dynamic module path lookup (`python3 -c "import whatportis.cli; print(whatportis.cli.__file__)"`).

- **Fix gRPC Connection Cancellation Error**:
  - Resolved `temporalio.service.RPCError: operation was canceled` in the python container during workflow execution result retrieval.
  - Refactored `stream_command` in `web/reNgine/utils/task.py` to create a single `asyncio.Task` wrapper around `handle.result()` and poll it using `asyncio.wait()`, preventing the accumulation of leaked history-fetching coroutines on timeout.
  - Ensured the task is cleanly cancelled on early exit or scan aborts.

- **Mobile App Login and ALLOWED_HOSTS Fix**:
  - Automatically dynamically extract and trust the host from `DOMAIN_NAME` inside `web/reNgine/settings.py` so the configured domain works out-of-the-box.
  - Forward the `ALLOWED_HOSTS` environment variable to the `web` container in both production `docker-compose.yml` and development `docker-compose.dev.yml` (defaulting to `*` in development to ensure seamless mobile emulator/simulator connectivity).
  - Updated Nginx's HTTP port 8082 redirect rule in `docker/proxy/config/rengine.conf` to use a `308 Permanent Redirect` instead of `301`, preventing HTTP POST methods (like mobile logins) from being converted to GET requests during HTTP-to-HTTPS redirects.

- **Docker: Pipx Isolation for Conflicting Python Tools**:
  - Migrated `dirsearch`, `maigret`, and `semgrep` out of the shared system `pip3` environment and into isolated `pipx` virtual environments in `docker/web/Dockerfile`.
  - Resolves five pip dependency incompatibility warnings at build time: `requests` (2.25.1 vs ≥2.27.0 / ≥2.32.4), `chardet` (4.0.0 vs ≥5), `idna` (2.10 vs ≥3.4), and `urllib3` (1.26.x vs ~2.0).
  - Each tool's transitive dependencies are now fully isolated and cannot conflict with the Django application's pinned `requirements.txt` packages or with each other.
  - Follows the same `pipx` pattern already established for `baddns`. `/root/.local/bin` is on `PATH`, so all shims remain accessible at runtime without any additional configuration.

- **CVE Enrichment System**:
  - **CVE Enrichment Service**: `web/reNgine/cve_enrichment.py` fully operational - fetches CVSS v3.1 metrics from NVD API v2.0, EPSS probability scores from FIRST, and syncs the CISA KEV catalog. Enriched data is cached (7-day TTL for CVEs, 1-hour for KEV) and gracefully degrades on API unavailability.
  - **Deployment Documentation** (`documents/CVE_ENRICHMENT.md`): Comprehensive documentation covering setup, programmatic usage, management commands, correlation integration, troubleshooting, data retention, performance, and monitoring.
  - **Deployment Checklist** (`documents/DEPLOYMENT_CHECKLIST.md`): Step-by-step v3.5 upgrade procedure including migration verification, initial data load, cron job setup, rollback plan, and post-deployment verification.
  - **End-to-End Integration Test** (`web/tests/test_integration.py`): Full pipeline integration test validating the CVE enrichment -> correlation -> in-scan deduplication -> VulnerabilityHistory creation -> cross-scan remediation detection flow. All 3 test suites pass (15 tests total: 7 enrichment + 7 correlation + 1 integration).
  - **Database Migrations Applied**: Migrations `0035_add_cve_enrichment_fields` and `0036_create_vulnerability_history` confirmed applied in all environments.

- **vulnx Integration (ProjectDiscovery CVE Intelligence)**:
  - Integrated ProjectDiscovery `vulnx` CLI into the `go-tools-builder` Docker stage alongside other Go tools.
  - Added `ProjectDiscoveryAPIKey` model and migration (`dashboard/migrations/0016`) for storing the PDCP API key.
  - Added PDCP API key field to the API Vault settings page (backend + frontend) so users can save and update their key.
  - Added `_enrich_from_vulnx` method to `CVEEnrichmentService` in `cve_enrichment.py`: runs `vulnx id --json <CVE>`, parses the JSON response, and populates `is_poc`, `is_template`, CVSS, EPSS, KEV, and date fields.
  - Added `is_poc` and `is_template` boolean fields to the `CveId` model (migration `startScan/migrations/0039`).
  - Exposed `is_poc` and `is_template` in the `CVEDetails` API response.
  - CVE Lookup modal now renders "HAS EXPLOIT / POC" (pink) and "NUCLEI TEMPLATE" (purple) badges alongside the CISA KEV badge when the respective flags are set.

- **CVE Correlation, Deduplication & Graph Sync Enhancements**:
  - **Enhanced CveId Model**: Added CVSS v3.1 base score, EPSS score, EPSS percentile, attack complexity, attack vector, privileges required, user interaction, and scope fields to the database schema (migration `0035`).
  - **Correlation Scoring & Deduplication**: Replaced basic CVSS severity lookups with a multi-criteria scoring algorithm in `correlation.py`. Calculates composite scores using configurable tool weights, asset criticality, exploitability factors (CISA KEV, EPSS), and temporal modifiers. Suppresses inside-scan duplicates in-memory and groups them under a unique `group_key` before writing.
  - **Vulnerability History Tracking**: Introduced `VulnerabilityHistory` tracking model (migration `0036`) to trace vulnerabilities across historical scans, automatically detecting if a vulnerability is new, persistent, or remediated.
  - **Durable Database Transactions**: Wrapped finding correlation, impact assessment creation, and history tracking inside atomic transaction blocks to prevent duplicate database insertions and race conditions.
  - **Neo4j ID-Based Graph Sync**: Refactored Neo4j sync in `graph.py` to link vulnerability nodes to CVE nodes using precise ID matches (CVE ID) instead of string names. Ingests rich metadata (CVSS base score, EPSS score) directly onto Neo4j nodes.
  - **Correlation Unit Testing**: Added comprehensive backend test coverage in `test_correlation.py` validating correlation scoring weights, duplicate suppression, and cross-scan history tracking.

### [v3.4.2] - 2026-06-03

- **Semgrep Finding Name Normalization**:
  - Implemented a centralized `clean_semgrep_check_id` helper in `common_func.py` to strip system/path-based prefixes (e.g. `usr.src.github.semgrep_rules.`) and deduplicate repeating suffixes in Semgrep check IDs.
  - Applied the normalization logic to `parse_semgrep_result` in `common_func.py`, as well as `save_semgrep_vulnerability_finding` and `save_semgrep_secret_finding` in `tasks.py`.
  - Added comprehensive unit tests in `test_semgrep_optimization.py` to verify normalization under various path structures.

### [v3.4.1] - 2026-06-03

- **Infrastructure Upgrade: Django 5.2 LTS + PostgreSQL 16 + Gunicorn ASGI**:
  - **Django 3.2 → 5.2.3 LTS**: Upgraded Django from the expired 3.2 LTS (support ended April 2024) to 5.2.3 LTS (supported until April 2028). All deprecated APIs migrated: `url()` → `re_path()` in `reNgine/urls.py` and `api/urls.py`; `USE_L10N` removed (dropped Django 4.0); `unique_together` converted to `UniqueConstraint` in `AuthCandidate` (migration `0034`) and `ADDomain` (AD plugin migration `0007`); `daphne` removed from `INSTALLED_APPS` (channels 4.x handles runserver natively).
  - **PostgreSQL 12.3 → 16**: Upgraded the database engine from PostgreSQL 12.3 (EOL November 2024) to PostgreSQL 16-alpine (supported until November 2028). Django 5.2 enforces a minimum of PostgreSQL 14; the upgrade is now fully automated by `make fullupgrade`.
  - **Gunicorn + Uvicorn ASGI**: Replaced the Django development server (`runserver`) used in production with Gunicorn 22 + `UvicornWorker`. The `UvicornWorker` provides full ASGI support including HTTP and WebSocket (Django Channels scan log streaming). Added `web/gunicorn.conf.py` with 4 workers and `exec gunicorn reNgine.routing:application` in `entrypoint.sh`. Development mode (`DEBUG=1`) continues to use `runserver`.
  - **Package upgrades**: `djangorestframework` 3.12.4 → 3.15.2, `channels` 3.0.5 → 4.2.2, `channels-redis` 3.4.1 → 4.2.0, `daphne` 3.0.2 → 4.1.2, `psycopg2` 2.9.7 → 2.9.10, `django-redis` 5.4.0 → 7.0.0, `drf-yasg` 1.21.3 → 1.21.15, `django-ace` 1.0.11 → 1.44.0, `django-timezone-field` 6.1.0 → 7.2.1, `djangorestframework-datatables` 0.6.0 → 0.7.0. Replaced `gevent` with `uvicorn[standard]==0.32.1`.
  - **LoginRequiredMiddleware**: Replaced the abandoned `django-login-required-middleware` package (no Django 4.x/5.x release) with a custom `LoginRequiredMiddleware` class in `reNgine/middleware.py`. Preserves all existing `LOGIN_REQUIRED_IGNORE_VIEW_NAMES` and `LOGIN_REQUIRED_IGNORE_PATHS` settings without any other changes.
  - **DRF router basename deduplication**: Added explicit `basename=` parameters to 13 `router.register()` calls in `api/urls.py`. DRF 3.15.2 added strict duplicate basename detection (first introduced in 3.14.0); viewsets sharing the same model (`Subdomain` ×5, `EndPoint` ×4, `Command` ×2) now have unique basenames.
  - **PostgreSQL connection pooling**: Added `CONN_MAX_AGE=60` and `CONN_HEALTH_CHECKS=True` to `DATABASES` settings. Connections are now reused across requests within each Gunicorn worker (safe with UvicornWorker's per-process model) and validated before reuse (Django 4.1+ feature).
  - **PostgreSQL SSL**: Enabled SSL client configuration in `DATABASES` options. SSL mode is env-configurable via `POSTGRES_SSLMODE` (default: `prefer`; set to `verify-full` in production with certs). The CA certificate is mounted from `secrets/certs/ca.crt` into the container at `BASE_DIR/ca.crt`.

- **Startup Recovery Optimization**:
  - Adjusted `recover_stuck_scans` to only recover and resume scans that were actively in the `RUNNING_TASK` status when the system stopped or crashed.
  - Commented out auto-recovery for completed, failed (`FAILED_TASK`), aborted (`ABORTED_TASK`), stopped, or paused scans to prevent unexpected restarts of non-running tasks.

- **Upgrade Tooling (`make fullupgrade`)**:
  - **`scripts/db_backup.sh`**: Dedicated pre-upgrade database backup script. Isolates `pg_dump` stderr from the dump file (previously `2>&1` could corrupt the backup with error text); checks the pg_dump exit code via `if !` (compatible with `set -euo pipefail`); verifies the output is non-empty before proceeding. Called at step [1/8] with database credentials passed from Makefile variables.
  - **`scripts/pg_upgrade.sh`**: Automated PostgreSQL major-version upgrade script. Reads the `PG_VERSION` file from the Docker data volume via a transient Alpine container, compares it to the target version parsed from the `postgres:` image tag in `docker-compose.yml`, and performs a dump/restore only when a version mismatch is detected. Idempotent — exits immediately if already on the target version. Called at step [3/8], between service shutdown and image rebuild.
  - **`fullupgrade` now 8 steps**: Added PG upgrade as step [3/8]; renumbered all subsequent steps. Replaced the fixed `sleep 8` database wait with a polling `pg_isready` loop (up to 60 s). Fixed `showmigrations --plan` grep pattern from `^\[ \]` to ` \[ \]` (Django output uses a leading space). Added gunicorn log check to final verification step.

- **Technology Tag Normalization**:
  - Updated the technology version-stripping regular expression in `tech_mapping.py` to correctly identify and strip version suffixes that are delimited by hyphens (e.g. `elementor-4-0-4`, `wordpress-7-0`, `woocommerce-10-7-0`), colons, or whitespace, while preserving hyphens in compound technology names like `moment-js` or `parallax-js`.

- **Scan Finalization & UI Timeline Fixes**:
  - Fixed an issue where resumed scans were incorrectly marked as `FAILED` on completion due to dangling `FAILED_TASK` status entries.
  - **Durable Scan Activity Claiming**: Refactored `_create_scan_activity` in `TemporalTaskProxy` to claim existing `ScanActivity` records by scan and name, regardless of status (e.g. claiming `FAILED_TASK` or `RUNNING_TASK` rows from prior runs on resume), eliminating duplicate timeline entries and cleanup race conditions.
  - **Target Profiling Status**: Wrapped `TargetProfilingActivity` with `TemporalTaskProxy` to correctly transition its database status to `SUCCESS_TASK` on completion (or `FAILED_TASK` on exception).
  - **Custom Tracking Names**: Added `db_task_name` parameter to `RunGenericTaskActivity` and `_run_task`, enabling tasks like `baddns` to run as `'subdomain_discovery'` but correctly update their corresponding `'baddns'` database rows.
  - **Compound Task Persistence**: Updated `MarkVulnerabilityScanCompleteActivity` to use `update_or_create` instead of `get_or_create` to ensure the status of the pre-populated compound `vulnerability_scan` task is correctly updated to `SUCCESS_TASK`.

### [v3.4.0] - 2026-06-03

- **Burp Suite Professional Integration Plugin**:
  - Implemented a fully self-contained standalone integration plugin (`burpsuite_integration`) for r3ngine.
  - **Backend Models & Schema**: Configured `BurpSuiteConfig` (singleton API connection parameters), `BurpIssue` (deduplicated local findings repository), and `BurpSyncLog` (sync history and counts) models in a clean, plugin-specific database namespace.
  - **REST APIs**: Added REST endpoints for retrieving config, sync log history, and issues with status-filtering (`?unmatched=true`). Implemented manual match action (`POST /issues/{id}/match/`) alongside subdomain and endpoint search endpoints.
  - **Bidirectional Temporal Workflows**: Structured sync into a two-phase architecture: Phase 1 (`run_burp_import_activity`) fetches and registers raw findings; Phase 2 (`run_burp_correlate_activity`) maps findings to existing subdomain/endpoint targets and creates/links core r3ngine `Vulnerability` records. Created `run_burp_push_activity` to send r3ngine targets back to Burp scope.
  - **Module Federation UI**: Engineered a complete React + MUI dashboard containing a metrics overview (HSL glowing KPI cards), a filterable issues grid with drawer details and a two-stage manual match dialog, a historical timeline, and a live config tester.
  - **Connection Health Badge**: Added a pulsing `HealthDot` status indicator to the plugin card and settings panel checking live connection health of the Burp REST API.
  - **Embedded Documentation**: Bound a detailed documentation markdown modal directly into the plugin card's doc icon.
  - **Build & Compatibility Fixes**: Fixed a Unicode print encoding error in `build_plugins.py` on Windows (replacing `→` with ASCII `->`) and resolved a nested tag JSX mismatch in the card configuration.

### [v3.3.0] - 2026-05-31

- **URL Deduplication After fetch_url**:
  - Implemented the previously dead `remove_duplicate_endpoints` and `duplicate_fields` scan config options in `fetch_url` (`tasks.py`). Both are now fully active (default: enabled, fields: `content_length`, `page_title`).
  - **Pass 1 — URL signature dedup (pre-save)**: After all URL filtering, parametric variants of the same path are collapsed to a single representative URL before any database writes. e.g. `/page?id=1`, `/page?id=2`, `/page?id=100` (all share signature `/page?id`) are reduced to one entry. URLs with structurally different parameter names (e.g. `/page?id=1` vs `/page?id=1&sort=asc`) are treated as distinct endpoints and preserved.
  - **Pass 2 — Content-based dedup (post-save)**: After skeleton endpoints are written to the database, endpoints already enriched by the Tier 2 `http_crawl` are grouped by `(subdomain, content_length, page_title)`. Duplicate records within each group (identical content fingerprint) are deleted, keeping the first encountered. Skeleton endpoints with no crawl data are unaffected.
  - Added `url_param_signature(url)` helper to `common_func.py` that generates the dedup key (`scheme://netloc/path?{sorted param names}`) used by Pass 1.
  - Both passes are guarded by the `should_remove_duplicate_endpoints` flag and log their reduction counts, visible in `temporal-python-orchestrator` logs during scans.
  - Reduces the endpoint list fed into Tier 4 (`dir_file_fuzz`), Tier 5 (`web_api_discovery`), and Tier 6 (`nuclei`) — directly lowering scan load for targets with large historical URL sets from tools like `gau`.

- **Nmap Vulners NSE Grouped Vulnerability Findings**:
  - Nmap vulners NSE script results are now grouped by product version (e.g. "Exim smtpd 4.99.2") instead of stored as individual records per CVE/hash. All CVE and exploit IDs for the same product are logically grouped under a single finding.
  - Added `group_key` field (indexed `CharField`) to the `Vulnerability` model. For vulners findings this is populated with the service product+version string (e.g. `"ISC BIND 9.11.36"`) derived from nmap's XML output. Migration `0033_vulnerability_group_key` applies the schema change.
  - Changed nmap vulners deduplication from `(name, http_url, scan_history)` to `(name, subdomain, scan_history)`, so the same CVE detected on multiple open ports of the same host (e.g. port 465 and 587) is stored as a single `Vulnerability` record rather than duplicated per port.
  - `parse_nmap_vulners_output()` in `tasks.py` now sets `group_key = service_title` on every returned vuln dict, including the legacy regex-based CVE fallback path. The field is re-asserted after CVE enrichment to prevent overwrite.
  - Added `build_vuln_context()` helper in `report_tasks.py` that splits scan vulnerabilities into non-vulners findings (passed to existing templates via `all_vulnerabilities`) and a `grouped_vulners_findings` list (one entry per product group, with `group_key`, `items`, `count`, `max_severity`, `max_cvss`). The combined `unique_vulnerabilities` summary and total `all_vulnerabilities_count` span both sources.
  - All four PDF/HTML report templates (`cyber_pro`, `enterprise`, `modern`, `default`) now include a dedicated **NMAP VULNERS NSE FINDINGS** section rendered after the standard vulnerability findings. Each product group is shown as a card with a sub-table of individual CVE/hash IDs, CVSS scores, severity, and references.
  - Fixed `modern.html` and `default.html` to guard the vulnerability section on `all_vulnerabilities_count` (total, including vulners) instead of `all_vulnerabilities.count` (non-vulners only), preventing scans with exclusively vulners results from rendering as "no vulnerabilities found".
  - In the vulnerability table UI, vulners groups with more than one entry are collapsed by default. Clicking the group header row expands/collapses the individual CVE rows. The header displays a `▲ COLLAPSE` / `▼ EXPAND` indicator. Grouping uses the DB-backed `group_key` field when present, with a regex fallback for older records. Non-vulners groupings (SSL/TLS audit, Semgrep) are unaffected.

### [v3.2.0] - 2026-05-29

- **fetch_url Empty Targets Execution Error Fix**:
  - Added an early exit check to the `fetch_url` task (`web/reNgine/tasks.py`) to properly return when no active target URLs are discovered.
  - Prevents fatal crashes in downstream URL fetching tools (such as `vigolium scan` throwing `target file contains no targets` exceptions) when invoked against domains with no active endpoints.

- **baddns JSON Parsing Error Fix**:
  - Resolved an issue in the `subdomain_discovery` task where JSON output from `baddns` was erroneously merged with extracted subdomains and parsed as invalid domains.
  - Renamed the raw output file to `baddns_report.json` to safely avoid the `subdomains_*.txt` merging glob, ensuring JSON records are only parsed by the takeover evaluation block and preventing task validation errors.

- **ReconX Target Monitoring Settings & API URL Normalization**:
  - Added a monitoring settings modal inside the mobile app's **ReconX Feed** screen (`app/feeds/monitoring.tsx`), accessible via a header settings icon, to view all database targets from `/mapi/listTargets/` and toggle their active monitoring status using `/mapi/toggle/monitoring/`.
  - Fixed a double-slash (`//`) API request URL routing and logging issue in the Axios client (`src/api/client.ts`) by stripping the leading slash from relative paths if the baseURL ends with a slash.

- **Mobile Scan Engines Layout Overflow Fix**:
  - Resolved layout overflow issues on the Scan Engines screen in the mobile application.
  - Added `flexShrink: 1` to the engine name and `flexWrap: 'wrap'` to both the title row and task preview tag container in `app/system/engines/index.tsx` to prevent default badges and tactical module tags from falling off cards.

- **Mobile Infrastructure & Monitoring Fixes**:
  - Added new `/api/listTools/` (`/mapi/listTools/`) API endpoint on the backend to list all installed tools, requiring `IsAuditor` permission.
  - Updated the mobile app's "Tools" tab to fetch from `/mapi/listTools/` instead of `/mapi/external/tool/get_current_release/`, resolving a backend 500 error when queried without arguments.
  - Integrated `configured_tools_count` into `EngineSerializer` on the backend by parsing the engine's YAML configuration to count configured tools, fixing a client-side bug where the character length of the YAML configuration was displayed.
  - Updated `manage_monitoring_task(domain)` in `web/targetApp/views.py` to remove references to the deprecated `monitor_periodic_task` model attribute, resolving `AttributeError` exceptions and enabling the continuous monitoring toggle switch to function without errors on both mobile and web.

- **Fix command execution and tool update failures**:
  - Replaced incorrect `run_command.run(...)` calls with correct direct `run_command(...)` function calls in `web/api/views.py` and `web/startScan/views.py`.
  - Resolved `'function' object has no attribute 'run'` exceptions that caused tool updates, uninstallation, WAF checks, CMS detection, and scan result deletions to fail.
  - Verified compilation and syntax correctness of views within the Docker container environment.

- **Import/Export Config Tool Configurations**:
  - Enhanced the backup import/export views `ExportConfig` and `ImportConfig` in `web/api/config_migration_views.py` to support `spiderfoot` (`/usr/src/github/spiderfoot/spiderfoot.cfg`) and `theHarvester` (`/usr/src/github/theHarvester/api-keys.yaml`) configurations.
  - Ensured nested destination directories are recursively created if they do not exist during the import operation.

- **Active Exploitation Dashboard Pagination**:
  - Implemented page-number pagination (10 items per page) for both the **Exploited Databases Queue** and the **Potential Targets** tables on the `active_exploitation` dashboard.
  - Defined a custom DRF pagination class `ExploitationPageNumberPagination` on the backend `ExploitedDatabaseDumpViewSet` and `TargetsView` in [api.py](file:///d:/Repos/r3ngine/r3ngine-plugins/active_exploitation/backend/api.py) to resolve `TypeError: y?.some is not a function` console errors caused by unpaginated JSON array expectations.
  - Implemented a custom `/metrics/` endpoint on the backend viewset to perform global aggregates (total targets, total tables, total rows, critical targets) dynamically across all pages.
  - Updated the React frontend [ActiveExploitationDashboard.tsx](file:///d:/Repos/r3ngine/r3ngine-plugins/active_exploitation/ui/src/components/ActiveExploitationDashboard.tsx) to manage state for `dumpsPage` and `targetsPage`, and rendered MUI `<Pagination>` controls beneath each table.

- **exploit_readiness_layer Plugin UI Build Fix**:
  - Resolved JSX syntax and compiler build errors in the `exploit_readiness_layer` plugin's `VulnerabilityTable.tsx` component. Fixed a missing closing parenthesis and brace `)}` in a ternary conditional block and corrected mismatched closing brackets in the `groupedVulnerabilities.map` loop.
  - Refactored `TextField`, `Menu`, and `Dialog` slots (`slotProps`) in `VulnerabilityTable.tsx` to use MUI v5 native properties (`InputProps`, `PaperProps`), resolving a compilation/type-checking error where `paperProps` was unrecognized.

- **Plugin Standardized Naming & Active Exploitation Alignment**:
  - Standardized all plugin folder, zip, and database slug names under `r3ngine-plugins/` to use underscores (`_`) instead of hyphens (`exploit_readiness_layer`, `active_directory`, `active_exploitation`), ensuring full Python package naming compliance.
  - Updated the dynamic router in `frontend/src/router.tsx` to automatically normalize hyphens to underscores in the `$pluginSlug` URL parameter, allowing user-friendly, hyphenated paths in the address bar (e.g., `/p/active-directory`) while mapping to underscore folders and database slugs under the hood.
  - Aligned the `active_exploitation` plugin manifest and configured Vite build options to output an ES library format, exporting `ActiveExploitationDashboard` via `src/index.ts`.
  - Built a premium dark-themed MUI control panel dashboard for `active_exploitation` showing target metrics, SQLMap databases queue, and a detailed cryptographic log pane.
  - Added REST API endpoints (`api.py`, `serializers.py`, `api_urls.py`) exposing `/api/plugins/active_exploitation/dumps/` to support viewing database dumps and toggling the data-masking state.

- **Dynamic Plugin Installation Migration Fix & Filesystem Cleanup**:
  - Resolved runtime installation stalls on the "installing..." status by replacing in-process `call_command` migration tasks in `web/plugins/utils.py` with clean subprocess execution via `sys.executable`. This ensures a fresh Django settings context is initialized, allowing the newly unzipped plugin to dynamically register in `INSTALLED_APPS` and apply migrations without triggering `No installed app with label` errors.
  - Hardened the dynamic plugin installer in `web/plugins/utils.py` to re-raise migration exceptions, triggering full database rollback and cleanly deleting newly unzipped directories and media assets on installation failure to prevent loop states.
  - Created a standalone utility script `scripts/clear_failed_plugins.py` to detect and purge orphaned or failed plugin directories from the filesystem that are not registered in the database, preventing startup loop states and duplicate application configuration errors.


- **Mobile Task Log Streaming Restoration**:
  - Restored real-time stream log output for scan tasks in the mobile application by capturing and publishing stdout/stderr lines from the Python orchestrator.
  - Implemented `_init_redis_logging` and `_publish_to_redis_log` helpers in `task.py` to cache configurations and stream logs to Redis for both local subprocess and Go-routed scan task executions.
  - Refactored `ScanLogConsumer` in `consumers.py` to start stream listening from ID `0` (instead of `$`), enabling historical log replay when connecting.

- **Mobile Scan In-Progress Indicator**:
  - Implemented `AnimatedActivityBadge` next to the alert bell in the mobile app dashboard header.
  - Configured a looping pulse/scale animation running at 60fps on the native driver.
  - Added polling logic via `/mapi/scan_status/` running every 30 seconds to toggle the badge visibility when scans are active, and configured routing to redirect the user to the scans tab on click.
  - Documented the new component in `r3ngine-mobile/documentation/AnimatedActivityBadge.md`.

- **URL Gathering Tools Regex Fix**:
  - Corrected a critical POSIX regular expression syntax error (`host_regex`) in the URL fetching task (`fetch_url`) of `tasks.py` that caused all output from `gau`, `waybackurls`, `hakrawler`, `katana`, and `gospider` to produce zero results.
  - Implemented a POSIX-compliant character class `[^][[:space:]\\\"\\`><]*` to correctly exclude brackets, whitespace, quotes, and backticks without causing syntax errors or early bracket terminations in POSIX `grep` execution.

- **baddns Scan Pipeline Integration**:
  - Registered `baddns` as a default subdomain discovery tool inside `subdomain_discovery` in `tasks.py` by appending it to the `default_subdomain_tools` list, resolving the issue where baddns execution was skipped with an unsupported warning.
  - Added support for executing `baddns` as a standalone discovery task inside the main scan workflow (`MasterScanWorkflow`) in `temporal_workflows.py`.
  - Fixed invalid CLI arguments (removed unrecognized `-d` and `-o` parameters) and refactored command to run in silent mode with output redirected to a results file (`baddns -s {host} > {results_file}`).
  - Added subdomain extraction logic to parse JSON findings and save newly discovered domains/subdomains to `subdomains_baddns_extracted.txt`.
  - Refactored the takeover validation parser in `tasks.py` to correctly check the JSON findings format instead of expecting plain-text labels.

- **Scan Queueing Feature**:
  - Implemented an optional queueing mechanism (`UserPreferences.enable_scan_queueing`) to restrict scan concurrency.
  - Limits execution to a maximum of 1 main scan and 1 subscan concurrently. Additional scans block in a Temporal polling loop (`check_scan_queue_status_activity`) and check again every 30 seconds.
  - Added backend APIs to get and toggle the queueing state (`ToggleScanQueueingView`).
  - Added a dedicated "SCAN CONFIGURATION" control panel with a toggle switch on the global Settings page.
  - Registered `CheckScanQueueStatusActivity` in the Temporal python worker commands (`run_temporal_orchestrator.py`).
  - Fixed a TypeScript syntax error regarding `PaperProps` typing in `DistributionCharts.tsx` for production builds.

- **Backend Architecture & Code Quality Remediation**:
  - Implemented a centralized, singleton-cached `TemporalClientProvider` to manage Temporal workflow client connections efficiently and prevent connection pool exhaustion.
  - Replaced unmanaged daemon threads and synchronous inline operations in Views and Celery tasks with durable Temporal workflows and registered 6 new workflows and activities (`HackerOneImportWorkflow`, `HackerOneSyncBookmarkedWorkflow`, `ProxyFetchWorkflow`, `ApmeTaskWorkflow`, `GeoLocalizeWorkflow`, `SubScanWorkflow`).
  - Added deferred reader closes and a 1MB scanner buffer limit configuration in the Go Executor (`web/executor/main.go`) to prevent subprocess scanner crashes and reader pipe resource leaks.
  - Wrapped multi-threaded OSINT tasks with `db_conn_safe_wrapper` to ensure safe database connection closure on thread finalization and joined them to block during activity run, resolving database lockups and resource exhaustion.
  - Rewrote the vulnerability correlation and impact assessment lookups in `correlation.py` to preload subdomains, CVEs, and assessments, performing duplicate verification in-memory and batching database writes (reducing query footprint from ~5,000 to ~5 queries for 1,000 processed findings).
  - Configured Django `pre_delete` signals on `ScanHistory` and `SubScan` to cleanly cancel associated workflows in Temporal and cleanup directories on disk.
  - Wrapped `UserPreferences` middleware lookup inside a `SimpleLazyObject` to prevent redundant queries on static asset requests.
  - Fixed subscan `bulk_stop` cancellation to correctly cancel workflows in Temporal.
  - Upgraded `temporalio` Python SDK dependency to version `1.7.0` to resolve `Ignoring add command while deleting` eviction failures incorrectly logging as workflow crashes.


- **Subscan Tiered Execution Steps Alignment**:
  - Refactored `SubScanWorkflow` to group and execute subdomain subscans in sequence-enforced execution tiers (Discovery -> HTTP Crawl & Port Scan -> URL Fetching -> Fuzzing -> Analysis -> Security Assessment), strictly mirroring the main scan (`MasterScanWorkflow`).
  - Modified the `InitiateSubTask` API view and `initiate_subscan_temporal` scan task helper to batch-create `SubScan` database records and trigger a single, unified `SubScanWorkflow` execution per subdomain rather than running separate concurrent workflows for each individual task.
  - Implemented logic in `SubScanWorkflow` to run matching verification parse activities (e.g. `ParseDiscoveryResultsActivity`, `ParseHTTPCrawlResultsActivity`, etc.) as soon as the respective tiers finish.
  - Optimized post-processing execution (vulnerability correlation/scoring and graph synchronization/APME) by only running them if their corresponding triggering task types were selected.
  - Added optional `subscan_id` support to `FinalizeSubScanActivity` to support granular database updates for each subscan task in the batch.

- **Semgrep Scan Pipeline Optimization & Stalling Mitigation**:
  - Refactored the raw URL file downloader loop in `semgrep_scan` to download files in parallel using a `ThreadPoolExecutor` (10 concurrent workers).
  - Implemented `clean_and_validate_url` to strip tool-specific trailing metadata (like `] - text/html`) from raw `gospider`/`hakrawler` outputs and filter out out-of-scope third-party CDN/external domains.
  - Added size and quantity guardrails by capping individual file downloads at **5MB** via streaming chunks and limiting total files scanned per domain to **500**.
  - Refactored the `host_regex` URL pattern in `fetch_url` to exclude whitespace, quotes, backticks, and brackets to prevent matching trailing metadata suffixes.

- **Temporal Activity & Scan Stability Fixes**:
  - Disabled inline synchronous HTTP crawling in the `port_scan` activity to prevent concurrent file/database collisions, process lockups, and eventual `CancelledError` activity cancellations.
  - Hardened the Aquatone session parser in `web_api_discovery` to handle cases where technology `tags` are `null` in the JSON output, avoiding database `NOT NULL` constraint violations on `Screenshot.technologies`.

- **Target Information Nameservers and History Tabs Fix**:
  - Resolved the empty Nameservers tab on the Scan Detail page by introducing the `nameservers` field (list of strings) in `ScanSummaryAPIView` and `TargetSummaryAPIView` to match the frontend component's requirements.
  - Implemented the missing rendering logic for the Nameservers (infoTab === 3) and History (infoTab === 4) tabs on the Target Summary page.
  - Added the missing History tab rendering logic on the Scan Detail page to display historical IP resolution details.

- **Screenshot Pipeline Optimization**:
  - Moved the visual screenshotting task (`screenshot`) from Tier 2 (parallel to HTTP Crawl & Port Scanning) to Tier 6 (parallel to Vulnerability Scanning).
  - This ensures that crawling, URL fetching, and directory/file fuzzing have completely finished execution, allowing a comprehensive set of alive endpoints to be gathered before screenshots are captured.

- **Nuclei Scan Sequential Severity Execution**:
  - Re-implemented nuclei scanning to run sequentially per configured severity level inside the `NucleiPlannerWorkflow`.
  - Updated `RunNucleiActivity` to accept a `severity` parameter and reflect it in the UI activity status (e.g. `Nuclei Scan (critical)`).
  - Configured `nuclei_scan` in `tasks.py` to isolate intermediate target endpoints and unfurl files by suffixing them with the active severity level (e.g. `input_endpoints_vulnerability_scan_{severity}.txt`) to prevent disk writes collision.
  - Re-enabled the `-tags` parameter which was previously dropped, ensuring only relevant checks are executed against the target stack.
  - Implemented dynamic fallback to the target root domain in the event that `Subdomain` queries return empty results during parameter resolution.
  - Gated the intensive `nuclei -update-templates` step behind the `auto_update_templates` boolean configuration.
  - Added explicit execution and run timeouts (`execution_timeout`, `run_timeout`) to the `NucleiPlannerWorkflow` child execution.
  - Removed obsolete parsing and preparation Temporal activities (`PrepareNucleiActivity`, `ParseNucleiResultsActivity`) resulting in a leaner execution graph.

- **Code Restructuring and Utility Sub-Package Migration**:
  - Relocated stress testing python files (`stress_views.py`, `stress_cmd_builder.py`, `stress_report_builder.py`, `stress_telemetry.py`, `stress_aggregation.py`, `stress_testing_tasks.py`) from the root of `web/reNgine/` to `web/reNgine/stress/`, dropping redundant prefixes.
  - Relocated general utility scripts (`database_utils.py`, `graph_utils.py`, `llm_utils.py`, `opsec_utils.py`, `task_utils.py`, `waf_utils.py`) from the root of `web/reNgine/` to a dedicated `web/reNgine/utils/` sub-package, stripping redundant suffixes.
  - Updated all imports and mock references across the Django views, background tasks, plugins, and unit tests to align with the new sub-packages.

- **Exploit Readiness Layer (ERL) Dedicated Dashboard & Routing Standardization**:
  - Replaced component-level override hijacking with a standardized dynamic plugin page routing system.
  - Added support for dynamic wildcard page loading at `/p/$pluginSlug` and `/p/$pluginSlug/$pageName` in the host router without requiring core codebase updates.
  - Implemented the Exploit Readiness Center split-pane dashboard under the `erl_temporal` plugin UI featuring KPI metrics, a compact project-wide vulnerability queue, and a detailed ERL intelligence panel (Evidence logs, Cytoscape attack path visualization, and AI impact assessments).
  - Updated the left navigation sidebar in the host shell to dynamically construct link paths from the enabled plugins registry configuration.
  - Standardized plugin bundle build configurations to export barrel-structured ESM components (`src/index.ts`) for dynamic loading via `PluginPageLoader`.

> **IMPORTANT — Existing installations must run the full upgrade script**
>
> v3.2.0 replaces Celery with Temporal. This is a breaking infrastructure change. Simply running `make up` on an existing install will leave stale Celery containers running and skip required database migrations.
>
> Run the full upgrade before starting services:
>
> ```bash
> # Linux / macOS
> git pull && make fullupgrade
>
> # Windows
> git pull && make.bat fullupgrade
> ```
>
> The script stops all containers, rebuilds all images from scratch, applies all migrations, and starts the updated stack. It will ask for explicit confirmation before making any changes.
>
> **Any scans running at upgrade time will be interrupted.**

- **Celery → Temporal Migration (Complete)**: Fully removed Celery from the codebase and replaced all task orchestration with [Temporal](https://temporal.io). This is a complete, production-grade infrastructure migration spanning the entire scan pipeline.
  - **Durable Workflow Execution**: All scans now run as `MasterScanWorkflow` instances on Temporal. Workflows survive container restarts, network blips, and worker crashes — execution resumes exactly where it left off with no data loss.
  - **Full Execution History**: Every workflow and activity is recorded in Temporal's history. The Temporal UI at `localhost:8080` provides step-by-step replay of any scan, past or present.
  - **Pause / Resume Signals**: Scans can be paused and resumed via Temporal signals without losing state.
  - **Abort via Cancellation**: Scan termination (`stop_scan`, `stop_scans`) now calls `TemporalClientProvider.cancel_workflow()` instead of `app.control.revoke()`, ensuring clean, tracked cancellation backed by `TemporalWorkflowExecution` records.
  - **Worker Health Check**: The system health API now verifies Temporal connectivity rather than polling Celery inspect.
  - **Celery Infrastructure Removed**: Deleted `celery.py`, `celery_custom_task.py`, `celery-entrypoint.sh`, and `beat-entrypoint.sh`. Removed `celery==5.4.0` and `django-celery-beat==2.6.0` from `requirements.txt`. Removed the `celery` Docker service from `docker-compose.yml`.
  - **Temporal Entrypoint**: Created `temporal-entrypoint.sh` — the new `temporal-python-orchestrator` container entrypoint that handles all one-time setup (wordlists, nuclei templates, kiterunner, gf-patterns, AI Map templates) previously owned by `celery-entrypoint.sh`, then starts the Temporal worker.
  - **Settings Cleanup**: Replaced the `CELERY_*` config block in `settings.py` with `REDIS_URL`-based configuration. Removed all Celery log handlers.
  - **Temporal Schedules**: Startup sync tasks (`sync_all_scans_to_graph`, `sync_cisa_kev_catalog`, `sync_semgrep_rules`) and domain monitoring schedules migrated from `django-celery-beat` `PeriodicTask` rows to native Temporal Schedules. Scheduled scan creation and management views updated accordingly.
  - **Go Executor**: A lightweight Go-based Temporal activity worker (`web/executor/main.go`) handles subprocess tool execution on the `go-executor-queue`.
  - **New Models**: `TemporalWorkflowExecution` and `TemporalSchedule` (migration `0026`) track running workflows and periodic schedules.

- **Scan Result Recovery Tool**: Added `recover_scan_results` Django management command (`web/scanEngine/management/commands/recover_scan_results.py`). In the event of database corruption or loss, this command walks the `scan_results` volume and reconstructs the database from files on disk — recovering Domains, ScanHistory records, Subdomains, EndPoints, Ports/IpAddresses, Vulnerabilities (nmap + nuclei), and WAF associations.
  - **Dry-run by default**: run without flags to preview what would be recovered, with per-record output and a summary table. Pass `--apply` to commit.
  - **Idempotent**: scans whose `results_dir` already exists in the database are silently skipped — safe to re-run at any time.
  - **Dual port-scan format support**: handles both the modern naabu JSONL format (`{"host":…,"port":…}` per line) and the legacy JSON-object format (`{"host": [port, …]}`).
  - **Targeted recovery**: use `--scan-dir /path/to/scan` to recover a single folder, or `--results-root /alt/path` to point at a non-default results volume.
  - **Usage**:
    ```bash
    # Inside the web or celery container:
    python manage.py recover_scan_results           # dry-run
    python manage.py recover_scan_results --apply   # write to DB
    python manage.py recover_scan_results --apply --scan-dir /usr/src/scan_results/defijn.io_108
    ```
- **Configuration Export & Import**: Added a complete backup and restore system for custom user settings.
  - **Export System**: Added the `/api/settings/export/` endpoint that dynamically generates a single `.zip` backup containing API keys, custom wordlists (from `/usr/src/wordlist/`), tool configurations, and custom scan engines.
  - **Import System**: Added the `/api/settings/import/` endpoint that accepts the zipped backup payload, safely extracting custom wordlists back to the filesystem and re-populating the database. Features an "Overwrite existing configurations" toggle.
  - **UI Integration**: Added a sleek, tactical **Configuration Export / Import** panel to the Settings page. This allows users to download a snapshot of their environment before clean installations and restore it effortlessly.
- **Stress Testing Telemetry, Security Hardening & Restructuring**:
  - Fixed a Temporal heartbeat context issue inside `RunStressToolActivity` by propagating the `contextvars` context to the background heartbeat loop thread, resolving `RuntimeError: Not in activity context` and allowing real-time status/cancellation detection.
  - Hardened process cleanup by switching process termination to send SIGTERM/SIGKILL to the entire process group (`os.killpg`) to ensure that orphaned background processes are cleanly terminated when a scan is stopped or aborted.
  - Resolved Vite dev server WebSocket configuration by proxying `/ws` paths to Daphne on port 8000, allowing the frontend telemetry component to receive real-time ECharts metrics and log lines during development.
  - **Security Audit & Hardening**:
    - Protected load testing tool command execution from command injection vulnerabilities by strictly escaping subprocess execution lists using `shlex.quote` in `cmd_builder.py`.
    - Hardened asynchronous report PDF generation against Server-Side Request Forgery (SSRF) and Local File Inclusion (LFI) by wrapping WeasyPrint HTML instances in a `secure_url_fetcher` that restricts fetches to data URIs, local files inside `BASE_DIR`/`MEDIA_ROOT`, and Google Fonts.
    - Prevented DB connection leaks in background threads by ensuring `close_old_connections()` is executed on thread finalization.
  - **Code Restructuring & Sub-Package Migration**:
    - Restructured and moved all stress testing Python scripts (`stress_views.py`, `stress_cmd_builder.py`, `stress_report_builder.py`, `stress_telemetry.py`, `stress_testing_tasks.py`, `stress_aggregation.py`) to the clean, dedicated sub-package directory [reNgine/stress/](file:///d:/Repos/r3ngine/web/reNgine/stress/) as `views.py`, `cmd_builder.py`, `report_builder.py`, `telemetry.py`, `testing_tasks.py`, and `aggregation.py`.
    - Updated all import definitions, mock patches, and test configurations to reference the new package paths.
    - Resolved `RuntimeWarning: coroutine ... was never awaited` test warnings by replacing global `asyncio.run` mocks with targeted helper patches.
- **Locust Path Splitting & K6 Telemetry Fixes**:
  - Fixed Locust target URL parsing in `_build_locust_cmd` by utilizing `urllib.parse.urlparse` to dynamically split target URLs into host and path components. This avoids trailing slash errors (such as `GET /xmlrpc.php/` returning `400 Bad Request`) and ensures Locust script generation properly separates the request path from the base host.
  - Resolved K6 real-time dashboard updates by adding dynamic `throughput_rps` calculation to `K6Parser`. It extracts elapsed minutes and seconds from K6's progress output via regex and divides total requests by elapsed seconds, resolving static or missing real-time telemetry metrics.
  - Fixed WrkParser final metrics aggregation by summing both socket errors and timeout errors to represent the correct count of failed requests.
- **Dalfox Scanner Enhancements & Stabilization**:
  - Resolved a missing findings issue caused by the `--only-poc r` filter overriding genuine verified payloads (`v`) by expanding the filter to `--only-poc v,r`.
  - Upgraded Dalfox execution to support optional Deep Scan (`--deep-scan`), remote payload dictionaries (`--remote-payloads`), remote parameter wordlists (`--remote-wordlists`), and automatic WAF bypassing (`--waf-bypass auto`) for deeper detection coverage.
  - Added a configurable scan timeout parameter (`--scan-timeout`) to prevent scan stagnation on heavily-parametrised endpoints, and removed the obsolete `--skip-bav` flag.

- **Active Directory Intelligence Plugin (Phases 7–12)**:
  - **Reporting Engine**: Implemented `ReportingEngine.compile()` producing 7-section AD intelligence reports covering executive summary, domain users, groups, computers, trusts, exposures, and recommendations. Exports to both JSON and PDF via `JSONRenderer` and `PDFRenderer` (WeasyPrint).
  - **Paginated Findings API**: All findings, trusts, and exposure endpoints now return paginated results (50 records per page) with `page`/`total_pages` metadata, preventing browser memory exhaustion against large Active Directory environments.
  - **Graph Scalability**: `graph_domains` endpoint enforces a `?limit=300` default node cap with a truncation warning banner and user-triggered "Load All" confirmation to prevent browser hangs on domains with thousands of objects.
  - **Performance Guardrails**: Cytoscape animations are automatically disabled for graphs exceeding 400 nodes; layout computation is deferred to a web worker to prevent UI thread blocking.
  - **Cytoscape Graph Layouts**: Added 5 named layout presets — `hierarchical` (KLay), `radial` (Concentric), `force` (CoSE-Bilkent), `bipartite` (Grid), and `cluster` (COSE) — selectable from the graph toolbar without page reload.
  - **Semantic Node Styling**: Domain controllers, trust bridges, exposed accounts, and disabled objects each carry distinct node shapes, border weights, and color families to allow at-a-glance risk triage.
  - **Real-Time WebSocket Streaming**: Backend emits graph and findings events through Django Channels with 150 ms client-side batching to coalesce burst updates during large LDAP/BloodHound ingests.
  - **Search, Focus & Node Detail Panel**: Graph toolbar includes live search with node focus/highlight; clicking any node opens a slide-over detail panel showing all attributes, related trust paths, and linked exposures.
  - **RBAC & Evidence Logs**: All sensitive assessment actions (launch, export, delete) require the `can_run_ad_assessment` permission; every action is written to an immutable evidence log accessible from the assessment detail view.
  - **AD Assessment from Subdomain**: Added API endpoint and subdomain list UI action to launch an AD assessment directly from any subdomain record, automatically pre-populating the target domain from the selected subdomain's resolved FQDN.
  - **AD Report Templates**: Added `ad_modern` and `cyber_pro` PDF report templates; `ADReportModal` component provides in-app template selection and one-click PDF download.

- **Scan Workflow Reliability & Cancellation Hardening**:
  - **Centralized Abort Utility** (`web/reNgine/utils/scan_cancellation.py`): Introduced `abort_scan_history(scan, aborted_by)` and `abort_subscan(subscan)` as the canonical abort path across all API surfaces. Workflow cancellation now always occurs *before* database status is updated to prevent a race where a resumed worker sees ABORTED state and skips cleanup.
  - **Child Subscan Propagation**: `abort_scan_history` now recursively aborts all child subscans in RUNNING state, ensuring no orphaned subscan workflows outlive a stopped parent scan.
  - **Fixed `StopScan` API** (`api/views.py`): Removed duplicate 68-line inline `abort_scan`/`abort_subscan` closures; endpoint now delegates entirely to the centralized utility.
  - **Fixed `stop_scans` Bulk Stop** (`startScan/views.py`): The bulk stop endpoint was cancelling Temporal workflows but never writing `scan.scan_status = ABORTED_TASK` to the database, leaving scans permanently shown as RUNNING in the UI.
  - **Fixed Queryset Bulk Delete Signal Bypass** (`api/subscans.py`): `SubScan.objects.filter(…).delete()` does not fire `pre_delete` signals and therefore never triggered workflow cancellation. Replaced with a per-instance loop that calls `abort_subscan(subscan)` before each deletion.
  - **Fixed `delete_all_scan_results` Signal Bypass** (`startScan/views.py`): Same queryset bypass issue affected the "Delete All Scans" action. Replaced `ScanHistory.objects.all().delete()` with a materialised loop that calls `abort_scan_history(scan)` and removes results directories before each `scan.delete()`.
  - **Fixed `scan_history` Bulk Stop Missing Child Cancellation** (`api/scan_history.py`): `stop_scan` and `bulk_stop` handlers had duplicated inline Temporal cancellation logic that never cancelled child subscans. Both now delegate to `abort_scan_history`.
  - **Workflow Execution Retry Cap**: Added `RetryPolicy(maximum_attempts=10)` to `MasterScanWorkflow` and `SubScanWorkflow` start calls in `tasks.py`. After 10 consecutive activity failures the workflow transitions to FAILED state in Temporal rather than retrying indefinitely. Users can re-trigger execution via the existing **Resume** button, which starts a fresh workflow from the last persisted checkpoint.
  - **Workflow Flush Utility** (`web/scripts/flush_workflows.py`): Added a one-shot maintenance script that terminates all running scan/subscan Temporal workflows and marks corresponding database records as ABORTED/CANCELLED. System scheduler workflows (`temporal-sys-scheduler:*`) are intentionally skipped. Run from inside the web container: `python3 scripts/flush_workflows.py`.

- **Dynamic Plugin Routing**:
  - Replaced 5 individually hard-coded Active Directory route definitions in the host router with a single dynamic entry via `ADPluginApp`, resolving the discrepancy between plugin slug registration and frontend route matching.
  - Plugin page routing now follows the established wildcard pattern (`/p/$pluginSlug` and `/p/$pluginSlug/$pageName`) so future plugin pages are automatically reachable without core router changes.

- **Plugin System Fixes**:
  - Fixed the plugin installer sync step to copy only the compiled `ui/dist/` output into `MEDIA_ROOT`, preventing unintentional inclusion of plugin source trees, `node_modules`, or private configuration files in the served static asset directory.

- **CSRF Security Fixes**:
  - Fixed a `TypeError: Cannot read properties of null` crash in `SubdomainsTab` caused by a null CSRF token on initial page load; token is now coerced to an empty string before use.
  - Fixed CSRF token not being included in AD plugin API requests (`adApi`); all mutating API calls now read the token from the Django cookie and attach it as the `X-CSRFToken` header.

- **Crash Recovery Improvements**:
  - `recover_stuck_scans` now correctly identifies `RUNNING_TASK` scans whose associated Temporal workflow no longer exists (e.g. after a container restart with no checkpoint), marks them as `ABORTED_TASK`, and surfaces them in the REST API recovery endpoint.
  - Added a hard cap to the REST API recovery endpoint: at most 50 scans are recovered per invocation to prevent a single recovery pass from overwhelming the Temporal task queue on large installations.

### [v3.1.0] - 2026-05-20

- **Scan Pipeline**: fully fixed and stabilized. All tools now working to their full capabilities again.
- **Stress Testing Pipeline**: added a new internal stress module that takes the adaptive stress engine from load testing to full denial-of-service testing to ensure you can test the full resiliance of your servers fall-over
- **Stress Testing Results & Reporting**: All stress testing results are all correctly parsed, stored and *surfaced? for reports.

**Official Repo location:** <p align="center"><a href="https://github.com/whiterabb17/r3ngine/releases" target="_blank"><img src="https://img.shields.io/badge/version-v3.0.0-informational?&logo=none" alt="r3ngine Latest Version" /></a>&nbsp;<a href="https://www.gnu.org/licenses/gpl-3.0" target="_blank"><img src="https://img.shields.io/badge/License-GPLv3-red.svg?&logo=none" alt="License" /></a>&nbsp;<a href="#" target="_blank"><img src="https://img.shields.io/badge/first--timers--only-friendly-blue.svg?&logo=none" alt="" /></a></p>


### [v3.0.0-rc9] - 2026-05-20

- **Stress Testing Dashboard WebSocket Telemetry**: Corrected WebSocket event parsing in the React frontend (`useStressTelemetry.ts`) to unwrap events from the `'telemetry_update'` envelope, enabling proper processing of `scan_status` updates and resolving the issue where the Kill Switch button failed to update to disabled.
- **Stress Tool Execution Scope Constraint**: Fixed `handleStart` in `StressTestingPage.tsx` to launch only the active tool tab (`activeTab`) instead of all tools in `config.uses_tools`, preventing unwanted concurrent tool runs.
- **Stressor Absolute Path Resolution**: Fixed path resolution in `stress_testing_tasks.py` for the custom stressor script to use `settings.BASE_DIR`, preventing execution failures on Celery workers.

### [v3.0.0-rc8] - 2026-05-20

- **Stress Testing Data Persistence**: Implemented stateful metric parsing and final metric aggregation (`get_final_metrics()`) for all five supported load testing tools (`k6`, `wrk`, `hping3`, `Locust`, and `TAStressor`) inside `parsers.py`.
- **Pipeline Metric Aggregation**: Enhanced `stress_testing_tasks.py` to accumulate total requests, successful/failed requests, average/percentile latencies, and peak requests per second across multiple endpoints/tools, persisting the final aggregates to the `StressTestResult` database model.
- **Report Generation Bug Fix**: Corrected a critical `NameError` in `report_tasks.py` where the undefined variable `avg_p95` was referenced during PDF report generation, resolving stress report failures.

### [v3.0.0-rc7] - 2026-05-19

- **APME Task Autodiscovery & Trigger Button Execution**: Created a dedicated `tasks.py` entrypoint in the `apme` app directory to resolve Celery autodiscovery failures (`run_llm_apme` not registered in workers), and documented all orchestrator functions with strict parameter and return descriptions conforming to codebase guidelines.
- **APME Concurrency & Graph Sync Stability**: Catch `IntegrityError` in vulnerability correlation during concurrent `ImpactAssessment` creation, falling back to updating the record. Safe-guard the Neo4j graph results synchronization parser against `None` references for missing relation attributes (e.g. `target_domain`, `subdomain`, `technologies`, `cve_ids`).
- **Celery binding and NameError fixes**: Fixed a critical `NameError` in `theHarvester` Celery task where `self` was referenced but not bound, causing task crashes and pipeline deadlocks. Changed task registration to use `bind=True` and `base=RengineTask` and injected the `self` context as the first argument.
- **CTFR Subdomain Extraction File Truncation**: Resolved a classic Bash file redirection bug in `ctfr` subdomain extraction that immediately truncated `{results_file}` to 0 bytes before `cat` could read it. Modified the extraction command to write to a temporary file first and rename it back.
- **URL Fetching and GF Pattern Filter Fix**: Corrected a overly restrictive regex in `fetch_url` and `gf` pattern filters (`host_regex`) that only permitted lowercase alphanumeric subdomains. This caused all captured URLs and endpoints belonging to subdomains with hyphens (`-`), underscores (`_`), and uppercase letters to be discarded. Modified the regex pattern to match standard RFC-compliant subdomain characters `[a-zA-Z0-9_-]`.
- **NUL Character Database Ingestion Fix**: Resolved a critical PostgreSQL/SQLite database error (`ValueError: A string literal cannot contain NUL (0x00) characters`) that aborted Celery tasks when tools produced stdout containing null bytes (e.g. `LinkFinder` output). Added automatic NUL character stripping inside `sanitize_command_for_db`, `run_command`, and `stream_command` before command models are persisted.
- **Mobile Companion App Enhancements**:
  - **Premium Vulnerability Detail Modal**: Integrated an elegant glassmorphic detail drawer on the dashboard's recent vulnerabilities list that displays detailed vulnerability descriptions, commands, severities, and the exact target domain names on which they were found (replacing generic N/A values).
  - **Most Vulnerable Targets Redirection**: Configured the "Most Vulnerable Targets" list to redirect users directly to a comprehensive `TargetSummary` view showing active subdomains, scan telemetry, and historical security findings.
  - **Interactive WHOIS Invalidation**: Added an on-demand, real-time WHOIS refresh trigger (`Zap` action) to the target information panel of the scan details tab, featuring live `ActivityIndicator` states and dynamic context refetching.
- **Aquatone Visual Discovery & Proxy Validation Hardening**: Resolved a critical issue where Aquatone scans failed to capture screenshots and returned empty results. Corrected the proxy validation logic to reject dead or slow public proxies returning HTTP error pages (`502`, `503`, `504`, `403`), isolated the leaked `proxy` task variable to prevent scope bleed, and explicitly configured the Playwright Chromium binary path (`-chrome-path /usr/bin/chromium`) inside the Celery container.
- **Nmap IP Target Parsing Stability**: Fixed a ValueError crash (`invalid literal for int() with base 10`) in the Celery `nmap` task during scanning of IP targets. Refactored the unsafe colon-splitting port extraction to use a robust, fallback-aware `urllib.parse.urlparse` logic.
- **Attack Surface Canvas Stability**: Resolved a critical application crash when loading the Attack Surface tab in the tactical interface by removing the non-functional separator item in the Cytoscape context menu configuration and replacing it with the library-supported native `hasTrailingDivider: true` option.
- **AI Vulnerability Enrichment & Description Sync**: Wired the Most Common Vulnerabilities overlay in the web dashboard to dynamically call the LLM-powered vulnerability details function. Clicking the new "AI Analysis" thinking button initiates the analysis, updates the modal in real-time, and saves the detailed description, impact, remediation, and references to the database.
- **Directories Tab Endpoint Fallback**: Implemented a robust fallback mechanism in the directories view set that dynamically extracts and populates directory items from crawled target URLs (`EndPoint` table) if a scan's direct directory fuzzing results (e.g. `ffuf` or `dirsearch`) are empty. This ensures visual completeness of the scan detail Directories tab.
- **Unified Vulnerability Dashboard Refinement**: Cleaned up the vulnerability table dashboard to display accurate, dedicated scanners (e.g. `Acunetix`, `Dalfox`, `CRLFuzz`, `S3Scanner`, `Semgrep`, `WPScan`, `Retire.js`) in the "Command/Source" badge and details view, replacing generic Nuclei templates or commands.
- **Scan Completion Pipeline Synchronization**: Fully integrated Celery-native retry/polling logic in downstream post-processing and reporting tasks (`correlate_vulnerabilities`, `calculate_risk_scores`, `generate_impact_assessment`, `run_apme`, and `report`), enabling them to dynamically poll `ScanActivity` and postpone execution until all scanning and vulnerability tool sub-tasks have successfully completed.
- **Harden URL Downloader in Semgrep Static Analysis**: Enabled dynamic relative/protocol-relative URL normalization based on the target scan's base domain, expanded the target list to scan `.html` and `.htm` pages with inline code/secrets, and automatically parsed and injected configured scan headers (falling back to a standard browser `User-Agent`) to prevent server-side blockages. Added a **resilient proxy-cycling rotation engine** that shuffles configured proxies and automatically switches to the next proxy when a connection error, timeout, or proxy error code (`407`, `502`, `503`, `504`) is encountered.
- **Mobile Notification Header Styling**: Restored appropriate dark styling (`Theme.colors.surface`) and readable title/icon color tokens (`Theme.colors.primary` / `Theme.colors.text`) to the mobile companion app's Notification Center (bell icon scan history drawer) header, preventing an unreadable white header issue under React Native Stack presentation modals.
- **APME Path Persistence Database Constraint Resolution**: Resolved a database unique constraint violation in the Attack Path Modeling Engine by separating lookup and update logic depending on whether a representative vulnerability exists, preventing duplicate key database crashes on `ImpactAssessment` creation.
- **Vulnerability Scan Engine Fault-Isolation**: Enhanced the Celery base class `RengineTask` to suppress exception propagation for vulnerability scanner sub-tasks (e.g. `nuclei_scan`, `acunetix_scan`, `crlfuzz_scan`, `s3scanner`, `cpanel_scan`, `wpscan_scan`, `react2shell_scan`, `semgrep_scan`). This preserves the Celery chord callback (`finish_vulnerability_scan`), preventing a single scanner tool's failure from halting or aborting the rest of the scanning engine.
- **Vulnerability Sub-Task Tracking**: Mapped `react2shell_scan`, `semgrep_scan`, and `crlfuzz_scan` inside the `RengineTask`'s `dependent_tasks` mapping to guarantee all scan activity and sub-task statuses are tracked and persisted.
- **Retire.js Parser Hardening**: Fixed an `AttributeError` in the `web_api_discovery` Retire.js parser by handling string type return values when no vulnerable libraries are found, preventing scanning task failure.
- **Nuclei Scan Import Resiliency**: Resolved a name resolution/unbound local variable error in `nuclei_scan` by correctly importing and referencing the `Subdomain` model when processing vulnerability scan results.
- **Result Path Isolation**: Configured the scanning output directory structure to persistently separate scan runs per target and scan ID (`scan_results/{target}_{scanId}`), preventing overlapping tool runs from overwriting each other.
- **Celery Chord & Chain Synchronization**: Re-orchestrated the scan pipeline's task dependencies to run vulnerability scans in a coordinated Celery chord, ensuring that subsequent downstream engines (e.g. `APME` and `ERL`) wait for all vulnerability sub-tasks to finish before starting.

### [v3.0.0-rc6] - 2026-05-16

### Added
- **Adaptive Stress Interface Layout Refinement**: Rearranged the live telemetry space below the KPIs into a highly optimized 2-column tactical cockpit. Stacks all three real-time graphs (Latency, Throughput, and Saturation Heatmap) in a unified left column while stretching the raw telemetry log component full-height in the right column for enhanced observation density.
- **Raw stdout/stderr Live Terminal Streaming**: Implemented real-time streaming of raw tool execution commands and stdout/stderr output lines via WebSockets to the frontend telemetry terminal log.
- **Persistent Telemetry Session History**: Modified the telemetry consumer to reload the past 1000 logged items upon client connection, restoring terminal logs and ECharts dynamically on browser refresh.
- **Stress Scan Database Sync & Safe Completion**: Wrapped the Celery stress scan task in a `try...finally` block to guarantee a final `'completed'` telemetry packet is always sent to the client. Integrated explicit database updates to the `ScanHistory` object's `scan_status` attribute (`RUNNING_TASK`, `SUCCESS_TASK`, `ABORTED_TASK`, `FAILED_TASK`).
- **Activity & Command History Integration**: Registered all generated stress testing commands as command history records prior to subprocess execution, storing command lines, return codes, and raw stdout upon completion.
- **Mobile Companion Documentation**: Integrated high-fidelity visual documentation into the `r3ngine-mobile` repository, including a functional interface walkthrough and core UI screenshots.
- **Clear Logs Button**: Added a beautifully styled outlined button in the headerAction of the web dashboard's telemetry panel ([StressTestingPage.tsx](file:///d:/Repos/r3ngine/frontend/src/pages/StressTestingPage.tsx)) that completely clears the telemetry store logs on-demand.
- **Mobile Stress Telemetry Cockpit**: Built a high-fidelity, real-time stress testing telemetry dashboard in the `r3ngine-mobile` companion app (`app/scan/stress/[id].tsx`) featuring lightweight custom SVG line and bar charts, a live raw console log terminal with dynamic filters, haptic feedback abort controls (Kill Switch), and glassmorphic muted report triggers.

### [v3.0.0-rc5] - 2026-05-15

### Added
- **Semgrep Static Analysis Integration**:
  - **Automated Rule Synchronization**: Introduced a startup sync routine that downloads and bundles high-impact Semgrep rules (OWASP Top 10, Secrets, etc.).
  - **Unified SAST Task**: Developed a robust `semgrep_scan` task that automatically downloads relevant files (JS, PHP, etc.) from discovered endpoints for analysis.
  - **Secrets Discovery**: Integrated Semgrep into the Tier 5 secret scanning phase to complement Gitleaks and Trufflehog.
  - **Vulnerability Assessment**: Integrated Semgrep as a default, always-run tool in the vulnerability scan pipeline to identify code-based flaws.
  - **Intelligence-Driven Finding Persistence**: Automated mapping of Semgrep results to `SecretLeak` and `Vulnerability` database models with context-aware severity mapping.
- **Backend Security Toolchain Optimization**:
  - **Infrastructure Hardening**: Streamlined Docker environment by removing legacy browser dependencies (Firefox/Gecko) and reducing container bloat.
  - **Integrated Fuzzing Engine**: Refactored `dir_file_fuzz` to operate a concurrent pipeline utilizing both `ffuf` and `dirsearch`, with automated result deduplication.
  - **Discovery Pipeline Upgrades**: Implemented `amass intel` for infrastructure mapping and enabled `subfinder` exhaustive mode (`-all`).
  - **Intelligence-Driven Scanning**: Developed a technology mapping engine to automatically inject relevant tags into `nuclei` scans, ensuring high-impact vulnerability coverage.
  - **System Reliability**: Finalized cleanup of redundant packages (`scapy`) and validated end-to-end performance of the refactored security pipeline.

### [v3.0.0-rc4] - 2026-05-15

### Added
- **Stress Test Intelligence Reports**:
  - **Specialized Reporting Engine**: Introduced professional-grade performance reports for the Adaptive Stress & Resilience Engine (ASRE).
  - **Dynamic Templates**: Created `stress_cyber_pro` (high-contrast) and `stress_modern` (minimalist) templates with performance-focused aesthetics.
  - **Automated Performance Insights**: Integrated LLM-generated executive summaries for stress test results, covering bottleneck analysis and resilience scoring.
  - **Advanced Visualizations**: Added dedicated PDF charts for latency distribution, throughput stability, and endpoint saturation.
  - **Dashboard Integration**: Added on-demand report generation directly from the Stress Testing dashboard.

## [v3.0.0-rc3] - 2026-05-15

### Added
- **Human-in-the-Loop OSINT Validation Pipeline**:
  - **OSINT Staging Engine**: Introduced a middle-tier validation layer for moderate-confidence findings (50%-80%), preventing data pollution while ensuring maximum coverage.
  - **Interactive Audit Dashboard**: Premium staging interface with multi-select support, bulk validation (promotion to primary assets), and safe discarding of false positives.
  - **Centralized Persistence Architecture**: Refactored the core ingestion pipeline into a unified `persist_osint_item` engine to ensure consistent asset creation and enrichment rules.
  - **Metadata Exploration**: Collapsible detail views for OSINT staging items, providing raw module findings and source context for informed decision-making.
  - **Confidence-Based Asset Routing**: Enhanced the OSINT task chain to automatically route high-confidence findings to primary tables while staging moderate-confidence findings for human review.
- **Enhanced Security Discovery Stack**:
  - **baddns Integration**: Automated subdomain takeover detection integrated into the core discovery pipeline with automatic critical vulnerability mapping.
  - **BetterLeaks Integration**: High-precision secret and leak identification in discovered assets, integrated into the Tier 5 scanning phase.
  - **Advanced Personnel Discovery**: Fully integrated **username-anarchy** and **GoSearch** for social presence mapping and identity enrichment.
  - **Expanded Secret Scanning**: Added support for 15+ sensitive file extensions (`.env`, `.conf`, `.bak`, `.old`, etc.) discovered during reconnaissance.

## [v3.0.0-rc2] - 2026-05-14

### Added
- **Dedicated 24/7 Monitoring Engine (ReconX Integration)**:
  - Transitioned ReconX into a persistent background monitoring service.
  - **Parallel Execution Support**: Implemented domain-specific data directories and PID-based process tracking, allowing simultaneous monitoring of multiple targets.
  - **Dynamic Configuration**: Automated generation of target-specific YAML configs for isolated monitoring cycles.
  - **Background Orchestration**: ReconX now runs as a detached background process, decoupled from the main scan pipeline.
  - **Deduplicated Result Ingestion**: Enhanced the parsing logic to target domain-specific findings, ensuring data integrity during parallel monitoring.
  - **Engine Optimization**: Removed ReconX from regular scan engines to strictly enforce its role as a 24/7 monitoring tool.
- **Attack Surface Visualization Redesign (v4.0)**:
  - **Hierarchical Asset Clustering**: Implemented automated grouping of infrastructure (Domains > Subdomains > Endpoints) using compound nodes.
  - **Advanced Layout Orchestration**: Added support for **fCoSE** (force-directed) and **KLay** (hierarchical) layouts for multi-perspective analysis.
  - **Interactive Intelligence Map**: Integrated high-performance **Cytoscape.js** canvas with semantic expansion/collapse and neighborhood highlighting.
  - **Tactical Context Menus**: Unified right-click actions for immediate intelligence lookups, blast radius calculation, and targeted scan initiation.
  - **Enterprise Performance**: Optimized rendering pipeline to handle 10k+ nodes with 60FPS interaction via viewport culling and edge-hiding.

## [v3.0.0-rc1] - 2026-05-14

### Added
- **Integrated Identity Enrichment Pipeline**: Automated OSINT enrichment for discovered personnel.
  - **username-anarchy**: Integrated for intelligent username permutation generation based on full names.
  - **gosearch**: Integrated for cross-platform social and web presence discovery using generated usernames.
  - **Automated Triggers**: OSINT enrichment now triggers automatically upon discovery of new emails or employee records.
- **Subdomain Takeover Detection (baddns)**:
  - Integrated `baddns` into the core subdomain discovery pipeline.
  - **Automated Vulnerability Scoring**: Takeovers detected by `baddns` are automatically promoted to "Critical" vulnerabilities and marked as important assets.
- **Enhanced Secrets & Leaks Pipeline**:
  - **betterleaks**: Integrated as a primary secret discovery tool for high-precision leak identification.
  - **Sequential Orchestration**: Refactored the scan pipeline to ensure secret scanning runs strictly after URL extraction and directory fuzzing (Tier 5).
  - **Multi-Extension Support**: Expanded scanning to include all sensitive file types (`.env`, `.conf`, `.bak`, etc.) discovered during reconnaissance.

## [v3.0.0-beta] - 2026-05-09

### Added
- **Multi-Service Brute-Force Orchestration**: Updated brute-force engine schema to support an array of services (SSH, FTP, HTTP, SMB, RDP, Telnet).
- **Brute-Force Candidate Filtering**: Refactored `BruteForceOrchestrator` to dynamically filter `AuthCandidate` records based on the engine's allowed services.
- **Adaptive Stress & Resilience Engine (ASRE)**: Implemented full-scale endpoint stress testing directly within the reNgine workflow.
  - **Multi-Tool Orchestration**: Seamlessly orchestrated backend stress tests via Celery, driving load testing tools such as `k6`, `wrk`, `hping3`, and `Locust`.
  - **Real-Time Telemetry**: High-frequency metrics streaming (Latency, RPS, Error Rate) via Redis Streams and WebSockets.
  - **Interactive Dashboard**: Premium React monitoring interface with synchronized ECharts and saturation heatmaps.
  - **Safety Guardrails**: Integrated Redis-based kill-switch mechanisms for instant termination.
- **Fixture Standardization**: Aligned default scan engine fixtures with the new multi-service schema and resolved YAML deserialization issues.
- **Plugin Tooling System**: Introduced `tools.yaml` contract for automated background tool installation.
- **Engine Fixture Ingestion**: Plugins can now ship `*_engine.yaml` fixtures for automatic engine registration.
- **Background Tool Installation**: Plugin tools are now installed/verified asynchronously via Celery on installation and system startup.
- **Subprocess Execution Model**: Standardized local execution for plugins to enhance performance and simplify container orchestration.
- **Chronological Table Ordering**: Standardized descending ID ordering across Scan History and Target Lists to ensure the most recent entries appear at the top.
- **Enhanced Pagination & Filtering**:
  - **Scan History**: Implemented memoized sorting and filtering logic in the frontend for consistent recency.
  - **Target List**: Introduced frontend-driven pagination and functional search filtering to the target management interface.

### Exploit Readiness Layer (ERL) Hardening (v3-beta)
- **Proxy Support**: Native integration with reNgine's proxy settings. Tools (`sqlmap`, `XSStrike`) now respect system-wide proxy rotation via proxychains or environmental injection.
- **OpSec Compliance**: ERL validations now inherit reNgine's OpSec policies, including random User-Agents and stealthy headers.
- **Subprocess Execution**: Migrated from Docker-in-Docker to high-performance local subprocess execution for tool validation.
- **Autonomous Tooling**: Standardized `tools.yaml` for automatic dependency management and installation of required binaries.
 
### New Features
- **Deep Pursuit OSINT Engine & Intelligence Hub**:
  - Replaced heavy Spiderfoot reliance with a modular, high-performance OSINT pipeline.
  - **Tool Orchestration**: Integrated `holehe` (email pivots), `maigret` (social profile mapping), and a custom **Playwright Social Intelligence Engine** into the core Celery task chain.
  - **Social Footprint Intelligence**: Added automated discovery of social media accounts associated with discovered emails, visualized in the enhanced "Emails & Credentials" section.
  - **Employee Dossiers**: Integrated username-to-profile mapping, allowing users to pivot from professional identities to social footprints with direct profile links.
  - **Metadata Persistence**: Added a schema-less `metadata` JSONField to `Email` and `Employee` models for storing rich, tool-specific intelligence findings.
  - **OpSec Proxy Rotation**: Fully integrated the `OpSecManager` into the OSINT pipeline, ensuring per-tool proxy rotation for all reconnaissance activities.
- **Internal Social Intelligence Engine (Playwright)**:
  - Developed a custom, high-performance LinkedIn reconnaissance engine powered by Playwright.
  - **Persistent Session Orchestration**: Implemented stateful context management in `scan_results/context/linkedin`, mimicking real-user sessions to drastically reduce account lockout risks.
  - **Evasion & Stealth**: Integrated a full evasion suite including `playwright-stealth`, randomized human-like behavioral modeling, and Gaussian interaction delays.
  - **Hybrid Personnel Discovery**: Sophisticated logic that pivots between Company Page scraping and global search filtering for maximum data extraction.
  - **Visual Verification**: Every discovery run generates a unique, timestamped screenshot (`linkedin_[company]_[timestamp].png`) for investigator audit.
- **Intelligence Credential Orchestration**:
  - Integrated secure management for LinkedIn and Hunter.io credentials directly within the reNgine API Vault.
  - Implemented intelligent skip logic to ensure OSINT tasks exit gracefully if credentials are not configured.
- **Asynchronous Report Generation Pipeline**: Eliminated 502 Bad Gateway timeouts by offloading PDF generation to background workers.
  - **Status Tracking & Polling**: Implemented a new `ScanReport` model and status API endpoints to monitor generation progress.
  - **Dynamic UI Progress**: Added a polling mechanism to the `ScanReportModal` with real-time status updates and manual download fallback.
  - **Custom Aesthetics**: Fully integrated user-configured branding, including custom colors and company identity settings.
- **Integrated Subdomain Action Interface**: Fully wired and enabled interactive management for the Subdomains tab in the scan detail interface.
  - **Subscan Configuration Overlay**: Implemented a tactical overlay for initiating targeted subscans with multiple engine selection support.
  - **LLM-Powered Attack Surface Analysis**: Integrated on-demand attack surface generation for individual subdomains using configured LLMs.
  - **Tactical TODO Management**: Added functionality to quickly attach reconnaissance notes (TODOs) to specific subdomains.
  - **Status & Lifecycle Management**: Fully implemented deletion and importance toggling for subdomains with immediate UI feedback and query invalidation.
- **Intelligent Brute-Force Orchestration Engine**: Replaced legacy Nmap-based triggers with a centralized, discovery-driven queue.
  - **AuthCandidate Queue**: Implemented a new database model to track and deduplicate brute-force targets (SSH, RDP, SMB, FTP, Telnet, HTTP) across all discovery tools.
  - **Tiered HTTP Discovery**:
    - **Tier 1 (Tech Hints)**: Automatic detection of common services.
    - **Tier 2 (Nuclei)**: Integrated 500+ authentication-related Nuclei templates into the candidate queue.
    - **Tier 3 (Intelligent Extraction)**: Automated form extraction using httpx and regex to identify unknown login portals.
  - **Unified Hydra Orchestrator**: Refactored the brute-force engine to use Hydra for high-speed, multi-protocol batching with OpSec awareness (rate-limiting and delay controls).
- **Hydra Brute-Force Integration**: Migrated from Medusa to Hydra as the primary brute-force engine for enhanced reliability and better service support.
- **Adaptive Stress & Resilience Engine (ASRE)**: Implemented full-scale endpoint stress testing directly within the reNgine workflow.
  - **Tool Orchestration**: Seamlessly orchestrated backend stress tests via Celery, driving load testing tools such as `k6`, `wrk`, `hping3`, and `Locust`.
  - **Safety Guardrails**: Integrated a Redis-based kill-switch mechanisms for safe testing and instant termination to protect target infrastructure.
  - **Telemetry Ingestion**: Real-time aggregation of latency, throughput, and error rate metrics directly into Neo4j for topological node analysis.
  - **Visualization Dashboard**: Created a new React-based interactive UI utilizing Apache ECharts and Nivo to visually represent endpoint resilience, saturation points, and errors across the network.
- **Documentation Overhaul**: Comprehensive restructuring of the documentation to provide high-level visibility into v3 capabilities and surgical recon pipelines, including a new dedicated section for the **Adaptive Stress & Resilience Engine (ASRE)**.
- **Exploitation Readiness Layer (ERL)**: Implemented a safe, modular, and production-grade validation layer for vulnerabilities.
  - **Vulnerability Validation**: Automatically converts potential findings into "Verified" status using non-destructive, containerized validation tools (e.g., safe SQLmap profiles).
  - **Confidence Scoring**: Integrated a Bayesian confidence engine that aggregates tool results, asset metadata, and tool reliability into a unified confidence score.
  - **Containerized Sandboxing**: Orchestrated on-demand, ephemeral Docker sandboxes for validation execution to maintain strict isolation.
  - **Policy-Driven Safety**: Implemented a Policy Engine that enforces safety boundaries, preventing validation on sensitive assets (e.g., .gov, production) or during restricted hours.
  - **Normalizer & Adapters**: Standardized validation evidence (request/response dumps, payloads) into a unified schema for consistent UI rendering.
  - **Global Configuration**: Added a global toggle `RENGINE_ERL_ENABLED` and updated all default scan engines to include ERL by default.
  - **Interactive Evidence Viewer**: Added a new "Validation" column and expandable evidence section in the vulnerability dashboard to display cryptographic-grade proof of findings.
- **Attack Path Modeling Engine (APME) Robustness & Rules Expansion**:
    - **Virtual Goal Injection**: Implemented automated injection of "Virtual Goal Nodes" (Objectives) into the attack graph, ensuring rules always have targets to wire to.
    - **Comprehensive Attack Rules**: Expanded `rules.yaml` with 20+ sophisticated rules covering XSS, XXE, SSRF, CORS, Prototype Pollution, and Open Redirects.
    - **SCA & Dependency Intelligence**: Integrated vulnerability mapping for supply chain and dependency findings, automatically deriving potential RCE and Data Exfil paths.
    - **Schema & Ingestion Hardening**: Expanded `vulnerabilities.py` to support deep subtype inference and updated `schema.py` for cloud-native capability modeling.
    - **Subscan Pipeline Integration**: Fixed a decoupling issue where APME and ERL validation would not trigger during targeted vulnerability subscans. Integrated correlation, risk scoring, and path modeling into the per-subdomain scan chain to ensure data consistency across targeted reconnaissance.
    - **Engine Decoupling**: Moved Attack Path Modeling configuration to its own independent engine block (`attack_path_modeling`), allowing it to be explicitly chained after other post-scan services like ERL validation.
- **WPScan Vulnerability Integration**:
  - Integrated **WPScan** as a first-class security tool for automated WordPress reconnaissance.
  - **Secure API Orchestration**: Added a dedicated persistence layer in the reNgine Vault for WPScan API tokens, enabling detailed vulnerability reporting.
  - **Deduplication & Persistence**: Integrated results directly into the `Vulnerability` database with intelligent deduplication against existing findings.
  - **Tactical Configuration**: Added per-engine controls for WPScan enumeration modes and detection sensitivity via YAML configurations.
  - **Infrastructure Support**: Updated the core Docker environment to include Ruby and WPScan as a pre-installed dependency.

- **Advanced Web App & API Discovery Pipeline**: Introduced a dedicated reconnaissance engine for deep API discovery, featuring:
ring:
 - **Kiterunner**: High-performance API endpoint brute-forcing with custom `.kite` wordlists (`routes-large.kite` by default).
 - **Arjun**: Automated HTTP parameter discovery for identifying hidden API inputs.
 - **ParamSpider**: Advanced parameter extraction from web archives and live sources.
 - **InQL**: Comprehensive GraphQL introspection and vulnerability analysis.
 - **Aquatone**: Automated visual reconnaissance for discovered API endpoints.
 - **LinkFinder**: Deep extraction of endpoints from JavaScript files.
- **Spiderfoot OSINT Integration**: Fully integrated Spiderfoot as a standalone scan module, supporting:
 - Dynamic module configuration via YAML scan engines.
 - Automatic ingestion of discovered subdomains and URLs into the reNgine database.
- Full Neo4j graph synchronization for OSINT assets.
- **Multi-Tier Theme System (Hacker, Hybrid, Enterprise)**: Implemented a 3-tier, switchable aesthetic architecture for the React v3 frontend.
  - **Hacker Theme (Default)**: Optimized the signature cyberpunk look with custom scanline logic and Orbitron-driven typography.
    - **Aesthetic Refinement**: Applied signature neon pink branding (`rgb(255, 0, 241)`) and red glow effects to the brand logo and version badge across all Cyberpunk profiles (Hacker & Hybrid).
  - **Hybrid (Modern) Theme**: Introduced a "clean" dark mode that preserves brand-essential neon accents but removes high-intensity background effects.
  - **Enterprise (Professional) Theme**: Added a new, professional "Slate & Blue" interface using Inter typography and a flat, high-density layout for corporate use cases.
  - **Functional Token Architecture**: Centralized all theme logic in `tokens.ts`, enabling dynamic injection of CSS variables for fonts, colors, and motion.
  - **Persistent Selection**: Integrated a `HeaderThemeSwitcher` with `localStorage` persistence and automatic theme propagation via `ThemeContext`.
- **Cyberpunk V3 "Neon" Dashboard**: Reimagined the entire UI with a premium glassmorphic theme, featuring:
 - Unified dark/neon color palette for enhanced data visualization.
 - Improved sorting and filtering UI for large subdomain datasets.
 - Optimized sidebar and navigation for complex scan management.
- **Semgrep-Powered Static Analysis**: Integrated Semgrep to automatically analyze discovered JavaScript and API endpoints for common security flaws (replacing legacy JSParser).
- **Enhanced Proxy Orchestration**: Integrated rotating proxy support across all new discovery tools (Arjun, Kiterunner, etc.) to bypass rate-limiting and WAF blocks.
- **Result Ingestion V3**: Overhauled the result ingestion pipeline to handle massive datasets from API discovery, ensuring database performance and graph integrity.
- **Centralized AI Hub**: Introduced a unified AI management interface supporting multiple providers (OpenAI, Anthropic, Google Gemini, and Ollama).
- **Multi-Provider LLM Support**: Added production-ready integration for Claude 3 (Anthropic) and Gemini (Google) via REST APIs, alongside existing OpenAI and Ollama support.
- **Dynamic Model Fetching**: Implemented real-time model discovery for all supported providers, including hardware requirements and expertise insights for local models.
- **On-Demand Model Loading**: Optimized the AI Hub by fetching available models only when the dropdown is clicked, reducing initial page load overhead.
- **Legacy API Vault Sync**: Automatically migrates existing OpenAI keys from the legacy API Vault to the new AI Hub configuration.
- **Granular Proxychains Control**: Integrated a new `use_proxychains` toggle for precise control over proxy orchestration.
  - **Conditional Wrapping**: Users can now choose whether to wrap tools with `proxychains4` or prefer native tool proxy support.
  - **Automated Cleanup**: Implemented safe, multi-threaded configuration management that automatically cleans up temporary proxychains configs after execution.
  - **Tool Parity**: Updated core tasks (Hydra, Amass, Subfinder, Katana, etc.) to respect the new setting and utilize native flags where available.
  - **Integrated UI Switch**: Added a dedicated "USE PROXYCHAINS WRAPPER" switch in the Proxy Settings dashboard.
  - **On-the-fly Validation**: Automatically verify proxy connectivity before use to ensure high reliability during automated scans.
- **Production-Ready SSL Serial Retrieval**: Implemented a robust `_get_ssl_serial` function in `waf_utils.py` using the `cryptography` library for reliable origin discovery via Shodan.
  - **Standardized Notification System (Snackbar)**: 
    - Replaced legacy `alert()` dialogs with consistent, non-intrusive MUI `Snackbar` and `Alert` components across all settings modules.
    - Implemented state-driven feedback for critical actions in `SubdomainsTab`, `ApiVault`, `ProxySettings`, `ReportSettings`, `OpSecSettings`, `LlmToolkit`, `SystemSettings`, and `AdminSettings`.
    - Enhanced error handling with detailed feedback from backend mutation responses.
    - Unified notification visuals with the "Cyberpunk" design language (Orbitron font, filled severity backgrounds).
- **Modernized Censys Platform Integration**: 
  - Migrated from legacy Search v2 (Basic Auth) to the latest **Censys Platform API (2026 standards)** using Personal Access Tokens (Bearer authentication).
  - Updated the `CensysAPIKey` database model to support a single-key schema.
  - Refactored `OriginDiscoveryManager` to utilize the `censys-platform` SDK for more reliable host lookups and origin discovery.
  - Streamlined the API Vault and Onboarding UI for single-key configuration.
- **Scoped Attack Surface Visualization**: Refactored the Neo4j ingestion and retrieval pipeline to support scan-specific and target-specific scoping:
  - Introduced `Scan` nodes in Neo4j to anchor assets to specific execution contexts.
  - Implemented target-level graph aggregation with color-coded scan distinction in the UI.
  - Added backend API support for segmented graph data fetching (`/api/graph/target/<target_id>/data/`).
  - Added new "Attack Surface" and "Visualization" tabs to the Target Summary view.
  - Resolved "node bleeding" where global graph data would pollute individual scan maps.
  - Included a `sync_all_scans` migration utility to retroactively anchor historical data.
  - Added a `reset_graph` Django management command to clear and re-populate the Neo4j database in case of data corruption or schema changes.
  - **Attack Surface Map v4.0 UI Architecture**:
    - **Multi-Panel Layout**: Transitioned the visualization area to a multi-panel layout managed by Zustand state architecture (`useGraphStore`).
    - **Advanced Node Analytics**: Upgraded Cytoscape rendering to dynamically scale node sizes based on degree centrality and highlight critical vulnerabilities.
    - **Interactive Node Details**: Added a dedicated slide-out panel displaying live graph metrics (centrality, vulnerabilities) with actionable options.
    - **Blast Radius Computation**: Integrated real-time blast radius calculations using Neo4j APOC, displaying downstream compromised assets.
    - **AI-Driven Graph Search**: Replaced standard graph search with a mock AI natural language query interface for future conversational exploration.
- **Enhanced GeoMap Visualization**:
  - **Custom Tactical Markers**: Replaced broken default Leaflet markers with high-performance CSS-animated pulsing `divIcon` markers, maintaining the "Cyberpunk Hacker" aesthetic.
  - **Comprehensive Global Mapping**: Integrated an external `countryCentroids.ts` database covering all ISO-2 country codes for high-precision asset positioning.
  - **Improved Interaction Layer**: Replaced unsupported React-based marker children with native `react-leaflet` `Tooltip` components for reliable hover interactions and tactical styling.
  - **Visual Polish**: Added dedicated `.map-marker-pulse` and `.tactical-tooltip` global CSS styles for smooth animations and premium UI consistency.
  - **Vulnerability Impact Intelligence**: Integrated AI-driven impact assessment and graph-based attack path visualization:
    - **AI-Driven Impact Assessment**: Automated generation of potential impact narratives and remediation priorities using LLMs (OpenAI, Anthropic, Gemini, Ollama).
    - **Attack Path Visualization**: Interactive Cytoscape.js-powered graph showing the full exploit chain from root domain to vulnerability.
    - **Impact Explorer**: A tactical React component for real-time monitoring of impact generation tasks and interactive graph exploration.
    - **PII Gate**: Implemented a privacy-preserving "gate" that anonymizes sensitive reconnaissance data (IPs, emails, hostnames) before sending it to external LLMs and deanonymizes the returned results.
    - **Persistence & Polling**: Impact findings are persisted in PostgreSQL and synchronized with React Query using smart polling for asynchronous background tasks.
- **Advanced Vulnerability Correlation Engine**: 
  - Integrated **Trivy** for automated Software Composition Analysis (SCA) and **Gitleaks** for secret discovery.
  - Added **Retire.js** integration to identify vulnerable client-side JavaScript libraries.
  - Implemented a weighted correlation algorithm that unifies results from Nuclei (DAST), Semgrep (SAST), Trivy (SCA), Gitleaks, and Retire.js.
  - Introduced **Potential Attack Chain** generation to visualize sequential exploitation steps (Initial Access -> Lateral Movement -> Impact).
  - Added automated unit tests to ensure correlation logic accuracy across all security tools.
- **Seamless AI Impact Intelligence**: 
    - Modernized the AI-driven vulnerability assessment workflow with a state-aware Impact Explorer UI.
    - Replaced intrusive alerts with immediate loading overlays and persistent status monitoring.
    - Implemented auto-generation logic for first-time assessment views.
    - Synchronized AI findings directly to the `Vulnerability` model for consistent report persistence.
    - Fully updated the Exploit Readiness Layer (ERL) plugin to maintain cross-feature parity.
- **Acunetix & ReconX Orchestration**: 
    - **Acunetix (AWVS) Pipeline**: Integrated automated vulnerability scanning via Acunetix API. Supports secure storage of server URLs and API keys in the reNgine Vault, automated target provisioning, and native ingestion of scan findings into the core `Vulnerability` database.
    - **ReconX Auxiliary Discovery**: Integrated ReconX into the `monitor_tasks.py` pipeline to complement existing subdomain discovery and OSINT tools. ReconX findings are automatically parsed and mapped to `MonitoringDiscovery` nodes for consolidated asset tracking.
- **Frontend Security & Resilience**: 
    - **Centralized Auth Architecture**: Implemented a robust `AuthContext` and `AuthProvider` to manage user sessions and state globally.
    - **Protected Route Guards**: Integrated TanStack Router `beforeLoad` hooks to enforce authentication across all sensitive application routes.
    - **Robust CSRF Protection**: Centralized CSRF token retrieval and automated injection into all mutation requests via Axios interceptors.
    - **Automatic SQLi Prevention**: Implemented a client-side request interceptor that blocks outgoing requests containing suspicious SQL injection patterns in the payload.
    - **DOM Sanitization**: Integrated `DOMPurify` for secure rendering of potentially unsafe content, preventing XSS in future features.
    - **Dependency Hardening**: Remediated high-severity ReDoS vulnerabilities in the `d3` ecosystem via `package.json` overrides.
    - **Regex Security**: Optimized search highlighting logic with centralized regex escaping to prevent ReDoS attacks from user inputs.
- **Integrated Attack Surface Map Navigation**: 
  - Properly integrated the Attack Surface Map feature into the Scan History page.
  - Replaced the broken `window.open` placeholder with a dedicated, SPA-managed `AttackSurfacePage`.
  - Implemented a new route `/$projectSlug/attack_surface/$scanId` to host the cytoscape-based visualization.
  - Enhanced the UI with navigation breadcrumbs and scan-specific metadata for better context.
- **Security Hardening (v3)**:
    - **Path Traversal Fix**: Secured `serve_protected_media` in `reNgine/views.py` using the existing `is_safe_path` utility to prevent `../` directory traversal attacks (LFI).
    - **CSRF & API Method Hardening**: Migrated project creation from an unsafe `GET` request (vulnerable to CSRF via URL) to a secure `POST` request with proper CSRF token validation in both frontend (`projects/api.ts`) and backend (`CreateProjectApi`).
    - **Frontend XSS Prevention**: Hardened `monitoring/utils/formatters.ts` to use `DOMPurify` for all dynamic content sanitization, added prototype pollution protection in JSON parsing, and applied strict type-checking before accessing object properties.
    - **Django Security Headers**: Enabled `SECURE_CONTENT_TYPE_NOSNIFF`, `SECURE_BROWSER_XSS_FILTER`, `X_FRAME_OPTIONS = DENY`, `SECURE_REFERRER_POLICY`, and secure `SESSION_COOKIE_HTTPONLY`. Configurable HTTPS/HSTS settings via `.env` (`RENGINE_HTTPS`, `SECURE_HSTS_SECONDS`).
    - **ALLOWED_HOSTS Hardening**: `ALLOWED_HOSTS` is now configurable via the `ALLOWED_HOSTS` environment variable (defaults to `*`; must be set to specific domains in production).
    - **DRF Rate Limiting**: Added global REST framework throttle classes (20/min anonymous, 200/min authenticated) to protect API endpoints from brute-force attacks.
    - **Role-Based Authorization Fix**: Corrected the `IsAuditor` DRF permission class which was incorrectly granting write access to all authenticated users. Auditors are now correctly restricted to read-only (`SAFE_METHODS`) access; `IsSysAdmin`, `IsPenetrationTester`, and `IsAuditor` role documentation updated to reflect the three-tier hierarchy.
    - **Command Injection Mitigation**: Replaced all `run_command.run(f'touch {path}', shell=True)` subprocess calls in `GetFileContents` with safe Python-native `pathlib.Path.touch()` calls. Fixed `delete_target` in `targetApp/views.py` to use `shutil.rmtree` on a validated path instead of `rm -rf {obj.name}*` with `shell=True`.
- **Proxy & Vault Persistence Stability**:
  - Resolved missing `CircularProgress` import in `ProxySettingsPage.tsx` that caused frontend build failures.
  - Fixed Acunetix (AWVS) configuration persistence bug by correctly mapping `acunetix_url` and `acunetix_key` in the `useUpdateApiVault` mutation.
  - Synchronized frontend `FormData` keys with backend expectations (`key_acunetix_url`, `key_acunetix_key`).
  - Improved UI responsiveness for rescan actions and proxy fetching with immediate Snackbar feedback.
- **OSINT Intelligence Dashboard**: Implemented a comprehensive reconnaissance data visualization suite:
    - **Modular OSINT Tab**: Integrated a new, tactical dashboard into the Scan Detail view to aggregate and visualize discovery data.
    - **Email & Credential Exposure**: Displays discovered email addresses and associated leaked credentials in a secure, copy-able table.
    - **Employee Insights**: Visualizes discovered professional personnel and their designations in a responsive card grid.
    - **Search Engine Dorking Results**: Consolidated view of all search engine discovery URLs with direct links to findings.
    - **Document Metadata Analysis**: Detailed table of metadata (Author, OS, Creation Software) extracted from public documents via MetaFinder.
    - **Automated Dork Generation**: Introduced an "Autogenerate Dorks" feature in the scan initiation modal to programmatically build sensitive search queries for any target domain.
- **Plugin Orchestration System**: Introduced a powerful, modular system to extend reNgine with custom engines and UI.
  - **Dynamic Task Injection**: Implemented `PluginOrchestrator` to inject custom tasks into Celery scan chains at specific anchor points (e.g., after Vulnerability Scan).
  - **Pipeline Builder**: Created a drag-and-drop UI for reordering plugins relative to core engines.
  - **Atomic Installation**: Developed a secure installation system with automated database backups and rollback mechanisms for plugin management.
  - **Dynamic UI Modules**: Enabled runtime injection of custom React components into scan detail pages via ESM module loading.
  - **Plugin Registry**: Full CRUD support for plugin management, including enabling/disabling and metadata tracking.
- **Frontend Bundle Optimization**: Implemented granular manual chunking in Vite to split massive vendor libraries into smaller, more manageable bundles.
- **Route-Level Code Splitting**: Implemented lazy loading for all major tactical pages using TanStack Router's `lazyRouteComponent`, significantly reducing the initial application payload.
- **Plugin Management Pipeline Stability**: 
  - **404 Route Resolution**: Fixed a critical routing issue where refreshing the plugin management page would result in a 404 error by correctly registering the `/plugins/` route in the dashboard URL configuration.
  - **Hardened Atomic Installation**: Resolved 500 Internal Server Errors during plugin uploads by improving the `AtomicInstaller` database backup and rollback logic.

- **Automated Startup Synchronization**:
  - Implemented a robust, Redis-locked startup sequence in Celery to ensure essential datasets are synchronized when the system comes online.
  - **Graph Sync**: Automatically triggers a global Attack Surface graph synchronization (`sync_all_scans_to_graph`) upon system startup.
  - **CISA KEV Sync**: Automatically fetches and updates the Known Exploited Vulnerabilities (KEV) catalog (`sync_cisa_kev_catalog`) to ensure vulnerability intelligence is available immediately.

### Bug Fixes
- **Brute-Force Success Parsing**: Hardened the Medusa result parsing regex to require an explicit `[SUCCESS]` marker, eliminating false positives caused by misinterpreting `[FAILURE]` results.
- **Hydra Result Extraction**: Implemented robust parsing for Hydra output logs to correctly ingest discovered credentials into the vulnerability dashboard.
- **Refined Proxy Rotation Logic**: Optimized proxy rotation across all discovery and vulnerability modules. Each individual tool execution (Arjun, Kiterunner, ParamSpider, LinkFinder, Nuclei severities, etc.) now fetches a fresh random proxy, ensuring maximum traffic randomization and bypassing detection.
- **ParamSpider Optimization**: Optimized `web_api_discovery` to ensure `ParamSpider` only runs once per unique subdomain. Previously, it was being re-executed for every URL belonging to the same subdomain, leading to redundant work and log clutter.
- **Endpoint Deduplication**: Implemented URL pattern normalization in `web_api_discovery`. The engine now intelligently skips redundant endpoints that differ only by parameter values (e.g., locale variations), significantly reducing the number of tool calls while maintaining discovery coverage.
- **cPanel Scan Fix**: Resolved an `AttributeError` in the `cpanel_scan` task where the system attempted to access a non-existent `use_proxy` attribute on the `ScanHistory` model. The task now correctly utilizes the global proxy configuration system.
- **Arjun Results Parsing Fix**: Resolved `'list' object has no attribute 'items'` error during endpoint ingestion.
- **Hydra Brute-Force Resilience & Service Mapping**:
    - Implemented `max_retries` in engine configuration to prevent infinite loops on tool failure.
    - Added automated service mapping to convert generic protocols (e.g., `http`, `https`) into valid Hydra modules (`http-get`, `https-get`).
    - Integrated automatic error tracking that terminates scan tasks after the configured retry threshold.
- **Onboarding Crash Fix**: Resolved a `TypeError` in the `onboarding` view where `AnonymousUser` would trigger a crash when accessing or creating `UserPreferences`.



## v2.5.2

### Bug Fixes
- **SSLScan Parser**: Hardened the SSLScan XML parser against `NoneType` errors and missing elements in reports.
- **UI Rendering**: Fixed a bug where newlines in vulnerability descriptions, impacts, and remediations were being lost due to aggressive HTML encoding. Added `white-space: pre-wrap` to correctly render multi-line text in the dashboard.
- **Medusa Brute-Force Parser**: Fixed success identification logic for Medusa v2.2 by updating the result parsing regex to handle variations in output format, including optional Host fields and bracket styles.
- **Selective Brute-Force Triggering**: Restricted automatic brute-force scan triggering to only occur if `brute_force_scan` is explicitly selected for the current scan or subscan, preventing unintended executions.


## v2.5.1

### Bug Fixes
- **Monitoring Frequency**: Fixed a bug where monitoring frequency was stored as an integer, causing mismatch with the expected choice values in task scheduling.
- **Nmap Parser**: Added validation logic to filter out common false positive alerts from Nmap script results (e.g., timeouts, failed executions, and "not vulnerable" messages).


### New Features
- **Continuous Monitoring Engine**: Automated periodic discovery of new subdomains, directories, and login pages with real-time alerting and automated scan triggers.
- **Monitoring Dashboards**: Dedicated global monitoring dashboard and target-specific monitoring tabs to track asset growth over time.
- **Auth Brute-Force Engine**: Integrated Medusa for high-performance authentication testing across multiple services (HTTP, SSH, etc.).
- **Stealth Brute-Force Orchestrator**: Advanced orchestrator with dynamic proxy rotation via Proxychains4, batched attempts (1-10 per proxy), and random delays to bypass account lockout and IP blacklisting.
- **Deep Fingerprint Parsing**: Enhanced Nmap parsing to extract page titles even from 404, 401, and 403 responses by analyzing raw service fingerprint strings.
- **Automated Auth Triggering**: New logic to automatically trigger brute-force scans when an authentication portal or VPN gateway is detected, provided the brute-force module is enabled in the selected scan engine.
- **Curated Auth Wordlists**: Added specially curated "top/default" and "most common" wordlists for authentication testing, persisted in the `/usr/src/wordlist/auth/` volume.
- **Nmap Vuln Script Support**: Added comprehensive parsing for Nmap `vuln` script outputs, integrating them directly into the vulnerability dashboard.
- **Repository Migration**: Formally transitioned the project to `whiterabb17/r3ngine` as an unofficial fork.
- **Enhanced Update Check**: Implemented a fallback mechanism that checks both GitHub Releases and the raw `.version` file in the master branch. If a newer version is detected in the repository root, the system directs users to the main repo instead of the releases page.

## v2.4.0

### New Features
- **OpSec Settings**: Advanced stealth configuration including User-Agent rotation, custom rate limiting, WAF bypass headers, and custom DNS resolvers.
- **Stealth Presets**: Quick configuration for "Quiet", "Balanced", and "Aggressive" scan modes.
- **Metadata Stripping**: Automatically remove sensitive EXIF data and metadata from captured screenshots and downloaded OSINT documents.
- **New Scan Engine (Firewall & VPN)**: Dedicated Sophos Firewall and VPN scan engine with IKE and SSL scan capabilities.
- **New Tool Integrations**: Integrated Chaos, TLSX, CTFR, Netlas, and Katana for broader and more efficient reconnaissance.
- **Automatic Proxy Fetching and Validation**: Automatically sources and tests live proxies from multiple providers to ensure scan stability and stealth.
- **Improved NMap Vulners Script Parsing**: Enhanced parsing of NMap vulnerability scan results for more accurate service and version identification.
- **LLM-Powered Report Summaries and Conclusions**: Automatically generates Assessment Overviews, Executive Briefs, and Final Conclusions in PDF reports using OpenAI or local LLMs (Ollama).

### Bug Fixes
- **theHarvester Integration**: Fixed Docker installation and runtime issues for theHarvester OSINT tool.

## v2.2.0

## What's Changed

### Summary
- Introducing Bounty Hub: Central platform for managing and importing bug bounty programs
- New Built-in notification system for important events and updates
- Enhanced subdomain discovery using Chaos project dataset
- Bug Bounty Mode as user preference to enable or disable features related to bug bounty
- Path exclusion feature for scans
- New visually appealing PDF report template
- Regex support for out-of-scope subdomains
- Stop All Scans killswitch to halt multiple running scans at once
- Smart rescans that automatically import and apply previous scan configurations
- Improved Start Scan UI for consistent configuration across multiple scans
- Support for bulk uploads of nuclei and gf patterns
- API key protection (masking in settings view)

* feat: Allow uploading of multiple gf patterns #1318 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1319
* feat: Introduce stop multiple scans #1270 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1321
* feat: Mask API keys Fixes #1213 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1331
* feat: Allow uploading multiple nuclei patterns #461 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1320
* feat: Introduce github action for auto updating version and changelog on every release by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1348
* chores: Removes external IP from reNgine ui by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1350
* feat: Implement URL Path Exclusion Feature with Regex Support Fixes #1264 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1354
* feat: Consistent start scan ui across schedule scan, multiple scans. Now supports import, out of scope subdomains, starting path, excluded path for all types of scan #1357 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1361
* Update of template.html with conditional statement by @DamianHusted in https://github.com/yogeshojha/rengine/pull/1378
* feat: feat ability to delete multiple scheduled scan #1360 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1382
* feat: Enhanced Out of Scope Subdomain Checking, Support for regex in out of scope scan parameter #1358  by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1380
* feat: Store and showcase scan related configuration such as imported subdomains, out of scope subdomains, starting point url and excluded paths fixes #1356 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1383
* Update celery-entrypoint.sh by @SJ029626 in https://github.com/yogeshojha/rengine/pull/1390
* feat:  Prefll the scan parameters during rescan with the scan configuration values that were being used in earlier scan #1381  by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1386
* feat: Added additional templates for PDF reports #1387 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1391
* Replace CVE-2024-41661 with CVE-2023-50094 by @shelbyc in https://github.com/yogeshojha/rengine/pull/1393
* hotfix: Workflow autocomment issues by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1396
* Fix comment workflow on fork PRs by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1400
* Hotfix/workflow cmt1 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1401
* fix author name by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1403
* Update of the uninstall.sh script by @DamianHusted in https://github.com/yogeshojha/rengine/pull/1385
* feat: Builtin notification system in reNgine #1392  by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1394
* feat: Show what's new popup when update happens and new features are released #1395  by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1405
* feat: Add Chaos for subdomain enumeration #173 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1406
* Version 2.1.3 contains a patch for CVE-2024-43381 by @shelbyc in https://github.com/yogeshojha/rengine/pull/1412
* feat: Introducing Bounty Hub, a central hub to import and manage your hackerone programs to reNgine by @null-ref-0000 in https://github.com/yogeshojha/rengine/pull/1410
* feat: Add ability to delete multiple organizations by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1417
* feat: Enable bug bounty mode as User Preference to separate bug bounty related features #1411 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1418
* bug: remove watchmedo usage in production #1419 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1424
* feat: Create organization when quick adding targets #492 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1425
* reNgine 2.2.0 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1349

## New Contributors
* @DamianHusted made their first contribution in https://github.com/yogeshojha/rengine/pull/1378
* @SJ029626 made their first contribution in https://github.com/yogeshojha/rengine/pull/1390
* @shelbyc made their first contribution in https://github.com/yogeshojha/rengine/pull/1393

**Full Changelog**: https://github.com/yogeshojha/rengine/compare/v2.1.3...v2.2.0

## 2.1.3

**Release Date: Aug 18, 2024**

## What's Changed

### Security Update

* (Security) CVE-2024-43381 Stored Cross-Site Scripting (XSS) via DNS Record Poisoning reported by @touhidshaikh Advisory https://github.com/yogeshojha/rengine/security/advisories/GHSA-96q4-fj2m-jqf7

### Bug Fixes

* remove redundant docker environment variables by @jxdv in https://github.com/yogeshojha/rengine/pull/1353
* fix: reNgine installation issue due to orjson and langchain #1362 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1363
* #1364 Fix whois lookup and improve performance by executing various modules of whois lookup to run concurrently by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1368
* chores: Add error handling for the curl command by @gitworkflows in https://github.com/yogeshojha/rengine/pull/1367
* Update Github Actions Workflows by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1369
* chores: Fix docker build on master by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1373

#### New Contributors
* @gitworkflows made their first contribution in https://github.com/yogeshojha/rengine/pull/1367

**Full Changelog**: https://github.com/yogeshojha/rengine/compare/v2.1.2...v2.1.3

## 2.1.2

**Release Date: July 30, 2024**

## What's Changed

### Security update
* (Security) CVE-2023-50094 Fix Authenticated command injection in WAF detection tool reported by @n-thumann Advisory https://github.com/yogeshojha/rengine/security/advisories/GHSA-fx7f-f735-vgh4

### Bug Fixes

* Fix issue while initiating periodic and clocked scan #1322 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1328
* Fix 500 error on "Test Hackerone api Key" by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1332
* UI Typos and bug Fixes #1333 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1334
* Fix error during tool update Fixes #1152 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1335
* Upgrade setuptools to 72.1.0 to resolve installation error by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1338
* (chores) Fix github pages build by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1339
* Fix subdomain import for subdomains with suffixes more than 4 chars Fixes #1128 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1340

**Full Changelog**: https://github.com/yogeshojha/rengine/compare/v2.1.1...v2.1.2


## 2.1.1

**Release Date: July 20, 2024**

## What's Changed and Fixed
* Update contribution guidelines reference by @emmanuel-ferdman in https://github.com/yogeshojha/rengine/pull/1286
* fix xss on page title fix #1185 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1296
* fix context key error #1263 #1209 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1294
* fix xss on vulnerability description payloads #1262 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1298
* (bug) fix screenshot csv parser #1299 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1300
* (Security) Fixes #1202 bug risk of leaking the scan result files by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1301
* Fix #1291 Refactor Makefiles for windows/linux to accomodate both v1 and v2 of docker compose by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1302
* Fix custom_header to accept multiple headers using custom_headers by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1303
* Handle hash in url, added navigation for Tabs, Fixes #1155 bug href link with html id does not link to the expected url by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1306
* Optimize uninstall scripts to perform operations only related to reNgine Fixes # 1187 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1307
* Added validators to validate URL fixes #1176 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1308
* Fix LLM/langchain issue for fetching vulnerability report using local LLM model Fixed #1292  local model dont use fetch gpt vulnerability details by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1311
* Fixes for Clocked and Periodic Scans Fix #1287 Fixes #1015 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1313
* Fix Not able to add todo from All Subdomains Section Fixes #1310 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1314
* Fix #1315 Fix for todo URLs not compatible with slugs by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1316
* Fixes #1122 But in port service lookup that caused multiple entries of Port with same port number but different service name/description by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1317

#### New Contributors
* @emmanuel-ferdman made their first contribution in https://github.com/yogeshojha/rengine/pull/1286

**Full Changelog**: https://github.com/yogeshojha/rengine/compare/v2.1.0...v2.1.1

## 2.1.0

**Release Date: June 22, 2024**

## What's Changed
* ARM support
* Add LLM Toolkit by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1259
* use django-env by @fopina in https://github.com/yogeshojha/rengine/pull/1230
* Add Lark to notifications. by @iuime in https://github.com/yogeshojha/rengine/pull/1137
* Added restart: always to redis container by @null-ref-0000 in https://github.com/yogeshojha/rengine/pull/1275
* Dockerfile cleanup: reduce image size 3x by @sa7mon in https://github.com/yogeshojha/rengine/pull/1212
* Support for ARM-based platforms and remove obsolete composer version by @metehan-arslan in https://github.com/yogeshojha/rengine/pull/1242
* Fix importing CIDR blocks by @pbehnke in https://github.com/yogeshojha/rengine/pull/1205
* Added SAN extension to the generated certs by @michschl in https://github.com/yogeshojha/rengine/pull/1282
* Release/2.1.0 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1147
* Dockerfile Build Multiple Platforms by @vncloudsco in https://github.com/yogeshojha/rengine/pull/1210

#### New Contributors
* @fopina made their first contribution in https://github.com/yogeshojha/rengine/pull/1230
* @iuime made their first contribution in https://github.com/yogeshojha/rengine/pull/1137
* @null-ref-0000 made their first contribution in https://github.com/yogeshojha/rengine/pull/1275
* @sa7mon made their first contribution in https://github.com/yogeshojha/rengine/pull/1212
* @metehan-arslan made their first contribution in https://github.com/yogeshojha/rengine/pull/1242
* @pbehnke made their first contribution in https://github.com/yogeshojha/rengine/pull/1205
* @michschl made their first contribution in https://github.com/yogeshojha/rengine/pull/1282
* @vncloudsco made their first contribution in https://github.com/yogeshojha/rengine/pull/1210

**Full Changelog**: https://github.com/yogeshojha/rengine/compare/v2.0.6...v2.1.0

## 2.0.6

**Release Date: May 11, 2024**

## What's Changed
* Fix installation error and celery workers having issues with httpcore
* remove duplicate gospider references by @Talanor in https://github.com/yogeshojha/rengine/pull/1245
* Fix "subdomain" s3 bucket by @Talanor in https://github.com/yogeshojha/rengine/pull/1244
* Fix Txt File Var Declaration by @specters312 in https://github.com/yogeshojha/rengine/pull/1239
* Bug Correction: When dumping and loading customscanengines by @TH3xACE in https://github.com/yogeshojha/rengine/pull/1224
* Fix/infoga removal by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1249
* Fix #1241 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1251

#### New Contributors
* @Talanor made their first contribution in https://github.com/yogeshojha/rengine/pull/1245
* @specters312 made their first contribution in https://github.com/yogeshojha/rengine/pull/1239
* @TH3xACE made their first contribution in https://github.com/yogeshojha/rengine/pull/1224

**Full Changelog**: https://github.com/yogeshojha/rengine/compare/v2.0.5...v2.0.6

## 2.0.5

**Release Date: April 20, 2024**

* Fix #1234 reNgine unable to load celery tasks due to mismatched celery and redis versions

## 2.0.4

**Release Date: April 18, 2024**

## What's Changed
* chore: update version number to 2.0.3 by @AnonymousWP in https://github.com/yogeshojha/rengine/pull/1180
* Fix various ffuf bugs by @yarysp in https://github.com/yogeshojha/rengine/pull/1199
* Set and update default YAML config with all latest vars by @yarysp in https://github.com/yogeshojha/rengine/pull/1200
* Add checks for placeholder in custom tool task by @yarysp in https://github.com/yogeshojha/rengine/pull/1201
* Whatportis - Replace purge by truncate to prevent port import error by @yarysp in https://github.com/yogeshojha/rengine/pull/1203
* ops(installation): fix nano not being installed when absent by @AnonymousWP in https://github.com/yogeshojha/rengine/pull/1143
* Complete dev environment to debug/code easily by @yarysp in https://github.com/yogeshojha/rengine/pull/1196
* Revert "Complete dev environment to debug/code easily" by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1225
* Update README.md | Fixed 1 broken link to the regine.wiki by @jostasik in https://github.com/yogeshojha/rengine/pull/1226
* Fix uninitialised variable cmd in custom_subdomain_tools by @cpandya2909 in https://github.com/yogeshojha/rengine/pull/1207
* [FIX] security: OS Command Injection vulnerability (x2) #1219 by @0xtejas in https://github.com/yogeshojha/rengine/pull/1227

### New Contributors :rocket: 
* @yarysp made their first contribution in https://github.com/yogeshojha/rengine/pull/1199
* @jostasik made their first contribution in https://github.com/yogeshojha/rengine/pull/1226
* @cpandya2909 made their first contribution in https://github.com/yogeshojha/rengine/pull/1207
* @0xtejas made their first contribution in https://github.com/yogeshojha/rengine/pull/1227

**Full Changelog**: https://github.com/yogeshojha/rengine/compare/v2.0.3...v2.0.4


## 2.0.3

**Release Date: January 25, 2024**

## What's Changed
* CI: update GitHub action versions by @jxdv in https://github.com/yogeshojha/rengine/pull/1136
* Fixed (subdomain_discovery | ERROR | local variable 'use_amass_config' referenced before assignment) by @Deathpoolxrs in https://github.com/yogeshojha/rengine/pull/1149
* chore: update LICENSE by @jxdv in https://github.com/yogeshojha/rengine/pull/1153
* Fix subdomains list empty in Target by @psyray in https://github.com/yogeshojha/rengine/pull/1166
* Fix top menu text overflow in low resolution by @psyray in https://github.com/yogeshojha/rengine/pull/1167
* Update auto comment workflow due to deprecation warnings by @ErdemOzgen in https://github.com/yogeshojha/rengine/pull/1126
* Change Redirect URL after login to prevent 500 error by @psyray in https://github.com/yogeshojha/rengine/pull/1124
* fix-1030: Add missing slug on target summary link by @psyray in https://github.com/yogeshojha/rengine/pull/1123

### New Contributors
* @Deathpoolxrs made their first contribution in https://github.com/yogeshojha/rengine/pull/1149
* @ErdemOzgen made their first contribution in https://github.com/yogeshojha/rengine/pull/1126

**Full Changelog**: https://github.com/yogeshojha/rengine/compare/v2.0.2...v2.0.3


## 2.0.2

**Release Date: December 8, 2023**


## What's Changed
* Added tooltip text to dashboard total vulnerabilities tooltip by @luizmlo in https://github.com/yogeshojha/rengine/pull/1029
* ops(`uninstall.sh`): add missing volumes and echo messages by @AnonymousWP in https://github.com/yogeshojha/rengine/pull/977
* Fix no results in target subdomain list by @psyray in https://github.com/yogeshojha/rengine/pull/1036
* Fix Tool Settings Broken Link by @aqhmal in https://github.com/yogeshojha/rengine/pull/1021
* Fix subdomains list empty in Target by @psyray in https://github.com/yogeshojha/rengine/pull/1053
* Raise page limit to 500 for popup list by @psyray in https://github.com/yogeshojha/rengine/pull/1051
* Add directories count on Directories list by @psyray in https://github.com/yogeshojha/rengine/pull/1050
* ops(docker-compose): upgrade to 2.23.0 by @AnonymousWP in https://github.com/yogeshojha/rengine/pull/1023
* Fix endpoints list and count by @psyray in https://github.com/yogeshojha/rengine/pull/1041
* Fix failing visualization when dorks are present by @psyray in https://github.com/yogeshojha/rengine/pull/1045
* Fix note not saving by @psyray in https://github.com/yogeshojha/rengine/pull/1047
* Count only not done todos in subdomains list by @psyray in https://github.com/yogeshojha/rengine/pull/1048
* Fix user agent definition keyword by @psyray in https://github.com/yogeshojha/rengine/pull/1054
* Upgrade project discovery tool at CT build by @psyray in https://github.com/yogeshojha/rengine/pull/1055
* Add a check to not load datatables twice by @psyray in https://github.com/yogeshojha/rengine/pull/1039
* Nmap port scan fails when Naabu return no port by @psyray in https://github.com/yogeshojha/rengine/pull/1067
* chore(issue-templates): incorrect label name by @AnonymousWP in https://github.com/yogeshojha/rengine/pull/1066
* Endpoints list popup empty by @psyray in https://github.com/yogeshojha/rengine/pull/1070
* Add missing domain id value in subscan by @psyray in https://github.com/yogeshojha/rengine/pull/1069
* Fixes for #1033, #1026, #1027 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1071
* Temporary fix to prevent celery beat crash by @psyray in https://github.com/yogeshojha/rengine/pull/1072
* fix: ffuf ANSI code processing preventing task to finish by @ocervell in https://github.com/yogeshojha/rengine/pull/1058
* Update views.py by @Vijayragha1 in https://github.com/yogeshojha/rengine/pull/1074
* Fix crash on saving endpoint (FFUF related only) by @psyray in https://github.com/yogeshojha/rengine/pull/1063
* chore(issue-templates): fix incorrect description by @AnonymousWP in https://github.com/yogeshojha/rengine/pull/1078
* IOError -> OSError by @jxdv in https://github.com/yogeshojha/rengine/pull/1081
* Add directories count on Directories list by @psyray in https://github.com/yogeshojha/rengine/pull/1090
* chore(issue-template): don't allow blank issues by @AnonymousWP in https://github.com/yogeshojha/rengine/pull/1089
* Fix bad nuclei config name by @psyray in https://github.com/yogeshojha/rengine/pull/1098
* disallow empty password by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1105
* fix attribute error on scan history #1103 by @yogeshojha in https://github.com/yogeshojha/rengine/pull/1104
* issue-633: added already-in-org filter to target dropdown in org form by @SeanOverton in https://github.com/yogeshojha/rengine/pull/1106
* Update Dockerfile to fix silicon incompatability by @SubGlitch1 in https://github.com/yogeshojha/rengine/pull/1107
* Add source for nmap scan by @psyray in https://github.com/yogeshojha/rengine/pull/1108
* Spelling mistake in hackerone.html by @Linuxinet in https://github.com/yogeshojha/rengine/pull/1112
* fix(version): incorrect number in art by @AnonymousWP in https://github.com/yogeshojha/rengine/pull/1111
* Fix report generation when `Ignore Informational Vulnerabilities` checked by @psyray in https://github.com/yogeshojha/rengine/pull/1100
* fix(tool_arsenal): incorrect regex version numbers by @AnonymousWP in https://github.com/yogeshojha/rengine/pull/1086

### New Contributors
* @luizmlo made their first contribution in https://github.com/yogeshojha/rengine/pull/1029 :partying_face: 
* @aqhmal made their first contribution in https://github.com/yogeshojha/rengine/pull/1021 :partying_face: 
* @C0wnuts made their first contribution in https://github.com/yogeshojha/rengine/pull/973 :partying_face: 
* @ocervell made their first contribution in https://github.com/yogeshojha/rengine/pull/1058 :partying_face: 
* @Vijayragha1 made their first contribution in https://github.com/yogeshojha/rengine/pull/1074 :partying_face: 
* @jxdv made their first contribution in https://github.com/yogeshojha/rengine/pull/1081 :partying_face: 
* @SeanOverton made their first contribution in https://github.com/yogeshojha/rengine/pull/1106 :partying_face: 
* @SubGlitch1 made their first contribution in https://github.com/yogeshojha/rengine/pull/1107 :partying_face: 
* @Linuxinet made their first contribution in https://github.com/yogeshojha/rengine/pull/1112 :partying_face: 

**Full Changelog**: https://github.com/yogeshojha/rengine/compare/v2.0.1...v2.0.2

Once again excellent work on reNgine v2.0.2 by @AnonymousWP, @psyray, @ocervell and everybody else! :rocket: 

## 2.0.1

**Release Date: October 24, 2023**


2.0.1 fixes a ton of issues in reNgine 2.0.

Fixes: 
1. Prevent duplicating Nuclei vulns for subdomain #1012 @psyray
2. Fixes for empty subdomain returned during nuclei scan #1011 @psyray
3. Add all the missing slug in scanEngine view & other places #1005 @psyray
4. Foxes for missing vulscan script #1004 @psyray
5. Fixes for missing slug in report settings saving #1003
6. Fixes for Nmap Parsing Error #1001 #1002 @psyray
7. Fix nmap script ports iterable args #1000 @psyray
8. Iterate over hostnames when multiple #1002 @psyray
8. Gau install #998, change gauplus to gau @psyray
9. Add missing slug parameter in schedule scan #996 @psyray
10. Add missing slug parameter in schedule scan #996, fixes #940, #937, #897, #764 @psyray
11. Add stack trace into make logs if DEBUG True #994 @psyray
12. Fix dirfuzz base64 name display #993 #992 @psyray
13. Fix target subdomains list not loading #991 @psyray
14. Change WORDLIST constant value #987, fixes #986@psyray 
15. fix(notification_settings): submitting results in error 502 #981 fixes #970 @psyray
16. Fixes with documentation and installation/update/uninstall scripts @anonymousWP
17. Fix file directory popup not showing in detailed scan #912 @psyray


@AnonymousWP and @psyray have been phenomenal in fixing these bugs. Thanks to both of you! :heart: :rocket: 


## 2.0.0

**Release Date: October 7, 2023**

###  Added
 - Projects: Projects allow you to efficiently organize their web application reconnaissance efforts. With this feature, you can create distinct project spaces, each tailored to a specific purpose, such as personal bug bounty hunting, client engagements, or any other specialized recon task.
 - Roles and Permissions: assign distinct roles to your team members: Sys Admin, Penetration Tester, and Auditor—each with precisely defined permissions to tailor their access and actions within the reNgine ecosystem.
 - GPT-powered Report Generation: With the power of OpenAI's GPT, reNgine now provides you with detailed vulnerability descriptions, remediation strategies, and impact assessments.
 - API Vault: This feature allows you to organize your API keys such as OpenAI or Netlas API keys.
 - GPT-powered Attack Surface Generation
 - URL gathering now is much more efficient, removing duplicate endpoints based on similar HTTP Responses, having the same content_lenth, or page_title. Custom duplicate fields can also be set from the scan engine configuration.
 - URL Path filtering while initiating scan: For instance, if we want to scan only endpoints starting with https://example.com/start/, we can pass the /start as a path filter while starting the scan. [@ocervell](https://github.com/ocervell)
 - Expanding Target Concept: reNgine 2.0 now accepts IPs, URLS, etc as targets. (#678, #658) Excellent work by [@ocervell](https://github.com/ocervell)
 - A ton of refactoring on reNgine's core to improve scan efficiency. Massive kudos to [@ocervell](https://github.com/ocervell)
 - Created a custom celery workflow to be able to run several tasks in parallel that are not dependent on each other, such OSINT task and subdomain discovery will run in parallel, and directory and file fuzzing, vulnerability scan, screenshot gathering etc. will run in parallel after port scan or url fetching is completed. This will increase the efficiency of scans and instead of having one long flow of tasks, they can run independently on their own. [@ocervell](https://github.com/ocervell)
 - Refactored all tasks to run asynchronously [@ocervell](https://github.com/ocervell)
 - Added a stream_command that allows to read the output of a command live: this means the UI is updated with results while the command runs and does not have to wait until the task completes. Excellent work by [@ocervell](https://github.com/ocervell)
 - Pwndb is now replaced by h8mail. [@ocervell](https://github.com/ocervell)
 - Group Scan Results: reNgine 2.0 allows to group of subdomains based on similar page titles and HTTP status, and also vulnerability grouping based on the same vulnerability title and severity.
 - Added Support for Nmap: reNgine 2.0 allows to run Nmap scripts and vuln scans on ports found by Naabu. [@ocervell](https://github.com/ocervell)
 - Added support for Shared Scan Variables in Scan Engine Configuration:
    - `enable_http_crawl`: (true/false) You can disable it to be more stealthy or focus on something different than HTTP
    - `timeout`: set timeout for all tasks
    - `rate_limit`: set rate limit for all tasks
    - `retries`: set retries for all tasks
    - `custom_header`: set the custom header for all tasks
 - Added Dalfox for XSS Vulnerability Scan
 - Added CRLFuzz for CRLF Vulnerability Scan
 - Added S3Scanner for scanning misconfigured S3 buckets
 - Improve OSINT Dork results, now detects admin panels, login pages and dashboards
 - Added Custom Dorks
 - Improved UI for vulnerability results, clicking on each vulnerability will open up a sidebar with vulnerability details.
 - Added HTTP Request and Response in vulnerability Results
 - Under Admin Settings, added an option to allow add/remove/deactivate additional users
 - Added Option to Preview Scan Report instead of forcing to download
 - Added Katana for crawling and spidering URLs
 - Added Netlas for Whois and subdomain gathering
 - Added TLSX for subdomain gathering
 - Added CTFR for subdomain gathering
 - Added historical IP in whois section
 - Added Pagination on Large datatables such as subdomains, endpoints, vulnerabilities etc #949 [@psyray](https://github.com/psyray)


### Fixes
 - GF patterns do not run on 404 endpoints (#574 closed)
 - Fixes for retrieving whois data (#693 closed)
 - Related/Associated Domains in Whois section is now fixed
 - Fixed missing lightbox css & js on target screenshot page #947 #948 [@psyray](https://github.com/psyray)
 - Issue in Port-scan: int object is not subscriptable Fixed #939, #938 [@AnonymousWP](https://github.com/AnonymousWP)


### Removed
 - Removed pwndb and tor related to it.
 - Removed tor for pwndb


## 1.3.6
**Release Date: March 2, 2023**

- Fixed installation errors. Fixed #824, #823, #816, #809, #803, #801, #798, #797, #794, #791 .


## 1.3.5
**Release Date: December 29, 2022**

- Fixed #769, #768, #766, #761, Thanks to, @bin-maker, @carsonchan12345, @paweloque, @opabravo


## 1.3.4
**Release Date: November 16, 2022**

### Fixes
- Fixed #748 , #743 , #738, #739


## 1.3.3
**Release Date: October 9, 2022**

### Fixes
- #723, Upgraded Go to 1.18.2


## 1.3.2
**Release Date: August 20, 2022**

### Fixes
- #683 For Filtering GF tags
- #669 Where Directory UI had to be collapsed


## 1.3.1
**Release Date: August 12, 2022**

### Fixes
- Fix for #643 Downloading issue for Subdomain and Endpoints
- Fix for #627 Too many Targets causes issues while loading datatable
- Fix version Numbering issue


## 1.3.0
**Release Date: July 11, 2022**

### Added

- Geographic Distribution of Assets Map
- Added WAF Detector as an optional tool in Scan Engine

### Fixes

- WHOIS Provider Changed
- Fixed Dark UI Issues
- Fix HTTPX Issue with custom Header

## 1.2.0
**Release Date: May 27, 2022**

### Added

- Naabu Exclude CDN Port Scanning
- Added WAF Detection

### Fixes

- Fix #630 Character Name too Long Issue
- [Security] Fixed several instances of Command Injections, CVE-2022-28995, CVE-2022-1813
- Hakrawler Fixed - #623
- Fixed XSS on Hackerone report via Markdown
- Fixed XSS on Import Target using malicious filename
- Stop Scan Fixed #561
- Fix installation issue due to missing curl
- Updated docker-compose version

## 🏷️ 1.1.0
**Release Date: Apr 24, 2022**

- Redeigned UI
- Added Subscan Feature

    Subscan allows further scanning any subdomains. Assume from a normal recon process you identified a subdomain that you wish to do port scan. Earlier, you had to add that subdomain as a target. Now you can just select the subdomain and initiate subscan.

- Ability to Download reconnaissance or vulnerability report
- Added option to customize report, customization includes the look and feel of report, executive summary etc.

- Add IP Address from IP
- WHOIS Addition on Detail Scan and fetch whois automatically on Adding Single Targets
- Universal Search Box
- Addition of Quick Add menus
- Added ToolBox Feature

    ToolBox will feature most commonly used recon tools. One can use these tools to identify whois, CMSDetection etc without adding targets. Currently, Whois, CMSDetector and CVE ID lookup is supported. More tools to follow up.

- Notify New Releases on reNgine if available
- Tools Arsenal Section to feature preinstalled and custom tools
- Ability to Update preinstalled tools from Tools Arsenal Section
- Ability to download/add custom tools
- Added option for Custom Header on Scan Engine
- Added CVE_ID, CWE_ID, CVSS Score, CVSS Metrics on Vulnerability Section, this also includes lookup using cve_id, cwe_id, cvss_score etc
- Added curl command and references on Vulnerability Section
- Added Columns Filtering Option on Subdomain, Vulnerability and Endpoints Tables
- Added Error Handling for Failed Scans, reason for failure scan will be displayed
- Added Related Domains using WHOIS
- Added Related TLDs
- Added HTTP Status Breakdown Widget
- Added CMS Detector
- Updated Visualization
- Option to Download Selected Subdomains
- Added additional Nuclei Templates from https://github.com/geeknik/the-nuclei-templates
- Added SSRF check from Nagli Nuclei Template
- Added option to fetch CVE_ID details
- Added option to Delete Multiple Scans
- Added ffuf as Directory and Files fuzzer
- Added widgets such as Most vulnerable Targets, Most Common Vulnerabilities, Most Common CVE IDs, Most Common CWE IDs, Most Common Vulnerability Tags

And more...

## 🏷️ 1.0.1

**Release Date: Aug 29, 2021**

**Changelog**

- Fixed [#482](https://github.com/yogeshojha/rengine/issues/482) Endpoints and Vulnerability Datatable were showing results of other targets due to the scan_id parameter
- Fixed [#479](https://github.com/yogeshojha/rengine/issues/479) where the scan was failing due to recent httpx release, change was in the JSON output
- Fixed [#476](https://github.com/yogeshojha/rengine/issues/476) where users were unable to click on Clocked Scan (Reported only on Firefox)
- Fixed [#442](https://github.com/yogeshojha/rengine/issues/442) where an extra slash was added in Directory URLs
- Fixed [#337](https://github.com/yogeshojha/rengine/issues/337) where users were unable to link custom wordlist
- Fixed [#436](https://github.com/yogeshojha/rengine/issues/436) Checkbox in Notification Settings were not working due to same name attribute, now fixed
- Fixed [#439](https://github.com/yogeshojha/rengine/issues/439) Hakrawler crashed if the deep mode was activated due to -plain flag
- Fixed [#437](https://github.com/yogeshojha/rengine/issues/437) If Out of Scope subdomains were supplied, the scan was failing due to None value
- Fixed [#424](https://github.com/yogeshojha/rengine/issues/424) Multiple Targets couldn't be scanned

**Improvements**

- Enhanced install script, check for if docker is running service or not #468

**Security**

- Fixed Cross Site Scripting
    - [#460](https://github.com/yogeshojha/rengine/issues/460)
    - [#457](https://github.com/yogeshojha/rengine/issues/457)
    - [#454](https://github.com/yogeshojha/rengine/issues/454)
    - [#453](https://github.com/yogeshojha/rengine/issues/453)
    - [#459](https://github.com/yogeshojha/rengine/issues/459)
    - [#460](https://github.com/yogeshojha/rengine/issues/460)
- Fixed Cross Site Scripting reported on Huntr [#478](https://github.com/yogeshojha/rengine/issues/478)
    [https://www.huntr.dev/bounties/ac07ae2a-1335-4dca-8d55-64adf720bafb/](https://www.huntr.dev/bounties/ac07ae2a-1335-4dca-8d55-64adf720bafb/)

### Verion 1.0 Major release

### Additions
- Dark Mode
- Recon Data visualization
- Improved correlation among recon data
- Ability to identify Interesting Subdomains
- Ability to Automatically report Vulnerabilities to Hackerone with customizable vulnerability report
- Added option to download URLs and Endpoints along with matched GF patterns
- Dorking support for stackoverflow, 3rdparty, social_media, project_management, code_sharing, config_files, jenkins, wordpress_files, cloud_buckets, php_error, exposed_documents, struts_rce, db_files, traefik, git_exposed
- Emails, metainfo, employees, leaked password discovery
- Optin to Add bulk targets
- Proxy Support
- Target Summary
- Recon Todo
- Unusual Port Identification
- GF patterns support #110, #88
- Screenshot Gallery with Filters
- Powerful recon data filtering with auto suggestions
- Added whatportis, this allows ports to be displayed as Service Name and Description
- Recon Data changes, finds new/removed subdomains/endpoints
- Tagging of targets into Organization
- Added option to delete all scan results or delete all screenshots inside Settings and reNgine settings
- Support for custom GF patterns and Nuclei Templates
- Support for editing tool related configuration files (Nuclei, Subfinder, Naabu, amass)
- Option to Mark Subdomains as important
- Separate tab for Directory scan results
- Option to Import Subdomains
- Clean your scan results and screenshots
- Enhanced and Customizable Scan alert with support for sending recon data directly to Discord
- Improvement in Vulnerability Scanning, If endpoint scan is performed, those endpoints will be an input to Nuclei.
- Ignore file extensions in URLs
- Added response time in endpoints and subdomains
- Added badge to identify CDN and non CDN IPs
- Added gospider, gauplus and waybackurls for url discovery
- Added activity log in Scan activity
- For better UX shifted nav bar from vertical position to horizontal position on top. This allows better navigation on recon data.
- Separate table for Directory scan results #244
- Scan results UI now in tabs
- Added badge on Subdomain Result table to directly query Vulnerability and Endpoints
- Webserver and content_type badge has been addeed in Subdomain Result table
- Inside Targets list, Recent Scan button has been added to quickly go to the last scan results
- In target summary, timelin of scan has been added
- Randomized user agent in HTTPX
- reNgine will no longer store any recon data apart from that in Database, this includes sorted_subdomains list.txt or any json file
- aquatone has been replaced with Eyewitness
- Out of Scope subdomains are no longer part of scan engine, they can be imported before initiating the scan
- Added script to uninstall reNgine
- Added option to filter targets and scans using organization, scan status, etc
- Added random user agent in directory scan
- Added concurrency, rate limit, timeout, retries in Scan Engine YAML
- Added Rescan option
- Other tiny fixes.....

### V0.5.3 Feb25 2021
- Build error for Naabu v2 Fixed
- Added rate support for Naabu

### V0.5.2 Feb 23 2021
- Fixed XSS https://github.com/yogeshojha/rengine/issues/347

### V0.5.1 Feb 19 2021

### Features
- Added Discord Support for Notification Web hooks

### V0.5 29 Nov 2020

### Features
- Nuclei Integration: v0.5 is primarily focused on vulnerability scanner using Nuclei. This was a long pending due and we've finally integrated it.

- Powerful search queries across endpoints, subdomains and vulnerability scan results: reNgine reconnaissance data can now be queried using operators like <,>,&,| and !, namely greater than, less than, and, or, and not. This is extremely useful in querying the recon data. More details can be found at Instructions to perform Queries on Recon data

- Out of scope options: Many of you have been asking for out of scope option. Thanks to Valerio Brussani for his pull request which made it possible for out of scope options. Please check the documentation on how to define out of scope options.

- Official Documentation(WIP): We often get asked on how to use reNgine. For long, we had no official documentation. Finally, I've worked on it and we have the official documentation at rengine.wiki

- The documentation is divided into two parts, for Developers and for Penetration Testers. For developers, it's a work in progress. I will keep you all updated throughout the process.

- Redefined Dashboard: We've also made some changes in the Dashboard. The additions include vulnerability scan results, most vulnerable targets, most common vulnerabilities.

- Global Search: This feature has been one of the most requested features for reNgine. Now you can search all the subdomains, endpoints, and vulnerabilities.

- OneForAll Support: reNgine now supports OneForAll for subdomain discovery, it is currently in beta. I am working on how to integrate OneForAll APIKeys and Configuration files.

- Configuration Support for subfinder: You will now have ability to add configurations for subfinder as well.

- Timeout option for aquatone: We added timeout options in yaml configuration as a lot of screenshots were missing. You can now define timeout for http, scan and screenshots for timeout in milliseconds.

- Design Changes A lot of design changes has happened in reNgine. Some of which are:

- Endpoints Results and Vulnerability Scan Results are now displayed as a separate page, this is to separate the results and decrease the page load time.
Checkbox next to Subdomains and Vulnerability report list to change the status, this allows you to mark all subdomains and vulnerabilities that you've already completed working on.
- Sometimes due to timeout, aquatone was skipping the screenshots and due to that, navigations between screenshots was little annoying. We have fixed it as well.
Ability to delete multiple targets and initiate multiple scans.

### Abandoned
- Subdomain Takeover: As we decided to use Nuclei for Vulnerability Scanner, and also, since Subjack wasn't giving enough results, I decided to remove Subjack. The subdomain Takeover will now be part of Nuclei Vulnerability Scanner.

### V0.4 Release 2020-10-08

### Features
- Background tasks migrated to Celery and redis
- Periodic and clocked scan added
- Ability to Stop and delete the scan
- CNAME and IP address added on detail scan
- Content type added on Endpoints section
- Ability to initiate multiple scans at a time

### V0.3 Release 2020-07-21

### Features
- YAML based Customization Engine
- Ability to add wordlists
- Login Feature

### V0.2 Release 2020-07-11

### Features
- Directory Search Enabled
- Fetch URLS using hakrawler
- Subdomain takeover using Subjack
- Add Bulk urls
- Delete Scan functionality

### Fix
- Windows Installation issue fixed
- Scrollbar Issue on small screens fixed

### V0.1 Release 2020-07-08
- reNgine is released
