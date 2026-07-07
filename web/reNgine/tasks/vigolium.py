import json
import logging
import os
import shlex
import subprocess
import tempfile

from reNgine.definitions import (
    ANTHROPIC,
    NUCLEI_SEVERITY_MAP,
    OPENAI,
    RUN_VIGOLIUM,
    RUN_VIGOLIUM_ANALYSIS,
    RUN_VIGOLIUM_AUDIT,
    RUN_VIGOLIUM_DISCOVERY,
    RUN_VIGOLIUM_HARVEST,
    VIGOLIUM,
    VIGOLIUM_AUDIT,
    VIGOLIUM_AUDIT_INTENSITY,
    VIGOLIUM_AUDIT_TIMEOUT,
    VIGOLIUM_AUDIT_USE_AI,
    VIGOLIUM_CONCURRENCY,
    VIGOLIUM_HARVEST,
    VIGOLIUM_MODULES,
    VIGOLIUM_RATE_LIMIT,
    VIGOLIUM_SEVERITY_FILTER,
    VIGOLIUM_STRATEGY,
    VIGOLIUM_TIMEOUT,
    VULNERABILITY_SCAN,
)
from reNgine.common_func import get_random_proxy, save_vulnerability
from reNgine.utils.task import save_endpoint
from startScan.models import Subdomain

logger = logging.getLogger(__name__)


def _ensure_duration(value) -> str:
    """Return *value* as a Go duration string (e.g. '30s').

    Vigolium requires a unit suffix; bare integers from YAML configs are
    treated as seconds.
    """
    s = str(value).strip()
    if s and s[-1].isdigit():
        return s + 's'
    return s


def _iter_jsonl(output_file):
    """Yield parsed JSON objects from a vigolium JSONL output file."""
    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        return
    with open(output_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                logger.warning(f"vigolium: skipping non-JSON line: {line[:80]}")


def parse_vigolium_finding(task_instance, finding_data, subdomain):
    """Save a single vigolium finding record to the Vulnerability model.

    The JSONL finding schema (confirmed from live output):
      module_id   → template_id
      module_name → name
      severity    → string "critical"/"high"/"medium"/"low"/"info"
      matched_at  → list of URLs (use first; fall back to data.url)
      tags        → list or null
      request     → raw HTTP request string

    Args:
        task_instance: Temporal task proxy with scan context.
        finding_data (dict): Finding payload from Vigolium JSONL.
        subdomain (Subdomain): Associated Subdomain database object.
    """
    name = finding_data.get('module_name')
    if not name:
        return

    severity_str = (finding_data.get('severity') or 'info').lower()
    severity_num = NUCLEI_SEVERITY_MAP.get(severity_str, 0)

    # matched_at is a list; use first entry, fall back to url field
    matched_at = finding_data.get('matched_at') or []
    http_url = matched_at[0] if matched_at else finding_data.get('url', f"https://{subdomain.name}")

    tags = finding_data.get('tags') or []
    if isinstance(tags, str):
        tags = [tags]

    extracted = finding_data.get('extracted_results') or []
    if isinstance(extracted, str):
        extracted = [extracted]

    raw_cvss = finding_data.get('cvss_score')
    cvss_score = float(raw_cvss) if raw_cvss else None

    # Deduplicate on (name, scan_history, subdomain, http_url, template_id) so
    # findings emitted by multiple phases (ExternalHarvest, Spidering, Discovery,
    # KnownIssueScan, DynamicAssessment) within a single vigolium run, or by
    # vigolium_scan and vigolium_analysis running at different tiers, never
    # create separate database rows for the same underlying issue.
    save_vulnerability(
        target_domain=task_instance.domain,
        http_url=http_url,
        scan_history=task_instance.scan,
        subdomain=subdomain,
        name=name,
        severity=severity_num,
        description=finding_data.get('description', ''),
        type='Vigolium',
        template_id=finding_data.get('module_id', ''),
        curl_command='',
        request=finding_data.get('request', ''),
        response=finding_data.get('response', ''),
        extracted_results=extracted or None,
        cvss_score=cvss_score,
        tags=tags,
        cve_ids=[],
        references=[],
        source='Vigolium',
        dedup_fields=['name', 'scan_history', 'subdomain', 'http_url', 'template_id'],
    )


def parse_vigolium_http_record(task_instance, record_data):
    """Save a single vigolium http_record to the EndPoint model.

    Called for type='http_record' lines — vigolium discovered URLs
    that should populate the endpoint DB for downstream pipeline tiers.
    """
    url = record_data.get('url')
    if not url:
        return

    ctx = {
        'scan_history_id': task_instance.scan_id,
        'domain_id': getattr(task_instance, 'domain_id', None),
    }
    save_endpoint(
        http_url=url,
        ctx=ctx,
        crawl=False,
        is_default=False,
        http_status=record_data.get('status_code') or 0,
    )


def _run_vigolium_phase(task_instance, cmd, output_file, phase_label, save_http_records=False):
    """Execute a vigolium command, then parse and persist findings from the JSONL output.

    Args:
        task_instance: Temporal task proxy with scan context.
        cmd: Full vigolium command string.
        output_file: Path where vigolium writes its JSONL output.
        phase_label: Human-readable label for logging.
        save_http_records: If True, also save http_record entries as EndPoints.
    """
    from reNgine.tasks import stream_command

    logger.info(f"Running Vigolium {phase_label}")
    logger.warning(f"Command: {cmd}")

    for _ in stream_command(cmd, scan_id=task_instance.scan_id, activity_id=task_instance.activity_id):
        pass

    findings_saved = 0
    duplicates_skipped = 0
    endpoints_saved = 0

    # In-file deduplication: track (module_id, hostname, http_url) tuples seen
    # within this JSONL output.  This is especially important now that all 5
    # vigolium phases (ExternalHarvest, Spidering, Discovery, KnownIssueScan,
    # DynamicAssessment) run inside a single vigolium invocation — the same
    # module may fire across multiple phases against the same URL.
    seen_findings: set = set()

    for record in _iter_jsonl(output_file):
        record_type = record.get('type')
        data = record.get('data', {})

        if record_type == 'finding':
            hostname = data.get('hostname', '')

            # Build a fingerprint for in-file dedup
            matched_at = data.get('matched_at') or []
            http_url = matched_at[0] if matched_at else data.get('url', '')
            fingerprint = (
                data.get('module_id', '') or data.get('module_name', ''),
                hostname,
                http_url,
            )
            if fingerprint in seen_findings:
                duplicates_skipped += 1
                continue
            seen_findings.add(fingerprint)

            subdomain = Subdomain.objects.filter(
                scan_history=task_instance.scan, name=hostname
            ).first()
            if subdomain:
                parse_vigolium_finding(task_instance, data, subdomain)
                findings_saved += 1
            else:
                logger.warning(f"Vigolium {phase_label}: no subdomain found for '{hostname}', skipping finding.")

        elif record_type == 'http_record' and save_http_records:
            parse_vigolium_http_record(task_instance, data)
            endpoints_saved += 1

    logger.info(
        f"Vigolium {phase_label} complete — {findings_saved} findings saved, "
        f"{duplicates_skipped} in-file duplicates skipped, {endpoints_saved} endpoints saved"
    )


def vigolium_scan(self, urls=None, ctx={}, description=None):
    """Run vigolium known-issue + dynamic-assessment scan against discovered endpoints.

    Runs inside NucleiPlannerWorkflow at Tier 6 alongside nuclei. Reads from
    the passed URL list or falls back to get_http_urls() from the endpoint DB.
    """
    if urls is None:
        urls = []
    logger.info("Starting Vigolium Vulnerability Scan")

    vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN, {})
    if not vuln_config.get(RUN_VIGOLIUM, True):
        logger.info("Vigolium scan disabled in configuration. Skipping.")
        return

    vig_config = vuln_config.get(VIGOLIUM, {})
    strategy = vig_config.get(VIGOLIUM_STRATEGY, 'balanced')
    concurrency = vig_config.get(VIGOLIUM_CONCURRENCY, 50)
    rate_limit = vig_config.get(VIGOLIUM_RATE_LIMIT, 100)
    timeout = _ensure_duration(vig_config.get(VIGOLIUM_TIMEOUT, '300s'))
    modules = vig_config.get(VIGOLIUM_MODULES, [])
    severity_filter = vig_config.get(VIGOLIUM_SEVERITY_FILTER, [])

    if urls:
        target_urls = urls
    else:
        from reNgine.common_func import collect_all_scan_urls
        target_urls = collect_all_scan_urls(
            ctx={
                'scan_history_id': self.scan_id,
                'domain_id': getattr(self, 'domain_id', None),
            },
            results_dir=self.scan.results_dir if hasattr(self, 'scan') and self.scan else f"{RENGINE_HOME}/scan_results/{self.scan_id}",
            ignore_files=True
        )

    if not target_urls:
        if self.scan and self.scan.domain:
            target_urls = [f"https://{self.scan.domain.name}"]
        else:
            logger.warning("Vigolium scan: no targets found. Skipping.")
            return

    results_dir = f"{self.scan.results_dir}/vigolium/vuln"
    os.makedirs(results_dir, exist_ok=True)

    targets_file = f"{results_dir}/targets.txt"
    with open(targets_file, 'w') as f:
        for url in target_urls:
            f.write(f"{url}\n")

    output_file = f"{results_dir}/findings.jsonl"

    cmd = (
        f"vigolium scan"
        f" -T {targets_file}"
        f" --stateless"
        f" --format jsonl"
        f" --verbose"
        f" -o {output_file}"
        # f" --only known-issue-scan,dynamic-assessment"
        f" -c {concurrency}"
        f" -r {rate_limit}"
        f" --timeout {timeout}"
        f" --strategy {strategy}"
        f" --skip-dependency-check"
        f" --omit-response"
    )

    if modules:
        cmd += f" -m {','.join(modules)}"


    proxy = get_random_proxy()
    if proxy:
        cmd += f" --proxy {proxy}"

    _run_vigolium_phase(self, cmd, output_file, "Vulnerability Scan", save_http_records=False)
    return "Vigolium scan completed"


def vigolium_harvest(self, ctx={}, description=None):
    """Run vigolium passive ingestion harvest at Tier 1.

    Collects data from external passive sources (wayback, CT logs, passive DNS, etc.)
    using vigolium's ingestion phase only. Runs early in Tier 1 so that passively
    harvested endpoints seed the DB before active crawling begins.

    Works with just the root domain — does not require prior subdomain enumeration.
    Falls back to the root domain when no subdomains are present in the DB yet.
    """
    logger.info("Starting Vigolium Passive Harvest")

    harvest_config = self.yaml_configuration.get(VIGOLIUM_HARVEST, {})
    if not harvest_config.get(RUN_VIGOLIUM_HARVEST, True):
        logger.info("Vigolium harvest disabled in configuration. Skipping.")
        return

    strategy = harvest_config.get(VIGOLIUM_STRATEGY, 'balanced')
    concurrency = harvest_config.get(VIGOLIUM_CONCURRENCY, 30)
    rate_limit = harvest_config.get(VIGOLIUM_RATE_LIMIT, 100)
    timeout = _ensure_duration(harvest_config.get(VIGOLIUM_TIMEOUT, '60s'))

    if self.subscan and self.subdomain:
        target_hosts = [f"https://{self.subdomain.name}"]
    else:
        subdomains = list(Subdomain.objects.filter(scan_history=self.scan))
        if subdomains:
            target_hosts = [f"https://{s.name}" for s in subdomains]
        elif self.scan and self.scan.domain:
            target_hosts = [f"https://{self.scan.domain.name}"]
        else:
            logger.warning("Vigolium harvest: no targets available. Skipping.")
            return

    results_dir = f"{self.scan.results_dir}/vigolium/harvest"
    os.makedirs(results_dir, exist_ok=True)

    targets_file = f"{results_dir}/targets.txt"
    with open(targets_file, 'w') as f:
        for host in target_hosts:
            f.write(f"{host}\n")

    output_file = f"{results_dir}/harvest.jsonl"

    cmd = (
        f"vigolium scan"
        f" -T {targets_file}"
        f" --stateless"
        f" --format jsonl"
        f" -o {output_file}"
        f" --only ingestion"
        f" -c {concurrency}"
        f" -r {rate_limit}"
        f" --timeout {timeout}"
        f" --strategy {strategy}"
        f" --skip-dependency-check"
    )

    proxy = get_random_proxy()
    if proxy:
        cmd += f" --proxy {proxy}"

    _run_vigolium_phase(self, cmd, output_file, f"Harvest ({len(target_hosts)} targets)", save_http_records=True)
    return "Vigolium harvest completed"


def vigolium_discovery(self, ctx={}, description=None):
    """Run vigolium active discovery at Tier 1.

    Executes vigolium's discovery phase (active probing / crawling) against all
    known targets. Runs in Tier 1 in parallel with subdomain enumeration so that
    vigolium-discovered endpoints are available to http_crawl in Tier 2.

    Falls back to the root domain if no subdomains have been enumerated yet,
    ensuring the task is never a no-op early in a full scan.
    Saves http_records as EndPoint entries for downstream pipeline stages.
    """
    logger.info("Starting Vigolium Discovery")

    discovery_config = self.yaml_configuration.get('vigolium_discovery', {})
    if not discovery_config.get(RUN_VIGOLIUM_DISCOVERY, True):
        logger.info("Vigolium discovery disabled in configuration. Skipping.")
        return

    strategy = discovery_config.get(VIGOLIUM_STRATEGY, 'balanced')
    concurrency = discovery_config.get(VIGOLIUM_CONCURRENCY, 40)
    rate_limit = discovery_config.get(VIGOLIUM_RATE_LIMIT, 100)
    timeout = _ensure_duration(discovery_config.get(VIGOLIUM_TIMEOUT, '30s'))

    if self.subscan and self.subdomain:
        target_hosts = [f"https://{self.subdomain.name}"]
    else:
        subdomains = list(Subdomain.objects.filter(scan_history=self.scan))
        if subdomains:
            target_hosts = [f"https://{s.name}" for s in subdomains]
        elif self.scan and self.scan.domain:
            target_hosts = [f"https://{self.scan.domain.name}"]
        else:
            logger.warning("Vigolium discovery: no targets available. Skipping.")
            return

    results_dir = f"{self.scan.results_dir}/vigolium/discovery"
    os.makedirs(results_dir, exist_ok=True)

    targets_file = f"{results_dir}/targets.txt"
    with open(targets_file, 'w') as f:
        for host in target_hosts:
            f.write(f"{host}\n")

    output_file = f"{results_dir}/discovery.jsonl"

    cmd = (
        f"vigolium scan"
        f" -T {targets_file}"
        f" --stateless"
        f" --format jsonl"
        f" -o {output_file}"
        f" --only discovery"
        f" -c {concurrency}"
        f" -r {rate_limit}"
        f" --timeout {timeout}"
        f" --strategy {strategy}"
        f" --skip-dependency-check"
    )

    proxy = get_random_proxy()
    if proxy:
        cmd += f" --proxy {proxy}"

    _run_vigolium_phase(self, cmd, output_file, f"Discovery ({len(target_hosts)} targets)", save_http_records=True)

    return "Vigolium discovery completed"


def vigolium_analysis(self, ctx={}, description=None):
    """Run vigolium dynamic assessment for all subdomains in a single tool call.

    Passes all subdomain targets via -T (targets file) so vigolium handles
    concurrency internally rather than spawning one process per subdomain.
    Saves findings as Vulnerability records and discovered URLs as EndPoints.
    """
    logger.info("Starting Vigolium Dynamic Analysis")

    analysis_config = self.yaml_configuration.get('vigolium_analysis', {})
    if not analysis_config.get(RUN_VIGOLIUM_ANALYSIS, True):
        logger.info("Vigolium analysis disabled in configuration. Skipping.")
        return

    strategy = analysis_config.get(VIGOLIUM_STRATEGY, 'balanced')
    concurrency = analysis_config.get(VIGOLIUM_CONCURRENCY, 20)
    rate_limit = analysis_config.get(VIGOLIUM_RATE_LIMIT, 50)
    timeout = _ensure_duration(analysis_config.get(VIGOLIUM_TIMEOUT, '10s'))

    if self.subscan and self.subdomain:
        subdomains = list(Subdomain.objects.filter(pk=self.subdomain.id))
    else:
        subdomains = list(Subdomain.objects.filter(scan_history=self.scan))

    if not subdomains:
        logger.info("No subdomains found for Vigolium analysis.")
        return

    results_dir = f"{self.scan.results_dir}/vigolium/analysis"
    os.makedirs(results_dir, exist_ok=True)

    targets_file = f"{results_dir}/targets.txt"
    with open(targets_file, 'w') as f:
        for subdomain in subdomains:
            f.write(f"https://{subdomain.name}\n")

    output_file = f"{results_dir}/analysis.jsonl"

    cmd = (
        f"vigolium scan"
        f" -T {targets_file}"
        f" --stateless"
        f" --format jsonl"
        f" -o {output_file}"
        f" --only external-harvest,spidering,discovery,known-issue-scan,dynamic-assessment"
        f" -c {concurrency}"
        f" -r {rate_limit}"
        f" --timeout {timeout}"
        f" --strategy {strategy}"
        f" --skip-dependency-check"
        f" --omit-response"
    )

    proxy = get_random_proxy()
    if proxy:
        cmd += f" --proxy {proxy}"

    _run_vigolium_phase(self, cmd, output_file, f"Analysis ({len(subdomains)} targets)", save_http_records=True)

    return "Vigolium analysis completed"


def _parse_vigolium_audit_finding(task_instance, data: dict) -> None:
    """Save a single vigolium audit finding to the Vulnerability model.

    Used for findings from `vigolium export --only findings` JSONL output,
    which may lack a hostname (code-scan context, no live HTTP target).
    Falls back to `parse_vigolium_finding` when a matching subdomain exists.
    """
    name = data.get('module_name') or data.get('name')
    if not name:
        return

    hostname = data.get('hostname', '')
    subdomain = None
    if hostname and task_instance.scan:
        subdomain = Subdomain.objects.filter(
            scan_history=task_instance.scan, name=hostname
        ).first()

    if subdomain:
        parse_vigolium_finding(task_instance, data, subdomain)
        return

    severity_str = (data.get('severity') or 'info').lower()
    severity_num = NUCLEI_SEVERITY_MAP.get(severity_str, 0)

    matched_at = data.get('matched_at') or []
    file_path = data.get('file') or data.get('source') or ''
    line_no = data.get('line') or data.get('start_line') or 0
    # Prefer a file reference when no URL is present
    http_url = (matched_at[0] if matched_at else None) or (
        'file://%s#L%s' % (file_path, line_no) if file_path else ''
    )

    tags = data.get('tags') or []
    if isinstance(tags, str):
        tags = [tags]

    extracted = data.get('extracted_results') or []
    if isinstance(extracted, str):
        extracted = [extracted]

    raw_cvss = data.get('cvss_score')
    cvss_score = float(raw_cvss) if raw_cvss else None

    snippet = data.get('snippet') or data.get('request') or ''

    # Deduplicate on (name, scan_history, http_url, template_id) — subdomain may
    # be absent for code-scan findings, so we use the tightest key available.
    dedup = ['name', 'scan_history', 'http_url', 'template_id']
    if subdomain:
        dedup.append('subdomain')

    save_vulnerability(
        target_domain=task_instance.domain,
        http_url=http_url,
        scan_history=task_instance.scan,
        subdomain=subdomain,
        name=name,
        severity=severity_num,
        description=data.get('description', ''),
        type='VigoliumAudit',
        template_id=data.get('module_id', ''),
        curl_command='',
        request=snippet,
        response=data.get('response', ''),
        extracted_results=extracted or None,
        cvss_score=cvss_score,
        tags=tags,
        cve_ids=[],
        references=[],
        source='VigoliumAudit',
        dedup_fields=dedup,
    )


def vigolium_audit_scan(self, code_path=None, ctx={}, description=None):
    """Run vigolium audit (source code security audit) against a code path or git URL.

    Dispatched by CodeScanWorkflow. Uses piolium (built-in, no AI) by default.
    When vigolium_audit.use_ai is true, looks up the active LLMConfig and passes
    credentials to vigolium audit via --agent/--api-key; unsupported providers
    fall back to piolium silently.

    Findings are exported from a temporary vigolium SQLite database after the
    audit completes and saved as Vulnerability records (type='VigoliumAudit').
    """
    audit_config = self.yaml_configuration.get(VIGOLIUM_AUDIT, {})
    if not audit_config.get(RUN_VIGOLIUM_AUDIT, True):
        logger.info("Vigolium audit disabled in configuration. Skipping.")
        return "Vigolium audit skipped (disabled)"

    source = (
        code_path
        or getattr(self, 'starting_point_path', None)
        or (ctx.get('target') if ctx else None)
    )
    if not source:
        logger.error("Vigolium audit: no source path available, skipping.")
        return None

    _VALID_INTENSITIES = ('quick', 'balanced', 'deep')
    intensity = audit_config.get(VIGOLIUM_AUDIT_INTENSITY, 'balanced')
    if intensity not in _VALID_INTENSITIES:
        logger.warning("vigolium audit: unknown intensity '%s', defaulting to 'balanced'", intensity)
        intensity = 'balanced'
    use_ai = audit_config.get(VIGOLIUM_AUDIT_USE_AI, False)
    timeout_seconds = int(audit_config.get(VIGOLIUM_AUDIT_TIMEOUT, 3600))

    scan_id = getattr(self, 'scan_id', 'unknown')
    results_dir = f"{self.scan.results_dir}/vigolium/audit" if self.scan else '/tmp'
    os.makedirs(results_dir, exist_ok=True)

    temp_db = os.path.join(results_dir, 'vigolium-audit.sqlite')
    findings_file = os.path.join(results_dir, 'audit-findings.jsonl')

    cmd = [
        'vigolium', 'audit',
        '--source', source,
        '--db', temp_db,
        '--intensity', intensity,
        '--skip-dependency-check',
        '--no-preflight',
        '--no-stream',
        '--soft-fail',
    ]

    audit_env = dict(os.environ)

    if use_ai:
        from dashboard.models import LLMConfig
        llm_config = LLMConfig.objects.filter(is_active=True).first()
        if llm_config and llm_config.api_key:
            if llm_config.provider == ANTHROPIC:
                cmd += ['--driver', 'audit', '--agent', 'claude']
                audit_env['VIGOLIUM_API_KEY'] = llm_config.api_key
                logger.info("Vigolium audit: using Anthropic (Claude) as AI agent")
            elif llm_config.provider == OPENAI:
                cmd += ['--driver', 'audit', '--agent', 'codex']
                audit_env['VIGOLIUM_API_KEY'] = llm_config.api_key
                logger.info("Vigolium audit: using OpenAI (Codex) as AI agent")
            else:
                logger.warning("Vigolium audit: LLM provider '%s' not supported, falling back to piolium", llm_config.provider)
                cmd += ['--driver', 'piolium']
        else:
            logger.info("Vigolium audit: no active LLM config, falling back to piolium")
            cmd += ['--driver', 'piolium']
    else:
        cmd += ['--driver', 'piolium']

    logger.info("Starting Vigolium Audit: source=%s intensity=%s use_ai=%s scan_id=%s", source, intensity, use_ai, scan_id)
    _prev = ''
    safe_cmd = []
    for _tok in cmd:
        safe_cmd.append('***' if _prev == '--api-key' else _tok)
        _prev = _tok
    logger.warning("Command: %s", ' '.join(shlex.quote(c) for c in safe_cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds, env=audit_env)
        if proc.returncode != 0:
            logger.warning("Vigolium audit exited %s: %s", proc.returncode, proc.stderr[:500])
    except subprocess.TimeoutExpired:
        logger.warning("Vigolium audit timed out after %d seconds for scan_id=%s", timeout_seconds, scan_id)
        return "Vigolium audit timed out"
    except Exception as exc:
        logger.error("Vigolium audit failed to run: %s", exc)
        raise

    # Export findings from the temp database
    export_cmd = [
        'vigolium', 'export',
        '--db', temp_db,
        '--only', 'findings',
        '--format', 'jsonl',
        '--omit-response',
        '-o', findings_file,
    ]
    try:
        subprocess.run(export_cmd, capture_output=True, text=True, timeout=120)
    except Exception as exc:
        logger.warning("Vigolium audit: export failed: %s", exc)

    findings_saved = 0
    for record in _iter_jsonl(findings_file):
        # vigolium export uses the same {type, data} envelope as vigolium scan
        record_type = record.get('type')
        data = record.get('data', record)  # flat if no envelope
        if record_type and record_type != 'finding':
            continue
        _parse_vigolium_audit_finding(self, data)
        findings_saved += 1

    logger.info("Vigolium audit complete — %d findings saved for scan_id=%s", findings_saved, scan_id)

    try:
        if os.path.exists(temp_db):
            os.unlink(temp_db)
    except Exception:
        pass

    return "Vigolium audit completed"
