"""Secret scanning of downloaded sensitive files (gitleaks, trufflehog, betterleaks, semgrep).

Split out of the former reNgine/tasks/osint.py; re-exported by
reNgine.tasks.osint for backward compatibility.
"""
import logging
import math
import shutil
import subprocess
import json
import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from reNgine.common_func import *  # noqa: F401,F403
from reNgine.definitions import *  # noqa: F401,F403
from startScan.models import *  # noqa: F401,F403
from reNgine.tasks.persistence import save_secret_leak
from reNgine.tasks.vuln import semgrep_scan

logger = logging.getLogger(__name__)

# Distinctive CLI help/usage phrases only — avoid broad substrings like
# ``BETTERLEAKS_`` / ``--hmac-key`` that can appear in real secret values.
_BETTERLEAKS_HELP_MARKERS = (
	'betterleaks scans code, past or present, for secrets',
	'hmac fingerprint key; overrides',
	'redact secrets in findings, including report',
	'download and scan one http(s) url for secrets',
	'scan git repositories for secrets',
	'scan github repositories and resources for secrets',
	'scan gitlab projects and resources for secrets',
	'scan an s3 or s3-compatible bucket for secrets',
	'detect secrets from stdin',
	'validate a known secret without running detection',
)


def _betterleaks_text_is_noise(value: str) -> bool:
	"""Return True when a match string looks like betterleaks CLI help/usage."""
	if not value or not str(value).strip():
		return True
	lower = str(value).lower().strip()
	# Exact/near-exact help lines from the CLI banner (not env-var prefixes).
	if any(marker in lower for marker in _BETTERLEAKS_HELP_MARKERS):
		return True
	# Short leftover fragments from the help dump that are not secrets.
	if lower in {'for secrets.', 'or hmac-sha-256 with a key).'}:
		return True
	return False


def _betterleaks_output_looks_like_help(combined: str) -> bool:
	"""True when tool stdout/stderr is CLI help rather than a scan report."""
	if not combined or not combined.strip():
		return False
	lower = combined.lower()
	if 'usage:' in lower or 'betterleaks scans code' in lower:
		return True
	return _betterleaks_text_is_noise(combined)

def _extract_betterleaks_findings(report) -> list:
	"""Normalize a betterleaks JSON report into a list of finding dicts."""
	if isinstance(report, list):
		return [f for f in report if isinstance(f, dict)]
	if isinstance(report, dict):
		findings = report.get('findings')
		if isinstance(findings, list):
			return [f for f in findings if isinstance(f, dict)]
	return []


def persist_betterleaks_report(scan_history, report) -> int:
	"""Persist structured betterleaks findings; skip help/usage-shaped values.

	Returns the number of SecretLeak rows attempted (created or existing).
	"""
	saved = 0
	for finding in _extract_betterleaks_findings(report):
		match = finding.get('match') if isinstance(finding.get('match'), dict) else {}
		match_content = (
			match.get('value')
			or match.get('full')
			or finding.get('Secret')
			or finding.get('Match')
			or ''
		)
		if _betterleaks_text_is_noise(match_content):
			continue
		location = finding.get('location') if isinstance(finding.get('location'), dict) else {}
		source_url = (
			location.get('path')
			or finding.get('File')
			or finding.get('file')
			or 'Unknown'
		)
		secret_type = (
			finding.get('rule_id')
			or finding.get('RuleID')
			or finding.get('description')
			or finding.get('Description')
			or 'Potential Secret'
		)
		save_secret_leak(
			scan_history=scan_history,
			tool_name=BETTERLEAKS,
			secret_type=str(secret_type)[:255],
			source_url=str(source_url)[:2048],
			match_content=str(match_content),
			status='unverified',
		)
		saved += 1
	return saved


def run_betterleaks_scan(scan_history, temp_dir) -> int:
	"""Run betterleaks filesystem scan and persist JSON findings.

	Uses ``betterleaks fs`` with a JSON report file. Persists nothing when the
	report is missing or invalid (e.g. CLI help printed instead of a scan).
	"""
	report_path = os.path.join(temp_dir, 'betterleaks_report.json')
	logger.info('Running Betterleaks on %s', temp_dir)
	process = subprocess.Popen(
		[
			'betterleaks',
			'--no-banner',
			'--silent',
			'fs',
			temp_dir,
			'--output',
			report_path,
		],
		shell=False,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		text=True,
	)
	stdout, stderr = process.communicate()
	if process.returncode not in (0, 1):
		logger.warning(
			'Betterleaks exited with code %s (stdout=%r stderr=%r)',
			process.returncode,
			(stdout or '')[:500],
			(stderr or '')[:500],
		)
	if not os.path.exists(report_path):
		combined = f'{stdout or ""}\n{stderr or ""}'
		if _betterleaks_output_looks_like_help(combined):
			logger.warning('Betterleaks produced no JSON report (likely help/usage); skipping persist')
		else:
			logger.warning('Betterleaks report missing at %s; skipping persist', report_path)
		return 0
	try:
		with open(report_path, 'r', encoding='utf-8') as f:
			report = json.load(f)
	except (OSError, json.JSONDecodeError) as e:
		logger.error('Error parsing Betterleaks report: %s', e)
		return 0
	return persist_betterleaks_report(scan_history, report)

def secret_scanning(self, config=None, host=None, ctx=None, **kwargs):
    """Scan for secrets in JS files and potentially other sources.

    Args:
            config (dict, optional): Leaks and secrets configuration dictionary.
            host (str, optional): Target hostname.
            ctx (dict, optional): Scan activity context.
    """
    if not self.scan:
        return "No scan history found."

    if config is None:
        config = (
            self.yaml_configuration.get("secret_scanning")
            or self.yaml_configuration.get("leaks_and_secrets")
            or self.yaml_configuration.get("osint", {}).get("leaks_and_secrets")
            or {}
        )

    ctx = ctx or {}
    endpoints = EndPoint.objects.filter(scan_history=self.scan)
    if ctx.get('subdomain_id'):
        endpoints = endpoints.filter(subdomain_id=ctx['subdomain_id'])
    elif ctx.get('singular_tool_run') and ctx.get('subdomain_name'):
        endpoints = endpoints.filter(subdomain__name=ctx['subdomain_name'])
    # Sensitive extensions to scan
    SENSITIVE_EXTENSIONS = (
        ".js",
        ".env",
        ".php",
        ".asp",
        ".aspx",
        ".jsp",
        ".jspx",
        ".txt",
        ".log",
        ".conf",
        ".config",
        ".bak",
        ".old",
        ".json",
        ".yaml",
        ".yml",
    )
    target_endpoints = [
        e for e in endpoints if e.http_url.lower().endswith(SENSITIVE_EXTENSIONS)
    ]

    if not target_endpoints:
        return "No sensitive files found to scan."

    # Cap at 70% to bound download time on large scans.
    total_found = len(target_endpoints)
    cap = max(1, math.ceil(total_found * 0.70))
    target_endpoints = target_endpoints[:cap]
    logger.info(
        "secret_scanning: downloading %d / %d sensitive endpoints (70%% cap)",
        cap,
        total_found,
    )

    temp_dir = f"{self.results_dir}/secrets_temp"
    os.makedirs(temp_dir, exist_ok=True)

    def _download_one(js):
        filename = "".join([c if c.isalnum() else "_" for c in js.http_url]) + ".js"
        filepath = os.path.join(temp_dir, filename)
        try:
            resp = requests.get(js.http_url, timeout=10, verify=False)
            if resp.status_code == 200:
                with open(filepath, "w") as f:
                    f.write(resp.text)
        except Exception as e:
            logger.error("Failed to download %s: %s", js.http_url, e)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_download_one, js) for js in target_endpoints]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error("Download thread error: %s", e)

    findings_count = 0

    # Run Gitleaks
    if config.get(GITLEAKS):
        report_path = f"{temp_dir}/gitleaks_report.json"
        # Gitleaks v8+ detect command
        subprocess.run(
            [
                "gitleaks",
                "detect",
                "--source",
                temp_dir,
                "--report-format",
                "json",
                "--report-path",
                report_path,
                "--exit-code",
                "0",
            ],
            check=False,
        )

        if os.path.exists(report_path):
            try:
                with open(report_path, "r") as f:
                    findings = json.load(f)
                    for finding in findings:
                        # Map finding to SecretLeak
                        save_secret_leak(
                            scan_history=self.scan,
                            tool_name=GITLEAKS,
                            secret_type=finding.get("Description", "Secret"),
                            source_url=finding.get("File", "Unknown"),
                            match_content=finding.get("Secret", ""),
                            status="unverified",
                        )
                        findings_count += 1
            except Exception as e:
                logger.error("Error parsing Gitleaks report: %s", e)

    # Run Trufflehog
    if config.get(TRUFFLEHOG):
        # Trufflehog v3 filesystem command
        process = subprocess.Popen(
            ["trufflehog", "filesystem", temp_dir, "--json"],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()

        for line in stdout.decode().splitlines():
            if not line:
                continue
            try:
                finding = json.loads(line)
                # Trufflehog v3 output format varies, but usually has 'SourceMetadata' or 'DetectorName'
                save_secret_leak(
                    scan_history=self.scan,
                    tool_name=TRUFFLEHOG,
                    secret_type=finding.get("DetectorName", "Secret"),
                    source_url=finding.get("SourceMetadata", {})
                    .get("Data", {})
                    .get("Filesystem", {})
                    .get("file", "Unknown"),
                    match_content=finding.get("Raw", ""),
                    status="unverified",
                )
                findings_count += 1
            except Exception as e:
                logger.error("Error parsing Trufflehog finding: %s", e)

    # Run Betterleaks (structured JSON report — never keyword-match CLI help)
    if config.get(BETTERLEAKS):
        findings_count += run_betterleaks_scan(self.scan, temp_dir)

    # Run Semgrep Secret Scan (Default)
    try:
        logger.info("Running Semgrep Secret Scan...")
        semgrep_scan(self, ctx=ctx, mode="secret", description="Semgrep Secret Scan")
    except Exception as e:
        logger.error("Semgrep secret scan failed: %s", e)

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)

    return f"Secret scanning completed. Found {findings_count} findings."
