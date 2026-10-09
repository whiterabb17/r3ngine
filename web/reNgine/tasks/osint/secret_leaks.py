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

    # Run Betterleaks
    if config.get(BETTERLEAKS):
        # Betterleaks is typically run against files or a directory
        # It's good for finding secrets like API keys, passwords, etc.
        # Command: betterleaks -p {temp_dir}
        logger.info("Running Betterleaks on %s", temp_dir)
        process = subprocess.Popen(
            ["betterleaks", "-p", temp_dir],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate()
        logger.info("Betterleaks output: %s", stdout)
        for line in stdout.splitlines():
            if line.strip():
                # Assuming betterleaks outputs findings in a recognizable format
                # For now, let's just log it and save if it looks like a finding
                if any(
                    keyword in line.lower()
                    for keyword in ["key", "password", "secret", "token", "found"]
                ):
                    save_secret_leak(
                        scan_history=self.scan,
                        tool_name=BETTERLEAKS,
                        secret_type="Potential Secret",
                        source_url="Discovered Files",
                        match_content=line.strip(),
                        status="unverified",
                    )
                    findings_count += 1

    # Run Semgrep Secret Scan (Default)
    try:
        logger.info("Running Semgrep Secret Scan...")
        semgrep_scan(self, ctx=ctx, mode="secret", description="Semgrep Secret Scan")
    except Exception as e:
        logger.error("Semgrep secret scan failed: %s", e)

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)

    return f"Secret scanning completed. Found {findings_count} findings."
