import logging
import os
import json
import shutil
from pathlib import Path

from reNgine.definitions import *
from reNgine.common_func import (
    save_vulnerability,
)
from startScan.models import EndPoint, Subdomain, Vulnerability
from reNgine.tasks import stream_command

logger = logging.getLogger(__name__)

# Maps taint-scan check_id values to (severity_str, canonical_name) tuples.
# Severity strings must match keys in NUCLEI_SEVERITY_MAP.
_CHECK_ID_MAP = {
    'path-transversal':                                   ('high',     'Path Traversal'),
    'request-path-read-delete':                           ('medium',   'Arbitrary File Read/Delete'),
    'tainted-sql-string':                                 ('high',     'SQL Injection (Tainted String)'),
    'unsafe-deserialization':                             ('critical', 'Unsafe Deserialization'),
    'wp-header-injection':                                ('medium',   'HTTP Header Injection'),
    'wp-open-redirect':                                   ('medium',   'Open Redirect'),
    'wp-reflected-xss-direct-request-output':             ('high',     'Reflected XSS'),
    'wp-request-file-upload-without-cap-check':           ('high',     'Unauthorized File Upload'),
    'wp-request-record-read-to-output-without-cap-check': ('medium',   'IDOR / Unauthorized Record Read'),
    'wp-request-sensitive-action-without-cap-check':      ('medium',   'Missing Capability Check'),
    'wp-stored-xss-persistent-read-to-output':            ('high',     'Stored XSS'),
}


def _check_id_to_severity_and_name(check_id):
    """Return (severity_str, canonical_name) for a taint-scan check_id."""
    if check_id in _CHECK_ID_MAP:
        return _CHECK_ID_MAP[check_id]
    # Fallback heuristic for unknown future rules
    lower = check_id.lower()
    if 'deserializ' in lower or 'rce' in lower:
        severity = 'critical'
    elif 'sql' in lower or 'xss' in lower or 'traversal' in lower or 'upload' in lower:
        severity = 'high'
    else:
        severity = 'medium'
    name = check_id.replace('-', ' ').title()
    return (severity, name)


def parse_wptaint_results(task_instance, output_file, subdomains, plugin_name):
    """
    Parses wp-taint-scan JSON output and saves vulnerabilities to the database.

    taint-scan emits: {"summary": {...}, "results": [...], "errors": null}
    Each result has: check_id, path, start.line, extra.message, extra.dataflow_trace
    """
    try:
        if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            return

        with open(output_file, 'r') as f:
            data = json.load(f)

        # taint-scan wraps results in a top-level dict
        findings = data.get('results', []) if isinstance(data, dict) else data
        if not findings:
            return

        from reNgine.definitions import NUCLEI_SEVERITY_MAP

        for finding in findings:
            if not isinstance(finding, dict):
                continue

            check_id = finding.get('check_id', 'unknown')
            severity_str, canonical_name = _check_id_to_severity_and_name(check_id)

            extra = finding.get('extra') or {}
            message = extra.get('message', '')

            description_parts = []
            if message:
                description_parts.append(message)

            file_path = finding.get('path', '')
            line = (finding.get('start') or {}).get('line')
            if file_path:
                file_line = '`%s`' % file_path
                if line:
                    file_line += ' (Line %d)' % line
                description_parts.append('**File**: ' + file_line)

            trace = extra.get('dataflow_trace') or {}
            source_snippet = (trace.get('source') or {}).get('snippet', '')
            sink_snippet = (trace.get('sink') or {}).get('snippet', '')
            if source_snippet:
                description_parts.append('**Source**:\n```php\n%s\n```' % source_snippet)
            if sink_snippet:
                description_parts.append('**Sink**:\n```php\n%s\n```' % sink_snippet)

            description = '\n\n'.join(description_parts)
            severity_num = NUCLEI_SEVERITY_MAP.get(severity_str, 3)

            for subdomain in subdomains:
                vuln, created = save_vulnerability(
                    target_domain=task_instance.domain,
                    http_url='http://%s' % subdomain.name,
                    scan_history=task_instance.scan,
                    subdomain=subdomain,
                    name='WP Taint (%s): %s' % (plugin_name, canonical_name),
                    severity=severity_num,
                    description=description,
                    type='WordPress',
                    references=[],
                    cve_ids=[],
                    source='WPTaintScan',
                )
                if not vuln.is_gpt_used:
                    try:
                        from reNgine.tasks import get_vulnerability_gpt_report
                        path = vuln.get_path() if hasattr(vuln, 'get_path') else '/'
                        if not path:
                            path = '/'
                        get_vulnerability_gpt_report((vuln.name, path), vulnerability_id=vuln.id)
                    except Exception as e:
                        logger.error('Failed to generate LLM description for WPTaint finding %s: %s', vuln.name, e)

    except Exception as e:
        logger.error('Failed to parse WP Taint Scan results for plugin %s: %s', plugin_name, str(e))

def wptaint_scan(self, urls=[], ctx={}, description=None):
    """
    wp-taint-scan task for WordPress plugin static analysis.
    Runs against plugins discovered by other WordPress tasks.
    """
    logger.info("Starting WP Taint Vulnerability Scan")
    
    # Configuration from engine
    vulnerability_config = self.yaml_configuration.get(VULNERABILITY_SCAN, {})
    should_run = vulnerability_config.get(RUN_WPTAINT_SCAN, True)
    
    if not should_run:
        logger.info("WP Taint Scan is disabled in configuration. Skipping.")
        return

    # Gather plugins discovered by WPScan/Nuclei or extracted from endpoint URLs
    import re
    plugin_url_re = re.compile(r'/wp-content/plugins/([^/?#]+)/')

    # Gather plugins from three sources:
    # 1. Vulnerability names: "WordPress Plugin: {slug}" (old) and
    #    "WordPress Plugin: {slug} - {vuln title}" (new)
    # 2. Vulnerability names: "WordPress Plugin Detected: {slug}" (new parser)
    # 3. EndPoint URLs: /wp-content/plugins/{slug}/
    plugin_subdomains = {}  # slug -> set of Subdomain objects

    from django.db.models import Q
    for vuln in Vulnerability.objects.filter(
        Q(name__startswith='WordPress Plugin:') | Q(name__startswith='WordPress Plugin Detected:'),
        scan_history=self.scan,
        target_domain=self.domain,
        type='WordPress',
    ):
        if vuln.name.startswith('WordPress Plugin Detected: '):
            slug = vuln.name[len('WordPress Plugin Detected: '):].strip()
        else:
            # Handle both "WordPress Plugin: slug" and "WordPress Plugin: slug - title"
            remainder = vuln.name[len('WordPress Plugin: '):]
            slug = remainder.split(' - ')[0].strip()

        if not slug:
            continue
        if slug not in plugin_subdomains:
            plugin_subdomains[slug] = set()
        if vuln.subdomain:
            plugin_subdomains[slug].add(vuln.subdomain)

    for ep in EndPoint.objects.filter(
        scan_history=self.scan,
        target_domain=self.domain,
        http_url__contains='/wp-content/plugins/',
    ):
        match = plugin_url_re.search(ep.http_url)
        if not match:
            continue
        slug = match.group(1)
        if not slug:
            continue
        if slug not in plugin_subdomains:
            plugin_subdomains[slug] = set()
        if ep.subdomain:
            plugin_subdomains[slug].add(ep.subdomain)

    if not plugin_subdomains:
        logger.info("No WordPress plugins discovered by previous tasks. Skipping WP Taint Scan.")
        return

    results_dir = f"{self.scan.results_dir}/vulnerability/wptaint"
    os.makedirs(results_dir, exist_ok=True)
    temp_download_dir = f"{self.scan.results_dir}/temp_wptaint"
    os.makedirs(temp_download_dir, exist_ok=True)

    for plugin_name, subdomains in plugin_subdomains.items():
        logger.info(f"WP Taint Scan target plugin: {plugin_name}")
        
        plugin_dir = os.path.join(temp_download_dir, plugin_name)
        plugin_zip = f"{plugin_dir}.zip"
        plugin_results_dir = os.path.join(results_dir, plugin_name)
        
        try:
            # 1. Download plugin source
            download_cmd = f"wget -q -O {plugin_zip} https://downloads.wordpress.org/plugin/{plugin_name}.zip"
            for _ in stream_command(download_cmd, scan_id=self.scan_id, activity_id=self.activity_id):
                pass
            
            if not os.path.exists(plugin_zip) or os.path.getsize(plugin_zip) == 0:
                logger.info("Could not download source for plugin %s. It may be a premium or unavailable plugin.", plugin_name)
                continue
                
            # 2. Unzip
            os.makedirs(plugin_dir, exist_ok=True)
            unzip_cmd = f"unzip -q -o {plugin_zip} -d {plugin_dir}"
            for _ in stream_command(unzip_cmd, scan_id=self.scan_id, activity_id=self.activity_id):
                pass
            
            # 3. Run taint-scan
            os.makedirs(plugin_results_dir, exist_ok=True)
            taint_cmd = f"taint-scan -target {plugin_dir} -output-dir {plugin_results_dir}"
            logger.info("Running WP Taint Scan on %s", plugin_name)
            for _ in stream_command(taint_cmd, scan_id=self.scan_id, activity_id=self.activity_id):
                pass
            
            # 4. Parse results
            results_file = os.path.join(plugin_results_dir, "taint-results.json")
            parse_wptaint_results(self, results_file, subdomains, plugin_name)
            
        except Exception as e:
            logger.error(f"Error executing WP Taint Scan on {plugin_name}: {e}")
        finally:
            # Cleanup source
            if os.path.exists(plugin_zip):
                os.remove(plugin_zip)
            if os.path.exists(plugin_dir):
                shutil.rmtree(plugin_dir)

    # Cleanup temp dir
    if os.path.exists(temp_download_dir):
        shutil.rmtree(temp_download_dir)
