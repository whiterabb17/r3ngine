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
            
            url_path = ''
            if file_path:
                # Convert backslashes to forward slashes for cross-platform robustness
                normalized_file_path = file_path.replace('\\', '/')
                temp_marker = '/temp_wptaint/'
                
                if temp_marker in normalized_file_path:
                    # Get path relative to the temp download directory
                    rel_part = normalized_file_path.split(temp_marker, 1)[1]
                else:
                    # Fallback path cleaning if the marker is missing (e.g. simplified paths)
                    rel_part = normalized_file_path.lstrip('/')
                
                path_parts = rel_part.split('/')
                # Remove the plugin name prefix (from plugin_dir and potentially the zip root folder)
                if path_parts and path_parts[0] == plugin_name:
                    path_parts = path_parts[1:]
                if path_parts and path_parts[0] == plugin_name:
                    path_parts = path_parts[1:]
                
                relative_path_within_plugin = '/'.join(path_parts)
                url_path = f"/wp-content/plugins/{plugin_name}/{relative_path_within_plugin}"

            if url_path:
                file_line = '`%s`' % url_path
                if line:
                    file_line += ' (Line %d)' % line
                description_parts.append('**File**: ' + file_line)
            elif file_path:
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
                vuln_http_url = 'http://%s%s' % (subdomain.name, url_path) if url_path else 'http://%s' % subdomain.name
                vuln, created = save_vulnerability(
                    target_domain=task_instance.domain,
                    http_url=vuln_http_url,
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


def correlate_wptaint_with_wpscan(scan, taint_run_meta=None):
    """Stamp WPTaint findings with WPScan version guidance for the same scan.

    Args:
        scan: ScanHistory instance.
        taint_run_meta (dict, optional): slug -> {tainted_version, tainted_source}.
    """
    from reNgine.tasks.wordpress_version import (
        apply_version_guidance_to_vuln,
        build_version_guidance,
        collect_wpscan_plugin_versions,
        parse_wptaint_plugin_slug,
    )

    taint_run_meta = taint_run_meta or {}
    by_slug = collect_wpscan_plugin_versions(scan)
    updated = 0
    for vuln in Vulnerability.objects.filter(scan_history=scan, source='WPTaintScan'):
        slug = parse_wptaint_plugin_slug(vuln.name or '')
        if not slug:
            continue
        base = dict(by_slug.get(slug) or {})
        run_meta = taint_run_meta.get(slug) or {}
        guidance = build_version_guidance(
            component=base.get('component') or 'plugin',
            slug=slug,
            installed=base.get('installed'),
            latest=base.get('latest'),
            outdated=base.get('outdated'),
            fixed_in=base.get('fixed_in'),
            tainted_version=run_meta.get('tainted_version') or base.get('tainted_version'),
            tainted_source=run_meta.get('tainted_source') or base.get('tainted_source'),
            extra={
                k: v for k, v in base.items()
                if k.startswith('fixed_in') and k != 'fixed_in'
            } or None,
        )
        apply_version_guidance_to_vuln(
            vuln,
            guidance,
            update_validation_reason=True,
        )
        updated += 1


    logger.info("Correlated version guidance onto %s WPTaint findings for scan %s", updated, scan.id)
    return updated


def _download_plugin_zip(plugin_name, plugin_zip, installed_version, scan_id, activity_id):
    """Download wordpress.org plugin zip for installed version when possible.

    Returns:
        tuple: (success: bool, tainted_version: str|None, tainted_source: str|None)
    """
    from reNgine.tasks.wordpress_version import wordpress_org_plugin_download_candidates

    for url, version_label, source in wordpress_org_plugin_download_candidates(
        plugin_name, installed_version
    ):
        if os.path.exists(plugin_zip):
            try:
                os.remove(plugin_zip)
            except OSError:
                pass
        download_cmd = f"wget -q -O {plugin_zip} {url}"
        logger.info("WP Taint downloading %s (%s)", url, source)
        for _ in stream_command(download_cmd, scan_id=scan_id, activity_id=activity_id):
            pass
        if os.path.exists(plugin_zip) and os.path.getsize(plugin_zip) > 0:
            return True, version_label, source
        logger.info("WP Taint download failed/empty for %s via %s", plugin_name, source)
    return False, None, None


def wptaint_scan(self, urls=[], ctx={}, description=None):
    """
    wp-taint-scan task for WordPress plugin static analysis.
    Runs against plugins discovered by other WordPress tasks.
    Prefers the WPScan-reported installed version zip when downloadable.
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
    from reNgine.tasks.wordpress_version import (
        collect_wpscan_plugin_versions,
        is_safe_wordpress_plugin_slug,
    )

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

        if not is_safe_wordpress_plugin_slug(slug):
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
        if not is_safe_wordpress_plugin_slug(slug):
            continue
        if slug not in plugin_subdomains:
            plugin_subdomains[slug] = set()
        if ep.subdomain:
            plugin_subdomains[slug].add(ep.subdomain)

    if not plugin_subdomains:
        logger.info("No WordPress plugins discovered by previous tasks. Skipping WP Taint Scan.")
        return

    version_by_slug = collect_wpscan_plugin_versions(self.scan)
    taint_run_meta = {}

    results_dir = f"{self.scan.results_dir}/vulnerability/wptaint"
    os.makedirs(results_dir, exist_ok=True)
    temp_download_dir = f"{self.scan.results_dir}/temp_wptaint"
    os.makedirs(temp_download_dir, exist_ok=True)

    for plugin_name, subdomains in plugin_subdomains.items():
        installed_version = (version_by_slug.get(plugin_name) or {}).get('installed')
        logger.info(
            "WP Taint Scan target plugin: %s (installed=%s)",
            plugin_name,
            installed_version or 'unknown',
        )
        
        plugin_dir = os.path.join(temp_download_dir, plugin_name)
        plugin_zip = f"{plugin_dir}.zip"
        plugin_results_dir = os.path.join(results_dir, plugin_name)
        
        try:
            # 1. Download plugin source (installed version when known)
            ok, tainted_version, tainted_source = _download_plugin_zip(
                plugin_name,
                plugin_zip,
                installed_version,
                self.scan_id,
                self.activity_id,
            )
            if not ok:
                logger.info(
                    "Could not download source for plugin %s. It may be a premium or unavailable plugin.",
                    plugin_name,
                )
                continue

            # Record only the zip that actually succeeded — never backfill
            # installed_version when analysis used latest/latest_fallback.
            taint_run_meta[plugin_name] = {
                'tainted_version': tainted_version,
                'tainted_source': tainted_source,
            }
                
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
            logger.error("Error executing WP Taint Scan on %s: %s", plugin_name, e)
        finally:
            # Cleanup source
            if os.path.exists(plugin_zip):
                os.remove(plugin_zip)
            if os.path.exists(plugin_dir):
                shutil.rmtree(plugin_dir)

    # Cleanup temp dir
    if os.path.exists(temp_download_dir):
        shutil.rmtree(temp_download_dir)

    # Stamp WPScan version guidance onto all WPTaint findings for this scan.
    correlate_wptaint_with_wpscan(self.scan, taint_run_meta=taint_run_meta)
