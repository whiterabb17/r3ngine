import logging
import os
import json
import time

from reNgine.definitions import *
from reNgine.common_func import (
    get_random_proxy,
    save_vulnerability,
    record_exists,
    get_subdomain_from_url
)
from dashboard.models import WpScanAPIKey
from scanEngine.models import Proxy
from startScan.models import EndPoint, ScanHistory, Subdomain, Vulnerability

logger = logging.getLogger(__name__)

def parse_wpscan_results(task_instance, output_file, subdomain):
    """Parses WPScan JSON output and saves vulnerabilities to the database.

    Args:
        task_instance: Temporal task proxy with scan context.
        output_file (str): Path to the WPScan JSON output file.
        subdomain (Subdomain): Associated Subdomain object.
    """
    try:
        if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            return
        with open(output_file, 'r') as f:
            data = json.load(f)
        _parse_interesting_findings(task_instance, data, subdomain)
        _parse_version(task_instance, data, subdomain)
        _parse_plugins(task_instance, data, subdomain)
        _parse_themes(task_instance, data, subdomain)
        _parse_users(task_instance, data, subdomain)
    except Exception as e:
        logger.error("Failed to parse WPScan results for %s: %s", subdomain.name, str(e))


def _parse_interesting_findings(task_instance, data, subdomain):
    """Parses interesting findings from WPScan output, maps type to severity/name,
    and handles unknown types with a robust catchall that records additional metadata.

    Args:
        task_instance: Temporal task proxy with scan context.
        data (dict): WPScan output dict.
        subdomain (Subdomain): Subdomain object.
    """
    for finding in data.get('interesting_findings', []):
        finding_type = finding.get('type', '')
        severity, default_title = _FINDING_TYPE_MAP.get(finding_type, (None, None))
        
        # If type is not mapped, use a catchall that records additional metadata
        if severity is None or default_title is None:
            severity = 'info'
            # Create a name from finding type if possible, or fallback
            if finding_type:
                formatted_type = finding_type.replace('_', ' ').title()
                default_title = f"WPScan Finding: {formatted_type}"
            else:
                default_title = 'WPScan Finding'
                
            # Record all other key-value pairs of the finding in the description as metadata
            metadata_lines = []
            for k, v in finding.items():
                if k not in ['type', 'to_s', 'description', 'references', 'interesting_entries']:
                    metadata_lines.append(f"- **{k}**: {v}")
            
            metadata_desc = ""
            if metadata_lines:
                metadata_desc = "**Additional Metadata:**\n" + "\n".join(metadata_lines)
        else:
            metadata_desc = ""

        name = finding.get('to_s', default_title)
        if ': http' in name:
            name = name.split(': http')[0].strip()
        
        entries = finding.get('interesting_entries', [])
        extra_desc = ''
        if entries:
            extra_desc = '**Details:**\n' + '\n'.join(f'- {e}' for e in entries)
            
        if metadata_desc:
            if extra_desc:
                extra_desc = f"{extra_desc}\n\n{metadata_desc}"
            else:
                extra_desc = metadata_desc

        save_finding(task_instance, finding, subdomain, name,
                     severity=severity, extra_description=extra_desc)


def _parse_version(task_instance, data, subdomain):
    """Parses WordPress core version and version vulnerabilities from WPScan output.

    Args:
        task_instance: Temporal task proxy with scan context.
        data (dict): WPScan output dict.
        subdomain (Subdomain): Subdomain object.
    """
    version = data.get('version')
    if not version:
        return
    version_num = version.get('number', 'Unknown')
    status = version.get('status', '')
    outdated = status not in ('latest', '')
    severity = 'medium' if outdated else 'info'
    extra_desc = f"WordPress core v{version_num} detected."
    if outdated:
        extra_desc += f" Version status: {status}."
    save_finding(task_instance, {}, subdomain,
                 f"WordPress Core Detected: v{version_num}",
                 severity=severity, extra_description=extra_desc)
    for vuln in version.get('vulnerabilities', []):
        vuln_title = vuln.get('title', f"WordPress Core Vulnerability (v{version_num})")
        save_finding(task_instance, vuln, subdomain, vuln_title)


def _parse_plugins(task_instance, data, subdomain):
    """Parses WordPress plugins, versions, and vulnerabilities from WPScan output.

    Args:
        task_instance: Temporal task proxy with scan context.
        data (dict): WPScan output dict.
        subdomain (Subdomain): Subdomain object.
    """
    plugins = data.get('plugins', {}) or {}
    for slug, info in plugins.items():
        version_obj = info.get('version') or {}
        version_num = version_obj.get('number', 'Unknown') if version_obj else 'Unknown'
        outdated = info.get('outdated', False)
        latest = info.get('latest_version', 'unknown')
        location = info.get('location', '')
        severity = 'medium' if outdated else 'info'
        desc_parts = [f"Plugin **{slug}** v{version_num} detected at `{location}`."]
        if outdated:
            desc_parts.append(f"Plugin is **outdated** (installed: {version_num}, latest: {latest}).")
        save_finding(task_instance, {}, subdomain,
                     f"WordPress Plugin Detected: {slug}",
                     severity=severity, extra_description=' '.join(desc_parts))
        for vuln in info.get('vulnerabilities', []):
            vuln_title = vuln.get('title', f"WordPress Plugin Vulnerability: {slug}")
            save_finding(task_instance, vuln, subdomain,
                         f"WordPress Plugin: {slug} - {vuln_title}")


def _parse_themes(task_instance, data, subdomain):
    """Parses WordPress themes (main theme and additional themes) from WPScan output.

    Args:
        task_instance: Temporal task proxy with scan context.
        data (dict): WPScan output dict.
        subdomain (Subdomain): Subdomain object.
    """
    all_themes = {}
    main_theme = data.get('main_theme')
    if main_theme:
        slug = main_theme.get('slug', 'unknown-theme')
        all_themes[slug] = main_theme
    all_themes.update(data.get('themes', {}) or {})
    for slug, info in all_themes.items():
        version_obj = info.get('version') or {}
        version_num = version_obj.get('number', 'Unknown') if version_obj else 'Unknown'
        outdated = info.get('outdated', False)
        latest = info.get('latest_version', 'unknown')
        location = info.get('location', '')
        severity = 'medium' if outdated else 'info'
        desc_parts = [f"Theme **{slug}** v{version_num} detected at `{location}`."]
        if outdated:
            desc_parts.append(f"Theme is **outdated** (installed: {version_num}, latest: {latest}).")
        save_finding(task_instance, {}, subdomain,
                     f"WordPress Theme Detected: {slug}",
                     severity=severity, extra_description=' '.join(desc_parts))
        for vuln in info.get('vulnerabilities', []):
            vuln_title = vuln.get('title', f"WordPress Theme Vulnerability: {slug}")
            save_finding(task_instance, vuln, subdomain,
                         f"WordPress Theme: {slug} - {vuln_title}")


def _parse_users(task_instance, data, subdomain):
    """Parses enumerated WordPress users from WPScan output.

    Args:
        task_instance: Temporal task proxy with scan context.
        data (dict): WPScan output dict.
        subdomain (Subdomain): Subdomain object.
    """
    users = data.get('users', {}) or {}
    for username, info in users.items():
        found_by = info.get('found_by', 'Unknown method')
        user_id = info.get('id')
        desc = f"WordPress user **{username}** enumerated via {found_by}."
        if user_id is not None:
            desc += f" User ID: {user_id}."
        save_finding(task_instance, {}, subdomain,
                     f"WordPress User Enumerated: {username}",
                     severity='medium', extra_description=desc)

_FINDING_TYPE_MAP = {
    'xmlrpc':                     ('high',     'XML-RPC Enabled'),
    'upload_directory_listing':   ('medium',   'WordPress Upload Directory Listing Enabled'),
    'readme':                     ('info',     'WordPress Readme File Exposed'),
    'wp_cron':                    ('info',     'External WP-Cron Enabled'),
    'headers':                    ('info',     'WordPress HTTP Headers'),
    'backup_db':                  ('critical', 'WordPress Database Backup Exposed'),
    'debug_log':                  ('high',     'WordPress Debug Log Exposed'),
    'registration_enabled':       ('medium',   'WordPress User Registration Open'),
    'mu_plugins_listing':         ('medium',   'WordPress Must-Use Plugins Directory Listing'),
    'config_backup':              ('high',     'WordPress Configuration Backup Exposed'),
    'timthumb':                   ('high',     'TimThumb Script Detected'),
    'emergency_pwd_reset_script': ('critical', 'Emergency Password Reset Script Detected'),
    'full_path_disclosure':       ('medium',   'WordPress Full Path Disclosure'),
    'license':                    ('info',     'WordPress License File Exposed'),
}


def save_finding(task_instance, finding, subdomain, name, severity='info', extra_description=''):
    """Saves a WPScan finding to the database.

    Args:
        task_instance: Temporal task proxy with scan context.
        finding (dict): WPScan finding dict (may be empty {} for synthetic entries).
        subdomain (Subdomain): Associated Subdomain object.
        name (str): Vulnerability name/title to store.
        severity (str): One of 'info', 'low', 'medium', 'high', 'critical'.
        extra_description (str): Additional text prepended to the finding description.
    """
    description_parts = []
    if extra_description:
        description_parts.append(extra_description)
    base_desc = finding.get('description', '')
    if base_desc:
        description_parts.append(base_desc)
    description = '\n\n'.join(description_parts)

    references = finding.get('references', {})
    ref_urls = []
    cve_ids = []
    if isinstance(references, dict):
        for ref_type, ref_list in references.items():
            if ref_type == 'cve':
                cve_ids.extend(ref_list)
            elif isinstance(ref_list, list):
                ref_urls.extend(ref_list)
            else:
                ref_urls.append(str(ref_list))

    severity_num = NUCLEI_SEVERITY_MAP.get(severity, 0)

    vuln, created = save_vulnerability(
        target_domain=task_instance.domain,
        http_url=f"http://{subdomain.name}",
        scan_history=task_instance.scan,
        subdomain=subdomain,
        name=name,
        severity=severity_num,
        description=description,
        type='WordPress',
        references=ref_urls,
        cve_ids=cve_ids,
        source='WPScan',
    )

    if not vuln.is_gpt_used:
        try:
            from reNgine.tasks import get_vulnerability_gpt_report
            path = vuln.get_path() if hasattr(vuln, 'get_path') else '/'
            if not path:
                path = '/'
            get_vulnerability_gpt_report((vuln.name, path), vulnerability_id=vuln.id)
        except Exception as e:
            logger.error("Failed to generate LLM description for finding %s: %s", vuln.name, e)

def wpscan_scan(self, urls=[], ctx={}, description=None):
    """WPScan task for WordPress vulnerability scanning.
    Runs against all discovered subdomains or specific URLs.

    Args:
        self: The Temporal task proxy with scan context.
        urls (list, optional): List of specific target URLs to scan.
        ctx (dict, optional): Scan context data.
        description (str, optional): Descriptive text for this task.

    Returns:
        str: Status message on completion, or None if skipped.
    """
    logger.info("Starting WPScan Vulnerability Scan")
    
    # Configuration from engine
    vulnerability_config = self.yaml_configuration.get(VULNERABILITY_SCAN, {})
    
    should_run = vulnerability_config.get(RUN_WPSCAN, True)
    if not should_run:
        logger.info("WPScan is disabled in configuration. Skipping.")
        return

    # Gate: only run when WordPress indicators are present, either from technology
    # fingerprinting or from wp-like paths found by fetch_url / dir_file_fuzz.
    # Mirrors the react2shell_scan gating pattern.
    from django.db.models import Q
    _WP_PATH_RE = r'(wp-login|wp-admin|wp-content|wp-json|xmlrpc\.php)'

    if self.subscan and self.subdomain:
        _sub_qs = Subdomain.objects.filter(pk=self.subdomain.id)
        _ep_qs = EndPoint.objects.filter(
            scan_history=self.scan,
            subdomain=self.subdomain,
            http_url__iregex=_WP_PATH_RE,
        )
    else:
        _sub_qs = Subdomain.objects.filter(scan_history=self.scan)
        _ep_qs = EndPoint.objects.filter(
            scan_history=self.scan,
            http_url__iregex=_WP_PATH_RE,
        )

    wp_via_tech = _sub_qs.filter(technologies__name__icontains='wordpress').exists()
    wp_via_paths = _ep_qs.exists()

    if not wp_via_tech and not wp_via_paths:
        logger.info("No WordPress indicators (technology or wp-like paths) found. Skipping WPScan.")
        return

    enumeration = vulnerability_config.get(WPSCAN_ENUMERATION, 'vp,vt,u')
    detection_mode = vulnerability_config.get(WPSCAN_DETECTION_MODE, 'mixed')

    # Get API Key
    api_key_obj = WpScanAPIKey.objects.first()
    api_key = api_key_obj.key if api_key_obj else None

    # Determine targets — narrow to only WordPress-positive subdomains.
    targets = []
    if self.subscan and self.subdomain:
        targets.append((f"https://{self.subdomain.name}/", self.subdomain))
    elif urls:
        # Targeted scan on specific URLs
        for url in urls:
            subdomain_name = get_subdomain_from_url(url)
            subdomain = Subdomain.objects.filter(scan_history=self.scan, name=subdomain_name).first()
            if subdomain:
                targets.append((url, subdomain))
    else:
        # Full scan — only subdomains with WP tech or WP-like endpoints.
        wp_subdomain_ids = set(
            _sub_qs.filter(technologies__name__icontains='wordpress')
            .values_list('id', flat=True)
        )
        ep_subdomain_ids = set(
            EndPoint.objects.filter(
                scan_history=self.scan,
                http_url__iregex=_WP_PATH_RE,
            ).values_list('subdomain_id', flat=True)
        )
        wp_ids = wp_subdomain_ids | ep_subdomain_ids
        for subdomain in Subdomain.objects.filter(scan_history=self.scan, id__in=wp_ids):
            targets.append((f"https://{subdomain.name}/", subdomain))

    if not targets:
        logger.info("No targets found for WPScan.")
        return

    results_dir = f"{self.scan.results_dir}/vulnerability/wpscan"
    os.makedirs(results_dir, exist_ok=True)

    from reNgine.tasks import stream_command

    # Attempt to update WPScan database first before running scans on targets
    update_cmd = "wpscan --update --no-banner"
    logger.info("Updating WPScan database without proxy...")
    try:
        for _ in stream_command(update_cmd, scan_id=self.scan_id, activity_id=self.activity_id):
            pass
    except Exception as e:
        logger.error("Failed to run wpscan database update: %s", e)

    for target_url, subdomain in targets:
        target_name = subdomain.name
        
        # Ensure trailing slash is stripped from target URL
        target_url = target_url.rstrip('/')
        logger.info("WPScan target: %s", target_url)
        
        output_file = f"{results_dir}/{target_name}_wpscan.json"
        
        max_attempts = 4  # 1 initial attempt + 3 retries
        for attempt in range(max_attempts):
            # Command construction
            cmd = f"wpscan --url {target_url} --format json --random-user-agent --output {output_file} --enumerate {enumeration} --detection-mode {detection_mode} --no-banner --ignore-main-redirect"
            
            # The final retry attempt must be executed without the proxy flag
            proxy = None
            if attempt < max_attempts - 1:
                proxy_obj = Proxy.objects.first()
                if proxy_obj and proxy_obj.use_proxy:
                    proxy = get_random_proxy()
            
            if proxy:
                cmd += f" --proxy {proxy}"
            if api_key:
                cmd += f" --api-token {api_key}"
            
            logger.info("Running WPScan for %s (Attempt %d/%d)", target_url, attempt + 1, max_attempts)
            logger.warning("Full WPScan command: %s", cmd)
            
            # Remove output file if it exists to ensure we don't read stale results
            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except Exception:
                    pass

            # Execute tool — stream_command is a generator; must be consumed to run the subprocess.
            for _ in stream_command(cmd, scan_id=self.scan_id, activity_id=self.activity_id):
                pass

            # Check after the tool call at the output files for SSL peer certificate error
            failed_with_ssl_error = False
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            db_update_started = data.get('db_update_started')
                            scan_aborted = data.get('scan_aborted')
                            target_url_in_json = data.get('target_url')
                            
                            target_url_normalized = target_url.rstrip('/')
                            json_url_normalized = target_url_in_json.rstrip('/') if isinstance(target_url_in_json, str) else ''
                            
                            # Verify if update failed due to SSL peer certificate check
                            if (
                                db_update_started is True and
                                isinstance(scan_aborted, str) and
                                "SSL peer certificate or SSH remote key was not OK" in scan_aborted and
                                target_url_normalized == json_url_normalized
                            ):
                                failed_with_ssl_error = True
                except Exception as parse_err:
                    logger.error("Failed to parse WPScan output JSON: %s", parse_err)

            if failed_with_ssl_error:
                if attempt < max_attempts - 1:
                    logger.warning(
                        "WPScan aborted due to SSL peer certificate error on %s. Retrying (%d/%d)...",
                        target_url, attempt + 1, max_attempts - 1,
                    )
                    time.sleep(2)
                    continue
                else:
                    logger.error(
                        "WPScan failed on %s with SSL certificate error after %d attempts. Skipping target.",
                        target_url, max_attempts,
                    )
                    # Clean up aborted output file to prevent parsing junk
                    if os.path.exists(output_file):
                        try:
                            os.remove(output_file)
                        except Exception:
                            pass
                    break
            else:
                # Execution succeeded or failed with different error
                break

        # Parse and save
        parse_wpscan_results(self, output_file, subdomain)

    return "WPScan completed"
