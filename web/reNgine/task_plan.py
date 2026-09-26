"""
Builds the planned task list for a scan based on the engine task list
and the full YAML configuration. Pure function — no Django ORM, no I/O.
"""
from reNgine.definitions import INITIATED_TASK

_TASK_TITLES = {
    # Tier 0
    'target_profiling':           'Target Profiling',
    # Tier 1
    'subdomain_discovery':        'Subdomain Discovery',
    'amass_intel_discovery':      'WHOIS / Infrastructure Intel',
    'firewall_vpn_scan':          'Firewall & VPN Detection',
    'dns_security':               'DNS Security',
    'osint':                      'OSINT Gathering',
    'spiderfoot_scan':            'SpiderFoot OSINT',
    'baddns':                     'BadDNS Vulnerability Check',
    'vigolium_harvest':           'Vigolium Passive Harvest',
    # Tier 2
    'http_crawl':                 'HTTP Crawl',
    'port_scan':                  'Port Scan',
    'vigolium_discovery':         'Vigolium Discovery',
    'acunetix_submit':            'Acunetix Target Submission',
    'check_if_email_exists':      'Mailbox Verification',
    # Tier 3
    'fetch_url':                  'URL Fetching',
    'http_crawl_bridge':          'HTTP Crawl Bridge',
    'screenshot':                 'Screenshot Capture',
    'param_discovery':            'Parameter Discovery (CPDE)',
    'web_api_discovery':          'Web API Discovery',
    # Tier 4
    'dir_file_fuzz':              'Directory & File Fuzzing',
    # Tier 5
    'waf_detection':              'WAF Detection',
    'secret_scanning':            'Secret Scanning',
    'vigolium_analysis':          'Vigolium Analysis',
    # Tier 6
    'vulnerability_scan':         'Vulnerability Scan',
    'nuclei_scan':                'Nuclei Vulnerability Scan',
    'crlfuzz_scan':               'CRLF Injection Scan',
    'dalfox_xss_scan':            'Dalfox XSS Scan',
    's3scanner':                  'S3 Bucket Scanner',
    'acunetix_scan':              'Acunetix Web Scan',
    'wpscan_scan':                'WPScan',
    'vigolium_scan':              'Vigolium Vulnerability Scan',
    'cpanel_scan':                'cPanel Scanner',
    'react2shell_scan':           'React2Shell Scanner',
    'waf_bypass':                 'WAF Bypass',

    # Tier 7 (always present)
    'correlate_vulnerabilities':  'Vulnerability Correlation',
    'calculate_risk_scores':      'Risk Scoring',
    'generate_impact_assessment': 'Impact Assessment',
    'sync_graph':                 'Graph Sync (Neo4j)',
    'run_apme':                   'Attack Path Modeling',
    'scan_notification':          'Send Scan Notification',
}

_TASK_TIER = {
    'target_profiling':      0,
    'subdomain_discovery':   1,
    'amass_intel_discovery': 1,
    'firewall_vpn_scan':     1,
    'dns_security':          1,
    'osint':                 1,
    'spiderfoot_scan':       1,
    'baddns':                1,
    'vigolium_harvest':      1,
    'http_crawl':            2,
    'port_scan':             2,
    # Both MasterScanWorkflow and SubScanWorkflow schedule vigolium_discovery in
    # Tier 2, after subdomain enumeration, so it targets every enumerated
    # subdomain. The timeline groups rows by this map, and the tier retry
    # endpoint selects rows by it, so it has to name the tier that really runs it.
    'vigolium_discovery':    2,
    'check_if_email_exists': 2,
    'fetch_url':             3,
    'http_crawl_bridge':     3,
    'screenshot':            3,
    'param_discovery':       3,
    'web_api_discovery':     3,
    'dir_file_fuzz':         4,
    'waf_detection':         5,
    'secret_scanning':       5,
    'vigolium_analysis':     5,
    'vulnerability_scan':    6,
    'nuclei_scan':           6,
    'crlfuzz_scan':          6,
    'dalfox_xss_scan':       6,
    's3scanner':             6,
    'acunetix_scan':         6,
    'acunetix_submit':       2,
    'wpscan_scan':           6,
    'vigolium_scan':         6,
    'cpanel_scan':           6,
    'react2shell_scan':      6,
    'waf_bypass':            6,

    # Runtime-only tasks: never part of the planned list, but their activity rows
    # need a tier so they are not all filed under Tier 7 in the timeline.
    'search_vulns_scan':     2,
    'smugglex_scan':         6,
    'second_order_scan':     6,
    'nuclei_dast_scan':      6,
    'semgrep_scan':          6,
    'wptaint_scan':          6,
}

_TIER7_TASKS = [
    'correlate_vulnerabilities',
    'calculate_risk_scores',
    'generate_impact_assessment',
    'sync_graph',
    'run_apme',
    'scan_notification',
]

# Engine YAML often stores resource keys (threads, timeout, ...) in ScanHistory.tasks.
# Recovery must ignore those and only resume real pipeline task names.
_SCAN_TASK_ALIASES = {
    'attack_path_modeling': 'run_apme',
}

KNOWN_SCAN_TASK_NAMES = set(_TASK_TITLES) | set(_TIER7_TASKS)


def canonical_scan_task_name(name: str):
    """Return a known pipeline task name, or None for YAML/resource keys."""
    if not name:
        return None
    mapped = _SCAN_TASK_ALIASES.get(name, name)
    if mapped in KNOWN_SCAN_TASK_NAMES:
        return mapped
    return None

_TIER1_TO_5 = [
    'subdomain_discovery', 'amass_intel_discovery', 'firewall_vpn_scan',
    'dns_security', 'osint', 'spiderfoot_scan', 'baddns',
    'vigolium_harvest',
    'http_crawl', 'port_scan', 'vigolium_discovery',
    'fetch_url', 'screenshot', 'param_discovery',
    'http_crawl_bridge',
    'dir_file_fuzz',
    'web_api_discovery', 'waf_detection', 'secret_scanning',
    'waf_bypass',
]


def get_task_tier(name: str) -> int:
    """Return the timeline tier a task belongs to (7 for unplanned/post-processing)."""
    return _TASK_TIER.get(pipeline_task_name(name), 7)


# ---------------------------------------------------------------------------
# Singular tool runs use a distinct ScanActivity.name namespace so they never
# claim, retry, or finalize pipeline / tier-retry rows that share a task slug.
# Workflow dispatch still uses the bare pipeline task name.
# ---------------------------------------------------------------------------
SINGLE_TOOL_ACTIVITY_PREFIX = 'single_tool_'


def singular_activity_name(task_name: str) -> str:
    """ScanActivity.name for a singular tool run (idempotent)."""
    name = (task_name or '').strip()
    if not name:
        return name
    if name.startswith(SINGLE_TOOL_ACTIVITY_PREFIX):
        return name
    return f'{SINGLE_TOOL_ACTIVITY_PREFIX}{name}'


def pipeline_task_name(activity_name: str) -> str:
    """Strip single_tool_ prefix to recover the pipeline task slug."""
    name = (activity_name or '').strip()
    if name.startswith(SINGLE_TOOL_ACTIVITY_PREFIX):
        return name[len(SINGLE_TOOL_ACTIVITY_PREFIX):]
    return name


def is_singular_activity_name(activity_name: str) -> bool:
    return (activity_name or '').startswith(SINGLE_TOOL_ACTIVITY_PREFIX)


def email_security_enabled(yaml_configuration: dict) -> bool:
    """True unless the engine config turns email security off.

    The workflow schedules the activity whenever port_scan is in the task list,
    so this is the only switch an operator has. Absent config means enabled, to
    keep existing engines behaving as they did.
    """
    section = yaml_configuration.get('email_security') if isinstance(yaml_configuration, dict) else None
    if not isinstance(section, dict):
        return True
    return bool(section.get('enabled', True))


def _mailbox_verification_planned(tasks: list, yaml_configuration: dict, is_subscan: bool = False) -> bool:
    """True when MasterScanWorkflow will run mailbox verification."""
    if is_subscan:
        return False
    if 'port_scan' not in tasks:
        return False
    if not email_security_enabled(yaml_configuration):
        return False
    section = yaml_configuration.get('email_security') if isinstance(yaml_configuration, dict) else None
    if not isinstance(section, dict):
        section = {}
    raw = section.get('mailbox_verification')
    if raw is None:
        return True
    if not isinstance(raw, dict):
        return True
    return bool(raw.get('enabled', True))


def _entry(name: str) -> dict:
    return {
        'name': name,
        'title': _TASK_TITLES.get(name, name.replace('_', ' ').title()),
        'tier': get_task_tier(name),
        'status': INITIATED_TASK,
    }


def build_scan_task_plan(tasks: list, yaml_configuration: dict, is_subscan: bool = False) -> list:
    """
    Return ordered list of planned-task dicts given an engine task list
    and the full parsed YAML configuration dict.

    Each dict: {name, title, tier, status=INITIATED_TASK}.
    Sorted by tier ascending. No I/O — pure function.
    is_subscan: SubScanWorkflow never runs RunEmailSecurityActivity.
    """
    plan = []
    seen = set()

    def add(name: str):
        if name not in seen:
            seen.add(name)
            plan.append(_entry(name))

    # Tier 0 — always
    add('target_profiling')

    # Tiers 1-5: conditional on top-level task names
    for t in _TIER1_TO_5:
        if t in tasks:
            add(t)
        elif t == 'http_crawl_bridge' and 'fetch_url' in tasks:
            add(t)

    # Acunetix target submission rides on http_crawl, which is what establishes
    # liveness — it is independent of whether the Acunetix scanner itself runs.
    acunetix_cfg = (yaml_configuration.get('vulnerability_scan') or {}).get('acunetix') or {}
    if 'http_crawl' in tasks and acunetix_cfg.get('submit_live_subdomains', False):
        add('acunetix_submit')

    # Post-tier-2 mailbox verification (same gate as RunEmailSecurityActivity).
    if _mailbox_verification_planned(tasks, yaml_configuration, is_subscan=is_subscan):
        add('check_if_email_exists')

    # Vigolium tasks: harvest + discovery auto-added when vulnerability_scan is selected
    # (unless explicitly disabled in yaml_configuration).
    # vigolium_analysis and vigolium_scan remain gated by vulnerability_scan.
    vuln_cfg = yaml_configuration.get('vulnerability_scan') or {}

    if 'vulnerability_scan' in tasks:
        vh_cfg = yaml_configuration.get('vigolium_harvest') or {}
        if vh_cfg.get('run_vigolium_harvest', True):
            add('vigolium_harvest')

        vd_cfg = yaml_configuration.get('vigolium_discovery') or {}
        if vd_cfg.get('run_vigolium_discovery', True):
            add('vigolium_discovery')

        va_cfg = vuln_cfg.get('vigolium_analysis') or {}
        if va_cfg.get('run_vigolium_analysis', True):
            add('vigolium_analysis')

    # Tier 6: vulnerability_scan parent + per-tool sub-tasks
    if 'vulnerability_scan' in tasks:
        add('vulnerability_scan')
        _SUB_TOOL_FLAGS = [
            ('run_nuclei',    True,  'nuclei_scan'),
            ('run_crlfuzz',   False, 'crlfuzz_scan'),
            ('run_dalfox',    False, 'dalfox_xss_scan'),
            ('run_s3scanner', True,  's3scanner'),
            ('run_acunetix',  False, 'acunetix_scan'),
            ('run_wpscan',    True,  'wpscan_scan'),
            ('run_vigolium',  True,  'vigolium_scan'),
        ]
        for flag, default, task_name in _SUB_TOOL_FLAGS:
            if vuln_cfg.get(flag, default):
                add(task_name)
        cpanel_cfg = vuln_cfg.get('cpanel_scanner') or {}
        if cpanel_cfg.get('run_cpanel2shell', True):
            add('cpanel_scan')
        react_cfg = vuln_cfg.get('react_scanner') or {}
        if react_cfg.get('run_react2shell', True):
            add('react2shell_scan')

    # Tier 7 — always run finalisation regardless of which tiers ran
    add('correlate_vulnerabilities')
    add('calculate_risk_scores')
    add('generate_impact_assessment')
    add('sync_graph')
    add('run_apme')
    add('scan_notification')

    return sorted(plan, key=lambda e: e['tier'])
