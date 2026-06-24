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
    # Tier 2
    'http_crawl':                 'HTTP Crawl',
    'port_scan':                  'Port Scan',
    'vigolium_discovery':         'Vigolium Discovery',
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
    'http_crawl':            2,
    'port_scan':             2,
    'vigolium_discovery':    2,
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
    'wpscan_scan':           6,
    'vigolium_scan':         6,
    'cpanel_scan':           6,
    'react2shell_scan':      6,
    'waf_bypass':            6,

}

_TIER7_TASKS = [
    'correlate_vulnerabilities',
    'calculate_risk_scores',
    'generate_impact_assessment',
    'sync_graph',
    'run_apme',
    'scan_notification',
]

_TIER1_TO_5 = [
    'subdomain_discovery', 'amass_intel_discovery', 'firewall_vpn_scan',
    'dns_security', 'osint', 'spiderfoot_scan', 'baddns',
    'http_crawl', 'port_scan',
    'fetch_url', 'screenshot', 'param_discovery',
    'http_crawl_bridge',
    'dir_file_fuzz',
    'web_api_discovery', 'waf_detection', 'secret_scanning',
    'waf_bypass',
]


def _entry(name: str) -> dict:
    return {
        'name': name,
        'title': _TASK_TITLES.get(name, name.replace('_', ' ').title()),
        'tier': _TASK_TIER.get(name, 7),
        'status': INITIATED_TASK,
    }


def build_scan_task_plan(tasks: list, yaml_configuration: dict) -> list:
    """
    Return ordered list of planned-task dicts given an engine task list
    and the full parsed YAML configuration dict.

    Each dict: {name, title, tier, status=INITIATED_TASK}.
    Sorted by tier ascending. No I/O — pure function.
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

    # Vigolium discovery/analysis are sub-tasks inside vulnerability_scan
    vuln_cfg = yaml_configuration.get('vulnerability_scan') or {}

    vd_cfg = vuln_cfg.get('vigolium_discovery') or {}
    if vd_cfg.get('run_vigolium_discovery', True) and 'vulnerability_scan' in tasks:
        add('vigolium_discovery')

    va_cfg = vuln_cfg.get('vigolium_analysis') or {}
    if va_cfg.get('run_vigolium_analysis', True) and 'vulnerability_scan' in tasks:
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
